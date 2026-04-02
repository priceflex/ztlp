//! Dedicated OS-thread ACK sender with dup'd socket.
//!
//! Solves the tokio cooperative scheduling starvation problem on iOS:
//! when the recv_loop is processing high-rate inbound data, tokio tasks
//! for ACK sending never get CPU time. This module provides a real OS
//! thread that the kernel schedules independently of the tokio runtime.
//!
//! The thread owns a dup'd copy of the main UDP socket (same source port)
//! and performs blocking send_to() calls. The recv_loop pre-encrypts
//! ACK packets using the normal transport pipeline (proper seq allocation),
//! then sends the raw encrypted bytes to this thread for I/O only.
//!
//! # Safety
//! Uses `libc::dup()` and `std::net::UdpSocket::from_raw_fd()` to create
//! a second file descriptor for the same socket. This is safe because:
//! - The dup'd fd is independent — closing it does not affect the original
//! - UDP sendto() is thread-safe at the kernel level
//! - Each fd maintains its own file offset (irrelevant for UDP)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A pre-encrypted packet ready to send on the wire.
/// The recv_loop builds these using the normal transport pipeline
/// (proper seq allocation + encryption), then hands them off for I/O.
pub struct WirePacket {
    /// The fully serialized, encrypted ZTLP packet bytes.
    pub data: Vec<u8>,
    /// Whether this is a NACK (should not be coalesced).
    pub is_nack: bool,
}

/// Duplicate a tokio UDP socket's file descriptor into a blocking std::net::UdpSocket.
///
/// The returned socket shares the same local address (IP + port) as the original,
/// but is an independent fd suitable for use from a blocking OS thread.
#[cfg(unix)]
pub fn dup_udp_socket(
    tokio_socket: &tokio::net::UdpSocket,
) -> Result<std::net::UdpSocket, std::io::Error> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let original_fd = tokio_socket.as_raw_fd();

    // SAFETY: libc::dup() creates a new file descriptor that refers to the same
    // open file description. The new fd is independent — closing it does not
    // affect the original. UDP socket send_to() is safe to call concurrently
    // from multiple fds/threads at the kernel level.
    let new_fd = unsafe { libc::dup(original_fd) };
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: new_fd is a valid, open file descriptor from dup(). We transfer
    // ownership to std::net::UdpSocket which will close it on drop.
    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(new_fd) };

    // Set to blocking mode (std::net::UdpSocket expects blocking)
    std_socket.set_nonblocking(false)?;

    Ok(std_socket)
}

/// Non-unix fallback: bind a new socket on 0.0.0.0:0 (different port).
/// The relay handles this via session_id matching + NAT rebind detection.
#[cfg(not(unix))]
pub fn dup_udp_socket(
    _tokio_socket: &tokio::net::UdpSocket,
) -> Result<std::net::UdpSocket, std::io::Error> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_nonblocking(false)?;
    Ok(sock)
}

/// Configuration for spawning the ACK sender OS thread.
pub struct AckSenderConfig {
    pub socket: std::net::UdpSocket,
    pub peer_addr: SocketAddr,
    pub stop_flag: Arc<AtomicBool>,
}

/// Spawn the dedicated ACK sender OS thread.
///
/// Returns a `std::sync::mpsc::Sender<WirePacket>` for sending pre-encrypted
/// ZTLP packets. The thread handles:
/// - Coalescing: drains queued ACKs, sends only the latest (cumulative)
/// - NACK passthrough: NACKs are sent immediately without coalescing
/// - Blocking send_to() on the dup'd socket (OS-scheduled, not tokio)
///
/// NO crypto or seq allocation happens on this thread — the recv_loop
/// pre-encrypts packets using the normal transport pipeline.
pub fn spawn_ack_sender(
    config: AckSenderConfig,
) -> std::sync::mpsc::Sender<WirePacket> {
    let (tx, rx) = std::sync::mpsc::channel::<WirePacket>();

    std::thread::Builder::new()
        .name("ztlp-ack-sender".into())
        .spawn(move || {
            let AckSenderConfig {
                socket,
                peer_addr,
                stop_flag,
            } = config;

            let mut sent_count: u64 = 0;
            let mut error_count: u64 = 0;

            tracing::info!(
                "ack_sender: started on OS thread (I/O only), peer={}",
                peer_addr
            );

            while let Ok(pkt) = rx.recv() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                // Coalesce: drain queued packets, keep only latest ACK.
                // NACKs are sent immediately since they carry specific gap info.
                let mut latest_data = pkt.data;
                while let Ok(queued) = rx.try_recv() {
                    if queued.is_nack {
                        // NACK — send immediately, not redundant
                        if let Err(e) = socket.send_to(&queued.data, peer_addr) {
                            error_count += 1;
                            if error_count <= 5 {
                                tracing::warn!("ack_sender: NACK send failed: {}", e);
                            }
                        } else {
                            sent_count += 1;
                        }
                    } else {
                        latest_data = queued.data; // newer ACK supersedes older
                    }
                }

                // Send the latest (coalesced) ACK
                if let Err(e) = socket.send_to(&latest_data, peer_addr) {
                    error_count += 1;
                    if error_count <= 5 {
                        tracing::warn!("ack_sender: ACK send failed: {}", e);
                    }
                } else {
                    sent_count += 1;
                }

                // Periodic status log
                if sent_count > 0 && sent_count % 500 == 0 {
                    tracing::info!(
                        "ack_sender: sent={} errors={}",
                        sent_count,
                        error_count
                    );
                }
            }

            tracing::info!(
                "ack_sender: exiting, sent={} errors={}",
                sent_count,
                error_count
            );
        })
        .expect("failed to spawn ztlp-ack-sender thread");

    tx
}
