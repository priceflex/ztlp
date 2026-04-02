//! Dedicated OS-thread ACK sender with dup'd socket.
//!
//! Solves the tokio cooperative scheduling starvation problem on iOS:
//! when the recv_loop is processing high-rate inbound data, tokio tasks
//! for ACK sending never get CPU time. This module provides a real OS
//! thread that the kernel schedules independently of the tokio runtime.
//!
//! The thread owns a dup'd copy of the main UDP socket (same source port)
//! and performs its own ChaCha20-Poly1305 encryption + ZTLP packet
//! serialization. Sequence numbers are allocated from a shared AtomicU64
//! that is also used by the main transport path, ensuring seqs stay
//! within the gateway's anti-replay window.
//!
//! # Safety
//! Uses `libc::dup()` and `std::net::UdpSocket::from_raw_fd()` to create
//! a second file descriptor for the same socket. This is safe because:
//! - The dup'd fd is independent — closing it does not affect the original
//! - UDP sendto() is thread-safe at the kernel level
//! - Each fd maintains its own file offset (irrelevant for UDP)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use crate::packet::{DataHeader, SessionId, ZtlpPacket};
use crate::pipeline::compute_header_auth_tag;

/// Get the raw file descriptor from a tokio UDP socket for direct sendto().
///
/// On iOS Network Extension, dup() + set_nonblocking can break the socket's
/// interface binding. Instead, we use the ORIGINAL fd directly with libc::sendto()
/// from the OS thread. UDP sendto() is thread-safe at the kernel level —
/// concurrent calls from tokio (recv) and the OS thread (send) are safe.
#[cfg(unix)]
pub fn get_socket_fd(tokio_socket: &tokio::net::UdpSocket) -> i32 {
    use std::os::unix::io::AsRawFd;
    tokio_socket.as_raw_fd()
}

#[cfg(not(unix))]
pub fn get_socket_fd(_tokio_socket: &tokio::net::UdpSocket) -> i32 {
    -1 // fallback, will fail gracefully
}

/// Send raw bytes to a destination using libc::sendto() on a raw fd.
/// This bypasses tokio's async I/O and works from any thread.
#[cfg(unix)]
fn raw_sendto(fd: i32, data: &[u8], dest: &SocketAddr) -> Result<usize, std::io::Error> {
    match dest {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            };
            // SAFETY: sin is a valid sockaddr_in on the stack. We pass it to
            // sendto which only reads it during the syscall. The cast to
            // *const libc::sockaddr is the standard BSD sockets pattern.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    0,
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(sent as usize);
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
            };
            let sent = unsafe {
                libc::sendto(
                    fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    0,
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(sent as usize);
        }
    }
}

#[cfg(not(unix))]
fn raw_sendto(_fd: i32, _data: &[u8], _dest: &SocketAddr) -> Result<usize, std::io::Error> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "raw_sendto not available on this platform"))
}

/// Serializes and encrypts a ZTLP data packet synchronously.
///
/// Replicates the exact wire format of `TransportNode::send_data()` but
/// without any async or pipeline lock dependencies.
fn build_encrypted_packet(
    session_id: SessionId,
    send_key: &[u8; 32],
    seq: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(send_key.into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encryption failed: {}", e))?;

    let mut header = DataHeader::new(session_id, seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(send_key, &aad);

    let packet = ZtlpPacket::Data {
        header,
        payload: encrypted,
    };
    Ok(packet.serialize())
}

/// Configuration for spawning the ACK sender OS thread.
pub struct AckSenderConfig {
    /// Raw fd of the ORIGINAL tokio socket (not dup'd).
    /// We call libc::sendto() directly on this fd from the OS thread.
    /// UDP sendto() is thread-safe — concurrent recv (tokio) and send (OS thread) are safe.
    pub socket_fd: i32,
    pub session_id: SessionId,
    pub send_key: [u8; 32],
    pub peer_addr: SocketAddr,
    pub stop_flag: Arc<AtomicBool>,
    /// Shared seq counter with the main transport.
    /// Both the main async path and this OS thread atomically increment
    /// from the same counter, so seqs are interleaved and stay within
    /// the gateway's anti-replay window.
    pub seq_counter: Arc<AtomicU64>,
}

/// Spawn the dedicated ACK sender OS thread.
///
/// Returns a `std::sync::mpsc::Sender<Vec<u8>>` for sending plaintext
/// ACK/NACK frames. The thread handles:
/// - Coalescing: drains queued ACKs, sends only the latest (cumulative)
/// - NACK passthrough: NACKs (0x03) are sent immediately without coalescing
/// - Full ZTLP packet serialization + ChaCha20 encryption
/// - Seq allocation from shared AtomicU64 (within anti-replay window)
/// - Blocking send_to() on the dup'd socket (OS-scheduled, not tokio)
pub fn spawn_ack_sender(
    config: AckSenderConfig,
) -> std::sync::mpsc::Sender<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();

    std::thread::Builder::new()
        .name("ztlp-ack-sender".into())
        .spawn(move || {
            let AckSenderConfig {
                socket_fd,
                session_id,
                send_key,
                peer_addr,
                stop_flag,
                seq_counter,
            } = config;

            let mut sent_count: u64 = 0;
            let mut error_count: u64 = 0;
            const FRAME_NACK: u8 = 0x03;

            tracing::info!(
                "ack_sender: started on OS thread (raw sendto fd={}), peer={}, session={}",
                socket_fd,
                peer_addr,
                session_id
            );

            while let Ok(frame) = rx.recv() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                // Coalesce: drain queued ACKs, keep only latest (cumulative).
                // NACKs are sent immediately since they carry specific gap info.
                let mut latest_frame = frame;
                while let Ok(f) = rx.try_recv() {
                    if !f.is_empty() && f[0] == FRAME_NACK {
                        // NACK — send immediately
                        let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                        match build_encrypted_packet(session_id, &send_key, seq, &f) {
                            Ok(pkt) => {
                                if let Err(e) = raw_sendto(socket_fd, &pkt, &peer_addr) {
                                    error_count += 1;
                                    if error_count <= 5 {
                                        tracing::warn!("ack_sender: NACK send failed: {}", e);
                                    }
                                } else {
                                    sent_count += 1;
                                }
                            }
                            Err(e) => {
                                error_count += 1;
                                if error_count <= 5 {
                                    tracing::warn!("ack_sender: NACK encrypt failed: {}", e);
                                }
                            }
                        }
                    } else {
                        latest_frame = f; // newer ACK supersedes older
                    }
                }

                // Send the latest (coalesced) ACK
                let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                match build_encrypted_packet(session_id, &send_key, seq, &latest_frame) {
                    Ok(pkt) => {
                        if let Err(e) = raw_sendto(socket_fd, &pkt, &peer_addr) {
                            error_count += 1;
                            if error_count <= 5 {
                                tracing::warn!("ack_sender: ACK send failed: {}", e);
                            }
                        } else {
                            sent_count += 1;
                        }
                    }
                    Err(e) => {
                        error_count += 1;
                        if error_count <= 5 {
                            tracing::warn!("ack_sender: ACK encrypt failed: {}", e);
                        }
                    }
                }

                // Periodic status log
                if sent_count > 0 && sent_count % 500 == 0 {
                    tracing::info!(
                        "ack_sender: sent={} errors={} seq={}",
                        sent_count,
                        error_count,
                        seq_counter.load(Ordering::Relaxed)
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
