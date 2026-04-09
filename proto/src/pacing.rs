//! Universal buffer-based flow control for ZTLP tunnels.
//!
//! # Design Philosophy
//!
//! After studying WireGuard-Go, Nebula, and boringtun, the conclusion
//! is clear: **don't pace, just use large buffers.**
//!
//! Previous versions of this module tried to detect kernel HZ and choose
//! between sleep, spin-yield, and no-op strategies. This was fragile:
//!
//! - HZ=1000 (modern): sleep(10µs) → ~65µs. Fine, but unnecessary.
//! - HZ=300 (Arch default): spin-yield → 100% CPU.
//! - HZ=250 (KVM/older): spin-yield → 100% CPU.
//!
//! WireGuard-Go uses 7MB socket buffers and zero pacing. Nebula uses
//! `recvmmsg` batching and zero pacing. boringtun uses raw epoll and
//! zero pacing. They all work on every kernel.
//!
//! # Current Approach
//!
//! 1. **Set SO_RCVBUF and SO_SNDBUF to 7MB** (matching WireGuard-Go).
//! 2. **No pacing between sub-batches** — just `yield_now()` to let
//!    the tokio runtime service the receiver task.
//! 3. **Sub-batch sizing based on buffer capacity** — larger buffers
//!    allow larger bursts without overflow.
//!
//! This works universally: Linux (any HZ), macOS, Windows, loopback,
//! remote, any kernel version.

use std::net::SocketAddr;
use std::time::Duration;

use tracing::{info, warn};

/// Target socket buffer size: 7MB, matching WireGuard-Go.
///
/// This absorbs full-window bursts without needing inter-batch pacing.
/// On Linux, the kernel may double this value (net.core.rmem_max
/// permitting). If rmem_max is lower, we get whatever the kernel allows.
pub const TARGET_BUFFER_SIZE: usize = 7 * 1024 * 1024;

/// The pacing strategy selected for this tunnel session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacingStrategy {
    /// No pacing — just yield between sub-batches.
    /// This is now the only strategy. The enum is kept for backward
    /// compatibility with the tunnel code that references it.
    None,
}

impl std::fmt::Display for PacingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacingStrategy::None => write!(f, "none (buffer-based)"),
        }
    }
}

/// Detect the UDP receive buffer size for a socket.
///
/// Returns the effective buffer size in bytes, or None if detection fails.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn detect_recv_buffer(udp: &std::net::UdpSocket) -> Option<usize> {
    use std::os::unix::io::AsRawFd;
    let fd = udp.as_raw_fd();
    let mut buf_size: libc::c_int = 0;
    let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd is valid, buf_size and opt_len are properly sized stack variables.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut buf_size as *mut _ as *mut libc::c_void,
            &mut opt_len,
        )
    };
    if ret == 0 {
        Some(buf_size as usize)
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn detect_recv_buffer(_udp: &std::net::UdpSocket) -> Option<usize> {
    None
}

/// Detect the UDP send buffer size for a socket.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn detect_send_buffer(udp: &std::net::UdpSocket) -> Option<usize> {
    use std::os::unix::io::AsRawFd;
    let fd = udp.as_raw_fd();
    let mut buf_size: libc::c_int = 0;
    let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd is valid, buf_size and opt_len are properly sized stack variables.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &mut buf_size as *mut _ as *mut libc::c_void,
            &mut opt_len,
        )
    };
    if ret == 0 {
        Some(buf_size as usize)
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn detect_send_buffer(_udp: &std::net::UdpSocket) -> Option<usize> {
    None
}

/// Set both SO_RCVBUF and SO_SNDBUF to the target size.
///
/// On Linux, `setsockopt(SO_RCVBUF)` requests a buffer size, but the
/// kernel caps it at `net.core.rmem_max` (and doubles the value internally
/// for bookkeeping overhead). If you have CAP_NET_ADMIN, SO_RCVBUFFORCE
/// bypasses the cap.
///
/// Returns the actual (recv, send) buffer sizes after the attempt.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn set_socket_buffers(udp: &std::net::UdpSocket) -> (Option<usize>, Option<usize>) {
    use std::os::unix::io::AsRawFd;
    let fd = udp.as_raw_fd();
    let desired: libc::c_int = TARGET_BUFFER_SIZE as libc::c_int;

    // SAFETY: fd is valid, desired is a simple integer on the stack.
    unsafe {
        // On Linux, try SO_RCVBUFFORCE first (bypasses rmem_max, needs CAP_NET_ADMIN).
        // On macOS/BSD, SO_*BUFFORCE doesn't exist — go straight to SO_RCVBUF.
        #[allow(unused_mut, unused_assignments)]
        let mut rcv_set = false;
        #[cfg(target_os = "linux")]
        {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &desired as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
            {
                rcv_set = true;
            }
        }
        if !rcv_set {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &desired as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        #[allow(unused_mut, unused_assignments)]
        let mut snd_set = false;
        #[cfg(target_os = "linux")]
        {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUFFORCE,
                &desired as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
            {
                snd_set = true;
            }
        }
        if !snd_set {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &desired as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    (detect_recv_buffer(udp), detect_send_buffer(udp))
}

#[cfg(not(unix))]
pub fn set_socket_buffers(_udp: &std::net::UdpSocket) -> (Option<usize>, Option<usize>) {
    (None, None)
}

/// Check if a peer address is loopback.
fn is_loopback(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

/// System capabilities detected at bridge startup.
#[derive(Debug, Clone)]
pub struct SystemProfile {
    /// Effective UDP receive buffer size, or None.
    pub recv_buffer_size: Option<usize>,
    /// Effective UDP send buffer size, or None.
    pub send_buffer_size: Option<usize>,
    /// Whether the peer is on loopback.
    pub is_loopback: bool,
    /// The chosen pacing strategy (always None now).
    pub pacing: PacingStrategy,
    /// Recommended MAX_SUB_BATCH for this system.
    pub max_sub_batch: usize,
}

/// Detect system capabilities and configure socket buffers.
///
/// Called once at bridge startup. Sets socket buffers to 7MB (or as
/// large as the kernel allows), then determines sub-batch sizing
/// based on the actual buffer sizes achieved.
///
/// No HZ detection. No sleep granularity measurement. No spin-yield.
/// Just big buffers and let the kernel handle queuing.
pub fn detect_system(
    peer_addr: SocketAddr,
    udp_std: Option<&std::net::UdpSocket>,
    _target_pace: Duration, // kept for API compat, ignored
) -> SystemProfile {
    let is_loopback = is_loopback(&peer_addr);

    // Set buffers and read back actual sizes
    let (recv_buffer_size, send_buffer_size) = match udp_std {
        Some(sock) => set_socket_buffers(sock),
        None => (None, None),
    };

    // Sub-batch sizing based on recv buffer.
    // With 7MB buffers, we can afford large batches.
    // Even if the kernel caps us at a smaller size, we adapt.
    let effective_recv = recv_buffer_size.unwrap_or(0);
    let max_sub_batch = if effective_recv >= 4 * 1024 * 1024 {
        128 // 4MB+: WireGuard-Go style large batches
    } else if effective_recv >= 2 * 1024 * 1024 {
        64
    } else if effective_recv >= 512 * 1024 {
        32
    } else {
        // Small or unknown buffer — still no pacing, but smaller bursts
        16
    };

    let profile = SystemProfile {
        recv_buffer_size,
        send_buffer_size,
        is_loopback,
        pacing: PacingStrategy::None,
        max_sub_batch,
    };

    info!(
        "system profile: recv_buf={}, send_buf={}, loopback={}, pacing={}, sub_batch={}",
        profile
            .recv_buffer_size
            .map(|s| format!("{}KB", s / 1024))
            .unwrap_or_else(|| "unknown".into()),
        profile
            .send_buffer_size
            .map(|s| format!("{}KB", s / 1024))
            .unwrap_or_else(|| "unknown".into()),
        profile.is_loopback,
        profile.pacing,
        profile.max_sub_batch,
    );

    // Warn if buffers are significantly below target
    let target_kb = TARGET_BUFFER_SIZE / 1024;
    if let Some(recv) = recv_buffer_size {
        if recv < TARGET_BUFFER_SIZE / 2 {
            warn!(
                "UDP receive buffer is {}KB (target: {}KB). Throughput may be reduced.",
                recv / 1024,
                target_kb,
            );
            // On iOS, the kernel caps SO_RCVBUF at ~192KB-1MB.
            // At 1140-byte packets and 55Mbps, the buffer holds ~170 packets
            // and fills in ~28ms. Log this prominently for iOS diagnostics.
            if recv <= 1_048_576 {
                warn!(
                    "UDP recv buffer capped at {}KB by kernel (requested {}KB). \
                     This limits in-flight packets to ~{} before kernel drops begin. \
                     Run `sudo ztlp tune --apply` to fix.",
                    recv / 1024, target_kb, recv / 1200
                );
            } else {
                warn!(
                    "To fix: sudo sysctl -w net.core.rmem_max={} net.core.wmem_max={}",
                    TARGET_BUFFER_SIZE, TARGET_BUFFER_SIZE,
                );
                warn!("Or run: ztlp tune (applies optimal kernel settings)");
            }
        }
    }
    if let Some(send) = send_buffer_size {
        if send < TARGET_BUFFER_SIZE / 2 {
            warn!(
                "UDP send buffer is {}KB (target: {}KB). ACK sending may be delayed.",
                send / 1024, target_kb
            );
        }
    }

    profile
}

/// Execute the chosen pacing delay between sub-batches.
///
/// With buffer-based flow control, this is always a simple yield.
/// The yield lets the tokio runtime service the receiver task and
/// other timers (ACK, NACK, stall detection) between bursts.
#[inline]
pub fn pace(_strategy: &PacingStrategy) {
    // Just yield to the OS scheduler. This gives the receiver task
    // a chance to run and drain packets from the socket buffer.
    // No sleep, no spin — the buffer absorbs the burst.
    std::thread::yield_now();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_is_loopback_v4() {
        let addr: SocketAddr = "127.0.0.1:1234".parse().expect("valid addr");
        assert!(is_loopback(&addr));
        let addr: SocketAddr = "10.0.0.1:1234".parse().expect("valid addr");
        assert!(!is_loopback(&addr));
    }

    #[test]
    fn test_is_loopback_v6() {
        let addr: SocketAddr = "[::1]:1234".parse().expect("valid addr");
        assert!(is_loopback(&addr));
        let addr: SocketAddr = "[2001:db8::1]:1234".parse().expect("valid addr");
        assert!(!is_loopback(&addr));
    }

    #[test]
    fn test_pacing_strategy_display() {
        assert_eq!(format!("{}", PacingStrategy::None), "none (buffer-based)");
    }

    #[test]
    fn test_pace_does_not_block() {
        let start = Instant::now();
        for _ in 0..10_000 {
            pace(&PacingStrategy::None);
        }
        // 10,000 yield_now() calls should take well under 100ms
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_detect_system_loopback() {
        let addr: SocketAddr = "127.0.0.1:23095".parse().expect("valid addr");
        let profile = detect_system(addr, None, Duration::from_micros(10));
        assert!(profile.is_loopback);
        assert_eq!(profile.pacing, PacingStrategy::None);
    }

    #[test]
    fn test_detect_system_remote() {
        let addr: SocketAddr = "10.0.0.5:23095".parse().expect("valid addr");
        let profile = detect_system(addr, None, Duration::from_micros(10));
        assert!(!profile.is_loopback);
        assert_eq!(profile.pacing, PacingStrategy::None);
    }

    #[test]
    fn test_sub_batch_default_without_socket() {
        let addr: SocketAddr = "10.0.0.1:23095".parse().expect("valid addr");
        let profile = detect_system(addr, None, Duration::from_micros(10));
        // Without recv buffer info, defaults to 16 (conservative)
        assert_eq!(profile.max_sub_batch, 16);
    }

    #[test]
    fn test_target_buffer_size() {
        assert_eq!(TARGET_BUFFER_SIZE, 7 * 1024 * 1024);
    }
}
