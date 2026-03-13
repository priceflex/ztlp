//! Kernel-aware pacing for inter-batch delays.
//!
//! On modern Linux kernels (6.x+, HZ=1000), `std::thread::sleep(10µs)`
//! sleeps ~65µs — ideal for pacing UDP bursts between sub-batches.
//!
//! On older kernels (5.x, HZ=250), the minimum sleep is **4ms** (one
//! scheduler tick), which is 60-400× longer than intended. This kills
//! throughput for bulk transfers: 10 sub-batches × 4ms = 40ms of dead
//! time per TCP read.
//!
//! This module detects the system's actual timer resolution at startup
//! and chooses the best pacing strategy:
//!
//! - **Spin-yield:** On HZ=250 kernels where sleep granularity exceeds
//!   the target delay, use `thread::yield_now()` in a tight loop with
//!   a TSC/Instant check. Burns a core briefly but maintains throughput.
//!
//! - **Sleep:** On HZ=1000+ kernels where sleep granularity is
//!   acceptable (< 500µs), use `std::thread::sleep()` as before.
//!
//! - **None:** When the peer is on loopback (RTT < 0.5ms) AND the
//!   receive buffer is large (≥ 2MB), skip pacing entirely — the
//!   receiver can drain fast enough.
//!
//! ## Detection
//!
//! Timer resolution is measured once by sleeping for 1µs ten times and
//! taking the median actual elapsed time. This is done at bridge startup,
//! not on every packet.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::info;

/// The pacing strategy selected for this tunnel session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacingStrategy {
    /// Use `std::thread::sleep()` — kernel timer is precise enough.
    Sleep(Duration),
    /// Use a spin-yield loop — kernel timer is too coarse.
    SpinYield(Duration),
    /// No pacing needed — loopback with large recv buffer.
    None,
}

impl std::fmt::Display for PacingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacingStrategy::Sleep(d) => write!(f, "sleep({}µs)", d.as_micros()),
            PacingStrategy::SpinYield(d) => write!(f, "spin-yield({}µs)", d.as_micros()),
            PacingStrategy::None => write!(f, "none"),
        }
    }
}

/// Measure the actual granularity of `std::thread::sleep()` on this system.
///
/// Sleeps for 1µs ten times, collects the actual elapsed durations,
/// and returns the median. This gives a reliable estimate of the
/// kernel's minimum sleep granularity.
///
/// Typical results:
/// - HZ=1000 (modern): ~55-80µs
/// - HZ=250 (older/KVM): ~4000-4200µs
/// - HZ=100 (very old): ~10000µs
pub fn measure_sleep_granularity() -> Duration {
    let mut samples = Vec::with_capacity(10);
    // Warm up the scheduler — first sleep is often an outlier
    std::thread::sleep(Duration::from_micros(1));

    for _ in 0..10 {
        let start = Instant::now();
        std::thread::sleep(Duration::from_micros(1));
        samples.push(start.elapsed());
    }

    samples.sort();
    // Median (index 5 of 10 sorted samples)
    samples[5]
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
    /// Median sleep granularity measured by `measure_sleep_granularity()`.
    pub sleep_granularity: Duration,
    /// Kernel HZ estimate derived from sleep granularity.
    pub estimated_hz: u32,
    /// Effective UDP receive buffer size (after SO_RCVBUF set), or None.
    pub recv_buffer_size: Option<usize>,
    /// Whether the peer is on loopback.
    pub is_loopback: bool,
    /// The chosen pacing strategy.
    pub pacing: PacingStrategy,
    /// Recommended MAX_SUB_BATCH for this system.
    pub max_sub_batch: usize,
}

/// Detect system capabilities and choose the optimal pacing strategy.
///
/// Called once at bridge startup. The `target_pace` is the desired
/// inter-batch delay (e.g., 10µs for the original pacing).
///
/// The `peer_addr` is used to detect loopback connections.
/// The `udp_std` is a reference to the raw std UdpSocket for buffer detection.
pub fn detect_system(
    peer_addr: SocketAddr,
    udp_std: Option<&std::net::UdpSocket>,
    target_pace: Duration,
) -> SystemProfile {
    let sleep_granularity = measure_sleep_granularity();

    // Estimate kernel HZ from sleep granularity
    let granularity_us = sleep_granularity.as_micros() as u32;
    let estimated_hz = if granularity_us < 200 {
        1000 // Very precise — likely HZ=1000 or high-res timers
    } else if granularity_us < 2000 {
        500 // ~2ms tick
    } else if granularity_us < 6000 {
        250 // ~4ms tick (common in KVM/older kernels)
    } else {
        100 // ~10ms tick (very old kernels)
    };

    let is_loopback = is_loopback(&peer_addr);

    let recv_buffer_size = udp_std.and_then(detect_recv_buffer);

    // Choose pacing strategy
    let pacing = if is_loopback && recv_buffer_size.is_some_and(|sz| sz >= 2 * 1024 * 1024) {
        // Loopback with large recv buffer: no pacing needed.
        // The receiver drains fast enough on loopback and the buffer
        // can absorb full-window bursts.
        PacingStrategy::None
    } else if sleep_granularity <= target_pace * 50 {
        // Sleep granularity is within 50× of target — sleep is acceptable.
        // On HZ=1000, sleep(10µs) → ~65µs, which is 6.5× target. Fine.
        PacingStrategy::Sleep(target_pace)
    } else {
        // Sleep is too coarse (HZ=100-300: 3-10ms per sleep).
        // Use spin-yield but with a SHORT duration to avoid burning
        // 100% CPU. The spin only needs to last long enough to let
        // the receiver's UDP stack drain a sub-batch — not long enough
        // to visibly affect CPU usage.
        //
        // Key insight: on HZ=250/300, we DON'T need 4ms pacing —
        // we just need a brief ~50-100µs pause. The spin loop provides
        // this without the kernel timer overhead.
        //
        // The spin duration is kept short AND we limit it to only fire
        // between sub-batches (not per-packet), so total spin time per
        // window is bounded: 64 sub-batches × 100µs = 6.4ms max.
        let spin_target = if is_loopback {
            Duration::from_micros(10) // Loopback: minimal
        } else {
            Duration::from_micros(50) // Remote: moderate (was 100µs — halved)
        };
        PacingStrategy::SpinYield(spin_target)
    };

    // Adjust sub-batch size based on recv buffer
    let max_sub_batch = match recv_buffer_size {
        Some(sz) if sz >= 4 * 1024 * 1024 => 128, // 4MB+ buffer: larger batches OK
        Some(sz) if sz >= 2 * 1024 * 1024 => 64,  // 2MB+: default
        Some(sz) if sz >= 512 * 1024 => 32,       // 512KB+: conservative
        Some(_) => 16,                            // Small buffer: very conservative
        None => 64,                               // Can't detect: use default
    };

    let profile = SystemProfile {
        sleep_granularity,
        estimated_hz,
        recv_buffer_size,
        is_loopback,
        pacing,
        max_sub_batch,
    };

    info!(
        "system profile: HZ≈{}, sleep_granularity={}µs, recv_buf={}, loopback={}, pacing={}, sub_batch={}",
        profile.estimated_hz,
        profile.sleep_granularity.as_micros(),
        profile.recv_buffer_size.map(|s| format!("{}KB", s / 1024)).unwrap_or_else(|| "unknown".into()),
        profile.is_loopback,
        profile.pacing,
        profile.max_sub_batch,
    );

    profile
}

/// Execute the chosen pacing delay between sub-batches.
///
/// This is the hot-path replacement for `std::thread::sleep(10µs)`.
/// On modern kernels it sleeps. On old kernels it spin-yields.
/// On loopback with large buffers it's a no-op.
#[inline]
pub fn pace(strategy: &PacingStrategy) {
    match strategy {
        PacingStrategy::None => {
            // No pacing — just yield to let the tokio runtime service
            // other tasks (like the receiver).
            std::thread::yield_now();
        }
        PacingStrategy::Sleep(duration) => {
            std::thread::sleep(*duration);
        }
        PacingStrategy::SpinYield(duration) => {
            let deadline = Instant::now() + *duration;
            loop {
                std::thread::yield_now();
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_sleep_granularity() {
        let granularity = measure_sleep_granularity();
        // Should be at least 1µs and less than 100ms on any reasonable system
        assert!(granularity >= Duration::from_micros(1));
        assert!(granularity < Duration::from_millis(100));
    }

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
        assert_eq!(
            format!("{}", PacingStrategy::Sleep(Duration::from_micros(10))),
            "sleep(10µs)"
        );
        assert_eq!(
            format!("{}", PacingStrategy::SpinYield(Duration::from_micros(100))),
            "spin-yield(100µs)"
        );
        assert_eq!(format!("{}", PacingStrategy::None), "none");
    }

    #[test]
    fn test_pace_none_does_not_block() {
        let start = Instant::now();
        for _ in 0..1000 {
            pace(&PacingStrategy::None);
        }
        // 1000 yield_now() calls should take well under 100ms
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_pace_spin_yield_approximate_duration() {
        let strategy = PacingStrategy::SpinYield(Duration::from_micros(100));
        let start = Instant::now();
        for _ in 0..10 {
            pace(&strategy);
        }
        let elapsed = start.elapsed();
        // 10 × 100µs = ~1ms, allow generous bounds (0.5ms to 50ms)
        assert!(elapsed >= Duration::from_micros(500));
        assert!(elapsed < Duration::from_millis(50));
    }

    #[test]
    fn test_detect_system_loopback() {
        let addr: SocketAddr = "127.0.0.1:23095".parse().expect("valid addr");
        let profile = detect_system(addr, None, Duration::from_micros(10));
        assert!(profile.is_loopback);
        // Should pick either None or SpinYield for loopback, never Sleep
        // (because even on HZ=1000, loopback benefits from no-pacing)
        // Actually, on HZ=1000 with unknown recv buffer it picks Sleep,
        // which is fine too.
        assert!(profile.estimated_hz > 0);
    }

    #[test]
    fn test_detect_system_remote() {
        let addr: SocketAddr = "10.0.0.5:23095".parse().expect("valid addr");
        let profile = detect_system(addr, None, Duration::from_micros(10));
        assert!(!profile.is_loopback);
    }

    #[test]
    fn test_sub_batch_sizing() {
        // Verify the sub-batch scaling logic
        let addr: SocketAddr = "10.0.0.1:23095".parse().expect("valid addr");

        // Without recv buffer info, default to 64
        let profile = detect_system(addr, None, Duration::from_micros(10));
        assert_eq!(profile.max_sub_batch, 64);
    }
}
