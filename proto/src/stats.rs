//! Tunnel debug statistics and performance instrumentation.
//!
//! When the `ZTLP_DEBUG` environment variable is set (or tracing is at DEBUG
//! level), the tunnel emits detailed per-batch and periodic summary stats
//! to help identify performance bottlenecks.
//!
//! ## Usage
//!
//! Run any ZTLP tunnel command with debug output:
//! ```text
//! ZTLP_DEBUG=1 ztlp connect ...
//! ```
//!
//! Or use the RUST_LOG filter:
//! ```text
//! RUST_LOG=ztlp_proto::stats=debug ztlp connect ...
//! ```
//!
//! ## Output Format
//!
//! Per-batch lines (every send/recv):
//! ```text
//! [TX] batch=14 pkts=8 bytes=131072 encrypt=42µs send=18µs strategy=sendmmsg window=2048/1024 data_seq=112
//! [RX] batch=7 pkts=3 gro_segments=3 bytes=49152 recv=12µs decrypt=31µs reassembly=2µs delivered=3 buffered=0
//! ```
//!
//! Periodic summary (every 1 second):
//! ```text
//! [STATS] elapsed=5.0s tx_bytes=52428800 rx_bytes=52428800 tx_rate=100.0MB/s rx_rate=100.0MB/s
//!         pkts_sent=3200 pkts_recv=3200 retransmits=2 nacks=1 acks=100
//!         cwnd=512.0 ssthresh=1024.0 srtt=0.4ms rto=201.6ms window_stalls=0
//!         gso=sendmmsg gro=available send_strategy=sendmmsg
//!         encrypt_time=134ms(2.7%) send_time=89ms(1.8%) recv_time=67ms(1.3%) decrypt_time=102ms(2.0%)
//!         tcp_read_time=4201ms(84.0%) tcp_write_time=312ms(6.2%) reassembly_time=45ms(0.9%)
//! ```

#![deny(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info};

// ─── Debug mode detection ───────────────────────────────────────────────────

/// Check if debug stats are enabled.
/// Returns true if ZTLP_DEBUG is set or tracing is at debug level for this module.
pub fn debug_enabled() -> bool {
    std::env::var("ZTLP_DEBUG").is_ok() || tracing::enabled!(tracing::Level::DEBUG)
}

// ─── Timing helper ──────────────────────────────────────────────────────────

/// A scoped timer that records elapsed time into an AtomicU64 (in nanoseconds).
pub struct ScopedTimer {
    start: Instant,
    accumulator: Arc<AtomicU64>,
}

impl ScopedTimer {
    pub fn start(accumulator: Arc<AtomicU64>) -> Self {
        Self {
            start: Instant::now(),
            accumulator,
        }
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        let elapsed_ns = self.start.elapsed().as_nanos() as u64;
        self.accumulator.fetch_add(elapsed_ns, Ordering::Relaxed);
    }
}

/// Measure a block and return (result, elapsed Duration).
pub fn timed<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}

/// Measure an async block and return (result, elapsed Duration).
pub async fn timed_async<F, Fut, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = R>,
{
    let start = Instant::now();
    let result = f().await;
    (result, start.elapsed())
}

// ─── Per-batch stats ────────────────────────────────────────────────────────

/// Stats for a single send batch (TCP → ZTLP direction).
#[derive(Debug)]
pub struct TxBatchStats {
    /// Batch number (sequential counter).
    pub batch_num: u64,
    /// Number of ZTLP packets in this batch.
    pub packet_count: usize,
    /// Total bytes read from TCP (pre-encryption).
    pub tcp_bytes: usize,
    /// Total bytes sent over UDP (post-encryption, with headers).
    pub udp_bytes: usize,
    /// Time spent reading from TCP.
    pub tcp_read_time: Duration,
    /// Time spent encrypting payloads.
    pub encrypt_time: Duration,
    /// Time spent in batch send (GSO/sendmmsg/individual).
    pub send_time: Duration,
    /// Time spent waiting for send window.
    pub window_wait_time: Duration,
    /// Send strategy used (GSO/sendmmsg/individual).
    pub send_strategy: String,
    /// Current data_seq after this batch.
    pub data_seq: u64,
    /// Current congestion window.
    pub cwnd: f64,
    /// Current effective send window.
    pub effective_window: u64,
    /// Whether we had to wait for window space.
    pub window_stall: bool,
}

impl TxBatchStats {
    pub fn log(&self) {
        if !debug_enabled() {
            return;
        }
        debug!(
            "[TX] batch={} pkts={} tcp_bytes={} udp_bytes={} tcp_read={} encrypt={} send={} \
             strategy={} data_seq={} cwnd={:.0} window={} {}",
            self.batch_num,
            self.packet_count,
            self.tcp_bytes,
            self.udp_bytes,
            format_duration(self.tcp_read_time),
            format_duration(self.encrypt_time),
            format_duration(self.send_time),
            self.send_strategy,
            self.data_seq,
            self.cwnd,
            self.effective_window,
            if self.window_stall {
                "WINDOW_STALL"
            } else {
                ""
            },
        );
    }
}

/// Stats for a single receive batch (ZTLP → TCP direction).
#[derive(Debug)]
pub struct RxBatchStats {
    /// Batch number (sequential counter).
    pub batch_num: u64,
    /// Number of GRO segments in this recv (1 = no coalescing).
    pub gro_segments: usize,
    /// Number of packets successfully processed (after pipeline/decrypt).
    pub packets_processed: usize,
    /// Number of packets dropped (pipeline reject, decrypt fail, etc.).
    pub packets_dropped: usize,
    /// Total bytes received from UDP.
    pub udp_bytes: usize,
    /// Total payload bytes delivered to TCP.
    pub tcp_bytes: usize,
    /// Time spent in recvmsg (including GRO).
    pub recv_time: Duration,
    /// Time spent in pipeline admission.
    pub pipeline_time: Duration,
    /// Time spent decrypting payloads.
    pub decrypt_time: Duration,
    /// Time spent in reassembly buffer operations.
    pub reassembly_time: Duration,
    /// Time spent writing to TCP.
    pub tcp_write_time: Duration,
    /// Number of packets delivered in-order to TCP this batch.
    pub delivered_count: usize,
    /// Number of packets buffered out-of-order.
    pub buffered_count: usize,
    /// Current reassembly buffer depth.
    pub reasm_buffer_depth: usize,
}

impl RxBatchStats {
    pub fn log(&self) {
        if !debug_enabled() {
            return;
        }
        debug!(
            "[RX] batch={} gro_segs={} pkts_ok={} pkts_drop={} udp_bytes={} tcp_bytes={} \
             recv={} pipeline={} decrypt={} reassembly={} tcp_write={} \
             delivered={} buffered={} reasm_depth={}",
            self.batch_num,
            self.gro_segments,
            self.packets_processed,
            self.packets_dropped,
            self.udp_bytes,
            self.tcp_bytes,
            format_duration(self.recv_time),
            format_duration(self.pipeline_time),
            format_duration(self.reassembly_time),
            format_duration(self.decrypt_time),
            format_duration(self.tcp_write_time),
            self.delivered_count,
            self.buffered_count,
            self.reasm_buffer_depth,
        );
    }
}

// ─── Cumulative tunnel stats ────────────────────────────────────────────────

/// Cumulative statistics for the entire tunnel lifetime.
/// All fields are atomic for lock-free updates from send/recv tasks.
pub struct TunnelStats {
    pub enabled: bool,
    pub start_time: Instant,

    // Counters
    pub tx_batches: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes_tcp: AtomicU64,
    pub tx_bytes_udp: AtomicU64,
    pub rx_batches: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes_udp: AtomicU64,
    pub rx_bytes_tcp: AtomicU64,
    pub rx_packets_dropped: AtomicU64,
    pub rx_gro_segments: AtomicU64,
    pub retransmits: AtomicU64,
    pub nacks_sent: AtomicU64,
    pub nacks_received: AtomicU64,
    pub acks_sent: AtomicU64,
    pub acks_received: AtomicU64,
    pub window_stalls: AtomicU64,
    pub delivered_packets: AtomicU64,
    pub buffered_packets: AtomicU64,

    // Cumulative time (nanoseconds)
    pub tcp_read_ns: AtomicU64,
    pub encrypt_ns: AtomicU64,
    pub send_ns: AtomicU64,
    pub window_wait_ns: AtomicU64,
    pub recv_ns: AtomicU64,
    pub pipeline_ns: AtomicU64,
    pub decrypt_ns: AtomicU64,
    pub reassembly_ns: AtomicU64,
    pub tcp_write_ns: AtomicU64,

    // Snapshot for periodic rate calculation
    pub last_report: std::sync::Mutex<Instant>,
    pub last_tx_bytes: AtomicU64,
    pub last_rx_bytes: AtomicU64,

    // Send strategy tracking
    pub send_strategy: std::sync::Mutex<String>,
    pub gro_available: AtomicBool,
}

impl Default for TunnelStats {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelStats {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            enabled: debug_enabled(),
            start_time: now,
            tx_batches: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes_tcp: AtomicU64::new(0),
            tx_bytes_udp: AtomicU64::new(0),
            rx_batches: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes_udp: AtomicU64::new(0),
            rx_bytes_tcp: AtomicU64::new(0),
            rx_packets_dropped: AtomicU64::new(0),
            rx_gro_segments: AtomicU64::new(0),
            retransmits: AtomicU64::new(0),
            nacks_sent: AtomicU64::new(0),
            nacks_received: AtomicU64::new(0),
            acks_sent: AtomicU64::new(0),
            acks_received: AtomicU64::new(0),
            window_stalls: AtomicU64::new(0),
            delivered_packets: AtomicU64::new(0),
            buffered_packets: AtomicU64::new(0),
            tcp_read_ns: AtomicU64::new(0),
            encrypt_ns: AtomicU64::new(0),
            send_ns: AtomicU64::new(0),
            window_wait_ns: AtomicU64::new(0),
            recv_ns: AtomicU64::new(0),
            pipeline_ns: AtomicU64::new(0),
            decrypt_ns: AtomicU64::new(0),
            reassembly_ns: AtomicU64::new(0),
            tcp_write_ns: AtomicU64::new(0),
            last_report: std::sync::Mutex::new(now),
            last_tx_bytes: AtomicU64::new(0),
            last_rx_bytes: AtomicU64::new(0),
            send_strategy: std::sync::Mutex::new("unknown".to_string()),
            gro_available: AtomicBool::new(false),
        }
    }

    /// Record a completed TX batch.
    pub fn record_tx(&self, batch: &TxBatchStats) {
        self.tx_batches.fetch_add(1, Ordering::Relaxed);
        self.tx_packets
            .fetch_add(batch.packet_count as u64, Ordering::Relaxed);
        self.tx_bytes_tcp
            .fetch_add(batch.tcp_bytes as u64, Ordering::Relaxed);
        self.tx_bytes_udp
            .fetch_add(batch.udp_bytes as u64, Ordering::Relaxed);
        self.tcp_read_ns
            .fetch_add(batch.tcp_read_time.as_nanos() as u64, Ordering::Relaxed);
        self.encrypt_ns
            .fetch_add(batch.encrypt_time.as_nanos() as u64, Ordering::Relaxed);
        self.send_ns
            .fetch_add(batch.send_time.as_nanos() as u64, Ordering::Relaxed);
        self.window_wait_ns
            .fetch_add(batch.window_wait_time.as_nanos() as u64, Ordering::Relaxed);
        if batch.window_stall {
            self.window_stalls.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut s) = self.send_strategy.lock() {
            *s = batch.send_strategy.clone();
        }
    }

    /// Record a completed RX batch.
    pub fn record_rx(&self, batch: &RxBatchStats) {
        self.rx_batches.fetch_add(1, Ordering::Relaxed);
        self.rx_packets
            .fetch_add(batch.packets_processed as u64, Ordering::Relaxed);
        self.rx_packets_dropped
            .fetch_add(batch.packets_dropped as u64, Ordering::Relaxed);
        self.rx_bytes_udp
            .fetch_add(batch.udp_bytes as u64, Ordering::Relaxed);
        self.rx_bytes_tcp
            .fetch_add(batch.tcp_bytes as u64, Ordering::Relaxed);
        self.rx_gro_segments
            .fetch_add(batch.gro_segments as u64, Ordering::Relaxed);
        self.recv_ns
            .fetch_add(batch.recv_time.as_nanos() as u64, Ordering::Relaxed);
        self.pipeline_ns
            .fetch_add(batch.pipeline_time.as_nanos() as u64, Ordering::Relaxed);
        self.decrypt_ns
            .fetch_add(batch.decrypt_time.as_nanos() as u64, Ordering::Relaxed);
        self.reassembly_ns
            .fetch_add(batch.reassembly_time.as_nanos() as u64, Ordering::Relaxed);
        self.tcp_write_ns
            .fetch_add(batch.tcp_write_time.as_nanos() as u64, Ordering::Relaxed);
        self.delivered_packets
            .fetch_add(batch.delivered_count as u64, Ordering::Relaxed);
        self.buffered_packets
            .fetch_add(batch.buffered_count as u64, Ordering::Relaxed);
    }

    /// Check if it's time to emit a periodic summary (every ~1 second).
    /// Returns true if a report was emitted.
    pub fn maybe_report(&self, cwnd: f64, ssthresh: f64, srtt_ms: f64, rto_ms: f64) -> bool {
        if !self.enabled {
            return false;
        }

        let now = Instant::now();
        let mut last = match self.last_report.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if now.duration_since(*last) < Duration::from_secs(1) {
            return false;
        }

        let interval = now.duration_since(*last);
        *last = now;

        let total_elapsed = self.start_time.elapsed();
        let total_secs = total_elapsed.as_secs_f64();
        let interval_secs = interval.as_secs_f64();

        // Current totals
        let tx_tcp = self.tx_bytes_tcp.load(Ordering::Relaxed);
        let rx_tcp = self.rx_bytes_tcp.load(Ordering::Relaxed);
        let tx_udp = self.tx_bytes_udp.load(Ordering::Relaxed);
        let rx_udp = self.rx_bytes_udp.load(Ordering::Relaxed);

        // Interval rates
        let prev_tx = self.last_tx_bytes.swap(tx_tcp, Ordering::Relaxed);
        let prev_rx = self.last_rx_bytes.swap(rx_tcp, Ordering::Relaxed);
        let tx_rate = if interval_secs > 0.0 {
            (tx_tcp - prev_tx) as f64 / interval_secs
        } else {
            0.0
        };
        let rx_rate = if interval_secs > 0.0 {
            (rx_tcp - prev_rx) as f64 / interval_secs
        } else {
            0.0
        };

        // Time breakdowns
        let tcp_read = self.tcp_read_ns.load(Ordering::Relaxed);
        let encrypt = self.encrypt_ns.load(Ordering::Relaxed);
        let send = self.send_ns.load(Ordering::Relaxed);
        let window_wait = self.window_wait_ns.load(Ordering::Relaxed);
        let recv = self.recv_ns.load(Ordering::Relaxed);
        let pipeline = self.pipeline_ns.load(Ordering::Relaxed);
        let decrypt = self.decrypt_ns.load(Ordering::Relaxed);
        let reassembly = self.reassembly_ns.load(Ordering::Relaxed);
        let tcp_write = self.tcp_write_ns.load(Ordering::Relaxed);
        let total_ns = total_elapsed.as_nanos() as u64;

        let strategy = self
            .send_strategy
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        let gro = self.gro_available.load(Ordering::Relaxed);

        info!(
            "\n[STATS] elapsed={:.1}s tx_tcp={} rx_tcp={} tx_udp={} rx_udp={} \
             tx_rate={}/s rx_rate={}/s",
            total_secs,
            format_bytes(tx_tcp),
            format_bytes(rx_tcp),
            format_bytes(tx_udp),
            format_bytes(rx_udp),
            format_bytes(tx_rate as u64),
            format_bytes(rx_rate as u64),
        );

        info!(
            "        pkts_sent={} pkts_recv={} pkts_drop={} retransmits={} \
             nacks_sent={} nacks_recv={} acks_sent={} acks_recv={}",
            self.tx_packets.load(Ordering::Relaxed),
            self.rx_packets.load(Ordering::Relaxed),
            self.rx_packets_dropped.load(Ordering::Relaxed),
            self.retransmits.load(Ordering::Relaxed),
            self.nacks_sent.load(Ordering::Relaxed),
            self.nacks_received.load(Ordering::Relaxed),
            self.acks_sent.load(Ordering::Relaxed),
            self.acks_received.load(Ordering::Relaxed),
        );

        info!(
            "        cwnd={:.0} ssthresh={:.0} srtt={:.1}ms rto={:.0}ms window_stalls={} \
             delivered={} buffered={} gro_segments={}",
            cwnd,
            ssthresh,
            srtt_ms,
            rto_ms,
            self.window_stalls.load(Ordering::Relaxed),
            self.delivered_packets.load(Ordering::Relaxed),
            self.buffered_packets.load(Ordering::Relaxed),
            self.rx_gro_segments.load(Ordering::Relaxed),
        );

        info!(
            "        strategy={} gro={} batches_tx={} batches_rx={}",
            strategy,
            if gro { "enabled" } else { "unavailable" },
            self.tx_batches.load(Ordering::Relaxed),
            self.rx_batches.load(Ordering::Relaxed),
        );

        // Time breakdown as percentages of total elapsed
        if total_ns > 0 {
            info!(
                "        time: tcp_read={}({:.1}%) encrypt={}({:.1}%) send={}({:.1}%) \
                 window_wait={}({:.1}%)",
                format_ns(tcp_read),
                pct(tcp_read, total_ns),
                format_ns(encrypt),
                pct(encrypt, total_ns),
                format_ns(send),
                pct(send, total_ns),
                format_ns(window_wait),
                pct(window_wait, total_ns),
            );
            info!(
                "              recv={}({:.1}%) pipeline={}({:.1}%) decrypt={}({:.1}%) \
                 reassembly={}({:.1}%) tcp_write={}({:.1}%)",
                format_ns(recv),
                pct(recv, total_ns),
                format_ns(pipeline),
                pct(pipeline, total_ns),
                format_ns(decrypt),
                pct(decrypt, total_ns),
                format_ns(reassembly),
                pct(reassembly, total_ns),
                format_ns(tcp_write),
                pct(tcp_write, total_ns),
            );
        }

        true
    }

    /// Emit a final summary when the tunnel closes.
    pub fn final_report(&self, cwnd: f64, ssthresh: f64, srtt_ms: f64, rto_ms: f64) {
        if !self.enabled {
            return;
        }

        let total = self.start_time.elapsed();
        let total_secs = total.as_secs_f64();
        let tx_tcp = self.tx_bytes_tcp.load(Ordering::Relaxed);
        let rx_tcp = self.rx_bytes_tcp.load(Ordering::Relaxed);

        info!("╔══════════════════════════════════════════════════════════╗");
        info!("║           ZTLP Tunnel — Final Statistics                ║");
        info!("╠══════════════════════════════════════════════════════════╣");
        info!("║ Duration:     {:<42} ║", format!("{:.2}s", total_secs));
        info!(
            "║ TX (TCP→ZTLP): {:<41} ║",
            format!(
                "{} ({}/s)",
                format_bytes(tx_tcp),
                format_bytes(if total_secs > 0.0 {
                    (tx_tcp as f64 / total_secs) as u64
                } else {
                    0
                })
            )
        );
        info!(
            "║ RX (ZTLP→TCP): {:<41} ║",
            format!(
                "{} ({}/s)",
                format_bytes(rx_tcp),
                format_bytes(if total_secs > 0.0 {
                    (rx_tcp as f64 / total_secs) as u64
                } else {
                    0
                })
            )
        );
        info!(
            "║ Packets sent:  {:<41} ║",
            format!("{}", self.tx_packets.load(Ordering::Relaxed))
        );
        info!(
            "║ Packets recv:  {:<41} ║",
            format!("{}", self.rx_packets.load(Ordering::Relaxed))
        );
        info!(
            "║ Dropped:       {:<41} ║",
            format!("{}", self.rx_packets_dropped.load(Ordering::Relaxed))
        );
        info!(
            "║ Retransmits:   {:<41} ║",
            format!("{}", self.retransmits.load(Ordering::Relaxed))
        );
        info!(
            "║ Window stalls: {:<41} ║",
            format!("{}", self.window_stalls.load(Ordering::Relaxed))
        );
        info!("║                                                          ║");
        info!("║ Congestion:                                              ║");
        info!(
            "║   cwnd={:.0}  ssthresh={:.0}  srtt={:.1}ms  rto={:.0}ms      ║",
            cwnd, ssthresh, srtt_ms, rto_ms
        );

        let strategy = self
            .send_strategy
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        let gro = self.gro_available.load(Ordering::Relaxed);
        info!("║                                                          ║");
        info!("║ Transport:                                               ║");
        info!(
            "║   send_strategy={}  gro={}                   ║",
            strategy,
            if gro { "enabled" } else { "off" }
        );

        // Time breakdown
        let total_ns = total.as_nanos() as u64;
        if total_ns > 0 {
            let items = [
                ("tcp_read", self.tcp_read_ns.load(Ordering::Relaxed)),
                ("encrypt", self.encrypt_ns.load(Ordering::Relaxed)),
                ("send", self.send_ns.load(Ordering::Relaxed)),
                ("window_wait", self.window_wait_ns.load(Ordering::Relaxed)),
                ("recv", self.recv_ns.load(Ordering::Relaxed)),
                ("pipeline", self.pipeline_ns.load(Ordering::Relaxed)),
                ("decrypt", self.decrypt_ns.load(Ordering::Relaxed)),
                ("reassembly", self.reassembly_ns.load(Ordering::Relaxed)),
                ("tcp_write", self.tcp_write_ns.load(Ordering::Relaxed)),
            ];

            info!("║                                                          ║");
            info!("║ Time Breakdown:                                          ║");
            for (name, ns) in &items {
                info!(
                    "║   {:<14} {:>10}  ({:>5.1}%)                       ║",
                    name,
                    format_ns(*ns),
                    pct(*ns, total_ns),
                );
            }
        }
        info!("╚══════════════════════════════════════════════════════════╝");
    }
}

// ─── Formatting helpers ─────────────────────────────────────────────────────

fn format_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us >= 1_000_000 {
        format!("{:.1}s", d.as_secs_f64())
    } else if us >= 1_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{}µs", us)
    }
}

fn format_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.0}µs", ns as f64 / 1_000.0)
    } else {
        format!("{}ns", ns)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2}GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

fn pct(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_micros(42)), "42µs");
        assert_eq!(format_duration(Duration::from_micros(1500)), "1.5ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2.0s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1500), "1.5KB");
        assert_eq!(format_bytes(5_242_880), "5.0MB");
        assert_eq!(format_bytes(1_073_741_824), "1.00GB");
    }

    #[test]
    fn test_format_ns() {
        assert_eq!(format_ns(500), "500ns");
        assert_eq!(format_ns(42_000), "42µs");
        assert_eq!(format_ns(1_500_000), "1.5ms");
        assert_eq!(format_ns(2_500_000_000), "2.50s");
    }

    #[test]
    fn test_pct() {
        assert!((pct(50, 100) - 50.0).abs() < 0.001);
        assert!((pct(0, 100) - 0.0).abs() < 0.001);
        assert!((pct(0, 0) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_tunnel_stats_new() {
        let stats = TunnelStats::new();
        assert_eq!(stats.tx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tx_batch_stats_record() {
        let stats = TunnelStats::new();
        let batch = TxBatchStats {
            batch_num: 1,
            packet_count: 8,
            tcp_bytes: 131072,
            udp_bytes: 132000,
            tcp_read_time: Duration::from_micros(50),
            encrypt_time: Duration::from_micros(42),
            send_time: Duration::from_micros(18),
            window_wait_time: Duration::ZERO,
            send_strategy: "sendmmsg".to_string(),
            data_seq: 8,
            cwnd: 512.0,
            effective_window: 2048,
            window_stall: false,
        };
        stats.record_tx(&batch);
        assert_eq!(stats.tx_packets.load(Ordering::Relaxed), 8);
        assert_eq!(stats.tx_bytes_tcp.load(Ordering::Relaxed), 131072);
        assert_eq!(stats.window_stalls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_rx_batch_stats_record() {
        let stats = TunnelStats::new();
        let batch = RxBatchStats {
            batch_num: 1,
            gro_segments: 3,
            packets_processed: 3,
            packets_dropped: 0,
            udp_bytes: 49152,
            tcp_bytes: 48000,
            recv_time: Duration::from_micros(12),
            pipeline_time: Duration::from_micros(5),
            decrypt_time: Duration::from_micros(31),
            reassembly_time: Duration::from_micros(2),
            tcp_write_time: Duration::from_micros(8),
            delivered_count: 3,
            buffered_count: 0,
            reasm_buffer_depth: 0,
        };
        stats.record_rx(&batch);
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 3);
        assert_eq!(stats.rx_gro_segments.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_scoped_timer() {
        let acc = Arc::new(AtomicU64::new(0));
        {
            let _timer = ScopedTimer::start(acc.clone());
            std::thread::sleep(Duration::from_millis(1));
        }
        // Should have accumulated at least ~1ms = 1_000_000 ns
        assert!(acc.load(Ordering::Relaxed) > 500_000);
    }

    #[test]
    fn test_timed() {
        let (result, duration) = timed(|| {
            std::thread::sleep(Duration::from_millis(1));
            42
        });
        assert_eq!(result, 42);
        assert!(duration.as_micros() > 500);
    }
}
