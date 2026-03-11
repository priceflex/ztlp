//! ztlp-load — ZTLP Load Generator
//!
//! Generate high-volume ZTLP traffic for stress testing relays, gateways, and NS servers.
//!
//! # Examples
//!
//! ```bash
//! # Local pipeline admission throughput test
//! ztlp-load pipeline
//!
//! # Flood a relay with data packets
//! ztlp-load relay --target 127.0.0.1:4433 --rate 10000 --duration 30
//!
//! # Test gateway with concurrent sessions
//! ztlp-load gateway --target 127.0.0.1:4434 --sessions 100 --duration 60
//!
//! # Flood NS with lookup queries
//! ztlp-load ns --target 127.0.0.1:4435 --rate 5000
//! ```

use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use ztlp_proto::identity::NodeId;
use ztlp_proto::packet::{DataHeader, HandshakeHeader, MsgType, SessionId, ZtlpPacket};
use ztlp_proto::pipeline::{compute_header_auth_tag, Pipeline};
use ztlp_proto::session::SessionState;

/// ZTLP Load Generator — stress test ZTLP infrastructure.
#[derive(Parser, Debug)]
#[command(name = "ztlp-load", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Flood a relay with ZTLP data packets via UDP.
    Relay {
        /// Target relay address (host:port).
        #[arg(long)]
        target: String,

        /// Number of concurrent sessions to simulate.
        #[arg(long, default_value = "10")]
        sessions: usize,

        /// Target packets per second (0 = unlimited).
        #[arg(long, default_value = "1000")]
        rate: u64,

        /// Test duration in seconds.
        #[arg(long, default_value = "10")]
        duration: u64,

        /// Packet payload size in bytes.
        #[arg(long, default_value = "64")]
        packet_size: usize,

        /// Perform handshake warm-up before load test.
        #[arg(long)]
        warmup: bool,
    },

    /// Test a gateway with handshake + data traffic.
    Gateway {
        /// Target gateway address (host:port).
        #[arg(long)]
        target: String,

        /// Number of concurrent sessions.
        #[arg(long, default_value = "10")]
        sessions: usize,

        /// Target packets per second (0 = unlimited).
        #[arg(long, default_value = "1000")]
        rate: u64,

        /// Test duration in seconds.
        #[arg(long, default_value = "10")]
        duration: u64,

        /// Packet payload size in bytes.
        #[arg(long, default_value = "64")]
        packet_size: usize,

        /// Perform handshake warm-up before load test.
        #[arg(long)]
        warmup: bool,
    },

    /// Flood a name server with ZTLP lookup queries.
    Ns {
        /// Target NS address (host:port).
        #[arg(long)]
        target: String,

        /// Target queries per second (0 = unlimited).
        #[arg(long, default_value = "1000")]
        rate: u64,

        /// Test duration in seconds.
        #[arg(long, default_value = "10")]
        duration: u64,
    },

    /// Local pipeline admission throughput test (no network needed).
    Pipeline {
        /// Number of packets to process.
        #[arg(long, default_value = "1000000")]
        packets: u64,

        /// Number of registered sessions in the pipeline.
        #[arg(long, default_value = "1000")]
        sessions: usize,

        /// Include Layer 3 auth check (slower but realistic).
        #[arg(long)]
        full: bool,
    },
}

// ─────────────────────────────────────────────────────────────────────────
// Statistics tracking
// ─────────────────────────────────────────────────────────────────────────

struct LoadStats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    latencies_ns: std::sync::Mutex<Vec<u64>>,
}

impl LoadStats {
    fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latencies_ns: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_send(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn record_latency(&self, ns: u64) {
        if let Ok(mut lats) = self.latencies_ns.lock() {
            // Sample to avoid OOM — keep at most 100K samples
            if lats.len() < 100_000 {
                lats.push(ns);
            }
        }
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * p) as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn print_summary(stats: &LoadStats, elapsed: Duration) {
    let pkts = stats.packets_sent.load(Ordering::Relaxed);
    let bytes = stats.bytes_sent.load(Ordering::Relaxed);
    let errs = stats.errors.load(Ordering::Relaxed);
    let secs = elapsed.as_secs_f64();

    println!(
        "\n{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
    println!("  {}", "Load Test Summary".white().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
    println!("  {:<24} {:.2}s", "Duration:".bright_blue(), secs);
    println!(
        "  {:<24} {}",
        "Packets sent:".bright_blue(),
        format_number(pkts)
    );
    println!(
        "  {:<24} {}",
        "Bytes sent:".bright_blue(),
        format_bytes(bytes)
    );
    println!(
        "  {:<24} {}",
        "Errors:".bright_blue(),
        if errs > 0 {
            format!("{}", errs).red().to_string()
        } else {
            "0".green().to_string()
        }
    );
    println!(
        "  {:<24} {:.0} pps",
        "Throughput:".bright_blue(),
        pkts as f64 / secs
    );
    println!(
        "  {:<24} {}/s",
        "Bandwidth:".bright_blue(),
        format_bytes((bytes as f64 / secs) as u64)
    );

    // Latency percentiles
    if let Ok(mut lats) = stats.latencies_ns.lock() {
        if !lats.is_empty() {
            lats.sort_unstable();
            let p50 = percentile(&lats, 0.50);
            let p95 = percentile(&lats, 0.95);
            let p99 = percentile(&lats, 0.99);
            let min = lats[0];
            let max = lats[lats.len() - 1];

            println!("\n  {}", "Latency (send):".bright_blue());
            println!("    {:<20} {}", "p50:".dimmed(), format_duration_ns(p50));
            println!("    {:<20} {}", "p95:".dimmed(), format_duration_ns(p95));
            println!("    {:<20} {}", "p99:".dimmed(), format_duration_ns(p99));
            println!("    {:<20} {}", "min:".dimmed(), format_duration_ns(min));
            println!("    {:<20} {}", "max:".dimmed(), format_duration_ns(max));

            // Simple histogram
            println!("\n  {}", "Latency histogram:".bright_blue());
            let buckets = [
                ("  < 1µs", 0, 1_000),
                ("  1-10µs", 1_000, 10_000),
                ("  10-100µs", 10_000, 100_000),
                ("  100µs-1ms", 100_000, 1_000_000),
                ("  1-10ms", 1_000_000, 10_000_000),
                ("  > 10ms", 10_000_000, u64::MAX),
            ];
            let total = lats.len() as f64;
            for (label, lo, hi) in &buckets {
                let count = lats.iter().filter(|&&l| l >= *lo && l < *hi).count();
                let pct = count as f64 / total * 100.0;
                let bar_len = (pct / 2.0) as usize;
                let bar: String = "█".repeat(bar_len);
                println!(
                    "    {:<14} {:>6} ({:>5.1}%) {}",
                    label,
                    count,
                    pct,
                    bar.bright_green()
                );
            }
        }
    }

    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

fn format_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.2} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.2} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}

fn format_duration_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.2}µs", ns as f64 / 1_000.0)
    } else {
        format!("{}ns", ns)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Packet generation helpers
// ─────────────────────────────────────────────────────────────────────────

fn build_data_packet(
    session_id: SessionId,
    seq: u64,
    key: &[u8; 32],
    payload_size: usize,
) -> Vec<u8> {
    let mut hdr = DataHeader::new(session_id, seq);
    let aad = hdr.aad_bytes();
    hdr.header_auth_tag = compute_header_auth_tag(key, &aad);
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
    let pkt = ZtlpPacket::Data {
        header: hdr,
        payload,
    };
    pkt.serialize()
}

fn build_hello_packet() -> Vec<u8> {
    let hdr = HandshakeHeader::new(MsgType::Hello);
    let pkt = ZtlpPacket::Handshake {
        header: hdr,
        payload: vec![],
    };
    pkt.serialize()
}

fn build_ns_query_packet(session_id: SessionId, seq: u64, key: &[u8; 32]) -> Vec<u8> {
    // NS queries use handshake-type packets with MsgType::Data and a service ID lookup payload
    let mut hdr = HandshakeHeader::new(MsgType::Ping);
    hdr.session_id = session_id;
    hdr.packet_seq = seq;
    let aad = hdr.aad_bytes();
    hdr.header_auth_tag = compute_header_auth_tag(key, &aad);
    // Include a minimal query payload (service name)
    let payload = b"lookup:test-service.ztlp.local".to_vec();
    hdr.payload_len = payload.len() as u16;
    let pkt = ZtlpPacket::Handshake {
        header: hdr,
        payload,
    };
    pkt.serialize()
}

// ─────────────────────────────────────────────────────────────────────────
// Network load generators
// ─────────────────────────────────────────────────────────────────────────

async fn run_udp_load(
    target: &str,
    sessions_count: usize,
    rate: u64,
    duration_secs: u64,
    packet_size: usize,
    warmup: bool,
    build_packet: impl Fn(SessionId, u64, &[u8; 32], usize) -> Vec<u8> + Send + Sync + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("Invalid target address '{}': {}", target, e))?;

    println!("  {:<24} {}", "Target:".bright_blue(), target_addr);
    println!("  {:<24} {}", "Sessions:".bright_blue(), sessions_count);
    println!(
        "  {:<24} {} pps",
        "Rate:".bright_blue(),
        if rate == 0 {
            "unlimited".to_string()
        } else {
            rate.to_string()
        }
    );
    println!("  {:<24} {}s", "Duration:".bright_blue(), duration_secs);
    println!("  {:<24} {}B", "Packet size:".bright_blue(), packet_size);

    // Generate sessions
    let mut session_keys: Vec<(SessionId, [u8; 32])> = Vec::new();
    for _ in 0..sessions_count {
        let sid = SessionId::generate();
        let key: [u8; 32] = rand::random();
        session_keys.push((sid, key));
    }

    // Warmup: send HELLO packets
    if warmup {
        println!(
            "\n  {} Sending warm-up HELLO packets...",
            "⏳".bright_yellow()
        );
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        for _ in 0..sessions_count {
            let hello = build_hello_packet();
            if let Err(e) = sock.send_to(&hello, target_addr).await {
                eprintln!("  {} Warm-up send error: {}", "⚠".yellow(), e);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        println!("  {} Warm-up complete.", "✓".green());
    }

    let stats = Arc::new(LoadStats::new());
    let running = Arc::new(AtomicBool::new(true));

    // Create progress bar
    let pb = ProgressBar::new(duration_secs);
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}s | {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    // Spawn progress updater
    let stats_clone = stats.clone();
    let running_clone = running.clone();
    let pb_clone = pb.clone();
    let progress_handle = tokio::spawn(async move {
        let mut last_pkts = 0u64;
        while running_clone.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let current_pkts = stats_clone.packets_sent.load(Ordering::Relaxed);
            let pps = current_pkts - last_pkts;
            let errs = stats_clone.errors.load(Ordering::Relaxed);
            pb_clone.set_message(format!("{} pps | {} errors", format_number(pps), errs));
            pb_clone.inc(1);
            last_pkts = current_pkts;
        }
    });

    // Rate limiter: compute delay between packets per session
    let delay_per_packet = if rate > 0 {
        Duration::from_nanos((1_000_000_000u64 / rate).max(1))
    } else {
        Duration::ZERO
    };

    let build_packet = Arc::new(build_packet);

    // Spawn sender tasks (one per session for better concurrency)
    let mut handles = Vec::new();
    let start = Instant::now();

    for (sid, key) in session_keys {
        let stats = stats.clone();
        let running = running.clone();
        let target_addr = target_addr;
        let build_packet = build_packet.clone();

        let handle = tokio::spawn(async move {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to bind socket: {}", e);
                    return;
                }
            };

            let mut seq = 0u64;
            while running.load(Ordering::Relaxed) {
                let packet = build_packet(sid, seq, &key, packet_size);
                let send_start = Instant::now();
                match sock.send_to(&packet, target_addr).await {
                    Ok(n) => {
                        let latency = send_start.elapsed().as_nanos() as u64;
                        stats.record_send(n as u64);
                        stats.record_latency(latency);
                    }
                    Err(_) => {
                        stats.record_error();
                    }
                }
                seq += 1;

                if delay_per_packet > Duration::ZERO {
                    tokio::time::sleep(delay_per_packet).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
        });
        handles.push(handle);
    }

    // Wait for duration
    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    running.store(false, Ordering::Relaxed);
    let elapsed = start.elapsed();

    // Wait for tasks to finish
    for h in handles {
        let _ = h.await;
    }
    let _ = progress_handle.await;
    pb.finish_and_clear();

    print_summary(&stats, elapsed);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Pipeline benchmark
// ─────────────────────────────────────────────────────────────────────────

fn run_pipeline_benchmark(total_packets: u64, session_count: usize, full_auth: bool) {
    println!(
        "  {:<24} {}",
        "Packets:".bright_blue(),
        format_number(total_packets)
    );
    println!("  {:<24} {}", "Sessions:".bright_blue(), session_count);
    println!(
        "  {:<24} {}",
        "Full auth:".bright_blue(),
        if full_auth {
            "yes (L1+L2+L3)"
        } else {
            "no (L1+L2 only)"
        }
    );

    // Build pipeline with sessions
    let mut pipeline = Pipeline::new();
    let mut test_sessions: Vec<(SessionId, [u8; 32])> = Vec::new();

    for _ in 0..session_count {
        let sid = SessionId::generate();
        let node_id = NodeId::generate();
        let send_key: [u8; 32] = rand::random();
        let recv_key: [u8; 32] = rand::random();
        let session = SessionState::new(sid, node_id, send_key, recv_key, false);
        test_sessions.push((sid, recv_key));
        pipeline.register_session(session);
    }

    // Pre-build test packets for each session
    let packets: Vec<Vec<u8>> = test_sessions
        .iter()
        .enumerate()
        .map(|(i, (sid, key))| build_data_packet(*sid, i as u64, key, 64))
        .collect();

    let stats = Arc::new(LoadStats::new());

    println!(
        "\n  {} Running pipeline benchmark...\n",
        "⏳".bright_yellow()
    );

    let pb = ProgressBar::new(total_packets);
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} | {per_sec}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    let start = Instant::now();
    let num_packets = packets.len();

    for i in 0..total_packets {
        let pkt = &packets[i as usize % num_packets];
        let op_start = Instant::now();

        if full_auth {
            std::hint::black_box(pipeline.process(pkt));
        } else {
            // Just L1 + L2
            let r1 = pipeline.layer1_magic_check(pkt);
            if r1 == ztlp_proto::pipeline::AdmissionResult::Pass {
                std::hint::black_box(pipeline.layer2_session_check(pkt));
            }
        }

        let latency = op_start.elapsed().as_nanos() as u64;
        stats.record_send(pkt.len() as u64);
        stats.record_latency(latency);

        if i % 10_000 == 0 {
            pb.set_position(i);
        }
    }

    let elapsed = start.elapsed();
    pb.finish_and_clear();

    print_summary(&stats, elapsed);

    // Also show pipeline counters
    let snap = pipeline.counters.snapshot();
    println!("\n  {}", "Pipeline counters:".bright_blue());
    println!(
        "    L1 drops: {}, L2 drops: {}, L3 drops: {}, passed: {}",
        snap.layer1_drops, snap.layer2_drops, snap.layer3_drops, snap.passed
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
    println!("  {}", "ZTLP Load Generator".white().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );

    match cli.command {
        Command::Relay {
            target,
            sessions,
            rate,
            duration,
            packet_size,
            warmup,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "Relay flood (UDP data packets)".bright_magenta()
            );
            if let Err(e) = run_udp_load(
                &target,
                sessions,
                rate,
                duration,
                packet_size,
                warmup,
                |sid, seq, key, psize| build_data_packet(sid, seq, key, psize),
            )
            .await
            {
                eprintln!("\n  {} {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
        Command::Gateway {
            target,
            sessions,
            rate,
            duration,
            packet_size,
            warmup,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "Gateway test (handshake + data)".bright_magenta()
            );
            if let Err(e) = run_udp_load(
                &target,
                sessions,
                rate,
                duration,
                packet_size,
                warmup,
                |sid, seq, key, psize| {
                    // Alternate between hello and data packets
                    if seq == 0 {
                        build_hello_packet()
                    } else {
                        build_data_packet(sid, seq, key, psize)
                    }
                },
            )
            .await
            {
                eprintln!("\n  {} {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
        Command::Ns {
            target,
            rate,
            duration,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "NS query flood".bright_magenta()
            );
            if let Err(e) = run_udp_load(
                &target,
                1,
                rate,
                duration,
                0,
                false,
                |sid, seq, key, _psize| build_ns_query_packet(sid, seq, key),
            )
            .await
            {
                eprintln!("\n  {} {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
        Command::Pipeline {
            packets,
            sessions,
            full,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "Local pipeline benchmark".bright_magenta()
            );
            run_pipeline_benchmark(packets, sessions, full);
        }
    }
}
