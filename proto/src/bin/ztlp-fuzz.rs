//! ztlp-fuzz — ZTLP Protocol Fuzzer
//!
//! Mutation-based fuzzing of the ZTLP protocol to find parser/handler bugs.
//!
//! # Examples
//!
//! ```bash
//! # Fuzz the local packet parser (no network needed)
//! ztlp-fuzz local --iterations 100000
//!
//! # Fuzz with a specific strategy
//! ztlp-fuzz local --strategy bitflip --seed 42
//!
//! # Fuzz a live relay
//! ztlp-fuzz relay --target 127.0.0.1:4433 --iterations 10000
//!
//! # Fuzz a live gateway
//! ztlp-fuzz gateway --target 127.0.0.1:4434 --iterations 10000 --strategy all
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use ztlp_proto::packet::{
    DataHeader, HandshakeHeader, MsgType, SessionId, ZtlpPacket, HANDSHAKE_HEADER_SIZE,
};
use ztlp_proto::pipeline::compute_header_auth_tag;

/// ZTLP Protocol Fuzzer — mutation-based fuzzing for ZTLP protocol analysis.
#[derive(Parser, Debug)]
#[command(name = "ztlp-fuzz", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fuzz the local Rust packet parser (no network needed).
    Local {
        /// Number of fuzz iterations.
        #[arg(long, default_value = "100000")]
        iterations: u64,

        /// Mutation strategy to use.
        #[arg(long, default_value = "all", value_enum)]
        strategy: Strategy,

        /// Random seed for reproducible fuzzing.
        #[arg(long)]
        seed: Option<u64>,
    },

    /// Send fuzzed packets to a live relay.
    Relay {
        /// Target relay address (host:port).
        #[arg(long)]
        target: String,

        /// Number of fuzz iterations.
        #[arg(long, default_value = "10000")]
        iterations: u64,

        /// Mutation strategy to use.
        #[arg(long, default_value = "all", value_enum)]
        strategy: Strategy,

        /// Random seed for reproducible fuzzing.
        #[arg(long)]
        seed: Option<u64>,

        /// Timeout in milliseconds for health checks.
        #[arg(long, default_value = "2000")]
        timeout_ms: u64,
    },

    /// Send fuzzed packets to a live gateway.
    Gateway {
        /// Target gateway address (host:port).
        #[arg(long)]
        target: String,

        /// Number of fuzz iterations.
        #[arg(long, default_value = "10000")]
        iterations: u64,

        /// Mutation strategy to use.
        #[arg(long, default_value = "all", value_enum)]
        strategy: Strategy,

        /// Random seed for reproducible fuzzing.
        #[arg(long)]
        seed: Option<u64>,

        /// Timeout in milliseconds for health checks.
        #[arg(long, default_value = "2000")]
        timeout_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum Strategy {
    /// Run all mutation strategies.
    All,
    /// Flip random bits in the packet.
    Bitflip,
    /// Replace random bytes with random values.
    ByteMutate,
    /// Mutate values at known field boundaries.
    FieldBoundary,
    /// Send truncated packets.
    Truncate,
    /// Append random data to packets.
    Extend,
    /// Corrupt the magic bytes.
    MagicCorrupt,
    /// Mutate SessionID bytes.
    SessionMutate,
    /// Sequence number attacks (replay, overflow, etc.).
    SequenceAttack,
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Strategy::All => write!(f, "all"),
            Strategy::Bitflip => write!(f, "bitflip"),
            Strategy::ByteMutate => write!(f, "byte-mutate"),
            Strategy::FieldBoundary => write!(f, "field-boundary"),
            Strategy::Truncate => write!(f, "truncate"),
            Strategy::Extend => write!(f, "extend"),
            Strategy::MagicCorrupt => write!(f, "magic-corrupt"),
            Strategy::SessionMutate => write!(f, "session-mutate"),
            Strategy::SequenceAttack => write!(f, "sequence-attack"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Mutation engines
// ─────────────────────────────────────────────────────────────────────────

/// Generate a valid base packet (data or handshake) for mutation.
fn generate_base_packet(rng: &mut impl Rng) -> Vec<u8> {
    if rng.gen_bool(0.5) {
        // Data packet
        let sid = SessionId::generate();
        let key: [u8; 32] = rand::random();
        let seq: u64 = rng.gen();
        let mut hdr = DataHeader::new(sid, seq);
        let aad = hdr.aad_bytes();
        hdr.header_auth_tag = compute_header_auth_tag(&key, &aad);
        let payload_size: usize = rng.gen_range(0..256);
        let payload: Vec<u8> = (0..payload_size).map(|_| rng.gen::<u8>()).collect();
        let pkt = ZtlpPacket::Data {
            header: hdr,
            payload,
        };
        pkt.serialize()
    } else {
        // Handshake packet
        let msg_types = [
            MsgType::Hello,
            MsgType::HelloAck,
            MsgType::Rekey,
            MsgType::Close,
            MsgType::Ping,
            MsgType::Pong,
        ];
        let mt = msg_types[rng.gen_range(0..msg_types.len())];
        let mut hdr = HandshakeHeader::new(mt);
        hdr.session_id = SessionId::generate();
        hdr.packet_seq = rng.gen();
        let key: [u8; 32] = rand::random();
        let aad = hdr.aad_bytes();
        hdr.header_auth_tag = compute_header_auth_tag(&key, &aad);
        let payload_size: usize = rng.gen_range(0..64);
        let payload: Vec<u8> = (0..payload_size).map(|_| rng.gen::<u8>()).collect();
        hdr.payload_len = payload.len() as u16;
        let pkt = ZtlpPacket::Handshake {
            header: hdr,
            payload,
        };
        pkt.serialize()
    }
}

fn mutate_bitflip(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    // Flip 1-8 random bits
    let flips = rng.gen_range(1..=8);
    for _ in 0..flips {
        let byte_idx = rng.gen_range(0..out.len());
        let bit_idx = rng.gen_range(0..8u8);
        out[byte_idx] ^= 1 << bit_idx;
    }
    out
}

fn mutate_byte(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    // Replace 1-4 random bytes
    let mutations = rng.gen_range(1..=4);
    for _ in 0..mutations {
        let idx = rng.gen_range(0..out.len());
        out[idx] = rng.gen::<u8>();
    }
    out
}

fn mutate_field_boundary(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.len() < 4 {
        return out;
    }

    // Known field offsets for data header (42 bytes)
    let data_offsets: &[(usize, usize, &str)] = &[
        (0, 2, "magic"),        // Magic
        (2, 4, "ver_hdrlen"),   // Ver+HdrLen
        (4, 6, "flags"),        // Flags
        (6, 18, "session_id"),  // SessionID
        (18, 26, "packet_seq"), // PacketSeq
        (26, 42, "auth_tag"),   // AuthTag
    ];

    // Known field offsets for handshake header (95 bytes)
    let hs_offsets: &[(usize, usize, &str)] = &[
        (0, 2, "magic"),
        (2, 4, "ver_hdrlen"),
        (4, 6, "flags"),
        (6, 7, "msg_type"),
        (7, 9, "crypto_suite"),
        (9, 11, "key_id"),
        (11, 23, "session_id"),
        (23, 31, "packet_seq"),
        (31, 39, "timestamp"),
        (39, 55, "src_node_id"),
        (55, 71, "dst_svc_id"),
        (71, 75, "policy_tag"),
        (75, 77, "ext_len"),
        (77, 79, "payload_len"),
        (79, 95, "auth_tag"),
    ];

    // Detect type and pick appropriate offsets
    let ver_hdrlen = u16::from_be_bytes([out[2], out[3]]);
    let hdr_len = ver_hdrlen & 0x0FFF;
    let offsets = if hdr_len == 24 && out.len() >= HANDSHAKE_HEADER_SIZE {
        hs_offsets
    } else {
        data_offsets
    };

    // Pick a random field to mutate
    let valid_offsets: Vec<_> = offsets
        .iter()
        .filter(|(_, end, _)| *end <= out.len())
        .collect();
    if let Some(&&(start, end, _name)) =
        valid_offsets.get(rng.gen_range(0..valid_offsets.len().max(1)))
    {
        // Fill field with interesting values
        let actual_end = end.min(out.len());
        let strategy = rng.gen_range(0..5);
        match strategy {
            0 => {
                // All zeros
                for b in &mut out[start..actual_end] {
                    *b = 0;
                }
            }
            1 => {
                // All 0xFF
                for b in &mut out[start..actual_end] {
                    *b = 0xFF;
                }
            }
            2 => {
                // Random
                for b in &mut out[start..actual_end] {
                    *b = rng.gen::<u8>();
                }
            }
            3 => {
                // Boundary value (e.g., max u16, max u32)
                let len = end - start;
                if len == 2 {
                    let vals: [u16; 4] = [0, 1, 0x7FFF, 0xFFFF];
                    let val = vals[rng.gen_range(0..4)];
                    if start + 2 <= out.len() {
                        out[start..start + 2].copy_from_slice(&val.to_be_bytes());
                    }
                } else if len == 4 {
                    let vals: [u32; 4] = [0, 1, 0x7FFFFFFF, 0xFFFFFFFF];
                    let val = vals[rng.gen_range(0..4)];
                    if start + 4 <= out.len() {
                        out[start..start + 4].copy_from_slice(&val.to_be_bytes());
                    }
                } else if len == 8 {
                    let vals: [u64; 4] = [0, 1, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];
                    let val = vals[rng.gen_range(0..4)];
                    if start + 8 <= out.len() {
                        out[start..start + 8].copy_from_slice(&val.to_be_bytes());
                    }
                }
            }
            _ => {
                // Swap with adjacent field
                if start > 0 && end < out.len() {
                    let len = end - start;
                    if start >= len {
                        let (before, after) = out.split_at_mut(start);
                        let copy_len = len.min(after.len()).min(before.len());
                        if copy_len > 0 {
                            let prev_start = start.saturating_sub(copy_len);
                            let tmp: Vec<u8> = before[prev_start..prev_start + copy_len].to_vec();
                            before[prev_start..prev_start + copy_len]
                                .copy_from_slice(&after[..copy_len]);
                            after[..copy_len].copy_from_slice(&tmp);
                        }
                    }
                }
            }
        }
    }
    out
}

fn mutate_truncate(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    if data.is_empty() {
        return vec![];
    }
    // Truncate to random length (0 to len-1)
    let new_len = rng.gen_range(0..data.len());
    data[..new_len].to_vec()
}

fn mutate_extend(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    let extra = rng.gen_range(1..256);
    for _ in 0..extra {
        out.push(rng.gen::<u8>());
    }
    out
}

fn mutate_magic_corrupt(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.len() < 2 {
        return out;
    }
    // Various magic corruptions
    match rng.gen_range(0..6) {
        0 => {
            out[0] = 0x00;
            out[1] = 0x00;
        } // Zero magic
        1 => {
            out[0] = 0xFF;
            out[1] = 0xFF;
        } // All-ones magic
        2 => {
            out[0] ^= 0xFF;
        } // Invert first byte
        3 => {
            out[1] ^= 0xFF;
        } // Invert second byte
        4 => {
            out.swap(0, 1);
        } // Swap magic bytes
        _ => {
            out[0] = rng.gen::<u8>();
            out[1] = rng.gen::<u8>();
        } // Random magic
    }
    out
}

fn mutate_session_id(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.len() < 4 {
        return out;
    }

    // Determine SessionID offset based on header type
    let ver_hdrlen = u16::from_be_bytes([out[2], out[3]]);
    let hdr_len = ver_hdrlen & 0x0FFF;
    let (sid_start, sid_end) = if hdr_len == 24 {
        (11usize, 23usize)
    } else {
        (6usize, 18usize)
    };

    if out.len() < sid_end {
        return out;
    }

    match rng.gen_range(0..5) {
        0 => {
            // Zero out SessionID
            for b in &mut out[sid_start..sid_end] {
                *b = 0;
            }
        }
        1 => {
            // All-ones SessionID
            for b in &mut out[sid_start..sid_end] {
                *b = 0xFF;
            }
        }
        2 => {
            // Random SessionID
            for b in &mut out[sid_start..sid_end] {
                *b = rng.gen::<u8>();
            }
        }
        3 => {
            // Swap bytes within SessionID
            let idx1 = rng.gen_range(sid_start..sid_end);
            let idx2 = rng.gen_range(sid_start..sid_end);
            out.swap(idx1, idx2);
        }
        _ => {
            // Flip one bit in SessionID
            let byte_idx = rng.gen_range(sid_start..sid_end);
            let bit_idx = rng.gen_range(0..8u8);
            out[byte_idx] ^= 1 << bit_idx;
        }
    }
    out
}

fn mutate_sequence_attack(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.len() < 4 {
        return out;
    }

    // Determine PacketSeq offset
    let ver_hdrlen = u16::from_be_bytes([out[2], out[3]]);
    let hdr_len = ver_hdrlen & 0x0FFF;
    let seq_start = if hdr_len == 24 { 23usize } else { 18usize };
    let seq_end = seq_start + 8;

    if out.len() < seq_end {
        return out;
    }

    let attack_seq: u64 = match rng.gen_range(0..6) {
        0 => 0,            // Zero sequence
        1 => u64::MAX,     // Maximum sequence (overflow)
        2 => u64::MAX - 1, // Near-overflow
        3 => rng.gen(),    // Random sequence
        4 => {
            // Duplicate: keep same (replay attack)
            return out;
        }
        _ => {
            // Out-of-order: set to very high then very low
            if rng.gen_bool(0.5) {
                u64::MAX / 2
            } else {
                1
            }
        }
    };

    out[seq_start..seq_end].copy_from_slice(&attack_seq.to_be_bytes());
    out
}

fn apply_mutation(data: &[u8], strategy: Strategy, rng: &mut impl Rng) -> Vec<u8> {
    match strategy {
        Strategy::All => {
            // Pick a random strategy
            let strategies = [
                Strategy::Bitflip,
                Strategy::ByteMutate,
                Strategy::FieldBoundary,
                Strategy::Truncate,
                Strategy::Extend,
                Strategy::MagicCorrupt,
                Strategy::SessionMutate,
                Strategy::SequenceAttack,
            ];
            let s = strategies[rng.gen_range(0..strategies.len())];
            apply_mutation(data, s, rng)
        }
        Strategy::Bitflip => mutate_bitflip(data, rng),
        Strategy::ByteMutate => mutate_byte(data, rng),
        Strategy::FieldBoundary => mutate_field_boundary(data, rng),
        Strategy::Truncate => mutate_truncate(data, rng),
        Strategy::Extend => mutate_extend(data, rng),
        Strategy::MagicCorrupt => mutate_magic_corrupt(data, rng),
        Strategy::SessionMutate => mutate_session_id(data, rng),
        Strategy::SequenceAttack => mutate_sequence_attack(data, rng),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Fuzz statistics
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct FuzzStats {
    packets_sent: u64,
    parse_ok: u64,
    parse_errors: u64,
    error_types: HashMap<String, u64>,
    panics: u64,
    crashes: u64,
    network_errors: u64,
}

impl FuzzStats {
    fn record_parse_result(&mut self, result: Result<(), String>) {
        self.packets_sent += 1;
        match result {
            Ok(()) => self.parse_ok += 1,
            Err(e) => {
                self.parse_errors += 1;
                *self.error_types.entry(e).or_insert(0) += 1;
            }
        }
    }

    fn record_network_error(&mut self) {
        self.network_errors += 1;
    }
}

fn print_fuzz_summary(stats: &FuzzStats, elapsed: Duration, strategy: Strategy) {
    println!(
        "\n{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
    println!("  {}", "Fuzz Test Summary".white().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
    println!(
        "  {:<24} {:.2}s",
        "Duration:".bright_blue(),
        elapsed.as_secs_f64()
    );
    println!(
        "  {:<24} {}",
        "Strategy:".bright_blue(),
        strategy.to_string().bright_magenta()
    );
    println!(
        "  {:<24} {}",
        "Packets generated:".bright_blue(),
        stats.packets_sent
    );
    println!(
        "  {:<24} {}",
        "Parse OK:".bright_blue(),
        stats.parse_ok.to_string().green()
    );
    println!(
        "  {:<24} {}",
        "Parse errors:".bright_blue(),
        stats.parse_errors.to_string().yellow()
    );
    println!(
        "  {:<24} {}",
        "Panics caught:".bright_blue(),
        if stats.panics > 0 {
            stats.panics.to_string().red().to_string()
        } else {
            "0".green().to_string()
        }
    );
    println!(
        "  {:<24} {}",
        "Crash signals:".bright_blue(),
        if stats.crashes > 0 {
            stats.crashes.to_string().red().bold().to_string()
        } else {
            "0".green().to_string()
        }
    );
    if stats.network_errors > 0 {
        println!(
            "  {:<24} {}",
            "Network errors:".bright_blue(),
            stats.network_errors.to_string().yellow()
        );
    }
    println!(
        "  {:<24} {}",
        "Unique error types:".bright_blue(),
        stats.error_types.len()
    );
    println!(
        "  {:<24} {:.0} pkts/sec",
        "Throughput:".bright_blue(),
        stats.packets_sent as f64 / elapsed.as_secs_f64()
    );

    if !stats.error_types.is_empty() {
        println!("\n  {}", "Error type breakdown:".bright_blue());
        let mut sorted: Vec<_> = stats.error_types.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (error, count) in sorted.iter().take(20) {
            let pct = **count as f64 / stats.packets_sent as f64 * 100.0;
            println!("    {:>6} ({:>5.1}%)  {}", count, pct, error.dimmed());
        }
        if sorted.len() > 20 {
            println!("    ... and {} more error types", sorted.len() - 20);
        }
    }

    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Local fuzzing
// ─────────────────────────────────────────────────────────────────────────

fn fuzz_local(iterations: u64, strategy: Strategy, seed: Option<u64>) {
    use rand::SeedableRng;

    let actual_seed = seed.unwrap_or_else(rand::random);
    println!(
        "  {:<24} {}{}",
        "Seed:".bright_blue(),
        actual_seed,
        if seed.is_some() { "" } else { " (auto)" }
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(actual_seed);

    let mut stats = FuzzStats::default();

    let pb = ProgressBar::new(iterations);
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} | errs: {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    let start = Instant::now();

    for i in 0..iterations {
        // Generate a base packet and mutate it
        let base = generate_base_packet(&mut rng);
        let mutated = apply_mutation(&base, strategy, &mut rng);

        // Try to parse as both packet types, catching panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Try parsing as data header
            let _ = DataHeader::deserialize(&mutated);
            // Try parsing as handshake header
            let _ = HandshakeHeader::deserialize(&mutated);
        }));

        match result {
            Ok(()) => {
                // Parse completed (may have returned errors, but didn't panic)
                // Try to get more specific error info
                let data_result = DataHeader::deserialize(&mutated);
                let hs_result = HandshakeHeader::deserialize(&mutated);

                if data_result.is_ok() || hs_result.is_ok() {
                    stats.record_parse_result(Ok(()));
                } else {
                    let err_msg = match (data_result, hs_result) {
                        (Err(e), _) => format!("{}", e),
                        (_, Err(e)) => format!("{}", e),
                        _ => "unknown".to_string(),
                    };
                    stats.record_parse_result(Err(err_msg));
                }
            }
            Err(_) => {
                stats.panics += 1;
                stats.record_parse_result(Err("PANIC".to_string()));
            }
        }

        // Also test the pipeline Layer 1 check
        {
            let pipeline = ztlp_proto::pipeline::Pipeline::new();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pipeline.layer1_magic_check(&mutated);
            }));
        }

        if i % 1000 == 0 {
            pb.set_position(i);
            pb.set_message(format!("{}", stats.parse_errors));
        }
    }

    let elapsed = start.elapsed();
    pb.finish_and_clear();

    print_fuzz_summary(&stats, elapsed, strategy);
}

// ─────────────────────────────────────────────────────────────────────────
// Network fuzzing
// ─────────────────────────────────────────────────────────────────────────

async fn fuzz_network(
    target: &str,
    iterations: u64,
    strategy: Strategy,
    seed: Option<u64>,
    timeout_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use rand::SeedableRng;

    let target_addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("Invalid target address '{}': {}", target, e))?;

    let actual_seed = seed.unwrap_or_else(rand::random);
    println!("  {:<24} {}", "Target:".bright_blue(), target_addr);
    println!(
        "  {:<24} {}{}",
        "Seed:".bright_blue(),
        actual_seed,
        if seed.is_some() { "" } else { " (auto)" }
    );

    let mut rng = rand::rngs::StdRng::seed_from_u64(actual_seed);

    // Check if target is reachable first
    println!(
        "\n  {} Checking target reachability...",
        "⏳".bright_yellow()
    );
    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    // Send a HELLO packet as a connectivity test
    let hello = {
        let hdr = HandshakeHeader::new(MsgType::Hello);
        let pkt = ZtlpPacket::Handshake {
            header: hdr,
            payload: vec![],
        };
        pkt.serialize()
    };

    match sock.send_to(&hello, target_addr).await {
        Ok(_) => println!(
            "  {} Target appears reachable (UDP send succeeded).",
            "✓".green()
        ),
        Err(e) => {
            eprintln!("  {} Cannot reach target: {}", "✗".red(), e);
            eprintln!(
                "  {} Continuing anyway (UDP is connectionless)...",
                "⚠".yellow()
            );
        }
    }

    let mut stats = FuzzStats::default();
    let health_check_interval = 1000u64; // Check every N packets

    let pb = ProgressBar::new(iterations);
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} | errs: {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    let start = Instant::now();

    for i in 0..iterations {
        let base = generate_base_packet(&mut rng);
        let mutated = apply_mutation(&base, strategy, &mut rng);

        match sock.send_to(&mutated, target_addr).await {
            Ok(n) => {
                stats.packets_sent += 1;
                stats.record_parse_result(Ok(()));
                let _ = n;
            }
            Err(e) => {
                stats.packets_sent += 1;
                stats.record_network_error();
                stats.record_parse_result(Err(format!("send error: {}", e)));
            }
        }

        // Periodic health check: send a valid HELLO and see if we get anything back
        if i > 0 && i % health_check_interval == 0 {
            let hello = {
                let hdr = HandshakeHeader::new(MsgType::Ping);
                let pkt = ZtlpPacket::Handshake {
                    header: hdr,
                    payload: vec![],
                };
                pkt.serialize()
            };

            if let Err(_) = sock.send_to(&hello, target_addr).await {
                stats.crashes += 1;
                pb.set_message(format!(
                    "{} errs | {} crashes",
                    stats.parse_errors, stats.crashes
                ));
            }

            // Try to receive any response (non-blocking with timeout)
            let mut buf = [0u8; 1500];
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms.min(100)),
                sock.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    // Got a response — target is alive
                }
                Ok(Err(_)) | Err(_) => {
                    // No response — could be normal for UDP
                }
            }
        }

        if i % 500 == 0 {
            pb.set_position(i);
            pb.set_message(format!(
                "{} errs | {} net_errs",
                stats.parse_errors, stats.network_errors
            ));
        }

        // Small yield to prevent starving the runtime
        if i % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let elapsed = start.elapsed();
    pb.finish_and_clear();

    print_fuzz_summary(&stats, elapsed, strategy);
    Ok(())
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
    println!("  {}", "ZTLP Protocol Fuzzer".white().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_cyan()
    );

    match cli.command {
        Command::Local {
            iterations,
            strategy,
            seed,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "Local parser fuzzing".bright_magenta()
            );
            println!("  {:<24} {}", "Iterations:".bright_blue(), iterations);
            println!(
                "  {:<24} {}",
                "Strategy:".bright_blue(),
                strategy.to_string().bright_yellow()
            );
            println!();
            fuzz_local(iterations, strategy, seed);
        }
        Command::Relay {
            target,
            iterations,
            strategy,
            seed,
            timeout_ms,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "Relay fuzzing (network)".bright_magenta()
            );
            println!("  {:<24} {}", "Iterations:".bright_blue(), iterations);
            println!(
                "  {:<24} {}",
                "Strategy:".bright_blue(),
                strategy.to_string().bright_yellow()
            );
            println!();
            if let Err(e) = fuzz_network(&target, iterations, strategy, seed, timeout_ms).await {
                eprintln!("\n  {} {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
        Command::Gateway {
            target,
            iterations,
            strategy,
            seed,
            timeout_ms,
        } => {
            println!(
                "  {:<24} {}",
                "Mode:".bright_blue(),
                "Gateway fuzzing (network)".bright_magenta()
            );
            println!("  {:<24} {}", "Iterations:".bright_blue(), iterations);
            println!(
                "  {:<24} {}",
                "Strategy:".bright_blue(),
                strategy.to_string().bright_yellow()
            );
            println!();
            if let Err(e) = fuzz_network(&target, iterations, strategy, seed, timeout_ms).await {
                eprintln!("\n  {} {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
    }
}
