//! ztlp-inspect — ZTLP Packet Decoder/Inspector
//!
//! Decode and pretty-print ZTLP packets from hex strings, binary files, or stdin.
//!
//! # Examples
//!
//! ```bash
//! # Decode a single packet from hex
//! ztlp-inspect 5a371018000001000100000000000000000000...
//!
//! # Read hex-encoded packets from stdin (one per line)
//! echo "5a37..." | ztlp-inspect --stdin
//!
//! # Scan a binary file for ZTLP packets
//! ztlp-inspect --file capture.bin
//!
//! # Output as JSON
//! ztlp-inspect --format json 5a37...
//! ```

use clap::{Parser, ValueEnum};
use colored::Colorize;
use std::io::{self, BufRead};

use ztlp_proto::packet::{
    DataHeader, HandshakeHeader, MsgType, MAGIC,
    DATA_HEADER_SIZE, HANDSHAKE_HEADER_SIZE, VERSION,
};

/// ZTLP Packet Decoder/Inspector — decode and pretty-print ZTLP packets.
#[derive(Parser, Debug)]
#[command(name = "ztlp-inspect", version, about, long_about = None)]
struct Cli {
    /// Hex-encoded packet data (positional argument).
    hex_data: Option<String>,

    /// Read hex-encoded packets from stdin (one per line).
    #[arg(long)]
    stdin: bool,

    /// Read and scan a binary file for ZTLP packets.
    #[arg(long, value_name = "PATH")]
    file: Option<String>,

    /// Output format.
    #[arg(long, default_value = "pretty", value_enum)]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Colored human-readable output with hex dump.
    Pretty,
    /// JSON output.
    Json,
    /// Single-line compact output.
    Compact,
}

// ─────────────────────────────────────────────────────────────────────────
// Decoded packet representation for JSON serialization
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type")]
enum DecodedPacket {
    #[serde(rename = "handshake")]
    Handshake {
        valid: bool,
        magic: String,
        version: u8,
        hdr_len: u16,
        flags: FlagInfo,
        msg_type: String,
        msg_type_raw: u8,
        crypto_suite: String,
        key_id: u16,
        session_id: String,
        packet_seq: u64,
        timestamp: u64,
        src_node_id: String,
        dst_svc_id: String,
        policy_tag: String,
        ext_len: u16,
        payload_len: u16,
        header_auth_tag: String,
        total_bytes: usize,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        warnings: Vec<String>,
    },
    #[serde(rename = "data")]
    Data {
        valid: bool,
        magic: String,
        version: u8,
        hdr_len: u16,
        flags: FlagInfo,
        session_id: String,
        packet_seq: u64,
        header_auth_tag: String,
        total_bytes: usize,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        warnings: Vec<String>,
    },
    #[serde(rename = "error")]
    Error {
        error: String,
        raw_hex: String,
        raw_len: usize,
    },
}

#[derive(Debug, serde::Serialize)]
struct FlagInfo {
    raw: String,
    has_ext: bool,
    ack_req: bool,
    rekey: bool,
    migrate: bool,
    multipath: bool,
    relay_hop: bool,
}

fn decode_flags(flags: u16) -> FlagInfo {
    use ztlp_proto::packet::flags::*;
    FlagInfo {
        raw: format!("0x{:04X}", flags),
        has_ext: flags & HAS_EXT != 0,
        ack_req: flags & ACK_REQ != 0,
        rekey: flags & REKEY != 0,
        migrate: flags & MIGRATE != 0,
        multipath: flags & MULTIPATH != 0,
        relay_hop: flags & RELAY_HOP != 0,
    }
}

fn msg_type_name(mt: MsgType) -> &'static str {
    match mt {
        MsgType::Data => "DATA",
        MsgType::Hello => "HELLO",
        MsgType::HelloAck => "HELLO_ACK",
        MsgType::Rekey => "REKEY",
        MsgType::Close => "CLOSE",
        MsgType::Error => "ERROR",
        MsgType::Ping => "PING",
        MsgType::Pong => "PONG",
    }
}

fn crypto_suite_name(cs: u16) -> String {
    match cs {
        0x0001 => "ChaCha20-Poly1305 + Noise_XX (0x0001)".to_string(),
        _ => format!("Unknown (0x{:04X})", cs),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Decoding logic
// ─────────────────────────────────────────────────────────────────────────

fn decode_packet(data: &[u8]) -> DecodedPacket {
    if data.len() < 4 {
        return DecodedPacket::Error {
            error: format!("Packet too short: {} bytes (need at least 4)", data.len()),
            raw_hex: hex::encode(data),
            raw_len: data.len(),
        };
    }

    let magic = u16::from_be_bytes([data[0], data[1]]);
    if magic != MAGIC {
        return DecodedPacket::Error {
            error: format!("Invalid magic: 0x{:04X} (expected 0x5A37)", magic),
            raw_hex: hex::encode(&data[..data.len().min(32)]),
            raw_len: data.len(),
        };
    }

    let ver_hdrlen = u16::from_be_bytes([data[2], data[3]]);
    let version = ((ver_hdrlen >> 12) & 0x0F) as u8;
    let hdr_len = ver_hdrlen & 0x0FFF;

    let mut warnings = Vec::new();

    if version != VERSION {
        warnings.push(format!("Unsupported version: {} (expected {})", version, VERSION));
    }

    // Discriminate by HdrLen: 24 = handshake, 11 = data
    if hdr_len == 24 {
        decode_handshake(data, version, hdr_len, warnings)
    } else if hdr_len == 11 {
        decode_data(data, version, hdr_len, warnings)
    } else {
        // Unknown header length — try to decode as much as possible
        warnings.push(format!("Unknown HdrLen: {} (expected 24 for handshake or 11 for data)", hdr_len));
        if data.len() >= HANDSHAKE_HEADER_SIZE {
            decode_handshake(data, version, hdr_len, warnings)
        } else if data.len() >= DATA_HEADER_SIZE {
            decode_data(data, version, hdr_len, warnings)
        } else {
            DecodedPacket::Error {
                error: format!("Unknown HdrLen {} and packet too short to decode ({}B)", hdr_len, data.len()),
                raw_hex: hex::encode(data),
                raw_len: data.len(),
            }
        }
    }
}

fn decode_handshake(data: &[u8], version: u8, hdr_len: u16, mut warnings: Vec<String>) -> DecodedPacket {
    if data.len() < HANDSHAKE_HEADER_SIZE {
        return DecodedPacket::Error {
            error: format!("Handshake header too short: {} bytes (need {})", data.len(), HANDSHAKE_HEADER_SIZE),
            raw_hex: hex::encode(data),
            raw_len: data.len(),
        };
    }

    match HandshakeHeader::deserialize(data) {
        Ok(hdr) => {
            if hdr.session_id.is_zero()
                && hdr.msg_type != MsgType::Hello
                && hdr.msg_type != MsgType::HelloAck
            {
                warnings.push("Non-Hello packet with zero SessionID".to_string());
            }

            DecodedPacket::Handshake {
                valid: warnings.is_empty(),
                magic: format!("0x{:04X}", MAGIC),
                version,
                hdr_len,
                flags: decode_flags(hdr.flags),
                msg_type: msg_type_name(hdr.msg_type).to_string(),
                msg_type_raw: hdr.msg_type as u8,
                crypto_suite: crypto_suite_name(hdr.crypto_suite),
                key_id: hdr.key_id,
                session_id: hex::encode(hdr.session_id.0),
                packet_seq: hdr.packet_seq,
                timestamp: hdr.timestamp,
                src_node_id: hex::encode(hdr.src_node_id),
                dst_svc_id: hex::encode(hdr.dst_svc_id),
                policy_tag: format!("0x{:08X}", hdr.policy_tag),
                ext_len: hdr.ext_len,
                payload_len: hdr.payload_len,
                header_auth_tag: hex::encode(hdr.header_auth_tag),
                total_bytes: data.len(),
                warnings,
            }
        }
        Err(e) => DecodedPacket::Error {
            error: format!("Failed to parse handshake header: {}", e),
            raw_hex: hex::encode(&data[..data.len().min(64)]),
            raw_len: data.len(),
        },
    }
}

fn decode_data(data: &[u8], version: u8, hdr_len: u16, warnings: Vec<String>) -> DecodedPacket {
    if data.len() < DATA_HEADER_SIZE {
        return DecodedPacket::Error {
            error: format!("Data header too short: {} bytes (need {})", data.len(), DATA_HEADER_SIZE),
            raw_hex: hex::encode(data),
            raw_len: data.len(),
        };
    }

    match DataHeader::deserialize(data) {
        Ok(hdr) => DecodedPacket::Data {
            valid: warnings.is_empty(),
            magic: format!("0x{:04X}", MAGIC),
            version,
            hdr_len,
            flags: decode_flags(hdr.flags),
            session_id: hex::encode(hdr.session_id.0),
            packet_seq: hdr.packet_seq,
            header_auth_tag: hex::encode(hdr.header_auth_tag),
            total_bytes: data.len(),
            warnings,
        },
        Err(e) => DecodedPacket::Error {
            error: format!("Failed to parse data header: {}", e),
            raw_hex: hex::encode(&data[..data.len().min(64)]),
            raw_len: data.len(),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Display
// ─────────────────────────────────────────────────────────────────────────

fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    let limit = data.len().min(max_bytes);
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        out.push_str(&format!("  {:04x}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                out.push(' ');
            }
        }
        // Pad remaining
        let remaining = 16 - chunk.len();
        for j in 0..remaining {
            out.push_str("   ");
            if chunk.len() + j == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    if data.len() > max_bytes {
        out.push_str(&format!("  ... ({} more bytes)\n", data.len() - max_bytes));
    }
    out
}

fn display_pretty(pkt: &DecodedPacket, raw: &[u8]) {
    match pkt {
        DecodedPacket::Handshake {
            valid, magic, version, hdr_len, flags, msg_type, msg_type_raw,
            crypto_suite, key_id, session_id, packet_seq, timestamp,
            src_node_id, dst_svc_id, policy_tag, ext_len, payload_len,
            header_auth_tag, total_bytes, warnings,
        } => {
            let status = if *valid {
                "✓ VALID".green().bold()
            } else {
                "⚠ WARNINGS".yellow().bold()
            };
            println!("{}", "╔══════════════════════════════════════════════════════╗".cyan());
            println!("{} {} {} {} {}",
                "║".cyan(),
                "ZTLP Handshake Packet".white().bold(),
                format!("({msg_type})").bright_magenta(),
                status,
                "║".cyan()
            );
            println!("{}", "╠══════════════════════════════════════════════════════╣".cyan());
            println!("{}  {:<20} {}", "║".cyan(), "Magic:".bright_blue(), magic);
            println!("{}  {:<20} {} (HdrLen: {} words = {} bytes)",
                "║".cyan(), "Version:".bright_blue(), version, hdr_len, hdr_len * 4);
            println!("{}  {:<20} {} (raw: {})",
                "║".cyan(), "MsgType:".bright_blue(), msg_type.bright_magenta(), msg_type_raw);
            println!("{}  {:<20} {}", "║".cyan(), "CryptoSuite:".bright_blue(), crypto_suite);
            println!("{}  {:<20} {}", "║".cyan(), "KeyID:".bright_blue(), key_id);
            println!("{}  {:<20} {}", "║".cyan(), "SessionID:".bright_blue(), session_id.bright_yellow());
            println!("{}  {:<20} {}", "║".cyan(), "PacketSeq:".bright_blue(), packet_seq);
            println!("{}  {:<20} {} ms", "║".cyan(), "Timestamp:".bright_blue(), timestamp);
            println!("{}  {:<20} {}", "║".cyan(), "SrcNodeID:".bright_blue(), src_node_id);
            println!("{}  {:<20} {}", "║".cyan(), "DstSvcID:".bright_blue(), dst_svc_id);
            println!("{}  {:<20} {}", "║".cyan(), "PolicyTag:".bright_blue(), policy_tag);
            println!("{}  {:<20} {}", "║".cyan(), "ExtLen:".bright_blue(), ext_len);
            println!("{}  {:<20} {}", "║".cyan(), "PayloadLen:".bright_blue(), payload_len);
            println!("{}  {:<20} {}", "║".cyan(), "AuthTag:".bright_blue(), header_auth_tag.bright_red());

            // Flags
            println!("{}  {:<20} {}", "║".cyan(), "Flags:".bright_blue(), flags.raw);
            let mut flag_strs = Vec::new();
            if flags.has_ext { flag_strs.push("HAS_EXT"); }
            if flags.ack_req { flag_strs.push("ACK_REQ"); }
            if flags.rekey { flag_strs.push("REKEY"); }
            if flags.migrate { flag_strs.push("MIGRATE"); }
            if flags.multipath { flag_strs.push("MULTIPATH"); }
            if flags.relay_hop { flag_strs.push("RELAY_HOP"); }
            if !flag_strs.is_empty() {
                println!("{}  {:<20} [{}]", "║".cyan(), "".bright_blue(), flag_strs.join(", ").bright_green());
            }

            println!("{}  {:<20} {} bytes", "║".cyan(), "Total size:".bright_blue(), total_bytes);

            if !warnings.is_empty() {
                println!("{}", "╠══════════════════════════════════════════════════════╣".yellow());
                for w in warnings {
                    println!("{}  {} {}", "║".yellow(), "⚠".yellow(), w.yellow());
                }
            }

            println!("{}", "╠══════════════════════════════════════════════════════╣".cyan());
            println!("{}  {}", "║".cyan(), "Raw hex dump:".dimmed());
            print!("{}", hex_dump(raw, 128));
            println!("{}", "╚══════════════════════════════════════════════════════╝".cyan());
        }
        DecodedPacket::Data {
            valid, magic, version, hdr_len, flags, session_id, packet_seq,
            header_auth_tag, total_bytes, warnings,
        } => {
            let status = if *valid {
                "✓ VALID".green().bold()
            } else {
                "⚠ WARNINGS".yellow().bold()
            };
            println!("{}", "╔══════════════════════════════════════════════════════╗".green());
            println!("{} {} {}",
                "║".green(),
                "ZTLP Data Packet".white().bold(),
                status
            );
            println!("{}", "╠══════════════════════════════════════════════════════╣".green());
            println!("{}  {:<20} {}", "║".green(), "Magic:".bright_blue(), magic);
            println!("{}  {:<20} {} (HdrLen: {} words = {} bytes)",
                "║".green(), "Version:".bright_blue(), version, hdr_len, hdr_len * 4);
            println!("{}  {:<20} {}", "║".green(), "SessionID:".bright_blue(), session_id.bright_yellow());
            println!("{}  {:<20} {}", "║".green(), "PacketSeq:".bright_blue(), packet_seq);
            println!("{}  {:<20} {}", "║".green(), "AuthTag:".bright_blue(), header_auth_tag.bright_red());

            // Flags
            println!("{}  {:<20} {}", "║".green(), "Flags:".bright_blue(), flags.raw);
            let mut flag_strs = Vec::new();
            if flags.has_ext { flag_strs.push("HAS_EXT"); }
            if flags.ack_req { flag_strs.push("ACK_REQ"); }
            if flags.rekey { flag_strs.push("REKEY"); }
            if flags.migrate { flag_strs.push("MIGRATE"); }
            if flags.multipath { flag_strs.push("MULTIPATH"); }
            if flags.relay_hop { flag_strs.push("RELAY_HOP"); }
            if !flag_strs.is_empty() {
                println!("{}  {:<20} [{}]", "║".green(), "".bright_blue(), flag_strs.join(", ").bright_green());
            }

            println!("{}  {:<20} {} bytes (payload: {} bytes)",
                "║".green(), "Total size:".bright_blue(), total_bytes,
                total_bytes.saturating_sub(DATA_HEADER_SIZE));

            if !warnings.is_empty() {
                println!("{}", "╠══════════════════════════════════════════════════════╣".yellow());
                for w in warnings {
                    println!("{}  {} {}", "║".yellow(), "⚠".yellow(), w.yellow());
                }
            }

            println!("{}", "╠══════════════════════════════════════════════════════╣".green());
            println!("{}  {}", "║".green(), "Raw hex dump:".dimmed());
            print!("{}", hex_dump(raw, 128));
            println!("{}", "╚══════════════════════════════════════════════════════╝".green());
        }
        DecodedPacket::Error { error, raw_hex, raw_len } => {
            println!("{}", "╔══════════════════════════════════════════════════════╗".red());
            println!("{} {}", "║".red(), "✗ DECODE ERROR".red().bold());
            println!("{}", "╠══════════════════════════════════════════════════════╣".red());
            println!("{}  {}", "║".red(), error.red());
            println!("{}  Size: {} bytes", "║".red(), raw_len);
            println!("{}  Hex:  {}", "║".red(), &raw_hex[..raw_hex.len().min(64)]);
            println!("{}", "╚══════════════════════════════════════════════════════╝".red());
        }
    }
}

fn display_compact(pkt: &DecodedPacket) {
    match pkt {
        DecodedPacket::Handshake {
            msg_type, session_id, packet_seq, total_bytes, ..
        } => {
            println!("[HANDSHAKE] type={} session={} seq={} size={}B",
                msg_type, &session_id[..16.min(session_id.len())], packet_seq, total_bytes);
        }
        DecodedPacket::Data {
            session_id, packet_seq, total_bytes, ..
        } => {
            println!("[DATA] session={} seq={} size={}B",
                &session_id[..16.min(session_id.len())], packet_seq, total_bytes);
        }
        DecodedPacket::Error { error, raw_len, .. } => {
            println!("[ERROR] {} ({}B)", error, raw_len);
        }
    }
}

fn display_json(pkt: &DecodedPacket) {
    match serde_json::to_string_pretty(pkt) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}

fn display_packet(pkt: &DecodedPacket, raw: &[u8], format: OutputFormat) {
    match format {
        OutputFormat::Pretty => display_pretty(pkt, raw),
        OutputFormat::Json => display_json(pkt),
        OutputFormat::Compact => display_compact(pkt),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// File scanning
// ─────────────────────────────────────────────────────────────────────────

fn scan_binary_file(data: &[u8], format: OutputFormat) -> usize {
    let magic_bytes = MAGIC.to_be_bytes();
    let mut count = 0;
    let mut pos = 0;

    while pos + 4 <= data.len() {
        if data[pos] == magic_bytes[0] && pos + 1 < data.len() && data[pos + 1] == magic_bytes[1] {
            // Found magic — try to decode
            let remaining = &data[pos..];
            let ver_hdrlen = if remaining.len() >= 4 {
                u16::from_be_bytes([remaining[2], remaining[3]])
            } else {
                pos += 1;
                continue;
            };
            let hdr_len = ver_hdrlen & 0x0FFF;

            // Determine expected header size
            let header_size = if hdr_len == 24 {
                HANDSHAKE_HEADER_SIZE
            } else if hdr_len == 11 {
                DATA_HEADER_SIZE
            } else {
                // Unknown, skip
                pos += 1;
                continue;
            };

            if remaining.len() >= header_size {
                count += 1;
                println!("\n{} Packet #{} at offset 0x{:04X} ({}):",
                    "►".bright_cyan(), count, pos, pos);
                let pkt = decode_packet(remaining);
                display_packet(&pkt, remaining, format);
                pos += header_size;
            } else {
                pos += 1;
            }
        } else {
            pos += 1;
        }
    }

    count
}

// ─────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Determine input mode
    if let Some(ref path) = cli.file {
        // Binary file mode
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{} Failed to read file '{}': {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        };
        println!("{} Scanning {} ({} bytes) for ZTLP packets...",
            "▶".bright_cyan(), path, data.len());
        let count = scan_binary_file(&data, cli.format);
        println!("\n{} Found {} packet(s).", "✓".green(), count);
    } else if cli.stdin {
        // Stdin mode — one hex packet per line
        let stdin = io::stdin();
        let mut count = 0;
        for line in stdin.lock().lines() {
            match line {
                Ok(hex_str) => {
                    let hex_str = hex_str.trim().to_string();
                    if hex_str.is_empty() || hex_str.starts_with('#') {
                        continue;
                    }
                    // Strip optional "0x" prefix
                    let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
                    match hex::decode(hex_str) {
                        Ok(data) => {
                            count += 1;
                            if matches!(cli.format, OutputFormat::Pretty) {
                                println!("\n{} Packet #{}:", "►".bright_cyan(), count);
                            }
                            let pkt = decode_packet(&data);
                            display_packet(&pkt, &data, cli.format);
                        }
                        Err(e) => {
                            eprintln!("{} Invalid hex on line {}: {}", "✗".red(), count + 1, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} Read error: {}", "✗".red(), e);
                    break;
                }
            }
        }
        if matches!(cli.format, OutputFormat::Pretty) {
            println!("\n{} Decoded {} packet(s) from stdin.", "✓".green(), count);
        }
    } else if let Some(ref hex_str) = cli.hex_data {
        // Single hex argument
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        match hex::decode(hex_str) {
            Ok(data) => {
                let pkt = decode_packet(&data);
                display_packet(&pkt, &data, cli.format);
            }
            Err(e) => {
                eprintln!("{} Invalid hex input: {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
    } else {
        // No input — show help
        eprintln!("No input specified. Use a hex argument, --stdin, or --file.");
        eprintln!("Run with --help for usage information.");
        std::process::exit(1);
    }
}
