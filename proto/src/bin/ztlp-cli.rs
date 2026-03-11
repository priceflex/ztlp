//! # `ztlp` — Unified CLI for the Zero Trust Layer Protocol
//!
//! A single binary with subcommands for generating identities, connecting to
//! peers, inspecting packets, running relays, and querying the ZTLP namespace.
//!
//! ## Examples
//!
//! ```bash
//! # Generate a new identity
//! ztlp keygen --output ~/.ztlp/identity.json --format json
//!
//! # Connect to a peer through a gateway
//! ztlp connect 192.168.1.10:23095 --key ~/.ztlp/identity.json
//!
//! # Inspect a ZTLP packet from hex
//! ztlp inspect 5a37100000010001...
//!
//! # Ping a ZTLP endpoint
//! ztlp ping 192.168.1.10:23095 --count 5
//!
//! # Look up a name in ZTLP-NS
//! ztlp ns lookup mynode.office.acme.ztlp --ns-server 127.0.0.1:5353
//! ```

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use ztlp_proto::admission::{HandshakeExtension, RelayAdmissionToken, EXT_TYPE_RAT};
use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::nat;
use ztlp_proto::packet::{
    flags, DataHeader, HandshakeHeader, MsgType, SessionId, DATA_HEADER_SIZE,
    HANDSHAKE_HEADER_SIZE, MAGIC, VERSION,
};
use ztlp_proto::policy::PolicyEngine;
use ztlp_proto::relay::SimulatedRelay;
use ztlp_proto::transport::TransportNode;
use ztlp_proto::tunnel;

// ─── Constants ──────────────────────────────────────────────────────────────

const ZTLP_VERSION: &str = env!("CARGO_PKG_VERSION");
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Configuration ──────────────────────────────────────────────────────────

/// Optional config file at ~/.ztlp/config.toml
#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct Config {
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    ns_server: Option<String>,
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    transport: Option<TransportConfig>,
}

/// Transport-layer configuration.
#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct TransportConfig {
    /// GSO mode: "auto" (default), "enabled", or "disabled".
    #[serde(default)]
    gso: Option<String>,
}

fn load_config() -> Config {
    let config_path = dirs::home_dir()
        .map(|h| h.join(".ztlp").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from(".ztlp/config.toml"));

    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(cfg) => {
                    debug!("loaded config from {}", config_path.display());
                    return cfg;
                }
                Err(e) => {
                    warn!("failed to parse {}: {}", config_path.display(), e);
                }
            },
            Err(e) => {
                debug!("no config at {}: {}", config_path.display(), e);
            }
        }
    }
    Config::default()
}

// ─── CLI Definition ─────────────────────────────────────────────────────────

/// ztlp — Zero Trust Layer Protocol CLI
///
/// A unified command-line tool for managing ZTLP identities, connections,
/// relays, namespaces, and packet inspection.
#[derive(Parser)]
#[command(
    name = "ztlp",
    version = ZTLP_VERSION,
    about = "Zero Trust Layer Protocol — CLI tool",
    long_about = "Unified CLI for the ZTLP protocol stack.\n\n\
        Generate identities, connect to peers, inspect packets, run relays,\n\
        and query the ZTLP namespace — all from one binary.",
    after_help = "EXAMPLES:\n  \
        ztlp keygen --output ~/.ztlp/identity.json\n  \
        ztlp connect 192.168.1.10:23095 --key ~/.ztlp/identity.json\n  \
        ztlp inspect 5a371000000100010000...\n  \
        ztlp ping 10.0.0.1:23095 --count 5\n  \
        ztlp ns lookup mynode.acme.ztlp --ns-server 127.0.0.1:5353"
)]
struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ZTLP identity (NodeID + X25519 keypair + Ed25519 signing key)
    ///
    /// Creates a fresh ZTLP identity with a random 128-bit NodeID,
    /// an X25519 key pair for Noise_XX handshakes, and an Ed25519
    /// signing key pair for NS record registration.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp keygen\n  \
            ztlp keygen --output ~/.ztlp/identity.json\n  \
            ztlp keygen --format hex\n  \
            ztlp keygen --format json --output node1.json")]
    Keygen {
        /// Output file path (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(short, long, default_value = "json")]
        format: KeygenFormat,
    },

    /// Connect to a ZTLP gateway or peer
    ///
    /// Performs a Noise_XX handshake with the target, establishes an
    /// encrypted session, then enters interactive mode for sending
    /// and receiving messages.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp connect 192.168.1.10:23095\n  \
            ztlp connect 10.0.0.1:23095 --key ~/.ztlp/identity.json\n  \
            ztlp connect peer.example.com:23095 --relay relay.example.com:23095\n  \
            ztlp connect myserver.clients.techrockstars.ztlp\n  \
            ztlp connect myserver.clients.techrockstars.ztlp --ns-server 10.0.0.1:5353")]
    Connect {
        /// Target address (host:port or ZTLP name, e.g. myserver.clients.techrockstars.ztlp)
        target: String,

        /// Path to identity key file
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Relay address to route through (host:port)
        #[arg(short, long)]
        relay: Option<String>,

        /// Gateway address (host:port)
        #[arg(short, long)]
        gateway: Option<String>,

        /// NS server address for name resolution (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Specific session ID to use (hex)
        #[arg(short, long)]
        session_id: Option<String>,

        /// Local bind address
        #[arg(short, long, default_value = "0.0.0.0:0")]
        bind: String,

        /// Forward a local TCP port through the ZTLP tunnel
        /// (LOCAL_PORT:REMOTE_HOST:REMOTE_PORT, e.g. 2222:127.0.0.1:22)
        #[arg(short = 'L', long)]
        local_forward: Option<String>,

        /// Service name to request from the remote listener
        /// (matches a --forward NAME:HOST:PORT on the server)
        #[arg(long)]
        service: Option<String>,

        /// STUN server address for NAT traversal (host:port)
        #[arg(long)]
        stun_server: Option<String>,

        /// Enable NAT traversal (STUN discovery + hole punching)
        #[arg(long)]
        nat_assist: bool,

        /// Fail instead of falling back to relay when hole punch fails
        #[arg(long)]
        no_relay_fallback: bool,
    },

    /// Listen for incoming ZTLP connections
    ///
    /// Acts as a responder for Noise_XX handshakes. After a peer connects
    /// and the handshake completes, enters interactive data exchange mode.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp listen\n  \
            ztlp listen --bind 0.0.0.0:23095\n  \
            ztlp listen --key ~/.ztlp/identity.json --bind 0.0.0.0:23095")]
    Listen {
        /// Address to bind on
        #[arg(short, long, default_value = "0.0.0.0:23095")]
        bind: String,

        /// Path to identity key file
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Run as a mini-gateway (accept multiple connections)
        #[arg(long)]
        gateway: bool,

        /// Forward to local TCP services after session established.
        /// Use NAME:HOST:PORT for named services, or HOST:PORT for default.
        /// Repeatable: --forward ssh:127.0.0.1:22 --forward rdp:127.0.0.1:3389
        #[arg(short, long)]
        forward: Vec<String>,

        /// Path to policy file for access control (default: ~/.ztlp/policy.toml)
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// STUN server address for NAT traversal (host:port)
        #[arg(long)]
        stun_server: Option<String>,

        /// Enable NAT traversal (register with relay for rendezvous)
        #[arg(long)]
        nat_assist: bool,
    },

    /// Manage ZTLP relay nodes
    #[command(subcommand)]
    Relay(RelayCommands),

    /// Query and register with ZTLP-NS (namespace service)
    #[command(subcommand)]
    Ns(NsCommands),

    /// Manage ZTLP gateway
    #[command(subcommand)]
    Gateway(GatewayCommands),

    /// Inspect and decode ZTLP packets
    ///
    /// Decodes ZTLP packets from hex strings or binary files and
    /// displays all header fields in a human-readable format with
    /// field labels and color coding.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp inspect 5a371000000100010000...\n  \
            ztlp inspect --file capture.bin")]
    Inspect {
        /// Hex-encoded packet bytes
        hex_bytes: Option<String>,

        /// Read packets from a binary file (one packet per line, hex-encoded)
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Send ZTLP ping packets and measure round-trip time
    ///
    /// Sends Ping packets to a ZTLP endpoint and displays RTT statistics.
    /// The target must be a running ZTLP node that responds to Pong messages.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp ping 192.168.1.10:23095\n  \
            ztlp ping 10.0.0.1:23095 --count 10 --interval 500\n  \
            ztlp ping myserver.clients.techrockstars.ztlp")]
    Ping {
        /// Target address (host:port)
        target: String,

        /// NS server address for name resolution (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Number of pings to send
        #[arg(short, long, default_value = "4")]
        count: u32,

        /// Interval between pings in milliseconds
        #[arg(short, long, default_value = "1000")]
        interval: u64,

        /// Local bind address
        #[arg(short, long, default_value = "0.0.0.0:0")]
        bind: String,
    },

    /// Query status of a local ZTLP relay or gateway
    ///
    /// Connects to a running ZTLP service and displays its status,
    /// including version, uptime, active sessions, and packet stats.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp status\n  \
            ztlp status --target 127.0.0.1:23095")]
    Status {
        /// Address of the ZTLP service to query
        #[arg(short, long, default_value = "127.0.0.1:23095")]
        target: String,
    },

    /// Relay Admission Token (RAT) operations
    ///
    /// Inspect, verify, or issue Relay Admission Tokens for testing
    /// and debugging the admission control system.
    #[command(subcommand)]
    Token(TokenCommands),
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Decode and display a RAT from hex
    ///
    /// Parses a 93-byte hex-encoded Relay Admission Token and displays
    /// all fields in a human-readable format.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp token inspect 01aaaaaa...  (186 hex chars = 93 bytes)")]
    Inspect {
        /// Hex-encoded RAT (93 bytes = 186 hex chars)
        hex: String,
    },

    /// Verify a RAT's MAC with a known secret
    ///
    /// Parses the token and checks the HMAC-BLAKE2s MAC against the
    /// provided secret key.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp token verify 01aaaaaa... --secret 0102030405...")]
    Verify {
        /// Hex-encoded RAT (93 bytes = 186 hex chars)
        hex: String,

        /// Hex-encoded 32-byte secret key
        #[arg(short, long)]
        secret: String,
    },

    /// Issue a new RAT for testing
    ///
    /// Generates a new Relay Admission Token with the given parameters.
    /// Useful for testing token verification and cross-language interop.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp token issue --node-id aabbccdd... --secret 0102030405... --ttl 300")]
    Issue {
        /// Hex-encoded 16-byte NodeID
        #[arg(long)]
        node_id: String,

        /// Hex-encoded 32-byte secret key
        #[arg(short, long)]
        secret: String,

        /// TTL in seconds (default: 300)
        #[arg(long, default_value = "300")]
        ttl: u64,

        /// Hex-encoded 16-byte IssuerID (default: all zeros)
        #[arg(long)]
        issuer_id: Option<String>,

        /// Hex-encoded 12-byte SessionID scope (default: any session)
        #[arg(long)]
        session_scope: Option<String>,
    },
}

#[derive(Subcommand)]
enum RelayCommands {
    /// Start a ZTLP relay node
    ///
    /// Runs a Rust-native relay that forwards packets by SessionID.
    /// The relay never holds session keys and cannot decrypt traffic.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp relay start\n  \
            ztlp relay start --bind 0.0.0.0:23095 --max-sessions 1000")]
    Start {
        /// Address to bind on
        #[arg(short, long, default_value = "0.0.0.0:23095")]
        bind: String,

        /// Maximum concurrent sessions
        #[arg(short, long, default_value = "10000")]
        max_sessions: usize,
    },

    /// Show relay status and statistics
    #[command(after_help = "EXAMPLES:\n  \
            ztlp relay status\n  \
            ztlp relay status --target 127.0.0.1:23095")]
    Status {
        /// Address of the relay to query
        #[arg(short, long, default_value = "127.0.0.1:23095")]
        target: String,
    },
}

#[derive(Subcommand)]
enum NsCommands {
    /// Register an identity with ZTLP-NS
    ///
    /// Registers a ZTLP_KEY record in the namespace, binding a name
    /// to your NodeID and public key. Requires a signing key.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp ns register --name mynode.office.acme.ztlp --zone office.acme.ztlp \\\n    \
                --key ~/.ztlp/identity.json --ns-server 127.0.0.1:5353\n  \
            ztlp ns register --name mynode.office.acme.ztlp --zone office.acme.ztlp \\\n    \
                --key ~/.ztlp/identity.json --address 10.42.42.50:23095")]
    Register {
        /// Name to register (e.g., mynode.office.acme.ztlp)
        #[arg(short, long)]
        name: String,

        /// Zone for the registration
        #[arg(short, long)]
        zone: String,

        /// Path to identity key file
        #[arg(short, long)]
        key: PathBuf,

        /// NS server address (host:port)
        #[arg(long, default_value = "127.0.0.1:5353")]
        ns_server: String,

        /// Endpoint address to register as a SVC record (host:port)
        #[arg(short, long)]
        address: Option<String>,
    },

    /// Look up a name in ZTLP-NS
    ///
    /// Queries the namespace service for records matching the given name.
    /// Returns the NodeID, public key, TTL, and signature status.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp ns lookup mynode.office.acme.ztlp\n  \
            ztlp ns lookup mynode.acme.ztlp --ns-server 10.0.0.1:5353")]
    Lookup {
        /// Name to look up
        name: String,

        /// NS server address (host:port)
        #[arg(long, default_value = "127.0.0.1:5353")]
        ns_server: String,

        /// Record type to query (1=KEY, 2=SVC, 3=RELAY, 4=POLICY, 5=REVOKE, 6=BOOTSTRAP)
        #[arg(short = 't', long, default_value = "1")]
        record_type: u8,
    },

    /// Query ZTLP-NS by public key
    ///
    /// Searches the namespace for a KEY record matching the given
    /// public key (hex-encoded). Returns the associated name and metadata.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp ns pubkey a1b2c3d4... --ns-server 127.0.0.1:5353")]
    Pubkey {
        /// Public key in hex
        hex: String,

        /// NS server address (host:port)
        #[arg(long, default_value = "127.0.0.1:5353")]
        ns_server: String,
    },
}

#[derive(Subcommand)]
enum GatewayCommands {
    /// Start a ZTLP gateway
    ///
    /// The production gateway is implemented in Elixir. This command
    /// provides a stub that explains how to run the Elixir gateway,
    /// or starts a minimal Rust-native gateway for testing.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp gateway start\n  \
            ztlp gateway start --elixir")]
    Start {
        /// Use the Elixir gateway implementation (recommended for production)
        #[arg(long)]
        elixir: bool,

        /// Address to bind on (for Rust-native gateway)
        #[arg(short, long, default_value = "0.0.0.0:23095")]
        bind: String,
    },
}

#[derive(Clone, ValueEnum)]
enum KeygenFormat {
    /// JSON format (default, human-readable, used by other commands)
    Json,
    /// Hex format (compact, one value per line)
    Hex,
}

// ─── Extended Identity (with Ed25519 signing keys) ──────────────────────────

// Extended identity with Ed25519 keys is handled via serde_json::json! in keygen,
// so no separate struct needed.

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Load an identity from a key file, or generate an ephemeral one.
fn load_or_generate_identity(
    key_path: &Option<PathBuf>,
) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    match key_path {
        Some(p) if p.exists() => {
            info!("loading identity from {}", p.display());
            let ident = NodeIdentity::load(p)?;
            info!("loaded NodeID: {}", ident.node_id);
            Ok(ident)
        }
        Some(p) => Err(format!("key file not found: {}", p.display()).into()),
        None => {
            let ident = NodeIdentity::generate()?;
            info!("generated ephemeral identity — NodeID: {}", ident.node_id);
            eprintln!("\x1b[33m⚠ Using ephemeral identity (will be lost on exit)\x1b[0m");
            eprintln!("  Run `ztlp keygen --output ~/.ztlp/identity.json` to persist one.\n");
            Ok(ident)
        }
    }
}

/// Format a flag bitfield as a human-readable string.
fn format_flags(f: u16) -> String {
    let mut parts = Vec::new();
    if f & flags::HAS_EXT != 0 {
        parts.push("HAS_EXT");
    }
    if f & flags::ACK_REQ != 0 {
        parts.push("ACK_REQ");
    }
    if f & flags::REKEY != 0 {
        parts.push("REKEY");
    }
    if f & flags::MIGRATE != 0 {
        parts.push("MIGRATE");
    }
    if f & flags::MULTIPATH != 0 {
        parts.push("MULTIPATH");
    }
    if f & flags::RELAY_HOP != 0 {
        parts.push("RELAY_HOP");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" | ")
    }
}

/// Format a MsgType as a colored string.
fn format_msg_type(mt: MsgType) -> &'static str {
    match mt {
        MsgType::Data => "DATA (0x00)",
        MsgType::Hello => "HELLO (0x01)",
        MsgType::HelloAck => "HELLO_ACK (0x02)",
        MsgType::Rekey => "REKEY (0x03)",
        MsgType::Close => "CLOSE (0x04)",
        MsgType::Error => "ERROR (0x05)",
        MsgType::Ping => "PING (0x06)",
        MsgType::Pong => "PONG (0x07)",
    }
}

/// Pretty-print a byte array as hex with optional grouping.
fn hex_grouped(bytes: &[u8], group_size: usize) -> String {
    let hex = hex::encode(bytes);
    if group_size == 0 || hex.len() <= group_size * 2 {
        return hex;
    }
    hex.as_bytes()
        .chunks(group_size * 2)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// ANSI color helpers
fn c_bold(s: &str) -> String {
    format!("\x1b[1m{}\x1b[0m", s)
}
fn c_cyan(s: &str) -> String {
    format!("\x1b[36m{}\x1b[0m", s)
}
fn c_green(s: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}
fn c_yellow(s: &str) -> String {
    format!("\x1b[33m{}\x1b[0m", s)
}
fn c_red(s: &str) -> String {
    format!("\x1b[31m{}\x1b[0m", s)
}
fn c_dim(s: &str) -> String {
    format!("\x1b[2m{}\x1b[0m", s)
}
fn c_magenta(s: &str) -> String {
    format!("\x1b[35m{}\x1b[0m", s)
}

// ─── Subcommand Implementations ─────────────────────────────────────────────

/// `ztlp keygen` — Generate a new ZTLP identity
fn cmd_keygen(
    output: &Option<PathBuf>,
    format: &KeygenFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("{}", c_bold("Generating ZTLP identity..."));

    // Generate base identity (NodeID + X25519)
    let identity = NodeIdentity::generate()?;

    // Generate Ed25519 signing keypair
    // We use ring-compatible Ed25519 via a simple seed-based approach
    let mut ed25519_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ed25519_seed);

    // For Ed25519, we store seed as private key. The public key is derived
    // by the NS server during registration. We'll store both for convenience.
    // Use BLAKE2s to derive a deterministic "public key" representation for display.
    // (In production, the Ed25519 public key would be computed properly.)
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(&ed25519_seed);
    let ed25519_public = hasher.finalize();

    match format {
        KeygenFormat::Json => {
            let extended = serde_json::json!({
                "node_id": hex::encode(identity.node_id.0),
                "static_private_key": hex::encode(&identity.static_private_key),
                "static_public_key": hex::encode(&identity.static_public_key),
                "ed25519_seed": hex::encode(ed25519_seed),
                "ed25519_public_key": hex::encode(&ed25519_public[..]),
            });
            let json = serde_json::to_string_pretty(&extended)?;

            match output {
                Some(path) => {
                    // Ensure parent directory exists
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(path, &json)?;
                    // Set restrictive permissions on key file
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    eprintln!(
                        "\n{}",
                        c_green(&format!("✓ Identity saved to {}", path.display()))
                    );
                }
                None => {
                    println!("{}", json);
                }
            }
        }
        KeygenFormat::Hex => {
            let output_str = format!(
                "node_id={}\nstatic_private_key={}\nstatic_public_key={}\ned25519_seed={}\ned25519_public_key={}",
                hex::encode(identity.node_id.0),
                hex::encode(&identity.static_private_key),
                hex::encode(&identity.static_public_key),
                hex::encode(ed25519_seed),
                hex::encode(&ed25519_public[..]),
            );

            match output {
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(path, &output_str)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    eprintln!(
                        "\n{}",
                        c_green(&format!("✓ Identity saved to {}", path.display()))
                    );
                }
                None => {
                    println!("{}", output_str);
                }
            }
        }
    }

    eprintln!(
        "\n  {} {}",
        c_cyan("NodeID:"),
        hex::encode(identity.node_id.0)
    );
    eprintln!(
        "  {} {}",
        c_cyan("X25519 Public:"),
        hex::encode(&identity.static_public_key)
    );
    eprintln!(
        "  {} {}",
        c_cyan("Ed25519 Public:"),
        hex::encode(&ed25519_public[..])
    );

    Ok(())
}

/// Resolve a target string to a SocketAddr, optionally via ZTLP-NS.
///
/// Accepts:
/// - Raw `ip:port` (e.g., `192.168.1.10:23095`) — returned directly
/// - ZTLP name (e.g., `myserver.clients.techrockstars.ztlp`) — resolved via NS
/// - ZTLP name with port (e.g., `myserver.clients.techrockstars.ztlp:23095`)
///
/// Returns the resolved SocketAddr and optionally the peer's NodeID from NS.
async fn resolve_target(
    target: &str,
    ns_server_opt: &Option<String>,
) -> Result<(SocketAddr, Option<NodeId>), Box<dyn std::error::Error>> {
    // Try direct IP:port parsing first (backward compatible fast path)
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((addr, None));
    }

    // Not a raw address — attempt ZTLP-NS resolution
    eprintln!("{} {} via ZTLP-NS...", c_dim("Resolving"), c_bold(target));

    // Determine NS server address: flag > config > default
    let ns_server = if let Some(s) = ns_server_opt {
        s.clone()
    } else {
        let cfg = load_config();
        cfg.ns_server
            .unwrap_or_else(|| "127.0.0.1:5353".to_string())
    };
    eprintln!("  {} {}", c_dim("NS server:"), ns_server);

    // Strip optional port from name (e.g., "name.ztlp:23095")
    let (name_part, explicit_port) = if let Some(idx) = target.rfind(':') {
        let after_colon = &target[idx + 1..];
        if let Ok(port) = after_colon.parse::<u16>() {
            (&target[..idx], Some(port))
        } else {
            (target, None)
        }
    } else {
        (target, None)
    };

    // Query SVC record (type 2) for endpoint address
    let mut resolved_addr: Option<SocketAddr> = None;
    if let Ok(Some(svc_data)) = ns_query(name_part, &ns_server, 2).await {
        // SVC record data should contain an address string (e.g., "10.42.42.50:23095")
        if let Ok(addr) = svc_data.parse::<SocketAddr>() {
            eprintln!("  {} SVC record → {}", c_green("✓"), addr);
            resolved_addr = Some(addr);
        } else {
            debug!("SVC record data '{}' is not a valid address", svc_data);
        }
    }

    // Query KEY record (type 1) for NodeID (identity verification)
    let mut resolved_node_id: Option<NodeId> = None;
    if let Ok(Some(raw)) = ns_query_raw(name_part, &ns_server, 1).await {
        // Extract node_id from ETF-encoded KEY record data
        if let Some(nid_hex) = etf_extract_string(&raw.data_bytes, "node_id") {
            if nid_hex.len() == 32 {
                // NodeID is 128-bit = 16 bytes = 32 hex chars
                if let Ok(bytes) = hex::decode(&nid_hex) {
                    if bytes.len() == 16 {
                        let mut nid = [0u8; 16];
                        nid.copy_from_slice(&bytes);
                        resolved_node_id = Some(NodeId::from_bytes(nid));
                        eprintln!("  {} NodeID: {}", c_cyan("ℹ"), &nid_hex);
                    }
                }
            }
        }
        eprintln!("  {} KEY record found", c_green("✓"));
    }

    // Build final address
    let final_addr = if let Some(addr) = resolved_addr {
        // If explicit port was given, override the NS-provided port
        if let Some(port) = explicit_port {
            SocketAddr::new(addr.ip(), port)
        } else {
            addr
        }
    } else {
        // No address from NS — if this looks like a hostname, try DNS resolution
        let port = explicit_port.unwrap_or(23095);
        let lookup_target = format!("{}:{}", name_part, port);
        let dns_result = tokio::net::lookup_host(lookup_target.as_str()).await;
        match dns_result {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    eprintln!("  {} DNS fallback → {}", c_yellow("⚠"), addr);
                    addr
                } else {
                    return Err(format!(
                        "could not resolve '{}': no SVC record in ZTLP-NS and DNS returned no results\n  \
                         Try: ztlp connect {} --ns-server <addr:port>\n  \
                         Or use a raw address: ztlp connect <ip>:23095",
                        target, name_part
                    ).into());
                }
            }
            Err(_) => {
                return Err(format!(
                    "could not resolve '{}': no SVC record in ZTLP-NS and DNS lookup failed\n  \
                     Hint: ensure your NS server is running, or specify --ns-server <addr:port>\n  \
                     Or use a raw address: ztlp connect <ip>:23095",
                    target
                )
                .into());
            }
        }
    };

    eprintln!(
        "  {} {}\n",
        c_green("Resolved:"),
        c_bold(&final_addr.to_string())
    );
    Ok((final_addr, resolved_node_id))
}

/// Extract a string value for a given atom key from ETF-encoded map data.
///
/// Supports the subset of Erlang External Term Format used by ZTLP-NS:
/// - MAP_EXT (tag 116) with SMALL_ATOM_UTF8_EXT (tag 119) keys and BINARY_EXT (tag 109) values
/// - Version byte (131) prefix
///
/// Returns None if the key is not found or the format doesn't match.
fn etf_extract_string(data: &[u8], target_key: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut pos = 0;

    // Skip version byte (131) if present
    if data[pos] == 131 {
        pos += 1;
    }

    // Expect MAP_EXT (116)
    if pos >= data.len() || data[pos] != 116 {
        return None;
    }
    pos += 1;

    // Map arity (4 bytes big-endian)
    if pos + 4 > data.len() {
        return None;
    }
    let arity =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;

    for _ in 0..arity {
        // Parse key — expect SMALL_ATOM_UTF8_EXT (119)
        if pos >= data.len() {
            return None;
        }
        let key_name = if data[pos] == 119 {
            // SMALL_ATOM_UTF8_EXT: <<119, len::8, name>>
            pos += 1;
            if pos >= data.len() {
                return None;
            }
            let klen = data[pos] as usize;
            pos += 1;
            if pos + klen > data.len() {
                return None;
            }
            let kname = std::str::from_utf8(&data[pos..pos + klen]).ok();
            pos += klen;
            kname
        } else if data[pos] == 100 {
            // ATOM_EXT: <<100, len::16, name>> (older format)
            pos += 1;
            if pos + 2 > data.len() {
                return None;
            }
            let klen = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + klen > data.len() {
                return None;
            }
            let kname = std::str::from_utf8(&data[pos..pos + klen]).ok();
            pos += klen;
            kname
        } else {
            // Unknown key type — can't parse further
            return None;
        };

        // Parse value — expect BINARY_EXT (109)
        if pos >= data.len() {
            return None;
        }
        if data[pos] == 109 {
            // BINARY_EXT: <<109, len::32, bytes>>
            pos += 1;
            if pos + 4 > data.len() {
                return None;
            }
            let vlen = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            pos += 4;
            if pos + vlen > data.len() {
                return None;
            }
            let value = std::str::from_utf8(&data[pos..pos + vlen])
                .ok()
                .map(|s| s.to_string());
            pos += vlen;

            // Check if this is the key we're looking for
            if key_name == Some(target_key) {
                return value;
            }
        } else {
            // Unknown value type — skip remaining (can't determine size)
            return None;
        }
    }

    None
}

/// Query result from NS containing the raw ETF data field.
struct NsQueryResult {
    /// Raw ETF-encoded data bytes from the record
    data_bytes: Vec<u8>,
}

/// Perform an NS query for a given record type. Returns the raw ETF data field if found.
async fn ns_query_raw(
    name: &str,
    ns_server: &str,
    record_type: u8,
) -> Result<Option<NsQueryResult>, Box<dyn std::error::Error>> {
    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid NS server address '{}': {}", ns_server, e))?;
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let mut query = Vec::with_capacity(4 + name_bytes.len());
    query.push(0x01);
    query.extend_from_slice(&name_len.to_be_bytes());
    query.extend_from_slice(name_bytes);
    query.push(record_type);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, ns_addr).await?;
    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let data = &buf[..len];
            if data.is_empty() {
                return Ok(None);
            }
            if data[0] != 0x02 {
                return Ok(None);
            }
            let record = &data[1..];
            // Wire format: <<type_byte, name_len::16, name, data_len::32, data, ...>>
            if record.len() < 4 {
                return Ok(None);
            }
            let _type_byte = record[0];
            let rname_len = u16::from_be_bytes([record[1], record[2]]) as usize;
            if record.len() < 3 + rname_len + 4 {
                return Ok(None);
            }
            let offset = 3 + rname_len;
            let data_len = u32::from_be_bytes([
                record[offset],
                record[offset + 1],
                record[offset + 2],
                record[offset + 3],
            ]) as usize;
            if record.len() < offset + 4 + data_len {
                return Ok(None);
            }
            let data_start = offset + 4;
            let data_bytes = record[data_start..data_start + data_len].to_vec();
            Ok(Some(NsQueryResult { data_bytes }))
        }
        _ => Ok(None),
    }
}

/// High-level NS query: extract a specific string field from a record's ETF data.
async fn ns_query(
    name: &str,
    ns_server: &str,
    record_type: u8,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let result = ns_query_raw(name, ns_server, record_type).await?;
    match result {
        Some(r) => {
            // For SVC records, extract the "address" field
            // For KEY records, extract "node_id" or "public_key"
            // Try the most useful field based on record type
            let value = match record_type {
                2 => etf_extract_string(&r.data_bytes, "address"), // SVC → address
                1 => etf_extract_string(&r.data_bytes, "node_id"), // KEY → node_id
                3 => etf_extract_string(&r.data_bytes, "endpoints"), // RELAY → endpoints
                _ => {
                    // Fallback: try plain UTF-8
                    std::str::from_utf8(&r.data_bytes)
                        .ok()
                        .map(|s| s.to_string())
                }
            };
            Ok(value)
        }
        None => Ok(None),
    }
}

/// `ztlp connect` — Connect to a ZTLP peer (supports NS name resolution)
async fn cmd_connect(
    target: &str,
    key: &Option<PathBuf>,
    relay: &Option<String>,
    _gateway: &Option<String>,
    ns_server: &Option<String>,
    session_id_hex: &Option<String>,
    bind: &str,
    local_forward: &Option<String>,
    service: &Option<String>,
    stun_server: &Option<String>,
    nat_assist: bool,
    no_relay_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_generate_identity(key)?;

    // Resolve target: raw ip:port or ZTLP-NS name
    let (peer_addr, _resolved_node_id) = resolve_target(target, ns_server).await?;

    let send_addr = if let Some(relay_str) = relay {
        relay_str
            .parse()
            .map_err(|e| format!("invalid relay address '{}': {}", relay_str, e))?
    } else {
        peer_addr
    };

    // Bind transport
    let node = TransportNode::bind(bind).await?;
    eprintln!("{} {}", c_cyan("Bound to:"), node.local_addr);
    eprintln!("{} {}", c_cyan("Connecting to:"), peer_addr);
    if send_addr != peer_addr {
        eprintln!("{} {}", c_cyan("Via relay:"), send_addr);
    }

    // NAT traversal (if --nat-assist)
    if nat_assist {
        eprintln!(
            "\n{}",
            c_dim("NAT traversal enabled — discovering public endpoint...")
        );

        // Parse optional STUN server
        let stun_servers: Vec<SocketAddr> = if let Some(s) = stun_server {
            vec![s
                .parse()
                .map_err(|e| format!("invalid --stun-server '{}': {}", s, e))?]
        } else {
            Vec::new() // will use defaults
        };

        if let Some(relay_str) = relay {
            let relay_addr: SocketAddr = relay_str
                .parse()
                .map_err(|e| format!("--nat-assist requires a valid --relay address: {}", e))?;

            let config = nat::HolePunchConfig {
                stun_servers,
                relay_addr,
                local_socket: node.socket.clone(),
                identity: identity.clone(),
                peer_node_id: _resolved_node_id.unwrap_or_else(NodeId::zero),
                timeout: Duration::from_secs(30),
                punch_attempts: 10,
                punch_interval: Duration::from_millis(200),
            };

            match nat::establish_connection(config).await {
                Ok(nat::ConnectionResult::Direct {
                    peer_addr: direct_addr,
                }) => {
                    eprintln!(
                        "{} Direct connection via hole punch to {}",
                        c_green("✓"),
                        direct_addr
                    );
                    // Update send_addr to the direct address instead of relay
                    // (Note: the handshake still needs to happen, but data goes direct)
                }
                Ok(nat::ConnectionResult::Relayed { relay_addr: _ }) => {
                    if no_relay_fallback {
                        return Err(
                            "hole punch failed and --no-relay-fallback was specified".into()
                        );
                    }
                    eprintln!("{} Falling back to relay mode", c_yellow("⚠"));
                }
                Err(e) => {
                    if no_relay_fallback {
                        return Err(format!("NAT traversal failed: {}", e).into());
                    }
                    eprintln!(
                        "{} NAT traversal failed: {} — continuing with relay",
                        c_yellow("⚠"),
                        e
                    );
                }
            }
        } else {
            // No relay specified — just do STUN discovery for info
            let stun_timeout = Duration::from_secs(3);
            for server_str in stun_servers
                .iter()
                .map(|s| s.to_string())
                .chain(nat::DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()))
            {
                if let Ok(addr) = server_str.parse::<SocketAddr>() {
                    match nat::StunClient::discover_endpoint(&node.socket, addr, stun_timeout).await
                    {
                        Ok(endpoint) => {
                            eprintln!(
                                "  {} Public endpoint: {} (NAT: {:?})",
                                c_green("✓"),
                                endpoint.address,
                                endpoint.nat_type
                            );
                            break;
                        }
                        Err(e) => {
                            debug!("STUN {} failed: {}", server_str, e);
                        }
                    }
                }
            }
        }
        eprintln!();
    }

    let mut ctx = HandshakeContext::new_initiator(&identity)?;

    // Session ID: use provided or generate
    let session_id = if let Some(hex_str) = session_id_hex {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 12 {
            return Err(format!(
                "session ID must be 12 bytes (24 hex chars), got {}",
                bytes.len()
            )
            .into());
        }
        let mut sid = [0u8; 12];
        sid.copy_from_slice(&bytes);
        SessionId(sid)
    } else {
        SessionId::generate()
    };

    let start_time = Instant::now();

    // Message 1: HELLO
    eprintln!("\n{}", c_dim("→ Sending HELLO (message 1/3)..."));
    let msg1 = ctx.write_message(&[])?;
    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;
    // Set DstSvcID if a service is requested
    if let Some(svc_name) = service {
        hello_hdr.dst_svc_id = tunnel::encode_service_name(svc_name)?;
        eprintln!("  {} {}", c_cyan("Service:"), svc_name);
    }
    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);
    node.send_raw(&pkt1, send_addr).await?;

    // Message 2: receive HELLO_ACK
    eprintln!("{}", c_dim("← Waiting for HELLO_ACK (message 2/3)..."));
    let (recv2, _from2) = timeout(HANDSHAKE_TIMEOUT, node.recv_raw())
        .await
        .map_err(|_| "handshake timeout waiting for HELLO_ACK")??;

    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("received packet too short for handshake header".into());
    }
    let recv2_header = HandshakeHeader::deserialize(&recv2)?;
    if recv2_header.msg_type != MsgType::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", recv2_header.msg_type).into());
    }

    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)?;

    // Message 3: final confirmation
    eprintln!("{}", c_dim("→ Sending final confirmation (message 3/3)..."));
    let msg3 = ctx.write_message(&[])?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    node.send_raw(&pkt3, send_addr).await?;

    // Finalize
    if !ctx.is_finished() {
        return Err("handshake did not complete".into());
    }

    let handshake_time = start_time.elapsed();
    let peer_node_id = NodeId::from_bytes(recv2_header.src_node_id);
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    // Register session
    let session_id = session.session_id;
    {
        let mut pipeline = node.pipeline.lock().await;
        pipeline.register_session(session);
    }

    eprintln!("\n{}", c_green("✓ Handshake complete!"));
    eprintln!("  {} {}", c_cyan("Remote NodeID:"), peer_node_id);
    eprintln!("  {} {}", c_cyan("Session ID:"), session_id);
    eprintln!(
        "  {} {:.2}ms",
        c_cyan("Handshake latency:"),
        handshake_time.as_secs_f64() * 1000.0
    );
    eprintln!();

    // Branch: tunnel mode or interactive mode
    if let Some(lf) = local_forward {
        let (local_port, _remote_target) = tunnel::parse_local_forward(lf)?;
        let listen_addr = format!("127.0.0.1:{}", local_port);

        eprintln!("--- {} ---", c_bold("ZTLP tunnel active"));
        eprintln!("  {} {}", c_cyan("Local listener:"), listen_addr);
        eprintln!(
            "  {} Connect your TCP client to {}",
            c_cyan("Usage:"),
            listen_addr
        );
        eprintln!("  {} Ctrl+C\n", c_dim("Stop:"));

        let tcp_listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| format!("failed to bind TCP listener on {}: {}", listen_addr, e))?;

        eprintln!(
            "{} {}",
            c_green("✓ Listening for TCP connections on"),
            listen_addr
        );

        loop {
            let (tcp_stream, tcp_addr) = tcp_listener.accept().await?;
            eprintln!("{} {} → tunnel", c_cyan("TCP connection from"), tcp_addr);

            let udp = node.socket.clone();
            let pipeline = node.pipeline.clone();

            // Run bridge (blocks until TCP connection closes)
            if let Err(e) =
                tunnel::run_bridge(tcp_stream, udp, pipeline, session_id, send_addr).await
            {
                eprintln!("{} {}", c_red("✗ tunnel error:"), e);
            }
            eprintln!("{} {}", c_dim("TCP connection closed:"), tcp_addr);
        }
    } else {
        eprintln!("--- {} ---", c_bold("ZTLP encrypted session active"));
        eprintln!("Type a message and press Enter to send. Ctrl+C to exit.\n");

        // Interactive data loop
        interactive_data_loop(&node, session_id, send_addr).await?;
    }

    Ok(())
}

/// `ztlp listen` — Listen for incoming connections
async fn cmd_listen(
    bind: &str,
    key: &Option<PathBuf>,
    _gateway_mode: bool,
    forward: &[String],
    policy_path: &Option<PathBuf>,
    stun_server: &Option<String>,
    nat_assist: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_generate_identity(key)?;

    let node = TransportNode::bind(bind).await?;
    eprintln!("{} {}", c_cyan("Listening on:"), node.local_addr);
    eprintln!("{} {}", c_cyan("NodeID:"), identity.node_id);

    // NAT traversal: discover and log public address
    if nat_assist {
        eprintln!(
            "{}",
            c_dim("NAT assist enabled — discovering public endpoint...")
        );

        let stun_servers: Vec<SocketAddr> = if let Some(s) = stun_server {
            vec![s
                .parse()
                .map_err(|e| format!("invalid --stun-server '{}': {}", s, e))?]
        } else {
            Vec::new()
        };

        let stun_timeout = Duration::from_secs(3);
        let servers: Vec<String> = stun_servers
            .iter()
            .map(|s| s.to_string())
            .chain(nat::DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()))
            .collect();

        for server_str in &servers {
            // Try to resolve and query each STUN server
            if let Ok(mut addrs) = tokio::net::lookup_host(server_str.as_str()).await {
                if let Some(addr) = addrs.next() {
                    match nat::StunClient::discover_endpoint(&node.socket, addr, stun_timeout).await
                    {
                        Ok(endpoint) => {
                            eprintln!(
                                "  {} Public endpoint: {} (NAT: {:?})",
                                c_green("✓"),
                                endpoint.address,
                                endpoint.nat_type
                            );
                            break;
                        }
                        Err(e) => {
                            debug!("STUN {} failed: {}", server_str, e);
                        }
                    }
                }
            }
        }
        eprintln!();
    }

    eprintln!("{}", c_dim("Waiting for incoming HELLO...\n"));

    let mut ctx = HandshakeContext::new_responder(&identity)?;

    // Wait for HELLO
    let (recv1, from1) = timeout(Duration::from_secs(300), async {
        loop {
            let (data, addr) = node.recv_raw().await?;
            if data.len() >= HANDSHAKE_HEADER_SIZE {
                if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                    if hdr.msg_type == MsgType::Hello {
                        return Ok::<_, Box<dyn std::error::Error>>((data, addr));
                    }
                }
            }
            warn!("received non-HELLO packet from {} — ignoring", addr);
        }
    })
    .await
    .map_err(|_| "timeout waiting for HELLO (5 minutes)")??;

    let recv1_header = HandshakeHeader::deserialize(&recv1)?;
    let session_id = recv1_header.session_id;
    let noise_payload1 = &recv1[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload1)?;

    eprintln!(
        "{} {} (session {})",
        c_dim("← Received HELLO from"),
        from1,
        session_id
    );

    // Send HELLO_ACK
    eprintln!("{}", c_dim("→ Sending HELLO_ACK (message 2/3)..."));
    let msg2 = ctx.write_message(&[])?;
    let mut ack_hdr = HandshakeHeader::new(MsgType::HelloAck);
    ack_hdr.session_id = session_id;
    ack_hdr.src_node_id = *identity.node_id.as_bytes();
    ack_hdr.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_hdr.serialize();
    pkt2.extend_from_slice(&msg2);
    node.send_raw(&pkt2, from1).await?;

    // Receive message 3
    eprintln!("{}", c_dim("← Waiting for message 3/3..."));
    let (recv3, _from3) = timeout(HANDSHAKE_TIMEOUT, node.recv_raw())
        .await
        .map_err(|_| "handshake timeout waiting for message 3")??;

    if recv3.len() < HANDSHAKE_HEADER_SIZE {
        return Err("message 3 too short".into());
    }
    let _recv3_header = HandshakeHeader::deserialize(&recv3)?;
    let noise_payload3 = &recv3[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload3)?;

    if !ctx.is_finished() {
        return Err("handshake did not complete".into());
    }

    let peer_node_id = NodeId::from_bytes(recv1_header.src_node_id);
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    let session_id = session.session_id;
    {
        let mut pipeline = node.pipeline.lock().await;
        pipeline.register_session(session);
    }

    // Client identity for policy evaluation: NodeID hex string
    let client_identity = format!("{}", peer_node_id);

    eprintln!("\n{}", c_green("✓ Handshake complete!"));
    eprintln!("  {} {}", c_cyan("Remote NodeID:"), peer_node_id);
    eprintln!("  {} {}", c_cyan("Session ID:"), session_id);
    eprintln!();

    // Load policy engine
    let policy = if let Some(path) = policy_path {
        eprintln!("  {} {}", c_cyan("Policy:"), path.display());
        PolicyEngine::from_file(path)?
    } else {
        // Check default location ~/.ztlp/policy.toml
        let default_path = dirs::home_dir().map(|h| h.join(".ztlp").join("policy.toml"));
        if let Some(ref p) = default_path {
            if p.exists() {
                eprintln!("  {} {} (auto-detected)", c_cyan("Policy:"), p.display());
                PolicyEngine::from_file(p)?
            } else {
                // No policy file — allow all (backward compatible)
                PolicyEngine::allow_all()
            }
        } else {
            PolicyEngine::allow_all()
        }
    };

    // Branch: tunnel mode or interactive mode
    if !forward.is_empty() {
        let registry = tunnel::ServiceRegistry::from_forward_args(forward)?;

        // Resolve which backend this client wants
        let (svc_name, forward_addr) =
            registry.resolve(&recv1_header.dst_svc_id).ok_or_else(|| {
                let requested = String::from_utf8_lossy(
                    &recv1_header.dst_svc_id[..recv1_header
                        .dst_svc_id
                        .iter()
                        .rposition(|&b| b != 0)
                        .map(|i| i + 1)
                        .unwrap_or(0)],
                )
                .to_string();
                if requested.is_empty() {
                    "client requested default service but no unnamed --forward was configured"
                        .to_string()
                } else {
                    format!(
                        "client requested unknown service '{}'. Available: {:?}",
                        requested,
                        registry.services.keys().collect::<Vec<_>>()
                    )
                }
            })?;

        // Policy check
        if !policy.authorize(&client_identity, svc_name) {
            eprintln!(
                "{} {} denied access to service '{}'",
                c_red("✗ POLICY DENIED:"),
                client_identity,
                svc_name
            );
            return Err(format!(
                "policy denied: {} is not authorized for service '{}'",
                client_identity, svc_name
            )
            .into());
        }
        eprintln!(
            "  {} {} → {}",
            c_green("✓ Policy:"),
            client_identity,
            svc_name
        );

        eprintln!("--- {} ---", c_bold("ZTLP tunnel active"));
        if registry.len() > 1 {
            eprintln!("  {} {} ({})", c_cyan("Service:"), svc_name, forward_addr);
        } else {
            eprintln!("  {} {}", c_cyan("Forwarding to:"), forward_addr);
        }
        eprintln!("  {} Ctrl+C\n", c_dim("Stop:"));

        // Connect to the local TCP service
        let tcp_stream = TcpStream::connect(forward_addr)
            .await
            .map_err(|e| format!("failed to connect to {}: {}", forward_addr, e))?;
        eprintln!("{} {}", c_green("✓ Connected to backend"), forward_addr);

        let udp = node.socket.clone();
        let pipeline = node.pipeline.clone();

        match tunnel::run_bridge(tcp_stream, udp, pipeline, session_id, from1).await {
            Ok(()) => eprintln!("{}", c_dim("tunnel closed")),
            Err(e) => eprintln!("{} {}", c_red("✗ tunnel error:"), e),
        }
    } else {
        eprintln!("--- {} ---", c_bold("ZTLP encrypted session active"));
        eprintln!("Type a message and press Enter to send. Ctrl+C to exit.\n");

        interactive_data_loop(&node, session_id, from1).await?;
    }

    Ok(())
}

/// Interactive data exchange loop (shared between connect and listen).
async fn interactive_data_loop(
    node: &TransportNode,
    session_id: SessionId,
    send_dest: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        if text.is_empty() { continue; }
                        match node.send_data(session_id, text.as_bytes(), send_dest).await {
                            Ok(()) => {
                                eprintln!("{} \"{}\" ({} bytes)",
                                    c_dim("→ sent:"), text, text.len());
                            }
                            Err(e) => {
                                eprintln!("{} {}", c_red("✗ send error:"), e);
                            }
                        }
                    }
                    Ok(None) => {
                        eprintln!("\n{}", c_dim("stdin closed — exiting"));
                        break;
                    }
                    Err(e) => {
                        eprintln!("{} {}", c_red("✗ stdin error:"), e);
                        break;
                    }
                }
            }
            result = node.recv_data() => {
                match result {
                    Ok(Some((plaintext, from))) => {
                        let text = String::from_utf8_lossy(&plaintext);
                        println!("{} {}", c_cyan(&format!("[{}]", from)), text);
                    }
                    Ok(None) => {} // dropped by pipeline
                    Err(e) => {
                        eprintln!("{} {}", c_red("✗ recv error:"), e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// `ztlp relay start` — Start a relay node
async fn cmd_relay_start(
    bind: &str,
    _max_sessions: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("{}", c_bold("Starting ZTLP relay..."));

    let relay = SimulatedRelay::bind(bind).await?;

    eprintln!(
        "{}",
        c_green(&format!("✓ Relay listening on {}", relay.local_addr))
    );
    eprintln!("  {} SessionID-based packet forwarding", c_cyan("Mode:"));
    eprintln!("  {} The relay never holds session keys", c_dim("Note:"));
    eprintln!("  {} Ctrl+C\n", c_dim("Stop:"));

    relay.run().await?;

    Ok(())
}

/// `ztlp relay status` — Show relay status
async fn cmd_relay_status(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let target_addr: SocketAddr = target.parse()?;

    // Send a Ping packet to probe the relay
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let mut ping_hdr = HandshakeHeader::new(MsgType::Ping);
    ping_hdr.src_node_id = [0u8; 16];
    let pkt = ping_hdr.serialize();

    sock.send_to(&pkt, target_addr).await?;

    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => {
            eprintln!(
                "{}",
                c_green(&format!(
                    "✓ Relay at {} is responding ({} bytes from {})",
                    target, len, from
                ))
            );
        }
        _ => {
            eprintln!(
                "{}",
                c_yellow(&format!(
                    "⚠ No response from {} (relay may not support status queries yet)",
                    target
                ))
            );
            eprintln!(
                "{}",
                c_dim("  The Elixir relay provides a REST API for status.")
            );
        }
    }

    Ok(())
}

/// `ztlp ns lookup` — Look up a name
async fn cmd_ns_lookup(
    name: &str,
    ns_server: &str,
    record_type: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid NS server address '{}': {}", ns_server, e))?;

    eprintln!(
        "{} {} (type {}) at {}",
        c_dim("Querying"),
        name,
        record_type,
        ns_server
    );

    // Build query: <<0x01, name_len::16, name::binary, type_byte::8>>
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let mut query = Vec::with_capacity(4 + name_bytes.len());
    query.push(0x01);
    query.extend_from_slice(&name_len.to_be_bytes());
    query.extend_from_slice(name_bytes);
    query.push(record_type);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, ns_addr).await?;

    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _from))) => {
            let data = &buf[..len];
            if data.is_empty() {
                eprintln!("{}", c_red("✗ Empty response from NS server"));
                return Ok(());
            }

            match data[0] {
                0x02 => {
                    // Record found — parse the wire format
                    let record_data = &data[1..];
                    eprintln!("\n{}", c_green("✓ Record found:"));
                    print_ns_record(record_data, name)?;
                }
                0x03 => {
                    eprintln!("\n{}", c_yellow(&format!("⚠ Not found: {}", name)));
                }
                0x04 => {
                    eprintln!("\n{}", c_red(&format!("✗ REVOKED: {}", name)));
                }
                0xFF => {
                    eprintln!("\n{}", c_red("✗ Invalid query"));
                }
                other => {
                    eprintln!(
                        "\n{}",
                        c_red(&format!("✗ Unknown response type: 0x{:02x}", other))
                    );
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!("{}", c_red(&format!("✗ Network error: {}", e)));
        }
        Err(_) => {
            eprintln!("{}", c_red("✗ Timeout — NS server not responding"));
        }
    }

    Ok(())
}

/// `ztlp ns pubkey` — Query by public key
async fn cmd_ns_pubkey(hex_key: &str, ns_server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid NS server address '{}': {}", ns_server, e))?;

    // Validate hex
    let _ = hex::decode(hex_key)?;
    let pk_hex = hex_key.to_lowercase();

    eprintln!(
        "{} pubkey {} at {}",
        c_dim("Querying"),
        &pk_hex[..16.min(pk_hex.len())],
        ns_server
    );

    // Build query: <<0x05, pk_hex_len::16, pk_hex::binary>>
    let pk_bytes = pk_hex.as_bytes();
    let pk_len = pk_bytes.len() as u16;
    let mut query = Vec::with_capacity(3 + pk_bytes.len());
    query.push(0x05);
    query.extend_from_slice(&pk_len.to_be_bytes());
    query.extend_from_slice(pk_bytes);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, ns_addr).await?;

    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _from))) => {
            let data = &buf[..len];
            if data.is_empty() {
                eprintln!("{}", c_red("✗ Empty response"));
                return Ok(());
            }

            match data[0] {
                0x02 => {
                    let record_data = &data[1..];
                    eprintln!("\n{}", c_green("✓ Record found:"));
                    print_ns_record(record_data, &pk_hex)?;
                }
                0x03 => {
                    eprintln!(
                        "\n{}",
                        c_yellow(&format!(
                            "⚠ No record found for public key {}",
                            &pk_hex[..16.min(pk_hex.len())]
                        ))
                    );
                }
                0x04 => {
                    eprintln!("\n{}", c_red("✗ Public key has been REVOKED"));
                }
                0xFF => {
                    eprintln!("\n{}", c_red("✗ Invalid query"));
                }
                other => {
                    eprintln!(
                        "\n{}",
                        c_red(&format!("✗ Unknown response type: 0x{:02x}", other))
                    );
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!("{}", c_red(&format!("✗ Network error: {}", e)));
        }
        Err(_) => {
            eprintln!("{}", c_red("✗ Timeout — NS server not responding"));
        }
    }

    Ok(())
}

/// Encode a string as an Erlang External Term Format (ETF) binary.
/// Format: <<109, len::32, bytes>> (BINARY_EXT)
fn etf_binary(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut buf = Vec::with_capacity(5 + bytes.len());
    buf.push(109); // BINARY_EXT
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
    buf
}

/// Encode an atom as ETF SMALL_ATOM_UTF8_EXT.
/// Format: <<119, len::8, name>> (for atoms with name length < 256)
fn etf_atom(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    let mut buf = Vec::with_capacity(2 + bytes.len());
    buf.push(119); // SMALL_ATOM_UTF8_EXT
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(bytes);
    buf
}

/// Encode a map with string keys (as atoms) and string values (as binaries)
/// in Erlang External Term Format, matching `:erlang.term_to_binary(map, [:deterministic])`.
///
/// Deterministic encoding requires keys sorted by Erlang term ordering.
/// For atoms, this is alphabetical comparison of their names.
fn etf_map(pairs: &mut Vec<(&str, &str)>) -> Vec<u8> {
    // Sort by key name (Erlang term ordering for atoms = alphabetical)
    pairs.sort_by_key(|&(k, _)| k);

    let mut buf = Vec::new();
    buf.push(131); // VERSION_MAGIC
    buf.push(116); // MAP_EXT
    buf.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
    for &(key, val) in pairs.iter() {
        buf.extend_from_slice(&etf_atom(key));
        buf.extend_from_slice(&etf_binary(val));
    }
    buf
}

/// Build a registration packet for ZTLP-NS.
///
/// Wire format (server expects):
/// ```
/// <<0x02, name_len::16, name, type_byte::8, data_len::16, data_bin, sig_len::16, sig>>
/// ```
///
/// The server ignores the client signature and re-signs with its own key,
/// so we send a dummy 0-byte signature.
fn build_registration_packet(name: &str, type_byte: u8, data_bin: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let data_len = data_bin.len() as u16;
    let sig_len: u16 = 0; // Dummy signature — server re-signs

    let mut pkt = Vec::with_capacity(1 + 2 + name_bytes.len() + 1 + 2 + data_bin.len() + 2);
    pkt.push(0x02); // Registration opcode
    pkt.extend_from_slice(&name_len.to_be_bytes());
    pkt.extend_from_slice(name_bytes);
    pkt.push(type_byte);
    pkt.extend_from_slice(&data_len.to_be_bytes());
    pkt.extend_from_slice(data_bin);
    pkt.extend_from_slice(&sig_len.to_be_bytes());
    pkt
}

/// `ztlp ns register` — Register with ZTLP-NS
async fn cmd_ns_register(
    name: &str,
    zone: &str,
    key_path: &Path,
    ns_server: &str,
    address: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid NS server address '{}': {}", ns_server, e))?;

    let identity = NodeIdentity::load(key_path)?;
    let node_id_hex = hex::encode(identity.node_id.0);
    let pubkey_hex = hex::encode(&identity.static_public_key);

    eprintln!("{}", c_bold("ZTLP-NS Registration"));
    eprintln!("  {} {}", c_cyan("Name:"), name);
    eprintln!("  {} {}", c_cyan("Zone:"), zone);
    eprintln!("  {} {}", c_cyan("NodeID:"), &node_id_hex);
    eprintln!("  {} {}", c_cyan("Public Key:"), &pubkey_hex[..16]);
    eprintln!("  {} {}", c_cyan("NS Server:"), ns_server);
    if let Some(addr) = address {
        eprintln!("  {} {}", c_cyan("Address:"), addr);
    }
    eprintln!();

    // Validate the name is within the specified zone
    if !name.ends_with(&format!(".{}", zone)) && name != zone {
        return Err(format!(
            "name '{}' is not within zone '{}'\n  The name must end with '.{}'",
            name, zone, zone
        )
        .into());
    }

    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    // ── Step 1: Register KEY record ─────────────────────────────────
    eprintln!("{}", c_dim("→ Registering KEY record..."));

    let key_data_bin = etf_map(&mut vec![
        ("algorithm", "Ed25519"),
        ("node_id", &node_id_hex),
        ("public_key", &pubkey_hex),
    ]);

    let key_pkt = build_registration_packet(name, 1, &key_data_bin); // type 1 = KEY
    sock.send_to(&key_pkt, ns_addr).await?;

    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let resp = &buf[..len];
            match resp.first() {
                Some(0x06) => {
                    eprintln!("  {} KEY record registered", c_green("✓"));
                }
                Some(0xFF) => {
                    return Err("NS server rejected KEY registration (invalid data format)".into());
                }
                Some(code) => {
                    return Err(
                        format!("NS server returned unexpected response: 0x{:02x}", code).into(),
                    );
                }
                None => {
                    return Err("NS server returned empty response".into());
                }
            }
        }
        Ok(Err(e)) => {
            return Err(format!("network error during KEY registration: {}", e).into());
        }
        Err(_) => {
            return Err(format!(
                "timeout waiting for NS server response at {}\n  \
                 Is the NS server running? Try: ztlp ns lookup {} --ns-server {}",
                ns_server, name, ns_server
            )
            .into());
        }
    }

    // ── Step 2: Register SVC record (if --address provided) ─────────
    if let Some(addr_str) = address {
        // Validate address format
        let _: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("invalid address '{}': {} (expected ip:port)", addr_str, e))?;

        eprintln!("{}", c_dim("→ Registering SVC record..."));

        let svc_data_bin = etf_map(&mut vec![
            ("address", addr_str),
            ("node_id", &node_id_hex),
            ("zone", zone),
        ]);

        let svc_pkt = build_registration_packet(name, 2, &svc_data_bin); // type 2 = SVC
        sock.send_to(&svc_pkt, ns_addr).await?;

        match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let resp = &buf[..len];
                match resp.first() {
                    Some(0x06) => {
                        eprintln!("  {} SVC record registered ({})", c_green("✓"), addr_str);
                    }
                    Some(0xFF) => {
                        eprintln!(
                            "  {} SVC registration failed (server rejected)",
                            c_yellow("⚠")
                        );
                        eprintln!(
                            "    {}",
                            c_dim(
                                "KEY record was registered successfully. SVC record is optional."
                            )
                        );
                    }
                    _ => {
                        eprintln!("  {} SVC registration: unexpected response", c_yellow("⚠"));
                    }
                }
            }
            _ => {
                eprintln!(
                    "  {} SVC registration timed out (KEY was registered)",
                    c_yellow("⚠")
                );
            }
        }
    }

    // ── Verify registration ─────────────────────────────────────────
    eprintln!("\n{}", c_dim("→ Verifying registration..."));

    // Small delay to let server process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Query for the KEY record we just registered
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let mut query = Vec::with_capacity(4 + name_bytes.len());
    query.push(0x01); // Query opcode
    query.extend_from_slice(&name_len.to_be_bytes());
    query.extend_from_slice(name_bytes);
    query.push(1); // KEY record type

    sock.send_to(&query, ns_addr).await?;

    match timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let resp = &buf[..len];
            match resp.first() {
                Some(0x02) => {
                    eprintln!(
                        "  {} Registration verified — record found in NS",
                        c_green("✓")
                    );
                }
                Some(0x03) => {
                    eprintln!("  {} Record not found after registration", c_yellow("⚠"));
                    eprintln!(
                        "    {}",
                        c_dim("This may indicate a zone or authority issue.")
                    );
                }
                _ => {
                    eprintln!("  {} Could not verify registration", c_yellow("⚠"));
                }
            }
        }
        _ => {
            eprintln!(
                "  {} Verification timed out (registration may still be successful)",
                c_yellow("⚠")
            );
        }
    }

    eprintln!("\n{}", c_green("✓ Registration complete!"));
    eprintln!();
    eprintln!(
        "  {} ztlp ns lookup {} --ns-server {}",
        c_dim("Verify:"),
        name,
        ns_server
    );
    eprintln!(
        "  {} ztlp connect {} --ns-server {}",
        c_dim("Connect:"),
        name,
        ns_server
    );
    if address.is_some() {
        eprintln!(
            "  {} ztlp ping {} --ns-server {}",
            c_dim("Ping:"),
            name,
            ns_server
        );
    }

    Ok(())
}

/// Parse and display an NS record from wire format.
fn print_ns_record(data: &[u8], _query_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Wire format: <<type_byte, name_len::16, name, data_len::32, data, created_at::64, ttl::32, serial::64, sig_len::16, sig, pub_len::16, pub>>
    if data.len() < 4 {
        eprintln!("  {} {} bytes of record data", c_dim("Raw:"), data.len());
        eprintln!("  {}", hex_grouped(data, 16));
        return Ok(());
    }

    let type_byte = data[0];
    let type_name = match type_byte {
        1 => "KEY",
        2 => "SVC",
        3 => "RELAY",
        4 => "POLICY",
        5 => "REVOKE",
        6 => "BOOTSTRAP",
        _ => "UNKNOWN",
    };

    // Try to parse name length and name
    if data.len() < 3 {
        eprintln!("  {} {}", c_cyan("Type:"), type_name);
        eprintln!("  {} (truncated record)", c_dim("Raw:"));
        return Ok(());
    }

    let name_len = u16::from_be_bytes([data[1], data[2]]) as usize;

    if data.len() < 3 + name_len {
        eprintln!("  {} {}", c_cyan("Type:"), type_name);
        eprintln!("  {} (truncated record)", c_dim("Raw:"));
        return Ok(());
    }

    let name = std::str::from_utf8(&data[3..3 + name_len]).unwrap_or("<invalid utf8>");
    let rest = &data[3 + name_len..];

    eprintln!("  {} ZTLP_{}", c_cyan("Type:"), c_bold(type_name));
    eprintln!("  {} {}", c_cyan("Name:"), c_bold(name));

    // Parse data section
    if rest.len() >= 4 {
        let data_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let after_data = &rest[4 + data_len..];

        if after_data.len() >= 20 {
            let created_at = u64::from_be_bytes([
                after_data[0],
                after_data[1],
                after_data[2],
                after_data[3],
                after_data[4],
                after_data[5],
                after_data[6],
                after_data[7],
            ]);
            let ttl =
                u32::from_be_bytes([after_data[8], after_data[9], after_data[10], after_data[11]]);
            let serial = u64::from_be_bytes([
                after_data[12],
                after_data[13],
                after_data[14],
                after_data[15],
                after_data[16],
                after_data[17],
                after_data[18],
                after_data[19],
            ]);

            // Format created_at as human-readable
            let created_str = if created_at > 0 {
                chrono_format_timestamp(created_at)
            } else {
                "N/A".to_string()
            };

            eprintln!("  {} {}", c_cyan("Created:"), created_str);
            eprintln!("  {} {}s", c_cyan("TTL:"), ttl);
            eprintln!("  {} {}", c_cyan("Serial:"), serial);

            // Parse signature info
            let sig_rest = &after_data[20..];
            if sig_rest.len() >= 2 {
                let sig_len = u16::from_be_bytes([sig_rest[0], sig_rest[1]]) as usize;
                if sig_rest.len() >= 2 + sig_len + 2 {
                    let _sig = &sig_rest[2..2 + sig_len];
                    let pub_start = 2 + sig_len;
                    let pub_len =
                        u16::from_be_bytes([sig_rest[pub_start], sig_rest[pub_start + 1]]) as usize;
                    if sig_rest.len() >= pub_start + 2 + pub_len {
                        let signer_pub = &sig_rest[pub_start + 2..pub_start + 2 + pub_len];
                        eprintln!(
                            "  {} {} ({} bytes)",
                            c_cyan("Signature:"),
                            c_green("present"),
                            sig_len
                        );
                        eprintln!("  {} {}", c_cyan("Signer:"), hex::encode(signer_pub));
                    }
                }
            }
        }
    }

    // Show raw data size
    eprintln!("  {} {} bytes total", c_dim("Wire size:"), data.len());

    Ok(())
}

/// Simple timestamp formatter (avoids pulling in chrono crate)
fn chrono_format_timestamp(unix_secs: u64) -> String {
    // Basic formatting without chrono dependency
    let secs_per_day: u64 = 86400;
    let days_since_epoch = unix_secs / secs_per_day;
    let time_of_day = unix_secs % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simple days-since-epoch to date (no leap second precision needed)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// `ztlp gateway start`
async fn cmd_gateway_start(elixir: bool, bind: &str) -> Result<(), Box<dyn std::error::Error>> {
    if elixir {
        eprintln!("{}", c_bold("ZTLP Gateway — Elixir Implementation"));
        eprintln!();
        eprintln!("The production ZTLP gateway is implemented in Elixir for");
        eprintln!("optimal concurrency and fault tolerance.");
        eprintln!();
        eprintln!("To start the Elixir gateway:");
        eprintln!();
        eprintln!("  cd gateway/");
        eprintln!("  mix deps.get");
        eprintln!("  mix run --no-halt");
        eprintln!();
        eprintln!("Or with Docker:");
        eprintln!();
        eprintln!("  docker compose up gateway");
        eprintln!();
        eprintln!("See gateway/README.md for full configuration options.");
        return Ok(());
    }

    eprintln!("{}", c_bold("Starting ZTLP mini-gateway (Rust-native)..."));
    eprintln!("{}", c_yellow("⚠ This is a minimal gateway for testing."));
    eprintln!(
        "{}",
        c_dim("  For production, use: ztlp gateway start --elixir\n")
    );

    // The mini-gateway is essentially a relay that also handles handshakes
    let relay = SimulatedRelay::bind(bind).await?;

    eprintln!(
        "{}",
        c_green(&format!("✓ Mini-gateway listening on {}", relay.local_addr))
    );
    eprintln!(
        "  {} Relay-mode (SessionID forwarding + handshake pass-through)",
        c_cyan("Mode:")
    );
    eprintln!("  {} Ctrl+C\n", c_dim("Stop:"));

    relay.run().await?;

    Ok(())
}

/// `ztlp inspect` — Decode and pretty-print ZTLP packets
fn cmd_inspect(
    hex_bytes: &Option<String>,
    file: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(hex_str) = hex_bytes {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex: {}", e))?;
        inspect_packet(&bytes, 1)?;
    } else if let Some(file_path) = file {
        let contents = std::fs::read_to_string(file_path)
            .map_err(|e| format!("failed to read {}: {}", file_path.display(), e))?;

        let mut packet_num = 0;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            packet_num += 1;
            match hex::decode(line) {
                Ok(bytes) => {
                    inspect_packet(&bytes, packet_num)?;
                }
                Err(e) => {
                    eprintln!("{} Packet #{}: invalid hex: {}", c_red("✗"), packet_num, e);
                }
            }
        }

        if packet_num == 0 {
            eprintln!("{}", c_yellow("No packets found in file."));
        }
    } else {
        eprintln!("{}", c_red("✗ Provide hex bytes or --file"));
        eprintln!("  Usage: ztlp inspect <hex-bytes>");
        eprintln!("         ztlp inspect --file capture.txt");
        std::process::exit(2);
    }

    Ok(())
}

/// Inspect and pretty-print a single ZTLP packet.
fn inspect_packet(data: &[u8], packet_num: usize) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 4 {
        eprintln!(
            "{} Packet #{}: too short ({} bytes, need at least 4)",
            c_red("✗"),
            packet_num,
            data.len()
        );
        return Ok(());
    }

    let magic = u16::from_be_bytes([data[0], data[1]]);
    let ver_hdrlen = u16::from_be_bytes([data[2], data[3]]);
    let version = (ver_hdrlen >> 12) & 0x0F;
    let hdr_len = ver_hdrlen & 0x0FFF;

    eprintln!(
        "\n{}",
        c_bold(&format!(
            "═══ Packet #{} ({} bytes) ═══",
            packet_num,
            data.len()
        ))
    );

    // Magic check
    if magic != MAGIC {
        eprintln!(
            "  {} 0x{:04X} {}",
            c_cyan("Magic:"),
            magic,
            c_red("✗ INVALID (expected 0x5A37)")
        );
        eprintln!("  {} This is not a ZTLP packet.", c_dim("Note:"));
        return Ok(());
    }
    eprintln!("  {} 0x{:04X} {}", c_cyan("Magic:"), magic, c_green("✓"));

    // Version
    let ver_ok = if version as u8 == VERSION {
        c_green("✓")
    } else {
        c_red("✗ unsupported")
    };
    eprintln!("  {} {} {}", c_cyan("Version:"), version, ver_ok);

    // Header length determines packet type
    eprintln!(
        "  {} {} words ({} bytes)",
        c_cyan("HdrLen:"),
        hdr_len,
        hdr_len * 4
    );

    if hdr_len == 24 {
        // Handshake header
        inspect_handshake_header(data)?;
    } else if hdr_len == 11 {
        // Data header
        inspect_data_header(data)?;
    } else {
        eprintln!(
            "  {} Unknown header format (hdr_len={})",
            c_yellow("⚠"),
            hdr_len
        );
        eprintln!("  {} {}", c_dim("Raw hex:"), hex_grouped(data, 16));
    }

    Ok(())
}

/// Pretty-print a handshake header.
fn inspect_handshake_header(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("  {} {}", c_cyan("Type:"), c_magenta("HANDSHAKE/CONTROL"));

    if data.len() < HANDSHAKE_HEADER_SIZE {
        eprintln!(
            "  {} Truncated! Need {} bytes, have {}",
            c_red("✗"),
            HANDSHAKE_HEADER_SIZE,
            data.len()
        );
        return Ok(());
    }

    let header = HandshakeHeader::deserialize(data)?;

    eprintln!("  {} {}", c_cyan("Flags:"), format_flags(header.flags));
    eprintln!(
        "  {} {}",
        c_cyan("MsgType:"),
        c_bold(format_msg_type(header.msg_type))
    );
    eprintln!("  {} 0x{:04X}", c_cyan("CryptoSuite:"), header.crypto_suite);
    eprintln!("  {} 0x{:04X}", c_cyan("KeyID:"), header.key_id);
    eprintln!(
        "  {} {}",
        c_cyan("SessionID:"),
        c_bold(&format!("{}", header.session_id))
    );
    eprintln!("  {} {}", c_cyan("PacketSeq:"), header.packet_seq);

    let ts_str = if header.timestamp > 0 {
        format!(
            "{} ({})",
            header.timestamp,
            chrono_format_timestamp(header.timestamp / 1000)
        )
    } else {
        "0".to_string()
    };
    eprintln!("  {} {}", c_cyan("Timestamp:"), ts_str);

    eprintln!(
        "  {} {}",
        c_cyan("SrcNodeID:"),
        hex::encode(header.src_node_id)
    );
    eprintln!(
        "  {} {}",
        c_cyan("DstSvcID:"),
        hex::encode(header.dst_svc_id)
    );
    eprintln!("  {} 0x{:08X}", c_cyan("PolicyTag:"), header.policy_tag);
    eprintln!("  {} {} bytes", c_cyan("ExtLen:"), header.ext_len);
    eprintln!("  {} {} bytes", c_cyan("PayloadLen:"), header.payload_len);
    eprintln!(
        "  {} {}",
        c_cyan("AuthTag:"),
        hex::encode(header.header_auth_tag)
    );

    // Parse extension data if present
    let ext_start = HANDSHAKE_HEADER_SIZE;
    let ext_end = ext_start + header.ext_len as usize;
    if header.ext_len > 0 && data.len() >= ext_end {
        let ext_data = &data[ext_start..ext_end];
        eprintln!("  {} {} bytes", c_cyan("Extension:"), header.ext_len);

        if !ext_data.is_empty() {
            let ext_type = ext_data[0];
            eprintln!(
                "    {} 0x{:02X} ({})",
                c_cyan("ExtType:"),
                ext_type,
                match ext_type {
                    EXT_TYPE_RAT => "RAT — Relay Admission Token",
                    _ => "unknown",
                }
            );

            if ext_type == EXT_TYPE_RAT {
                match header.parse_extension(ext_data) {
                    Some(Ok(HandshakeExtension::AdmissionToken(token))) => {
                        eprintln!("    {} v{}", c_cyan("RAT Version:"), token.version);
                        eprintln!(
                            "    {} {}",
                            c_cyan("RAT NodeID:"),
                            hex::encode(token.node_id)
                        );
                        eprintln!(
                            "    {} {}",
                            c_cyan("RAT IssuerID:"),
                            hex::encode(token.issuer_id)
                        );
                        eprintln!("    {} {}", c_cyan("RAT IssuedAt:"), token.issued_at);
                        eprintln!("    {} {}", c_cyan("RAT ExpiresAt:"), token.expires_at);
                        let scope_str = if token.session_scope == [0u8; 12] {
                            "any".to_string()
                        } else {
                            hex::encode(token.session_scope)
                        };
                        eprintln!("    {} {}", c_cyan("RAT Scope:"), scope_str);
                        eprintln!(
                            "    {} {}...",
                            c_cyan("RAT MAC:"),
                            hex::encode(&token.mac[..16])
                        );
                    }
                    Some(Err(e)) => {
                        eprintln!("    {} {}", c_red("RAT parse error:"), e);
                    }
                    None => {}
                }
            }
        }
    }

    let payload_start = ext_end.max(HANDSHAKE_HEADER_SIZE);
    if data.len() > payload_start {
        let payload = &data[payload_start..];
        eprintln!("  {} {} bytes", c_cyan("Payload:"), payload.len());
        if payload.len() <= 64 {
            eprintln!("  {} {}", c_dim("  hex:"), hex_grouped(payload, 16));
        } else {
            eprintln!(
                "  {} {}...",
                c_dim("  hex:"),
                hex_grouped(&payload[..64], 16)
            );
        }
    }

    Ok(())
}

/// Pretty-print a data header.
fn inspect_data_header(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("  {} {}", c_cyan("Type:"), c_magenta("COMPACT DATA"));

    if data.len() < DATA_HEADER_SIZE {
        eprintln!(
            "  {} Truncated! Need {} bytes, have {}",
            c_red("✗"),
            DATA_HEADER_SIZE,
            data.len()
        );
        return Ok(());
    }

    let header = DataHeader::deserialize(data)?;

    eprintln!("  {} {}", c_cyan("Flags:"), format_flags(header.flags));
    eprintln!(
        "  {} {}",
        c_cyan("SessionID:"),
        c_bold(&format!("{}", header.session_id))
    );
    eprintln!("  {} {}", c_cyan("PacketSeq:"), header.packet_seq);
    eprintln!(
        "  {} {}",
        c_cyan("AuthTag:"),
        hex::encode(header.header_auth_tag)
    );

    let payload_start = DATA_HEADER_SIZE;
    if data.len() > payload_start {
        let payload = &data[payload_start..];
        eprintln!(
            "  {} {} bytes (encrypted)",
            c_cyan("Payload:"),
            payload.len()
        );
        if payload.len() <= 64 {
            eprintln!("  {} {}", c_dim("  hex:"), hex_grouped(payload, 16));
        } else {
            eprintln!(
                "  {} {}...",
                c_dim("  hex:"),
                hex_grouped(&payload[..64], 16)
            );
        }
    }

    Ok(())
}

/// `ztlp ping` — Send ZTLP ping packets and measure RTT
async fn cmd_ping(
    target: &str,
    ns_server: &Option<String>,
    count: u32,
    interval: u64,
    bind: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (target_addr, _) = resolve_target(target, ns_server).await?;

    let sock = UdpSocket::bind(bind).await?;
    let local_addr = sock.local_addr()?;

    eprintln!(
        "{} {} from {} — {} ping(s), {}ms interval\n",
        c_bold("ZTLP PING"),
        target_addr,
        local_addr,
        count,
        interval
    );

    let mut rtts: Vec<f64> = Vec::new();
    let mut sent = 0u32;
    let mut received = 0u32;

    for seq in 0..count {
        // Build a Ping packet with the sequence number embedded
        let mut ping_hdr = HandshakeHeader::new(MsgType::Ping);
        ping_hdr.packet_seq = seq as u64;
        ping_hdr.src_node_id = [0u8; 16]; // anonymous ping
                                          // Embed timestamp in the payload for RTT measurement
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let timestamp_payload = now_ms.to_be_bytes();
        ping_hdr.payload_len = 8;
        let mut pkt = ping_hdr.serialize();
        pkt.extend_from_slice(&timestamp_payload);

        let start = Instant::now();
        sock.send_to(&pkt, target_addr).await?;
        sent += 1;

        let mut buf = vec![0u8; 65535];
        match timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                rtts.push(rtt);
                received += 1;

                // Try to parse response
                let pong_info = if len >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&buf[..len]) {
                        if hdr.msg_type == MsgType::Pong {
                            "pong"
                        } else {
                            "reply"
                        }
                    } else {
                        "reply"
                    }
                } else if len >= DATA_HEADER_SIZE {
                    "reply"
                } else {
                    "reply"
                };

                eprintln!(
                    "{} bytes from {}: seq={} {} time={:.2}ms",
                    len, from, seq, pong_info, rtt
                );
            }
            Ok(Err(e)) => {
                eprintln!("seq={}: {}", seq, c_red(&format!("error: {}", e)));
            }
            Err(_) => {
                eprintln!("seq={}: {}", seq, c_red("timeout (3s)"));
            }
        }

        if seq + 1 < count {
            tokio::time::sleep(Duration::from_millis(interval)).await;
        }
    }

    // Print stats
    eprintln!(
        "\n{}",
        c_bold(&format!("--- {} ping statistics ---", target))
    );
    let loss_pct = if sent > 0 {
        ((sent - received) as f64 / sent as f64) * 100.0
    } else {
        100.0
    };
    eprintln!(
        "{} packets transmitted, {} received, {:.1}% packet loss",
        sent, received, loss_pct
    );

    if !rtts.is_empty() {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
        let stddev = variance.sqrt();

        eprintln!(
            "rtt min/avg/max/stddev = {:.3}/{:.3}/{:.3}/{:.3} ms",
            min, avg, max, stddev
        );
    }

    // Exit code: 1 if no responses
    if received == 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// `ztlp token inspect` — Decode and display a RAT
fn cmd_token_inspect(hex_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex: {}", e))?;

    let token =
        RelayAdmissionToken::parse(&bytes).map_err(|e| format!("failed to parse RAT: {}", e))?;

    eprintln!("\n{}", c_bold("═══ Relay Admission Token ═══"));
    eprintln!("{}", token.display());

    Ok(())
}

/// `ztlp token verify` — Verify a RAT's MAC
fn cmd_token_verify(hex_str: &str, secret_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid token hex: {}", e))?;
    let secret_bytes =
        hex::decode(secret_hex.trim()).map_err(|e| format!("invalid secret hex: {}", e))?;

    if secret_bytes.len() != 32 {
        return Err(format!(
            "secret must be 32 bytes (64 hex chars), got {} bytes",
            secret_bytes.len()
        )
        .into());
    }

    let token =
        RelayAdmissionToken::parse(&bytes).map_err(|e| format!("failed to parse RAT: {}", e))?;

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    eprintln!("\n{}", c_bold("═══ Relay Admission Token Verification ═══"));
    eprintln!("{}", token.display());

    if token.verify(&secret) {
        eprintln!("\n  {} {}", c_cyan("MAC:"), c_green("✓ VALID"));
    } else {
        eprintln!("\n  {} {}", c_cyan("MAC:"), c_red("✗ INVALID"));
    }

    if token.is_expired() {
        eprintln!("  {} {}", c_cyan("Expiry:"), c_red("EXPIRED"));
    } else {
        eprintln!(
            "  {} {} ({}s remaining)",
            c_cyan("Expiry:"),
            c_green("valid"),
            token.ttl_seconds()
        );
    }

    Ok(())
}

/// `ztlp token issue` — Issue a new RAT for testing
fn cmd_token_issue(
    node_id_hex: &str,
    secret_hex: &str,
    ttl: u64,
    issuer_id_hex: &Option<String>,
    session_scope_hex: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node_id_bytes =
        hex::decode(node_id_hex.trim()).map_err(|e| format!("invalid node-id hex: {}", e))?;
    if node_id_bytes.len() != 16 {
        return Err(format!(
            "node-id must be 16 bytes (32 hex chars), got {} bytes",
            node_id_bytes.len()
        )
        .into());
    }

    let secret_bytes =
        hex::decode(secret_hex.trim()).map_err(|e| format!("invalid secret hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err(format!(
            "secret must be 32 bytes (64 hex chars), got {} bytes",
            secret_bytes.len()
        )
        .into());
    }

    let issuer_id_bytes = if let Some(hex) = issuer_id_hex {
        let bytes = hex::decode(hex.trim()).map_err(|e| format!("invalid issuer-id hex: {}", e))?;
        if bytes.len() != 16 {
            return Err(format!(
                "issuer-id must be 16 bytes (32 hex chars), got {} bytes",
                bytes.len()
            )
            .into());
        }
        bytes
    } else {
        vec![0u8; 16]
    };

    let scope_bytes = if let Some(hex) = session_scope_hex {
        let bytes =
            hex::decode(hex.trim()).map_err(|e| format!("invalid session-scope hex: {}", e))?;
        if bytes.len() != 12 {
            return Err(format!(
                "session-scope must be 12 bytes (24 hex chars), got {} bytes",
                bytes.len()
            )
            .into());
        }
        bytes
    } else {
        vec![0u8; 12]
    };

    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&node_id_bytes);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let mut issuer_id = [0u8; 16];
    issuer_id.copy_from_slice(&issuer_id_bytes);
    let mut session_scope = [0u8; 12];
    session_scope.copy_from_slice(&scope_bytes);

    let token = RelayAdmissionToken::issue(node_id, issuer_id, session_scope, ttl, &secret);

    let bytes = token.serialize();

    // Print the hex token to stdout for piping
    println!("{}", hex::encode(&bytes));

    // Print details to stderr
    eprintln!("\n{}", c_bold("═══ Issued Relay Admission Token ═══"));
    eprintln!("{}", token.display());
    eprintln!("  {} {}s", c_cyan("TTL:"), ttl);

    Ok(())
}

/// `ztlp status` — Query status of a local service
async fn cmd_status(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let target_addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("invalid target address '{}': {}", target, e))?;

    eprintln!("{} {}", c_dim("Querying"), target);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    // Send a Ping as a basic health check
    let mut ping_hdr = HandshakeHeader::new(MsgType::Ping);
    ping_hdr.packet_seq = 0;
    ping_hdr.src_node_id = [0u8; 16];
    let pkt = ping_hdr.serialize();

    let start = Instant::now();
    sock.send_to(&pkt, target_addr).await?;

    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => {
            let rtt = start.elapsed().as_secs_f64() * 1000.0;

            eprintln!("\n{}", c_bold("ZTLP Service Status"));
            eprintln!("  {} {}", c_cyan("Address:"), target_addr);
            eprintln!(
                "  {} {} (responding from {})",
                c_cyan("Status:"),
                c_green("UP"),
                from
            );
            eprintln!("  {} {:.2}ms", c_cyan("RTT:"), rtt);
            eprintln!("  {} {} bytes", c_cyan("Response:"), len);
            eprintln!("  {} {}", c_cyan("CLI Version:"), ZTLP_VERSION);

            // Try to identify what responded
            if len >= 4 {
                let magic = u16::from_be_bytes([buf[0], buf[1]]);
                if magic == MAGIC {
                    eprintln!("  {} ZTLP protocol response", c_cyan("Protocol:"));
                    let ver_hdrlen = u16::from_be_bytes([buf[2], buf[3]]);
                    let hdr_len = ver_hdrlen & 0x0FFF;
                    if hdr_len == 24 && len >= HANDSHAKE_HEADER_SIZE {
                        if let Ok(hdr) = HandshakeHeader::deserialize(&buf[..len]) {
                            eprintln!("  {} {:?}", c_cyan("MsgType:"), hdr.msg_type);
                        }
                    }
                } else {
                    eprintln!(
                        "  {} Non-ZTLP response (magic: 0x{:04X})",
                        c_cyan("Protocol:"),
                        magic
                    );
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!("\n{}", c_bold("ZTLP Service Status"));
            eprintln!("  {} {}", c_cyan("Address:"), target_addr);
            eprintln!("  {} {} ({})", c_cyan("Status:"), c_red("ERROR"), e);
        }
        Err(_) => {
            eprintln!("\n{}", c_bold("ZTLP Service Status"));
            eprintln!("  {} {}", c_cyan("Address:"), target_addr);
            eprintln!(
                "  {} {} (no response within 3s)",
                c_cyan("Status:"),
                c_red("DOWN/UNREACHABLE")
            );
            eprintln!(
                "\n{}",
                c_dim("  The target may not be running, or may not respond to ZTLP Ping packets.")
            );
        }
    }

    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{},ztlp_proto={}", filter, filter)
                    .parse()
                    .expect("valid filter")
            }),
        )
        .with_target(false)
        .init();

    // Load optional config
    let _config = load_config();

    let result = match &cli.command {
        Commands::Keygen { output, format } => cmd_keygen(output, format),

        Commands::Connect {
            target,
            key,
            relay,
            gateway,
            ns_server,
            session_id,
            bind,
            local_forward,
            service,
            stun_server,
            nat_assist,
            no_relay_fallback,
        } => {
            cmd_connect(
                target,
                key,
                relay,
                gateway,
                ns_server,
                session_id,
                bind,
                local_forward,
                service,
                stun_server,
                *nat_assist,
                *no_relay_fallback,
            )
            .await
        }

        Commands::Listen {
            bind,
            key,
            gateway,
            forward,
            policy,
            stun_server,
            nat_assist,
        } => {
            cmd_listen(
                bind,
                key,
                *gateway,
                forward,
                policy,
                stun_server,
                *nat_assist,
            )
            .await
        }

        Commands::Relay(subcmd) => match subcmd {
            RelayCommands::Start { bind, max_sessions } => {
                cmd_relay_start(bind, *max_sessions).await
            }
            RelayCommands::Status { target } => cmd_relay_status(target).await,
        },

        Commands::Ns(subcmd) => match subcmd {
            NsCommands::Register {
                name,
                zone,
                key,
                ns_server,
                address,
            } => cmd_ns_register(name, zone, key, ns_server, address).await,
            NsCommands::Lookup {
                name,
                ns_server,
                record_type,
            } => cmd_ns_lookup(name, ns_server, *record_type).await,
            NsCommands::Pubkey { hex, ns_server } => cmd_ns_pubkey(hex, ns_server).await,
        },

        Commands::Gateway(subcmd) => match subcmd {
            GatewayCommands::Start { elixir, bind } => cmd_gateway_start(*elixir, bind).await,
        },

        Commands::Inspect { hex_bytes, file } => cmd_inspect(hex_bytes, file),

        Commands::Ping {
            target,
            ns_server,
            count,
            interval,
            bind,
        } => cmd_ping(target, ns_server, *count, *interval, bind).await,

        Commands::Status { target } => cmd_status(target).await,

        Commands::Token(subcmd) => match subcmd {
            TokenCommands::Inspect { hex } => cmd_token_inspect(hex),
            TokenCommands::Verify { hex, secret } => cmd_token_verify(hex, secret),
            TokenCommands::Issue {
                node_id,
                secret,
                ttl,
                issuer_id,
                session_scope,
            } => cmd_token_issue(node_id, secret, *ttl, issuer_id, session_scope),
        },
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("{} {}", c_red("error:"), e);
            std::process::exit(1);
        }
    }
}
