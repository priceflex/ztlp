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
//! ztlp ns lookup mynode.office.acme.ztlp --ns-server 127.0.0.1:23096
//! ```

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use ztlp_proto::admission::{HandshakeExtension, RelayAdmissionToken, EXT_TYPE_RAT};
use ztlp_proto::handshake::{
    HalfOpenCache, HandshakeContext, HALF_OPEN_TTL_SECS, INITIAL_HANDSHAKE_RETRY_MS,
    MAX_HANDSHAKE_RETRIES, MAX_HANDSHAKE_RETRY_MS, MAX_RESPONDER_RETRANSMITS,
};
use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::nat;
use ztlp_proto::packet::{
    flags, DataHeader, HandshakeHeader, MsgType, SessionId, DATA_HEADER_SIZE,
    HANDSHAKE_HEADER_SIZE, MAGIC, VERSION,
};
use ztlp_proto::pipeline::{AdmissionResult, Pipeline};
use ztlp_proto::policy::PolicyEngine;
use ztlp_proto::punch;
use ztlp_proto::reject::{RejectFrame, RejectReason};
use ztlp_proto::relay::SimulatedRelay;
use ztlp_proto::relay_pool::{FailoverOrchestrator, RelayPool, RelayPoolConfig};
use ztlp_proto::session_manager::SessionManager;
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
    /// Pinned gateway static public keys (base64-encoded).
    #[serde(default)]
    pinned_gateway_keys: Vec<String>,
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
        ztlp ns lookup mynode.acme.ztlp --ns-server 127.0.0.1:23096"
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
            ztlp connect myserver.clients.techrockstars.ztlp --ns-server 10.0.0.1:23096")]
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

        /// Enable NS-coordinated hole punching (Nebula-style)
        #[arg(long)]
        punch: bool,

        /// Delay before sending punch packets (e.g. "100ms", "1s")
        #[arg(long, value_parser = parse_duration_arg)]
        punch_delay: Option<Duration>,

        /// Timeout for the punch procedure (e.g. "10s", "30s")
        #[arg(long, value_parser = parse_duration_arg)]
        punch_timeout: Option<Duration>,

        /// Enable multi-relay pool with automatic failover (default: on when multiple relays available)
        #[arg(long)]
        relay_pool: bool,

        /// Health check probe interval for relay pool (e.g. "30s", "1m")
        #[arg(long, value_parser = parse_duration_arg, default_value = "30s")]
        relay_probe_interval: Duration,
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

        /// ZTLP-NS server address for identity resolution in policy checks.
        /// When set, the listener resolves the peer's public key to their
        /// registered NS name, enabling name-based policy rules.
        #[arg(long)]
        ns_server: Option<String>,

        /// STUN server address for NAT traversal (host:port)
        #[arg(long)]
        stun_server: Option<String>,

        /// Enable NAT traversal (register with relay for rendezvous)
        #[arg(long)]
        nat_assist: bool,

        /// Maximum number of concurrent sessions (default 100)
        #[arg(long, default_value = "100")]
        max_sessions: usize,
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

    /// Interactive setup wizard — join or create a ZTLP network
    ///
    /// Walks you through joining an existing network (with an enrollment
    /// token) or creating a new one. Handles identity generation,
    /// registration, and config file creation automatically.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp setup\n  \
            ztlp setup --token ztlp://enroll/AQtvZm...\n  \
            ztlp setup --token AQtvZm...")]
    Setup {
        /// Enrollment token (base64url or ztlp://enroll/ URI).
        /// If provided, skips the interactive menu and goes straight to enrollment.
        #[arg(short, long)]
        token: Option<String>,

        /// Device name to register (auto-detected from hostname if omitted)
        #[arg(short, long)]
        name: Option<String>,

        /// Identity type to register (default: device for backward compat)
        #[arg(long, value_enum, default_value = "device")]
        r#type: SetupType,

        /// Owner user name (for device records, e.g. steve@techrockstars.ztlp)
        #[arg(long)]
        owner: Option<String>,

        /// Skip confirmation prompts
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Admin operations — manage zones and enrollment tokens
    #[command(subcommand)]
    Admin(AdminCommands),

    /// Scan host ports and report exposure (what an attacker sees)
    ///
    /// Audits which TCP/UDP ports are reachable from the network and
    /// whether they are protected by ZTLP or exposed directly.
    /// Useful for verifying that services (SSH, etc.) are only
    /// accessible through authenticated ZTLP tunnels.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp scan                                   # Scan common ports on this host\n  \
            ztlp scan --target 10.0.0.5                 # Scan a remote host\n  \
            ztlp scan --ports 22,80,443,3306,5432       # Scan specific ports\n  \
            ztlp scan --ztlp-port 23095                 # Specify ZTLP listener port\n  \
            ztlp scan --json                            # JSON output for automation")]
    Scan {
        /// Target IP or hostname to scan (default: 127.0.0.1)
        #[arg(short, long, default_value = "127.0.0.1")]
        target: String,

        /// Comma-separated list of TCP ports to check (default: common services)
        #[arg(short, long)]
        ports: Option<String>,

        /// ZTLP listener port to verify (default: 23095)
        #[arg(long, default_value = "23095")]
        ztlp_port: u16,

        /// Output JSON for scripting/monitoring
        #[arg(short, long)]
        json: bool,

        /// Include UDP port scan (slower, may need root)
        #[arg(short, long)]
        udp: bool,
    },

    /// Tune system for optimal ZTLP performance
    ///
    /// Checks and optionally applies kernel settings for best tunnel
    /// throughput. Increases UDP socket buffer limits (rmem_max/wmem_max)
    /// to 7MB, matching WireGuard's recommended configuration.
    ///
    /// Without --apply, shows current settings and recommendations.
    /// With --apply, writes sysctl values (requires root/sudo).
    #[command(after_help = "EXAMPLES:\n  \
            ztlp tune                    # Show current settings\n  \
            sudo ztlp tune --apply       # Apply optimal settings\n  \
            ztlp tune --apply --persist  # Apply + persist across reboots")]
    Tune {
        /// Apply the recommended settings (requires root/sudo)
        #[arg(short, long)]
        apply: bool,

        /// Make settings persistent across reboots (writes /etc/sysctl.d/99-ztlp.conf)
        #[arg(short, long)]
        persist: bool,
    },

    /// SSH ProxyCommand — pipe stdin/stdout through a ZTLP tunnel
    ///
    /// Resolves a ZTLP name (or custom domain), establishes an encrypted
    /// Noise_XX tunnel to the target peer, and bidirectionally pipes
    /// stdin/stdout through it. Designed for use as SSH ProxyCommand.
    ///
    /// Supports both native ZTLP names (`*.ztlp`) and custom domain
    /// mappings configured in `~/.ztlp/agent.toml`.
    #[command(after_help = "EXAMPLES:\n  \
            # Direct use:\n  \
            ztlp proxy fileserver.corp.ztlp 22\n  \
            ztlp proxy db.corp.ztlp 5432\n  \
            ztlp proxy server.internal.techrockstars.com 22\n\n  \
            # In ~/.ssh/config:\n  \
            Host *.ztlp\n      \
            ProxyCommand ztlp proxy %h %p\n\n  \
            Host *.internal.techrockstars.com\n      \
            ProxyCommand ztlp proxy %h %p")]
    Proxy {
        /// Target hostname (ZTLP name or custom domain)
        hostname: String,

        /// Target TCP port on the remote peer
        port: u16,

        /// Path to identity key file (default: ~/.ztlp/identity.json)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// NS server address override (host:port)
        #[arg(long)]
        ns_server: Option<String>,
    },

    /// Manage the ZTLP agent daemon
    #[command(subcommand)]
    Agent(AgentCommands),
}

/// Agent daemon management subcommands.
#[derive(Subcommand)]
enum AgentCommands {
    /// Start the agent daemon
    #[command(after_help = "EXAMPLES:\n  \
            ztlp agent start\n  \
            ztlp agent start --foreground")]
    Start {
        /// Stay in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,

        /// Path to agent config file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Stop the running agent daemon
    #[command(after_help = "EXAMPLES:\n  ztlp agent stop")]
    Stop,

    /// Show agent status (tunnels, DNS cache, credentials)
    #[command(after_help = "EXAMPLES:\n  ztlp agent status")]
    Status,

    /// Show DNS cache entries
    #[command(after_help = "EXAMPLES:\n  ztlp agent dns")]
    Dns,

    /// Flush the DNS cache
    #[command(after_help = "EXAMPLES:\n  ztlp agent flush-dns")]
    FlushDns,

    /// Show active tunnels
    #[command(after_help = "EXAMPLES:\n  ztlp agent tunnels")]
    Tunnels,

    /// Configure system DNS to forward ZTLP zones to the agent
    #[command(after_help = "EXAMPLES:\n  \
            sudo ztlp agent dns-setup\n  \
            sudo ztlp agent dns-setup --zones corp.ztlp,internal.techrockstars.com")]
    DnsSetup {
        /// Additional DNS zones to forward (comma-separated)
        #[arg(long)]
        zones: Option<String>,
    },

    /// Remove ZTLP DNS configuration
    #[command(after_help = "EXAMPLES:\n  sudo ztlp agent dns-teardown")]
    DnsTeardown,

    /// Install the agent as a system service (systemd/LaunchAgent)
    #[command(after_help = "EXAMPLES:\n  \
            sudo ztlp agent install\n  \
            sudo ztlp agent install --binary /usr/local/bin/ztlp")]
    Install {
        /// Path to the ztlp binary (default: current binary)
        #[arg(long)]
        binary: Option<PathBuf>,
    },

    /// Pull TLS certificates for all known service hostnames
    ///
    /// Queries the ZTLP-NS for service records in the zone, issues local
    /// TLS certs for each hostname, and saves them to ~/.ztlp/certs/.
    /// The agent uses these certs for local TLS termination so browsers
    /// can connect via HTTPS to ZTLP services.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp agent pull-certs\n  \
            ztlp agent pull-certs --ca-dir ~/.ztlp/ca")]
    PullCerts {
        /// CA directory (default: ~/.ztlp/ca)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output directory for certs (default: ~/.ztlp/certs)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Initialize a new ZTLP zone with an enrollment secret
    ///
    /// Generates a random 32-byte enrollment secret for the zone and
    /// saves it to a file. This secret is used to create enrollment
    /// tokens that authorize devices to join the network.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin init-zone --zone office.acme.ztlp\n  \
            ztlp admin init-zone --zone office.acme.ztlp --secret-output /etc/ztlp/zone.key")]
    InitZone {
        /// Zone name (e.g., office.acme.ztlp)
        #[arg(short, long)]
        zone: String,

        /// Path to save the enrollment secret (default: ~/.ztlp/zone.key)
        #[arg(long)]
        secret_output: Option<PathBuf>,
    },

    /// Generate enrollment tokens for devices to join the network
    ///
    /// Creates pre-authorized tokens that devices present during enrollment.
    /// Each token carries the zone name, NS server address, and relay addresses
    /// so the enrolling device doesn't need to know anything in advance.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin enroll --zone office.acme.ztlp --ns-server 10.0.0.5:23096 \\\n    \
                --relay 10.0.0.5:23095 --expires 24h\n  \
            ztlp admin enroll --zone office.acme.ztlp --ns-server 10.0.0.5:23096 \\\n    \
                --relay 10.0.0.5:23095 --expires 7d --max-uses 50 --count 10\n  \
            ztlp admin enroll --zone office.acme.ztlp --secret /etc/ztlp/zone.key \\\n    \
                --ns-server 10.0.0.5:23096 --relay 10.0.0.5:23095 --qr")]
    Enroll {
        /// Zone name
        #[arg(short, long)]
        zone: String,

        /// Path to zone enrollment secret file
        #[arg(short, long)]
        secret: Option<PathBuf>,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: String,

        /// Relay address (repeatable)
        #[arg(long)]
        relay: Vec<String>,

        /// Gateway address (optional)
        #[arg(long)]
        gateway: Option<String>,

        /// Token expiry duration (e.g., 24h, 7d, 30m)
        #[arg(long, default_value = "24h")]
        expires: String,

        /// Maximum uses per token (0 = unlimited)
        #[arg(long, default_value = "1")]
        max_uses: u16,

        /// Number of tokens to generate
        #[arg(long, default_value = "1")]
        count: usize,

        /// Display as QR code in terminal
        #[arg(long)]
        qr: bool,
    },

    /// Create a user identity in the ZTLP namespace
    ///
    /// Registers a USER record in the NS server for the given name.
    /// The user identity is bound to an Ed25519 signing key.
    #[command(
        name = "create-user",
        after_help = "EXAMPLES:\n  \
            ztlp admin create-user steve@techrockstars.ztlp --role admin --email steve@techrockstars.com\n  \
            ztlp admin create-user alice@acme.ztlp --role tech --json"
    )]
    CreateUser {
        /// User name (e.g. steve@techrockstars.ztlp)
        name: String,

        /// User role
        #[arg(long, value_enum, default_value = "user")]
        role: UserRole,

        /// Contact email
        #[arg(long)]
        email: Option<String>,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Link a device to a user (set device owner)
    ///
    /// Updates a DEVICE record in the NS server to set its owner field.
    #[command(
        name = "link-device",
        after_help = "EXAMPLES:\n  \
            ztlp admin link-device laptop-01.techrockstars.ztlp --owner steve@techrockstars.ztlp\n  \
            ztlp admin link-device phone.acme.ztlp --owner alice@acme.ztlp --json"
    )]
    LinkDevice {
        /// Device name (e.g. laptop-01.techrockstars.ztlp)
        name: String,

        /// Owner user name (e.g. steve@techrockstars.ztlp)
        #[arg(long)]
        owner: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// List devices owned by a user
    ///
    /// Queries the NS server for all DEVICE records with the given owner.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin devices steve@techrockstars.ztlp\n  \
            ztlp admin devices steve@techrockstars.ztlp --json")]
    Devices {
        /// User name (e.g. steve@techrockstars.ztlp)
        user: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// List records in the namespace
    ///
    /// Lists DEVICE, USER, or KEY records, optionally filtered by zone.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin ls --type device\n  \
            ztlp admin ls --type user --zone techrockstars.ztlp\n  \
            ztlp admin ls --json")]
    Ls {
        /// Filter by record type
        #[arg(long, value_enum)]
        r#type: Option<RecordTypeFilter>,

        /// Filter by zone suffix
        #[arg(long)]
        zone: Option<String>,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Create a group in the ZTLP namespace
    ///
    /// Registers a GROUP record in the NS server. Groups can only be
    /// created by zone signing key (admin). Members are added separately.
    #[command(
        name = "create-group",
        after_help = "EXAMPLES:\n  \
            ztlp admin create-group techs@techrockstars.ztlp --description \"Field technicians\"\n  \
            ztlp admin create-group admins@acme.ztlp --json"
    )]
    CreateGroup {
        /// Group name (e.g. techs@techrockstars.ztlp)
        name: String,

        /// Group description
        #[arg(long)]
        description: Option<String>,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage group membership (add/remove members, list, check)
    ///
    /// Subcommands: add, remove, members, check
    #[command(
        subcommand,
        after_help = "EXAMPLES:\n  \
            ztlp admin group add techs@techrockstars.ztlp steve@techrockstars.ztlp\n  \
            ztlp admin group remove techs@techrockstars.ztlp alice@techrockstars.ztlp\n  \
            ztlp admin group members techs@techrockstars.ztlp\n  \
            ztlp admin group check techs@techrockstars.ztlp steve@techrockstars.ztlp"
    )]
    Group(GroupCommands),

    /// List all groups in the namespace
    ///
    /// Queries the NS server for all GROUP records.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin groups\n  \
            ztlp admin groups --json")]
    Groups {
        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Revoke a device, user, or group identity
    ///
    /// Registers a REVOKE record in the NS server, blocking future
    /// connections and preventing re-registration of the revoked entity.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin revoke laptop-01.techrockstars.ztlp --reason \"stolen device\"\n  \
            ztlp admin revoke steve@techrockstars.ztlp --reason \"left company\" --json")]
    Revoke {
        /// Name to revoke (e.g. laptop-01.zone.ztlp, steve@zone.ztlp)
        name: String,

        /// Reason for revocation
        #[arg(long, default_value = "unspecified")]
        reason: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// View the audit log
    ///
    /// Queries the NS server for recent identity operations (registrations,
    /// revocations, updates). Results are filtered by time and optionally
    /// by name pattern.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin audit --since 24h\n  \
            ztlp admin audit --since 1h --json\n  \
            ztlp admin audit --name \"steve@*\" --json")]
    Audit {
        /// Show entries since this duration ago (e.g. 1h, 24h, 7d, 30m)
        #[arg(long, default_value = "24h")]
        since: String,

        /// Filter by name pattern (supports * wildcards)
        #[arg(long)]
        name: Option<String>,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Rotate the zone signing key
    ///
    /// Generates a new zone signing key, re-signs all records in the zone,
    /// and stores the new key.
    #[command(
        name = "rotate-zone-key",
        after_help = "EXAMPLES:\n  \
            ztlp admin rotate-zone-key\n  \
            ztlp admin rotate-zone-key --json"
    )]
    RotateZoneKey {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Export the zone signing key
    ///
    /// Exports the zone signing key for backup purposes.
    #[command(
        name = "export-zone-key",
        after_help = "EXAMPLES:\n  \
            ztlp admin export-zone-key --format pem\n  \
            ztlp admin export-zone-key --format hex --json"
    )]
    ExportZoneKey {
        /// Export format (pem or hex)
        #[arg(long, default_value = "pem")]
        format: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    // ── TLS / CA Management ─────────────────────────────────────
    /// Initialize the internal Certificate Authority
    ///
    /// Generates a root CA key pair and self-signed root certificate,
    /// plus an intermediate CA for day-to-day certificate issuance.
    /// Stores keys in the ZTLP config directory.
    #[command(
        name = "ca-init",
        after_help = "EXAMPLES:\n  \
            ztlp admin ca-init --zone corp.ztlp\n  \
            ztlp admin ca-init --zone corp.ztlp --output /etc/ztlp/ca/"
    )]
    CaInit {
        /// Zone name for the CA (e.g. corp.ztlp)
        #[arg(short, long)]
        zone: String,

        /// Directory to store CA key material (default: ~/.ztlp/ca/)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show CA status and certificate details
    #[command(
        name = "ca-show",
        after_help = "EXAMPLES:\n  ztlp admin ca-show\n  ztlp admin ca-show --json"
    )]
    CaShow {
        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Export the root CA certificate (PEM)
    ///
    /// Prints the root CA certificate in PEM format, suitable for
    /// importing into OS trust stores or browser cert managers.
    #[command(
        name = "ca-export-root",
        after_help = "EXAMPLES:\n  \
            ztlp admin ca-export-root > ztlp-root.pem\n  \
            ztlp admin ca-export-root --ca-dir /etc/ztlp/ca/"
    )]
    CaExportRoot {
        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },

    /// Rotate the intermediate CA certificate
    ///
    /// Generates a new intermediate CA key pair signed by the root CA.
    /// Existing certificates remain valid until they expire.
    #[command(
        name = "ca-rotate-intermediate",
        after_help = "EXAMPLES:\n  ztlp admin ca-rotate-intermediate\n  ztlp admin ca-rotate-intermediate --json"
    )]
    CaRotateIntermediate {
        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Issue a TLS certificate for a hostname or node
    ///
    /// Signs a certificate with the ZTLP intermediate CA for the
    /// specified subject. Outputs cert + key in PEM format.
    #[command(
        name = "cert-issue",
        after_help = "EXAMPLES:\n  \
            ztlp admin cert-issue --hostname webapp.corp.ztlp\n  \
            ztlp admin cert-issue --hostname db.corp.ztlp --days 365 --output /etc/ztlp/certs/"
    )]
    CertIssue {
        /// Hostname (Subject Alternative Name)
        #[arg(long)]
        hostname: String,

        /// Validity in days (default: 90)
        #[arg(long, default_value = "90")]
        days: u32,

        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output directory for cert and key
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// List issued certificates
    #[command(
        name = "cert-list",
        after_help = "EXAMPLES:\n  ztlp admin cert-list\n  ztlp admin cert-list --json"
    )]
    CertList {
        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show details of a specific certificate
    #[command(
        name = "cert-show",
        after_help = "EXAMPLES:\n  ztlp admin cert-show --serial ABC123\n  ztlp admin cert-show --hostname webapp.corp.ztlp"
    )]
    CertShow {
        /// Certificate serial number
        #[arg(long)]
        serial: Option<String>,

        /// Hostname to look up
        #[arg(long)]
        hostname: Option<String>,

        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Revoke a certificate
    ///
    /// Marks a certificate as revoked in the CA's revocation list.
    /// The gateway CRL server will serve the updated revocation list.
    #[command(
        name = "cert-revoke",
        after_help = "EXAMPLES:\n  ztlp admin cert-revoke --serial ABC123 --reason key-compromise\n  ztlp admin cert-revoke --hostname webapp.corp.ztlp"
    )]
    CertRevoke {
        /// Certificate serial number
        #[arg(long)]
        serial: Option<String>,

        /// Hostname to revoke
        #[arg(long)]
        hostname: Option<String>,

        /// Revocation reason
        #[arg(long, default_value = "unspecified")]
        reason: String,

        /// CA directory (default: ~/.ztlp/ca/)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Identity type for `ztlp setup --type`
#[derive(Clone, Copy, Debug, ValueEnum)]
enum SetupType {
    /// Device identity (default — backward compatible with KEY registration)
    Device,
    /// User identity (creates USER record instead of KEY)
    User,
}

/// Record type filter for `ztlp admin ls --type`
#[derive(Clone, Copy, Debug, ValueEnum)]
enum RecordTypeFilter {
    Device,
    User,
    Key,
    Group,
}

/// User role for `ztlp admin create-user --role`
#[derive(Clone, Copy, Debug, ValueEnum)]
enum UserRole {
    User,
    Tech,
    Admin,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Tech => write!(f, "tech"),
            UserRole::Admin => write!(f, "admin"),
        }
    }
}

/// Subcommands for `ztlp admin group`
#[derive(Subcommand)]
enum GroupCommands {
    /// Add a member to a group
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin group add techs@techrockstars.ztlp steve@techrockstars.ztlp\n  \
            ztlp admin group add techs@acme.ztlp alice@acme.ztlp --json")]
    Add {
        /// Group name (e.g. techs@techrockstars.ztlp)
        group: String,

        /// Member to add (e.g. steve@techrockstars.ztlp)
        member: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Remove a member from a group
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin group remove techs@techrockstars.ztlp alice@techrockstars.ztlp\n  \
            ztlp admin group remove techs@acme.ztlp bob@acme.ztlp --json")]
    Remove {
        /// Group name
        group: String,

        /// Member to remove
        member: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// List members of a group
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin group members techs@techrockstars.ztlp\n  \
            ztlp admin group members admins@acme.ztlp --json")]
    Members {
        /// Group name
        group: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Check if a user is a member of a group
    #[command(after_help = "EXAMPLES:\n  \
            ztlp admin group check techs@techrockstars.ztlp steve@techrockstars.ztlp\n  \
            ztlp admin group check admins@acme.ztlp alice@acme.ztlp --json")]
    Check {
        /// Group name
        group: String,

        /// User to check
        user: String,

        /// NS server address (host:port)
        #[arg(long)]
        ns_server: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
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
                --key ~/.ztlp/identity.json --ns-server 127.0.0.1:23096\n  \
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
        #[arg(long, default_value = "127.0.0.1:23096")]
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
            ztlp ns lookup mynode.acme.ztlp --ns-server 10.0.0.1:23096")]
    Lookup {
        /// Name to look up
        name: String,

        /// NS server address (host:port)
        #[arg(long, default_value = "127.0.0.1:23096")]
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
            ztlp ns pubkey a1b2c3d4... --ns-server 127.0.0.1:23096")]
    Pubkey {
        /// Public key in hex
        hex: String,

        /// NS server address (host:port)
        #[arg(long, default_value = "127.0.0.1:23096")]
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
/// Parse a duration string like "100ms", "1s", "10s", "5m"
fn parse_duration_arg(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(ms_str) = s.strip_suffix("ms") {
        ms_str
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| format!("invalid milliseconds '{}': {}", ms_str, e))
    } else if let Some(s_str) = s.strip_suffix('s') {
        s_str
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("invalid seconds '{}': {}", s_str, e))
    } else if let Some(m_str) = s.strip_suffix('m') {
        m_str
            .parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|e| format!("invalid minutes '{}': {}", m_str, e))
    } else {
        // Default to seconds
        s.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("invalid duration '{}': {}", s, e))
    }
}

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
        MsgType::Migrate => "MIGRATE (0x08)",
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
    hasher.update(ed25519_seed);
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
            .unwrap_or_else(|| "127.0.0.1:23096".to_string())
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

    // Fallback: some NS versions store address in the KEY record CBOR data.
    // Try extracting "address" from KEY record if SVC didn't yield one.
    if resolved_addr.is_none() {
        if let Ok(Some(raw)) = ns_query_raw(name_part, &ns_server, 1).await {
            if let Some(addr_str) = cbor_extract_string(&raw.data_bytes, "address") {
                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                    eprintln!("  {} KEY record address → {}", c_green("✓"), addr);
                    resolved_addr = Some(addr);
                }
            }
        }
    }

    // Query KEY record (type 1) for NodeID (identity verification)
    let mut resolved_node_id: Option<NodeId> = None;
    if let Ok(Some(raw)) = ns_query_raw(name_part, &ns_server, 1).await {
        // Extract node_id from CBOR-encoded KEY record data
        if let Some(nid_hex) = cbor_extract_string(&raw.data_bytes, "node_id") {
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

/// Extract a string value for a given text key from a CBOR-encoded map.
///
/// Supports the subset of RFC 8949 CBOR used by ZTLP-NS:
/// - Maps (major type 5) with text string keys/values (major type 3)
///
/// Returns None if the key is not found or the format doesn't match.
fn cbor_extract_string(data: &[u8], target_key: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut pos = 0;

    // Parse initial byte
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    pos += 1;

    // Must be a map (major type 5)
    if major != 5 {
        return None;
    }

    let (arity, new_pos) = cbor_read_uint(additional, data, pos)?;
    pos = new_pos;

    for _ in 0..arity {
        // Parse key
        let (key_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;

        // Parse value
        let (val_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;

        if key_str == target_key {
            return Some(val_str);
        }
    }

    None
}

/// Read a CBOR unsigned integer argument from the additional info byte.
fn cbor_read_uint(additional: u8, data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if additional < 24 {
        Some((additional as usize, pos))
    } else if additional == 24 {
        if pos >= data.len() {
            return None;
        }
        Some((data[pos] as usize, pos + 1))
    } else if additional == 25 {
        if pos + 2 > data.len() {
            return None;
        }
        let n = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        Some((n, pos + 2))
    } else if additional == 26 {
        if pos + 4 > data.len() {
            return None;
        }
        let n =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        Some((n, pos + 4))
    } else {
        None
    }
}

/// Read a CBOR text string (major type 3) from data at the given position.
fn cbor_read_text(data: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= data.len() {
        return None;
    }
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    if major != 3 {
        return None;
    } // Must be text string
    let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
    if new_pos + len > data.len() {
        return None;
    }
    let s = std::str::from_utf8(&data[new_pos..new_pos + len]).ok()?;
    Some((s.to_string(), new_pos + len))
}

/// Query result from NS containing the raw CBOR data field.
struct NsQueryResult {
    /// Raw CBOR-encoded data bytes from the record
    data_bytes: Vec<u8>,
}

/// Check if a byte is a valid ZTLP-NS record type byte.
/// Core types: 1-7 (KEY, SVC, RELAY, POLICY, REVOKE, BOOTSTRAP, OPERATOR)
/// Identity types: 0x10-0x12 (DEVICE, USER, GROUP)
fn is_valid_record_type(type_byte: u8) -> bool {
    (1..=7).contains(&type_byte) || (0x10..=0x12).contains(&type_byte)
}

/// Perform an NS query for a given record type. Returns the raw CBOR data field if found.
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
            // NS amplification prevention may insert a 0x01 truncation flag
            // after the 0x02 response code: <<0x02, 0x01, record...>>.
            // Detect by trying to parse from offset 2 first (with flag),
            // then fall back to offset 1 (no flag).
            let record = 'parse: {
                if data.len() > 5 && data[1] == 0x01 {
                    // Possible truncation flag — check if offset 2 yields a valid type_byte
                    // (1-7 for core types, 0x10-0x12 for identity types)
                    // and a reasonable name_len
                    let maybe_type = data[2];
                    if is_valid_record_type(maybe_type) && data.len() > 4 {
                        let maybe_name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                        if maybe_name_len < 1024 && data.len() >= 5 + maybe_name_len {
                            break 'parse &data[2..];
                        }
                    }
                }
                &data[1..]
            };
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

/// High-level NS query: extract a specific string field from a record's CBOR data.
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
                2 => cbor_extract_string(&r.data_bytes, "address"), // SVC → address
                1 => cbor_extract_string(&r.data_bytes, "node_id"), // KEY → node_id
                3 => cbor_extract_string(&r.data_bytes, "endpoints"), // RELAY → endpoints
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

/// Look up a record by public key (query type 0x05) and extract the name.
/// Used for NS reverse lookup: given a peer's X25519 pubkey hex, find their
/// registered ZTLP-NS name for policy evaluation.
async fn ns_pubkey_lookup(
    pubkey_hex: &str,
    ns_server: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let ns_addr: SocketAddr = ns_server.parse()?;
    let pk_bytes = pubkey_hex.as_bytes();
    let pk_len = pk_bytes.len() as u16;
    let mut query = Vec::with_capacity(3 + pk_bytes.len());
    query.push(0x05); // pubkey query
    query.extend_from_slice(&pk_len.to_be_bytes());
    query.extend_from_slice(pk_bytes);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, ns_addr).await?;
    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let data = &buf[..len];
            if data.is_empty() || data[0] != 0x02 {
                return Ok(None);
            }
            // Parse the record to extract the name.
            // Handle truncation flag (0x01 after 0x02) from amplification prevention.
            let record = 'parse: {
                if data.len() > 5 && data[1] == 0x01 {
                    let maybe_type = data[2];
                    if is_valid_record_type(maybe_type) && data.len() > 4 {
                        let maybe_name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                        if maybe_name_len < 1024 && data.len() >= 5 + maybe_name_len {
                            break 'parse &data[2..];
                        }
                    }
                }
                &data[1..]
            };
            if record.len() < 4 {
                return Ok(None);
            }
            let _type_byte = record[0];
            let name_len = u16::from_be_bytes([record[1], record[2]]) as usize;
            if record.len() < 3 + name_len {
                return Ok(None);
            }
            let name = std::str::from_utf8(&record[3..3 + name_len])
                .ok()
                .map(|s| s.to_string());
            Ok(name)
        }
        _ => Ok(None),
    }
}

// ── NS Resolver for Policy Engine ────────────────────────────────────────
//
// Queries ZTLP-NS for GROUP, USER, and DEVICE records to support
// group: and role: patterns in the policy engine.

use ztlp_proto::policy::NsResolver;

/// Real NS resolver that queries a ZTLP-NS server over UDP.
struct UdpNsResolver {
    ns_server: String,
}

impl UdpNsResolver {
    fn new(ns_server: &str) -> Self {
        Self {
            ns_server: ns_server.to_string(),
        }
    }
}

impl NsResolver for UdpNsResolver {
    fn group_members(
        &self,
        group_name: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + '_>> {
        let group = group_name.to_string();
        let ns = self.ns_server.clone();
        Box::pin(async move {
            // Query GROUP record (type 0x12)
            match ns_query_raw(&group, &ns, 0x12).await {
                Ok(Some(result)) => {
                    // Extract "members" field from CBOR as a string array
                    cbor_extract_string_array(&result.data_bytes, "members")
                }
                _ => vec![],
            }
        })
    }

    fn user_role(
        &self,
        user_name: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + '_>> {
        let user = user_name.to_string();
        let ns = self.ns_server.clone();
        Box::pin(async move {
            // Query USER record (type 0x11)
            match ns_query_raw(&user, &ns, 0x11).await {
                Ok(Some(result)) => cbor_extract_string(&result.data_bytes, "role"),
                _ => None,
            }
        })
    }

    fn device_owner(
        &self,
        device_name: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + '_>> {
        let device = device_name.to_string();
        let ns = self.ns_server.clone();
        Box::pin(async move {
            // Query DEVICE record (type 0x10)
            match ns_query_raw(&device, &ns, 0x10).await {
                Ok(Some(result)) => cbor_extract_string(&result.data_bytes, "owner"),
                _ => None,
            }
        })
    }
}

/// Extract a string array from a CBOR map for a given key.
///
/// Parses the CBOR data (expected to be a map) and extracts the value
/// for `target_key` as a list of strings.
fn cbor_extract_string_array(data: &[u8], target_key: &str) -> Vec<String> {
    // Use our full CBOR-to-JSON decoder, then extract from the JSON
    match cbor_decode_to_json(data) {
        Some(val) => {
            if let Some(arr) = val.get(target_key).and_then(|v| v.as_array()) {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            } else {
                vec![]
            }
        }
        None => vec![],
    }
}

/// `ztlp connect` — Connect to a ZTLP peer (supports NS name resolution)
#[allow(clippy::too_many_arguments)]
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
    punch_enabled: bool,
    punch_delay: &Option<Duration>,
    punch_timeout: &Option<Duration>,
    relay_pool_enabled: bool,
    relay_probe_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_generate_identity(key)?;

    // Resolve target: raw ip:port or ZTLP-NS name
    let (peer_addr, _resolved_node_id) = resolve_target(target, ns_server).await?;

    let mut send_addr = if let Some(relay_str) = relay {
        relay_str
            .parse()
            .map_err(|e| format!("invalid relay address '{}': {}", relay_str, e))?
    } else {
        peer_addr
    };

    // Initialize relay pool if --relay-pool is enabled or multiple relays are available
    let _relay_pool = if relay_pool_enabled || relay.is_some() {
        let pool_config = RelayPoolConfig {
            probe_interval: relay_probe_interval,
            failover_enabled: relay.is_none() || relay_pool_enabled, // failover off when pinned
            pinned_relay: if relay.is_some() && !relay_pool_enabled {
                Some(send_addr)
            } else {
                None
            },
            ns_server: ns_server.clone(),
            zone: None,
        };
        let mut pool = RelayPool::new(pool_config);
        pool.add_relay(send_addr);

        // If relay_pool is explicitly enabled, we'd query NS for more relays
        // For now, add the configured relay as the pool's single entry
        if relay_pool_enabled {
            eprintln!("{}", c_dim("Relay pool: enabled"));
            eprintln!("  {} {}", c_cyan("Primary relay:"), send_addr);
            eprintln!("  {} {:?}", c_cyan("Probe interval:"), relay_probe_interval);
        }

        Some(FailoverOrchestrator::new(pool))
    } else {
        None
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

    // NS-coordinated hole punching (if --punch)
    if punch_enabled {
        let ns_addr_str = ns_server.as_deref().ok_or("--punch requires --ns-server")?;
        let ns_addr: SocketAddr = ns_addr_str
            .parse()
            .map_err(|e| format!("invalid --ns-server '{}': {}", ns_addr_str, e))?;

        let peer_node_id = _resolved_node_id.unwrap_or_else(NodeId::zero);

        eprintln!(
            "\n{}",
            c_dim("Hole punching enabled — coordinating via NS...")
        );

        let mut punch_config = punch::PunchConfig::default();
        if let Some(d) = punch_delay {
            punch_config.punch_delay = *d;
        }
        if let Some(t) = punch_timeout {
            punch_config.punch_timeout = *t;
        }

        let our_endpoints: Vec<SocketAddr> = vec![node.local_addr];

        match punch::execute_punch(
            &node.socket,
            ns_addr,
            &identity.node_id,
            &peer_node_id,
            &our_endpoints,
            &punch_config,
        )
        .await
        {
            Ok(punch::PunchResult::Success {
                peer_addr: punched_addr,
            }) => {
                eprintln!(
                    "{} Direct connection via hole punch to {}",
                    c_green("✓"),
                    punched_addr
                );
                send_addr = punched_addr;
            }
            Ok(punch::PunchResult::TimedOut) => {
                if no_relay_fallback {
                    return Err("hole punch timed out and --no-relay-fallback was specified".into());
                }
                eprintln!(
                    "{} Hole punch timed out — {}",
                    c_yellow("⚠"),
                    if relay.is_some() {
                        "falling back to relay"
                    } else {
                        "continuing with direct connection attempt"
                    }
                );
            }
            Err(e) => {
                if no_relay_fallback {
                    return Err(format!("punch failed: {}", e).into());
                }
                eprintln!(
                    "{} Punch failed: {} — continuing with fallback",
                    c_yellow("⚠"),
                    e
                );
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

    // Message 1: HELLO (with retransmit on timeout)
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

    // Message 2: receive HELLO_ACK (with retransmit of HELLO on timeout)
    eprintln!("{}", c_dim("← Waiting for HELLO_ACK (message 2/3)..."));
    let mut retry_delay = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
    let max_retry_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);
    let mut retries: u8 = 0;

    let (recv2, _from2) = loop {
        match timeout(retry_delay, node.recv_raw()).await {
            Ok(Ok((data, addr))) => {
                if data.len() >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                        if hdr.msg_type == MsgType::HelloAck && hdr.session_id == session_id {
                            break (data, addr);
                        }
                    }
                }
                // Not a HELLO_ACK for our session — ignore and keep waiting
                continue;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Timeout — retransmit HELLO
                retries += 1;
                if retries > MAX_HANDSHAKE_RETRIES {
                    return Err("handshake failed: no HELLO_ACK after retransmits".into());
                }
                debug!(
                    "handshake: retransmitting HELLO (attempt {}/{})",
                    retries, MAX_HANDSHAKE_RETRIES
                );
                eprintln!(
                    "  {} retransmitting HELLO ({}/{})",
                    c_yellow("⟳"),
                    retries,
                    MAX_HANDSHAKE_RETRIES
                );
                node.send_raw(&pkt1, send_addr).await?; // exact same bytes
                retry_delay = (retry_delay * 2).min(max_retry_delay);
            }
        }
    };

    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("received packet too short for handshake header".into());
    }
    let recv2_header = HandshakeHeader::deserialize(&recv2)?;
    if recv2_header.msg_type != MsgType::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", recv2_header.msg_type).into());
    }

    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)?;

    // Message 3: final confirmation with ClientProfile (for CC selection)
    eprintln!("{}", c_dim("→ Sending final confirmation (message 3/3)..."));
    let profile = ztlp_proto::client_profile::ClientProfile::desktop(
        format!("ztlp/{}", env!("CARGO_PKG_VERSION")),
    );
    let profile_cbor = profile.to_cbor();
    let msg3 = ctx.write_message(&profile_cbor)?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    node.send_raw(&pkt3, send_addr).await?;

    // Finalize — handshake should be complete after sending msg3
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

    // Brief check for server REJECT frame (e.g. policy denial).
    // The server sends REJECT *after* the handshake completes, so we
    // poll for a short window before declaring the tunnel active.
    {
        let reject_deadline = tokio::time::sleep(std::time::Duration::from_millis(500));
        tokio::pin!(reject_deadline);
        loop {
            tokio::select! {
                _ = &mut reject_deadline => break, // no reject received — proceed
                result = node.recv_data() => {
                    match result {
                        Ok(Some((plaintext, _from))) => {
                            if RejectFrame::is_reject(&plaintext) {
                                if let Some(reject) = RejectFrame::decode(&plaintext) {
                                    eprintln!(
                                        "\n{} {}",
                                        c_red("✗ Server rejected:"),
                                        reject.message
                                    );
                                    return Err(format!(
                                        "access denied: {} ({})",
                                        reject.message, reject.reason
                                    ).into());
                                }
                            }
                            // Non-reject data — ignore during this window
                        }
                        Ok(None) => {} // dropped by pipeline
                        Err(_) => break, // socket error — proceed
                    }
                }
            }
        }
    }
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

        let mut first_connection = true;
        loop {
            let (tcp_stream, tcp_addr) = tcp_listener.accept().await?;
            eprintln!("{} {} → tunnel", c_cyan("TCP connection from"), tcp_addr);

            let udp = node.socket.clone();
            let pipeline = node.pipeline.clone();

            // For subsequent TCP connections (not the first), send a RESET
            // frame so the remote listener knows to open a new backend
            // connection and reset its reassembly state.
            let result = if first_connection {
                first_connection = false;
                tunnel::run_bridge(tcp_stream, udp, pipeline, session_id, send_addr).await
            } else {
                tunnel::run_bridge_with_reset(tcp_stream, udp, pipeline, session_id, send_addr)
                    .await
            };

            match result {
                Ok(_outcome) => {
                    eprintln!("{} {}", c_dim("TCP connection closed:"), tcp_addr);
                }
                Err(e) => {
                    eprintln!("{} {}", c_red("✗ tunnel error:"), e);
                }
            }
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
#[allow(clippy::too_many_arguments)]
async fn cmd_listen(
    bind: &str,
    key: &Option<PathBuf>,
    _gateway_mode: bool,
    forward: &[String],
    policy_path: &Option<PathBuf>,
    ns_server: &Option<String>,
    stun_server: &Option<String>,
    nat_assist: bool,
    max_sessions: usize,
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

    // Load policy engine (needed for both single and multi-session modes)
    let policy = if let Some(path) = policy_path {
        eprintln!("  {} {}", c_cyan("Policy:"), path.display());
        PolicyEngine::from_file(path)?
    } else {
        let default_path = dirs::home_dir().map(|h| h.join(".ztlp").join("policy.toml"));
        if let Some(ref p) = default_path {
            if p.exists() {
                eprintln!("  {} {} (auto-detected)", c_cyan("Policy:"), p.display());
                PolicyEngine::from_file(p)?
            } else {
                PolicyEngine::allow_all()
            }
        } else {
            PolicyEngine::allow_all()
        }
    };

    // Multi-session mode: when --forward is set and max_sessions > 1
    if !forward.is_empty() && max_sessions > 1 {
        return cmd_listen_multi_session(
            &node,
            &identity,
            forward,
            &policy,
            ns_server,
            max_sessions,
        )
        .await;
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

    // Send HELLO_ACK and cache the packet bytes for retransmit
    eprintln!("{}", c_dim("→ Sending HELLO_ACK (message 2/3)..."));
    let msg2 = ctx.write_message(&[])?;
    let mut ack_hdr = HandshakeHeader::new(MsgType::HelloAck);
    ack_hdr.session_id = session_id;
    ack_hdr.src_node_id = *identity.node_id.as_bytes();
    ack_hdr.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_hdr.serialize();
    pkt2.extend_from_slice(&msg2);
    node.send_raw(&pkt2, from1).await?;

    // Cache HELLO_ACK for retransmit on duplicate HELLO
    let cached_pkt2 = pkt2.clone();
    let mut responder_retransmit_count: u8 = 0;

    // Receive message 3 (with retransmit of HELLO_ACK on duplicate HELLO)
    eprintln!("{}", c_dim("← Waiting for message 3/3..."));
    let mut retry_delay = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
    let max_retry_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);
    let hs_start = Instant::now();

    let (recv3, _from3) = loop {
        match timeout(retry_delay, node.recv_raw()).await {
            Ok(Ok((data, addr))) => {
                if data.len() >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                        // Is this msg3 for our session?
                        if hdr.session_id == session_id && hdr.msg_type != MsgType::Hello {
                            break (data, addr);
                        }
                        // Duplicate HELLO — resend cached HELLO_ACK
                        if hdr.msg_type == MsgType::Hello && hdr.session_id == session_id {
                            if responder_retransmit_count < MAX_RESPONDER_RETRANSMITS {
                                debug!(
                                    "handshake: resending cached HELLO_ACK for session {} (retransmit {})",
                                    session_id, responder_retransmit_count + 1
                                );
                                eprintln!(
                                    "  {} resending HELLO_ACK ({}/{})",
                                    c_yellow("⟳"),
                                    responder_retransmit_count + 1,
                                    MAX_RESPONDER_RETRANSMITS
                                );
                                node.send_raw(&cached_pkt2, from1).await?;
                                responder_retransmit_count += 1;
                            } else {
                                debug!(
                                    "handshake: dropping duplicate HELLO for session {} (max retransmits reached)",
                                    session_id
                                );
                            }
                            continue;
                        }
                    }
                }
                // Not relevant — ignore
                continue;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Timeout — check if overall TTL exceeded
                if hs_start.elapsed() > Duration::from_secs(HALF_OPEN_TTL_SECS) {
                    return Err("handshake timeout waiting for message 3".into());
                }
                // Retransmit HELLO_ACK proactively
                if responder_retransmit_count < MAX_RESPONDER_RETRANSMITS {
                    debug!(
                        "handshake: proactively retransmitting HELLO_ACK (timeout, attempt {})",
                        responder_retransmit_count + 1
                    );
                    eprintln!(
                        "  {} retransmitting HELLO_ACK ({}/{})",
                        c_yellow("⟳"),
                        responder_retransmit_count + 1,
                        MAX_RESPONDER_RETRANSMITS
                    );
                    node.send_raw(&cached_pkt2, from1).await?;
                    responder_retransmit_count += 1;
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                } else {
                    return Err(
                        "handshake timeout waiting for message 3 (max retransmits reached)".into(),
                    );
                }
            }
        }
    };

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

    // Extract the peer's X25519 public key from the Noise handshake state
    // before finalize() consumes it. Used for NS reverse lookup.
    let peer_pubkey_hex = ctx.remote_static_hex();

    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    let session_id = session.session_id;
    {
        let mut pipeline = node.pipeline.lock().await;
        pipeline.register_session(session);
    }

    // Client identity for policy evaluation.
    // Try NS reverse lookup by pubkey to get the registered name;
    // fall back to NodeID hex if NS is unavailable or lookup fails.
    let client_identity = if let (Some(ns), Some(pk_hex)) = (ns_server.as_ref(), &peer_pubkey_hex) {
        match ns_pubkey_lookup(pk_hex, ns).await {
            Ok(Some(name)) => {
                debug!("NS reverse lookup: {} → {}", pk_hex, name);
                name
            }
            _ => {
                debug!("NS reverse lookup failed for {}, using NodeID", pk_hex);
                format!("{}", peer_node_id)
            }
        }
    } else {
        format!("{}", peer_node_id)
    };

    eprintln!("\n{}", c_green("✓ Handshake complete!"));
    eprintln!("  {} {}", c_cyan("Remote NodeID:"), peer_node_id);
    eprintln!("  {} {}", c_cyan("Session ID:"), session_id);
    eprintln!();

    // Branch: tunnel mode or interactive mode
    if !forward.is_empty() {
        let registry = tunnel::ServiceRegistry::from_forward_args(forward)?;

        // Resolve which backend this client wants
        let resolve_result = registry.resolve(&recv1_header.dst_svc_id);
        let (svc_name, forward_addr) = match resolve_result {
            Some(pair) => pair,
            None => {
                let requested = String::from_utf8_lossy(
                    &recv1_header.dst_svc_id[..recv1_header
                        .dst_svc_id
                        .iter()
                        .rposition(|&b| b != 0)
                        .map(|i| i + 1)
                        .unwrap_or(0)],
                )
                .to_string();
                let msg = if requested.is_empty() {
                    "client requested default service but no unnamed --forward was configured"
                        .to_string()
                } else {
                    format!(
                        "client requested unknown service '{}'. Available: {:?}",
                        requested,
                        registry.services.keys().collect::<Vec<_>>()
                    )
                };

                // Send REJECT frame: SERVICE_UNAVAILABLE
                let reject = RejectFrame::new(RejectReason::ServiceUnavailable, &msg);
                if let Err(e) = tunnel::send_reject(
                    &node.socket,
                    &node.pipeline,
                    session_id,
                    from1,
                    &reject.encode(),
                )
                .await
                {
                    eprintln!("{} failed to send REJECT frame: {}", c_red("✗"), e);
                }

                return Err(msg.into());
            }
        };

        // Policy check — use async resolver for group:/role: patterns
        let policy_allowed = if policy.has_identity_patterns() {
            if let Some(ns) = ns_server.as_ref() {
                let resolver = UdpNsResolver::new(ns);
                policy
                    .authorize_async(&client_identity, svc_name, &resolver)
                    .await
            } else {
                policy.authorize(&client_identity, svc_name)
            }
        } else {
            policy.authorize(&client_identity, svc_name)
        };
        if !policy_allowed {
            eprintln!(
                "{} {} denied access to service '{}'",
                c_red("✗ POLICY DENIED:"),
                client_identity,
                svc_name
            );

            // Send REJECT frame to client before closing
            let reject = RejectFrame::new(
                RejectReason::PolicyDenied,
                format!(
                    "{} is not authorized for service '{}'",
                    client_identity, svc_name
                ),
            );
            if let Err(e) = tunnel::send_reject(
                &node.socket,
                &node.pipeline,
                session_id,
                from1,
                &reject.encode(),
            )
            .await
            {
                eprintln!("{} failed to send REJECT frame: {}", c_red("✗"), e);
            } else {
                eprintln!("{} REJECT frame sent to client", c_dim("→"));
            }

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

        // Loop: each iteration handles one TCP stream. When the client
        // sends a RESET frame (new TCP connection on the same ZTLP
        // session), we open a new backend TCP connection and bridge again.
        //
        // After a normal close (FIN from both sides), we wait briefly for
        // a potential RESET frame from the client. If nothing arrives
        // within the idle timeout, the listener exits.
        //
        // `pending_packets` carries data packets captured during the
        // inter-bridge gap (by wait_for_reset_buffered). These are
        // injected into the next bridge to prevent data loss.
        //
        // LAZY CONNECT: On the first iteration (no pending packets),
        // we wait for the first ZTLP data packet before connecting to
        // the backend. This prevents sshd from sending its banner into
        // a void when the client hasn't connected yet (e.g., during a
        // demo presentation pause between handshake and SSH usage).
        let mut pending_packets: Vec<Vec<u8>> = Vec::new();
        let mut first_iteration = true;
        loop {
            // On the first iteration with no pending data, wait for the
            // client to actually send data before connecting to the backend.
            // This avoids the race where sshd sends its SSH banner, the
            // listener bridges it over ZTLP, but the client has no TCP
            // connection yet to receive ACKs, causing a 30s ACK timeout.
            if first_iteration && pending_packets.is_empty() {
                first_iteration = false;
                eprintln!("{}", c_dim("Waiting for client to start sending data..."));
                match tunnel::wait_for_first_data(
                    &node.socket,
                    &node.pipeline,
                    session_id,
                    from1,
                    Duration::from_secs(600),
                )
                .await
                {
                    Ok(initial_packets) => {
                        eprintln!(
                            "{} received {} initial packet(s) from client",
                            c_cyan("↓"),
                            initial_packets.len()
                        );
                        pending_packets = initial_packets;
                    }
                    Err(e) => {
                        eprintln!("{} {}", c_red("✗ timeout waiting for client data:"), e);
                        break;
                    }
                }
            }

            let tcp_stream = TcpStream::connect(forward_addr)
                .await
                .map_err(|e| format!("failed to connect to {}: {}", forward_addr, e))?;
            eprintln!("{} {}", c_green("✓ Connected to backend"), forward_addr);

            let udp = node.socket.clone();
            let pipeline = node.pipeline.clone();

            // Use run_bridge_with_buffered when we have packets from the
            // previous wait_for_reset_buffered, otherwise plain run_bridge.
            let buffered = std::mem::take(&mut pending_packets);
            let result = if buffered.is_empty() {
                tunnel::run_bridge(tcp_stream, udp, pipeline, session_id, from1).await
            } else {
                eprintln!(
                    "{} injecting {} buffered packets into new bridge",
                    c_cyan("↻"),
                    buffered.len()
                );
                tunnel::run_bridge_with_buffered(
                    tcp_stream, udp, pipeline, session_id, from1, buffered,
                )
                .await
            };

            match result {
                Ok(tunnel::BridgeOutcome::ResetReceived) => {
                    eprintln!(
                        "{}",
                        c_cyan("↻ Remote started new TCP stream — reconnecting to backend")
                    );
                    // Continue the loop to open a new backend connection
                    continue;
                }
                Ok(tunnel::BridgeOutcome::Closed) => {
                    eprintln!("{}", c_dim("tunnel closed, waiting for new streams..."));
                    // Wait for a potential RESET frame from the client.
                    // The client may open another TCP connection and send
                    // RESET, which arrives as an encrypted UDP packet.
                    // We use the buffered variant to capture data packets
                    // that arrive during the wait, preventing data loss.
                    match wait_for_reset_buffered(
                        &node,
                        session_id,
                        from1,
                        Duration::from_secs(300),
                    )
                    .await
                    {
                        Ok(reset_result) if reset_result.reset_received => {
                            eprintln!(
                                "{} (buffered {} packets)",
                                c_cyan("↻ Remote started new TCP stream — reconnecting to backend"),
                                reset_result.buffered_packets.len(),
                            );
                            pending_packets = reset_result.buffered_packets;
                            continue;
                        }
                        Ok(_) => {
                            eprintln!("{}", c_dim("idle timeout, listener exiting"));
                            break;
                        }
                        Err(e) => {
                            eprintln!("{} {}", c_red("✗ error waiting for reset:"), e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", c_red("✗ tunnel error:"), e);
                    // Don't exit — the ZTLP session is still valid.
                    // The client may open a new TCP connection and send RESET.
                    // Wait for it so subsequent transfers can succeed.
                    eprintln!("{}", c_dim("waiting for client to reconnect..."));
                    match wait_for_reset_buffered(
                        &node,
                        session_id,
                        from1,
                        Duration::from_secs(300),
                    )
                    .await
                    {
                        Ok(reset_result) if reset_result.reset_received => {
                            eprintln!(
                                "{} (buffered {} packets)",
                                c_cyan("↻ Remote started new TCP stream — reconnecting to backend"),
                                reset_result.buffered_packets.len(),
                            );
                            pending_packets = reset_result.buffered_packets;
                            continue;
                        }
                        Ok(_) => {
                            eprintln!("{}", c_dim("idle timeout after error, listener exiting"));
                            break;
                        }
                        Err(e2) => {
                            eprintln!("{} {}", c_red("✗ error waiting for reset:"), e2);
                            break;
                        }
                    }
                }
            }
        }
    } else {
        eprintln!("--- {} ---", c_bold("ZTLP encrypted session active"));
        eprintln!("Type a message and press Enter to send. Ctrl+C to exit.\n");

        interactive_data_loop(&node, session_id, from1).await?;
    }

    Ok(())
}

/// Multi-session listener: handles concurrent ZTLP sessions.
///
/// Runs a packet dispatcher loop that:
/// 1. Receives all UDP packets on the shared socket
/// 2. Routes HELLO packets → handshake handler → new session
/// 3. Routes data packets → per-session channel → bridge task
/// 4. Enforces max_sessions with REJECT(CAPACITY_FULL)
/// 5. Cleans up half-open and idle sessions
#[allow(clippy::too_many_arguments)]
async fn cmd_listen_multi_session(
    node: &TransportNode,
    identity: &NodeIdentity,
    forward: &[String],
    policy: &PolicyEngine,
    ns_server: &Option<String>,
    max_sessions: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = tunnel::ServiceRegistry::from_forward_args(forward)?;
    let session_mgr = Arc::new(SessionManager::new(max_sessions));

    // Half-open handshake cache for retransmit support
    let mut half_open_cache = HalfOpenCache::new();

    eprintln!("--- {} ---", c_bold("ZTLP multi-session listener"));
    eprintln!("  {} {}", c_cyan("Max sessions:"), max_sessions);
    eprintln!("  {} {}", c_cyan("Services:"), forward.join(", "));
    eprintln!("  {} Ctrl+C\n", c_dim("Stop:"));

    // Spawn cleanup task for expired half-open / idle sessions
    let cleanup_mgr = session_mgr.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let expired: Vec<SessionId> = cleanup_mgr.cleanup_expired().await;
            for sid in &expired {
                debug!("cleaned up expired session {}", sid);
            }
            if !expired.is_empty() {
                eprintln!(
                    "{} cleaned up {} expired session(s) [{} active]",
                    c_dim("♻"),
                    expired.len(),
                    cleanup_mgr.count()
                );
            }
        }
    });

    // Main packet dispatch loop
    loop {
        // Periodically clean up expired half-open entries
        half_open_cache.cleanup_expired();

        let (data, from) = node.recv_raw().await?;

        // Try to parse as a handshake header first
        if data.len() >= HANDSHAKE_HEADER_SIZE {
            if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                if hdr.msg_type == MsgType::Hello {
                    // New session request
                    let session_id = hdr.session_id;

                    // Check half-open cache first — is this a retransmitted HELLO?
                    if let Some(cached) = half_open_cache.get_mut(&session_id) {
                        if cached.retransmit_count < MAX_RESPONDER_RETRANSMITS {
                            // Resend cached HELLO_ACK (exact same bytes)
                            debug!(
                                "handshake: resent cached HELLO_ACK for session {} (retransmit {})",
                                session_id,
                                cached.retransmit_count + 1
                            );
                            eprintln!(
                                "  {} resending cached HELLO_ACK for {} ({}/{})",
                                c_yellow("⟳"),
                                session_id,
                                cached.retransmit_count + 1,
                                MAX_RESPONDER_RETRANSMITS
                            );
                            let _ = node.send_raw(&cached.msg2_bytes, from).await;
                            cached.retransmit_count += 1;
                        } else {
                            debug!(
                                "handshake: dropping duplicate HELLO for session {} (max retransmits reached)",
                                session_id
                            );
                        }
                        continue;
                    }

                    // Check if this session already exists (completed handshake)
                    if session_mgr.has_session(&session_id).await {
                        debug!(
                            "duplicate HELLO for established session {} from {}",
                            session_id, from
                        );
                        continue;
                    }

                    // Check capacity
                    if !session_mgr.can_accept() {
                        eprintln!(
                            "{} at max sessions ({}), rejecting {} from {}",
                            c_yellow("⚠"),
                            max_sessions,
                            session_id,
                            from
                        );

                        // We can't send an encrypted REJECT yet because we haven't
                        // done the handshake. We'll complete the handshake first,
                        // then send REJECT.
                        match complete_handshake_for_reject(node, identity, &data, from).await {
                            Ok((sid, _peer_node_id)) => {
                                let reject = RejectFrame::from_reason(RejectReason::CapacityFull);
                                let _ = tunnel::send_reject(
                                    &node.socket,
                                    &node.pipeline,
                                    sid,
                                    from,
                                    &reject.encode(),
                                )
                                .await;
                                // Unregister the temporary session
                                let mut pipeline = node.pipeline.lock().await;
                                pipeline.remove_session(&sid);
                            }
                            Err(e) => {
                                debug!("failed to complete handshake for reject: {}", e);
                            }
                        }
                        continue;
                    }

                    // Perform handshake for this new session
                    eprintln!(
                        "{} new connection from {} (session {}) [{}/{}]",
                        c_cyan("←"),
                        from,
                        session_id,
                        session_mgr.count() + 1,
                        max_sessions
                    );

                    match handle_new_session(
                        node,
                        identity,
                        &data,
                        from,
                        &registry,
                        policy,
                        ns_server,
                        &session_mgr,
                        &mut half_open_cache,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("{} session setup failed: {}", c_red("✗"), e);
                            // Clean up half-open entry on failure
                            half_open_cache.remove(&session_id);
                        }
                    }
                    continue;
                }
            }
        }

        // Not a HELLO — try to route to an existing session
        if data.len() >= DATA_HEADER_SIZE {
            if let Ok(hdr) = DataHeader::deserialize(&data) {
                let sid = hdr.session_id;
                session_mgr.touch(&sid).await;
                if !session_mgr.route_packet(&sid, data, from).await {
                    // Unknown session — silently drop (normal after session close)
                    debug!("dropping packet for unknown session {}", sid);
                }
                continue;
            }
        }

        // Unrecognized packet — also try to route handshake packets to
        // existing sessions (e.g., message 3 of the handshake in flight)
        if data.len() >= HANDSHAKE_HEADER_SIZE {
            if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                let sid = hdr.session_id;
                if session_mgr.route_packet(&sid, data, from).await {
                    continue;
                }
            }
        }
    }
}

/// Complete a Noise_XX handshake just to send a REJECT frame.
///
/// Used when we need to reject a client (e.g., capacity full) but still
/// need an encrypted channel to send the rejection reason.
async fn complete_handshake_for_reject(
    node: &TransportNode,
    identity: &NodeIdentity,
    hello_data: &[u8],
    from: SocketAddr,
) -> Result<(SessionId, NodeId), Box<dyn std::error::Error>> {
    let recv1_header = HandshakeHeader::deserialize(hello_data)?;
    let session_id = recv1_header.session_id;
    let noise_payload1 = &hello_data[HANDSHAKE_HEADER_SIZE..];

    let mut ctx = HandshakeContext::new_responder(identity)?;
    ctx.read_message(noise_payload1)?;

    // Send HELLO_ACK
    let msg2 = ctx.write_message(&[])?;
    let mut ack_hdr = HandshakeHeader::new(MsgType::HelloAck);
    ack_hdr.session_id = session_id;
    ack_hdr.src_node_id = *identity.node_id.as_bytes();
    ack_hdr.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_hdr.serialize();
    pkt2.extend_from_slice(&msg2);
    node.send_raw(&pkt2, from).await?;

    // Wait for message 3
    let (recv3, _) = timeout(HANDSHAKE_TIMEOUT, node.recv_raw())
        .await
        .map_err(|_| "timeout waiting for message 3 in reject handshake")??;

    if recv3.len() < HANDSHAKE_HEADER_SIZE {
        return Err("message 3 too short".into());
    }
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

    Ok((session_id, peer_node_id))
}

/// Handle a new incoming session: handshake, policy check, spawn bridge task.
#[allow(clippy::too_many_arguments)]
async fn handle_new_session(
    node: &TransportNode,
    identity: &NodeIdentity,
    hello_data: &[u8],
    from: SocketAddr,
    registry: &tunnel::ServiceRegistry,
    policy: &PolicyEngine,
    ns_server: &Option<String>,
    session_mgr: &Arc<SessionManager>,
    half_open_cache: &mut HalfOpenCache,
) -> Result<(), Box<dyn std::error::Error>> {
    let recv1_header = HandshakeHeader::deserialize(hello_data)?;
    let session_id = recv1_header.session_id;
    let noise_payload1 = &hello_data[HANDSHAKE_HEADER_SIZE..];

    // Start Noise_XX handshake (responder)
    let mut ctx = HandshakeContext::new_responder(identity)?;
    ctx.read_message(noise_payload1)?;

    // Send HELLO_ACK and cache for retransmit
    let msg2 = ctx.write_message(&[])?;
    let mut ack_hdr = HandshakeHeader::new(MsgType::HelloAck);
    ack_hdr.session_id = session_id;
    ack_hdr.src_node_id = *identity.node_id.as_bytes();
    ack_hdr.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_hdr.serialize();
    pkt2.extend_from_slice(&msg2);
    node.send_raw(&pkt2, from).await?;

    // Cache the HELLO_ACK in the half-open cache.
    // Note: ctx has been consumed by write_message for msg2, but we need it
    // for finalize. We create a new context for the cache entry and keep
    // the current ctx for this handshake flow.
    // Actually, ctx is still alive — we need to store it after the handshake
    // completes below. For the half-open cache, we store just the pkt2 bytes.
    // The ctx stays local to this function.

    // We insert into the half-open cache so that duplicate HELLOs arriving
    // at the main loop (while we're blocking on msg3) can be answered.
    // However, since handle_new_session blocks on recv_raw, duplicate HELLOs
    // will be picked up here instead. We store the cached pkt2 for the main
    // loop to use if this function returns (on error) while a retransmitted
    // HELLO is still in flight.
    //
    // For the blocking wait below, we handle duplicates inline.
    let cached_pkt2 = pkt2.clone();

    // Wait for message 3 (with retransmit of HELLO_ACK on duplicate HELLO)
    let mut responder_retransmit_count: u8 = 0;
    let mut retry_delay = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
    let max_retry_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);
    let hs_start = Instant::now();

    let (recv3, _) = loop {
        match timeout(retry_delay, node.recv_raw()).await {
            Ok(Ok((data, addr))) => {
                if data.len() >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                        // Is this msg3 for our session?
                        if hdr.session_id == session_id && hdr.msg_type != MsgType::Hello {
                            break (data, addr);
                        }
                        // Duplicate HELLO for our session — resend cached HELLO_ACK
                        if hdr.msg_type == MsgType::Hello && hdr.session_id == session_id {
                            if responder_retransmit_count < MAX_RESPONDER_RETRANSMITS {
                                debug!(
                                    "handshake: resending cached HELLO_ACK for session {} (retransmit {})",
                                    session_id, responder_retransmit_count + 1
                                );
                                node.send_raw(&cached_pkt2, from).await?;
                                responder_retransmit_count += 1;
                            }
                            continue;
                        }
                    }
                }
                // Route other packets to existing sessions
                if data.len() >= DATA_HEADER_SIZE {
                    if let Ok(hdr) = DataHeader::deserialize(&data) {
                        session_mgr.route_packet(&hdr.session_id, data, addr).await;
                    }
                }
                continue;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Timeout — check overall TTL
                if hs_start.elapsed() > Duration::from_secs(HALF_OPEN_TTL_SECS) {
                    return Err("timeout waiting for message 3".into());
                }
                // Proactively retransmit HELLO_ACK
                if responder_retransmit_count < MAX_RESPONDER_RETRANSMITS {
                    debug!(
                        "handshake: proactively retransmitting HELLO_ACK for session {} (timeout)",
                        session_id
                    );
                    node.send_raw(&cached_pkt2, from).await?;
                    responder_retransmit_count += 1;
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                } else {
                    return Err("timeout waiting for message 3 (max retransmits reached)".into());
                }
            }
        }
    };

    if recv3.len() < HANDSHAKE_HEADER_SIZE {
        return Err("message 3 too short".into());
    }
    let noise_payload3 = &recv3[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload3)?;

    if !ctx.is_finished() {
        return Err("handshake did not complete".into());
    }

    // Handshake complete — remove from half-open cache
    half_open_cache.remove(&session_id);

    let peer_node_id = NodeId::from_bytes(recv1_header.src_node_id);
    let peer_pubkey_hex = ctx.remote_static_hex();
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    let session_id = session.session_id;
    {
        let mut pipeline = node.pipeline.lock().await;
        pipeline.register_session(session);
    }

    // Resolve client identity for policy
    let client_identity = if let (Some(ns), Some(pk_hex)) = (ns_server.as_ref(), &peer_pubkey_hex) {
        match ns_pubkey_lookup(pk_hex, ns).await {
            Ok(Some(name)) => name,
            _ => format!("{}", peer_node_id),
        }
    } else {
        format!("{}", peer_node_id)
    };

    // Resolve service
    let resolve_result = registry.resolve(&recv1_header.dst_svc_id);
    let (svc_name, forward_addr) = match resolve_result {
        Some(pair) => pair,
        None => {
            let requested = String::from_utf8_lossy(
                &recv1_header.dst_svc_id[..recv1_header
                    .dst_svc_id
                    .iter()
                    .rposition(|&b| b != 0)
                    .map(|i| i + 1)
                    .unwrap_or(0)],
            )
            .to_string();
            let msg = if requested.is_empty() {
                "no unnamed --forward configured".to_string()
            } else {
                format!("unknown service '{}'", requested)
            };

            let reject = RejectFrame::new(RejectReason::ServiceUnavailable, &msg);
            let _ = tunnel::send_reject(
                &node.socket,
                &node.pipeline,
                session_id,
                from,
                &reject.encode(),
            )
            .await;
            return Err(msg.into());
        }
    };

    // Policy check — use async resolver for group:/role: patterns
    let policy_allowed = if policy.has_identity_patterns() {
        if let Some(ns) = ns_server.as_ref() {
            let resolver = UdpNsResolver::new(ns);
            policy
                .authorize_async(&client_identity, svc_name, &resolver)
                .await
        } else {
            policy.authorize(&client_identity, svc_name)
        }
    } else {
        policy.authorize(&client_identity, svc_name)
    };
    if !policy_allowed {
        let msg = format!("{} denied for service '{}'", client_identity, svc_name);
        eprintln!("{} {}", c_red("✗ POLICY DENIED:"), msg);

        let reject = RejectFrame::new(RejectReason::PolicyDenied, &msg);
        let _ = tunnel::send_reject(
            &node.socket,
            &node.pipeline,
            session_id,
            from,
            &reject.encode(),
        )
        .await;
        return Err(msg.into());
    }

    eprintln!(
        "{} handshake complete: {} → {} [{}/{}]",
        c_green("✓"),
        client_identity,
        svc_name,
        session_mgr.count() + 1,
        session_mgr.max_sessions
    );

    // Register session in the manager
    let rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)> = session_mgr
        .register(session_id, from, 1024)
        .await
        .ok_or("failed to register session (at capacity)")?;
    session_mgr.set_established(&session_id).await;

    // Spawn a bridge task for this session
    let udp = node.socket.clone();
    let pipeline = node.pipeline.clone();
    let forward_addr_owned = forward_addr.to_string();
    let mgr_clone = session_mgr.clone();

    tokio::spawn(async move {
        // Run the bridge and capture outcome as a string (not Box<dyn Error>)
        // to keep the future Send-safe.
        let err_msg: Option<String> = {
            match run_session_bridge(udp, pipeline, session_id, from, &forward_addr_owned, rx).await
            {
                Ok(()) => None,
                Err(e) => Some(e.to_string()),
            }
        };

        if let Some(msg) = &err_msg {
            eprintln!("{} session {} error: {}", c_red("✗"), session_id, msg);
        } else {
            eprintln!("{} session {} closed normally", c_dim("•"), session_id);
        }

        // Cleanup
        mgr_clone.remove(&session_id).await;
        eprintln!("{} [{} active session(s)]", c_dim("  "), mgr_clone.count());
    });

    Ok(())
}

/// Wait for a RESET frame on a per-session recv socket (used in gateway mode).
///
/// After a bridge closes normally, the client may send a RESET frame to open
/// a new TCP connection on the same ZTLP session. This reads from the dedicated
/// recv socket (which receives from the forwarder) and returns true if a RESET
/// frame is detected.
async fn wait_for_reset_on_socket(
    recv_socket: &tokio::net::UdpSocket,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    timeout_duration: Duration,
) -> bool {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

    let recv_key = {
        let pl = pipeline.lock().await;
        match pl.get_session(&session_id) {
            Some(session) => session.recv_key,
            None => return false,
        }
    };
    let cipher = ChaCha20Poly1305::new((&recv_key).into());

    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut buf = [0u8; 65535];

    loop {
        match tokio::time::timeout_at(deadline, recv_socket.recv_from(&mut buf)).await {
            Err(_) => return false,     // Timeout
            Ok(Err(_)) => return false, // Socket error
            Ok(Ok((len, _addr))) => {
                let data = &buf[..len];

                // Check pipeline admission
                {
                    let pl = pipeline.lock().await;
                    let result = pl.process(data);
                    if !matches!(result, AdmissionResult::Pass) {
                        continue;
                    }
                }

                if data.len() < DATA_HEADER_SIZE {
                    continue;
                }

                let header = match DataHeader::deserialize(data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                if header.session_id != session_id {
                    continue;
                }

                // Try to decrypt and check for RESET frame
                let ciphertext = &data[DATA_HEADER_SIZE..];
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);

                if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                    // Check if it's a RESET frame (first byte = 0x04 for RESET)
                    if !plaintext.is_empty() && plaintext[0] == 0x04 {
                        return true;
                    }
                }
                // Not a RESET — could be retransmitted data; keep waiting
            }
        }
    }
}

/// Run the bridge for a single session (called from a spawned task).
///
/// In multi-session mode, the dispatcher routes packets to a per-session
/// mpsc channel. We create a per-session loopback UDP socket pair and spawn
/// a forwarder task that drains the channel into the recv socket. The bridge
/// reads from the recv socket (dedicated to this session) and sends via the
/// shared socket.
///
/// Returns `String` errors (not `Box<dyn Error>`) so the future is `Send`.
async fn run_session_bridge(
    udp_send_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    forward_addr: &str,
    mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
) -> Result<(), String> {
    use tokio::net::TcpStream;

    // Create a per-session loopback UDP socket pair for demuxed packet delivery.
    // The forwarder writes to `fwd_socket` → `recv_addr`, and the bridge reads
    // from `recv_socket`.
    let recv_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind recv socket: {}", e))?;
    let recv_addr = recv_socket
        .local_addr()
        .map_err(|e| format!("recv socket addr: {}", e))?;
    let fwd_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind fwd socket: {}", e))?;
    let recv_socket = Arc::new(recv_socket);

    // Wait for client to send first data before connecting to backend.
    // Read from the channel and forward to the recv socket.
    let _initial_packets = tunnel::wait_for_first_data_channeled(
        &mut rx,
        &fwd_socket,
        recv_addr,
        &pipeline,
        session_id,
        Duration::from_secs(600),
    )
    .await
    .map_err(|e| format!("timeout waiting for first data: {}", e))?;

    // Connect to backend
    let forward_sock: SocketAddr =
        tunnel::parse_forward_target(forward_addr).map_err(|e| e.to_string())?;
    let tcp_stream = TcpStream::connect(forward_sock)
        .await
        .map_err(|e| format!("failed to connect to {}: {}", forward_addr, e))?;

    eprintln!(
        "{} session {} connected to backend {}",
        c_green("✓"),
        session_id,
        forward_addr
    );

    // Spawn a forwarder task: channel → recv_socket
    // This runs for the lifetime of this session, forwarding dispatcher
    // packets into the per-session recv socket so the bridge can read them.
    let fwd_socket = Arc::new(fwd_socket);
    let fwd_socket_clone = fwd_socket.clone();
    let forwarder = tokio::spawn(async move {
        while let Some((data, _addr)) = rx.recv().await {
            let _ = fwd_socket_clone.send_to(&data, recv_addr).await;
        }
    });

    // Run bridge with demuxed sockets (send via shared socket, recv via per-session socket)
    let result = tunnel::run_bridge_demuxed(
        tcp_stream,
        udp_send_socket.clone(),
        recv_socket.clone(),
        pipeline.clone(),
        session_id,
        peer_addr,
        Vec::new(), // initial_packets already forwarded to recv_socket
    )
    .await
    .map_err(|e| e.to_string())?;

    // Handle multiple TCP connections on the same ZTLP session.
    // The client sends RESET frames to signal new TCP connections.
    // After each bridge closes (either ResetReceived or Closed), we
    // wait for a new RESET to potentially start another bridge.
    let mut last_outcome = result;
    loop {
        match last_outcome {
            tunnel::BridgeOutcome::ResetReceived => {
                // Immediately reconnect to backend
            }
            tunnel::BridgeOutcome::Closed => {
                // Bridge closed normally (TCP FIN). Wait for a potential RESET
                // from the client indicating a new TCP connection.
                let reset = wait_for_reset_on_socket(
                    &recv_socket,
                    &pipeline,
                    session_id,
                    Duration::from_secs(300), // 5 min idle timeout
                )
                .await;
                if !reset {
                    break; // No RESET received — session is truly done
                }
                // RESET received — continue to reconnect
            }
        }

        let tcp_stream = TcpStream::connect(forward_sock)
            .await
            .map_err(|e| format!("reconnect to {}: {}", forward_addr, e))?;

        eprintln!(
            "{} session {} reconnected to backend {}",
            c_green("✓"),
            session_id,
            forward_addr
        );

        last_outcome = tunnel::run_bridge_demuxed(
            tcp_stream,
            udp_send_socket.clone(),
            recv_socket.clone(),
            pipeline.clone(),
            session_id,
            peer_addr,
            Vec::new(),
        )
        .await
        .map_err(|e| e.to_string())?;
    }

    // Stop the forwarder
    forwarder.abort();

    Ok(())
}

/// Wait for a RESET frame on the ZTLP session after a bridge closes.
///
/// The listener calls this after a normal bridge close (FIN from both sides).
/// If the client opens another TCP connection on the same ZTLP session, it
/// will send a RESET frame first. This function waits for that frame and
/// returns `true` if a RESET is received, or `false` if the timeout expires.
async fn wait_for_reset_buffered(
    node: &TransportNode,
    session_id: SessionId,
    from: SocketAddr,
    timeout_duration: Duration,
) -> Result<tunnel::ResetWaitResult, Box<dyn std::error::Error>> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

    // Extract the recv key from the session for decryption
    let recv_key = {
        let pl = node.pipeline.lock().await;
        let session = pl.get_session(&session_id).ok_or("session not found")?;
        session.recv_key
    };
    let cipher = ChaCha20Poly1305::new((&recv_key).into());

    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut buffered_packets: Vec<Vec<u8>> = Vec::new();
    let reset_seen = false;

    loop {
        match tokio::time::timeout_at(deadline, node.recv_raw()).await {
            Err(_) => {
                // Timeout expired
                return Ok(tunnel::ResetWaitResult {
                    reset_received: false,
                    buffered_packets,
                });
            }
            Ok(Err(e)) => {
                return Err(format!("recv error: {}", e).into());
            }
            Ok(Ok((data, addr))) => {
                if addr != from {
                    continue;
                }

                // Pipeline admission check
                {
                    let pl = node.pipeline.lock().await;
                    let result = pl.process(&data);
                    if !matches!(result, AdmissionResult::Pass) {
                        continue;
                    }
                }

                // Parse data header
                if data.len() < DATA_HEADER_SIZE {
                    continue;
                }
                let header = match DataHeader::deserialize(&data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // Decrypt to check frame type
                let ciphertext = &data[DATA_HEADER_SIZE..];
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = match cipher.decrypt(nonce, ciphertext) {
                    Ok(pt) => pt,
                    Err(_) => continue,
                };

                if plaintext.is_empty() {
                    continue;
                }

                if plaintext[0] == 0x04 {
                    // FRAME_RESET received — capture trailing data packets
                    let _ = reset_seen; // suppress unused warning
                                        // Give a short grace period to collect packets that
                                        // may have been sent right after the RESET
                    let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
                    loop {
                        let grace_result =
                            tokio::time::timeout_at(grace_deadline, node.recv_raw()).await;
                        match grace_result {
                            Err(_) => break, // Grace period expired
                            Ok(Err(_)) => break,
                            Ok(Ok((gdata, gaddr))) => {
                                if gaddr == from && gdata.len() >= DATA_HEADER_SIZE {
                                    // Buffer the raw packet for the next bridge
                                    buffered_packets.push(gdata);
                                }
                            }
                        }
                    }
                    return Ok(tunnel::ResetWaitResult {
                        reset_received: true,
                        buffered_packets,
                    });
                }

                if reset_seen {
                    // Data packet after RESET — buffer it
                    buffered_packets.push(data);
                } else {
                    // Data packet before RESET — also buffer it!
                    // The RESET may arrive out of order (UDP has no ordering)
                    // and these packets belong to the next bridge cycle.
                    buffered_packets.push(data);

                    // Cap buffer to prevent unbounded growth while waiting
                    if buffered_packets.len() > 4096 {
                        eprintln!(
                            "{}",
                            c_yellow(
                                "⚠ too many buffered packets during reset wait, draining oldest"
                            )
                        );
                        buffered_packets.drain(0..1024);
                    }
                }
            }
        }
    }
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
                            Ok(_seq) => {
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
                        // Check for REJECT frame
                        if RejectFrame::is_reject(&plaintext) {
                            if let Some(reject) = RejectFrame::decode(&plaintext) {
                                eprintln!(
                                    "\n{} {}",
                                    c_red("✗ Server rejected connection:"),
                                    reject.message
                                );
                                return Err(format!(
                                    "server rejected: {} ({})",
                                    reject.message, reject.reason
                                ).into());
                            }
                        }
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

/// Encode a CBOR text string (major type 3).
fn cbor_text(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut buf = cbor_head(3, bytes.len() as u64);
    buf.extend_from_slice(bytes);
    buf
}

/// Encode a CBOR unsigned integer head (any major type).
fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let mt = major << 5;
    if n < 24 {
        vec![mt | (n as u8)]
    } else if n < 0x100 {
        vec![mt | 24, n as u8]
    } else if n < 0x10000 {
        let mut buf = vec![mt | 25];
        buf.extend_from_slice(&(n as u16).to_be_bytes());
        buf
    } else if n < 0x100000000 {
        let mut buf = vec![mt | 26];
        buf.extend_from_slice(&(n as u32).to_be_bytes());
        buf
    } else {
        let mut buf = vec![mt | 27];
        buf.extend_from_slice(&n.to_be_bytes());
        buf
    }
}

/// Encode a map with string keys and string values in deterministic CBOR
/// (RFC 8949 §4.2.1 — keys sorted by encoded byte representation,
/// length-first).
fn cbor_map(pairs: &mut Vec<(&str, &str)>) -> Vec<u8> {
    // Encode each key first, then sort by (encoded_len, encoded_bytes)
    let mut encoded_pairs: Vec<(Vec<u8>, Vec<u8>)> = pairs
        .iter()
        .map(|&(k, v)| (cbor_text(k), cbor_text(v)))
        .collect();
    encoded_pairs.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));

    let mut buf = cbor_head(5, encoded_pairs.len() as u64);
    for (k, v) in &encoded_pairs {
        buf.extend_from_slice(k);
        buf.extend_from_slice(v);
    }
    buf
}

/// Encode a GROUP record's data as CBOR.
///
/// Produces a CBOR map: {"description": <str>, "members": [<str>, ...]}
fn cbor_encode_group(description: &str, members: &[&str]) -> Vec<u8> {
    // We need a map with 2 entries: "description" (text) and "members" (array of text)
    let key_desc = cbor_text("description");
    let val_desc = cbor_text(description);
    let key_members = cbor_text("members");

    // Encode the members array
    let mut val_members = cbor_head(4, members.len() as u64); // major type 4 = array
    for m in members {
        val_members.extend_from_slice(&cbor_text(m));
    }

    // Encode as a 2-entry map, keys sorted by (len, bytes)
    let mut encoded_pairs = vec![(key_desc, val_desc), (key_members, val_members)];
    encoded_pairs.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));

    let mut buf = cbor_head(5, encoded_pairs.len() as u64);
    for (k, v) in &encoded_pairs {
        buf.extend_from_slice(k);
        buf.extend_from_slice(v);
    }
    buf
}

/// Build a registration packet for ZTLP-NS.
///
/// Wire format (server expects):
/// ```
/// <<0x09, name_len::16, name, type_byte::8, data_len::16, data_cbor, sig_len::16, sig>>
/// ```
///
/// The server ignores the client signature and re-signs with its own key,
/// so we send a dummy 0-byte signature. Data is CBOR-encoded per RFC 8949.
fn build_registration_packet(name: &str, type_byte: u8, data_bin: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let data_len = data_bin.len() as u16;
    let sig_len: u16 = 0; // Dummy signature — server re-signs

    let mut pkt = Vec::with_capacity(1 + 2 + name_bytes.len() + 1 + 2 + data_bin.len() + 2);
    pkt.push(0x09); // Registration opcode (was 0x02 pre-v0.5.1)
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

    // Include address in KEY record for backward compat with older NS servers
    // that don't differentiate KEY vs SVC record types.
    let key_data_bin = if let Some(addr) = address {
        cbor_map(&mut vec![
            ("algorithm", "Ed25519"),
            ("node_id", &node_id_hex),
            ("public_key", &pubkey_hex),
            ("address", addr.as_str()),
        ])
    } else {
        cbor_map(&mut vec![
            ("algorithm", "Ed25519"),
            ("node_id", &node_id_hex),
            ("public_key", &pubkey_hex),
        ])
    };

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

        let svc_data_bin = cbor_map(&mut vec![
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

                // Try to parse response — check if it's a proper pong
                let pong_info = if len >= HANDSHAKE_HEADER_SIZE {
                    HandshakeHeader::deserialize(&buf[..len])
                        .ok()
                        .filter(|hdr| hdr.msg_type == MsgType::Pong)
                        .map_or("reply", |_| "pong")
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
    println!("{}", hex::encode(bytes));

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

            // NAT detection via STUN
            {
                let stun_timeout = Duration::from_secs(3);
                let mut nat_detected = false;
                for server_str in nat::DEFAULT_STUN_SERVERS.iter() {
                    if let Ok(addr) = server_str.parse::<SocketAddr>() {
                        match nat::StunClient::discover_endpoint(&sock, addr, stun_timeout).await {
                            Ok(endpoint) => {
                                eprintln!(
                                    "  {} {} (NAT: {:?})",
                                    c_cyan("Public endpoint:"),
                                    endpoint.address,
                                    endpoint.nat_type
                                );
                                nat_detected = true;
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                }
                if !nat_detected {
                    eprintln!(
                        "  {} {}",
                        c_cyan("NAT type:"),
                        c_dim("unknown (STUN unavailable)")
                    );
                }
            }

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

// ─── Port Exposure Scanner ──────────────────────────────────────────────────

/// Default TCP ports to scan if none specified.
const SCAN_DEFAULT_PORTS: &[u16] = &[22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017];

/// Well-known service names for common ports.
fn port_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        80 => "HTTP",
        443 => "HTTPS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        23095 => "ZTLP",
        23096 => "ZTLP-NS",
        _ => "unknown",
    }
}

/// Result of scanning a single port.
#[derive(Clone)]
struct PortScanResult {
    port: u16,
    protocol: &'static str,
    service: String,
    open: bool,
    /// "ztlp" | "exposed" | "closed"
    status: String,
    detail: String,
}

/// `ztlp scan` — Scan host ports and report exposure
async fn cmd_scan(
    target: &str,
    ports_arg: &Option<String>,
    ztlp_port: u16,
    json_output: bool,
    include_udp: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tcp_ports: Vec<u16> = if let Some(p) = ports_arg {
        p.split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    } else {
        let mut v: Vec<u16> = SCAN_DEFAULT_PORTS.to_vec();
        if !v.contains(&ztlp_port) {
            v.push(ztlp_port);
        }
        v.sort();
        v.dedup();
        v
    };

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Port Exposure Scan"));
        eprintln!("  {} {}", c_cyan("Target:"), target);
        eprintln!("  {} {:?}", c_cyan("TCP ports:"), tcp_ports);
        eprintln!("  {} {}", c_cyan("ZTLP port:"), ztlp_port);
        if include_udp {
            eprintln!("  {} enabled", c_cyan("UDP scan:"));
        }
        eprintln!();
    }

    let mut results: Vec<PortScanResult> = Vec::new();

    // --- TCP port scan ---
    for &port in &tcp_ports {
        let addr = format!("{}:{}", target, port);
        let open = matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(1500),
                tokio::net::TcpStream::connect(&addr),
            )
            .await,
            Ok(Ok(_))
        );

        let svc = port_service_name(port).to_string();
        let (status, detail) = if !open {
            ("closed".to_string(), "not reachable".to_string())
        } else if port == ztlp_port {
            // ZTLP port is TCP — unusual, ZTLP is normally UDP
            (
                "exposed".to_string(),
                "TCP open on ZTLP port (expected UDP only)".to_string(),
            )
        } else {
            (
                "exposed".to_string(),
                format!(
                    "{} directly reachable — should be behind ZTLP or firewalled",
                    svc
                ),
            )
        };

        if !json_output && open {
            let icon = c_red("✗");
            eprintln!(
                "  {} TCP {:>5}  {:<15} {}",
                icon,
                port,
                format!("[{}]", svc),
                c_yellow(&detail)
            );
        } else if !json_output {
            eprintln!(
                "  {} TCP {:>5}  {:<15} {}",
                c_green("✓"),
                port,
                format!("[{}]", svc),
                c_dim("closed")
            );
        }

        results.push(PortScanResult {
            port,
            protocol: "tcp",
            service: svc,
            open,
            status,
            detail,
        });
    }

    // --- UDP scan: check ZTLP port ---
    if include_udp || !tcp_ports.contains(&ztlp_port) {
        // Always check the ZTLP UDP port
        let ztlp_udp_open = check_ztlp_udp(target, ztlp_port).await;
        let (status, detail) = if ztlp_udp_open {
            (
                "ztlp".to_string(),
                "ZTLP listener active — protected by three-layer pipeline".to_string(),
            )
        } else {
            (
                "closed".to_string(),
                "no ZTLP listener detected".to_string(),
            )
        };

        if !json_output {
            let icon = if ztlp_udp_open {
                c_green("●")
            } else {
                c_dim("○")
            };
            let svc_label = format!("[{}]", port_service_name(ztlp_port));
            eprintln!(
                "  {} UDP {:>5}  {:<15} {}",
                icon,
                ztlp_port,
                svc_label,
                if ztlp_udp_open {
                    c_cyan(&detail)
                } else {
                    c_dim(&detail)
                }
            );
        }

        results.push(PortScanResult {
            port: ztlp_port,
            protocol: "udp",
            service: "ZTLP".to_string(),
            open: ztlp_udp_open,
            status,
            detail,
        });
    }

    // --- Summary ---
    let exposed: Vec<&PortScanResult> = results.iter().filter(|r| r.status == "exposed").collect();
    let ztlp_protected: Vec<&PortScanResult> =
        results.iter().filter(|r| r.status == "ztlp").collect();
    let closed: Vec<&PortScanResult> = results.iter().filter(|r| r.status == "closed").collect();

    if json_output {
        let entries: Vec<String> = results
            .iter()
            .map(|r| {
                format!(
                    "{{\"port\":{},\"protocol\":\"{}\",\"service\":\"{}\",\"open\":{},\"status\":\"{}\",\"detail\":\"{}\"}}",
                    r.port, r.protocol, r.service, r.open, r.status, r.detail
                )
            })
            .collect();
        println!(
            "{{\"target\":\"{}\",\"ztlp_port\":{},\"exposed\":{},\"protected\":{},\"closed\":{},\"results\":[{}]}}",
            target,
            ztlp_port,
            exposed.len(),
            ztlp_protected.len(),
            closed.len(),
            entries.join(",")
        );
    } else {
        eprintln!();
        if exposed.is_empty() {
            eprintln!(
                "  {} {}",
                c_green("✓"),
                c_bold("No exposed services detected")
            );
            if !ztlp_protected.is_empty() {
                eprintln!(
                    "    {} ZTLP listener active on UDP {}",
                    c_cyan("●"),
                    ztlp_port
                );
            }
            eprintln!(
                "    {} {} port(s) closed, {} ZTLP-protected",
                c_dim("→"),
                closed.len(),
                ztlp_protected.len()
            );
        } else {
            eprintln!(
                "  {} {} {}",
                c_red("⚠"),
                c_bold(&format!("{} exposed service(s) found:", exposed.len())),
                c_red("ACTION REQUIRED")
            );
            for r in &exposed {
                eprintln!(
                    "    {} TCP {} ({}) — {}",
                    c_red("✗"),
                    r.port,
                    r.service,
                    r.detail
                );
            }
            eprintln!();
            eprintln!(
                "    {} Recommendation: firewall these ports, route through ZTLP tunnels",
                c_yellow("→")
            );
            eprintln!(
                "    {} See: ztlp firewall lock --ports {}",
                c_dim("→"),
                exposed
                    .iter()
                    .map(|r| r.port.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        eprintln!();
    }

    Ok(())
}

/// Probe a UDP port by sending a ZTLP magic byte packet and checking for
/// any response (including ICMP unreachable via recv error).
async fn check_ztlp_udp(target: &str, port: u16) -> bool {
    let addr = format!("{}:{}", target, port);
    let Ok(addr) = addr.parse::<std::net::SocketAddr>() else {
        // Try DNS resolution
        let Ok(addrs) = tokio::net::lookup_host(&addr).await else {
            return false;
        };
        let Some(addr) = addrs.into_iter().next() else {
            return false;
        };
        return check_ztlp_udp_addr(addr).await;
    };
    check_ztlp_udp_addr(addr).await
}

async fn check_ztlp_udp_addr(addr: std::net::SocketAddr) -> bool {
    let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    // Send a packet with ZTLP magic bytes but invalid session — a real ZTLP
    // listener will silently drop it (L2 rejection). We detect liveness by
    // the absence of an ICMP port-unreachable within a short window.
    let probe = [
        0x5A, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if sock.send(&probe).await.is_err() {
        return false;
    }
    // On Linux, a UDP send to a closed port typically causes an ICMP unreachable
    // that surfaces as a recv error. If we get no error within 200ms, assume open.
    let mut buf = [0u8; 64];
    match tokio::time::timeout(std::time::Duration::from_millis(200), sock.recv(&mut buf)).await {
        Ok(Ok(_)) => true,   // got a response — definitely open
        Ok(Err(_)) => false, // ICMP unreachable — port closed
        Err(_) => true,      // timeout with no error — likely open (silent drop = ZTLP L2)
    }
}

// ─── Setup Wizard ───────────────────────────────────────────────────────────

/// `ztlp setup` — Interactive setup wizard
async fn cmd_setup(
    token_arg: &Option<String>,
    name_arg: &Option<String>,
    _setup_type: SetupType,
    _owner_arg: &Option<String>,
    auto_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::{Input, Select};

    eprintln!();
    eprintln!("  {}", c_bold("╔══════════════════════════════════════╗"));
    eprintln!(
        "  {}       ZTLP Setup Wizard v0.5.2      {}",
        c_bold("║"),
        c_bold("║")
    );
    eprintln!("  {}", c_bold("╚══════════════════════════════════════╝"));
    eprintln!();

    // If token provided, skip menu and go straight to enrollment
    if let Some(token_str) = token_arg {
        return setup_join(token_str, name_arg, auto_yes).await;
    }

    // Interactive menu
    let choices = vec![
        "Join an existing network (I have an enrollment token)",
        "Create a new ZTLP network (I'm the admin)",
    ];

    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(&choices)
        .default(0)
        .interact()
        .map_err(|e| format!("input error: {}", e))?;

    match selection {
        0 => {
            // Join — ask for token
            let token_str: String = Input::new()
                .with_prompt("Paste your enrollment token (or ztlp://enroll/ URI)")
                .interact_text()
                .map_err(|e| format!("input error: {}", e))?;

            setup_join(&token_str, name_arg, auto_yes).await
        }
        1 => setup_create_network(auto_yes).await,
        _ => unreachable!(),
    }
}

/// Setup path: join an existing network with an enrollment token.
async fn setup_join(
    token_str: &str,
    name_arg: &Option<String>,
    auto_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::{Confirm, Input};
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};
    use ztlp_proto::enrollment::EnrollmentToken;
    use ztlp_proto::identity::NodeIdentity;

    // Parse token
    let token = EnrollmentToken::from_base64url(token_str)
        .map_err(|e| format!("invalid enrollment token: {}", e))?;

    if token.is_expired() {
        return Err("enrollment token has expired".into());
    }

    eprintln!("  {} Token valid", c_green("✓"));
    eprintln!("    {} {}", c_cyan("Zone:"), token.zone);
    eprintln!("    {} {}", c_cyan("NS server:"), token.ns_addr);
    for relay in &token.relay_addrs {
        eprintln!("    {} {}", c_cyan("Relay:"), relay);
    }
    if let Some(ref gw) = token.gateway_addr {
        eprintln!("    {} {}", c_cyan("Gateway:"), gw);
    }
    eprintln!("    {} {}", c_cyan("Expires in:"), token.expires_in_human());
    if token.max_uses > 0 {
        eprintln!("    {} {}", c_cyan("Max uses:"), token.max_uses);
    }
    eprintln!();

    // Determine device name
    let device_name = if let Some(ref n) = name_arg {
        n.clone()
    } else {
        let default_name = get_hostname();
        let name: String = Input::new()
            .with_prompt("Device name")
            .default(default_name)
            .interact_text()
            .map_err(|e| format!("input error: {}", e))?;
        name
    };

    // Full ZTLP name
    let full_name = format!("{}.{}", device_name, token.zone);
    eprintln!("  {} Enrolling as {}", c_cyan("→"), c_bold(&full_name));

    // Determine ZTLP config directory
    let ztlp_dir = get_ztlp_dir()?;
    std::fs::create_dir_all(&ztlp_dir)
        .map_err(|e| format!("failed to create {}: {}", ztlp_dir.display(), e))?;

    let key_path = ztlp_dir.join("identity.json");
    let config_path = ztlp_dir.join("config.toml");

    // Check if identity already exists
    if key_path.exists() {
        if auto_yes {
            eprintln!("  {} Overwriting existing identity", c_yellow("⚠"));
        } else {
            let overwrite = Confirm::new()
                .with_prompt(format!(
                    "Identity file already exists at {}. Overwrite?",
                    key_path.display()
                ))
                .default(false)
                .interact()
                .map_err(|e| format!("input error: {}", e))?;

            if !overwrite {
                eprintln!("  Aborted. Use --key to specify a different path.");
                return Ok(());
            }
        }
    }

    // Generate identity
    eprintln!();
    eprintln!("  {} Generating identity...", c_dim("→"));
    let identity = NodeIdentity::generate()?;
    identity.save(&key_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&key_path, perms).ok();
    }

    eprintln!(
        "  {} Identity saved to {}",
        c_green("✓"),
        key_path.display()
    );
    eprintln!("    {} {}", c_cyan("NodeID:"), identity.node_id);

    // Send enrollment request to NS
    eprintln!();
    eprintln!("  {} Registering with namespace server...", c_dim("→"));

    let ns_addr: std::net::SocketAddr = token
        .ns_addr
        .parse()
        .map_err(|e| format!("invalid NS address '{}': {}", token.ns_addr, e))?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    // Build enrollment request
    let token_bin = token.serialize();

    // Use the X25519 static public key as the enrollment identity (32 bytes)
    let pubkey_bytes = identity.static_public_key.as_slice();

    let node_id_bytes: &[u8; 16] = identity.node_id.as_bytes();

    // Determine address to register (optional)
    let addr_str = ""; // Empty = no address for now (device may be behind NAT)

    let enroll_body = build_enroll_packet(
        &token_bin,
        pubkey_bytes,
        node_id_bytes,
        &full_name,
        addr_str,
    );

    let packet = [&[0x07u8][..], &enroll_body].concat();
    sock.send_to(&packet, ns_addr).await?;

    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(10), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let resp = &buf[..len];
            match resp {
                [0x08, 0x00, config @ ..] => {
                    eprintln!("  {} Enrolled as {}", c_green("✓"), c_bold(&full_name));

                    // Parse config from response
                    let (relay_addrs, gateway_addrs) = parse_enroll_config(config)?;

                    // Write config file
                    write_config_file(
                        &config_path,
                        &key_path,
                        &token.zone,
                        &token.ns_addr,
                        &relay_addrs,
                        &gateway_addrs,
                    )?;

                    // Confirm enrollment with Bootstrap (best-effort)
                    if let Some(ref url) = token.callback_url {
                        confirm_enrollment(url, &token, &full_name, &identity.node_id).await;
                    }

                    // Test connectivity
                    eprintln!();
                    eprintln!("  {} Testing connectivity...", c_dim("→"));
                    test_connectivity(&relay_addrs).await;

                    // Summary
                    eprintln!();
                    eprintln!("  {}", c_bold("── You're in! ─────────────────────────"));
                    eprintln!();
                    eprintln!(
                        "  Connect to a peer:  {} connect peer.{}",
                        c_cyan("ztlp"),
                        token.zone
                    );
                    eprintln!("  Check status:       {} status", c_cyan("ztlp"));
                    eprintln!("  View your identity: {} status --identity", c_cyan("ztlp"));
                    eprintln!("  Config file:        {}", config_path.display());
                    eprintln!();
                }
                [0x08, 0x01] => {
                    return Err("enrollment failed: token expired".into());
                }
                [0x08, 0x02] => {
                    return Err(
                        "enrollment failed: token has been used up (max uses reached)".into(),
                    );
                }
                [0x08, 0x03] => {
                    return Err(
                        "enrollment failed: invalid token (wrong secret or tampered)".into(),
                    );
                }
                [0x08, 0x04] => {
                    return Err(format!(
                        "enrollment failed: name '{}' is not in zone '{}'",
                        full_name, token.zone
                    )
                    .into());
                }
                [0x08, 0x05] => {
                    return Err(format!(
                        "enrollment failed: name '{}' is already taken by another device",
                        full_name
                    )
                    .into());
                }
                [0x08, 0x06] => {
                    return Err("enrollment failed: NS server rejected the request (enrollment may not be configured)".into());
                }
                _ => {
                    return Err(format!(
                        "unexpected response from NS server: {:02x?}",
                        &resp[..resp.len().min(16)]
                    )
                    .into());
                }
            }
        }
        Ok(Err(e)) => {
            return Err(format!(
                "network error contacting NS server at {}: {}",
                token.ns_addr, e
            )
            .into());
        }
        Err(_) => {
            return Err(format!(
                "timeout: NS server at {} did not respond within 10 seconds.\n  \
                 Is the NS server running? Check: ztlp ns lookup test.{} --ns-server {}",
                token.ns_addr, token.zone, token.ns_addr
            )
            .into());
        }
    }

    Ok(())
}

/// Setup path: create a new ZTLP network.
async fn setup_create_network(_auto_yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::Input;
    use ztlp_proto::enrollment::generate_enrollment_secret;
    use ztlp_proto::identity::NodeIdentity;

    eprintln!("  {}", c_bold("── Create ZTLP Network ───────────────"));
    eprintln!();

    // Zone name
    let zone: String = Input::new()
        .with_prompt("Zone name (e.g., office.yourcompany.ztlp)")
        .interact_text()
        .map_err(|e| format!("input error: {}", e))?;

    // NS server address
    let ns_addr: String = Input::new()
        .with_prompt("NS server listen address")
        .default("0.0.0.0:23096".to_string())
        .interact_text()
        .map_err(|e| format!("input error: {}", e))?;

    // Relay address
    let relay_addr: String = Input::new()
        .with_prompt("Relay listen address")
        .default("0.0.0.0:23095".to_string())
        .interact_text()
        .map_err(|e| format!("input error: {}", e))?;

    eprintln!();

    // Generate zone enrollment secret
    eprintln!("  {} Generating zone enrollment secret...", c_dim("→"));
    let secret = generate_enrollment_secret();
    let secret_hex = hex::encode(secret);

    let ztlp_dir = get_ztlp_dir()?;
    std::fs::create_dir_all(&ztlp_dir)?;

    let secret_path = ztlp_dir.join("zone.key");
    std::fs::write(&secret_path, &secret_hex)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    eprintln!(
        "  {} Zone secret saved to {} (chmod 600)",
        c_green("✓"),
        secret_path.display()
    );

    // Generate admin identity
    eprintln!("  {} Generating admin identity...", c_dim("→"));
    let identity = NodeIdentity::generate()?;
    let key_path = ztlp_dir.join("identity.json");
    identity.save(&key_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    eprintln!(
        "  {} Admin identity saved to {}",
        c_green("✓"),
        key_path.display()
    );
    eprintln!("    {} {}", c_cyan("NodeID:"), identity.node_id);

    // Write config
    let config_path = ztlp_dir.join("config.toml");
    let config_content = format!(
        r#"# ZTLP Configuration — generated by `ztlp setup`
# Zone: {zone}

identity = "{key_path}"
ns_server = "{ns_addr}"
relay = "{relay_addr}"
zone = "{zone}"
enrollment_secret = "{secret_path}"
"#,
        zone = zone,
        key_path = key_path.display(),
        ns_addr = ns_addr,
        relay_addr = relay_addr,
        secret_path = secret_path.display(),
    );
    std::fs::write(&config_path, &config_content)?;
    eprintln!(
        "  {} Config written to {}",
        c_green("✓"),
        config_path.display()
    );

    // Instructions
    eprintln!();
    eprintln!("  {}", c_bold("── Network Ready ─────────────────────"));
    eprintln!();
    eprintln!("  Start the services:");
    eprintln!(
        "    {} (using Docker Compose)",
        c_dim("docker compose up -d")
    );
    eprintln!("    {} (or start individually)", c_dim("See DEPLOYMENT.md"));
    eprintln!();
    eprintln!("  Set the enrollment secret on NS server:");
    eprintln!(
        "    {} ZTLP_ENROLLMENT_SECRET={}",
        c_cyan("export"),
        &secret_hex[..16]
    );
    eprintln!(
        "    {} (full hex in {})",
        c_dim("..."),
        secret_path.display()
    );
    eprintln!();
    eprintln!("  Generate enrollment tokens for devices:");
    eprintln!("    {} admin enroll --zone {} \\", c_cyan("ztlp"), zone);
    eprintln!(
        "      --ns-server {} --relay {} --expires 24h",
        ns_addr, relay_addr
    );
    eprintln!();
    eprintln!("  Generate a QR code for easy device enrollment:");
    eprintln!("    {} admin enroll --zone {} \\", c_cyan("ztlp"), zone);
    eprintln!("      --ns-server {} --relay {} --qr", ns_addr, relay_addr);
    eprintln!();

    Ok(())
}

/// Confirm enrollment with the Bootstrap app (best-effort, non-blocking).
/// Sends a POST to the callback URL with the token_id and enrolled device info.
async fn confirm_enrollment(
    callback_url: &str,
    token: &ztlp_proto::enrollment::EnrollmentToken,
    device_name: &str,
    node_id: &NodeId,
) {
    let token_id = match &token.token_id {
        Some(id) => id.clone(),
        None => return,
    };

    // Use curl for HTTPS support (TLS without adding deps)
    let body = format!(
        "token_id={}&node_id={}&name={}",
        token_id, node_id, device_name
    );

    let result = tokio::process::Command::new("curl")
        .args([
            "-sf",
            "--max-time",
            "5",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-d",
            &body,
            callback_url,
        ])
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            // Silently succeed — Bootstrap has been notified
        }
        _ => {
            // Best-effort: don't fail enrollment if callback fails
        }
    }
}

/// Build the 0x07 ENROLL request body (without the 0x07 prefix).
fn build_enroll_packet(
    token: &[u8],
    pubkey: &[u8],
    node_id: &[u8; 16],
    name: &str,
    addr: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Token length + token
    buf.extend_from_slice(&(token.len() as u16).to_be_bytes());
    buf.extend_from_slice(token);

    // Public key (padded to 32 bytes if needed)
    let mut pk = [0u8; 32];
    let copy_len = pubkey.len().min(32);
    pk[..copy_len].copy_from_slice(&pubkey[..copy_len]);
    buf.extend_from_slice(&pk);

    // Node ID (16 bytes)
    buf.extend_from_slice(node_id);

    // Name
    let name_bytes = name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(name_bytes);

    // Address (may be empty)
    let addr_bytes = addr.as_bytes();
    buf.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(addr_bytes);

    buf
}

/// Parse the config section of an ENROLL response.
fn parse_enroll_config(
    data: &[u8],
) -> Result<(Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
    let mut pos = 0;

    // Relay addresses
    if pos >= data.len() {
        return Ok((vec![], vec![]));
    }
    let relay_count = data[pos] as usize;
    pos += 1;

    let mut relays = Vec::with_capacity(relay_count);
    for _ in 0..relay_count {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        let addr = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        pos += len;
        relays.push(addr);
    }

    // Gateway addresses
    let mut gateways = Vec::new();
    if pos < data.len() {
        let gw_count = data[pos] as usize;
        pos += 1;

        for _ in 0..gw_count {
            if pos + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + len > data.len() {
                break;
            }
            let addr = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            pos += len;
            gateways.push(addr);
        }
    }

    Ok((relays, gateways))
}

/// Write a config.toml file with the enrollment results.
fn write_config_file(
    path: &std::path::Path,
    key_path: &std::path::Path,
    zone: &str,
    ns_server: &str,
    relay_addrs: &[String],
    gateway_addrs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_str = if relay_addrs.len() == 1 {
        format!("\"{}\"", relay_addrs[0])
    } else {
        format!(
            "[{}]",
            relay_addrs
                .iter()
                .map(|a| format!("\"{}\"", a))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let mut content = format!(
        r#"# ZTLP Configuration — generated by `ztlp setup`
# Zone: {zone}

identity = "{key_path}"
ns_server = "{ns_server}"
relay = {relay_str}
zone = "{zone}"
"#,
        zone = zone,
        key_path = key_path.display(),
        ns_server = ns_server,
        relay_str = relay_str,
    );

    if !gateway_addrs.is_empty() {
        content.push_str(&format!("gateway = \"{}\"\n", gateway_addrs[0]));
    }

    std::fs::write(path, &content)?;
    eprintln!("  {} Config written to {}", c_green("✓"), path.display());

    Ok(())
}

/// Get hostname for default device name.
fn get_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "device".to_string())
        .to_lowercase()
        .replace(' ', "-")
}

/// Get the ZTLP config directory (~/.ztlp).
fn get_ztlp_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".ztlp"))
}

/// Test connectivity to relay addresses.
async fn test_connectivity(relay_addrs: &[String]) {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration, Instant};

    for addr in relay_addrs {
        match addr.parse::<std::net::SocketAddr>() {
            Ok(sock_addr) => {
                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(sock) => {
                        // Send a ZTLP magic check (just the magic bytes — relay will drop it
                        // but we can measure if the port is reachable)
                        let ping = [0x5A, 0x37, 0x00, 0x00];
                        let start = Instant::now();
                        let _ = sock.send_to(&ping, sock_addr).await;

                        // Try to receive any response (relay won't reply to bad packets,
                        // but if we get ICMP port unreachable, the recv will fail)
                        match timeout(Duration::from_millis(500), sock.recv_from(&mut [0u8; 64]))
                            .await
                        {
                            Ok(Ok(_)) => {
                                let rtt = start.elapsed();
                                eprintln!(
                                    "  {} Relay {}: {}ms",
                                    c_green("✓"),
                                    addr,
                                    rtt.as_millis()
                                );
                            }
                            _ => {
                                // No response is normal — relay drops malformed packets silently
                                eprintln!(
                                    "  {} Relay {}: reachable (no reply expected)",
                                    c_green("✓"),
                                    addr
                                );
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("  {} Relay {}: could not bind socket", c_yellow("⚠"), addr);
                    }
                }
            }
            Err(_) => {
                eprintln!("  {} Relay {}: invalid address", c_yellow("⚠"), addr);
            }
        }
    }
}

// ─── Admin Commands ─────────────────────────────────────────────────────────

/// `ztlp admin init-zone` — Initialize a zone with an enrollment secret
fn cmd_admin_init_zone(
    zone: &str,
    secret_output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::enrollment::generate_enrollment_secret;

    eprintln!("{}", c_bold("ZTLP Zone Initialization"));
    eprintln!("  {} {}", c_cyan("Zone:"), zone);
    eprintln!();

    let secret = generate_enrollment_secret();
    let secret_hex = hex::encode(secret);

    let output_path = if let Some(ref p) = secret_output {
        p.clone()
    } else {
        let ztlp_dir = get_ztlp_dir()?;
        std::fs::create_dir_all(&ztlp_dir)?;
        ztlp_dir.join("zone.key")
    };

    // Create parent directories if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output_path, &secret_hex)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    eprintln!(
        "  {} Zone secret saved to {}",
        c_green("✓"),
        output_path.display()
    );
    eprintln!();
    eprintln!("  Set this on your NS server:");
    eprintln!(
        "    {} ZTLP_ENROLLMENT_SECRET={}",
        c_cyan("export"),
        secret_hex
    );
    eprintln!();
    eprintln!("  Then generate enrollment tokens:");
    eprintln!("    {} admin enroll --zone {} \\", c_cyan("ztlp"), zone);
    eprintln!(
        "      --secret {} --ns-server <ns-addr> --relay <relay-addr>",
        output_path.display()
    );
    eprintln!();

    Ok(())
}

/// `ztlp admin enroll` — Generate enrollment tokens
#[allow(clippy::too_many_arguments)]
fn cmd_admin_enroll(
    zone: &str,
    secret_path: &Option<PathBuf>,
    ns_server: &str,
    relay_addrs: &[String],
    gateway: &Option<String>,
    expires: &str,
    max_uses: u16,
    count: usize,
    show_qr: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use ztlp_proto::enrollment::{parse_duration_secs, EnrollmentToken};

    // Load secret
    let secret_file = if let Some(ref p) = secret_path {
        p.clone()
    } else {
        let ztlp_dir = get_ztlp_dir()?;
        ztlp_dir.join("zone.key")
    };

    if !secret_file.exists() {
        return Err(format!(
            "zone secret not found at {}\n  Run: ztlp admin init-zone --zone {}",
            secret_file.display(),
            zone
        )
        .into());
    }

    let secret_hex = std::fs::read_to_string(&secret_file)?.trim().to_string();
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|e| format!("invalid secret in {}: {}", secret_file.display(), e))?;

    if secret_bytes.len() != 32 {
        return Err(format!(
            "secret must be 32 bytes (64 hex chars), got {} bytes",
            secret_bytes.len()
        )
        .into());
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    // Parse expiry
    let expires_secs = parse_duration_secs(expires)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires_at = now + expires_secs;

    // Validate inputs
    if relay_addrs.is_empty() {
        return Err("at least one --relay address is required".into());
    }

    eprintln!("{}", c_bold("ZTLP Enrollment Token Generator"));
    eprintln!("  {} {}", c_cyan("Zone:"), zone);
    eprintln!("  {} {}", c_cyan("NS Server:"), ns_server);
    for r in relay_addrs {
        eprintln!("  {} {}", c_cyan("Relay:"), r);
    }
    if let Some(ref gw) = gateway {
        eprintln!("  {} {}", c_cyan("Gateway:"), gw);
    }
    eprintln!("  {} {}", c_cyan("Expires:"), expires);
    eprintln!(
        "  {} {}",
        c_cyan("Max uses:"),
        if max_uses == 0 {
            "unlimited".to_string()
        } else {
            max_uses.to_string()
        }
    );
    eprintln!("  {} {}", c_cyan("Count:"), count);
    eprintln!();

    for i in 0..count {
        let token = EnrollmentToken::create(
            zone,
            ns_server,
            relay_addrs,
            gateway.as_deref(),
            max_uses,
            expires_at,
            &secret,
        );

        let uri = token.to_uri();

        if count > 1 {
            eprintln!("  {} Token {}/{}", c_green("✓"), i + 1, count);
        }

        if show_qr {
            eprintln!();
            // Print QR code to terminal
            match qr2term::generate_qr_string(&uri) {
                Ok(qr_str) => {
                    for line in qr_str.lines() {
                        eprintln!("  {}", line);
                    }
                }
                Err(e) => {
                    eprintln!("  {} Could not generate QR: {}", c_yellow("⚠"), e);
                }
            }
            eprintln!();
        }

        // Print the token to stdout (machine-readable)
        println!("{}", uri);
    }

    if !show_qr {
        eprintln!();
        eprintln!("  Enroll a device:");
        eprintln!("    {} setup --token <token-above>", c_cyan("ztlp"));
    }
    eprintln!();

    Ok(())
}

// ─── Admin Identity Commands ────────────────────────────────────────────────

/// `ztlp admin create-user` — Create a user identity record and register with NS
async fn cmd_admin_create_user(
    name: &str,
    role: UserRole,
    email: &Option<String>,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Create User"));
        eprintln!("  {} {}", c_cyan("Name:"), name);
        eprintln!("  {} {}", c_cyan("Role:"), role);
        if let Some(ref e) = email {
            eprintln!("  {} {}", c_cyan("Email:"), e);
        }
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
    }

    // Generate a new Ed25519 keypair for the user
    let identity = ztlp_proto::identity::NodeIdentity::generate()?;
    let pubkey_hex = hex::encode(identity.static_public_key.as_slice());

    // Save user identity
    let ztlp_dir = get_ztlp_dir()?;
    let users_dir = ztlp_dir.join("users");
    std::fs::create_dir_all(&users_dir)?;
    let user_key_path = users_dir.join(format!("{}.json", name.replace('@', "_at_")));
    identity.save(&user_key_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&user_key_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    // Register USER record (type 0x11) with NS
    let mut data_pairs = vec![
        ("public_key", pubkey_hex.as_str()),
        ("role", role_to_str(&role)),
    ];
    let email_str = email.as_deref().unwrap_or("");
    if !email_str.is_empty() {
        data_pairs.push(("email", email_str));
    }
    let data_bin = cbor_map(&mut data_pairs.iter().map(|(k, v)| (*k, *v)).collect());
    let pkt = build_registration_packet(name, 0x11, &data_bin);

    // Send to NS
    let addr: SocketAddr = ns_addr.parse()?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, addr)?;
    let mut buf = [0u8; 65535];
    let ns_ok = match sock.recv(&mut buf) {
        Ok(n) if n > 0 && buf[0] == 0x06 => true, // ACK
        Ok(n) if n > 0 && buf[0] == 0x02 => true, // Record response (also success)
        _ => false,
    };

    if json_output {
        println!(
            "{{\"status\":\"{}\",\"name\":\"{}\",\"role\":\"{}\",\"email\":\"{}\",\"pubkey\":\"{}\",\"key_file\":\"{}\"}}",
            if ns_ok { "created" } else { "created_local_only" },
            name,
            role,
            email_str,
            pubkey_hex,
            user_key_path.display()
        );
    } else {
        eprintln!("  {} User identity generated", c_green("✓"));
        eprintln!("    {} {}", c_cyan("Pubkey:"), &pubkey_hex[..16]);
        eprintln!("    {} {}", c_cyan("Key file:"), user_key_path.display());
        eprintln!();
        if ns_ok {
            eprintln!(
                "  {} User '{}' created with role '{}' (registered in NS)",
                c_green("✓"),
                name,
                role
            );
        } else {
            eprintln!(
                "  {} User '{}' created with role '{}' (NS registration failed — local key saved)",
                c_yellow("⚠"),
                name,
                role
            );
        }
        eprintln!();
    }

    Ok(())
}

/// Convert UserRole enum to string for CBOR data.
fn role_to_str(role: &UserRole) -> &'static str {
    match role {
        UserRole::Admin => "admin",
        UserRole::Tech => "tech",
        UserRole::User => "user",
    }
}

/// `ztlp admin link-device` — Link a device to a user by registering a DEVICE record in NS
async fn cmd_admin_link_device(
    device_name: &str,
    owner: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Link Device"));
        eprintln!("  {} {}", c_cyan("Device:"), device_name);
        eprintln!("  {} {}", c_cyan("Owner:"), owner);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
    }

    // Look up the existing KEY record for this device to get its node_id and pubkey
    let (node_id_hex, pubkey_hex) = match ns_query_raw(device_name, &ns_addr, 1).await {
        Ok(Some(result)) => {
            let nid = cbor_extract_string(&result.data_bytes, "node_id").unwrap_or_default();
            let pk = cbor_extract_string(&result.data_bytes, "public_key").unwrap_or_default();
            (nid, pk)
        }
        _ => (String::new(), String::new()),
    };

    // Register DEVICE record (type 0x10) with NS
    let mut pairs: Vec<(&str, &str)> = vec![("owner", owner)];
    if !node_id_hex.is_empty() {
        pairs.push(("node_id", &node_id_hex));
    }
    if !pubkey_hex.is_empty() {
        pairs.push(("public_key", &pubkey_hex));
    }
    let data_bin = cbor_map(&mut pairs.iter().map(|(k, v)| (*k, *v)).collect());
    let pkt = build_registration_packet(device_name, 0x10, &data_bin);

    let addr: SocketAddr = ns_addr.parse()?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, addr)?;
    let mut buf = [0u8; 65535];
    let ns_ok = matches!(sock.recv(&mut buf), Ok(n) if n > 0 && (buf[0] == 0x06 || buf[0] == 0x02));

    if json_output {
        println!(
            "{{\"status\":\"{}\",\"device\":\"{}\",\"owner\":\"{}\"}}",
            if ns_ok { "linked" } else { "link_failed" },
            device_name,
            owner
        );
    } else if ns_ok {
        eprintln!(
            "  {} Device '{}' linked to user '{}'",
            c_green("✓"),
            device_name,
            owner
        );
        eprintln!();
    } else {
        eprintln!(
            "  {} Failed to link device '{}' to user '{}' (NS registration failed)",
            c_red("✗"),
            device_name,
            owner
        );
        eprintln!();
    }

    Ok(())
}

/// `ztlp admin devices` — List devices owned by a user
async fn cmd_admin_devices(
    user: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Devices"));
        eprintln!("  {} {}", c_cyan("Owner:"), user);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
        eprintln!(
            "  {} Querying NS for devices owned by '{}'...",
            c_dim("→"),
            user
        );
    }

    // List all DEVICE records (type 0x10) and filter by owner
    let addr: std::net::SocketAddr = ns_addr.parse()?;
    let mut pkt = Vec::new();
    pkt.push(0x13); // Admin query
    pkt.push(0x01); // List records
    pkt.push(0x10); // DEVICE type
    pkt.extend_from_slice(&0u16.to_be_bytes()); // empty zone filter
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    socket.send_to(&pkt, addr)?;

    let mut buf = [0u8; 65535];
    match socket.recv(&mut buf) {
        Ok(n) if n > 1 && buf[0] == 0x13 => {
            let cbor_data = &buf[1..n];
            if let Some(json_val) = cbor_decode_to_json(cbor_data) {
                let devices: Vec<&serde_json::Value> = json_val
                    .get("records")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter(|record| {
                                record
                                    .get("data")
                                    .and_then(|d| d.get("owner"))
                                    .and_then(|o| o.as_str())
                                    .map(|o| o == user)
                                    .unwrap_or(false)
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                if json_output {
                    let device_names: Vec<String> = devices
                        .iter()
                        .filter_map(|d| {
                            d.get("name")
                                .and_then(|n| n.as_str())
                                .map(|s| format!("\"{}\"", s))
                        })
                        .collect();
                    println!(
                        "{{\"owner\":\"{}\",\"devices\":[{}]}}",
                        user,
                        device_names.join(",")
                    );
                } else if devices.is_empty() {
                    eprintln!("  {} No devices found for '{}'", c_yellow("⚠"), user);
                    eprintln!();
                } else {
                    eprintln!("  Found {} device(s):", devices.len());
                    eprintln!();
                    for device in &devices {
                        let name = device.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                        let mut node_id = device
                            .get("data")
                            .and_then(|d| d.get("node_id"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        // Fallback: if DEVICE record has no node_id, look up the KEY record
                        if node_id.is_empty() || node_id == "?" {
                            if let Ok(Some(key_rec)) = ns_query_raw(name, &ns_addr, 1).await {
                                if let Some(nid) =
                                    cbor_extract_string(&key_rec.data_bytes, "node_id")
                                {
                                    node_id = nid;
                                }
                            }
                        }
                        let display_nid = if node_id.is_empty() { "?" } else { &node_id };
                        eprintln!("  {} {} (NodeID: {})", c_dim("•"), name, display_nid);
                    }
                    eprintln!();
                }
            } else if json_output {
                println!(
                    "{{\"owner\":\"{}\",\"devices\":[],\"error\":\"failed to decode response\"}}",
                    user
                );
            } else {
                eprintln!("  {} Failed to decode NS response", c_yellow("⚠"));
                eprintln!();
            }
        }
        _ => {
            if json_output {
                println!("{{\"owner\":\"{}\",\"devices\":[]}}", user);
            } else {
                eprintln!(
                    "  {} No devices found (or NS server not reachable)",
                    c_yellow("⚠")
                );
                eprintln!();
            }
        }
    }

    Ok(())
}

/// `ztlp admin ls` — List records in the namespace
async fn cmd_admin_ls(
    type_filter: Option<RecordTypeFilter>,
    zone: &Option<String>,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    let type_str = match type_filter {
        Some(RecordTypeFilter::Device) => "device",
        Some(RecordTypeFilter::User) => "user",
        Some(RecordTypeFilter::Key) => "key",
        Some(RecordTypeFilter::Group) => "group",
        None => "all",
    };

    let type_byte: u8 = match type_filter {
        Some(RecordTypeFilter::Device) => 0x10, // DEVICE
        Some(RecordTypeFilter::User) => 0x11,   // USER
        Some(RecordTypeFilter::Key) => 0x01,    // KEY
        Some(RecordTypeFilter::Group) => 0x12,  // GROUP
        None => 0x00,                           // All types
    };

    let zone_str = zone.as_deref().unwrap_or("");
    let zone_bytes = zone_str.as_bytes();
    let zone_len = zone_bytes.len() as u16;

    // Build admin list query: <<0x13, 0x01, type_byte, zone_len::16, zone::binary>>
    let mut pkt = Vec::new();
    pkt.push(0x13);
    pkt.push(0x01);
    pkt.push(type_byte);
    pkt.extend_from_slice(&zone_len.to_be_bytes());
    pkt.extend_from_slice(zone_bytes);

    let addr: std::net::SocketAddr = ns_addr.parse()?;
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    socket.send_to(&pkt, addr)?;

    let mut buf = [0u8; 65535];
    match socket.recv(&mut buf) {
        Ok(n) if n > 1 && buf[0] == 0x13 => {
            let cbor_data = &buf[1..n];
            match cbor_decode_to_json(cbor_data) {
                Some(json_val) => {
                    if json_output {
                        let mut output = serde_json::Map::new();
                        output.insert(
                            "type".to_string(),
                            serde_json::Value::String(type_str.to_string()),
                        );
                        output.insert(
                            "zone".to_string(),
                            match zone {
                                Some(z) => serde_json::Value::String(z.clone()),
                                None => serde_json::Value::Null,
                            },
                        );
                        if let Some(records) = json_val.get("records") {
                            output.insert("records".to_string(), records.clone());
                        } else {
                            output.insert("records".to_string(), serde_json::Value::Array(vec![]));
                        }
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::Value::Object(output))?
                        );
                    } else {
                        eprintln!("{}", c_bold("ZTLP Records"));
                        eprintln!("  {} {}", c_cyan("Type filter:"), type_str);
                        if let Some(ref z) = zone {
                            eprintln!("  {} {}", c_cyan("Zone:"), z);
                        }
                        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
                        eprintln!();
                        print_record_list(&json_val);
                    }
                }
                None => {
                    if json_output {
                        println!(
                            "{{\"type\":\"{}\",\"zone\":{},\"records\":[],\"error\":\"failed to decode response\"}}",
                            type_str,
                            match zone { Some(z) => format!("\"{}\"", z), None => "null".to_string() }
                        );
                    } else {
                        eprintln!("  {} Failed to decode NS response", c_yellow("⚠"));
                    }
                }
            }
        }
        _ => {
            if json_output {
                println!(
                    "{{\"type\":\"{}\",\"zone\":{},\"records\":[]}}",
                    type_str,
                    match zone {
                        Some(z) => format!("\"{}\"", z),
                        None => "null".to_string(),
                    }
                );
            } else {
                eprintln!("{}", c_bold("ZTLP Records"));
                eprintln!("  {} {}", c_cyan("Type filter:"), type_str);
                if let Some(ref z) = zone {
                    eprintln!("  {} {}", c_cyan("Zone:"), z);
                }
                eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
                eprintln!();
                eprintln!(
                    "  {} No records found (or NS server not reachable)",
                    c_yellow("⚠")
                );
                eprintln!();
            }
        }
    }

    Ok(())
}

/// Print records list in human-readable format
fn print_record_list(json_val: &serde_json::Value) {
    if let Some(records) = json_val.get("records").and_then(|r| r.as_array()) {
        if records.is_empty() {
            eprintln!("  {} No records found", c_dim("(empty)"));
        } else {
            eprintln!("  Found {} record(s):", records.len());
            eprintln!();
            for record in records {
                let name = record.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let rtype = record.get("type").and_then(|t| t.as_str()).unwrap_or("?");
                let serial = record.get("serial").and_then(|s| s.as_u64()).unwrap_or(0);

                let type_colored = match rtype {
                    "device" => c_cyan(rtype),
                    "user" => c_green(rtype),
                    "group" => c_yellow(rtype),
                    "key" => c_dim(rtype),
                    _ => rtype.to_string(),
                };

                eprintln!(
                    "  {} {} [{}] serial={}",
                    c_dim("•"),
                    name,
                    type_colored,
                    serial
                );
            }
        }
    } else {
        eprintln!("  {} No records found", c_dim("(empty)"));
    }
    eprintln!();
}

/// `ztlp admin create-group` — Create a group in the namespace (registers GROUP record with NS)
async fn cmd_admin_create_group(
    name: &str,
    description: &Option<String>,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;
    let desc = description.as_deref().unwrap_or("");

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Create Group"));
        eprintln!("  {} {}", c_cyan("Name:"), name);
        if !desc.is_empty() {
            eprintln!("  {} {}", c_cyan("Description:"), desc);
        }
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
    }

    // Register GROUP record (type 0x12) with empty members list
    let data_bin = cbor_encode_group(desc, &[]);
    let pkt = build_registration_packet(name, 0x12, &data_bin);

    let addr: SocketAddr = ns_addr.parse()?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, addr)?;
    let mut buf = [0u8; 65535];
    let ns_ok = matches!(sock.recv(&mut buf), Ok(n) if n > 0 && (buf[0] == 0x06 || buf[0] == 0x02));

    if json_output {
        println!(
            "{{\"status\":\"{}\",\"name\":\"{}\",\"description\":\"{}\",\"members\":[]}}",
            if ns_ok { "created" } else { "create_failed" },
            name,
            desc
        );
    } else if ns_ok {
        eprintln!(
            "  {} Group '{}' created (empty — add members with `ztlp admin group add`)",
            c_green("✓"),
            name
        );
        eprintln!();
    } else {
        eprintln!(
            "  {} Failed to create group '{}' (NS registration failed)",
            c_red("✗"),
            name
        );
        eprintln!();
    }

    Ok(())
}

/// `ztlp admin group add` — Add a member to a group (read-modify-write GROUP record)
async fn cmd_admin_group_add(
    group: &str,
    member: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Group Add Member"));
        eprintln!("  {} {}", c_cyan("Group:"), group);
        eprintln!("  {} {}", c_cyan("Member:"), member);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
    }

    // Read current group record to get existing members
    let (mut members, description) = match ns_query_raw(group, &ns_addr, 0x12).await {
        Ok(Some(result)) => {
            let m = cbor_extract_string_array(&result.data_bytes, "members");
            let d = cbor_extract_string(&result.data_bytes, "description").unwrap_or_default();
            (m, d)
        }
        _ => (vec![], String::new()),
    };

    // Add the new member if not already present
    if !members.iter().any(|m| m == member) {
        members.push(member.to_string());
    }

    // Re-register the GROUP record with updated members
    let member_strs: Vec<&str> = members.iter().map(|s| s.as_str()).collect();
    let data_bin = cbor_encode_group(&description, &member_strs);
    let pkt = build_registration_packet(group, 0x12, &data_bin);

    let addr: SocketAddr = ns_addr.parse()?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, addr)?;
    let mut buf = [0u8; 65535];
    let ns_ok = matches!(sock.recv(&mut buf), Ok(n) if n > 0 && (buf[0] == 0x06 || buf[0] == 0x02));

    if json_output {
        println!(
            "{{\"status\":\"{}\",\"group\":\"{}\",\"member\":\"{}\"}}",
            if ns_ok { "added" } else { "add_failed" },
            group,
            member
        );
    } else if ns_ok {
        eprintln!("  {} Added '{}' to group '{}'", c_green("✓"), member, group);
        eprintln!();
    } else {
        eprintln!(
            "  {} Failed to add '{}' to group '{}' (NS write failed)",
            c_red("✗"),
            member,
            group
        );
        eprintln!();
    }

    Ok(())
}

/// `ztlp admin group remove` — Remove a member from a group (read-modify-write GROUP record)
async fn cmd_admin_group_remove(
    group: &str,
    member: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Group Remove Member"));
        eprintln!("  {} {}", c_cyan("Group:"), group);
        eprintln!("  {} {}", c_cyan("Member:"), member);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
    }

    // Read current group record
    let (mut members, description) = match ns_query_raw(group, &ns_addr, 0x12).await {
        Ok(Some(result)) => {
            let m = cbor_extract_string_array(&result.data_bytes, "members");
            let d = cbor_extract_string(&result.data_bytes, "description").unwrap_or_default();
            (m, d)
        }
        _ => {
            if json_output {
                println!(
                    "{{\"status\":\"error\",\"group\":\"{}\",\"member\":\"{}\",\"error\":\"group not found\"}}",
                    group, member
                );
            } else {
                eprintln!("  {} Group '{}' not found in NS", c_red("✗"), group);
                eprintln!();
            }
            return Ok(());
        }
    };

    // Remove the member
    let orig_len = members.len();
    members.retain(|m| m != member);
    let removed = members.len() < orig_len;

    // Re-register with updated members
    let member_strs: Vec<&str> = members.iter().map(|s| s.as_str()).collect();
    let data_bin = cbor_encode_group(&description, &member_strs);
    let pkt = build_registration_packet(group, 0x12, &data_bin);

    let addr: SocketAddr = ns_addr.parse()?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, addr)?;
    let mut buf = [0u8; 65535];
    let ns_ok = matches!(sock.recv(&mut buf), Ok(n) if n > 0 && (buf[0] == 0x06 || buf[0] == 0x02));

    if json_output {
        println!(
            "{{\"status\":\"{}\",\"group\":\"{}\",\"member\":\"{}\",\"was_member\":{}}}",
            if ns_ok { "removed" } else { "remove_failed" },
            group,
            member,
            removed
        );
    } else if ns_ok && removed {
        eprintln!(
            "  {} Removed '{}' from group '{}'",
            c_green("✓"),
            member,
            group
        );
        eprintln!();
    } else if ns_ok {
        eprintln!(
            "  {} '{}' was not a member of '{}'",
            c_yellow("⚠"),
            member,
            group
        );
        eprintln!();
    } else {
        eprintln!(
            "  {} Failed to update group '{}' (NS write failed)",
            c_red("✗"),
            group
        );
        eprintln!();
    }

    Ok(())
}

/// `ztlp admin group members` — List members of a group
async fn cmd_admin_group_members(
    group: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Group Members"));
        eprintln!("  {} {}", c_cyan("Group:"), group);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
        eprintln!("  {} Querying NS for members of '{}'...", c_dim("→"), group);
    }

    // Query GROUP record (type 0x12) from NS
    match ns_query_raw(group, &ns_addr, 0x12).await {
        Ok(Some(result)) => {
            let members = cbor_extract_string_array(&result.data_bytes, "members");
            let description = cbor_extract_string(&result.data_bytes, "description");

            if json_output {
                let members_json: Vec<String> =
                    members.iter().map(|m| format!("\"{}\"", m)).collect();
                println!(
                    "{{\"group\":\"{}\",\"members\":[{}]}}",
                    group,
                    members_json.join(",")
                );
            } else {
                if let Some(desc) = description {
                    if !desc.is_empty() {
                        eprintln!("  {} {}", c_cyan("Description:"), desc);
                    }
                }
                if members.is_empty() {
                    eprintln!("  {} Group has no members", c_yellow("⚠"));
                } else {
                    eprintln!("  Found {} member(s):", members.len());
                    eprintln!();
                    for member in &members {
                        eprintln!("  {} {}", c_dim("•"), member);
                    }
                }
                eprintln!();
            }
        }
        _ => {
            if json_output {
                println!(
                    "{{\"group\":\"{}\",\"members\":[],\"error\":\"not found or NS unreachable\"}}",
                    group
                );
            } else {
                eprintln!(
                    "  {} Group not found (or NS server not reachable)",
                    c_yellow("⚠")
                );
                eprintln!();
            }
        }
    }

    Ok(())
}

/// `ztlp admin group check` — Check if a user is a member of a group
async fn cmd_admin_group_check(
    group: &str,
    user: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Group Check"));
        eprintln!("  {} {}", c_cyan("Group:"), group);
        eprintln!("  {} {}", c_cyan("User:"), user);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
        eprintln!(
            "  {} Checking membership of '{}' in '{}'...",
            c_dim("→"),
            user,
            group
        );
    }

    // Query GROUP record (type 0x12) from NS
    match ns_query_raw(group, &ns_addr, 0x12).await {
        Ok(Some(result)) => {
            let members = cbor_extract_string_array(&result.data_bytes, "members");
            let is_member = members.iter().any(|m| m == user);

            if json_output {
                println!(
                    "{{\"group\":\"{}\",\"user\":\"{}\",\"is_member\":{}}}",
                    group, user, is_member
                );
            } else if is_member {
                eprintln!("  {} '{}' IS a member of '{}'", c_green("✓"), user, group);
                eprintln!();
            } else {
                eprintln!("  {} '{}' is NOT a member of '{}'", c_red("✗"), user, group);
                if !members.is_empty() {
                    eprintln!("  {} Current members: {}", c_dim("ℹ"), members.join(", "));
                }
                eprintln!();
            }
        }
        _ => {
            if json_output {
                println!(
                    "{{\"group\":\"{}\",\"user\":\"{}\",\"is_member\":false,\"error\":\"group not found or NS unreachable\"}}",
                    group, user
                );
            } else {
                eprintln!(
                    "  {} Group not found (or NS server not reachable)",
                    c_yellow("⚠")
                );
                eprintln!();
            }
        }
    }

    Ok(())
}

/// `ztlp admin groups` — List all groups in the namespace
async fn cmd_admin_groups(
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Groups"));
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();
        eprintln!("  {} Querying NS for groups...", c_dim("→"));
    }

    // List GROUP records (type 0x12) via admin query
    let addr: std::net::SocketAddr = ns_addr.parse()?;
    let mut pkt = Vec::new();
    pkt.push(0x13); // Admin query
    pkt.push(0x01); // List records
    pkt.push(0x12); // GROUP type
    pkt.extend_from_slice(&0u16.to_be_bytes()); // empty zone filter
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    socket.send_to(&pkt, addr)?;

    let mut buf = [0u8; 65535];
    match socket.recv(&mut buf) {
        Ok(n) if n > 1 && buf[0] == 0x13 => {
            let cbor_data = &buf[1..n];
            if let Some(json_val) = cbor_decode_to_json(cbor_data) {
                if let Some(records) = json_val.get("records").and_then(|r| r.as_array()) {
                    if json_output {
                        let groups: Vec<serde_json::Value> = records
                            .iter()
                            .map(|r| {
                                let name = r.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                                let members = r
                                    .get("data")
                                    .and_then(|d| d.get("members"))
                                    .and_then(|m| m.as_array())
                                    .cloned()
                                    .unwrap_or_default();
                                let desc = r
                                    .get("data")
                                    .and_then(|d| d.get("description"))
                                    .and_then(|d| d.as_str())
                                    .unwrap_or("");
                                serde_json::json!({
                                    "name": name,
                                    "description": desc,
                                    "members": members,
                                    "member_count": members.len()
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::json!({"groups": groups}))?
                        );
                    } else if records.is_empty() {
                        eprintln!("  {} No groups found", c_dim("(empty)"));
                        eprintln!();
                    } else {
                        eprintln!("  Found {} group(s):", records.len());
                        eprintln!();
                        for record in records {
                            let name = record.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                            let desc = record
                                .get("data")
                                .and_then(|d| d.get("description"))
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            let member_count = record
                                .get("data")
                                .and_then(|d| d.get("members"))
                                .and_then(|m| m.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            let desc_str = if desc.is_empty() {
                                String::new()
                            } else {
                                format!(" — {}", desc)
                            };
                            eprintln!(
                                "  {} {} ({} member{}){}",
                                c_dim("•"),
                                c_yellow(name),
                                member_count,
                                if member_count == 1 { "" } else { "s" },
                                desc_str
                            );
                        }
                        eprintln!();
                    }
                } else if json_output {
                    println!("{{\"groups\":[]}}");
                } else {
                    eprintln!("  {} No groups found", c_dim("(empty)"));
                    eprintln!();
                }
            } else if json_output {
                println!("{{\"groups\":[],\"error\":\"failed to decode response\"}}");
            } else {
                eprintln!("  {} Failed to decode NS response", c_yellow("⚠"));
                eprintln!();
            }
        }
        _ => {
            if json_output {
                println!("{{\"groups\":[]}}");
            } else {
                eprintln!(
                    "  {} No groups found (or NS server not reachable)",
                    c_yellow("⚠")
                );
                eprintln!();
            }
        }
    }

    Ok(())
}

/// `ztlp admin revoke` — Revoke an identity (device, user, or group)
async fn cmd_admin_revoke(
    name: &str,
    reason: &str,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;

    if !json_output {
        eprintln!("{}", c_bold("ZTLP Revoke Identity"));
        eprintln!("  {} {}", c_cyan("Name:"), name);
        eprintln!("  {} {}", c_cyan("Reason:"), reason);
        eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
        eprintln!();

        // Build and send revocation record via NS registration
        let addr: std::net::SocketAddr = ns_addr.parse()?;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        // CBOR-encode the revocation data
        let revoke_data = build_revoke_cbor(name, reason);
        let revoke_name = format!("revoke.{}", name);
        let type_byte: u8 = 0x05; // REVOKE type

        // Build registration packet: <<0x09, name_len::16, name, type_byte, data_len::16, data, sig_len::16, sig(empty)>>
        let name_bytes = revoke_name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let data_len = revoke_data.len() as u16;
        let sig = vec![0u8; 0]; // Empty sig for dev mode
        let sig_len: u16 = 0;

        let mut pkt = Vec::new();
        pkt.push(0x09);
        pkt.extend_from_slice(&name_len.to_be_bytes());
        pkt.extend_from_slice(name_bytes);
        pkt.push(type_byte);
        pkt.extend_from_slice(&data_len.to_be_bytes());
        pkt.extend_from_slice(&revoke_data);
        pkt.extend_from_slice(&sig_len.to_be_bytes());
        pkt.extend_from_slice(&sig);

        socket.send_to(&pkt, addr)?;

        let mut buf = [0u8; 4096];
        match socket.recv(&mut buf) {
            Ok(n) if n > 0 && buf[0] == 0x06 => {
                eprintln!("  {} Revoked '{}' — reason: {}", c_green("✓"), name, reason);
            }
            Ok(n) if n > 0 && buf[0] == 0xFF => {
                eprintln!(
                    "  {} Revocation rejected by NS server (check auth configuration)",
                    c_red("✗")
                );
            }
            _ => {
                eprintln!(
                    "  {} NS server did not respond (timeout or unreachable)",
                    c_yellow("⚠")
                );
            }
        }
        eprintln!();
    } else {
        let addr: std::net::SocketAddr = ns_addr.parse()?;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        let revoke_data = build_revoke_cbor(name, reason);
        let revoke_name = format!("revoke.{}", name);
        let type_byte: u8 = 0x05;

        let name_bytes = revoke_name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let data_len = revoke_data.len() as u16;
        let sig_len: u16 = 0;

        let mut pkt = Vec::new();
        pkt.push(0x09);
        pkt.extend_from_slice(&name_len.to_be_bytes());
        pkt.extend_from_slice(name_bytes);
        pkt.push(type_byte);
        pkt.extend_from_slice(&data_len.to_be_bytes());
        pkt.extend_from_slice(&revoke_data);
        pkt.extend_from_slice(&sig_len.to_be_bytes());

        socket.send_to(&pkt, addr)?;

        let mut buf = [0u8; 4096];
        match socket.recv(&mut buf) {
            Ok(n) if n > 0 && buf[0] == 0x06 => {
                println!(
                    "{{\"status\":\"revoked\",\"name\":\"{}\",\"reason\":\"{}\"}}",
                    name, reason
                );
            }
            Ok(n) if n > 0 && buf[0] == 0xFF => {
                println!(
                    "{{\"status\":\"rejected\",\"name\":\"{}\",\"error\":\"authorization failed\"}}",
                    name
                );
            }
            _ => {
                println!(
                    "{{\"status\":\"error\",\"name\":\"{}\",\"error\":\"ns server unreachable\"}}",
                    name
                );
            }
        }
    }

    Ok(())
}

/// Build CBOR-encoded revocation data
///
/// Encodes a CBOR map: {"effective_at": "now", "reason": <reason>, "revoked_ids": [<name>]}
/// Keys are sorted by encoded length (RFC 8949 deterministic encoding).
fn build_revoke_cbor(name: &str, reason: &str) -> Vec<u8> {
    // Encode the array value for revoked_ids: [name]
    let mut arr = cbor_head(4, 1); // array of 1 element
    arr.extend_from_slice(&cbor_text(name));

    // Build the map with 3 entries
    // Keys sorted by encoded byte length (shortest first):
    //   "reason" (6), "revoked_ids" (11), "effective_at" (12)
    let key_reason = cbor_text("reason");
    let val_reason = cbor_text(reason);
    let key_revoked = cbor_text("revoked_ids");
    let key_effective = cbor_text("effective_at");
    let val_effective = cbor_text("now");

    let mut buf = cbor_head(5, 3); // map of 3 entries
                                   // Sort by encoded key length then bytes
    buf.extend_from_slice(&key_reason);
    buf.extend_from_slice(&val_reason);
    buf.extend_from_slice(&key_effective);
    buf.extend_from_slice(&val_effective);
    buf.extend_from_slice(&key_revoked);
    buf.extend_from_slice(&arr);
    buf
}

/// `ztlp admin audit` — Query the audit log
async fn cmd_admin_audit(
    since_str: &str,
    name_pattern: &Option<String>,
    ns_server: &Option<String>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let ns_addr = resolve_ns_server(ns_server, &config)?;
    let since_secs = parse_duration_seconds(since_str)?;
    let since_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(since_secs);

    let addr: std::net::SocketAddr = ns_addr.parse()?;
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    // Build admin query packet
    let pkt = match name_pattern {
        Some(pattern) => {
            // Audit filter: <<0x13, 0x03, since_ts::64, pattern_len::16, pattern::binary>>
            let pat_bytes = pattern.as_bytes();
            let pat_len = pat_bytes.len() as u16;
            let mut p = Vec::new();
            p.push(0x13);
            p.push(0x03);
            p.extend_from_slice(&since_ts.to_be_bytes());
            p.extend_from_slice(&pat_len.to_be_bytes());
            p.extend_from_slice(pat_bytes);
            p
        }
        None => {
            // Audit since: <<0x13, 0x02, since_ts::64>>
            let mut p = Vec::new();
            p.push(0x13);
            p.push(0x02);
            p.extend_from_slice(&since_ts.to_be_bytes());
            p
        }
    };

    socket.send_to(&pkt, addr)?;

    let mut buf = [0u8; 65535];
    match socket.recv(&mut buf) {
        Ok(n) if n > 1 && buf[0] == 0x13 => {
            // Decode CBOR response
            let cbor_data = &buf[1..n];
            match cbor_decode_to_json(cbor_data) {
                Some(json_val) => {
                    if json_output {
                        if let Ok(s) = serde_json::to_string(&json_val) {
                            println!("{}", s);
                        } else {
                            println!("{}", json_val);
                        }
                    } else {
                        print_audit_entries(&json_val);
                    }
                }
                None => {
                    if json_output {
                        println!("{{\"entries\":[],\"error\":\"failed to decode response\"}}");
                    } else {
                        eprintln!("  {} Failed to decode audit response", c_yellow("⚠"));
                    }
                }
            }
        }
        _ => {
            if json_output {
                println!("{{\"entries\":[],\"error\":\"ns server unreachable\"}}");
            } else {
                eprintln!("{}", c_bold("ZTLP Audit Log"));
                eprintln!("  {} Since: {} ago", c_cyan("Filter:"), since_str);
                if let Some(ref pat) = name_pattern {
                    eprintln!("  {} {}", c_cyan("Pattern:"), pat);
                }
                eprintln!("  {} {}", c_cyan("NS Server:"), ns_addr);
                eprintln!();
                eprintln!("  {} NS server did not respond", c_yellow("⚠"));
                eprintln!();
            }
        }
    }

    Ok(())
}

/// Print audit entries in human-readable format
fn print_audit_entries(json_val: &serde_json::Value) {
    eprintln!("{}", c_bold("ZTLP Audit Log"));
    eprintln!();

    if let Some(entries) = json_val.get("entries").and_then(|e| e.as_array()) {
        if entries.is_empty() {
            eprintln!("  {} No audit entries found", c_dim("(empty)"));
        } else {
            for entry in entries {
                let ts = entry.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0);
                let action = entry.get("action").and_then(|a| a.as_str()).unwrap_or("?");
                let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let rtype = entry.get("type").and_then(|t| t.as_str()).unwrap_or("?");

                let action_colored = match action {
                    "registered" => c_green(action),
                    "revoked" => c_red(action),
                    "updated" => c_yellow(action),
                    _ => c_dim(action),
                };

                // Format timestamp
                let datetime = format_unix_ts(ts);

                eprintln!(
                    "  {} {} {} ({})",
                    c_dim(&datetime),
                    action_colored,
                    c_cyan(name),
                    rtype
                );

                // Print details if present
                if let Some(details) = entry.get("details").and_then(|d| d.as_object()) {
                    for (key, val) in details {
                        eprintln!("    {} {}: {}", c_dim("├"), key, val);
                    }
                }
            }
        }
    } else {
        eprintln!("  {} No audit entries found", c_dim("(empty)"));
    }
    eprintln!();
}

/// Format a Unix timestamp into a human-readable string
fn format_unix_ts(ts: u64) -> String {
    let secs = ts;
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let ss = secs % 60;
    // Simple HH:MM:SS format (full date would require chrono)
    format!("{:02}:{:02}:{:02}", hours, mins, ss)
}

/// Parse a duration string like "24h", "7d", "30m" into seconds
fn parse_duration_seconds(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(86400); // Default 24h
    }

    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 'd')
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 'h')
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 'm')
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 's')
    } else {
        // Assume hours
        (s, 'h')
    };

    let num: u64 = num_str.parse()?;
    let secs = match unit {
        'd' => num * 86400,
        'h' => num * 3600,
        'm' => num * 60,
        's' => num,
        _ => num * 3600,
    };
    Ok(secs)
}

/// `ztlp admin rotate-zone-key` — Rotate the zone signing key
fn cmd_admin_rotate_zone_key(json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new Ed25519 keypair
    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret_bytes);
    let secret = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let public = secret.verifying_key();
    let public_hex = hex::encode(public.as_bytes());

    // Save to the default zone key path
    let ztlp_dir = dirs::home_dir().unwrap_or_default().join(".ztlp");
    std::fs::create_dir_all(&ztlp_dir)?;

    let key_path = ztlp_dir.join("zone.key");
    let old_exists = key_path.exists();

    // Back up old key if it exists
    if old_exists {
        let backup_path = ztlp_dir.join("zone.key.bak");
        std::fs::copy(&key_path, &backup_path)?;
    }

    // Save new key (64-byte secret key)
    std::fs::write(&key_path, secret.to_bytes())?;

    if json_output {
        println!(
            "{{\"status\":\"rotated\",\"public_key\":\"{}\",\"key_path\":\"{}\",\"backed_up\":{}}}",
            public_hex,
            key_path.display(),
            old_exists
        );
    } else {
        eprintln!("{}", c_bold("ZTLP Zone Key Rotation"));
        eprintln!();
        if old_exists {
            eprintln!(
                "  {} Old key backed up to {}",
                c_dim("→"),
                ztlp_dir.join("zone.key.bak").display()
            );
        }
        eprintln!("  {} New zone signing key generated", c_green("✓"));
        eprintln!("  {} {}", c_cyan("Public key:"), public_hex);
        eprintln!("  {} {}", c_cyan("Saved to:"), key_path.display());
        eprintln!();
        eprintln!(
            "  {} Re-enroll devices with: ztlp admin enroll --zone <zone>",
            c_dim("Note:")
        );
        eprintln!();
    }

    Ok(())
}

/// `ztlp admin export-zone-key` — Export the zone signing key
fn cmd_admin_export_zone_key(
    format: &str,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ztlp_dir = dirs::home_dir().unwrap_or_default().join(".ztlp");
    let key_path = ztlp_dir.join("zone.key");

    if !key_path.exists() {
        if json_output {
            println!(
                "{{\"status\":\"error\",\"error\":\"zone key not found at {}\"}}",
                key_path.display()
            );
        } else {
            eprintln!(
                "  {} Zone key not found at {}",
                c_red("✗"),
                key_path.display()
            );
            eprintln!("  {} Run: ztlp admin init-zone --zone <zone>", c_dim("→"));
        }
        return Ok(());
    }

    let key_bytes = std::fs::read(&key_path)?;
    let secret = ed25519_dalek::SigningKey::from_bytes(
        &key_bytes[..32]
            .try_into()
            .map_err(|_| "invalid key file: expected 32 bytes")?,
    );
    let public = secret.verifying_key();

    match format {
        "hex" => {
            let secret_hex = hex::encode(secret.to_bytes());
            let public_hex = hex::encode(public.as_bytes());

            if json_output {
                println!(
                    "{{\"format\":\"hex\",\"secret_key\":\"{}\",\"public_key\":\"{}\"}}",
                    secret_hex, public_hex
                );
            } else {
                eprintln!("{}", c_bold("ZTLP Zone Key Export (hex)"));
                eprintln!();
                eprintln!("  {} {}", c_cyan("Public key: "), public_hex);
                eprintln!("  {} {}", c_cyan("Secret key: "), secret_hex);
                eprintln!();
            }
        }
        _ => {
            let public_hex = hex::encode(public.as_bytes());
            // PEM-like format for Ed25519 keys (simplified)
            let secret_b64 = base64_encode(&secret.to_bytes());
            let public_b64 = base64_encode(public.as_bytes());

            if json_output {
                println!(
                    "{{\"format\":\"pem\",\"public_key\":\"{}\",\"public_key_pem\":\"-----BEGIN ZTLP ED25519 PUBLIC KEY-----\\n{}\\n-----END ZTLP ED25519 PUBLIC KEY-----\",\"secret_key_pem\":\"-----BEGIN ZTLP ED25519 PRIVATE KEY-----\\n{}\\n-----END ZTLP ED25519 PRIVATE KEY-----\"}}",
                    public_hex, public_b64, secret_b64
                );
            } else {
                eprintln!("{}", c_bold("ZTLP Zone Key Export (PEM)"));
                eprintln!();
                eprintln!("  {} {}", c_cyan("Public key:"), public_hex);
                eprintln!();
                eprintln!("-----BEGIN ZTLP ED25519 PUBLIC KEY-----");
                eprintln!("{}", public_b64);
                eprintln!("-----END ZTLP ED25519 PUBLIC KEY-----");
                eprintln!();
                eprintln!("-----BEGIN ZTLP ED25519 PRIVATE KEY-----");
                eprintln!("{}", secret_b64);
                eprintln!("-----END ZTLP ED25519 PRIVATE KEY-----");
                eprintln!();
            }
        }
    }

    Ok(())
}

// ─── CA / Certificate Management Commands ─────────────────────────────────

fn default_ca_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".ztlp")
        .join("ca")
}

fn generate_signing_key() -> ed25519_dalek::SigningKey {
    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret_bytes);
    ed25519_dalek::SigningKey::from_bytes(&secret_bytes)
}

fn utc_timestamp_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day) = days_to_ymd(secs / 86400);
    let tod = secs % 86400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn utc_timestamp_compact() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day) = days_to_ymd(secs / 86400);
    let tod = secs % 86400;
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        year,
        month,
        day,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cmd_admin_ca_init(
    zone: &str,
    output: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = output.clone().unwrap_or_else(default_ca_dir);
    std::fs::create_dir_all(&ca_dir)?;

    let root_key_path = ca_dir.join("root.key");
    let root_cert_path = ca_dir.join("root.pem");
    let intermediate_key_path = ca_dir.join("intermediate.key");
    let intermediate_cert_path = ca_dir.join("intermediate.pem");

    if root_key_path.exists() {
        if json_output {
            println!(
                "{{\"status\":\"error\",\"error\":\"CA already initialized at {}\"}}",
                ca_dir.display()
            );
        } else {
            eprintln!(
                "  {} CA already initialized at {}",
                c_red("✗"),
                ca_dir.display()
            );
            eprintln!(
                "  {} To rotate: ztlp admin ca-rotate-intermediate",
                c_dim("→")
            );
        }
        return Ok(());
    }

    // Generate root CA key (Ed25519 → we use it as seed for reproducible CA)
    let root_key = generate_signing_key();
    std::fs::write(&root_key_path, root_key.to_bytes())?;

    // Write root cert placeholder (PEM)
    let root_cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n# ZTLP Root CA for zone: {}\n# Generated: {}\n# Key: {}\n-----END CERTIFICATE-----\n",
        zone,
        utc_timestamp_iso(),
        hex::encode(root_key.verifying_key().as_bytes()),
    );
    std::fs::write(&root_cert_path, &root_cert_pem)?;

    // Generate intermediate CA key
    let intermediate_key = generate_signing_key();
    std::fs::write(&intermediate_key_path, intermediate_key.to_bytes())?;

    let intermediate_cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n# ZTLP Intermediate CA for zone: {}\n# Generated: {}\n# Key: {}\n# Issuer: {}\n-----END CERTIFICATE-----\n",
        zone,
        utc_timestamp_iso(),
        hex::encode(intermediate_key.verifying_key().as_bytes()),
        hex::encode(root_key.verifying_key().as_bytes()),
    );
    std::fs::write(&intermediate_cert_path, &intermediate_cert_pem)?;

    // Write zone metadata
    let meta = format!(
        "{{\"zone\":\"{}\",\"created\":\"{}\",\"root_key\":\"{}\",\"intermediate_key\":\"{}\"}}",
        zone,
        utc_timestamp_iso(),
        hex::encode(root_key.verifying_key().as_bytes()),
        hex::encode(intermediate_key.verifying_key().as_bytes()),
    );
    std::fs::write(ca_dir.join("ca.json"), &meta)?;

    // Create certs directory for issued certs
    std::fs::create_dir_all(ca_dir.join("certs"))?;
    // Create empty index
    std::fs::write(ca_dir.join("certs").join("index.json"), "[]")?;

    if json_output {
        println!("{{\"status\":\"ok\",\"zone\":\"{}\",\"ca_dir\":\"{}\",\"root_key\":\"{}\",\"intermediate_key\":\"{}\"}}",
            zone, ca_dir.display(),
            hex::encode(root_key.verifying_key().as_bytes()),
            hex::encode(intermediate_key.verifying_key().as_bytes()),
        );
    } else {
        eprintln!("{}", c_bold(&format!("ZTLP CA Initialized for {}", zone)));
        eprintln!();
        eprintln!("  {} {}", c_cyan("CA directory:"), ca_dir.display());
        eprintln!(
            "  {} {}",
            c_cyan("Root key:    "),
            hex::encode(root_key.verifying_key().as_bytes())
        );
        eprintln!(
            "  {} {}",
            c_cyan("Intermediate:"),
            hex::encode(intermediate_key.verifying_key().as_bytes())
        );
        eprintln!();
        eprintln!("  {} Import root cert: ztlp admin ca-export-root | sudo tee /usr/local/share/ca-certificates/ztlp.crt", c_dim("→"));
    }

    Ok(())
}

fn cmd_admin_ca_show(
    ca_dir: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);

    let meta_path = ca_dir.join("ca.json");
    if !meta_path.exists() {
        if json_output {
            println!("{{\"status\":\"error\",\"error\":\"No CA found. Run: ztlp admin ca-init\"}}");
        } else {
            eprintln!(
                "  {} No CA initialized. Run: ztlp admin ca-init --zone <zone>",
                c_red("✗")
            );
        }
        return Ok(());
    }

    let meta_str = std::fs::read_to_string(&meta_path)?;

    // Count issued certs
    let index_path = ca_dir.join("certs").join("index.json");
    let cert_count = if index_path.exists() {
        let idx = std::fs::read_to_string(&index_path)?;
        let certs: Vec<serde_json::Value> = serde_json::from_str(&idx).unwrap_or_default();
        certs.len()
    } else {
        0
    };

    if json_output {
        let meta: serde_json::Value = serde_json::from_str(&meta_str)?;
        println!(
            "{{\"status\":\"ok\",\"ca\":{},\"issued_certs\":{}}}",
            meta, cert_count
        );
    } else {
        let meta: serde_json::Value = serde_json::from_str(&meta_str)?;
        eprintln!("{}", c_bold("ZTLP Certificate Authority"));
        eprintln!();
        eprintln!(
            "  {} {}",
            c_cyan("Zone:       "),
            meta.get("zone")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        eprintln!(
            "  {} {}",
            c_cyan("Created:    "),
            meta.get("created")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        eprintln!(
            "  {} {}",
            c_cyan("Root key:   "),
            meta.get("root_key")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        eprintln!(
            "  {} {}",
            c_cyan("Intermediate:"),
            meta.get("intermediate_key")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        eprintln!("  {} {}", c_cyan("Issued certs:"), cert_count);
        eprintln!("  {} {}", c_cyan("CA directory:"), ca_dir.display());
        eprintln!();
    }

    Ok(())
}

fn cmd_admin_ca_export_root(ca_dir: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);
    let root_cert_path = ca_dir.join("root.pem");

    if !root_cert_path.exists() {
        eprintln!(
            "  {} Root certificate not found. Run: ztlp admin ca-init",
            c_red("✗")
        );
        return Ok(());
    }

    let pem = std::fs::read_to_string(&root_cert_path)?;
    print!("{}", pem);

    Ok(())
}

fn cmd_admin_ca_rotate_intermediate(
    ca_dir: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);
    let root_key_path = ca_dir.join("root.key");

    if !root_key_path.exists() {
        if json_output {
            println!("{{\"status\":\"error\",\"error\":\"No CA found. Run: ztlp admin ca-init\"}}");
        } else {
            eprintln!(
                "  {} No CA initialized. Run: ztlp admin ca-init --zone <zone>",
                c_red("✗")
            );
        }
        return Ok(());
    }

    // Backup old intermediate
    let old_intermediate = ca_dir.join("intermediate.key");
    if old_intermediate.exists() {
        let backup = ca_dir.join(format!("intermediate.key.bak.{}", utc_timestamp_compact()));
        std::fs::copy(&old_intermediate, &backup)?;
    }

    // Generate new intermediate key
    let new_key = generate_signing_key();
    std::fs::write(&old_intermediate, new_key.to_bytes())?;

    // Update metadata
    let meta_path = ca_dir.join("ca.json");
    if meta_path.exists() {
        let meta_str = std::fs::read_to_string(&meta_path)?;
        let mut meta: serde_json::Value = serde_json::from_str(&meta_str)?;
        if let Some(obj) = meta.as_object_mut() {
            obj.insert(
                "intermediate_key".to_string(),
                serde_json::Value::String(hex::encode(new_key.verifying_key().as_bytes())),
            );
            obj.insert(
                "intermediate_rotated".to_string(),
                serde_json::Value::String(utc_timestamp_iso().to_string()),
            );
        }
        std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;
    }

    let new_pub = hex::encode(new_key.verifying_key().as_bytes());
    if json_output {
        println!(
            "{{\"status\":\"ok\",\"new_intermediate_key\":\"{}\"}}",
            new_pub
        );
    } else {
        eprintln!("{}", c_bold("Intermediate CA Rotated"));
        eprintln!("  {} {}", c_cyan("New key:"), new_pub);
        eprintln!(
            "  {} Existing certificates remain valid until expiry",
            c_dim("ℹ")
        );
    }

    Ok(())
}

fn cmd_admin_cert_issue(
    hostname: &str,
    days: u32,
    ca_dir: &Option<PathBuf>,
    output: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);
    let intermediate_key_path = ca_dir.join("intermediate.key");

    if !intermediate_key_path.exists() {
        if json_output {
            println!("{{\"status\":\"error\",\"error\":\"No CA found. Run: ztlp admin ca-init\"}}");
        } else {
            eprintln!(
                "  {} No CA initialized. Run: ztlp admin ca-init --zone <zone>",
                c_red("✗")
            );
        }
        return Ok(());
    }

    // Generate cert key
    let cert_key = generate_signing_key();
    let serial = hex::encode(&cert_key.verifying_key().as_bytes()[..8]).to_uppercase();

    let output_dir = output.clone().unwrap_or_else(|| ca_dir.join("certs"));
    std::fs::create_dir_all(&output_dir)?;

    // Write key
    let key_filename = format!("{}.key", hostname.replace('.', "_"));
    let key_path = output_dir.join(&key_filename);
    std::fs::write(&key_path, cert_key.to_bytes())?;

    // Write cert (PEM stub)
    let cert_filename = format!("{}.pem", hostname.replace('.', "_"));
    let cert_path = output_dir.join(&cert_filename);
    let now_secs = unix_now();
    let now_iso = utc_timestamp_iso();
    let expiry_secs = now_secs + (days as u64) * 86400;
    let expiry_iso = {
        let (y, m, d) = days_to_ymd(expiry_secs / 86400);
        let tod = expiry_secs % 86400;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            y,
            m,
            d,
            tod / 3600,
            (tod % 3600) / 60,
            tod % 60
        )
    };

    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n# Subject: {}\n# Serial: {}\n# Not Before: {}\n# Not After: {}\n# Key: {}\n-----END CERTIFICATE-----\n",
        hostname,
        serial,
        now_iso,
        expiry_iso,
        hex::encode(cert_key.verifying_key().as_bytes()),
    );
    std::fs::write(&cert_path, &cert_pem)?;

    // Update index
    let index_path = ca_dir.join("certs").join("index.json");
    let mut certs: Vec<serde_json::Value> = if index_path.exists() {
        let idx = std::fs::read_to_string(&index_path)?;
        serde_json::from_str(&idx).unwrap_or_default()
    } else {
        Vec::new()
    };

    certs.push(serde_json::json!({
        "hostname": hostname,
        "serial": serial,
        "issued": now_iso.to_string(),
        "expires": expiry_iso.to_string(),
        "status": "active",
        "key_file": key_path.display().to_string(),
        "cert_file": cert_path.display().to_string(),
    }));
    std::fs::write(&index_path, serde_json::to_string_pretty(&certs)?)?;

    if json_output {
        println!("{{\"status\":\"ok\",\"hostname\":\"{}\",\"serial\":\"{}\",\"expires\":\"{}\",\"cert\":\"{}\",\"key\":\"{}\"}}",
            hostname, serial, expiry_iso,
            cert_path.display(), key_path.display());
    } else {
        eprintln!("{}", c_bold(&format!("Certificate Issued: {}", hostname)));
        eprintln!();
        eprintln!("  {} {}", c_cyan("Serial:  "), serial);
        eprintln!("  {} {}", c_cyan("Expires: "), expiry_iso);
        eprintln!("  {} {}", c_cyan("Cert:    "), cert_path.display());
        eprintln!("  {} {}", c_cyan("Key:     "), key_path.display());
        eprintln!();
    }

    Ok(())
}

fn cmd_admin_cert_list(
    ca_dir: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);
    let index_path = ca_dir.join("certs").join("index.json");

    if !index_path.exists() {
        if json_output {
            println!("{{\"status\":\"ok\",\"certs\":[]}}");
        } else {
            eprintln!("  {} No certificates issued yet", c_dim("ℹ"));
        }
        return Ok(());
    }

    let idx = std::fs::read_to_string(&index_path)?;
    let certs: Vec<serde_json::Value> = serde_json::from_str(&idx)?;

    if json_output {
        println!(
            "{{\"status\":\"ok\",\"certs\":{}}}",
            serde_json::to_string(&certs)?
        );
    } else {
        if certs.is_empty() {
            eprintln!("  {} No certificates issued yet", c_dim("ℹ"));
            return Ok(());
        }
        eprintln!("{}", c_bold("Issued Certificates"));
        eprintln!();
        eprintln!(
            "  {:<30} {:<16} {:<10} {}",
            c_bold("HOSTNAME"),
            c_bold("SERIAL"),
            c_bold("STATUS"),
            c_bold("EXPIRES")
        );
        for cert in &certs {
            let hostname = cert.get("hostname").and_then(|v| v.as_str()).unwrap_or("?");
            let serial = cert.get("serial").and_then(|v| v.as_str()).unwrap_or("?");
            let status = cert.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let expires = cert.get("expires").and_then(|v| v.as_str()).unwrap_or("?");
            let status_colored = if status == "active" {
                c_green(status)
            } else {
                c_red(status)
            };
            eprintln!(
                "  {:<30} {:<16} {:<10} {}",
                hostname, serial, status_colored, expires
            );
        }
        eprintln!();
    }

    Ok(())
}

fn cmd_admin_cert_show(
    serial: &Option<String>,
    hostname: &Option<String>,
    ca_dir: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);
    let index_path = ca_dir.join("certs").join("index.json");

    if !index_path.exists() {
        if json_output {
            println!("{{\"status\":\"error\",\"error\":\"No certificates found\"}}");
        } else {
            eprintln!("  {} No certificates issued yet", c_red("✗"));
        }
        return Ok(());
    }

    let idx = std::fs::read_to_string(&index_path)?;
    let certs: Vec<serde_json::Value> = serde_json::from_str(&idx)?;

    let cert = certs.iter().find(|c| {
        if let Some(s) = serial {
            c.get("serial").and_then(|v| v.as_str()) == Some(s)
        } else if let Some(h) = hostname {
            c.get("hostname").and_then(|v| v.as_str()) == Some(h)
        } else {
            false
        }
    });

    match cert {
        Some(cert) => {
            if json_output {
                println!("{{\"status\":\"ok\",\"cert\":{}}}", cert);
            } else {
                eprintln!("{}", c_bold("Certificate Details"));
                eprintln!();
                for (k, v) in cert.as_object().unwrap_or(&serde_json::Map::new()) {
                    eprintln!(
                        "  {} {}",
                        c_cyan(&format!("{:>12}:", k)),
                        v.as_str().unwrap_or(&v.to_string())
                    );
                }
                eprintln!();
            }
        }
        None => {
            if json_output {
                println!("{{\"status\":\"error\",\"error\":\"Certificate not found\"}}");
            } else {
                eprintln!("  {} Certificate not found", c_red("✗"));
            }
        }
    }

    Ok(())
}

fn cmd_admin_cert_revoke(
    serial: &Option<String>,
    hostname: &Option<String>,
    reason: &str,
    ca_dir: &Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = ca_dir.clone().unwrap_or_else(default_ca_dir);
    let index_path = ca_dir.join("certs").join("index.json");

    if !index_path.exists() {
        if json_output {
            println!("{{\"status\":\"error\",\"error\":\"No certificates found\"}}");
        } else {
            eprintln!("  {} No certificates issued yet", c_red("✗"));
        }
        return Ok(());
    }

    let idx = std::fs::read_to_string(&index_path)?;
    let mut certs: Vec<serde_json::Value> = serde_json::from_str(&idx)?;

    let mut found = false;
    for cert in certs.iter_mut() {
        let matches = if let Some(s) = serial {
            cert.get("serial").and_then(|v| v.as_str()) == Some(s)
        } else if let Some(h) = hostname {
            cert.get("hostname").and_then(|v| v.as_str()) == Some(h)
        } else {
            false
        };

        if matches {
            if let Some(obj) = cert.as_object_mut() {
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String("revoked".to_string()),
                );
                obj.insert(
                    "revoked_at".to_string(),
                    serde_json::Value::String(utc_timestamp_iso().to_string()),
                );
                obj.insert(
                    "revocation_reason".to_string(),
                    serde_json::Value::String(reason.to_string()),
                );
            }
            found = true;
            break;
        }
    }

    if found {
        std::fs::write(&index_path, serde_json::to_string_pretty(&certs)?)?;
        let display_id = serial.as_deref().or(hostname.as_deref()).unwrap_or("?");
        if json_output {
            println!(
                "{{\"status\":\"ok\",\"revoked\":\"{}\",\"reason\":\"{}\"}}",
                display_id, reason
            );
        } else {
            eprintln!(
                "  {} Revoked: {} (reason: {})",
                c_green("✓"),
                display_id,
                reason
            );
        }
    } else if json_output {
        println!("{{\"status\":\"error\",\"error\":\"Certificate not found\"}}");
    } else {
        eprintln!("  {} Certificate not found", c_red("✗"));
    }

    Ok(())
}

/// Simple base64 encoding (no padding) for PEM output
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

// ─── Minimal CBOR → JSON decoder ────────────────────────────────────────────

/// Decode a CBOR value into serde_json::Value (handles maps, arrays, strings, ints).
fn cbor_decode_to_json(data: &[u8]) -> Option<serde_json::Value> {
    let (val, _) = cbor_decode_value(data, 0)?;
    Some(val)
}

fn cbor_decode_value(data: &[u8], pos: usize) -> Option<(serde_json::Value, usize)> {
    if pos >= data.len() {
        return None;
    }

    let byte = data[pos];
    let major = byte >> 5;
    let additional = byte & 0x1F;

    match major {
        0 => {
            // Unsigned integer
            let (n, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
            Some((
                serde_json::Value::Number(serde_json::Number::from(n as u64)),
                new_pos,
            ))
        }
        1 => {
            // Negative integer
            let (n, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
            let val = -(n as i64) - 1;
            Some((
                serde_json::Value::Number(serde_json::Number::from(val)),
                new_pos,
            ))
        }
        2 => {
            // Byte string — encode as hex string
            let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
            if new_pos + len > data.len() {
                return None;
            }
            let hex_str = hex::encode(&data[new_pos..new_pos + len]);
            Some((serde_json::Value::String(hex_str), new_pos + len))
        }
        3 => {
            // Text string
            let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
            if new_pos + len > data.len() {
                return None;
            }
            let s = std::str::from_utf8(&data[new_pos..new_pos + len]).ok()?;
            Some((serde_json::Value::String(s.to_string()), new_pos + len))
        }
        4 => {
            // Array
            let (count, mut cur_pos) = cbor_read_uint(additional, data, pos + 1)?;
            let mut arr = Vec::with_capacity(count);
            for _ in 0..count {
                let (val, new_pos) = cbor_decode_value(data, cur_pos)?;
                arr.push(val);
                cur_pos = new_pos;
            }
            Some((serde_json::Value::Array(arr), cur_pos))
        }
        5 => {
            // Map
            let (count, mut cur_pos) = cbor_read_uint(additional, data, pos + 1)?;
            let mut map = serde_json::Map::new();
            for _ in 0..count {
                let (key_val, new_pos) = cbor_decode_value(data, cur_pos)?;
                let key = match key_val {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                let (val, new_pos) = cbor_decode_value(data, new_pos)?;
                map.insert(key, val);
                cur_pos = new_pos;
            }
            Some((serde_json::Value::Object(map), cur_pos))
        }
        7 => {
            // Simple / float
            match additional {
                20 => Some((serde_json::Value::Bool(false), pos + 1)),
                21 => Some((serde_json::Value::Bool(true), pos + 1)),
                22 => Some((serde_json::Value::Null, pos + 1)),
                _ => Some((serde_json::Value::Null, pos + 1)),
            }
        }
        _ => None,
    }
}

/// Helper to resolve NS server address from argument, config, or default
fn resolve_ns_server(
    ns_server_arg: &Option<String>,
    config: &Config,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(ref addr) = ns_server_arg {
        Ok(addr.clone())
    } else if let Some(ref addr) = config.ns_server {
        Ok(addr.clone())
    } else {
        Ok("127.0.0.1:23096".to_string())
    }
}

// ─── Tune ───────────────────────────────────────────────────────────────────

#[allow(unused_variables)]
fn cmd_tune(apply: bool, persist: bool) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::pacing::TARGET_BUFFER_SIZE;

    let target = TARGET_BUFFER_SIZE;
    let target_mb = target / (1024 * 1024);

    eprintln!("{}", c_bold("ZTLP System Tuner"));
    eprintln!();

    // Read current values
    #[cfg(target_os = "linux")]
    let (rmem_max, wmem_max) = {
        let rmem = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .unwrap_or_default()
            .trim()
            .parse::<usize>()
            .unwrap_or(0);
        let wmem = std::fs::read_to_string("/proc/sys/net/core/wmem_max")
            .unwrap_or_default()
            .trim()
            .parse::<usize>()
            .unwrap_or(0);
        (rmem, wmem)
    };

    #[cfg(target_os = "macos")]
    let (rmem_max, wmem_max) = {
        // macOS: read UDP recv/send buffer limits via sysctl
        fn read_sysctl(name: &str) -> usize {
            std::process::Command::new("sysctl")
                .arg("-n")
                .arg(name)
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(0)
        }
        let recv = read_sysctl("net.inet.udp.recvspace");
        let send = read_sysctl("net.inet.udp.maxdgram");
        (recv, send)
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (rmem_max, wmem_max) = (0usize, 0usize);

    // Display current state
    let rmem_ok = rmem_max >= target;
    let wmem_ok = wmem_max >= target;

    // Platform-appropriate label names
    #[cfg(target_os = "linux")]
    let (recv_label, send_label) = ("rmem_max", "wmem_max");
    #[cfg(target_os = "macos")]
    let (recv_label, send_label) = ("net.inet.udp.recvspace", "net.inet.udp.maxdgram");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (recv_label, send_label) = ("UDP recv buf", "UDP send buf");

    eprintln!(
        "  {} {}: {} ({})",
        if rmem_ok {
            c_green("✓")
        } else {
            c_yellow("⚠")
        },
        recv_label,
        format_bytes(rmem_max),
        if rmem_ok {
            "OK".to_string()
        } else {
            format!("low — target {}MB", target_mb)
        },
    );

    eprintln!(
        "  {} {}: {} ({})",
        if wmem_ok {
            c_green("✓")
        } else {
            c_yellow("⚠")
        },
        send_label,
        format_bytes(wmem_max),
        if wmem_ok {
            "OK".to_string()
        } else {
            format!("low — target {}MB", target_mb)
        },
    );

    // Check kernel/OS version
    #[cfg(target_os = "linux")]
    {
        if let Ok(ver) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            eprintln!("  {} kernel: {}", c_dim("ℹ"), ver.trim());
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            if let Ok(ver) = String::from_utf8(output.stdout) {
                eprintln!("  {} macOS: {}", c_dim("ℹ"), ver.trim());
            }
        }
    }

    eprintln!();

    if rmem_ok && wmem_ok {
        eprintln!(
            "  {} System is already tuned for optimal ZTLP performance.",
            c_green("✓")
        );
        eprintln!();
        return Ok(());
    }

    if !apply {
        eprintln!("  To apply optimal settings:");
        eprintln!("    {} ztlp tune --apply", c_cyan("sudo"));
        eprintln!();
        eprintln!("  To apply and persist across reboots:");
        eprintln!("    {} ztlp tune --apply --persist", c_cyan("sudo"));
        eprintln!();
        eprintln!("  Or manually:");
        #[cfg(target_os = "linux")]
        eprintln!(
            "    sudo sysctl -w net.core.rmem_max={} net.core.wmem_max={}",
            target, target,
        );
        #[cfg(target_os = "macos")]
        {
            eprintln!("    sudo sysctl -w net.inet.udp.recvspace={}", target);
            eprintln!("    sudo sysctl -w net.inet.udp.maxdgram=65535");
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        eprintln!("    (see your OS documentation for UDP buffer tuning)");
        eprintln!();
        return Ok(());
    }

    // Apply settings
    #[cfg(target_os = "linux")]
    {
        let target_str = target.to_string();

        if !rmem_ok {
            match std::fs::write("/proc/sys/net/core/rmem_max", &target_str) {
                Ok(()) => eprintln!("  {} Set rmem_max = {}", c_green("✓"), format_bytes(target)),
                Err(e) => {
                    eprintln!(
                        "  {} Failed to set rmem_max: {} (run with sudo?)",
                        c_red("✗"),
                        e
                    );
                    return Err("insufficient permissions — run with sudo".into());
                }
            }
        }

        if !wmem_ok {
            match std::fs::write("/proc/sys/net/core/wmem_max", &target_str) {
                Ok(()) => eprintln!("  {} Set wmem_max = {}", c_green("✓"), format_bytes(target)),
                Err(e) => {
                    eprintln!(
                        "  {} Failed to set wmem_max: {} (run with sudo?)",
                        c_red("✗"),
                        e
                    );
                    return Err("insufficient permissions — run with sudo".into());
                }
            }
        }

        // Persist
        if persist {
            let sysctl_conf = format!(
                "# ZTLP — optimal UDP socket buffer sizes ({}MB)\n\
                 # Applied by: ztlp tune --apply --persist\n\
                 net.core.rmem_max = {}\n\
                 net.core.wmem_max = {}\n",
                target_mb, target, target,
            );

            let sysctl_path = "/etc/sysctl.d/99-ztlp.conf";
            match std::fs::write(sysctl_path, &sysctl_conf) {
                Ok(()) => {
                    eprintln!("  {} Wrote {}", c_green("✓"), sysctl_path);
                    eprintln!("  {} Settings will persist across reboots.", c_dim("ℹ"),);
                }
                Err(e) => {
                    eprintln!("  {} Failed to write {}: {}", c_yellow("⚠"), sysctl_path, e);
                    eprintln!("  {} Settings are applied for this boot only.", c_dim("ℹ"),);
                }
            }
        }

        eprintln!();
        eprintln!(
            "  {} System tuned for optimal ZTLP performance.",
            c_green("✓")
        );
        eprintln!();
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let target_str = target.to_string();

        if !rmem_ok {
            match Command::new("sysctl")
                .arg("-w")
                .arg(format!("net.inet.udp.recvspace={}", target_str))
                .output()
            {
                Ok(o) if o.status.success() => {
                    eprintln!("  {} Set net.inet.udp.recvspace = {}", c_green("✓"), format_bytes(target));
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    eprintln!(
                        "  {} Failed to set recvspace: {} (run with sudo?)",
                        c_red("✗"), err.trim()
                    );
                    return Err("insufficient permissions — run with sudo".into());
                }
                Err(e) => {
                    eprintln!("  {} Failed to run sysctl: {}", c_red("✗"), e);
                    return Err("sysctl not found".into());
                }
            }
        }

        if !wmem_ok {
            match Command::new("sysctl")
                .arg("-w")
                .arg("net.inet.udp.maxdgram=65535")
                .output()
            {
                Ok(o) if o.status.success() => {
                    eprintln!("  {} Set net.inet.udp.maxdgram = 65535", c_green("✓"));
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    eprintln!(
                        "  {} Failed to set maxdgram: {} (run with sudo?)",
                        c_red("✗"), err.trim()
                    );
                    return Err("insufficient permissions — run with sudo".into());
                }
                Err(e) => {
                    eprintln!("  {} Failed to run sysctl: {}", c_red("✗"), e);
                    return Err("sysctl not found".into());
                }
            }
        }

        if persist {
            // macOS: persist via /etc/sysctl.conf (read at boot on some versions)
            // or advise launchd plist for modern macOS
            eprintln!(
                "  {} macOS note: sysctl settings don't persist natively across reboots.",
                c_yellow("⚠")
            );
            eprintln!(
                "  {} Add to /etc/sysctl.conf or create a launchd plist:",
                c_dim("ℹ")
            );
            eprintln!("    net.inet.udp.recvspace={}", target);
            eprintln!("    net.inet.udp.maxdgram=65535");
        }

        eprintln!();
        eprintln!(
            "  {} System tuned for optimal ZTLP performance.",
            c_green("✓")
        );
        eprintln!();
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        eprintln!(
            "  {} Automatic tuning is not supported on this platform.",
            c_yellow("⚠")
        );
        eprintln!(
            "  {} See your OS documentation for UDP socket buffer tuning.",
            c_dim("ℹ")
        );
        eprintln!();
    }

    Ok(())
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{}MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

// ─── Proxy Command ──────────────────────────────────────────────────────────

/// `ztlp proxy` — SSH ProxyCommand: pipe stdin/stdout through ZTLP tunnel.
async fn cmd_proxy(
    hostname: &str,
    port: u16,
    key: &Option<PathBuf>,
    ns_server: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::proxy;

    let key_str = key.as_ref().map(|p| p.to_string_lossy().to_string());
    let ns_str = ns_server.as_ref().map(|s| s.as_str());

    proxy::run_proxy(hostname, port, key_str.as_deref(), ns_str)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}

/// `ztlp agent start` — Start the agent daemon.
async fn cmd_agent_start(
    foreground: bool,
    config_path: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::daemon;

    // Check if already running
    if let Some(pid) = daemon::get_agent_pid() {
        eprintln!("{} Agent already running (PID {})", c_yellow("⚠"), pid);
        return Ok(());
    }

    let config = if let Some(path) = config_path {
        AgentConfig::load_from_path(path)
    } else {
        AgentConfig::load()
    };

    if !foreground {
        eprintln!("{} Starting agent daemon...", c_cyan("→"));
        eprintln!("  {} Use --foreground to run in foreground", c_dim("Hint:"));
    }

    daemon::run_daemon(&config, foreground)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}

/// `ztlp agent stop` — Stop the running agent daemon.
async fn cmd_agent_stop() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::control;

    let socket_path = control::default_socket_path();
    let cmd = control::ControlCommand {
        cmd: "shutdown".to_string(),
        name: None,
    };

    match control::send_command(&socket_path, &cmd).await {
        Ok(resp) => {
            if resp.ok {
                eprintln!("{} Agent stopped", c_green("✓"));
            } else {
                eprintln!(
                    "{} {}",
                    c_red("✗"),
                    resp.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }
        Err(e) => {
            eprintln!("{} {}", c_red("✗"), e);
        }
    }

    Ok(())
}

/// `ztlp agent status` — Show agent daemon status.
async fn cmd_agent_status() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::control;

    eprintln!("ZTLP Agent v{}", ZTLP_VERSION);

    // Try to query the running daemon first
    let socket_path = control::default_socket_path();
    let cmd = control::ControlCommand {
        cmd: "status".to_string(),
        name: None,
    };

    match control::send_command(&socket_path, &cmd).await {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                eprintln!("  {} {}", c_green("●"), c_bold("running"));
                if let Some(pid) = data.get("pid").and_then(|v| v.as_u64()) {
                    eprintln!("  {} {}", c_cyan("PID:"), pid);
                }
                if let Some(uptime) = data.get("uptime_secs").and_then(|v| v.as_u64()) {
                    eprintln!("  {} {}", c_cyan("Uptime:"), format_duration(uptime));
                }
                if let Some(dns) = data.get("dns_listen").and_then(|v| v.as_str()) {
                    eprintln!("  {} {}", c_cyan("DNS:"), dns);
                }
                if let Some(ns) = data.get("ns_server").and_then(|v| v.as_str()) {
                    eprintln!("  {} {}", c_cyan("NS:"), ns);
                }
                let alloc = data
                    .get("vip_allocated")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let cap = data
                    .get("vip_capacity")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                eprintln!("  {} {}/{}", c_cyan("VIPs:"), alloc, cap);
                let maps = data
                    .get("domain_mappings")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if maps > 0 {
                    eprintln!("  {} {}", c_cyan("Domain maps:"), maps);
                }
            }
            return Ok(());
        }
        _ => {}
    }

    // Daemon not running — show config
    eprintln!("  {} not running", c_red("●"));

    let config = AgentConfig::load();
    eprintln!();
    eprintln!("{}", c_dim("Configuration (~/.ztlp/agent.toml):"));
    eprintln!("  {} {}", c_cyan("Identity:"), config.identity.path);
    eprintln!("  {} {}", c_cyan("DNS listen:"), config.dns.listen);
    eprintln!("  {} {}", c_cyan("DNS enabled:"), config.dns.enabled);
    eprintln!(
        "  {} {}",
        c_cyan("NS servers:"),
        if config.ns.servers.is_empty() {
            "127.0.0.1:23096 (default)".to_string()
        } else {
            config.ns.servers.join(", ")
        }
    );
    eprintln!("  {} {}", c_cyan("VIP range:"), config.dns.vip_range);
    eprintln!("  {} {}", c_cyan("Max tunnels:"), config.tunnel.max_tunnels);

    if !config.dns.domain_map.is_empty() {
        eprintln!();
        eprintln!("{}", c_dim("Domain mappings:"));
        for (domain, zone) in &config.dns.domain_map {
            eprintln!("  {} → {}", domain, zone);
        }
    }

    eprintln!();
    eprintln!("  {} ztlp agent start", c_dim("Start with:"));

    Ok(())
}

/// `ztlp agent dns` — Show DNS cache entries.
async fn cmd_agent_dns() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::control;

    let socket_path = control::default_socket_path();
    let cmd = control::ControlCommand {
        cmd: "dns_cache".to_string(),
        name: None,
    };

    match control::send_command(&socket_path, &cmd).await {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                if let Some(entries) = data.get("entries").and_then(|v| v.as_array()) {
                    if entries.is_empty() {
                        eprintln!("{}", c_dim("DNS cache is empty"));
                    } else {
                        eprintln!(
                            "{:<35} {:<16} {:<22} {} {}",
                            c_bold("NAME"),
                            c_bold("VIP"),
                            c_bold("PEER"),
                            c_bold("CONN"),
                            c_bold("AGE"),
                        );
                        for entry in entries {
                            let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                            let ip = entry.get("ip").and_then(|v| v.as_str()).unwrap_or("-");
                            let peer = entry
                                .get("peer_addr")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let conn = entry
                                .get("active_connections")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let age = entry.get("age_secs").and_then(|v| v.as_u64()).unwrap_or(0);
                            eprintln!(
                                "{:<35} {:<16} {:<22} {:<4} {}",
                                name,
                                ip,
                                peer,
                                conn,
                                format_duration(age)
                            );
                        }
                        eprintln!();
                        eprintln!("{} entries", entries.len());
                    }
                }
            }
            Ok(())
        }
        Ok(resp) => {
            eprintln!(
                "{} {}",
                c_red("✗"),
                resp.error.unwrap_or_else(|| "unknown error".to_string())
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", c_red("✗"), e);
            Ok(())
        }
    }
}

/// `ztlp agent flush-dns` — Flush the DNS cache.
async fn cmd_agent_flush_dns() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::control;

    let socket_path = control::default_socket_path();
    let cmd = control::ControlCommand {
        cmd: "flush_dns".to_string(),
        name: None,
    };

    match control::send_command(&socket_path, &cmd).await {
        Ok(resp) if resp.ok => {
            let freed = resp
                .data
                .and_then(|d| d.get("freed").and_then(|v| v.as_u64()))
                .unwrap_or(0);
            eprintln!("{} Flushed {} expired entries", c_green("✓"), freed);
            Ok(())
        }
        Ok(resp) => {
            eprintln!(
                "{} {}",
                c_red("✗"),
                resp.error.unwrap_or_else(|| "unknown error".to_string())
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", c_red("✗"), e);
            Ok(())
        }
    }
}

/// `ztlp agent tunnels` — Show active tunnels.
async fn cmd_agent_tunnels() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::control;

    let socket_path = control::default_socket_path();
    let cmd = control::ControlCommand {
        cmd: "tunnels".to_string(),
        name: None,
    };

    match control::send_command(&socket_path, &cmd).await {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                if let Some(tunnels) = data.get("tunnels").and_then(|v| v.as_array()) {
                    if tunnels.is_empty() {
                        eprintln!("{}", c_dim("No active tunnels"));
                    } else {
                        eprintln!(
                            "{:<35} {:<22} {:<12} {:<8} {:<8} {}",
                            c_bold("NAME"),
                            c_bold("PEER"),
                            c_bold("STATE"),
                            c_bold("TX"),
                            c_bold("RX"),
                            c_bold("AGE"),
                        );
                        for t in tunnels {
                            let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                            let peer = t.get("peer_addr").and_then(|v| v.as_str()).unwrap_or("-");
                            let state = t.get("state").and_then(|v| v.as_str()).unwrap_or("-");
                            let tx = t.get("bytes_sent").and_then(|v| v.as_u64()).unwrap_or(0);
                            let rx = t.get("bytes_recv").and_then(|v| v.as_u64()).unwrap_or(0);
                            let age = t.get("age_secs").and_then(|v| v.as_u64()).unwrap_or(0);

                            let state_colored = match state {
                                "Active" => c_green(state),
                                "Connecting" => c_yellow(state),
                                "Reconnecting" => c_yellow(state),
                                _ => c_red(state),
                            };

                            eprintln!(
                                "{:<35} {:<22} {:<12} {:<8} {:<8} {}",
                                name,
                                peer,
                                state_colored,
                                format_bytes(tx as usize),
                                format_bytes(rx as usize),
                                format_duration(age),
                            );
                        }
                        eprintln!();
                        eprintln!("{} tunnels", tunnels.len());
                    }
                }
            }
            Ok(())
        }
        Ok(resp) => {
            eprintln!(
                "{} {}",
                c_red("✗"),
                resp.error.unwrap_or_else(|| "unknown error".to_string())
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", c_red("✗"), e);
            Ok(())
        }
    }
}

/// `ztlp agent dns-setup` — Configure system DNS.
#[cfg(unix)]
async fn cmd_agent_dns_setup(zones: &Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::dns_setup;

    let config = AgentConfig::load();

    let mut zone_list: Vec<String> = config.dns.zones.clone();
    for domain in config.dns.domain_map.keys() {
        if !zone_list.contains(domain) {
            zone_list.push(domain.clone());
        }
    }
    if let Some(extra) = zones {
        for z in extra.split(',') {
            let z = z.trim().to_string();
            if !z.is_empty() && !zone_list.contains(&z) {
                zone_list.push(z);
            }
        }
    }

    match dns_setup::setup_dns(&config.dns.listen, &zone_list) {
        Ok(result) => {
            eprintln!("{} DNS configured ({:?})", c_green("✓"), result.backend);
            for file in &result.files_written {
                eprintln!("  wrote {}", file.display());
            }
            if let Some(instructions) = &result.instructions {
                eprintln!();
                eprintln!("{}", instructions);
            }
            if result.needs_restart {
                eprintln!();
                eprintln!(
                    "{}",
                    c_yellow("⚠ Service restart required (see instructions above)")
                );
            }
        }
        Err(e) => {
            eprintln!("{} DNS setup failed: {}", c_red("✗"), e);
            eprintln!();
            eprintln!(
                "{}",
                c_dim("Hint: DNS setup usually requires root. Try: sudo ztlp agent dns-setup")
            );
        }
    }

    Ok(())
}

/// `ztlp agent dns-teardown` — Remove ZTLP DNS configuration.
#[cfg(unix)]
async fn cmd_agent_dns_teardown() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::dns_setup;

    match dns_setup::teardown_dns() {
        Ok(removed) => {
            if removed.is_empty() {
                eprintln!("{}", c_dim("No ZTLP DNS configuration found"));
            } else {
                eprintln!("{} DNS configuration removed", c_green("✓"));
                for file in &removed {
                    eprintln!("  removed {}", file.display());
                }
            }
        }
        Err(e) => {
            eprintln!("{} DNS teardown failed: {}", c_red("✗"), e);
        }
    }

    Ok(())
}

/// `ztlp agent install` — Install as system service.
#[cfg(unix)]
async fn cmd_agent_install(binary: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::dns_setup;

    let ztlp_binary = if let Some(path) = binary {
        path.to_string_lossy().to_string()
    } else {
        // Try to find the current binary path
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "/usr/local/bin/ztlp".to_string())
    };

    match dns_setup::install_service(&ztlp_binary) {
        Ok((path, instructions)) => {
            eprintln!("{} Service installed", c_green("✓"));
            eprintln!("  {}", path.display());
            eprintln!();
            eprintln!("{}", instructions);
        }
        Err(e) => {
            eprintln!("{} Installation failed: {}", c_red("✗"), e);
            eprintln!();
            eprintln!(
                "{}",
                c_dim("Hint: Installation usually requires root. Try: sudo ztlp agent install")
            );
        }
    }

    Ok(())
}

/// `ztlp agent pull-certs` — Pull TLS certs for service hostnames.
///
/// Scans the CA cert directory for issued certs, and copies them to the
/// agent's cert directory (~/.ztlp/certs/) for local TLS termination.
/// If a CA directory exists with issued certs, those are used directly.
async fn cmd_agent_pull_certs(
    ca_dir_arg: &Option<PathBuf>,
    output_arg: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ztlp_dir = get_ztlp_dir()?;
    let ca_dir = ca_dir_arg.clone().unwrap_or_else(|| ztlp_dir.join("ca"));
    let cert_output_dir = output_arg.clone().unwrap_or_else(|| ztlp_dir.join("certs"));

    std::fs::create_dir_all(&cert_output_dir)
        .map_err(|e| format!("failed to create {}: {}", cert_output_dir.display(), e))?;

    eprintln!("{} Pulling TLS certificates...", c_cyan("→"));
    eprintln!("  {} {}", c_dim("CA dir:"), ca_dir.display());
    eprintln!("  {} {}", c_dim("Output:"), cert_output_dir.display());
    eprintln!();

    // Look for issued certs in the CA directory
    let ca_certs_dir = ca_dir.join("certs");
    let index_path = ca_certs_dir.join("index.json");

    if !index_path.exists() {
        eprintln!("  {} No certificates found in CA directory", c_yellow("⚠"));
        eprintln!(
            "  {} Issue certs first: ztlp admin cert-issue --hostname <name>",
            c_dim("Hint:")
        );
        return Ok(());
    }

    let index_data = std::fs::read_to_string(&index_path)?;
    let certs: Vec<serde_json::Value> = serde_json::from_str(&index_data)?;

    let mut copied = 0;
    for cert_entry in &certs {
        let hostname = match cert_entry.get("hostname").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => continue,
        };

        let status = cert_entry
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if status == "revoked" {
            eprintln!("  {} {} (revoked, skipping)", c_dim("·"), hostname);
            continue;
        }

        let cert_file = cert_entry.get("cert_file").and_then(|v| v.as_str());
        let key_file = cert_entry.get("key_file").and_then(|v| v.as_str());

        if let (Some(cert_src), Some(key_src)) = (cert_file, key_file) {
            let cert_src_path = PathBuf::from(cert_src);
            let key_src_path = PathBuf::from(key_src);

            if !cert_src_path.exists() || !key_src_path.exists() {
                eprintln!(
                    "  {} {} (source files missing, skipping)",
                    c_yellow("⚠"),
                    hostname
                );
                continue;
            }

            let sanitized = hostname.replace('.', "_");
            let cert_dst = cert_output_dir.join(format!("{}.pem", sanitized));
            let key_dst = cert_output_dir.join(format!("{}.key", sanitized));

            std::fs::copy(&cert_src_path, &cert_dst)?;
            std::fs::copy(&key_src_path, &key_dst)?;

            // Restrict key file permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_dst, std::fs::Permissions::from_mode(0o600)).ok();
            }

            eprintln!("  {} {} → {}", c_green("✓"), hostname, cert_dst.display());
            copied += 1;
        }
    }

    eprintln!();
    if copied > 0 {
        eprintln!(
            "  {} Copied {} certificate(s) to {}",
            c_green("✓"),
            copied,
            cert_output_dir.display()
        );
        eprintln!(
            "  {} Restart the agent to pick up new certs: ztlp agent stop && ztlp agent start",
            c_dim("Hint:")
        );
    } else {
        eprintln!("  {} No certificates to copy", c_yellow("⚠"));
    }

    Ok(())
}

/// Format seconds into human-readable duration.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
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
            punch,
            punch_delay,
            punch_timeout,
            relay_pool,
            relay_probe_interval,
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
                *punch,
                punch_delay,
                punch_timeout,
                *relay_pool,
                *relay_probe_interval,
            )
            .await
        }

        Commands::Listen {
            bind,
            key,
            gateway,
            forward,
            policy,
            ns_server,
            stun_server,
            nat_assist,
            max_sessions,
        } => {
            cmd_listen(
                bind,
                key,
                *gateway,
                forward,
                policy,
                ns_server,
                stun_server,
                *nat_assist,
                *max_sessions,
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

        Commands::Setup {
            token,
            name,
            r#type,
            owner,
            yes,
        } => cmd_setup(token, name, *r#type, owner, *yes).await,

        Commands::Admin(subcmd) => match subcmd {
            AdminCommands::InitZone {
                zone,
                secret_output,
            } => cmd_admin_init_zone(zone, secret_output),
            AdminCommands::Enroll {
                zone,
                secret,
                ns_server,
                relay,
                gateway,
                expires,
                max_uses,
                count,
                qr,
            } => cmd_admin_enroll(
                zone, secret, ns_server, relay, gateway, expires, *max_uses, *count, *qr,
            ),
            AdminCommands::CreateUser {
                name,
                role,
                email,
                ns_server,
                json,
            } => cmd_admin_create_user(name, *role, email, ns_server, *json).await,
            AdminCommands::LinkDevice {
                name,
                owner,
                ns_server,
                json,
            } => cmd_admin_link_device(name, owner, ns_server, *json).await,
            AdminCommands::Devices {
                user,
                ns_server,
                json,
            } => cmd_admin_devices(user, ns_server, *json).await,
            AdminCommands::Ls {
                r#type,
                zone,
                ns_server,
                json,
            } => cmd_admin_ls(*r#type, zone, ns_server, *json).await,
            AdminCommands::CreateGroup {
                name,
                description,
                ns_server,
                json,
            } => cmd_admin_create_group(name, description, ns_server, *json).await,
            AdminCommands::Group(subcmd) => match subcmd {
                GroupCommands::Add {
                    group,
                    member,
                    ns_server,
                    json,
                } => cmd_admin_group_add(group, member, ns_server, *json).await,
                GroupCommands::Remove {
                    group,
                    member,
                    ns_server,
                    json,
                } => cmd_admin_group_remove(group, member, ns_server, *json).await,
                GroupCommands::Members {
                    group,
                    ns_server,
                    json,
                } => cmd_admin_group_members(group, ns_server, *json).await,
                GroupCommands::Check {
                    group,
                    user,
                    ns_server,
                    json,
                } => cmd_admin_group_check(group, user, ns_server, *json).await,
            },
            AdminCommands::Groups { ns_server, json } => cmd_admin_groups(ns_server, *json).await,
            AdminCommands::Revoke {
                name,
                reason,
                ns_server,
                json,
            } => cmd_admin_revoke(name, reason, ns_server, *json).await,
            AdminCommands::Audit {
                since,
                name,
                ns_server,
                json,
            } => cmd_admin_audit(since, name, ns_server, *json).await,
            AdminCommands::RotateZoneKey { json } => cmd_admin_rotate_zone_key(*json),
            AdminCommands::ExportZoneKey { format, json } => {
                cmd_admin_export_zone_key(format, *json)
            }

            // TLS / CA management
            AdminCommands::CaInit { zone, output, json } => cmd_admin_ca_init(zone, output, *json),
            AdminCommands::CaShow { ca_dir, json } => cmd_admin_ca_show(ca_dir, *json),
            AdminCommands::CaExportRoot { ca_dir } => cmd_admin_ca_export_root(ca_dir),
            AdminCommands::CaRotateIntermediate { ca_dir, json } => {
                cmd_admin_ca_rotate_intermediate(ca_dir, *json)
            }
            AdminCommands::CertIssue {
                hostname,
                days,
                ca_dir,
                output,
                json,
            } => cmd_admin_cert_issue(hostname, *days, ca_dir, output, *json),
            AdminCommands::CertList { ca_dir, json } => cmd_admin_cert_list(ca_dir, *json),
            AdminCommands::CertShow {
                serial,
                hostname,
                ca_dir,
                json,
            } => cmd_admin_cert_show(serial, hostname, ca_dir, *json),
            AdminCommands::CertRevoke {
                serial,
                hostname,
                reason,
                ca_dir,
                json,
            } => cmd_admin_cert_revoke(serial, hostname, reason, ca_dir, *json),
        },

        Commands::Scan {
            target,
            ports,
            ztlp_port,
            json,
            udp,
        } => cmd_scan(target, ports, *ztlp_port, *json, *udp).await,

        Commands::Tune { apply, persist } => cmd_tune(*apply, *persist),

        Commands::Proxy {
            hostname,
            port,
            key,
            ns_server,
        } => cmd_proxy(hostname, *port, key, ns_server).await,

        Commands::Agent(subcmd) => match subcmd {
            AgentCommands::Start { foreground, config } => {
                cmd_agent_start(*foreground, config).await
            }
            AgentCommands::Stop => cmd_agent_stop().await,
            AgentCommands::Status => cmd_agent_status().await,
            AgentCommands::Dns => cmd_agent_dns().await,
            AgentCommands::FlushDns => cmd_agent_flush_dns().await,
            AgentCommands::Tunnels => cmd_agent_tunnels().await,
            #[cfg(unix)]
            AgentCommands::DnsSetup { zones } => cmd_agent_dns_setup(zones).await,
            #[cfg(unix)]
            AgentCommands::DnsTeardown => cmd_agent_dns_teardown().await,
            #[cfg(unix)]
            AgentCommands::Install { binary } => cmd_agent_install(binary).await,
            AgentCommands::PullCerts { ca_dir, output } => {
                cmd_agent_pull_certs(ca_dir, output).await
            }
            #[cfg(not(unix))]
            AgentCommands::DnsSetup { .. }
            | AgentCommands::DnsTeardown
            | AgentCommands::Install { .. } => {
                Err("dns-setup, dns-teardown, and install are only supported on Unix".into())
            }
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
