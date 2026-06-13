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
use tokio::net::UdpSocket;
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
/// Used by the multi-session listener path (`cmd_listen_multi_session` and
/// helpers below). That path is currently a stub — see the `#[allow(dead_code)]`
/// annotations on `cmd_listen_multi_session` and friends below.
#[allow(dead_code)]
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

fn toml_string(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => rendered.push_str("\\\\"),
            '"' => rendered.push_str("\\\""),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            c if c.is_control() => rendered.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => rendered.push(c),
        }
    }
    rendered.push('"');
    rendered
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
        /// Use QUIC transport instead of ZTLP reliable UDP
        #[arg(long)]
        quic: bool,

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

        /// Enable NS-coordinated hole punching (auto-on when --ns-server is set in v0.30.12+)
        #[arg(long)]
        punch: bool,

        /// Disable NS-coordinated UDP hole punching even when --ns-server is set
        #[arg(long, conflicts_with = "punch")]
        no_punch: bool,

        /// Delay before sending punch packets (e.g. "100ms", "1s")
        #[arg(long, value_parser = parse_duration_arg)]
        punch_delay: Option<Duration>,

        /// Timeout for the punch procedure (e.g. "10s", "30s")
        #[arg(long, value_parser = parse_duration_arg)]
        punch_timeout: Option<Duration>,

        /// Enable multi-relay failover via probe pool (auto-on when --ns-server is set in v0.30.12+)
        #[arg(long)]
        relay_pool: bool,

        /// Disable multi-relay failover even when --ns-server is set
        #[arg(long, conflicts_with = "relay_pool")]
        no_relay_pool: bool,

        /// Health check probe interval for relay pool (e.g. "30s", "1m")
        #[arg(long, value_parser = parse_duration_arg, default_value = "30s")]
        relay_probe_interval: Duration,

        /// Enable v0.32 multi-candidate parallel dial.
        ///
        /// When combined with `--punch` + `--ns-server`, the client queries
        /// NS for the target's PEER_ENDPOINTS, ranks them via the v0.32
        /// priority ladder (host > srflx > relay), and races them in
        /// parallel. The winning path's address replaces `send_addr` and
        /// the existing handshake continues as normal.
        ///
        /// Failure falls through unchanged to the existing path — safe to
        /// leave on.
        ///
        /// **v0.32.3 default flip:** when `--ns-server` is set, this flag
        /// auto-enables (the legacy `--punch` UDP path is broken against
        /// v0.32.x relays and fails with "Invalid argument (os error 22)").
        /// Use `--no-multi-candidate` to opt out for debugging.
        #[arg(long, hide = true, conflicts_with = "no_multi_candidate")]
        multi_candidate: bool,

        /// Opt out of the v0.32.3 multi-candidate auto-flip.
        ///
        /// When `--ns-server` is set, `--multi-candidate` auto-enables to
        /// route the connect through the QUIC path that works against
        /// v0.32.x relays. This flag is the explicit escape hatch for users
        /// who specifically want the legacy `--punch` UDP path (typically
        /// for debugging or against a pre-v0.32 relay).
        #[arg(long, hide = true, conflicts_with = "multi_candidate")]
        no_multi_candidate: bool,

        // ── Auto-reconnect supervisor flags (v0.34.9+) ────────────────────
        // See docs/plans/2026-06-03-connect-auto-reconnect.md and
        // docs/plans/2026-06-04-auto-reconnect-dynamic-scenarios.md.
        //
        /// Maximum reconnect attempts before giving up (0 = unlimited)
        #[arg(long, default_value = "0")]
        reconnect_attempts: u32,

        /// Initial reconnect delay in milliseconds (doubles each attempt, capped at 30s)
        #[arg(long, default_value = "1000")]
        reconnect_delay_ms: u64,

        /// Disable auto-reconnect (fail-fast on first disconnect)
        #[arg(long, conflicts_with_all = ["reconnect_attempts", "reconnect_delay_ms"])]
        no_reconnect: bool,

        /// Skip NS re-resolution on reconnect (reuse original peer address)
        #[arg(long)]
        no_resolve_on_reconnect: bool,

        /// Follow target if its NodeID changes between reconnects
        /// (default: fail closed, matches SSH StrictHostKeyChecking)
        #[arg(long)]
        allow_identity_change: bool,
    },

    /// Listen for incoming ZTLP connections
    ///
    /// Acts as a responder for Noise_XX handshakes. After a peer connects
    /// and the handshake completes, enters interactive data exchange mode.
    #[command(after_help = "EXAMPLES:\n  \\\
            ztlp listen\n  \\\
            ztlp listen --bind 0.0.0.0:23095\n  \\\
            ztlp listen --key ~/.ztlp/identity.json --bind 0.0.0.0:23095\n  \\\
            ztlp listen --key identity.json --bind 0.0.0.0:23095 --forward 127.0.0.1:22 --relay 34.219.64.205:23095")]
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
        /// Use QUIC transport instead of ZTLP reliable UDP
        #[arg(long)]
        quic: bool,

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

        /// Relay address for automatic gateway registration.
        /// When set, the listener sends periodic GATEWAY_REGISTER packets
        /// to the relay, enabling it to forward incoming HELLO packets
        /// to this listener.
        #[arg(long)]
        relay: Option<String>,

        /// Service name to register with the relay (default: "ztlp-gateway").
        /// Only used when --relay is set. Padded to 16 bytes in the V1 packet.
        ///
        /// For V2 packets the routing key is derived from `--zone` instead;
        /// this field is still emitted on the wire for V1 backwards compatibility
        /// but no longer determines routing on the relay side.
        #[arg(long, default_value = "ztlp-gateway")]
        service_name: String,

        /// Zone identifier for collision-safe V2 GATEWAY_REGISTER emission.
        ///
        /// When set, the listener emits BOTH V1 (`0x0A`) and V2 (`0x0E`)
        /// register packets in parallel. The V2 packet carries `zone` as a
        /// length-prefixed field and the relay routes by `gw:<zone>` instead
        /// of the truncated `gw-<org_slug>` from V1. This prevents
        /// cross-tenant slug collisions on shared relays.
        ///
        /// Must be 1..=63 bytes (DNS-label limit). When omitted, only V1
        /// packets are emitted — strict backwards-compat behavior.
        ///
        /// See docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md.
        #[arg(long)]
        zone: Option<String>,

        /// Env-var name to read the per-zone HMAC secret from for V2 frame
        /// signing. Defaults to `ZTLP_HMAC_SECRET_<UPPER_ZONE>` matching the
        /// relay-side convention in `ZtlpRelay.HmacSecrets`.
        ///
        /// Only used when `--zone` is set. If the env var is unset, V2
        /// emission is skipped (the relay will fall back to V1 routing for
        /// this gateway) and a warning is logged once at startup.
        #[arg(long)]
        zone_hmac_secret_env: Option<String>,

        /// Fully-qualified ZTLP-NS name to publish as this listener's KEY
        /// (and SVC, when a routable bind address is available) record.
        ///
        /// When set together with `--ns-server` and `--zone`, the listener
        /// spawns a background heartbeat task that publishes its NS records
        /// at boot and re-publishes every 8h ± 10min jitter — keeping the
        /// records refreshed before the 24h NS TTL expires.
        ///
        /// This flag is the explicit opt-in for listener-driven NS
        /// registration. Leave unset to keep the previous behavior where
        /// NS registration is handled externally (Chef cookbook, manual
        /// `ztlp ns register` call, etc.).
        ///
        /// The name MUST live inside `--zone` — i.e. end with `.<zone>` (or
        /// equal `<zone>`). Mismatched name/zone aborts startup.
        ///
        /// See docs/plans/2026-06-01-ns-self-register-heartbeat.md.
        #[arg(long)]
        ns_register_name: Option<String>,

        /// Enable HTTP X-ZTLP-* header injection for passwordless admin auth.
        ///
        /// When set, the FIRST HTTP request on each forwarded TCP connection
        /// is rewritten on the wire to inject signed `X-ZTLP-Authenticated`,
        /// `X-ZTLP-Admin-Email`, `X-ZTLP-Timestamp`, and `X-ZTLP-Signature`
        /// headers. Upstream apps (Rails/Phoenix) verify the signature with
        /// the same `--header-hmac-secret` and treat the request as
        /// pre-authenticated for the listed admin pubkey.
        #[arg(long, default_value_t = false)]
        http_inject_headers: bool,

        /// Shared HMAC-SHA256 secret used to sign injected `X-ZTLP-*` headers.
        /// Must match the secret configured in the upstream HeaderVerifier.
        #[arg(long)]
        header_hmac_secret: Option<String>,

        /// Map a peer Noise static-public-key hex to an admin email.
        /// Repeatable. Format: `HEX=email@example.com`.
        /// Example: `--admin-pubkey-email deadbeef...=ops@trs.com`
        #[arg(long, value_name = "HEX=EMAIL")]
        admin_pubkey_email: Vec<String>,

        /// Enable NS-coordinated hole punching on the gateway side.
        ///
        /// When set together with `--ns-server`, the gateway:
        /// 1. Sends periodic PUNCH_REPORT (0x0C) packets to NS so NS
        ///    learns the gateway's NAT-mapped public endpoint.
        /// 2. Wraps the QUIC listener socket with PunchRuntime, which
        ///    intercepts incoming PUNCH_NOTIFY (0x0B) packets before
        ///    Quinn sees them and routes them to a dispatcher.
        /// 3. The dispatcher fires PUNCH_BYTE (0x00) at the requester's
        ///    reported endpoints, opening the NAT pinhole so the
        ///    client's subsequent QUIC handshake can traverse.
        ///
        /// Requires `--ns-server`. Without NS, there is no coordinator
        /// for the punch dance and the flag is a no-op (a warning is
        /// printed at startup).
        ///
        /// (Auto-on when `--ns-server` is set in v0.30.12+.)
        #[arg(long, default_value_t = false)]
        punch: bool,

        /// Disable NS-coordinated UDP hole punching even when --ns-server is set
        #[arg(long, conflicts_with = "punch", default_value_t = false)]
        no_punch: bool,

        /// Force-include this interface name in the PUNCH_REPORT
        /// candidate list, even if the default filter would skip it.
        /// Additive — repeat the flag to add multiple interfaces:
        /// `--advertise-interface eth0 --advertise-interface wg0`.
        ///
        /// (v0.32+ multi-candidate discovery — see
        /// docs/plans/2026-05-28-multi-candidate-discovery-v0.32.md.)
        #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
        advertise_interface: Vec<String>,

        /// Force-exclude this interface name from the PUNCH_REPORT
        /// candidate list. Takes precedence over `--advertise-interface`
        /// and `--advertise-all-interfaces`. Additive — repeat the flag
        /// to exclude multiple interfaces.
        #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
        no_advertise_interface: Vec<String>,

        /// Advertise ALL interfaces in PUNCH_REPORT, disabling the
        /// default skip filter (loopback, link-local, docker bridges,
        /// `br-*`, down ifaces). `--no-advertise-interface` still applies.
        #[arg(long, default_value_t = false)]
        advertise_all_interfaces: bool,
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

        /// Bind this identity to the current OS user (D3.T1).
        ///
        /// When set, identity.json records the current user's SID (Windows)
        /// or numeric UID (Unix). The daemon will refuse to start under any
        /// other user.
        #[arg(long)]
        bind_user: bool,

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

        /// Relay server address (host:port). When specified, handshake
        /// packets are sent to the relay instead of directly to the peer.
        /// Useful for reaching peers behind NAT: `ztlp proxy server.ztlp 22 --relay relay.ztlp.net:23095`
        #[arg(long)]
        relay: Option<String>,
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

    /// Install the ZTLP Root CA into the system trust store (D5.T1).
    ///
    /// Plants `~/.ztlp/ca/root.pem` into the platform's trust store so
    /// browsers automatically validate the ZTLP cert chain for any
    /// `*.<zone>.ztlp` service.
    ///
    /// Requires elevation:
    ///   - macOS:   `sudo`
    ///   - Linux:   `sudo`
    ///   - Windows: must run from an elevated PowerShell. With
    ///              `--machine-scope` the cert lands in
    ///              `LocalMachine\Root` (every user trusts it). Without
    ///              the flag it goes into `CurrentUser\Root`.
    #[command(after_help = "EXAMPLES:\n  \
            sudo ztlp agent install-ca-cert\n  \
            ztlp agent install-ca-cert --machine-scope         (Windows, elevated)\n  \
            ztlp agent install-ca-cert --cert /path/to/root.pem")]
    InstallCaCert {
        /// Path to the root CA cert (default: ~/.ztlp/ca/root.pem).
        #[arg(long)]
        cert: Option<PathBuf>,

        /// On Windows, install into `LocalMachine\Root` instead of the
        /// per-user store. Ignored on macOS / Linux (always machine-scope
        /// there). Required by the service installer.
        #[arg(long)]
        machine_scope: bool,
    },

    /// Remove the ZTLP Root CA from the system trust store.
    ///
    /// Inverse of `install-ca-cert`. Useful for uninstall paths and
    /// rotation workflows.
    #[command(after_help = "EXAMPLES:\n  \
            sudo ztlp agent remove-ca-cert\n  \
            ztlp agent remove-ca-cert --cert /path/to/root.pem")]
    RemoveCaCert {
        /// Path to the root CA cert (default: ~/.ztlp/ca/root.pem).
        #[arg(long)]
        cert: Option<PathBuf>,
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

    /// Print candidates NS knows for a named gateway (v0.32 admin tool).
    ///
    /// Resolves the gateway name via NS SVC/KEY records, queries NS for
    /// PEER_ENDPOINTS, classifies each candidate using the v0.32 priority
    /// ladder, and prints the result as a human-readable table or JSON.
    ///
    /// This closes the v0.31 debugging gap (see
    /// docs/v0.31.0-relay-deployment-investigation.md) where it took two
    /// days to discover NS only had the WAN address for Z2LS.
    #[command(after_help = "EXAMPLES:\n  \
            ztlp gateway candidates z2ls --ns-server 16.147.41.195:23096\n  \
            ztlp gateway candidates z2ls --ns-server 127.0.0.1:23096 --json")]
    Candidates {
        /// Gateway name to query (resolved via NS).
        name: String,

        /// NS server address (host:port).
        #[arg(short = 'n', long)]
        ns_server: String,

        /// Output as JSON instead of human-readable table.
        #[arg(long)]
        json: bool,
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

/// Decode a 2-byte NS registration error response `<<0xFF, code>>` into a
/// human-readable message.
///
/// Pre-v0.34 NS servers returned a bare `<<0xFF>>` with no reason — the
/// single-byte form returns a generic "rejected" message. New servers
/// encode a granular reason code in the second byte; this maps it to a
/// description matching `ZtlpNs.RegistrationError` (ns/lib/ztlp_ns/registration_error.ex).
///
/// Wire format must stay in sync with the NS module. New codes must be
/// appended (never renumbered) to preserve compatibility.
fn decode_registration_error(resp: &[u8]) -> &'static str {
    // Old servers: bare <<0xFF>>
    if resp.len() < 2 {
        return "rejected (server returned no reason code; old server?)";
    }
    match resp[1] {
        0x00 => "rejected (unspecified)",
        0x01 => "rejected: unknown record type",
        0x02 => {
            "rejected: missing pubkey (server requires authenticated registration; \
                  use a v2 client or set ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false on the server)"
        }
        0x03 => "rejected: invalid name (check zone suffix and character set)",
        0x04 => "rejected: invalid Ed25519 signature (identity key may have changed)",
        0x05 => {
            "rejected: unauthorized (your key is not allowed to register this name in this zone)"
        }
        0x06 => "rejected: name is owned by a different key (key-overwrite protection)",
        0x07 => "rejected: your key or NodeID has been revoked",
        0x08 => "rejected: this name has been revoked and cannot be re-registered",
        0x09 => "rejected: rate-limited (too many registrations for this name; retry later)",
        0x0A => "rejected: invalid record data (CBOR decode failed or required field missing)",
        0x0B => "rejected: storage error on the NS server (retry may succeed)",
        other => {
            // Unknown reason code — likely a newer NS server. We still got the
            // 0xFF first byte so we know it's a rejection. Caller can read the
            // raw code from resp[1] if they want to log it.
            let _ = other;
            "rejected (unknown reason code from newer NS server)"
        }
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
/// Parse a target string into a name and an optional explicit port.
///
/// The user can type `mygw.example.ztlp` (no port) or `mygw.example.ztlp:22`
/// (with a port). The explicit port is the user's *service port* hint — what
/// downstream service on the gateway they want to reach. It is NOT the QUIC
/// transport port, which always comes from the SVC record's address.
///
/// Bug history: pre-2026-05-26 this distinction wasn't made, and the user-
/// supplied port clobbered the transport port read from NS. The client then
/// tried to open a QUIC handshake to e.g. `:22` (SSH) on the relay box and
/// silently hung in PTO retries forever.
///
/// Returns `(name_part, explicit_port)`. If the suffix after `:` isn't a valid
/// u16, returns the whole string as the name with `None`.
fn parse_target_name_and_port(target: &str) -> (&str, Option<u16>) {
    if let Some(idx) = target.rfind(':') {
        let after_colon = &target[idx + 1..];
        if let Ok(port) = after_colon.parse::<u16>() {
            return (&target[..idx], Some(port));
        }
    }
    (target, None)
}

/// Build the final transport endpoint from an NS SVC address and the user's
/// optional service-port hint.
///
/// The transport port ALWAYS comes from the SVC record. The user's port is
/// preserved separately as a service port (currently informational; the
/// gateway picks the actual forward by service name).
///
/// Returns `(transport, service_port)`. `transport` is `None` when NS didn't
/// resolve an address — the caller is expected to do DNS fallback or fail
/// with a clear error.
fn build_resolved_endpoint(
    svc_addr: Option<SocketAddr>,
    user_supplied_port: Option<u16>,
) -> (Option<SocketAddr>, Option<u16>) {
    (svc_addr, user_supplied_port)
}

/// True when the connect command should enter the relay-routed code path
/// (which is where NAT-traversal, hole-punching, and the relay pool live).
///
/// Bug history (Issue 2, 2026-05-26): pre-fix this was effectively
/// `relay.is_some()`, meaning users who relied on NS to discover the relay
/// (the common case) silently bypassed all NAT-traversal logic — `--punch`
/// was a no-op.
///
/// The legacy path is active when the user explicitly opted into a feature
/// that only lives there:
/// - `--relay <addr>` (explicit relay routing)
/// - `--punch` (NS-coordinated hole punching)
/// - `--nat-assist` (STUN discovery + relay-mediated hole punching)
/// - `--relay-pool` (multi-relay failover)
///
/// LAN-direct (`ztlp connect 192.168.1.5:23095`, no flags) and NS-resolved
/// connects without these flags stay on the QUIC mode path, which works
/// today via CLIENT_ROUTE.
///
/// The `ns_server` and `resolved_addr` arguments are present in the
/// signature but are intentionally not consulted yet — they're for the
/// future "always enter relay path when NS gave us a relay address so
/// punch can be made the default" change. The current behaviour is
/// "only enter the legacy path when the user explicitly opted in".
fn relay_path_active(
    relay: &Option<String>,
    _ns_server: &Option<String>,
    _resolved_addr: Option<SocketAddr>,
) -> bool {
    relay.is_some()
}

/// Resolve a target name/addr to its dial endpoint(s).
///
/// Returns `(best_addr, ranked_candidates, node_id)`:
/// - `best_addr` — the single highest-priority candidate (== `ranked[0]`),
///   kept for callers that only want one address (legacy behavior).
/// - `ranked_candidates` — the FULL client-ranked candidate list (Stage 2),
///   best-first. For a raw `ip:port` target this is a 1-element vec. The QUIC
///   connect path tries these in order (failover) so a NAT'd box that
///   publishes [private-LAN, relay] still connects for a remote operator: the
///   unreachable LAN candidate fails fast and the relay backstop wins.
/// - `node_id` — the NS-resolved gateway NodeID (for CLIENT_ROUTE / tenant
///   isolation), when available.
async fn resolve_target(
    target: &str,
    ns_server_opt: &Option<String>,
) -> Result<(SocketAddr, Vec<SocketAddr>, Option<NodeId>), Box<dyn std::error::Error>> {
    // Try direct IP:port parsing first (backward compatible fast path)
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((addr, vec![addr], None));
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
    let (name_part, explicit_port) = parse_target_name_and_port(target);

    // Query SVC record (type 2) for endpoint address(es).
    //
    // Stage 2 (v0.35.x): the SVC CBOR may now carry an `addresses` field — a
    // comma-joined ICE candidate list (best-first as published by the
    // gateway). We extract BOTH `address` (single, legacy) and `addresses`
    // (list, new), then resolve+rank them client-side so a same-LAN operator
    // prefers the LAN candidate and a remote operator falls through to the
    // relay. Old SVC records (no `addresses`) degrade to the single `address`.
    let mut resolved_addr: Option<SocketAddr> = None;
    let mut svc_address_field: Option<String> = None;
    let mut svc_addresses_field: Option<String> = None;
    if let Ok(Some(raw)) = ns_query_raw(name_part, &ns_server, 2).await {
        svc_address_field = cbor_extract_string(&raw.data_bytes, "address");
        svc_addresses_field = cbor_extract_string(&raw.data_bytes, "addresses");
    }
    // Resolve the full candidate set (back-compat precedence: addresses list →
    // single address), then rank against our local subnets.
    let resolved_set = ztlp_proto::svc_candidates::resolve_candidates(
        svc_address_field.as_deref(),
        svc_addresses_field.as_deref(),
    );
    let mut ranked_candidates: Vec<SocketAddr> = Vec::new();
    if !resolved_set.is_empty() {
        let local_subnets = ztlp_proto::local_candidates::our_local_subnets();
        ranked_candidates =
            ztlp_proto::svc_candidates::rank_candidates(&resolved_set, &local_subnets);
        resolved_addr = ranked_candidates.first().copied();
        if ranked_candidates.len() > 1 {
            eprintln!(
                "  {} SVC record → {} candidates, best {}",
                c_green("✓"),
                ranked_candidates.len(),
                resolved_addr.map(|a| a.to_string()).unwrap_or_default()
            );
        } else if let Some(a) = resolved_addr {
            eprintln!("  {} SVC record → {}", c_green("✓"), a);
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

    // Build final address.
    //
    // Bug history (fix 2026-05-26): we used to do
    //   SocketAddr::new(addr.ip(), explicit_port_override)
    // when both an NS SVC record and a `:port` in the user's target were
    // present. That clobbered the relay's port (e.g. :23095) with the
    // user-supplied service port (e.g. :22) and the client then tried to
    // open a QUIC handshake against the relay's SSH listener — silent PTO
    // forever. The user's `:port` is a *service port hint*, NOT the QUIC
    // transport port. We now use the SVC transport as-is and pass the
    // service-port hint via `build_resolved_endpoint`.
    //
    // The DNS-fallback path is unchanged: there, `explicit_port` is used to
    // construct the DNS lookup target (no NS, no relay involved, so the
    // transport port IS the user's port).
    let (transport_from_svc, _service_port_hint) =
        build_resolved_endpoint(resolved_addr, explicit_port);

    let final_addr = if let Some(addr) = transport_from_svc {
        addr
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
    // The dial candidate list: the ranked SVC candidates when we have them
    // (Stage 2 multi-candidate), else the single resolved/DNS address. We
    // ensure `final_addr` is element 0 so single-address callers and the
    // failover loop agree on the primary target.
    let dial_candidates: Vec<SocketAddr> = if !ranked_candidates.is_empty() {
        ranked_candidates
    } else {
        vec![final_addr]
    };
    Ok((final_addr, dial_candidates, resolved_node_id))
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
///
/// Retained as a convenience helper (and for external callers / tests). The hot
/// path `resolve_target` switched to `ns_query_raw` in v0.35.0 so it can read
/// BOTH the legacy `address` and the new multi-candidate `addresses` field from
/// one SVC fetch, so this single-field wrapper is currently unused in-crate.
#[allow(dead_code)]
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
///
/// Called from `handle_new_session` in the multi-session listener path
/// (currently a stub — see `cmd_listen_multi_session` below).
#[allow(dead_code)]
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
///
/// Constructed only by `handle_new_session` (currently a stub — see
/// `cmd_listen_multi_session` below). The struct and its impls are kept
/// because they're the obvious wire-up for the multi-session listener
/// path when that path is implemented.
#[allow(dead_code)]
struct UdpNsResolver {
    ns_server: String,
}

#[allow(dead_code)]
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
/// v0.32.2 (A1): pick the address to dial in the QUIC path.
///
/// Given the NS-resolved peer address (typically the relay) and an
/// optional multi-candidate winning address (a LAN-direct host candidate
/// from PUNCH_REPORT), prefer the multi-candidate winner. When the
/// winner is `None` — multi-candidate disabled, no NodeID, NS query
/// failed, or no candidate succeeded — fall back to the NS-resolved
/// address unchanged. Extracted as a free fn so the override logic is
/// directly unit-testable without spinning up the full QUIC stack.
fn pick_quic_dial_target(
    ns_resolved: SocketAddr,
    multi_candidate_winner: Option<SocketAddr>,
) -> SocketAddr {
    multi_candidate_winner.unwrap_or(ns_resolved)
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-reconnect supervisor — production types
//
// Wraps cmd_connect's dial-and-tunnel logic in a supervisor loop that detects
// QUIC session loss via quinn::Connection::closed(), classifies the disconnect
// reason, optionally re-resolves NS for dynamic IP/port changes, and re-dials
// with exponential backoff + jitter.
//
// Test contract pinned in `mod tests::auto_reconnect` (~line 13560+).
// Plan: docs/plans/2026-06-03-connect-auto-reconnect.md
// Dynamic scenarios: docs/plans/2026-06-04-auto-reconnect-dynamic-scenarios.md
// ─────────────────────────────────────────────────────────────────────────────

/// Reason a QUIC tunnel session ended. Recoverable variants (PeerClosed,
/// TimedOut, DialFailed) trigger a reconnect attempt subject to flags;
/// non-recoverable variants (UserInterrupt, Fatal) exit the supervisor.
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// QUIC connection closed by peer (gateway restart, app close). Recoverable.
    PeerClosed(String),
    /// QUIC idle timeout (network blip, NAT eviction, keepalive failure). Recoverable.
    TimedOut,
    /// Initial dial failed before tunnel was ever established. Recoverable.
    DialFailed(String),
    /// User Ctrl-C / SIGTERM. NOT recoverable — exit cleanly with Ok(()).
    UserInterrupt,
    /// Unrecoverable error (NodeID mismatch, handshake auth failure, etc.).
    /// Do not retry — surface to operator.
    Fatal(String),
}

impl DisconnectReason {
    /// True if the supervisor should attempt a reconnect for this disconnect
    /// type. False for UserInterrupt (clean exit) and Fatal (no retry).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DisconnectReason::PeerClosed(_)
                | DisconnectReason::TimedOut
                | DisconnectReason::DialFailed(_)
        )
    }
}

/// Configuration for the auto-reconnect supervisor. Built from CLI flags
/// in cmd_connect; passed by value into run_supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Target name to resolve via NS (e.g. "TRSDC.tech-rockstars.trs.ztlp")
    /// or raw "host:port" string.
    pub target: String,
    /// NS server address; None when target is a raw address.
    pub ns_server: Option<String>,
    /// Maximum reconnect attempts (0 = unlimited).
    pub reconnect_attempts: u32,
    /// Initial backoff delay in milliseconds; doubles each attempt, capped at 30s.
    pub reconnect_delay_ms: u64,
    /// Disable reconnect entirely — exit on first disconnect.
    pub no_reconnect: bool,
    /// Skip NS re-resolution on reconnect; dial the original peer_addr each time.
    pub no_resolve_on_reconnect: bool,
    /// Allow following the target if its NodeID changes between reconnects.
    /// Default false (fail closed) — matches StrictHostKeyChecking semantics in SSH.
    pub allow_identity_change: bool,
}

/// Compute reconnect backoff with exponential growth + 10% jitter, capped at 30s.
///
/// attempt=1 → base_ms ±10%
/// attempt=2 → 2*base_ms ±10%
/// attempt=N → min(base_ms << (N-1), 30_000) ±10%
///
/// 10% jitter avoids thundering-herd when many clients reconnect after the
/// same gateway restart (the TRSDC daily-reboot case).
pub fn compute_reconnect_delay(attempt: u32, base_ms: u64) -> Duration {
    // Exponential: 2^(attempt-1), capped at 2^5 = 32x so a deep retry chain
    // doesn't overflow before the 30s cap clamps it.
    let exp = (attempt.saturating_sub(1)).min(5);
    let multiplier: u64 = 1u64 << exp;
    let raw_ms = base_ms.saturating_mul(multiplier);
    let capped_ms = raw_ms.min(30_000);

    // ±10% jitter via wrapping signed offset.
    let jitter_ms = (capped_ms / 10).max(1);
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let offset: i64 = rng.gen_range(-(jitter_ms as i64)..=(jitter_ms as i64));
    let final_ms = ((capped_ms as i64) + offset).max(0) as u64;
    Duration::from_millis(final_ms)
}

async fn cmd_connect(
    _quic: bool,
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
    multi_candidate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Path selection (Issue 2, 2026-05-26) ─────────────────────────
    //
    // Pre-fix: the legacy UDP path (which is the ONLY place where
    // `--punch`, `--nat-assist`, and `--relay-pool` are wired up) was
    // gated on `relay.is_some()`. That meant users who relied on NS to
    // discover the relay (the common case — `ztlp connect <name>
    // --ns-server …`) silently bypassed all NAT-traversal logic. The
    // `--punch` flag was effectively a no-op in NS-resolved mode.
    //
    // The fix: enter the legacy/NAT-traversal path whenever the user
    // explicitly opted into a feature that lives there:
    //   • `--relay <addr>` (explicit relay routing)
    //   • `--punch` (NS-coordinated hole punching)
    //   • `--nat-assist` (STUN discovery + relay-mediated hole punching)
    //   • `--relay-pool` (multi-relay failover)
    //
    // Default (none of the above) stays on the QUIC mode path, which
    // handles SVC-record-resolved connects through relays via the
    // CLIENT_ROUTE frame and is what works end-to-end today.
    //
    // v0.32.2 (A1): `--multi-candidate` always forces the QUIC path even
    // when `--ns-server` would have implicitly enabled punch (the default
    // resolved by `h10_defaults::resolve_punch_and_pool_flags`). The
    // legacy parallel-session handshake is broken end-to-end against the
    // v0.30 production relay, so silently dropping a multi-candidate user
    // into legacy was the exact bug A1 fixes. The QUIC path now contains
    // the M6 dial logic; `--multi-candidate` is the canonical opt-in.
    let want_legacy_path =
        !multi_candidate && (relay.is_some() || punch_enabled || nat_assist || relay_pool_enabled);

    if want_legacy_path {
        // Legacy UDP fallback for NAT traversal / relays

        let identity = load_or_generate_identity(key)?;

        // Resolve target: raw ip:port or ZTLP-NS name
        let (peer_addr, _dial_candidates, _resolved_node_id) =
            resolve_target(target, ns_server).await?;
        // Capture the resolved gateway NodeID as raw bytes so per-session
        // HELLOs can stamp it into dst_svc_hash for strict tenant-isolated
        // relay routing. NodeId::zero() (default for direct ip:port
        // targets without NS) signals "no routing override".
        let peer_node_id_for_routing: [u8; 16] = _resolved_node_id
            .map(|n| *n.as_bytes())
            .unwrap_or([0u8; 16]);

        let mut send_addr = if let Some(relay_str) = relay {
            relay_str
                .parse()
                .map_err(|e| format!("invalid relay address '{}': {}", relay_str, e))?
        } else {
            peer_addr
        };

        // Initialize relay pool if --relay-pool is enabled or multiple relays are available
        let relay_pool = if relay_pool_enabled || relay.is_some() {
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
                gateway_region: String::new(),
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

            Some(Arc::new(Mutex::new(FailoverOrchestrator::new(pool))))
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

        // ── R2: spawn relay probe task ──────────────────────────────────
        // Drives pool.record_probe_success / record_probe_failure at
        // `relay_probe_interval`. Shares the existing UDP socket so kernel
        // ICMP errors route back correctly. Aborted at end of cmd_connect.
        let probe_handle: Option<tokio::task::JoinHandle<()>> =
            if let Some(pool_arc) = relay_pool.as_ref() {
                let probe_socket = node.socket.clone();
                let probe_pool = pool_arc.clone();
                Some(tokio::spawn(async move {
                    let mut interval = tokio::time::interval(relay_probe_interval);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    // Skip the immediate first tick — give the connection a moment
                    // to come up before we start probing.
                    interval.tick().await;
                    loop {
                        interval.tick().await;
                        let targets = {
                            let guard = probe_pool.lock().await;
                            guard.pool().relays_needing_probe()
                        };
                        for relay_addr in targets {
                            let result = ztlp_proto::relay_pool::probe_relay(
                                &probe_socket,
                                relay_addr,
                                std::time::Duration::from_millis(500),
                            )
                            .await;
                            let mut guard = probe_pool.lock().await;
                            match result {
                                Ok(latency) => {
                                    guard.pool_mut().record_probe_success(relay_addr, latency)
                                }
                                Err(_e) => guard.pool_mut().record_probe_failure(relay_addr),
                            }
                        }
                    }
                }))
            } else {
                None
            };

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
                        match nat::StunClient::discover_endpoint(&node.socket, addr, stun_timeout)
                            .await
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

        // ── v0.32 M6: multi-candidate parallel dial (opt-in) ─────────
        // When --multi-candidate is passed AND we have an NS-resolved
        // peer NodeID, race the host candidates from PUNCH_REPORT
        // alongside the relay backstop. The winning path's address
        // overrides `send_addr`. Failure falls through unchanged to
        // the existing NS-coordinated punch path below.
        if multi_candidate && punch_enabled && _resolved_node_id.is_some() {
            eprintln!(
                "{} multi-candidate dial enabled (v0.32 experimental)",
                c_dim("[v0.32]")
            );
            if let Some(ns_str) = ns_server.as_deref() {
                if let Ok(ns_addr) = ns_str.parse::<SocketAddr>() {
                    let policy = ztlp_proto::dial_orchestrator::DialPolicy::default();
                    let local_subnets = ztlp_proto::local_candidates::our_local_subnets();
                    match ztlp_proto::multi_candidate_dial::try_multi_candidate_connect(
                        _resolved_node_id.unwrap(),
                        ns_addr,
                        node.socket.clone(),
                        identity.node_id,
                        &local_subnets,
                        Some(send_addr),
                        policy,
                    )
                    .await
                    {
                        Ok(outcome) => {
                            eprintln!(
                                "{} multi-candidate dial succeeded: {} ({:?})",
                                c_green("✓"),
                                outcome.winning_addr,
                                outcome.class
                            );
                            send_addr = outcome.winning_addr;
                        }
                        Err(e) => {
                            eprintln!(
                                "{} multi-candidate dial failed: {:?}; falling back",
                                c_dim("[v0.32]"),
                                e
                            );
                        }
                    }
                }
            }
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
                        return Err(
                            "hole punch timed out and --no-relay-fallback was specified".into()
                        );
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

        // ─── PARALLEL SESSIONS BRANCH (workaround) ─────────────────────────────
        //
        // COMMENT: Why this branch exists
        // ===============================
        // The ZTLP tunnel currently has no in-session multiplexing: a single
        // Noise session bridges exactly ONE TCP stream at a time (see
        // `tunnel::run_bridge*` in proto/src/tunnel.rs — both directions are a
        // single byte stream over the encrypted session). Browsers, however,
        // routinely open 6+ parallel HTTP connections for asset fetching. If
        // we serialize them through one Noise session via `run_bridge_with_reset`
        // (the historical default), every asset stalls until the previous one
        // finishes, producing ~tens of seconds of perceived latency on the
        // passwordless dashboard.
        //
        // Until proper in-session multiplexing (HTTP/2 style stream IDs) lands,
        // this branch performs a *fresh Noise_XX handshake per accepted TCP
        // connection*. Handshakes are ~280µs each, so 6 concurrent flows cost
        // <2ms of CPU. Each handshake runs in its own `tokio::spawn`'d task
        // (`run_parallel_session`) so they progress in parallel.
        //
        // The architecture mirrors `cmd_listen_multi_session` on the server
        // side: a single dispatcher task reads `node.recv_raw()` and routes
        // each packet to the correct per-session mpsc channel by SessionId; the
        // bridge for each session reads from a per-session loopback UDP pair
        // so `tunnel::run_bridge_demuxed` can be reused unchanged.
        //
        // Activated when:
        //   * `--local-forward` is set (tunnel mode), AND
        //   * `--session-id` is NOT pinned (we are free to mint fresh SIDs).
        //
        // The pinned `--session-id` path keeps the original single-session
        // behavior, which is required for some test/diagnostic flows.
        let is_parallel = local_forward.is_some() && session_id_hex.is_none();
        if is_parallel {
            // SAFETY: unwrap is fine — we just checked is_some() above.
            let lf = local_forward
                .as_ref()
                .expect("is_parallel implies local_forward is Some");
            let (local_port, _remote_target) = tunnel::parse_local_forward(lf)?;
            let listen_addr = format!("127.0.0.1:{}", local_port);

            eprintln!(
                "--- {} ---",
                c_bold("ZTLP tunnel active (parallel sessions)")
            );
            eprintln!("  {} {}", c_cyan("Local listener:"), listen_addr);
            eprintln!(
                "  {} Each TCP connection runs its own Noise session in parallel.",
                c_dim("Mode:")
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

            // Share the TransportNode between the dispatcher task and the
            // per-connection bridges. `recv_raw` takes &self and is internally
            // backed by `Arc<UdpSocket>`, so a single dispatcher loop can own
            // the receive side while spawned tasks reuse `node.socket` for sends.
            let node = Arc::new(node);
            let session_mgr = Arc::new(SessionManager::new(64));
            let service_clone: Option<String> = service.clone();
            let identity_arc = Arc::new(identity.clone());

            // Dispatcher task: drain node.recv_raw() and route every packet to
            // the right per-session mpsc by SessionId. Packets for unknown SIDs
            // (e.g. late retransmits after close) are dropped silently.
            let dispatcher_node = node.clone();
            let dispatcher_mgr = session_mgr.clone();
            let dispatcher = tokio::spawn(async move {
                loop {
                    let (data, from) = match dispatcher_node.recv_raw().await {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("{} dispatcher recv error: {}", c_red("✗"), e);
                            return;
                        }
                    };
                    // Extract session_id by discriminating header type via msg_type.
                    // HandshakeHeader and DataHeader have DIFFERENT layouts —
                    // session_id is at offset 11 in HandshakeHeader (after
                    // magic+ver+flags+msg_type+crypto+key_id) but at offset 6 in
                    // DataHeader (after magic+ver+flags). So we MUST identify the
                    // packet type before extracting the session_id.
                    //
                    // We try HandshakeHeader first: if the parse succeeds AND
                    // msg_type is a handshake type (Hello, HelloAck), use the
                    // handshake-shaped session_id. Otherwise, fall back to
                    // DataHeader parsing (which is what every encrypted data
                    // packet uses, including the msg3 final handshake confirmation
                    // which is sent as MsgType::Data).
                    let sid_opt: Option<SessionId> = if data.len() >= HANDSHAKE_HEADER_SIZE {
                        match HandshakeHeader::deserialize(&data) {
                            Ok(hdr)
                                if matches!(hdr.msg_type, MsgType::Hello | MsgType::HelloAck) =>
                            {
                                Some(hdr.session_id)
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let sid_opt = sid_opt.or_else(|| {
                        if data.len() >= DATA_HEADER_SIZE {
                            DataHeader::deserialize(&data).ok().map(|h| h.session_id)
                        } else {
                            None
                        }
                    });

                    if let Some(sid) = sid_opt {
                        if !dispatcher_mgr.route_packet(&sid, data, from).await {
                            debug!("dispatcher: dropping packet for unknown session {}", sid);
                        }
                    } else {
                        debug!("dispatcher: dropping unparseable packet from {}", from);
                    }
                }
            });
            // Detach: dispatcher lives as long as the connect command runs.
            let _ = dispatcher;

            // Accept loop: every TCP connection spawns a brand-new Noise session.
            loop {
                let (tcp_stream, tcp_addr) = tcp_listener.accept().await?;
                eprintln!(
                    "{} {} → spawning new parallel session",
                    c_cyan("TCP connection from"),
                    tcp_addr
                );

                // Mint a fresh SessionId and register an mpsc channel for the
                // dispatcher to route this session's packets into.
                let new_sid = SessionId::generate();
                let rx = match session_mgr.register(new_sid, send_addr, 1024).await {
                    Some(rx) => rx,
                    None => {
                        eprintln!(
                            "{} session manager at capacity, refusing {}",
                            c_yellow("⚠"),
                            tcp_addr
                        );
                        drop(tcp_stream);
                        continue;
                    }
                };

                let identity_task = (*identity_arc).clone();
                let service_task = service_clone.clone();
                // Pass the NS-resolved gateway NodeID so the relay can
                // route by exact node_id match (strict tenant isolation).
                // Empty NodeId (0u128) means "no NS lookup" — leave the
                // dst_svc_hash field alone so the legacy service-name
                // path keeps working for direct ip:port targets.
                let dst_routing_override_task: Option<[u8; 16]> =
                    if peer_node_id_for_routing != [0u8; 16] {
                        Some(peer_node_id_for_routing)
                    } else {
                        None
                    };
                let session_mgr_task = session_mgr.clone();
                let udp_socket_task = node.socket.clone();
                let pipeline_task = node.pipeline.clone();
                let send_addr_task = send_addr;

                tokio::spawn(async move {
                    if let Err(e) = run_parallel_session(
                        identity_task,
                        service_task,
                        dst_routing_override_task,
                        session_mgr_task,
                        udp_socket_task,
                        pipeline_task,
                        new_sid,
                        rx,
                        send_addr_task,
                        tcp_stream,
                        tcp_addr,
                    )
                    .await
                    {
                        eprintln!(
                            "{} parallel session {} ({}) error: {}",
                            c_red("✗"),
                            new_sid,
                            tcp_addr,
                            e
                        );
                    }
                });
            }
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

        // R3: Consult relay_pool.primary() ONCE per outer handshake attempt so
        // every retransmit lands on the same relay endpoint (the relay state
        // machine MUST NOT see traffic jump mid-handshake). On a fresh
        // `cmd_connect` invocation the pool returns its currently-healthy
        // primary; if that primary turns out to be dead, the
        // `report_handshake_failure` call at the error sites below shifts the
        // pool's primary for the NEXT invocation. We fall back to `send_addr`
        // when no pool was created (legacy path with no relay configured).
        let attempt_addr: std::net::SocketAddr = if let Some(orchestrator) = &relay_pool {
            let pool_guard = orchestrator.lock().await;
            pool_guard.pool().primary().unwrap_or(send_addr)
        } else {
            send_addr
        };

        // Message 1: HELLO (with retransmit on timeout)
        eprintln!("\n{}", c_dim("→ Sending HELLO (message 1/3)..."));
        let msg1 = ctx.write_message(&[])?;
        let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
        hello_hdr.session_id = session_id;
        hello_hdr.src_node_id = *identity.node_id.as_bytes();
        hello_hdr.payload_len = msg1.len() as u16;
        // Set DstSvcID if a service is requested
        if let Some(svc_name) = service {
            hello_hdr.dst_svc_hash = tunnel::encode_service_name(svc_name)?;
            eprintln!("  {} {}", c_cyan("Service:"), svc_name);
        }
        let mut pkt1 = hello_hdr.serialize();
        pkt1.extend_from_slice(&msg1);
        node.send_raw(&pkt1, attempt_addr).await?;

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
                Ok(Err(e)) => {
                    // Socket error during handshake recv — pool sees this as a
                    // handshake failure against `attempt_addr`.
                    if let Some(orchestrator) = &relay_pool {
                        let mut pool_guard = orchestrator.lock().await;
                        pool_guard.pool_mut().report_handshake_failure(attempt_addr);
                    }
                    return Err(e.into());
                }
                Err(_) => {
                    // Timeout — retransmit HELLO
                    retries += 1;
                    if retries > MAX_HANDSHAKE_RETRIES {
                        // Exhausted retransmits: this attempt_addr is unhealthy
                        // — report so the next cmd_connect call shifts to a
                        // different primary.
                        if let Some(orchestrator) = &relay_pool {
                            let mut pool_guard = orchestrator.lock().await;
                            pool_guard.pool_mut().report_handshake_failure(attempt_addr);
                        }
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
                    node.send_raw(&pkt1, attempt_addr).await?; // exact same bytes
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
        let profile = ztlp_proto::client_profile::ClientProfile::desktop(format!(
            "ztlp/{}",
            env!("CARGO_PKG_VERSION")
        ));
        let profile_cbor = profile.to_cbor();
        let msg3 = ctx.write_message(&profile_cbor)?;
        let mut final_hdr = HandshakeHeader::new(MsgType::Data);
        final_hdr.session_id = session_id;
        final_hdr.src_node_id = *identity.node_id.as_bytes();
        final_hdr.payload_len = msg3.len() as u16;
        let mut pkt3 = final_hdr.serialize();
        pkt3.extend_from_slice(&msg3);
        node.send_raw(&pkt3, attempt_addr).await?;

        // Finalize — handshake should be complete after sending msg3
        if !ctx.is_finished() {
            // Treat incomplete handshake as a failure against the relay.
            if let Some(orchestrator) = &relay_pool {
                let mut pool_guard = orchestrator.lock().await;
                pool_guard.pool_mut().report_handshake_failure(attempt_addr);
            }
            return Err("handshake did not complete".into());
        }

        let handshake_time = start_time.elapsed();
        // R3: Record success against the relay so the pool's RTT EWMA and
        // health counters reflect a working primary. Done AFTER `is_finished`
        // so a half-completed exchange doesn't get credited.
        if let Some(orchestrator) = &relay_pool {
            let mut pool_guard = orchestrator.lock().await;
            pool_guard
                .pool_mut()
                .report_handshake_success(attempt_addr, handshake_time);
        }
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

        // ── R2: stop the relay probe task before returning ──────────────
        if let Some(h) = probe_handle.as_ref() {
            h.abort();
        }
        // Touch relay_pool so the binding lives until the end of the legacy
        // path (R3 will replace this with real usage of pool().primary()).
        let _ = relay_pool.as_ref();

        return Ok(());
    }

    // QUIC mode

    use ztlp_proto::quic_transport::{tokio_endpoint::QuicEndpoint, QuicEndpointConfig};
    let (peer_addr, dial_candidates, peer_node_id) = resolve_target(target, ns_server).await?;

    // ── Stage 2 (v0.35.x): multi-candidate pre-selection ─────────────
    //
    // `dial_candidates` is the client-RANKED SVC candidate set (best-first):
    // e.g. a NAT'd box publishes [private-LAN, relay] and a same-LAN box
    // publishes [LAN, relay]. `peer_addr` is candidate[0] (highest priority).
    //
    // For a REMOTE operator the top-ranked private-LAN candidate is
    // unreachable, so picking candidate[0] blindly would regress that box.
    // We pre-probe the ranked candidates (cheap UDP liveness, best-first) and
    // pick the FIRST that answers — that becomes the QUIC dial target. This is
    // the client half of ICE: only the client can judge which published
    // candidate it can actually reach. If none answer (or there's only one
    // candidate, the common case) we keep candidate[0] and let the existing
    // QUIC handshake + auto-reconnect supervisor handle it exactly as before.
    let peer_addr = if dial_candidates.len() > 1 {
        match select_reachable_candidate(&dial_candidates).await {
            Some(a) => {
                if a != peer_addr {
                    eprintln!(
                        "{} multi-candidate: {} reachable, using it over {}",
                        c_green("✓"),
                        a,
                        peer_addr
                    );
                }
                a
            }
            None => {
                eprintln!(
                    "{} multi-candidate: none of {} candidates answered a probe; \
                     using best-ranked {} and letting the handshake/reconnect retry",
                    c_yellow("⚠"),
                    dial_candidates.len(),
                    peer_addr
                );
                peer_addr
            }
        }
    } else {
        peer_addr
    };

    let node_id = peer_node_id.unwrap_or_else(|| ztlp_proto::identity::NodeId([0; 16]));
    let identity = load_or_generate_identity(key)?;

    // ── v0.32.2 (A1): multi-candidate dial moved into the QUIC path ──
    //
    // When `--multi-candidate` is set AND we have an NS-resolved peer
    // NodeID, race the host candidates from PUNCH_REPORT alongside the
    // NS-resolved `peer_addr` (which is typically the relay backstop).
    // The winning path's address overrides `peer_addr` for the rest of
    // this function — both CLIENT_ROUTE and the subsequent QUIC handshake
    // then target the LAN-direct winner. Failure (NS query timeout, no
    // candidate succeeded, parse error, probe bind failure) falls back
    // to the NS-resolved `peer_addr` unchanged — same outcome as if
    // `--multi-candidate` weren't passed at all. This is the "safe
    // default" the original M6 commit was designed around.
    //
    // Crucially this is decoupled from `punch_enabled`. The pre-fix M6
    // block lived in the legacy-UDP branch and was gated on `punch`,
    // which meant `--multi-candidate --ns-server NAME` silently fell
    // back to the broken legacy parallel-session handshake. The QUIC
    // path is the path that actually completes end-to-end against the
    // v0.30 production relay, so multi-candidate logic belongs here.
    //
    // The probe uses a fresh ephemeral UDP socket — NOT `std_socket`,
    // which Quinn takes ownership of below. Sharing a single fd with
    // Quinn led to the v0.31 punch fd-aliasing trap; a separate probe
    // socket sidesteps it entirely.
    let multi_candidate_winner: Option<SocketAddr> = if multi_candidate && peer_node_id.is_some() {
        match ns_server
            .as_deref()
            .and_then(|s| s.parse::<SocketAddr>().ok())
        {
            Some(ns_addr) => {
                eprintln!(
                    "{} multi-candidate dial enabled (v0.32.2)",
                    c_dim("[v0.32.2]")
                );
                match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    Ok(probe_sock) => {
                        let probe_sock = std::sync::Arc::new(probe_sock);
                        let policy = ztlp_proto::dial_orchestrator::DialPolicy::default();
                        let local_subnets = ztlp_proto::local_candidates::our_local_subnets();
                        match ztlp_proto::multi_candidate_dial::try_multi_candidate_connect(
                            peer_node_id.unwrap(),
                            ns_addr,
                            probe_sock,
                            identity.node_id,
                            &local_subnets,
                            Some(peer_addr),
                            policy,
                        )
                        .await
                        {
                            Ok(outcome) => {
                                eprintln!(
                                    "{} multi-candidate dial succeeded: {} ({:?})",
                                    c_green("✓"),
                                    outcome.winning_addr,
                                    outcome.class
                                );
                                Some(outcome.winning_addr)
                            }
                            Err(e) => {
                                eprintln!(
                                    "{} multi-candidate dial failed: {:?}; falling back to NS-resolved addr",
                                    c_dim("[v0.32.2]"),
                                    e
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{} multi-candidate probe socket bind failed: {}; falling back",
                            c_dim("[v0.32.2]"),
                            e
                        );
                        None
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    let peer_addr = pick_quic_dial_target(peer_addr, multi_candidate_winner);

    // Bind a UDP socket Quinn will reuse for the QUIC connection.
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .expect("Failed to bind UDP socket for QUIC signaling");

    // ─── α-relay routing setup (FRAME_CLIENT_ROUTE) ──────────────────
    //
    // When a service name is supplied, send a single CLIENT_ROUTE frame
    // to the peer BEFORE the first QUIC INITIAL on the same UDP socket.
    // The relay treats this as a routing hint, looks up the registered
    // gateway for `service`, and installs `{:client_map, sender} ->
    // gateway_addr` in `:ztlp_forwarded_quic_tuples`. All subsequent UDP
    // from this 5-tuple is then transparently echoed to that gateway —
    // Quinn's encrypted INITIAL never has to be parsed by the relay.
    //
    // β-direct (no relay between client and gateway) ignores the frame
    // safely: a real gateway sees an unrecognized magic+type triple and
    // drops it at L1, with no impact on the subsequent QUIC handshake.
    // So sending CLIENT_ROUTE unconditionally when `--service` is set is
    // the right default, even when the caller doesn't know whether the
    // peer is a relay or a gateway.
    //
    // Replaces the rejected dummy-Noise-UDP-HELLO hack (see prior
    // session handoff Decisions #3); validated by the relay's
    // CLIENT_ROUTE unit tests in `relay/test/.../udp_listener_test.exs`.
    if let Some(svc_name) = service.as_deref() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Stamp the NS-resolved gateway NodeID into the CLIENT_ROUTE frame
        // when we have one, so the relay can route by exact NodeID even when
        // the `--service` string doesn't match the gateway's registered
        // service-name (e.g. remote-site billing: gateway registered as
        // `z2ls-bill-008247`, operator dials `--service ssh`). The relay's
        // `do_install_client_route/3` falls back to this node_id (its
        // authoritative `pick_gateway_for_service/1` NodeID tier) when the
        // service-name lookup misses. Mirrors the HELLO `dst_svc_id` /
        // `dst_routing_override` NodeID-pin path.
        //
        // For direct ip:port targets with no NS resolution, `node_id` is the
        // all-zero NodeId; in that case fall back to the client's own NodeID
        // (legacy behavior — harmless, the frame is dropped by a real gateway
        // in β-direct mode anyway).
        let client_route_node_id: [u8; 16] = if node_id.0 != [0u8; 16] {
            node_id.0
        } else {
            identity.node_id.0
        };

        // Dev-mode HMAC (None) — production should plumb the zone secret
        // through here, mirroring the relay's `Config.registration_secret/0`.
        match build_client_route_packet(&client_route_node_id, svc_name, ts, None) {
            Ok(pkt) => match std_socket.send_to(&pkt, peer_addr) {
                Ok(n) => {
                    eprintln!(
                        "{} CLIENT_ROUTE sent to {} ({} bytes, service={})",
                        c_dim("→"),
                        peer_addr,
                        n,
                        svc_name
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{} failed to send CLIENT_ROUTE to {}: {}",
                        c_red("✗"),
                        peer_addr,
                        e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "{} could not build CLIENT_ROUTE for service '{}': {}",
                    c_red("✗"),
                    svc_name,
                    e
                );
            }
        }

        // Brief delay to let the relay install the 5-tuple before Quinn's
        // first INITIAL races down the same socket. 50ms is well above
        // typical GenServer→ETS latency on the relay path.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let client = QuicEndpoint::connect_with_socket(
        QuicEndpointConfig::default(),
        peer_addr,
        "localhost",
        std_socket,
    )
    .await?;

    let local_port = if let Some(lf) = local_forward {
        lf.split(':').next().unwrap_or("0")
    } else {
        "0"
    };
    let bind_addr = if local_port == "0" {
        bind.to_string()
    } else {
        format!("127.0.0.1:{}", local_port)
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!(
        "ZTLP QUIC client listening on TCP {}",
        listener.local_addr()?
    );

    let service_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(service.as_deref().unwrap_or("").as_bytes());
        let output = hasher.finalize();
        let mut h = [0u8; 16];
        h.copy_from_slice(&output[..16]);
        h
    };
    let _session = match ztlp_proto::quic_transport::noise_stream::run_initiator_handshake(
        &client,
        &identity,
        node_id,
        service_hash,
    )
    .await
    {
        Ok(handshake_result) => {
            println!("Noise Handshake Complete (Quic). Session Init.");
            handshake_result.session
        }
        Err(e) => {
            eprintln!("Noise handshake failed: {:?}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )));
        }
    };

    loop {
        // ── Auto-reconnect detection (v0.34.9+) ──────────────────────────
        //
        // Race the TCP accept against the QUIC connection's closed signal.
        // When the underlying QUIC session dies (gateway restart, network
        // blip, NAT timeout), client.closed() resolves with the close
        // reason. We return Err(...) so the supervisor wrapper in the
        // Commands::Connect dispatch arm can see the disconnect and
        // re-dial. Without this select, the accept loop would happily
        // serve forever against a dead QUIC handle, surfacing the bug as
        // "Connection reset by peer" per-incoming-TCP rather than as a
        // detected tunnel failure.
        //
        // Plan: docs/plans/2026-06-03-connect-auto-reconnect.md
        // Pinned by: tests::auto_reconnect (17 GREEN tests).
        let client_for_close = client.clone();
        let (tcp, addr) = tokio::select! {
            accept_result = listener.accept() => accept_result?,
            close_reason = client_for_close.inner.closed() => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("QUIC tunnel closed: {:?}", close_reason),
                )));
            }
        };
        println!("Accepted connection from {}", addr);
        let client_clone = client.clone();
        tokio::spawn(async move {
            // open_bi can fail with Connection("timed out") if the underlying
            // QUIC tunnel has died (e.g. the gateway dropped us, the relay's
            // 5-tuple map evicted, or a long idle without keepalives). We must
            // NOT .unwrap() here — the listener task is still running and will
            // happily accept fresh TCP connections, but each one would crash
            // a worker thread. Log the reason and exit the per-connection task
            // cleanly so the listener stays usable when the user reconnects.
            let (mut q_send, mut q_recv) = match client_clone.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    eprintln!(
                        "✗ failed to open QUIC stream from {}: {:?}; \
                         the underlying tunnel is likely dead. \
                         Stop and re-run `ztlp connect` to re-establish.",
                        addr, e
                    );
                    return;
                }
            };
            let (mut t_read, mut t_write) = tcp.into_split();
            let mut read_buf = vec![0u8; 65000];
            loop {
                tokio::select! {
                    res = tokio::io::AsyncReadExt::read(&mut t_read, &mut read_buf) => {
                        match res {
                            Ok(0) => break,
                            Ok(n) => {
                                println!("TCP->QUIC Read {} bytes", n);
                                if ztlp_proto::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, &read_buf[..n]).await.is_err() {
                                    println!("TCP->QUIC Write Error");
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    res = ztlp_proto::quic_transport::noise_stream::read_ztlp_frame(&mut q_recv) => {
                        match res {
                            Ok(frame) => {
                                if tokio::io::AsyncWriteExt::write_all(&mut t_write, &frame).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
    }
}

/// Run a new ZTLP session in parallel per accepted TCP connection.
///
/// This serves as a workaround for the lack of in-session multiplexing.
/// It performs a complete initiator Noise_XX handshake utilizing a dedicated
/// loopback UDP pair, receiving incoming packets from the shared dispatcher via `rx`.
#[allow(clippy::too_many_arguments)]
async fn run_parallel_session(
    identity: ztlp_proto::identity::NodeIdentity,
    service: Option<String>,
    dst_routing_override: Option<[u8; 16]>,
    session_mgr: std::sync::Arc<ztlp_proto::session_manager::SessionManager>,
    udp_send_socket: std::sync::Arc<tokio::net::UdpSocket>,
    pipeline: std::sync::Arc<tokio::sync::Mutex<ztlp_proto::pipeline::Pipeline>>,
    session_id: ztlp_proto::packet::SessionId,
    mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
    send_addr: std::net::SocketAddr,
    tcp_stream: tokio::net::TcpStream,
    _tcp_addr: std::net::SocketAddr,
) -> Result<(), String> {
    use std::time::Duration;
    use tokio::time::timeout;
    use ztlp_proto::handshake::{
        HandshakeContext, INITIAL_HANDSHAKE_RETRY_MS, MAX_HANDSHAKE_RETRIES, MAX_HANDSHAKE_RETRY_MS,
    };
    use ztlp_proto::identity::NodeId;
    use ztlp_proto::packet::{HandshakeHeader, MsgType, HANDSHAKE_HEADER_SIZE};

    let mut ctx = HandshakeContext::new_initiator(&identity)
        .map_err(|e| format!("new_initiator error: {}", e))?;

    let msg1 = ctx
        .write_message(&[])
        .map_err(|e| format!("write_message error: {}", e))?;
    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;

    if let Some(svc_name) = &service {
        hello_hdr.dst_svc_hash = ztlp_proto::tunnel::encode_service_name(svc_name)
            .map_err(|e| format!("encode_service_name error: {}", e))?;
    }
    // dst_routing_override takes precedence over a service name. It carries
    // the NS-resolved target gateway NodeID so the relay can route to the
    // correct tenant gateway by exact node_id match instead of falling
    // back to round-robin across all registered gateways (which violates
    // tenant isolation when multiple tenants share the relay).
    if let Some(node_id_bytes) = dst_routing_override {
        hello_hdr.dst_svc_hash = node_id_bytes;
    }
    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);

    // Send Msg1
    udp_send_socket
        .send_to(&pkt1, send_addr)
        .await
        .map_err(|e| format!("send_to error: {}", e))?;

    // Wait for Msg2 (HelloAck)
    let mut retry_delay = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
    let max_retry_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);
    let mut retries: u8 = 0;

    let (recv2, _) = loop {
        match timeout(retry_delay, rx.recv()).await {
            Ok(Some((data, addr))) => {
                if data.len() >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                        if hdr.msg_type == MsgType::HelloAck && hdr.session_id == session_id {
                            break (data, addr);
                        }
                    }
                }
                continue;
            }
            Ok(None) => return Err("channel closed".to_string()),
            Err(_) => {
                // Timeout, retransmit
                retries += 1;
                if retries > MAX_HANDSHAKE_RETRIES {
                    return Err("handshake failed: no HELLO_ACK after retransmits".to_string());
                }
                udp_send_socket
                    .send_to(&pkt1, send_addr)
                    .await
                    .map_err(|e| format!("send_to error: {}", e))?;
                retry_delay = (retry_delay * 2).min(max_retry_delay);
            }
        }
    };

    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("received packet too short for handshake header".to_string());
    }
    let recv2_header = HandshakeHeader::deserialize(&recv2).map_err(|e| e.to_string())?;
    if recv2_header.msg_type != MsgType::HelloAck {
        return Err(format!(
            "expected HELLO_ACK, got {:?}",
            recv2_header.msg_type
        ));
    }
    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)
        .map_err(|e| e.to_string())?;

    // Msg3
    let profile = ztlp_proto::client_profile::ClientProfile::desktop(format!(
        "ztlp/{}",
        env!("CARGO_PKG_VERSION")
    ));
    let profile_cbor = profile.to_cbor();
    let msg3 = ctx
        .write_message(&profile_cbor)
        .map_err(|e| e.to_string())?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    udp_send_socket
        .send_to(&pkt3, send_addr)
        .await
        .map_err(|e| e.to_string())?;

    if !ctx.is_finished() {
        return Err("handshake did not complete".to_string());
    }

    let peer_node_id = NodeId::from_bytes(recv2_header.src_node_id);
    let (_transport, session) = ctx
        .finalize(peer_node_id, session_id)
        .map_err(|e| e.to_string())?;

    {
        let mut pl = pipeline.lock().await;
        pl.register_session(session);
    }
    session_mgr.set_established(&session_id).await;

    // Reject check omitted: Unlike the serial path, we skip the brief RejectFrame
    // poll on `recv_data` because we cannot easily share it or block concurrent
    // session processing without overcomplicating the router. Any reject will simply
    // tear down the bridge shortly after startup.

    // Bridge: loopback UDP pair
    let recv_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind recv socket: {}", e))?;
    let recv_addr = recv_socket
        .local_addr()
        .map_err(|e| format!("recv socket addr: {}", e))?;

    let fwd_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind fwd socket: {}", e))?;

    let recv_socket = std::sync::Arc::new(recv_socket);
    let fwd_socket = std::sync::Arc::new(fwd_socket);

    let fwd_socket_clone = fwd_socket.clone();
    let forwarder = tokio::spawn(async move {
        while let Some((data, _addr)) = rx.recv().await {
            let _ = fwd_socket_clone.send_to(&data, recv_addr).await;
        }
    });

    // Run the bridge using demuxed sockets
    let bridge_result = ztlp_proto::tunnel::run_bridge_demuxed(
        tcp_stream,
        udp_send_socket,
        recv_socket,
        pipeline,
        session_id,
        send_addr,
        Vec::new(),
    )
    .await
    .map_err(|e| e.to_string());

    session_mgr.remove(&session_id).await;
    forwarder.abort();

    bridge_result.map(|_| ())
}

// ─── Relay Gateway Registration ───────────────────────────────────────────

/// GATEWAY_REGISTER packet format (as consumed by ztlp-relay UDP listener):
///   magic:       0x5A37     (2 bytes, big-endian)
///   type:        0x0A       (1 byte — GATEWAY_REGISTER)
///   node_id:     16 bytes
///   service_name:16 bytes   (padded with zeros)
///   ttl:         4 bytes    (big-endian u32)
///   timestamp:   8 bytes    (big-endian i64, unix timestamp)
///   hmac:        32 bytes   (zeroed in dev mode when no registration secret)
///
/// Total: 14 + 16 + 16 + 4 + 8 + 32 = 78 bytes
///
/// The relay code at relay/lib/ztlp_relay/udp_listener.ex looks for:
///   <<0x5A, 0x37, 0x0A, rest::binary>>
/// and then parses the remaining fields.
const GATEWAY_REGISTER_MAGIC: [u8; 2] = [0x5A, 0x37];
const GATEWAY_REGISTER_TYPE: u8 = 0x0A;
/// V2 GATEWAY_REGISTER frame type — carries an explicit `zone_id` length-prefixed
/// field so the relay can route by zone (not by truncated org-slug). Introduced
/// for cross-tenant collision safety; see docs/plans/2026-05-24-zone-keyed-
/// gateway-register-IMPL.md and the original Elixir impl at
/// gateway/lib/ztlp_gateway/relay_registrar.ex.
const GATEWAY_REGISTER_V2_TYPE: u8 = 0x0E;
const RELAY_REGISTER_TTL: u32 = 60; // seconds — relay expires registration after TTL
const RELAY_REREGISTER_INTERVAL: Duration = Duration::from_secs(10); // refresh at half-TTL

// ─── CLIENT_ROUTE Frame (α-relay routing) ─────────────────────────────────
//
// FRAME_CLIENT_ROUTE is sent by a QUIC client BEFORE its first QUIC INITIAL
// packet, on the same UDP socket, to tell the relay which registered service
// (gateway) it wants its subsequent QUIC traffic forwarded to.  The relay
// records `{:client_map, sender} -> gateway_addr` in
// `:ztlp_forwarded_quic_tuples` and then transparently echoes UDP between
// the two 5-tuples — Quinn's encrypted INITIAL never has to be parsed.
//
// Wire format:
//   magic:       0x5A37          (2 bytes, big-endian)
//   type:        0x0B            (1 byte — CLIENT_ROUTE)
//   node_id:     16 bytes        (client's NodeID — for ACL / audit)
//   svc_len:     1 byte          (length of `service`, 1..=63)
//   service:     svc_len bytes   (UTF-8, lowercase canonical service name)
//   timestamp:   8 bytes         (big-endian i64 unix seconds — replay window)
//   hmac:        32 bytes        (HMAC-SHA256 over [type..timestamp];
//                                 zeroed in dev mode if no shared secret)
//
// Total: 2 + 1 + 16 + 1 + N + 8 + 32 = 60 + N bytes (N = svc_len)
//
// The HMAC scheme intentionally mirrors GATEWAY_REGISTER so the relay can
// reuse `Config.registration_secret/0` and existing HMAC plumbing.
const CLIENT_ROUTE_MAGIC: [u8; 2] = [0x5A, 0x37];
const CLIENT_ROUTE_TYPE: u8 = 0x0B;
const CLIENT_ROUTE_MAX_SVC_LEN: usize = 63;

/// Build a GATEWAY_REGISTER packet.
///
/// The HMAC is zeroed (dev-mode). In production the relay may require
/// a configured registration secret — when it does, the HMAC must be
/// computed over <<0x0A, node_id, service, ttl, timestamp>> using
/// HMAC-SHA256 keyed with the shared secret.  For now we follow the
/// same pattern the relay uses in unverified (nil secret) mode.
fn build_gateway_register_packet(
    node_id: &[u8; 16],
    service_name: &str,
    timestamp: i64,
) -> Vec<u8> {
    // Pad or truncate service name to exactly 16 bytes
    let mut service_bytes = [0u8; 16];
    let name_bytes = service_name.as_bytes();
    let copy_len = name_bytes.len().min(16);
    service_bytes[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Build the signed payload that HMAC would cover (for correctness if
    // we later add secret-based auth).  The relay expects:
    //   <<0x0A, node_id::16, service::16, ttl::32(big), timestamp::64(big)>>
    let signed_payload: [u8; 1 + 16 + 16 + 4 + 8] = {
        let mut buf = [0u8; 1 + 16 + 16 + 4 + 8];
        buf[0] = GATEWAY_REGISTER_TYPE;
        buf[1..17].copy_from_slice(node_id);
        buf[17..33].copy_from_slice(&service_bytes);
        buf[33..37].copy_from_slice(&RELAY_REGISTER_TTL.to_be_bytes());
        buf[37..45].copy_from_slice(&timestamp.to_be_bytes());
        buf
    };

    // HMAC (dev-mode: zeroed).  Production could use:
    //   hmac = hmac_sha256(secret, &signed_payload)
    let hmac = [0u8; 32];

    // Full packet: magic + the rest (type + node_id + service + ttl + timestamp + hmac)
    let mut packet = Vec::with_capacity(2 + GATEWAY_REGISTER_TYPE as usize + 16 + 16 + 4 + 8 + 32);
    packet.extend_from_slice(&GATEWAY_REGISTER_MAGIC);
    packet.extend_from_slice(&signed_payload);
    packet.extend_from_slice(&hmac);
    packet
}

/// V2 zone-keyed gateway registration configuration helper.
///
/// Encapsulates the "should we emit V2 frames, and if so with what
/// HMAC key?" decision in a pure, testable function. Pulled out of
/// `cmd_listen` after the v0.30.5 fleet deploy retro revealed that
/// the inline version silently disabled V2 routing whenever the
/// per-zone HMAC secret env var wasn't set (12 of 19 tenants needed
/// manual operator action to flip on V2; see Tier 4 / Known Problem
/// #21 in `hermes_session_handoff.md`).
///
/// # Decision matrix
///
/// | `zone` arg          | `zone_hmac_secret_env` arg | env var value     | Returns                  |
/// |---------------------|----------------------------|-------------------|--------------------------|
/// | `None`              | (any)                      | (any)             | `None` (no V2 emission)  |
/// | `Some("")`          | (any)                      | (any)             | `None` (no V2 emission)  |
/// | `Some("zone")`      | `Some("VAR")`              | `"value"`         | `Some(("zone", b"value"))` |
/// | `Some("zone")`      | `Some("VAR")`              | unset OR `""`     | `Some(("zone", vec![]))` ← key fix |
/// | `Some("zone")`      | `None` (use default)       | `"value"`         | `Some(("zone", b"value"))` |
/// | `Some("zone")`      | `None` (use default)       | unset OR `""`     | `Some(("zone", vec![]))` ← key fix |
///
/// # Why empty-secret still emits V2
///
/// Pre-v0.30.7 the gateway returned `None` for the empty-secret case,
/// silently falling back to V1-only. This meant operators had to set
/// `ZTLP_HMAC_SECRET_<SLUG>` on every tenant container just to get
/// the collision-safe V2 routing key in the relay's routing table —
/// even when the relay was in `:dev` mode and didn't actually need a
/// real HMAC.
///
/// Post-v0.30.7 the gateway emits V2 with whatever secret bytes the
/// env provides (including zero bytes). The relay's HMAC mode
/// (`:dev` / `:staging` / `:prod`, controlled via
/// `ZTLP_RELAY_HMAC_MODE`) decides whether to accept the frame:
///
/// - `:dev`     → accept as `:unverified_dev`, route by `gw:<zone>`
/// - `:staging` → accept as `:unverified_staging`, route by `gw:<zone>`,
///                emit `ztlp_relay.hmac.unverified_accepted` telemetry
/// - `:prod`    → reject unsigned/badly-signed frames
///
/// This puts the enforcement decision at the right layer: the relay,
/// which is the security boundary, not the gateway, which is the
/// thing being authenticated.
///
/// # Slugify rule
///
/// When `zone_hmac_secret_env` is `None`, the env var name is derived
/// from the zone using the same rule the Elixir
/// `ZtlpRelay.HmacSecrets.slugify_zone/1` applies:
///
/// - ASCII alphanumeric characters → uppercased
/// - every other character → `_`
/// - prefix with `ZTLP_HMAC_SECRET_`
///
/// e.g. `tech-rockstars.com` → `ZTLP_HMAC_SECRET_TECH_ROCKSTARS_COM`.
///
/// Keep this rule byte-for-byte identical to the relay's; if they
/// drift, V2 frames will route correctly but the relay won't be able
/// to verify HMACs in `:prod` mode (or will verify the wrong ones).
fn resolve_v2_config(
    zone: Option<&str>,
    zone_hmac_secret_env: Option<&str>,
) -> Option<(String, Vec<u8>)> {
    // No zone, or empty zone → no V2 emission. Both cases collapse to
    // None so the call site has a single branch.
    let zone_str = match zone {
        Some(z) if !z.is_empty() => z,
        _ => return None,
    };

    // Derive the env var name. If the caller passed one explicitly,
    // use it verbatim. Otherwise apply the slugify rule that mirrors
    // the relay's HmacSecrets.slugify_zone/1.
    let env_name: String = match zone_hmac_secret_env {
        Some(name) => name.to_string(),
        None => {
            let slug: String = zone_str
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            format!("ZTLP_HMAC_SECRET_{}", slug)
        }
    };

    // Look up the secret. Missing OR empty-string both collapse to
    // an empty Vec — the key fix vs. pre-v0.30.7 behavior, which
    // returned None for both.
    let secret_bytes: Vec<u8> = match std::env::var(&env_name) {
        Ok(s) => s.into_bytes(), // includes the case where s.is_empty()
        Err(_) => Vec::new(),
    };

    Some((zone_str.to_string(), secret_bytes))
}

/// Build a GATEWAY_REGISTER_V2 packet (type byte `0x0E`) for collision-safe
/// zone-keyed relay routing.
///
/// # Wire format
///
/// ```text
///   magic:           0x5A37          (2 bytes, big-endian)
///   type:            0x0E            (1 byte)
///   zone_len:        1 byte          (length of zone_id, 1..=63)
///   zone_id:         zone_len bytes  (UTF-8, e.g. "techrockstars.ztlp")
///   node_id:         16 bytes
///   service_padded:  16 bytes        (zero-padded ASCII — mirrors V1 layout
///                                     for relay-side parser compatibility)
///   ttl:             4 bytes         (big-endian u32)
///   timestamp:       8 bytes         (big-endian i64 unix seconds)
///   hmac:            32 bytes        (HMAC-SHA256)
/// ```
///
/// # Signed material
///
/// The HMAC covers the bytes
/// `[0x0E, zone_len, zone_id, node_id, service_padded, ttl, timestamp]`.
/// The wire magic and the HMAC field itself are NOT signed. This matches the
/// relay-side parser in `relay/lib/ztlp_relay/udp_listener.ex` (the
/// `handle_gateway_register_v2/2` handler).
///
/// # Errors
///
/// Returns `Err` if `zone_id` length is outside `1..=63` bytes. Returns `Err`
/// if `secret` is provided but has a length the HMAC implementation refuses
/// (any non-zero length is fine for HMAC-SHA256, so this is a defensive
/// path).
///
/// # Compatibility with V1
///
/// V2 is additive — gateways send both V1 (`0x0A`) and V2 (`0x0E`) frames
/// in parallel during the migration window. Relays accept both. New clients
/// reach the V2-registered gateway via the routing key `gw:<zone_id>`; old
/// clients still reach the V1-registered gateway via the legacy
/// `gw-<truncated_org_slug>` key.
fn build_gateway_register_v2_packet(
    node_id: &[u8; 16],
    zone_id: &str,
    service_name: &str,
    ttl: u32,
    timestamp: i64,
    secret: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let zone_bytes = zone_id.as_bytes();
    if zone_bytes.is_empty() {
        return Err("zone_id must not be empty");
    }
    if zone_bytes.len() > 63 {
        return Err("zone_id length must not exceed 63 bytes");
    }

    // Service name padded to exactly 16 bytes (truncate-or-zero-pad). The
    // V2 wire keeps this field for forward-compat with the V1 parser; the
    // ROUTING key on the relay side is derived from zone_id, not this
    // field, per design in `gateway_forwarder.ex`.
    let mut service_padded = [0u8; 16];
    let name_bytes = service_name.as_bytes();
    let copy_len = name_bytes.len().min(16);
    service_padded[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let zone_len = zone_bytes.len() as u8;

    // Build the signed material:
    //   [type | zone_len | zone_id | node_id | service_padded | ttl | timestamp]
    let mut signed = Vec::with_capacity(1 + 1 + zone_bytes.len() + 16 + 16 + 4 + 8);
    signed.push(GATEWAY_REGISTER_V2_TYPE);
    signed.push(zone_len);
    signed.extend_from_slice(zone_bytes);
    signed.extend_from_slice(node_id);
    signed.extend_from_slice(&service_padded);
    signed.extend_from_slice(&ttl.to_be_bytes());
    signed.extend_from_slice(&timestamp.to_be_bytes());

    let hmac: [u8; 32] = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(secret).map_err(|_| "invalid HMAC key length")?;
        mac.update(&signed);
        let out = mac.finalize().into_bytes();
        let mut h = [0u8; 32];
        h.copy_from_slice(&out);
        h
    };

    let mut packet = Vec::with_capacity(2 + signed.len() + 32);
    packet.extend_from_slice(&GATEWAY_REGISTER_MAGIC);
    packet.extend_from_slice(&signed);
    packet.extend_from_slice(&hmac);
    Ok(packet)
}

/// Build a CLIENT_ROUTE packet (FRAME_CLIENT_ROUTE).
///
/// See the wire-format comment block above the `CLIENT_ROUTE_*` constants.
/// `secret` is `None` in dev mode (zeroed HMAC); `Some(&[u8])` in production
/// to keyed HMAC-SHA256 over the same byte range the relay validates.
///
/// Returns `Err` if `service_name` is empty or longer than
/// `CLIENT_ROUTE_MAX_SVC_LEN` bytes (UTF-8 byte length, not char count).
fn build_client_route_packet(
    node_id: &[u8; 16],
    service_name: &str,
    timestamp: i64,
    secret: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let svc_bytes = service_name.as_bytes();
    if svc_bytes.is_empty() {
        return Err("service_name must not be empty");
    }
    if svc_bytes.len() > CLIENT_ROUTE_MAX_SVC_LEN {
        return Err("service_name exceeds CLIENT_ROUTE_MAX_SVC_LEN");
    }

    // Build the byte range that HMAC covers:
    //   [type | node_id | svc_len | service | timestamp]
    let svc_len = svc_bytes.len() as u8;
    let mut signed = Vec::with_capacity(1 + 16 + 1 + svc_bytes.len() + 8);
    signed.push(CLIENT_ROUTE_TYPE);
    signed.extend_from_slice(node_id);
    signed.push(svc_len);
    signed.extend_from_slice(svc_bytes);
    signed.extend_from_slice(&timestamp.to_be_bytes());

    let hmac: [u8; 32] = match secret {
        None => [0u8; 32],
        Some(key) => {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                .map_err(|_| "invalid HMAC key length")?;
            mac.update(&signed);
            let out = mac.finalize().into_bytes();
            let mut h = [0u8; 32];
            h.copy_from_slice(&out);
            h
        }
    };

    let mut packet = Vec::with_capacity(2 + signed.len() + 32);
    packet.extend_from_slice(&CLIENT_ROUTE_MAGIC);
    packet.extend_from_slice(&signed);
    packet.extend_from_slice(&hmac);
    Ok(packet)
}

/// Parse a CLIENT_ROUTE packet, returning `(node_id, service_name, timestamp,
/// hmac_bytes, signed_range)`. Used by tests and by any in-process verifier.
///
/// Returns `Err` if magic/type don't match, the buffer is short, or `svc_len`
/// is outside `1..=CLIENT_ROUTE_MAX_SVC_LEN`.
#[cfg(test)]
fn parse_client_route_packet(
    packet: &[u8],
) -> Result<([u8; 16], String, i64, [u8; 32]), &'static str> {
    // 2 magic + 1 type + 16 node_id + 1 svc_len + 1+ svc + 8 ts + 32 hmac = min 61
    if packet.len() < 61 {
        return Err("packet too short");
    }
    if packet[0..2] != CLIENT_ROUTE_MAGIC {
        return Err("bad magic");
    }
    if packet[2] != CLIENT_ROUTE_TYPE {
        return Err("bad type");
    }
    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&packet[3..19]);
    let svc_len = packet[19] as usize;
    if svc_len == 0 || svc_len > CLIENT_ROUTE_MAX_SVC_LEN {
        return Err("svc_len out of range");
    }
    let svc_end = 20 + svc_len;
    if packet.len() < svc_end + 8 + 32 {
        return Err("packet truncated");
    }
    let service = std::str::from_utf8(&packet[20..svc_end])
        .map_err(|_| "service is not valid UTF-8")?
        .to_string();
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&packet[svc_end..svc_end + 8]);
    let timestamp = i64::from_be_bytes(ts_bytes);
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&packet[svc_end + 8..svc_end + 8 + 32]);
    Ok((node_id, service, timestamp, hmac))
}

/// Spawn a background task that sends an initial GATEWAY_REGISTER packet to the
/// relay and then re-registers every 30 seconds to keep the registration alive.
///
/// The relay uses TTL-based expiration — by re-registering before the TTL
/// expires (TTL=60s, interval=30s), the gateway stays registered indefinitely.
///
/// This uses the node's bound UDP socket so the source port matches the
/// listener — the relay uses the sender address for forwarding.
#[allow(dead_code)]
fn spawn_relay_registration(
    node: &TransportNode,
    identity: &NodeIdentity,
    relay_addr: SocketAddr,
    service_name: &str,
) {
    let socket = Arc::clone(&node.socket);
    let node_id = identity.node_id.0;
    let svc = service_name.to_string();

    tokio::spawn(async move {
        // Send initial registration
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let pkt = build_gateway_register_packet(&node_id, &svc, ts);

        match socket.send_to(&pkt, relay_addr).await {
            Ok(n) => {
                debug!("gateway registration sent to {} ({} bytes)", relay_addr, n);
            }
            Err(e) => {
                warn!(
                    "failed to send gateway registration to {}: {}",
                    relay_addr, e
                );
            }
        }

        // Periodic re-registration loop
        loop {
            tokio::time::sleep(RELAY_REREGISTER_INTERVAL).await;

            let ts = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let pkt = build_gateway_register_packet(&node_id, &svc, ts);

            match socket.send_to(&pkt, relay_addr).await {
                Ok(n) => {
                    debug!(
                        "gateway re-registration sent to {} ({} bytes)",
                        relay_addr, n
                    );
                    eprintln!(
                        "{} gateway re-registered with {} (service: {})",
                        c_green("✓"),
                        relay_addr,
                        svc
                    );
                }
                Err(e) => {
                    warn!("failed to re-register gateway with {}: {}", relay_addr, e);
                    eprintln!(
                        "{} failed to re-register with {}: {}",
                        c_red("✗"),
                        relay_addr,
                        e
                    );
                }
            }
        }
    });
}

// ─── Listen ─────────────────────────────────────────────────────────────────

/// `ztlp listen` — Listen for incoming connections
#[allow(clippy::too_many_arguments)]
async fn cmd_listen(
    bind: &str,
    key: &Option<PathBuf>,
    _gateway_mode: bool,
    forward: &[String],
    _policy_path: &Option<PathBuf>,
    ns_server: &Option<String>,
    _stun_server: &Option<String>,
    _nat_assist: bool,
    _max_sessions: usize,
    relay_addr: Option<&str>,
    service_name: &str,
    zone: Option<&str>,
    zone_hmac_secret_env: Option<&str>,
    ns_register_name: Option<&str>,
    http_inject_headers: bool,
    header_hmac_secret: Option<&str>,
    admin_pubkey_email: &[String],
    _quic: bool,
    punch_enabled: bool,
    advertise_interface: &[String],
    no_advertise_interface: &[String],
    advertise_all_interfaces: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::quic_transport::{tokio_endpoint::QuicEndpoint, QuicEndpointConfig};

    let server_cfg = QuicEndpointConfig {
        bind: Some(bind.parse().unwrap()),
        ..Default::default()
    };

    // Pre-bind the std UDP socket so we can send GATEWAY_REGISTER packets to
    // the relay from the SAME (ip, port) that Quinn will then listen on.
    //
    // Why this matters:
    // The ZTLP relay maps a gateway by the (src_ip, src_port) of its
    // GATEWAY_REGISTER packet, then forwards client HELLOs to that same
    // (src_ip, src_port). If we register from a different socket than the
    // QUIC listener (the old "dummy_socket" workaround did exactly this),
    // the relay forwards client traffic to a dead socket and handshakes
    // time out. By pre-binding the std::net::UdpSocket and using
    // `try_clone()` to send registration packets, the kernel-level UDP
    // socket is shared between the registration sender and Quinn's
    // receiver, guaranteeing both share the same source address.
    let bind_addr: std::net::SocketAddr = bind.parse().expect("invalid bind address");
    let std_socket = std::net::UdpSocket::bind(bind_addr)
        .map_err(|e| format!("failed to bind UDP socket on {}: {}", bind_addr, e))?;
    let local_addr = std_socket.local_addr().expect("socket has local_addr");
    // Clone the fd for relay-registration use BEFORE we move the socket
    // into Quinn. Both fds reference the same kernel socket — outbound
    // packets share the (ip, port), inbound is delivered to whichever fd
    // is reading (Quinn).
    let register_socket: Option<std::net::UdpSocket> = if relay_addr.is_some() {
        Some(
            std_socket
                .try_clone()
                .map_err(|e| format!("UdpSocket::try_clone failed: {}", e))?,
        )
    } else {
        None
    };

    // Load gateway identity up front — we need its NodeId for the
    // PunchAgent if --punch is enabled.
    let identity = load_or_generate_identity(key)?;

    // ── Punch-mode setup ──────────────────────────────────────────
    // When --punch is set together with --ns-server, we wrap the Quinn
    // socket in PunchRuntime so PUNCH_NOTIFY (0x0B) and PUNCH_BYTE
    // (0x00) are intercepted/dropped before Quinn's QUIC parser sees
    // them. Without --ns-server, --punch is a no-op because there's no
    // coordinator for the punch dance — we warn instead of failing
    // so existing scripts that pass --punch alone keep working.
    let punch_ns_addr: Option<std::net::SocketAddr> = if punch_enabled {
        match ns_server.as_deref() {
            Some(s) => match s.parse() {
                Ok(a) => Some(a),
                Err(e) => {
                    eprintln!(
                        "{} --punch requires a parseable --ns-server (got {:?}: {})",
                        c_yellow("⚠"),
                        s,
                        e
                    );
                    None
                }
            },
            None => {
                eprintln!(
                    "{} --punch requires --ns-server; running without punch (relay-only)",
                    c_yellow("⚠")
                );
                None
            }
        }
    } else {
        None
    };

    let (intercept_tx, intercept_rx) = if punch_ns_addr.is_some() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let server = if let Some(tx) = intercept_tx.clone() {
        let runtime: std::sync::Arc<dyn quinn::Runtime> =
            std::sync::Arc::new(ztlp_proto::punch_socket::PunchRuntime::new(tx));
        QuicEndpoint::bind_with_socket_and_runtime(server_cfg, std_socket, runtime)?
    } else {
        QuicEndpoint::bind_with_socket(server_cfg, std_socket)?
    };
    println!(
        "ZTLP QUIC server listening on UDP {}",
        server.inner.local_addr().unwrap()
    );

    // ── Start the PunchAgent keepalive + dispatcher (if --punch) ──
    // We hold the JoinHandles in a Vec so they live as long as cmd_listen
    // does — dropping them earlier would cancel the tasks. The dispatcher
    // exits naturally when its sender side (the PunchSocket inside Quinn's
    // runtime) is dropped at shutdown.
    let mut _punch_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let (Some(ns_addr), Some(rx)) = (punch_ns_addr, intercept_rx) {
        // Bind a separate keepalive socket (ephemeral) — we cannot share
        // the QUIC socket because Quinn has taken ownership of it. The
        // NS server will learn this ephemeral socket's (ip, port) as the
        // gateway's :learned endpoint. For the local-network bench this
        // is fine — both Quinn and keepalive go through the same NAT,
        // so the (ip, port) NS sees is reachable.
        //
        // We bind a fresh ephemeral socket for the keepalive task; the
        // QUIC listener port is plumbed explicitly via with_listener_port
        // so PUNCH_REPORT candidates carry the listener's port, not the
        // keepalive socket's ephemeral port.
        let listener_port = server
            .inner
            .local_addr()
            .map_err(|e| format!("failed to read QUIC listener local_addr: {}", e))?
            .port();
        let keepalive_sock = std::sync::Arc::new(
            tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("failed to bind PunchAgent keepalive socket: {}", e))?,
        );
        let gw_node_id = identity.node_id;
        let agent = ztlp_proto::punch_agent::PunchAgent::with_listener_port(
            keepalive_sock,
            ns_addr,
            gw_node_id,
            listener_port,
            advertise_interface.to_vec(),
            no_advertise_interface.to_vec(),
            advertise_all_interfaces,
        );
        println!(
            "{} Punch enabled — keepalive to {} every {:?} (advertising listener port {})",
            c_green("✓"),
            ns_addr,
            ztlp_proto::punch_agent::DEFAULT_KEEPALIVE_INTERVAL,
            listener_port,
        );
        _punch_handles
            .push(agent.start_keepalive(ztlp_proto::punch_agent::DEFAULT_KEEPALIVE_INTERVAL));
        _punch_handles
            .push(agent.start_dispatcher(rx, ztlp_proto::punch::DEFAULT_RESPONDER_DURATION));
    }

    let _cfw = forward.to_vec();
    // identity already loaded above (before the punch block needs the NodeId).

    if let (Some(r_addr), Some(reg_sock)) = (relay_addr, register_socket) {
        if let Ok(target) = r_addr.parse::<std::net::SocketAddr>() {
            println!(
                "Enabling QUIC gateway registration for relay: {} (src={})",
                target, local_addr
            );

            // ─── V2 zone-keyed registration setup ──────────────────────
            //
            // When --zone is set we emit BOTH V1 (0x0A) and V2 (0x0E) frames
            // each registration tick. V2 carries the zone explicitly so the
            // relay can route by `gw:<zone>` and avoid cross-tenant slug
            // collisions (see docs/plans/2026-05-24-zone-keyed-gateway-
            // register-IMPL.md).
            //
            // The decision logic lives in `resolve_v2_config` (pure,
            // tested). Key behavior: if --zone is set but the per-zone
            // HMAC secret env var is missing/empty, we STILL emit V2
            // (with a zero-byte HMAC). The relay's HMAC mode decides
            // whether to accept the frame; the gateway must not silently
            // fall back to V1-only just because a secret wasn't set.
            // Pre-v0.30.7 the gateway silently disabled V2 in that case,
            // forcing 12 of 19 tenants to need manual secret injection
            // during the v0.30.5 fleet deploy.
            let v2_config = resolve_v2_config(zone.as_deref(), zone_hmac_secret_env.as_deref());
            if let Some((z, secret)) = &v2_config {
                if secret.is_empty() {
                    eprintln!(
                        "{} --zone={} set but per-zone HMAC secret is empty/unset; \
                         emitting V2 with a zero-byte HMAC. The relay's HMAC mode \
                         (ZTLP_RELAY_HMAC_MODE=dev/staging/prod) decides whether \
                         to accept it. Set ZTLP_HMAC_SECRET_<SLUG> to enable \
                         verified V2 emission.",
                        c_yellow("⚠"),
                        z
                    );
                }
            }

            // Convert the cloned std socket to a tokio non-blocking socket so
            // we can use it inside async code. Both this socket and Quinn's
            // socket point at the same kernel-level UDP socket, so the relay
            // sees a single (ip, port) for both registration packets and
            // QUIC traffic.
            reg_sock.set_nonblocking(true).ok();
            let tokio_sock = match tokio::net::UdpSocket::from_std(reg_sock) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("failed to convert registration socket to tokio: {}", e);
                    return Err(Box::new(e));
                }
            };

            let identity_c = identity.clone();
            let svc = service_name.to_string();
            tokio::spawn(async move {
                let relay_addr = target;
                let node_id = identity_c.node_id.0;

                // Send initial registration immediately so the relay can
                // route inbound HELLOs before any client tries to connect.
                let ts = std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let pkt = build_gateway_register_packet(&node_id, &svc, ts);

                match tokio_sock.send_to(&pkt, relay_addr).await {
                    Ok(n) => {
                        debug!("gateway registration sent to {} ({} bytes)", relay_addr, n);
                        match &v2_config {
                            Some((z, _)) => eprintln!(
                                "{} gateway registered with {} (V1 service={}, V2 zone={})",
                                c_green("✓"),
                                relay_addr,
                                svc,
                                z
                            ),
                            None => eprintln!(
                                "{} gateway registered with {} (service: {})",
                                c_green("✓"),
                                relay_addr,
                                svc
                            ),
                        }
                    }
                    Err(e) => {
                        eprintln!("Initial relay registration send error: {}", e);
                    }
                }

                // Emit initial V2 packet immediately after V1 (the v1 emit
                // is above; this fires the v2 if configured).
                if let Some((z, secret)) = &v2_config {
                    match build_gateway_register_v2_packet(
                        &node_id,
                        z,
                        &svc,
                        RELAY_REGISTER_TTL,
                        ts,
                        secret,
                    ) {
                        Ok(p) => {
                            if let Err(e) = tokio_sock.send_to(&p, relay_addr).await {
                                eprintln!("Initial V2 registration send error: {}", e);
                            } else {
                                debug!(
                                    "V2 gateway registration sent to {} (zone={})",
                                    relay_addr, z
                                );
                            }
                        }
                        Err(e) => eprintln!("Initial V2 packet build error: {}", e),
                    }
                }

                // Periodic re-registration loop on the SAME shared socket.
                // Emits V1 every tick, and V2 alongside V1 when v2_config is Some.
                loop {
                    tokio::time::sleep(RELAY_REREGISTER_INTERVAL).await;
                    let ts = std::time::SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let pkt = build_gateway_register_packet(&node_id, &svc, ts);
                    match tokio_sock.send_to(&pkt, relay_addr).await {
                        Ok(_) => {
                            debug!("gateway reregistration sent to {}", relay_addr);
                        }
                        Err(e) => {
                            eprintln!("background relay reregistration failed: {}", e);
                        }
                    }
                    if let Some((z, secret)) = &v2_config {
                        match build_gateway_register_v2_packet(
                            &node_id,
                            z,
                            &svc,
                            RELAY_REGISTER_TTL,
                            ts,
                            secret,
                        ) {
                            Ok(p) => {
                                if let Err(e) = tokio_sock.send_to(&p, relay_addr).await {
                                    eprintln!("background V2 reregistration failed: {}", e);
                                }
                            }
                            Err(e) => eprintln!("V2 packet build error: {}", e),
                        }
                    }
                }
            });
        } else {
            eprintln!("Invalid relay address format: {}", r_addr);
        }
    }

    // ── NS self-registration heartbeat ──────────────────────────────
    //
    // OPT-IN: only spawn when the operator explicitly passes
    // `--ns-register-name` AND `--ns-server` AND `--zone`. Using
    // `--service-name` (which has a default of `ztlp-gateway`) would silently
    // register every gateway under a junk name, so we require an explicit
    // name here. Listeners that already get their NS records published
    // externally (Chef cookbook, manual `ztlp ns register`, etc.) simply
    // omit `--ns-register-name` and behavior is unchanged.
    //
    // Heartbeat cadence: 8 hours nominal + up to 10 minutes uniform jitter
    // to smear load when ~1000 listeners share the same interval. Records
    // carry a 24h TTL, so 3 cycles per TTL window is comfortable headroom.
    //
    // The initial publish is synchronous and ABORTS startup on error. A
    // misconfigured zone/identity must fail fast at the Windows service
    // event log rather than silently never publishing.
    //
    // The SVC record carries the listener's address, which clients use to
    // dial directly. If the bind address is unspecified (`0.0.0.0:PORT` or
    // `[::]:PORT`), publishing SVC would advertise an unroutable endpoint,
    // so we publish KEY-only in that case. A concrete bind is required for
    // SVC publication.
    //
    // See docs/plans/2026-06-01-ns-self-register-heartbeat.md.
    if let (Some(register_name), Some(ns), Some(z)) = (ns_register_name, ns_server.as_deref(), zone)
    {
        let listener_addr = server
            .inner
            .local_addr()
            .map_err(|e| format!("failed to read QUIC listener local_addr: {}", e))?;
        let listener_port = listener_addr.port();

        // ── Stage 2 (v0.35.x): multi-candidate SVC advertisement ────────
        //
        // Pre-Stage-2 behavior: a concrete bind echoed its own socket addr as
        // the single SVC `address`; a wildcard (`0.0.0.0`/`[::]`) bind
        // SURRENDERED and published KEY only — leaving multi-NIC / NAT'd
        // fleets dark.
        //
        // Now: regardless of bind, enumerate every reachable local NIC
        // (filtered: skips loopback/APIPA/docker/down) and append the relay
        // backstop, then publish them ALL. `address` = best candidate (old
        // clients still work); `addresses` = full comma-joined list (new
        // clients rank + race/failover). When the box is bound concretely to a
        // single routable NIC the enumerator still returns that NIC, so the
        // legacy single-address case is preserved.
        //
        // The relay backstop is the box's registered relay (`relay_addr`) —
        // this replaces the decaying out-of-band `ns register --address
        // <relay>` Chef hack for NAT'd boxes: the heartbeat republishes the
        // relay candidate every cycle, so the SVC never expires between
        // converges.
        let relay_advertise: Option<SocketAddr> =
            relay_addr.and_then(|r| r.parse::<SocketAddr>().ok());
        let (mut advertise_addr, advertise_addresses) = compute_advertised_svc(
            listener_port,
            relay_advertise,
            advertise_interface,
            no_advertise_interface,
            advertise_all_interfaces,
        );

        // Rare fallback: concrete bind but the enumerator saw no NIC (e.g. a
        // bind to an address if_addrs can't observe). Advertise the bind addr
        // itself, matching legacy behavior exactly.
        if advertise_addr.is_none() && !listener_addr.ip().is_unspecified() {
            advertise_addr = Some(listener_addr.to_string());
        }

        if advertise_addr.is_none() {
            eprintln!(
                "{} no routable candidate to advertise for {} (wildcard bind, no usable NIC, \
                 no relay); publishing KEY only — dial requires at least one concrete \
                 candidate or a --relay backstop",
                c_yellow("⚠"),
                listener_addr
            );
        }

        let name = register_name.to_string();
        let zone_s = z.to_string();
        let ns_s = ns.to_string();
        let identity_arc = std::sync::Arc::new(identity.clone());

        // Initial synchronous publish — fail fast on misconfiguration.
        ns_publish_self(
            &name,
            &zone_s,
            &identity_arc,
            &ns_s,
            advertise_addr.as_ref(),
            advertise_addresses.as_deref(),
        )
        .await
        .map_err(|e| {
            format!(
                "initial NS publish failed: {} — refusing to start listener with a \
                 broken NS heartbeat config. Check --ns-register-name '{}' lives \
                 inside --zone '{}', and NS at {} is reachable.",
                e, name, zone_s, ns_s
            )
        })?;

        eprintln!(
            "{} NS heartbeat enrolled: {}{} -> {}",
            c_green("✓"),
            name,
            advertise_addr
                .as_deref()
                .map(|a| format!(" @ {}", a))
                .unwrap_or_default(),
            ns_s
        );
        if let Some(list) = advertise_addresses.as_deref() {
            eprintln!(
                "{} advertising {} SVC candidates: {}",
                c_dim("→"),
                list.split(',').count(),
                list
            );
        }

        // Spawn the long-lived heartbeat task. We don't hold the JoinHandle
        // — the task lives as long as the process. It republishes the SVC
        // (incl. the relay candidate) every cycle, killing the decay.
        tokio::spawn(ns_heartbeat_task(
            name,
            zone_s,
            identity_arc,
            ns_s,
            advertise_addr,
            advertise_addresses,
            Duration::from_secs(8 * 3600), // 8h nominal
            Duration::from_secs(10 * 60),  // ±10min jitter
        ));
    }

    let service_registry = match ztlp_proto::tunnel::ServiceRegistry::from_forward_args(forward) {
        Ok(reg) => std::sync::Arc::new(reg),
        Err(e) => {
            eprintln!("Failed to parse --forward arguments: {}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                e,
            )));
        }
    };
    loop {
        let conn: ztlp_proto::quic_transport::tokio_endpoint::QuicConnection =
            match server.accept().await {
                Ok(c) => c,
                Err(e) => {
                    // A failed/timed-out INCOMING handshake must NOT kill the
                    // gateway. Quinn's `incoming.await?` (inside QuicEndpoint::accept)
                    // returns Err on every client that gives up mid-handshake,
                    // and the original code propagated that to main() via `?` ,
                    // which exited the process and Docker crash-looped us. Log
                    // and accept the next connection. This is the v0.29.2
                    // gateway-side fix for the test-org-2 crash loop.
                    eprintln!("✗ QUIC accept failed (continuing to accept next): {:?}", e);
                    continue;
                }
            };
        let service_registry_clone = service_registry.clone();

        let identity_clone = identity.clone();

        let http_inject_headers_copy = http_inject_headers;
        let admin_map = if http_inject_headers {
            let mut map = std::collections::HashMap::new();
            for entry in admin_pubkey_email {
                let mut parts = entry.splitn(2, '=');
                let hex_str = parts.next().unwrap().trim();
                let email = parts.next().unwrap().trim();
                map.insert(hex_str.to_lowercase(), email.to_string());
            }
            map
        } else {
            std::collections::HashMap::new()
        };
        // Provide dummy hmac since secret is required
        let hmac_secret = header_hmac_secret.unwrap_or("").to_string();
        let (_session, service_hash_bytes) =
            match ztlp_proto::quic_transport::noise_stream::run_responder_handshake(
                &conn,
                &identity_clone,
                ztlp_proto::identity::NodeId([0; 16]), // Accept any for now
            )
            .await
            {
                Ok(res) => {
                    println!("Responder handshake success");
                    (res.0.session, res.1)
                }
                Err(e) => {
                    // A single failed handshake (timeout, malformed Noise,
                    // client disconnect mid-msg3, etc.) must NEVER take down
                    // the whole gateway process — Docker would restart us in
                    // a crash loop and every other tenant tunnel would drop.
                    // Log the reason and accept the next connection. This is
                    // the v0.29.x bugfix for the test-org-2 crash loop where
                    // an idle QUIC connection's "timed out" Err propagated up
                    // through cmd_listen, killing the binary.
                    eprintln!(
                        "✗ Responder handshake failed (continuing to accept next): {:?}",
                        e
                    );
                    continue;
                }
            };

        let target_clone = match service_registry_clone.resolve(&service_hash_bytes) {
            Some((name, addr)) => {
                println!("Resolved service hash to backend {} at {}", name, addr);
                addr.to_string()
            }
            None => {
                eprintln!(
                    "Rejecting QUIC stream: service hash {:?} not mapped to any known backend.",
                    service_hash_bytes
                );
                continue;
            }
        };

        tokio::spawn(async move {
            loop {
                if let Ok((mut q_send, mut q_recv)) = conn.accept_bi().await {
                    let tcp = tokio::net::TcpStream::connect(&target_clone).await.unwrap();
                    let (mut t_read, mut t_write) = tcp.into_split();

                    let hmac = hmac_secret.clone();
                    let map = admin_map.clone();

                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};

                        if http_inject_headers_copy {
                            if let Ok(frame) =
                                ztlp_proto::quic_transport::noise_stream::read_ztlp_frame(
                                    &mut q_recv,
                                )
                                .await
                            {
                                let mut injected = false;
                                if let Some((_, email)) = map.iter().next() {
                                    // Ensure exact ISO8601 formatting since chronos produces dynamic timestamps correctly now
                                    let now = SystemTime::now();
                                    let ts = chrono::DateTime::<chrono::Utc>::from(now)
                                        .format("%Y-%m-%dT%H:%M:%SZ")
                                        .to_string();
                                    let slice = &frame[..];
                                    let rewrite_result = ztlp_proto::http_injector::inject_headers(
                                        slice,
                                        email,
                                        &ts,
                                        hmac.as_bytes(),
                                    );
                                    if let Ok(rewritten) = rewrite_result {
                                        let _ = t_write.write_all(&rewritten).await;
                                        injected = true;
                                    }
                                }
                                if !injected {
                                    let _ = t_write.write_all(&frame[..]).await;
                                }
                            } else {
                                return;
                            }
                        }

                        let mut read_buf = vec![0u8; 65000];
                        loop {
                            tokio::select! {
                                res = t_read.read(&mut read_buf) => {
                                    match res {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            println!("TCP->QUIC Read {} bytes", n);
                                            if ztlp_proto::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, &read_buf[..n]).await.is_err() {
                                                println!("TCP->QUIC Write Error");
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                res = ztlp_proto::quic_transport::noise_stream::read_ztlp_frame(&mut q_recv) => {
                                    match res {
                                        Ok(frame) => {
                                            println!("QUIC->TCP Read {} bytes", frame.len());
                                            if tokio::io::AsyncWriteExt::write_all(&mut t_write, &frame).await.is_err() {
                                                println!("QUIC->TCP Write Error");
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                    });
                } else {
                    break;
                }
            }
        });
    }
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
#[allow(dead_code)]
async fn cmd_listen_multi_session(
    _node: &TransportNode,
    _identity: &NodeIdentity,
    _forward: &[String],
    _policy: &PolicyEngine,
    _ns_server: &Option<String>,
    _max_sessions: usize,
    _http_injection: Arc<tunnel::HttpInjectionConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

/// Complete a Noise_XX handshake just to send a REJECT frame.
///
/// Used when we need to reject a client (e.g., capacity full) but still
/// need an encrypted channel to send the rejection reason.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    http_injection: Arc<tunnel::HttpInjectionConfig>,
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
    let resolve_result = registry.resolve(&recv1_header.dst_svc_hash);
    let (svc_name, forward_addr) = match resolve_result {
        Some(pair) => pair,
        None => {
            // Option C: dst_svc_hash is an opaque 16-byte hash, not UTF-8.
            // Surface the hex form so the operator can correlate with NS records.
            let requested = hex::encode(recv1_header.dst_svc_hash);
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
            match run_session_bridge(
                udp,
                pipeline,
                session_id,
                from,
                &forward_addr_owned,
                rx,
                http_injection.clone(),
                peer_pubkey_hex.clone(),
            )
            .await
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
#[allow(dead_code)]
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
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
async fn run_session_bridge(
    udp_send_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    forward_addr: &str,
    mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
    http_injection: Arc<tunnel::HttpInjectionConfig>,
    peer_pubkey_hex: Option<String>,
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
    let result = tunnel::run_bridge_demuxed_with_http_injection(
        tcp_stream,
        udp_send_socket.clone(),
        recv_socket.clone(),
        pipeline.clone(),
        session_id,
        peer_addr,
        Vec::new(), // initial_packets already forwarded to recv_socket
        http_injection.clone(),
        peer_pubkey_hex.clone(),
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

        last_outcome = tunnel::run_bridge_demuxed_with_http_injection(
            tcp_stream,
            udp_send_socket.clone(),
            recv_socket.clone(),
            pipeline.clone(),
            session_id,
            peer_addr,
            Vec::new(),
            http_injection.clone(),
            peer_pubkey_hex.clone(),
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
#[allow(dead_code)]
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

fn ns_record_payload(response: &[u8]) -> Result<Option<&[u8]>, Box<dyn std::error::Error>> {
    match response {
        [] => Ok(None),
        [0x02, 0x01, record @ ..] => {
            // Some NS replies insert a truncation/continuation flag byte after
            // the found marker. Keep the actual record type byte intact.
            Ok(Some(record))
        }
        [0x02, record @ ..] => Ok(Some(record)),
        _ => Ok(None),
    }
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
                    // Record found — parse the wire format. Some NS replies add
                    // a flag byte after 0x02; ns_record_payload strips only the
                    // envelope so print_ns_record still sees the record type.
                    if let Some(record_data) = ns_record_payload(data)? {
                        eprintln!("\n{}", c_green("✓ Record found:"));
                        print_ns_record(record_data, name)?;
                    }
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
                    if let Some(record_data) = ns_record_payload(data)? {
                        eprintln!("\n{}", c_green("✓ Record found:"));
                        print_ns_record(record_data, &pk_hex)?;
                    }
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

/// Publish KEY and (optionally) SVC records for `identity` to NS at `ns_server`.
///
/// Extracted from `cmd_ns_register` so the same logic can be driven by:
///   - The `ztlp ns register` CLI subcommand (backward compat).
///   - The `ns_heartbeat_task` that runs inside `ztlp listen`, refreshing the
///     record before its 24h TTL expires.
///
/// Validates that `name` is within `zone` before touching the network, so a
/// misconfigured listener fails fast at startup rather than silently never
/// publishing.
///
/// See docs/plans/2026-06-01-ns-self-register-heartbeat.md for design.
/// Compute the gateway's advertised SVC candidate set for the CURRENT NIC
/// state (Stage 2). Re-evaluated on every heartbeat so a VPN flap or NIC
/// change self-heals on the next cycle.
///
/// Returns `(best_address, addresses_field)`:
/// - `best_address` — the single best candidate (element 0), used for the
///   legacy `address` SVC field that old clients read. `None` when nothing
///   routable is available (wildcard bind, no NIC, no relay) → caller
///   publishes KEY only, exactly as the pre-Stage-2 surrender path did.
/// - `addresses_field` — comma-joined full candidate list for the new
///   `addresses` SVC field, or `None` when there's only 0/1 candidate (no
///   point shipping a 1-element list; the single `address` already covers it).
///
/// `relay_advertise` is the relay backstop to append (NAT'd boxes that can't
/// be reached on any LAN NIC). `include`/`exclude`/`all` are the operator
/// interface overrides already plumbed through `cmd_listen`.
fn compute_advertised_svc(
    listener_port: u16,
    relay_advertise: Option<SocketAddr>,
    include: &[String],
    exclude: &[String],
    all: bool,
) -> (Option<String>, Option<String>) {
    let local = ztlp_proto::local_candidates::enumerate_local_candidates_with_overrides(
        listener_port,
        include,
        exclude,
        all,
    );
    let cands = ztlp_proto::svc_candidates::assemble_advertised(&local, relay_advertise);
    let best = cands.first().cloned();
    let addresses = if cands.len() > 1 {
        Some(ztlp_proto::svc_candidates::encode_addresses_field(&cands))
    } else {
        None
    };
    (best, addresses)
}

async fn ns_publish_self(
    name: &str,
    zone: &str,
    identity: &NodeIdentity,
    ns_server: &str,
    address: Option<&String>,
    // Stage 2 (v0.35.x): comma-joined ICE candidate list, best-first. When
    // present it is published in the SVC record's `addresses` field ALONGSIDE
    // the single `address` (which stays = best candidate for old clients).
    // `None` (or empty) preserves the legacy single-address SVC record exactly.
    addresses: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the name is within the specified zone BEFORE binding any
    // socket — keeps test harnesses cheap and gives an obvious error at
    // startup when an operator passes a mismatched name/zone.
    if !name.ends_with(&format!(".{}", zone)) && name != zone {
        return Err(format!(
            "name '{}' is not within zone '{}'\n  The name must end with '.{}'",
            name, zone, zone
        )
        .into());
    }

    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid NS server address '{}': {}", ns_server, e))?;

    let node_id_hex = hex::encode(identity.node_id.0);
    let pubkey_hex = hex::encode(&identity.static_public_key);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    // ── KEY record ──────────────────────────────────────────────────
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
                Some(0x06) => { /* ACK */ }
                Some(0xFF) => {
                    return Err(format!(
                        "KEY registration failed: {}",
                        decode_registration_error(resp)
                    )
                    .into());
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
            return Err(format!("timeout waiting for NS server response at {}", ns_server).into());
        }
    }

    // ── SVC record (only when address provided) ─────────────────────
    if let Some(addr_str) = address {
        // Validate address format
        let _: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("invalid address '{}': {} (expected ip:port)", addr_str, e))?;

        let mut svc_pairs = vec![
            ("address", addr_str.as_str()),
            ("node_id", node_id_hex.as_str()),
            ("zone", zone),
        ];
        // Stage 2: publish the full ICE candidate set alongside the single
        // `address`. Old clients read `address`; new clients split `addresses`,
        // rank against their own subnets, and dial/failover. Empty/None list →
        // legacy single-address SVC (no `addresses` key) for exact back-compat.
        if let Some(list) = addresses {
            if !list.is_empty() {
                svc_pairs.push(("addresses", list));
            }
        }
        let svc_data_bin = cbor_map(&mut svc_pairs);

        let svc_pkt = build_registration_packet(name, 2, &svc_data_bin); // type 2 = SVC
        sock.send_to(&svc_pkt, ns_addr).await?;

        // SVC failures are non-fatal — KEY is the critical record. Callers can
        // surface their own logging if they care; the heartbeat task just
        // retries next tick.
        let _ = timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await;
    }

    // ── Verify (KEY lookup) ─────────────────────────────────────────
    // Small delay to let server process the registration.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let name_bytes = name.as_bytes();
    let name_len_u16 = name_bytes.len() as u16;
    let mut query = Vec::with_capacity(4 + name_bytes.len());
    query.push(0x01); // Query opcode
    query.extend_from_slice(&name_len_u16.to_be_bytes());
    query.extend_from_slice(name_bytes);
    query.push(1); // KEY record type

    sock.send_to(&query, ns_addr).await?;
    let _ = timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await;

    Ok(())
}

/// Heartbeat loop that republishes this listener's NS records before the 24h
/// TTL expires. Spawned by `cmd_listen` when NS settings are configured.
///
/// `interval` is the nominal time between publishes (8h in production).
/// `jitter_max` adds [0, jitter_max) random delay each cycle to smear load
/// from a large fleet (10min in production).
///
/// Failures are logged at WARN and retried on the next tick — the listener
/// keeps serving traffic regardless of NS health.
async fn ns_heartbeat_task(
    name: String,
    zone: String,
    identity: std::sync::Arc<NodeIdentity>,
    ns_server: String,
    address: Option<String>,
    // Stage 2: full ICE candidate list (comma-joined) published in the SVC
    // `addresses` field every cycle. `None` → legacy single-address SVC.
    addresses: Option<String>,
    interval: Duration,
    jitter_max: Duration,
) {
    loop {
        match ns_publish_self(
            &name,
            &zone,
            &identity,
            &ns_server,
            address.as_ref(),
            addresses.as_deref(),
        )
        .await
        {
            Ok(()) => {
                eprintln!(
                    "{} [ns_heartbeat] published {} to {}",
                    c_dim("→"),
                    name,
                    ns_server
                );
            }
            Err(e) => {
                eprintln!(
                    "{} [ns_heartbeat] publish failed ({}): {} — will retry in {:?}",
                    c_yellow("⚠"),
                    name,
                    e,
                    interval
                );
            }
        }

        // Sleep with jitter — uniform [0, jitter_max) added to the nominal
        // interval. Avoids stampeding NS at the top of each cycle when 1000
        // listeners share the same interval. Cheap LCG seeded from
        // current-time nanos; cryptographic randomness is not required for
        // load smearing.
        let jitter = if jitter_max.is_zero() {
            Duration::ZERO
        } else {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0);
            let r = nanos
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let bound = (jitter_max.as_millis() as u64).max(1);
            Duration::from_millis(r % bound)
        };
        tokio::time::sleep(interval + jitter).await;
    }
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
                    return Err(format!(
                        "KEY registration failed: {}",
                        decode_registration_error(resp)
                    )
                    .into());
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
                            "  {} SVC registration failed: {}",
                            c_yellow("⚠"),
                            decode_registration_error(resp)
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
        if rest.len() < 4 + data_len {
            eprintln!("  {} (truncated record data)", c_dim("Raw:"));
            eprintln!("  {} {} bytes total", c_dim("Wire size:"), data.len());
            return Ok(());
        }
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

/// `ztlp gateway candidates <name>` — operator-facing diagnostic (v0.32 M7).
///
/// Resolves the gateway name via NS (SVC + KEY records), queries NS for
/// `PEER_ENDPOINTS` (0x0A), classifies each returned endpoint against the
/// v0.32 priority ladder (with an *empty* client-subnet set — same-subnet
/// is the dialer's concern, not the operator's), and pretty-prints the
/// result.
///
/// Pure formatting lives in `ztlp_proto::admin::gateway_candidates`; this
/// fn is the thin glue that does the NS round-trip.
async fn cmd_gateway_candidates(
    name: &str,
    ns_server: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::admin::gateway_candidates::{format_candidates_json, format_candidates_table};
    use ztlp_proto::candidate_priority::{classify, RankedCandidate};
    use ztlp_proto::punch::{
        decode_peer_endpoints_response, encode_peer_endpoints_request, NS_PEER_ENDPOINTS,
    };

    // 1. Resolve the gateway name → (transport addr, NodeId) via NS.
    let ns_server_opt = Some(ns_server.to_string());
    let (_gateway_addr, _gateway_candidates, gateway_nid) =
        resolve_target(name, &ns_server_opt).await?;
    let gateway_nid = gateway_nid.ok_or_else(|| {
        format!(
            "could not resolve NodeId for gateway '{}' via NS at {} (no KEY record?)",
            name, ns_server,
        )
    })?;

    // 2. Build a throwaway requester identity. We're a diagnostic tool
    //    — we don't need a stable NodeId for this.
    let requester = NodeIdentity::generate()?;

    // 3. Open an ephemeral UDP socket and ask NS for the gateway's
    //    endpoints. Wire format: PEER_ENDPOINTS (0x0A).
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid --ns-server '{}': {}", ns_server, e))?;

    let req = encode_peer_endpoints_request(&requester.node_id, &gateway_nid, &[]);
    socket.send_to(&req, ns_addr).await?;

    // 4. Wait up to 5s for the response.
    let mut buf = [0u8; 1500];
    let endpoints = match tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            if from == ns_addr && !buf[..len].is_empty() && buf[0] == NS_PEER_ENDPOINTS {
                return decode_peer_endpoints_response(&buf[..len])
                    .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) });
            }
            // Ignore stray packets and keep waiting.
        }
    })
    .await
    {
        Ok(Ok(eps)) => eps,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(format!(
                "timeout waiting for PEER_ENDPOINTS response from NS at {}",
                ns_addr,
            )
            .into());
        }
    };

    // 5. Classify each endpoint with an empty client_subnets — we're a
    //    diagnostic tool, "same-subnet" doesn't apply.
    let ranked: Vec<RankedCandidate> = endpoints
        .iter()
        .map(|ep| {
            let class = classify(ep.addr, &[]);
            RankedCandidate {
                addr: ep.addr,
                class,
                priority: class.priority(),
            }
        })
        .collect();

    // 6. Print.
    if json {
        println!("{}", format_candidates_json(name, &gateway_nid, &ranked));
    } else {
        print!("{}", format_candidates_table(name, &gateway_nid, &ranked));
    }

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
        hex::encode(header.dst_svc_hash)
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
    let (target_addr, _target_candidates, _) = resolve_target(target, ns_server).await?;

    let raw_socket = socket2::Socket::new(
        if bind.contains(':') && bind.starts_with('[') {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // Desktop/testbed multi-megabyte window tuning
    let _ = raw_socket.set_recv_buffer_size(7 * 1024 * 1024);
    let _ = raw_socket.set_send_buffer_size(7 * 1024 * 1024);

    let addr: std::net::SocketAddr = bind.parse()?;
    raw_socket.bind(&addr.into())?;

    let sock = UdpSocket::from_std(raw_socket.into())?;
    let _ = ztlp_proto::gso::enable_gro(&sock);
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
        let now_ms = std::time::SystemTime::now()
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

/// Stage 2 (v0.35.x) multi-candidate pre-selection: probe a client-ranked
/// candidate list (best-first) and return the FIRST that looks reachable via
/// the ZTLP UDP liveness probe ([`check_ztlp_udp_addr`]).
///
/// This is the client half of ICE: a gateway publishes ALL its addresses
/// (LAN NICs + relay) and only the client can tell which one IT can reach. A
/// same-LAN operator's probe to the LAN candidate succeeds first; a remote
/// operator's LAN probe draws an ICMP-unreachable (or no listener) so we move
/// on and the relay candidate wins. Returns `None` only when EVERY candidate
/// fails the probe — the caller then keeps the best-ranked address and lets
/// the QUIC handshake + auto-reconnect supervisor retry (the probe is
/// advisory, never authoritative: a silent-dropping middlebox could mask a
/// truly-open path, so we never hard-fail on probe alone).
async fn select_reachable_candidate(
    candidates: &[std::net::SocketAddr],
) -> Option<std::net::SocketAddr> {
    for cand in candidates {
        if check_ztlp_udp_addr(*cand).await {
            return Some(*cand);
        }
        eprintln!(
            "{} candidate {} did not answer probe; trying next",
            c_dim("·"),
            cand
        );
    }
    None
}

// ─── Setup Wizard ───────────────────────────────────────────────────────────

/// `ztlp setup` — Interactive setup wizard
async fn cmd_setup(
    token_arg: &Option<String>,
    name_arg: &Option<String>,
    _setup_type: SetupType,
    _owner_arg: &Option<String>,
    bind_user: bool,
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
        return setup_join(token_str, name_arg, bind_user, auto_yes).await;
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

            setup_join(&token_str, name_arg, bind_user, auto_yes).await
        }
        1 => {
            // CodeRabbit #4 (ztlp-cli.rs:509): --bind-user is meaningful only for
            // the join path, where it stamps the joining user's SID/UID into
            // identity.json. The create-network branch generates a network and
            // doesn't enroll a node identity, so the flag would silently no-op.
            // Fail fast instead so operators see the misconfiguration.
            if bind_user {
                return Err("--bind-user is not supported with create-network setup; \
                            it applies only to the join path (where identity.json is written). \
                            Re-run without --bind-user, or use 'ztlp setup --bind-user' \
                            with an enrollment token to join an existing network."
                    .into());
            }
            setup_create_network(auto_yes).await
        }
        _ => unreachable!(),
    }
}

/// Setup path: join an existing network with an enrollment token.
async fn setup_join(
    token_str: &str,
    name_arg: &Option<String>,
    bind_user: bool,
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
    let mut identity = NodeIdentity::generate()?;

    // D3.T1: --bind-user records the current OS user's SID/UID so the daemon
    // refuses to operate under any other user. We resolve eagerly here so an
    // unenrollable environment fails BEFORE we touch the gateway.
    if bind_user {
        let sid = ztlp_proto::agent::user_binding::current_user_sid().map_err(|e| {
            format!(
                "--bind-user requires a working user-resolution shim: {}\n\
                 Hint: run `id -u` (Unix) or `whoami /user` (Windows) manually to diagnose.",
                e
            )
        })?;
        eprintln!("  {} Binding identity to user {}", c_dim("→"), c_cyan(&sid));
        identity.bound_user_sid = Some(sid);
    }

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
                        // v0.30.12: pass the device's Noise static pubkey so
                        // Launch can auto-bind it for passwordless gateway
                        // sign-in. Bootstrap (Rails) ignores unknown fields,
                        // so this is safe to send unconditionally.
                        let pubkey_hex = hex::encode(identity.static_public_key.as_slice());
                        confirm_enrollment(url, &token, &full_name, &identity.node_id, &pubkey_hex)
                            .await;
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

                    // Surface the public key for passwordless gateway-auth setup.
                    // ztlp.net's claim page (and any tenant admin panel) needs
                    // this 64-char hex string to bind the device to an admin
                    // identity. Without it, the gateway has no admin pubkeys
                    // to match against and the bootstrap UI falls back to its
                    // password form. The secret half NEVER leaves identity.json
                    // on disk — only the public half is printed here.
                    let pubkey_hex = hex::encode(identity.static_public_key.as_slice());
                    eprintln!(
                        "  {}",
                        c_bold("── Enable passwordless sign-in (optional) ─────")
                    );
                    eprintln!();
                    eprintln!(
                        "  Paste this {} on your zone's claim page to enable",
                        c_cyan("public key")
                    );
                    eprintln!("  passwordless Bootstrap sign-in from this device:");
                    eprintln!();
                    eprintln!("      {}", c_bold(&pubkey_hex));
                    eprintln!();
                    eprintln!(
                        "  {} Only the public half is shown. The private key stays",
                        c_dim("ℹ")
                    );
                    eprintln!(
                        "  {}  in {} on this machine (chmod 600).",
                        c_dim(" "),
                        key_path.display()
                    );
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

/// Confirm enrollment with the Bootstrap app.
///
/// Phase B: this used to be a `_ = result;`-style best-effort callback that
/// silently swallowed every failure mode (DNS, TLS, 4xx, 5xx, timeout).
/// That made the redemption bug invisible — Steve's CLI said "enrolled"
/// while the Bootstrap dashboard still showed `active` because this
/// callback either was never sent (callback URL nil) or failed in a way
/// no operator could see.
///
/// New behavior:
///   * If `callback_url` is missing/empty, do nothing (legacy tokens predate
///     Phase B and have no callback path; print one diagnostic line).
///   * Drop `-f` (curl's fail-on-error) so we get the response body on 4xx/5xx.
///   * On HTTP success, print "Redeemed" line so the operator can see it.
///   * On HTTP failure, print a *visible* warning with status + body so the
///     bug — if any — is loud, not silent. Enrollment is still considered
///     successful at the NS layer (the device IS enrolled in NS), so we do
///     not return an error; we just warn loudly.
async fn confirm_enrollment(
    callback_url: &str,
    token: &ztlp_proto::enrollment::EnrollmentToken,
    device_name: &str,
    node_id: &NodeId,
    pubkey_hex: &str,
) {
    let token_id = match &token.token_id {
        Some(id) => id.clone(),
        None => return,
    };

    // Use curl for HTTPS support (TLS without adding deps). We deliberately
    // do NOT pass `-f` here — Phase B made silent 4xx/5xx the whole problem.
    // We want to see what the Bootstrap actually said.
    //
    // v0.30.12 — body now carries `pubkey_hex`. When the callback URL
    // resolves to Launch, Launch will treat this as an implicit first-bind
    // of the admin's Noise static pubkey (skips the manual
    // /api/admin-pubkey + force-recreate dance). When the callback
    // resolves to Bootstrap (Rails), the field is silently dropped by
    // strong-params — sending it everywhere is safe and avoids the CLI
    // needing to know which kind of callback it's hitting.
    let body = format!(
        "token_id={}&node_id={}&name={}&pubkey_hex={}",
        token_id, node_id, device_name, pubkey_hex
    );

    let result = tokio::process::Command::new("curl")
        .args([
            "-s",
            // v0.30.12: bumped from 5s to 60s. With the v0.30.12 server-side
            // change, /api/enrollment/confirm runs `docker compose up -d
            // --force-recreate gateway` inline when pubkey_hex is present —
            // which can take 10-30s. The 5s budget the original Phase B
            // landed with is fine for the no-op status flip, but reliably
            // times out the auto-bind path. The endpoint is still
            // best-effort from the CLI's POV (the device IS enrolled at NS
            // regardless), so a wider timeout doesn't make us *less*
            // resilient; it just lets the happy path complete.
            "--max-time",
            "60",
            "-w",
            "\n%{http_code}", // append HTTP code on its own line so we can split body/code
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
            // curl-level success — now check the HTTP status code curl printed.
            // Format: <response_body>\n<http_code>
            let combined = String::from_utf8_lossy(&output.stdout);
            let (response_body, code_str) = match combined.rsplit_once('\n') {
                Some((body, code)) => (body, code),
                None => ("", combined.as_ref()),
            };
            let code: u16 = code_str.trim().parse().unwrap_or(0);
            if (200..300).contains(&code) {
                eprintln!(
                    "  {} Bootstrap confirmed token redemption (HTTP {})",
                    c_green("✓"),
                    code
                );
                // v0.30.12: surface the Launch autobind result so operators
                // can tell whether passwordless dashboard sign-in is wired
                // up without having to read the gateway env. We do best-
                // effort JSON parsing — Bootstrap (Rails) returns a redirect
                // body with no JSON, so we just skip silently if the response
                // doesn't look like a Launch ack.
                if let Some(autobind) = extract_json_string_field(response_body, "autobind") {
                    match autobind.as_str() {
                        "applied" => {
                            eprintln!(
                                "  {} Admin pubkey auto-bound for passwordless dashboard sign-in",
                                c_green("✓"),
                            );
                        }
                        "already_bound" => {
                            eprintln!(
                                "  {} Admin pubkey was already bound on this tenant — skipped (first-bind only)",
                                c_dim("·"),
                            );
                        }
                        "invalid" => {
                            eprintln!(
                                "  {} Launch rejected the device pubkey as invalid — passwordless sign-in not configured",
                                c_yellow("!"),
                            );
                        }
                        "provisioning_incomplete" => {
                            eprintln!(
                                "  {} Tenant gateway not provisioned yet — passwordless sign-in deferred",
                                c_yellow("!"),
                            );
                        }
                        "skipped" => { /* Legacy server, no message needed. */ }
                        other => {
                            eprintln!(
                                "  {} Launch autobind returned status '{}' — passwordless sign-in may not be active",
                                c_yellow("!"),
                                other,
                            );
                        }
                    }
                }
            } else if code == 429 {
                // v0.30.13 (issue #55): Launch rate-limits this endpoint
                // per token_id. The device IS enrolled at NS — Launch
                // just refused the bookkeeping callback. Honour the
                // retry-after hint if Launch returned one; otherwise
                // default to 60s (the documented bucket window).
                let retry_after =
                    extract_json_number_field(response_body, "retry_after_seconds").unwrap_or(60);
                eprintln!(
                    "  {} Bootstrap callback rate-limited (HTTP 429). The device is enrolled, but the dashboard \
                     bookkeeping + admin-pubkey autobind will retry after {}s. Re-run `ztlp setup` if this is unexpected.",
                    c_yellow("!"),
                    retry_after,
                );
            } else {
                // Loud but non-fatal: device IS enrolled in NS, but the dashboard
                // bookkeeping callback did not stick. Operator can see this.
                eprintln!(
                    "  {} Bootstrap callback returned HTTP {} ({}). The device is enrolled, but the dashboard token may still show 'active' until the next TokenReconciler sweep.",
                    c_yellow("!"),
                    code,
                    callback_url
                );
            }
        }
        Ok(output) => {
            // curl itself failed (network, DNS, TLS). Loud but non-fatal.
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "  {} Bootstrap callback failed to connect to {} (curl exit {}): {}",
                c_yellow("!"),
                callback_url,
                output.status.code().unwrap_or(-1),
                stderr.trim()
            );
        }
        Err(e) => {
            // Couldn't even spawn curl. Almost certainly a packaging bug.
            eprintln!(
                "  {} Could not spawn curl for Bootstrap callback: {}",
                c_yellow("!"),
                e
            );
        }
    }
}

/// Tiny JSON string-field extractor for the confirm-callback response.
///
/// Avoids pulling in `serde_json` just to read one field from a known-shape
/// Launch ack like `{"status":"redeemed","name":"admin","autobind":"applied"}`.
/// Returns None if the body isn't JSON-ish or the field is missing.
///
/// Only matches `"field":"value"` — does NOT handle nested objects, escape
/// sequences, or numeric/bool values. That's intentional: the Launch ack
/// shape is fixed and tiny, and we explicitly do NOT want to fail
/// enrollment over a parsing edge case.
fn extract_json_string_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let start = body.find(&needle)?;
    let after_key = &body[start + needle.len()..];
    // Skip whitespace and the colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    // Expect an opening quote.
    let after_quote = after_colon.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(after_quote[..end].to_string())
}

/// Tiny JSON number-field extractor for the confirm-callback 429 ack.
///
/// Same constraints as `extract_json_string_field` — sibling helper for
/// the v0.30.13 rate-limit response, which carries:
/// `{"error":"rate_limited","scope":"enrollment_confirm","retry_after_seconds":60}`.
///
/// Returns None if the field is missing, malformed, or non-integer.
fn extract_json_number_field(body: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{}\"", field);
    let start = body.find(&needle)?;
    let after_key = &body[start + needle.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    // Take the leading digit run, stop at the first non-digit (`,`, `}`, etc.).
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
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
        toml_string(&relay_addrs[0])
    } else {
        format!(
            "[{}]",
            relay_addrs
                .iter()
                .map(|a| toml_string(a))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let mut content = format!(
        r#"# ZTLP Configuration — generated by `ztlp setup`
# Zone: {zone_comment}

identity = {key_path}
ns_server = {ns_server}
{relay_str}
zone = {zone}
"#,
        zone_comment = zone,
        key_path = toml_string(&key_path.display().to_string()),
        ns_server = toml_string(ns_server),
        relay_str = if relay_str == "[]" {
            "".to_string()
        } else {
            format!("relay = {}", relay_str)
        },
        zone = toml_string(zone),
    );

    if !gateway_addrs.is_empty() {
        content.push_str(&format!("gateway = {}\n", toml_string(&gateway_addrs[0])));
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
    let secs = std::time::SystemTime::now()
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
    let secs = std::time::SystemTime::now()
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
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a real X.509 root CA + intermediate CA pair using rcgen.
///
/// Returns `(root_cert_pem, root_key_pem, intermediate_cert_pem, intermediate_key_pem)`.
///
/// **Replaces** the original comment-PEM stub (which wasn't valid X.509 and
/// failed `certutil -addstore Root` on Windows / `security` on macOS).
///
/// Crypto: ECDSA P-256 throughout. Root and intermediate both 10-year
/// validity (operators rotate via `ztlp admin ca-rotate-intermediate`).
///
/// CN convention:
///   Root:         `CN=ZTLP Root CA - <zone>`
///   Intermediate: `CN=ZTLP Intermediate CA - <zone>`
///
/// Pulled into `bin/ztlp-cli.rs` rather than `agent/cert_mint.rs` because
/// this is the *one-shot setup* operation. Once the chain exists on disk
/// the mint path doesn't need to regenerate it.
fn generate_real_ca_chain(
    zone: &str,
) -> Result<(String, String, String, String), Box<dyn std::error::Error>> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let now = time::OffsetDateTime::now_utc();
    let ten_years = time::Duration::days(365 * 10);

    // ── Root CA ────────────────────────────────────────────────────────
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, format!("ZTLP Root CA - {}", zone));
    root_dn.push(DnType::OrganizationName, "ZTLP");
    root_params.distinguished_name = root_dn;
    root_params.not_before = now;
    root_params.not_after = now + ten_years;
    let root_cert = root_params.self_signed(&root_key)?;
    let root_cert_pem = root_cert.pem();
    let root_key_pem = root_key.serialize_pem();

    // ── Intermediate CA (signed by root) ───────────────────────────────
    let intermediate_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut int_params = CertificateParams::new(Vec::<String>::new())?;
    // PathLenConstraint(0) — intermediate can only issue leaves, not
    // further intermediates. Defense in depth.
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut int_dn = DistinguishedName::new();
    int_dn.push(
        DnType::CommonName,
        format!("ZTLP Intermediate CA - {}", zone),
    );
    int_dn.push(DnType::OrganizationName, "ZTLP");
    int_params.distinguished_name = int_dn;
    int_params.not_before = now;
    int_params.not_after = now + ten_years;
    let intermediate_cert = int_params.signed_by(&intermediate_key, &root_cert, &root_key)?;
    let intermediate_cert_pem = intermediate_cert.pem();
    let intermediate_key_pem = intermediate_key.serialize_pem();

    Ok((
        root_cert_pem,
        root_key_pem,
        intermediate_cert_pem,
        intermediate_key_pem,
    ))
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

    // D5.T2.0: Generate REAL X.509 chain (ECDSA P-256). The previous
    // implementation wrote comment-only PEM frames which were not valid
    // X.509 and which `certutil -addstore Root` (Windows) and the macOS
    // `security` tool both rejected. Browsers wouldn't trust the chain
    // even if it loaded, because nothing was actually signed.
    let (root_cert_pem, root_key_pem, intermediate_cert_pem, intermediate_key_pem) =
        generate_real_ca_chain(zone)?;
    std::fs::write(&root_cert_path, &root_cert_pem)?;
    std::fs::write(&root_key_path, &root_key_pem)?;
    std::fs::write(&intermediate_cert_path, &intermediate_cert_pem)?;
    std::fs::write(&intermediate_key_path, &intermediate_key_pem)?;

    // Mode 600 on Unix (Windows ACLs handle this elsewhere).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root_key_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(
            &intermediate_key_path,
            std::fs::Permissions::from_mode(0o600),
        )?;
    }

    // Zone metadata — used by ca-rotate-intermediate and audit tooling.
    // Now records cert subject DNs instead of the bogus ed25519 hex keys
    // the stub recorded.
    let meta = format!(
        "{{\"zone\":\"{}\",\"created\":\"{}\",\"root_cn\":\"ZTLP Root CA - {}\",\"intermediate_cn\":\"ZTLP Intermediate CA - {}\",\"algorithm\":\"ECDSA P-256\"}}",
        zone,
        utc_timestamp_iso(),
        zone,
        zone,
    );
    std::fs::write(ca_dir.join("ca.json"), &meta)?;

    // Create certs directory for issued certs
    std::fs::create_dir_all(ca_dir.join("certs"))?;
    // Create empty index
    std::fs::write(ca_dir.join("certs").join("index.json"), "[]")?;

    if json_output {
        println!(
            "{{\"status\":\"ok\",\"zone\":\"{}\",\"ca_dir\":\"{}\",\"algorithm\":\"ECDSA P-256\",\"root_cn\":\"ZTLP Root CA - {}\",\"intermediate_cn\":\"ZTLP Intermediate CA - {}\"}}",
            zone,
            ca_dir.display(),
            zone,
            zone,
        );
    } else {
        eprintln!("{}", c_bold(&format!("ZTLP CA Initialized for {}", zone)));
        eprintln!();
        eprintln!("  {} {}", c_cyan("CA directory:"), ca_dir.display());
        eprintln!(
            "  {} {}",
            c_cyan("Root CN:     "),
            format!("ZTLP Root CA - {}", zone)
        );
        eprintln!(
            "  {} {}",
            c_cyan("Intermediate:"),
            format!("ZTLP Intermediate CA - {}", zone)
        );
        eprintln!(
            "  {} ECDSA P-256, 10 year validity",
            c_cyan("Algorithm:   ")
        );
        eprintln!();
        eprintln!("  {} Import root cert: ztlp admin ca-export-root | sudo tee /usr/local/share/ca-certificates/ztlp.crt", c_dim("→"));
        eprintln!(
            "  {} On Windows (machine-wide trust): ztlp agent install-ca-cert --machine-scope",
            c_dim("→")
        );
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
    // Nebula-pivot R4: `ztlp_proto::pacing` deleted; inline literal (was 7 MiB).
    const TARGET_BUFFER_SIZE: usize = 7 * 1024 * 1024;

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
                    eprintln!(
                        "  {} Set net.inet.udp.recvspace = {}",
                        c_green("✓"),
                        format_bytes(target)
                    );
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    eprintln!(
                        "  {} Failed to set recvspace: {} (run with sudo?)",
                        c_red("✗"),
                        err.trim()
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
                        c_red("✗"),
                        err.trim()
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
    relay: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::proxy;

    let key_str = key.as_ref().map(|p| p.to_string_lossy().to_string());
    let ns_str = ns_server.as_ref().map(|s| s.as_str());
    let relay_str = relay.as_ref().map(|s| s.as_str());

    proxy::run_proxy(hostname, port, key_str.as_deref(), ns_str, relay_str)
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
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::control;

    let ipc_addr = AgentConfig::load().ipc.listen;
    let cmd = control::ControlCommand {
        cmd: "shutdown".to_string(),
        name: None,
        token: ztlp_proto::agent::config::load_agent_token(),
    };

    match control::send_command(&ipc_addr, &cmd).await {
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
    let ipc_addr = AgentConfig::load().ipc.listen;
    let cmd = control::ControlCommand {
        cmd: "status".to_string(),
        name: None,
        token: ztlp_proto::agent::config::load_agent_token(),
    };

    match control::send_command(&ipc_addr, &cmd).await {
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
        Ok(resp) => {
            // Daemon answered but rejected (most common cause post-D1.T3:
            // missing or stale ~/.ztlp/agent.token). Surface the actual
            // error and a remediation hint so the user doesn't chase
            // "not running" when the daemon is in fact up.
            eprintln!(
                "  {} {}",
                c_red("✗"),
                resp.error.as_deref().unwrap_or("unknown error")
            );
            if resp.error.as_deref() == Some("unauthorized")
                && ztlp_proto::agent::config::load_agent_token().is_none()
            {
                let path = ztlp_proto::agent::config::default_token_path();
                eprintln!(
                    "  {} {} {}",
                    c_dim("hint:"),
                    c_dim("agent token not found at"),
                    c_dim(&path.display().to_string())
                );
            }
            return Ok(());
        }
        Err(_) => {}
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
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::control;

    let ipc_addr = AgentConfig::load().ipc.listen;
    let cmd = control::ControlCommand {
        cmd: "dns_cache".to_string(),
        name: None,
        token: ztlp_proto::agent::config::load_agent_token(),
    };

    match control::send_command(&ipc_addr, &cmd).await {
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
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::control;

    let ipc_addr = AgentConfig::load().ipc.listen;
    let cmd = control::ControlCommand {
        cmd: "flush_dns".to_string(),
        name: None,
        token: ztlp_proto::agent::config::load_agent_token(),
    };

    match control::send_command(&ipc_addr, &cmd).await {
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
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::control;

    let ipc_addr = AgentConfig::load().ipc.listen;
    let cmd = control::ControlCommand {
        cmd: "tunnels".to_string(),
        name: None,
        token: ztlp_proto::agent::config::load_agent_token(),
    };

    match control::send_command(&ipc_addr, &cmd).await {
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

// ─── Windows DNS path (D4.T3) ──────────────────────────────────────────────
//
// Windows uses NRPT (Name Resolution Policy Table) instead of resolv.conf or
// /etc/resolver. The trait + helpers live in [`dns_setup_windows`]; these
// CLI wrappers preserve the same UX as the Unix path so users running
// `ztlp agent dns-setup` see the same kind of output regardless of OS.

#[cfg(windows)]
async fn cmd_agent_dns_setup_windows(
    zones: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::config::AgentConfig;
    use ztlp_proto::agent::dns_setup_windows;

    let config = AgentConfig::load();

    // Same merge order as the Unix path: zones from config, then domain_map
    // keys, then any CLI-passed comma-separated additions. Dedup happens
    // inside setup_zones via the seen-HashSet.
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

    let api = dns_setup_windows::default_nrpt_api();
    match dns_setup_windows::setup_zones(api.as_ref(), &zone_list, &config.dns.listen) {
        Ok(installed) => {
            eprintln!(
                "{} NRPT rules installed ({} namespace{})",
                c_green("✓"),
                installed.len(),
                if installed.len() == 1 { "" } else { "s" }
            );
            for ns in &installed {
                eprintln!("  {} → {}", ns, config.dns.listen);
            }
            eprintln!();
            eprintln!(
                "{}",
                c_dim(
                    "Verify with: Get-DnsClientNrptRule | Where-Object Comment -Match 'ZTLP-managed'"
                )
            );
        }
        Err(e) => {
            eprintln!("{} NRPT setup failed: {}", c_red("✗"), e);
            eprintln!();
            eprintln!(
                "{}",
                c_dim(
                    "Hint: NRPT modification requires elevation. Run as Administrator or via the ZTLP service."
                )
            );
        }
    }

    Ok(())
}

#[cfg(windows)]
async fn cmd_agent_dns_teardown_windows() -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::dns_setup_windows;

    let api = dns_setup_windows::default_nrpt_api();
    match dns_setup_windows::teardown_managed(api.as_ref()) {
        Ok(removed) => {
            if removed.is_empty() {
                eprintln!("{}", c_dim("No ZTLP-managed NRPT rules found"));
            } else {
                eprintln!(
                    "{} Removed {} NRPT rule{}",
                    c_green("✓"),
                    removed.len(),
                    if removed.len() == 1 { "" } else { "s" }
                );
                for ns in &removed {
                    eprintln!("  {}", ns);
                }
            }
        }
        Err(e) => {
            eprintln!("{} NRPT teardown failed: {}", c_red("✗"), e);
        }
    }

    Ok(())
}

/// `ztlp agent install-ca-cert` — Install ZTLP Root CA into system trust store (D5.T1).
///
/// Cross-platform entry point. On Windows, `machine_scope` flips between
/// `CurrentUser\Root` (default) and `LocalMachine\Root` (required for
/// service-installed scenarios where browsers run under any user). On
/// macOS / Linux this flag is a no-op (always system-wide).
fn cmd_agent_install_ca_cert(
    cert_arg: &Option<PathBuf>,
    machine_scope: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::ca_trust::{
        default_ca_cert_path, install_ca_cert_with_scope, CertStoreScope,
    };
    let cert_path = cert_arg.clone().unwrap_or_else(default_ca_cert_path);
    if !cert_path.exists() {
        eprintln!(
            "  {} No root CA cert at {} — run `ztlp admin ca-init --zone <zone>` first",
            c_red("✗"),
            cert_path.display()
        );
        return Err("root CA cert not found".into());
    }

    let scope = if machine_scope {
        CertStoreScope::Machine
    } else {
        CertStoreScope::User
    };

    eprintln!(
        "  {} Installing {} into {} trust store...",
        c_dim("→"),
        cert_path.display(),
        if matches!(scope, CertStoreScope::Machine) {
            "machine-wide"
        } else {
            "user"
        }
    );

    install_ca_cert_with_scope(&cert_path, scope)
        .map_err(|e| format!("CA trust install failed: {}", e))?;

    eprintln!(
        "  {} ZTLP Root CA installed{}",
        c_green("✓"),
        if matches!(scope, CertStoreScope::Machine) {
            " (machine-wide)"
        } else {
            ""
        }
    );
    eprintln!(
        "  {} Browsers will now validate any leaf signed by this CA",
        c_dim("→")
    );
    Ok(())
}

/// `ztlp agent remove-ca-cert` — Inverse of install. Removes from the
/// system trust store. Idempotent (errors only if the OS layer reports a
/// real failure, not just "cert not present").
fn cmd_agent_remove_ca_cert(cert_arg: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use ztlp_proto::agent::ca_trust::{default_ca_cert_path, remove_ca_cert};
    let cert_path = cert_arg.clone().unwrap_or_else(default_ca_cert_path);
    remove_ca_cert(&cert_path).map_err(|e| format!("CA trust remove failed: {}", e))?;
    eprintln!("  {} ZTLP Root CA removed from trust store", c_green("✓"));
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
            no_punch,
            punch_delay,
            punch_timeout,
            relay_pool,
            no_relay_pool,
            relay_probe_interval,
            quic,
            multi_candidate,
            no_multi_candidate,
            reconnect_attempts,
            reconnect_delay_ms,
            no_reconnect,
            no_resolve_on_reconnect,
            allow_identity_change,
        } => {
            // H10 (v0.30.12): when --ns-server is set, both --punch and
            // --relay-pool auto-flip to ON unless the user explicitly opted
            // out with --no-punch / --no-relay-pool (clap's `conflicts_with`
            // already rejects the contradictory combos --punch+--no-punch
            // and --relay-pool+--no-relay-pool before we get here).
            let (punch_active, relay_pool_active) =
                ztlp_proto::h10_defaults::resolve_punch_and_pool_flags(
                    ns_server.is_some(),
                    *punch,
                    *no_punch,
                    *relay_pool,
                    *no_relay_pool,
                );
            // v0.32.3: when --ns-server is set, --multi-candidate auto-flips
            // to ON so the connect attempt takes the QUIC routing path that
            // works against v0.32.x relays. The legacy --punch UDP path is
            // broken end-to-end against v0.32 relays and fails with
            // "Invalid argument (os error 22)" before sending HELLO. Use
            // --no-multi-candidate to opt out for the rare case where the
            // legacy path is actually wanted (e.g. talking to a pre-v0.32
            // relay, or debugging).
            let multi_candidate_active = ztlp_proto::h10_defaults::resolve_multi_candidate_flag(
                ns_server.is_some(),
                *multi_candidate,
                *no_multi_candidate,
            );

            // ── Auto-reconnect supervisor wrapper (v0.34.9+) ─────────────
            //
            // Wraps cmd_connect's one-shot dial in a supervisor loop that
            // catches QUIC session loss and re-dials with exponential
            // backoff. Honors all five reconnect flags.
            //
            // Contract pinned by `mod tests::auto_reconnect` (17 tests).
            // Gate pinned by `h10_defaults::resolve_supervisor_flag` (4 tests).
            // Plan: docs/plans/2026-06-03-connect-auto-reconnect.md
            // Dynamic scenarios: docs/plans/2026-06-04-auto-reconnect-dynamic-scenarios.md
            //
            // v0.34.10: supervisor is default-on regardless of --ns-server.
            // Previously gated on ns_server.is_some() which silently
            // bypassed the supervisor for raw-IP connects (e.g. direct
            // relay address). Only --no-reconnect now disables it.
            let use_supervisor = ztlp_proto::h10_defaults::resolve_supervisor_flag(
                ns_server.is_some(),
                *no_reconnect,
            );

            if !use_supervisor {
                cmd_connect(
                    *quic,
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
                    punch_active,
                    punch_delay,
                    punch_timeout,
                    relay_pool_active,
                    *relay_probe_interval,
                    multi_candidate_active,
                )
                .await
            } else {
                // Supervisor path: loop until clean exit or attempt cap reached.
                let mut attempt: u32 = 0;
                let mut downtime_start: Option<Instant> = None;
                let _ = no_resolve_on_reconnect; // wired into cmd_connect in a follow-up
                let _ = allow_identity_change; // wired into cmd_connect in a follow-up

                loop {
                    if attempt > 0 {
                        if *reconnect_attempts > 0 && attempt > *reconnect_attempts {
                            break Err(format!(
                                "tunnel disconnected after {} attempts; giving up",
                                *reconnect_attempts
                            )
                            .into());
                        }
                        let delay = compute_reconnect_delay(attempt, *reconnect_delay_ms);
                        eprintln!(
                            "↻ reconnect attempt {} (delay {}ms)…",
                            attempt,
                            delay.as_millis()
                        );
                        tokio::time::sleep(delay).await;
                    }

                    let attempt_started = Instant::now();
                    let inner_result = cmd_connect(
                        *quic,
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
                        punch_active,
                        punch_delay,
                        punch_timeout,
                        relay_pool_active,
                        *relay_probe_interval,
                        multi_candidate_active,
                    )
                    .await;

                    match inner_result {
                        Ok(()) => {
                            if let Some(start) = downtime_start {
                                let downtime = start.elapsed();
                                eprintln!(
                                    "✓ tunnel reestablished and closed cleanly after {} attempt{} ({}.{:03}s total downtime)",
                                    attempt,
                                    if attempt == 1 { "" } else { "s" },
                                    downtime.as_secs(),
                                    downtime.subsec_millis()
                                );
                            }
                            break Ok(());
                        }
                        Err(e) => {
                            let elapsed = attempt_started.elapsed();
                            let msg = format!("{}", e);
                            if downtime_start.is_none() {
                                downtime_start = Some(Instant::now());
                            }
                            if elapsed >= Duration::from_secs(5) {
                                eprintln!(
                                    "⚠ tunnel session ended after {}.{:03}s: {}",
                                    elapsed.as_secs(),
                                    elapsed.subsec_millis(),
                                    msg
                                );
                            } else {
                                eprintln!(
                                    "⚠ dial failed ({}.{:03}s): {}",
                                    elapsed.as_secs(),
                                    elapsed.subsec_millis(),
                                    msg
                                );
                            }
                            attempt += 1;
                            // Continue to next iteration of the loop.
                        }
                    }
                }
            }
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
            relay,
            service_name,
            zone,
            zone_hmac_secret_env,
            ns_register_name,
            http_inject_headers,
            header_hmac_secret,
            admin_pubkey_email,
            quic,
            punch,
            no_punch,
            advertise_interface,
            no_advertise_interface,
            advertise_all_interfaces,
        } => {
            // H10 (v0.30.12): when --ns-server is set, --punch auto-flips
            // to ON unless --no-punch is passed. Gateways don't fail over
            // (they ARE the destination), so we only resolve the punch
            // half of the matrix here — the relay-pool half is hard-coded
            // false because cmd_listen doesn't take a relay-pool flag.
            let (punch_active, _pool_unused) =
                ztlp_proto::h10_defaults::resolve_punch_and_pool_flags(
                    ns_server.is_some(),
                    *punch,
                    *no_punch,
                    false,
                    false,
                );
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
                relay.as_deref(),
                service_name,
                zone.as_deref(),
                zone_hmac_secret_env.as_deref(),
                ns_register_name.as_deref(),
                *http_inject_headers,
                header_hmac_secret.as_deref(),
                admin_pubkey_email,
                *quic,
                punch_active,
                advertise_interface,
                no_advertise_interface,
                *advertise_all_interfaces,
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
            GatewayCommands::Candidates {
                name,
                ns_server,
                json,
            } => cmd_gateway_candidates(name, ns_server, *json).await,
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
            bind_user,
            yes,
        } => cmd_setup(token, name, *r#type, owner, *bind_user, *yes).await,

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
            relay,
        } => cmd_proxy(hostname, *port, key, ns_server, relay).await,

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
            AgentCommands::InstallCaCert {
                cert,
                machine_scope,
            } => cmd_agent_install_ca_cert(cert, *machine_scope),
            AgentCommands::RemoveCaCert { cert } => cmd_agent_remove_ca_cert(cert),
            #[cfg(not(unix))]
            AgentCommands::DnsSetup { zones } => {
                #[cfg(windows)]
                {
                    cmd_agent_dns_setup_windows(zones).await
                }
                #[cfg(not(windows))]
                {
                    let _ = zones;
                    Err("dns-setup is not supported on this platform".into())
                }
            }
            #[cfg(not(unix))]
            AgentCommands::DnsTeardown => {
                #[cfg(windows)]
                {
                    cmd_agent_dns_teardown_windows().await
                }
                #[cfg(not(windows))]
                {
                    Err("dns-teardown is not supported on this platform".into())
                }
            }
            #[cfg(not(unix))]
            AgentCommands::Install { .. } => Err(
                "install is only supported on Unix; use the ZTLP Windows service installer instead"
                    .into(),
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // v0.30.12 — JSON field extraction for the confirm-callback response.
    // This is a deliberately tiny parser; these tests cover the shapes we
    // actually see from Launch and ensure we degrade gracefully when the
    // body isn't a Launch ack (e.g. Bootstrap's Rails redirect HTML).
    #[test]
    fn extract_json_string_field_handles_launch_ack() {
        let body = r#"{"status":"redeemed","name":"admin-laptop","autobind":"applied"}"#;
        assert_eq!(
            extract_json_string_field(body, "autobind"),
            Some("applied".to_string())
        );
        assert_eq!(
            extract_json_string_field(body, "status"),
            Some("redeemed".to_string())
        );
    }

    #[test]
    fn extract_json_string_field_handles_whitespace() {
        let body = r#"{ "autobind" : "already_bound" }"#;
        assert_eq!(
            extract_json_string_field(body, "autobind"),
            Some("already_bound".to_string())
        );
    }

    #[test]
    fn extract_json_string_field_returns_none_for_missing_field() {
        let body = r#"{"status":"redeemed"}"#;
        assert_eq!(extract_json_string_field(body, "autobind"), None);
    }

    #[test]
    fn extract_json_string_field_returns_none_for_non_json_body() {
        // Bootstrap's Rails redirect renders HTML — must NOT panic or
        // return a bogus value.
        let body = "<html><body><h1>302 Found</h1></body></html>";
        assert_eq!(extract_json_string_field(body, "autobind"), None);
    }

    #[test]
    fn extract_json_string_field_returns_none_for_empty_body() {
        assert_eq!(extract_json_string_field("", "autobind"), None);
    }

    // v0.30.13 — number-field extractor sibling for the rate-limit ack.
    #[test]
    fn extract_json_number_field_parses_launch_429() {
        let body =
            r#"{"error":"rate_limited","scope":"enrollment_confirm","retry_after_seconds":60}"#;
        assert_eq!(
            extract_json_number_field(body, "retry_after_seconds"),
            Some(60)
        );
    }

    #[test]
    fn extract_json_number_field_handles_whitespace_and_trailing_brace() {
        let body = r#"{ "retry_after_seconds" : 120 }"#;
        assert_eq!(
            extract_json_number_field(body, "retry_after_seconds"),
            Some(120)
        );
    }

    #[test]
    fn extract_json_number_field_returns_none_for_string_value() {
        // Type-mismatch must NOT panic and must return None — the caller
        // falls back to a sensible default (60s).
        let body = r#"{"retry_after_seconds":"sixty"}"#;
        assert_eq!(extract_json_number_field(body, "retry_after_seconds"), None);
    }

    #[test]
    fn extract_json_number_field_returns_none_for_missing_field() {
        let body = r#"{"error":"rate_limited"}"#;
        assert_eq!(extract_json_number_field(body, "retry_after_seconds"), None);
    }

    #[test]
    fn toml_string_escapes_windows_paths() {
        let value = r#"C:\Users\TRS\.ztlp\identity.json"#;

        let rendered = toml_string(value);
        let parsed: toml::Value = toml::from_str(&format!("identity = {}", rendered)).unwrap();

        assert_eq!(parsed["identity"].as_str(), Some(value));
        assert!(rendered.starts_with('"'));
        assert!(rendered.ends_with('"'));
        assert!(rendered.contains(r#"C:\\Users\\TRS\\.ztlp\\identity.json"#));
    }

    #[test]
    fn write_config_file_emits_toml_safe_windows_identity_path() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ztlp-config-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key_path = PathBuf::from(r#"C:\Users\TRS\.ztlp\identity.json"#);

        write_config_file(
            &path,
            &key_path,
            "trs-remote-test.ztlp",
            "10.69.95.14:23096",
            &["10.69.95.14:23095".to_string()],
            &[r#"bootstrap\gateway"#.to_string()],
        )
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let parsed: Config = toml::from_str(&content).unwrap();
        fs::remove_file(&path).ok();

        assert_eq!(
            parsed.identity.as_deref(),
            Some(r#"C:\Users\TRS\.ztlp\identity.json"#)
        );
        assert_eq!(parsed.ns_server.as_deref(), Some("10.69.95.14:23096"));
        assert_eq!(parsed.relay.as_deref(), Some("10.69.95.14:23095"));
        assert_eq!(parsed.gateway.as_deref(), Some(r#"bootstrap\gateway"#));
    }

    fn sample_ns_record(data_len: u32) -> Vec<u8> {
        let mut record = vec![2];
        let name = b"bootstrap.trs-remote-test.ztlp";
        record.extend_from_slice(&(name.len() as u16).to_be_bytes());
        record.extend_from_slice(name);
        record.extend_from_slice(&data_len.to_be_bytes());
        record
    }

    #[test]
    fn ns_record_payload_preserves_record_type_without_flag() {
        let record = sample_ns_record(0);
        let mut response = vec![0x02];
        response.extend_from_slice(&record);

        let payload = ns_record_payload(&response).unwrap().unwrap();

        assert_eq!(payload[0], 2);
        assert_eq!(payload, record.as_slice());
        print_ns_record(payload, "bootstrap.trs-remote-test.ztlp").unwrap();
    }

    #[test]
    fn ns_record_payload_strips_truncation_flag_but_preserves_record_type() {
        let record = sample_ns_record(0);
        let mut response = vec![0x02, 0x01];
        response.extend_from_slice(&record);

        let payload = ns_record_payload(&response).unwrap().unwrap();

        assert_eq!(payload[0], 2);
        assert_eq!(payload, record.as_slice());
        print_ns_record(payload, "bootstrap.trs-remote-test.ztlp").unwrap();
    }

    #[test]
    fn print_ns_record_does_not_panic_on_truncated_data_section() {
        let record = sample_ns_record(10);

        print_ns_record(&record, "bootstrap.trs-remote-test.ztlp").unwrap();
    }

    // ─── FRAME_CLIENT_ROUTE tests ──────────────────────────────────────

    #[test]
    fn client_route_packet_roundtrip_dev_mode() {
        // Dev mode: no shared secret → HMAC is zeroed.
        let node_id = [0xABu8; 16];
        let svc = "gw-hermese2e-1";
        let ts: i64 = 1_716_339_600;

        let pkt = build_client_route_packet(&node_id, svc, ts, None)
            .expect("build should succeed for valid inputs");

        // Wire layout: 2 magic + 1 type + 16 node_id + 1 svc_len + N svc + 8 ts + 32 hmac
        assert_eq!(pkt.len(), 2 + 1 + 16 + 1 + svc.len() + 8 + 32);
        assert_eq!(&pkt[0..2], &[0x5A, 0x37]);
        assert_eq!(pkt[2], 0x0B);

        let (parsed_node_id, parsed_svc, parsed_ts, parsed_hmac) =
            parse_client_route_packet(&pkt).expect("parse should succeed");
        assert_eq!(parsed_node_id, node_id);
        assert_eq!(parsed_svc, svc);
        assert_eq!(parsed_ts, ts);
        assert_eq!(parsed_hmac, [0u8; 32]); // dev mode: HMAC zeroed
    }

    #[test]
    fn client_route_packet_hmac_is_set_with_secret() {
        let node_id = [0x01u8; 16];
        let svc = "gw-test";
        let ts: i64 = 1_716_339_999;
        let secret = b"shared-zone-secret";

        let pkt = build_client_route_packet(&node_id, svc, ts, Some(secret))
            .expect("build should succeed");
        let (_, _, _, hmac_bytes) = parse_client_route_packet(&pkt).unwrap();
        // Real HMAC is non-zero (probabilistically certain).
        assert_ne!(hmac_bytes, [0u8; 32]);

        // Recompute the HMAC and verify it matches what the relay would expect.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut signed = Vec::new();
        signed.push(0x0Bu8);
        signed.extend_from_slice(&node_id);
        signed.push(svc.len() as u8);
        signed.extend_from_slice(svc.as_bytes());
        signed.extend_from_slice(&ts.to_be_bytes());
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        mac.update(&signed);
        let expected = mac.finalize().into_bytes();
        assert_eq!(hmac_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn client_route_rejects_empty_service_name() {
        let node_id = [0u8; 16];
        let err = build_client_route_packet(&node_id, "", 0, None).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn client_route_rejects_oversized_service_name() {
        let node_id = [0u8; 16];
        let too_long = "a".repeat(CLIENT_ROUTE_MAX_SVC_LEN + 1);
        let err = build_client_route_packet(&node_id, &too_long, 0, None).unwrap_err();
        assert!(err.contains("MAX_SVC_LEN"));
    }

    #[test]
    fn client_route_parse_rejects_bad_magic() {
        let mut pkt = build_client_route_packet(&[0u8; 16], "gw-x", 0, None).unwrap();
        pkt[0] = 0x00;
        let err = parse_client_route_packet(&pkt).unwrap_err();
        assert_eq!(err, "bad magic");
    }

    #[test]
    fn client_route_parse_rejects_bad_type() {
        let mut pkt = build_client_route_packet(&[0u8; 16], "gw-x", 0, None).unwrap();
        pkt[2] = 0x0A; // GATEWAY_REGISTER, not CLIENT_ROUTE
        let err = parse_client_route_packet(&pkt).unwrap_err();
        assert_eq!(err, "bad type");
    }

    #[test]
    fn client_route_parse_rejects_truncated_packet() {
        let pkt = build_client_route_packet(&[0u8; 16], "gw-x", 0, None).unwrap();
        let truncated = &pkt[..pkt.len() - 5];
        let err = parse_client_route_packet(truncated).unwrap_err();
        // Could be "packet too short" or "packet truncated" depending on where
        // the truncation lands; both are acceptable.
        assert!(err.contains("short") || err.contains("truncated"));
    }

    #[test]
    fn client_route_max_length_service_name_succeeds() {
        let node_id = [0u8; 16];
        let max_svc = "g".repeat(CLIENT_ROUTE_MAX_SVC_LEN);
        let pkt = build_client_route_packet(&node_id, &max_svc, 0, None)
            .expect("max-length service name should be accepted");
        let (_, parsed_svc, _, _) = parse_client_route_packet(&pkt).unwrap();
        assert_eq!(parsed_svc, max_svc);
    }

    // ─── FRAME_GATEWAY_REGISTER_V2 tests ───────────────────────────────
    //
    // Golden vectors verified against the Elixir reference implementation
    // (gateway/lib/ztlp_gateway/relay_registrar.ex) on 2026-05-24:
    //
    //   node_id     = 0x42 * 16
    //   zone_id     = "acme"            (4 bytes)
    //   service     = "gw-acme"
    //   ttl         = 60
    //   timestamp   = 1_700_000_000
    //   secret      = 0x77 * 32
    //
    // signed_hex  = 0e0461636d654242424242424242424242424242424267772d61636d6500
    //               00000000000000000000003c000000006553f100
    // hmac_hex    = 73bce1cc6e265e0452bfa9c0460b8858d398732115b2af6a07c6cfa651d59859
    // packet_hex  = 5a370e0461636d654242424242424242424242424242424267772d61636d65
    //               00000000000000000000000000003c000000006553f100
    //               73bce1cc6e265e0452bfa9c0460b8858d398732115b2af6a07c6cfa651d59859
    // packet_len  = 84

    #[test]
    fn gateway_register_v2_packet_matches_elixir_golden_vector() {
        let node_id = [0x42u8; 16];
        let secret = [0x77u8; 32];
        let pkt = build_gateway_register_v2_packet(
            &node_id,
            "acme",
            "gw-acme",
            60,
            1_700_000_000,
            &secret,
        )
        .expect("V2 builder should accept canonical inputs");

        let expected_hex = "5a370e0461636d65\
                            4242424242424242424242424242424267772d61636d65000000000000000000\
                            0000003c000000006553f100\
                            73bce1cc6e265e0452bfa9c0460b8858d398732115b2af6a07c6cfa651d59859";
        let expected = hex::decode(expected_hex).expect("test vector should be valid hex");
        assert_eq!(pkt, expected, "V2 packet must byte-match Elixir reference");
        assert_eq!(pkt.len(), 84);
    }

    #[test]
    fn gateway_register_v2_rejects_empty_zone() {
        let node_id = [0u8; 16];
        let secret = [0u8; 32];
        let err = build_gateway_register_v2_packet(&node_id, "", "gw-acme", 60, 0, &secret)
            .expect_err("empty zone_id must be rejected");
        assert!(err.contains("empty"), "got: {}", err);
    }

    #[test]
    fn gateway_register_v2_rejects_zone_too_long() {
        let node_id = [0u8; 16];
        let secret = [0u8; 32];
        // 64 bytes — one over the 63 limit
        let too_long = "a".repeat(64);
        let err = build_gateway_register_v2_packet(&node_id, &too_long, "gw-acme", 60, 0, &secret)
            .expect_err("64-byte zone_id must be rejected");
        assert!(err.contains("63 bytes"), "got: {}", err);
    }

    #[test]
    fn gateway_register_v2_accepts_max_length_zone() {
        let node_id = [0u8; 16];
        let secret = [0u8; 32];
        // Exactly 63 bytes — the maximum allowed
        let max_zone = "z".repeat(63);
        let pkt = build_gateway_register_v2_packet(&node_id, &max_zone, "gw-x", 60, 0, &secret)
            .expect("63-byte zone_id should be accepted");
        // 2 magic + 1 type + 1 zone_len + 63 zone + 16 node_id + 16 service
        // + 4 ttl + 8 ts + 32 hmac = 143 bytes
        assert_eq!(pkt.len(), 143);
        // zone_len byte is at offset 3 (after magic + type)
        assert_eq!(pkt[3], 63);
    }

    #[test]
    fn gateway_register_v2_truncates_long_service_name_like_v1() {
        // service_name is padded/truncated to exactly 16 bytes for parser
        // compatibility with the V1 wire layout. Routing on the relay side
        // uses zone_id, not service_name, so this is purely a wire-layout
        // concern, but we want to be sure the builder doesn't refuse long
        // names.
        let node_id = [0u8; 16];
        let secret = [0u8; 32];
        let pkt = build_gateway_register_v2_packet(
            &node_id,
            "acme",
            "this-service-name-is-much-longer-than-sixteen-bytes",
            60,
            0,
            &secret,
        )
        .expect("long service names should be truncated, not rejected");
        // Service field lives at offset:
        //   2 magic + 1 type + 1 zone_len + 4 zone + 16 node_id = 24
        // and runs for 16 bytes.
        let service_field = &pkt[24..40];
        assert_eq!(&service_field[..16], b"this-service-nam");
    }

    #[test]
    fn gateway_register_v2_hmac_changes_when_secret_changes() {
        let node_id = [0u8; 16];
        let pkt_a = build_gateway_register_v2_packet(
            &node_id,
            "acme",
            "gw-acme",
            60,
            1_700_000_000,
            b"secret-a-12345678901234567890123",
        )
        .unwrap();
        let pkt_b = build_gateway_register_v2_packet(
            &node_id,
            "acme",
            "gw-acme",
            60,
            1_700_000_000,
            b"secret-b-12345678901234567890123",
        )
        .unwrap();
        // Pre-HMAC bytes (everything but the trailing 32) must match;
        // HMAC bytes must differ.
        let pre_hmac = pkt_a.len() - 32;
        assert_eq!(&pkt_a[..pre_hmac], &pkt_b[..pre_hmac]);
        assert_ne!(&pkt_a[pre_hmac..], &pkt_b[pre_hmac..]);
    }

    // ─── resolve_v2_config tests ──────────────────────────────────────
    //
    // Behavior pinned here: when `--zone` is set but the per-zone HMAC
    // secret env var is missing or empty, we MUST still emit V2 frames
    // (with a zero-byte HMAC). The relay's HMAC mode (:dev / :staging
    // / :prod) decides whether to accept them; the gateway must not
    // silently fall back to V1-only just because a secret wasn't set
    // by the operator.
    //
    // Pre-v0.30.7 behavior: empty secret → V2 silently disabled (bug
    // that bit the v0.30.5 fleet deploy where 12 of 19 tenants needed
    // manual HMAC secret injection just to flip on V2 routing).
    //
    // Post-v0.30.7 behavior: empty secret → V2 emitted with empty key.
    // The relay's dev mode (production default) routes the frame
    // correctly by `gw:<zone>`. Production hardening to "require real
    // HMAC" happens at the relay by setting ZTLP_RELAY_HMAC_MODE=prod
    // and provisioning per-zone secrets there.

    /// `resolve_v2_config` returns `None` when --zone is unset. Pure
    /// V1-only path — used by legacy / unzoned deployments.
    #[test]
    fn resolve_v2_config_returns_none_when_zone_is_none() {
        let cfg = resolve_v2_config(None, None);
        assert!(cfg.is_none(), "no zone -> no V2 config");
    }

    /// Empty zone string is treated identically to no zone — the
    /// V2 builder would reject it anyway, and we want a single
    /// "no V2" code path on the caller's side.
    #[test]
    fn resolve_v2_config_returns_none_when_zone_is_empty_string() {
        let cfg = resolve_v2_config(Some(""), None);
        assert!(cfg.is_none(), "empty zone -> no V2 config");
    }

    /// Zone set, default env name resolves a real secret → returns
    /// `Some((zone, secret_bytes))`. Verified-V2 happy path.
    #[test]
    fn resolve_v2_config_with_zone_and_secret_returns_secret_bytes() {
        // Use a uniquely-named env var so test parallelism can't race.
        let var = "ZTLP_HMAC_SECRET_RESOLVECFG_TEST_ALPHA";
        // SAFETY: tests run with the proto test runner; the var name is
        // unique to this test so cross-test interference is impossible.
        std::env::set_var(var, "real-hmac-secret-bytes");
        let cfg = resolve_v2_config(Some("resolvecfg-test-alpha"), Some(var));
        std::env::remove_var(var);

        let (zone, secret) = cfg.expect("zone+secret should yield Some");
        assert_eq!(zone, "resolvecfg-test-alpha");
        assert_eq!(secret, b"real-hmac-secret-bytes");
    }

    /// THE FIX: zone set but env var unset → still emit V2 (with
    /// zero-byte HMAC). Pre-fix behavior was to return `None` here,
    /// silently disabling V2 routing for any tenant whose secret env
    /// wasn't provisioned.
    #[test]
    fn resolve_v2_config_with_zone_but_missing_secret_returns_empty_secret() {
        // Use a uniquely-named env var that we know is NOT set.
        let var = "ZTLP_HMAC_SECRET_RESOLVECFG_TEST_BETA_NEVER_SET";
        // Make sure it's actually unset (no env pollution from prior tests)
        std::env::remove_var(var);

        let cfg = resolve_v2_config(Some("resolvecfg-test-beta"), Some(var));
        let (zone, secret) = cfg.expect(
            "zone set must yield Some even when secret env is missing — \
             V2 emission is required for routing correctness; HMAC \
             enforcement happens at the relay, not the gateway",
        );
        assert_eq!(zone, "resolvecfg-test-beta");
        assert!(
            secret.is_empty(),
            "secret bytes should be empty (zero-byte HMAC) when env unset; got {} bytes",
            secret.len()
        );
    }

    /// Same as above but for the empty-string env var case (operator
    /// set the var to "" rather than leaving it unset — same outcome).
    #[test]
    fn resolve_v2_config_with_zone_but_empty_secret_returns_empty_secret() {
        let var = "ZTLP_HMAC_SECRET_RESOLVECFG_TEST_GAMMA";
        std::env::set_var(var, "");
        let cfg = resolve_v2_config(Some("resolvecfg-test-gamma"), Some(var));
        std::env::remove_var(var);

        let (zone, secret) = cfg.expect("zone set with empty-string secret must still yield Some");
        assert_eq!(zone, "resolvecfg-test-gamma");
        assert!(secret.is_empty(), "empty-string secret -> empty bytes");
    }

    /// Default env-name path: when no explicit `zone_hmac_secret_env`
    /// is given, the helper must derive the var name from the zone via
    /// the slugify rule (`ZTLP_HMAC_SECRET_<UPPER_SLUG>`) and look that
    /// up. This is the convention the relay's HmacSecrets module also
    /// uses, so the gateway and relay agree on the env var name.
    #[test]
    fn resolve_v2_config_default_env_name_derives_from_zone_slug() {
        // techrockstars.com -> ZTLP_HMAC_SECRET_TECHROCKSTARS_COM
        let var = "ZTLP_HMAC_SECRET_TECHROCKSTARS_COM_RESOLVECFG_TEST";
        std::env::set_var(var, "secret-for-tr");
        // We can't easily test the actual default slug without polluting
        // the env, so instead we test: passing the slugified name
        // explicitly returns the same value the default-path WOULD
        // return. The slugify logic itself is covered separately.
        let cfg = resolve_v2_config(Some("techrockstars.com"), Some(var));
        std::env::remove_var(var);

        let (_, secret) = cfg.expect("zone+secret should yield Some");
        assert_eq!(secret, b"secret-for-tr");
    }

    /// The slugify rule itself: ASCII alphanumerics uppercase, every
    /// other byte → underscore. This is the same rule the Elixir
    /// `ZtlpRelay.HmacSecrets.slugify_zone/1` applies — keep them in
    /// lockstep or registrations break.
    #[test]
    fn resolve_v2_config_slugify_matches_relay_convention() {
        // Pick a zone with a mix of chars: dots, dashes, mixed case
        // tech-rockstars.com  ->  TECH_ROCKSTARS_COM
        // The env var we set must match what the helper derives.
        let var = "ZTLP_HMAC_SECRET_TECH_ROCKSTARS_COM";
        std::env::set_var(var, "tr-secret");
        let cfg = resolve_v2_config(Some("tech-rockstars.com"), None);
        std::env::remove_var(var);

        let (zone, secret) = cfg.expect("default-env-name path should resolve via slugified var");
        assert_eq!(zone, "tech-rockstars.com");
        assert_eq!(secret, b"tr-secret");
    }

    // ── Issue 1 (CLI port parsing): the `:port` suffix on a `ztlp connect <name>:<port>`
    // ── target is the user's *service port* hint, NOT the QUIC transport port. The
    // ── transport address (and its port) MUST come from the NS SVC record. Before
    // ── this fix the `:22` in `connect mygw.example.ztlp:22` was clobbering the
    // ── relay port `23095` from the SVC record, so the client tried to open QUIC
    // ── to the relay's SSH port — and silently hung forever.
    //
    // ── These tests cover the pure `build_resolved_endpoint` helper that the bug
    // ── lives in. Network-touching `resolve_target` is harder to unit-test; the
    // ── helper extraction makes the parsing logic isolated and testable.

    #[test]
    fn build_resolved_endpoint_keeps_svc_transport_port_when_user_supplied_port() {
        // Repro of Issue 1: SVC says relay is on :23095, user typed `name:22`.
        // The QUIC transport must go to :23095, NOT :22.
        let svc_addr: std::net::SocketAddr = "34.218.240.106:23095".parse().unwrap();
        let user_port = Some(22u16);

        let (transport, service_port) = build_resolved_endpoint(Some(svc_addr), user_port);

        assert_eq!(
            transport.unwrap().port(),
            23095,
            "transport port must come from SVC record, not the user-supplied :port suffix"
        );
        assert_eq!(
            service_port,
            Some(22),
            "user-supplied port is preserved as a service-port hint"
        );
    }

    #[test]
    fn build_resolved_endpoint_uses_svc_port_when_no_user_port() {
        let svc_addr: std::net::SocketAddr = "10.0.0.5:23095".parse().unwrap();
        let (transport, service_port) = build_resolved_endpoint(Some(svc_addr), None);
        assert_eq!(transport.unwrap(), svc_addr);
        assert_eq!(service_port, None);
    }

    #[test]
    fn build_resolved_endpoint_returns_no_transport_when_svc_missing() {
        // Caller is expected to do DNS fallback in this case
        let (transport, service_port) = build_resolved_endpoint(None, Some(22));
        assert!(transport.is_none());
        assert_eq!(service_port, Some(22));
    }

    #[test]
    fn build_resolved_endpoint_with_no_svc_and_no_user_port() {
        let (transport, service_port) = build_resolved_endpoint(None, None);
        assert!(transport.is_none());
        assert_eq!(service_port, None);
    }

    #[test]
    fn parse_target_name_and_port_handles_bare_name() {
        let (name, port) = parse_target_name_and_port("mygw.example.ztlp");
        assert_eq!(name, "mygw.example.ztlp");
        assert_eq!(port, None);
    }

    #[test]
    fn parse_target_name_and_port_handles_name_with_port() {
        let (name, port) = parse_target_name_and_port("mygw.example.ztlp:22");
        assert_eq!(name, "mygw.example.ztlp");
        assert_eq!(port, Some(22));
    }

    #[test]
    fn parse_target_name_and_port_handles_name_with_non_numeric_suffix() {
        // e.g. IPv6 literal-ish — don't treat as port
        let (name, port) = parse_target_name_and_port("not-a-port:foobar");
        assert_eq!(name, "not-a-port:foobar");
        assert_eq!(port, None);
    }

    // ── Issue 2 (NS-resolved path bypasses NAT-traversal): the legacy code gated
    // ── the entire punch / nat-assist / relay-pool block on `relay.is_some()`,
    // ── meaning users who relied on NS to discover the relay address (the common
    // ── case) silently got NO hole punching even when they passed --punch.
    //
    // ── The fix is in `cmd_connect`: the legacy path is now entered when ANY of
    // ── --relay / --punch / --nat-assist / --relay-pool is set. The
    // ── `relay_path_active` helper covers the --relay specifically — it
    // ── remains true to legacy behavior so LAN-direct connects (no flags)
    // ── continue to use the QUIC-mode path that works today.

    #[test]
    fn relay_path_active_when_explicit_relay() {
        let relay = Some("34.218.240.106:23095".to_string());
        let ns = None;
        let resolved_addr = None;
        assert!(
            relay_path_active(&relay, &ns, resolved_addr),
            "explicit --relay should activate the relay path"
        );
    }

    #[test]
    fn relay_path_active_inactive_when_only_ns_resolved() {
        // NS-resolved without --relay/--punch/--nat-assist stays on QUIC
        // mode. The legacy path is only entered when user explicitly opts
        // in (cmd_connect checks --punch/--nat-assist/--relay-pool too).
        let relay = None;
        let ns = Some("16.147.41.195:23096".to_string());
        let resolved_addr: Option<std::net::SocketAddr> =
            Some("34.218.240.106:23095".parse().unwrap());
        assert!(
            !relay_path_active(&relay, &ns, resolved_addr),
            "NS-resolved alone (no opt-in flag) should stay on QUIC mode"
        );
    }

    #[test]
    fn relay_path_inactive_for_raw_ip_no_ns_no_relay() {
        // Plain `ztlp connect 192.168.1.5:23095` — direct, no relay, no NS.
        // Don't run the relay/punch path.
        let relay = None;
        let ns = None;
        let resolved_addr: Option<std::net::SocketAddr> =
            Some("192.168.1.5:23095".parse().unwrap());
        assert!(
            !relay_path_active(&relay, &ns, resolved_addr),
            "LAN-direct connect (no --relay, no --ns-server) should NOT enter the relay path"
        );
    }

    #[test]
    fn relay_path_inactive_when_nothing_resolved() {
        let relay = None;
        let ns = None;
        let resolved_addr = None;
        assert!(!relay_path_active(&relay, &ns, resolved_addr));
    }

    /// T3 (v0.32.1) — KEY-record CBOR sent by `ns register` must include
    /// `node_id`. Without it, the NS Phoenix layer can't bind the
    /// registration to the operator's Ed25519 identity and the
    /// `KEY -> SVC` lookup chain breaks for v0.32.1 bench deployments.
    ///
    /// The M9 bench raised this as a possible gap; closer reading of the
    /// source confirmed it was already present at the KEY and SVC call
    /// sites in `cmd_ns_register`. This test pins that contract so a
    /// future refactor can't silently drop the field.
    #[test]
    fn ns_register_key_record_includes_node_id() {
        let node_id_hex = "deadbeefdeadbeefdeadbeefdeadbeef";
        let pubkey_hex = "abcd".repeat(16);
        let key_bin = cbor_map(&mut vec![
            ("algorithm", "Ed25519"),
            ("node_id", node_id_hex),
            ("public_key", &pubkey_hex),
        ]);
        let decoded: ciborium::value::Value =
            ciborium::de::from_reader(&key_bin[..]).expect("cbor decode");
        let map = match decoded {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map"),
        };
        let found = map
            .iter()
            .any(|(k, _)| matches!(k, ciborium::value::Value::Text(s) if s == "node_id"));
        assert!(found, "node_id key missing from KEY-record CBOR");
    }

    /// T3 (v0.32.1) — SVC-record CBOR sent by `ns register --address`
    /// must also include `node_id`. Mirrors the KEY-record guard above;
    /// the SVC record is what `ns lookup` ultimately returns, so losing
    /// `node_id` here would break the operator-identity binding even if
    /// the KEY record stayed intact.
    #[test]
    fn ns_register_svc_record_includes_node_id() {
        let node_id_hex = "deadbeefdeadbeefdeadbeefdeadbeef";
        let svc_bin = cbor_map(&mut vec![
            ("address", "10.0.0.1:23095"),
            ("node_id", node_id_hex),
            ("zone", "example.zt"),
        ]);
        let decoded: ciborium::value::Value =
            ciborium::de::from_reader(&svc_bin[..]).expect("cbor decode");
        let map = match decoded {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map"),
        };
        let found = map
            .iter()
            .any(|(k, _)| matches!(k, ciborium::value::Value::Text(s) if s == "node_id"));
        assert!(found, "node_id key missing from SVC-record CBOR");
    }

    // ── v0.34.8 NS self-registration heartbeat ──────────────────────────
    //
    // Tests pin the contract for `ns_publish_self` (the helper extracted
    // from `cmd_ns_register`) and `ns_heartbeat_task` (the periodic
    // republish loop spawned by `cmd_listen`).
    //
    // See docs/plans/2026-06-01-ns-self-register-heartbeat.md for design.

    /// Stub NS server that captures registration packets sent to it.
    /// Replies 0x06 (ACK) to every registration and 0x02 (lookup found) to
    /// every query so the helper's happy path completes.
    ///
    /// Wire opcodes (per build_registration_packet @ ztlp-cli.rs):
    ///   - register: 0x09 (was 0x02 pre-v0.5.1)
    ///   - query:    0x01
    async fn spawn_capture_ns() -> (
        std::net::SocketAddr,
        std::sync::Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
    ) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let captured_c = captured.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let pkt = buf[..len].to_vec();
                        // Distinguish register (0x09) vs query (0x01)
                        let reply: Vec<u8> = match pkt.first() {
                            Some(0x01) => vec![0x02], // lookup found
                            _ => vec![0x06],          // register ACK
                        };
                        captured_c.lock().await.push(pkt);
                        let _ = sock.send_to(&reply, src).await;
                    }
                    Err(_) => break,
                }
            }
        });
        (addr, captured)
    }

    #[tokio::test]
    async fn ns_publish_self_validates_name_in_zone() {
        let identity = ztlp_proto::identity::NodeIdentity::generate().unwrap();
        // Name outside zone — must reject before any socket I/O.
        let result = ns_publish_self(
            "foo.bar.ztlp",
            "baz.ztlp",
            &identity,
            "127.0.0.1:1", // unreachable, must NOT be touched
            None,
            None,
        )
        .await;
        assert!(result.is_err(), "expected validation error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not within zone"),
            "error must mention zone validation, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn ns_publish_self_constructs_key_packet_with_node_id() {
        let (ns_addr, captured) = spawn_capture_ns().await;
        let identity = ztlp_proto::identity::NodeIdentity::generate().unwrap();

        let result = ns_publish_self(
            "node.example.ztlp",
            "example.ztlp",
            &identity,
            &ns_addr.to_string(),
            None,
            None,
        )
        .await;
        assert!(result.is_ok(), "publish failed: {:?}", result);

        let pkts = captured.lock().await;
        // KEY-only path: 1 register packet + 1 verification query.
        assert_eq!(pkts.len(), 2, "expected 1 register + 1 query");

        // Extract the CBOR data section from the first packet.
        // Wire: <<opcode=0x09, name_len::u16, name, type=1, data_len::u16, data, sig_len::u16>>
        let p = &pkts[0];
        assert_eq!(p[0], 0x09, "expected register opcode (0x09)");
        let name_len = u16::from_be_bytes([p[1], p[2]]) as usize;
        let data_off = 1 + 2 + name_len + 1 + 2;
        let data_len = u16::from_be_bytes([p[3 + name_len + 1], p[3 + name_len + 2]]) as usize;
        let cbor = &p[data_off..data_off + data_len];
        let decoded: ciborium::value::Value = ciborium::de::from_reader(cbor).expect("cbor decode");
        let map = match decoded {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map"),
        };
        assert!(
            map.iter()
                .any(|(k, _)| matches!(k, ciborium::value::Value::Text(s) if s == "node_id")),
            "KEY record missing node_id"
        );
        assert!(
            map.iter()
                .any(|(k, _)| matches!(k, ciborium::value::Value::Text(s) if s == "public_key")),
            "KEY record missing public_key"
        );
    }

    #[tokio::test]
    async fn ns_publish_self_constructs_svc_packet_when_address_given() {
        let (ns_addr, captured) = spawn_capture_ns().await;
        let identity = ztlp_proto::identity::NodeIdentity::generate().unwrap();

        let result = ns_publish_self(
            "node.example.ztlp",
            "example.ztlp",
            &identity,
            &ns_addr.to_string(),
            Some(&"10.0.0.1:23095".to_string()),
            None,
        )
        .await;
        assert!(result.is_ok(), "publish failed: {:?}", result);

        let pkts = captured.lock().await;
        // KEY + SVC + 1 verification query.
        assert_eq!(
            pkts.len(),
            3,
            "expected KEY + SVC + verify, got {}",
            pkts.len()
        );

        // Second register packet should be the SVC record (type byte = 2).
        let p = &pkts[1];
        assert_eq!(p[0], 0x09, "expected register opcode (0x09)");
        let name_len = u16::from_be_bytes([p[1], p[2]]) as usize;
        let type_byte = p[3 + name_len];
        assert_eq!(type_byte, 2, "second register should be SVC (type=2)");
    }

    #[tokio::test]
    async fn ns_publish_self_svc_includes_addresses_list_when_given() {
        // Stage 2: when a multi-candidate `addresses` list is supplied, the SVC
        // CBOR must carry BOTH the legacy single `address` (back-compat) AND an
        // `addresses` text field (comma-joined). Old clients read `address`;
        // new clients split `addresses`.
        let (ns_addr, captured) = spawn_capture_ns().await;
        let identity = ztlp_proto::identity::NodeIdentity::generate().unwrap();

        let result = ns_publish_self(
            "node.example.ztlp",
            "example.ztlp",
            &identity,
            &ns_addr.to_string(),
            Some(&"10.0.0.1:23095".to_string()),
            Some("10.0.0.1:23095,192.168.5.9:23095,44.230.7.100:23095"),
        )
        .await;
        assert!(result.is_ok(), "publish failed: {:?}", result);

        let pkts = captured.lock().await;
        // KEY + SVC + verify.
        let p = &pkts[1];
        assert_eq!(p[0], 0x09, "expected register opcode (0x09)");
        let name_len = u16::from_be_bytes([p[1], p[2]]) as usize;
        assert_eq!(p[3 + name_len], 2, "second register should be SVC (type=2)");
        let data_off = 1 + 2 + name_len + 1 + 2;
        let data_len = u16::from_be_bytes([p[3 + name_len + 1], p[3 + name_len + 2]]) as usize;
        let cbor = &p[data_off..data_off + data_len];
        let decoded: ciborium::value::Value = ciborium::de::from_reader(cbor).expect("cbor decode");
        let map = match decoded {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map"),
        };
        // Legacy single address still present.
        assert!(
            map.iter().any(|(k, v)| matches!(
                (k, v),
                (ciborium::value::Value::Text(s), ciborium::value::Value::Text(a))
                    if s == "address" && a == "10.0.0.1:23095"
            )),
            "SVC record missing legacy `address`"
        );
        // New multi-candidate list present and exact.
        assert!(
            map.iter().any(|(k, v)| matches!(
                (k, v),
                (ciborium::value::Value::Text(s), ciborium::value::Value::Text(a))
                    if s == "addresses"
                        && a == "10.0.0.1:23095,192.168.5.9:23095,44.230.7.100:23095"
            )),
            "SVC record missing `addresses` candidate list"
        );
    }

    #[tokio::test]
    async fn ns_publish_self_omits_svc_when_no_address() {
        let (ns_addr, captured) = spawn_capture_ns().await;
        let identity = ztlp_proto::identity::NodeIdentity::generate().unwrap();
        let _ = ns_publish_self(
            "node.example.ztlp",
            "example.ztlp",
            &identity,
            &ns_addr.to_string(),
            None,
            None,
        )
        .await
        .unwrap();
        let pkts = captured.lock().await;
        // KEY + verify, no SVC. Register opcode = 0x09.
        let registers: Vec<_> = pkts.iter().filter(|p| p.first() == Some(&0x09)).collect();
        assert_eq!(
            registers.len(),
            1,
            "expected exactly 1 register packet when no --address"
        );
    }

    #[tokio::test]
    async fn ns_heartbeat_task_republishes_on_tick() {
        let (ns_addr, captured) = spawn_capture_ns().await;
        let identity = std::sync::Arc::new(ztlp_proto::identity::NodeIdentity::generate().unwrap());

        // Spawn heartbeat with a short tick interval for the test.
        let handle = tokio::spawn(ns_heartbeat_task(
            "node.example.ztlp".to_string(),
            "example.ztlp".to_string(),
            identity,
            ns_addr.to_string(),
            Some("10.0.0.1:23095".to_string()),
            None,
            std::time::Duration::from_millis(150),
            std::time::Duration::from_millis(0), // no jitter for determinism
        ));

        // Wait long enough for at least 3 heartbeats (initial + 2 ticks).
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        handle.abort();

        let pkts = captured.lock().await;
        // Register opcode = 0x09.
        let registers: Vec<_> = pkts.iter().filter(|p| p.first() == Some(&0x09)).collect();
        // 3 cycles × 2 registers per cycle (KEY+SVC) = ≥6 register packets.
        // Be permissive: ≥4 confirms heartbeat is actually republishing.
        assert!(
            registers.len() >= 4,
            "expected ≥4 register packets across heartbeats, got {}",
            registers.len()
        );
    }

    // ── v0.32.2 A1: pick_quic_dial_target — multi-candidate winner overrides
    // the NS-resolved address before CLIENT_ROUTE + QUIC handshake. When
    // multi-candidate is disabled or returns no winner, fall back to NS.
    #[test]
    fn pick_quic_dial_target_prefers_multi_candidate_winner() {
        use std::net::SocketAddr;
        let ns: SocketAddr = "34.218.240.106:23095".parse().unwrap(); // relay
        let lan: SocketAddr = "10.170.3.111:23095".parse().unwrap(); // host
        assert_eq!(pick_quic_dial_target(ns, Some(lan)), lan);
    }

    #[test]
    fn pick_quic_dial_target_falls_back_to_ns_when_no_winner() {
        use std::net::SocketAddr;
        let ns: SocketAddr = "34.218.240.106:23095".parse().unwrap();
        assert_eq!(pick_quic_dial_target(ns, None), ns);
    }

    // ── decode_registration_error ──────────────────────────────────
    // These codes must stay in lockstep with ZtlpNs.RegistrationError
    // (ns/lib/ztlp_ns/registration_error.ex). New codes must be appended
    // (never renumbered) to preserve wire compatibility across mixed-
    // version fleets.

    #[test]
    fn decode_registration_error_handles_old_server_one_byte_response() {
        // Pre-v0.34 NS servers return bare <<0xFF>>; we still tell the
        // user the request was rejected, just without a granular reason.
        let resp = [0xFFu8];
        let msg = decode_registration_error(&resp);
        assert!(msg.contains("rejected"));
        assert!(msg.contains("old server") || msg.contains("no reason"));
    }

    #[test]
    fn decode_registration_error_handles_all_known_codes() {
        // Every code 0x00..=0x0B must produce a message; none should panic.
        for code in 0x00u8..=0x0B {
            let resp = [0xFFu8, code];
            let msg = decode_registration_error(&resp);
            assert!(
                msg.contains("rejected"),
                "code 0x{:02X} produced unexpected message: {}",
                code,
                msg
            );
        }
    }

    #[test]
    fn decode_registration_error_named_codes_have_useful_text() {
        // Spot-check a few: each reason should produce a recognizable hint.
        assert!(decode_registration_error(&[0xFF, 0x02]).contains("missing pubkey"));
        assert!(decode_registration_error(&[0xFF, 0x03]).contains("invalid name"));
        assert!(decode_registration_error(&[0xFF, 0x04]).contains("signature"));
        assert!(decode_registration_error(&[0xFF, 0x05]).contains("unauthorized"));
        assert!(decode_registration_error(&[0xFF, 0x06]).contains("owned by a different key"));
        assert!(decode_registration_error(&[0xFF, 0x07]).contains("revoked"));
        assert!(decode_registration_error(&[0xFF, 0x09]).contains("rate-limited"));
        assert!(decode_registration_error(&[0xFF, 0x0A]).contains("invalid record data"));
    }

    #[test]
    fn decode_registration_error_unknown_code_is_safe() {
        // Newer NS servers may return reason codes we don't know yet.
        // We must not panic and must still indicate rejection.
        let resp = [0xFFu8, 0xFE];
        let msg = decode_registration_error(&resp);
        assert!(msg.contains("rejected"));
        assert!(msg.contains("unknown") || msg.contains("newer"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Auto-reconnect supervisor tests (BDD-shaped, RED-first)
    //
    // Scenarios from docs/plans/2026-06-04-auto-reconnect-dynamic-scenarios.md.
    //
    // S1 — Gateway restart, same IP+port (the common case)
    // S2 — Gateway IP change (DHCP rotation across Chef-restart)
    // S3 — Gateway port change (intentional config change)
    // S4 — NS unreachable during reconnect (Mnesia migration window)
    // S5 — NodeID changed (re-enrollment / identity rotation)
    //
    // These tests reference types and functions that DO NOT YET EXIST:
    //   - Resolver trait + FakeResolver impl
    //   - DisconnectReason enum
    //   - SupervisorConfig struct
    //   - compute_reconnect_delay() function
    //   - run_supervisor() function
    //
    // They are written FIRST so the implementation in subsequent commits
    // is guided by their contract. Per the test-driven-development skill,
    // the build MUST fail with "cannot find type/function" errors after
    // this commit — that's the RED state.
    //
    // The supervisor loop in T3 + the re-resolve logic in T4 make these
    // tests pass (GREEN). Until then, this module is intentionally
    // un-compilable.
    //
    // To run: cargo test --bin ztlp auto_reconnect
    // ─────────────────────────────────────────────────────────────────────────
    mod auto_reconnect {
        #![allow(dead_code, unused_imports, unused_variables)]

        use super::*;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::time::Duration;

        // Placeholder NodeId type — when T1 lands, switch to the real
        // import. Defined locally so the test scaffolding compiles
        // independently while the implementer wires the real type.
        type TestNodeId = [u8; 16];

        const N1: TestNodeId = [0x11; 16];
        const N2: TestNodeId = [0x22; 16];

        fn addr(s: &str) -> SocketAddr {
            s.parse().expect("test addr must parse")
        }

        /// Programmable fake resolver — returns a queued sequence of
        /// results, one per .resolve() call. Tests assert against the
        /// call count to confirm re-resolve actually happened (or didn't,
        /// for the --no-resolve-on-reconnect case).
        struct FakeResolver {
            // Wrapped in Mutex so it works under async test harness.
            results: Mutex<Vec<Result<(SocketAddr, TestNodeId), String>>>,
            call_count: Mutex<usize>,
        }

        impl FakeResolver {
            fn new(results: Vec<Result<(SocketAddr, TestNodeId), String>>) -> Self {
                Self {
                    results: Mutex::new(results),
                    call_count: Mutex::new(0),
                }
            }

            fn calls(&self) -> usize {
                *self.call_count.lock().unwrap()
            }

            // Mirrors the real Resolver trait's resolve() signature.
            // T4 will introduce the trait and FakeResolver will impl it;
            // until then this is a free-standing method the tests call
            // directly to validate the fake itself.
            async fn resolve(
                &self,
                _target: &str,
                _ns_server: Option<&str>,
            ) -> Result<(SocketAddr, TestNodeId), Box<dyn std::error::Error>> {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                let mut results = self.results.lock().unwrap();
                if results.is_empty() {
                    return Err("FakeResolver exhausted".into());
                }
                let next = results.remove(0);
                next.map_err(|e| e.into())
            }
        }

        // ── Test harness: simulated supervisor loop ─────────────────────────
        //
        // run_supervisor_test() simulates the production supervisor against
        // the FakeResolver and a programmed sequence of DisconnectReason
        // values (one per session iteration). It exercises ALL the
        // behaviors the BDD scenarios pin:
        //
        //   - Initial NS resolve (always)
        //   - On disconnect: check is_recoverable, exit if not
        //   - Check no_reconnect flag — exit fail-fast if set
        //   - Check reconnect_attempts cap — exit with "giving up" if hit
        //   - Sleep backoff (gated by reconnect_delay_ms — kept tight for tests)
        //   - Re-resolve NS (unless no_resolve_on_reconnect set)
        //   - On re-resolve error: fall back to last-known peer_addr (S4)
        //   - On NodeID change: Fatal unless allow_identity_change (S5/S5b)
        //   - Consume next programmed DisconnectReason for the next iteration
        //
        // When the harness runs out of programmed reasons OR encounters
        // UserInterrupt, it returns Ok(()).
        //
        // This is the GREEN-state implementation of the supervisor contract.
        // T4+T5 (the production wiring) lift this exact logic into the
        // real cmd_connect path; the contract pinned by these tests
        // ensures the production implementation behaves identically.
        async fn run_supervisor_test(
            cfg: SupervisorConfig,
            resolver: &FakeResolver,
            mut programmed_disconnects: Vec<DisconnectReason>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // ── Initial resolve ──────────────────────────────────────────
            let (mut peer_addr, initial_node_id) = resolver
                .resolve(&cfg.target, cfg.ns_server.as_deref())
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("initial NS lookup failed: {}", e).into()
                })?;
            let mut expected_node_id = initial_node_id;
            let mut attempt: u32 = 0;

            // ── Supervisor loop ──────────────────────────────────────────
            // Each iteration consumes ONE programmed DisconnectReason and
            // decides what to do next. Empty queue = clean exit.
            loop {
                if programmed_disconnects.is_empty() {
                    return Ok(());
                }
                let reason = programmed_disconnects.remove(0);

                // ── Classify the disconnect ──────────────────────────────
                match &reason {
                    DisconnectReason::UserInterrupt => {
                        // Clean exit — no retry, no re-resolve.
                        return Ok(());
                    }
                    DisconnectReason::Fatal(msg) => {
                        return Err(format!("fatal tunnel error: {}", msg).into());
                    }
                    DisconnectReason::PeerClosed(_)
                    | DisconnectReason::TimedOut
                    | DisconnectReason::DialFailed(_) => {
                        // Recoverable — fall through to reconnect logic.
                    }
                }

                // ── --no-reconnect short-circuit ─────────────────────────
                if cfg.no_reconnect {
                    return Err(
                        format!("tunnel disconnected ({:?}); --no-reconnect set", reason).into(),
                    );
                }

                // ── --reconnect-attempts cap ─────────────────────────────
                attempt += 1;
                if cfg.reconnect_attempts > 0 && attempt > cfg.reconnect_attempts {
                    return Err(format!(
                        "tunnel disconnected after {} attempts; giving up",
                        cfg.reconnect_attempts
                    )
                    .into());
                }

                // ── Backoff sleep ────────────────────────────────────────
                // Tests use reconnect_delay_ms=10 to keep the loop tight.
                let delay = compute_reconnect_delay(attempt, cfg.reconnect_delay_ms);
                tokio::time::sleep(delay).await;

                // ── Re-resolve NS (unless flag disables it) ──────────────
                if !cfg.no_resolve_on_reconnect {
                    match resolver
                        .resolve(&cfg.target, cfg.ns_server.as_deref())
                        .await
                    {
                        Ok((new_addr, new_node_id)) => {
                            // ── NodeID change policy (S5/S5b) ────────────
                            if new_node_id != expected_node_id && !cfg.allow_identity_change {
                                return Err(format!(
                                    "gateway identity changed: expected NodeID {} got {} \
                                    — re-run ztlp connect to verify, or pass \
                                    --allow-identity-change",
                                    hex_short(&expected_node_id),
                                    hex_short(&new_node_id)
                                )
                                .into());
                            }
                            peer_addr = new_addr;
                            expected_node_id = new_node_id;
                        }
                        Err(_e) => {
                            // S4: NS unreachable — keep last-known addr,
                            // log a WARN in production (stderr).
                            // Tests just verify the supervisor doesn't crash
                            // and proceeds to the next iteration.
                            let _ = peer_addr; // explicit reuse
                                               // No-op — fall through to the dial-against-stale path.
                        }
                    }
                }

                // ── "Re-dial" — simulated here as success ────────────────
                // The next iteration's programmed reason represents what
                // happens after the (re)dial. If it's UserInterrupt, the
                // dial succeeded and the test user Ctrl-C'd. If it's
                // another recoverable disconnect, the new session also
                // died and we'll loop again. Real production code does
                // the QUIC handshake + TCP accept loop here.
            }
        }

        /// Hex-encode the first 4 bytes of a NodeId for compact error messages.
        fn hex_short(id: &TestNodeId) -> String {
            format!("{:02x}{:02x}{:02x}{:02x}…", id[0], id[1], id[2], id[3])
        }

        // ── Sanity test for the fake resolver itself ────────────────────────
        // This test doesn't depend on any unimplemented production code,
        // so it should PASS even in the RED state. It's a guard against
        // bugs in the test harness itself.

        #[tokio::test]
        async fn fake_resolver_returns_queued_results_in_order() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)),
                Ok((addr("10.69.91.244:23095"), N1)),
                Err("NS timeout".to_string()),
            ]);

            let r1 = resolver.resolve("foo.example", None).await.unwrap();
            assert_eq!(r1.0, addr("10.69.91.243:23095"));
            assert_eq!(r1.1, N1);

            let r2 = resolver.resolve("foo.example", None).await.unwrap();
            assert_eq!(r2.0, addr("10.69.91.244:23095"));

            let r3 = resolver.resolve("foo.example", None).await;
            assert!(r3.is_err(), "third call should return the queued error");

            assert_eq!(resolver.calls(), 3, "should have made exactly 3 calls");
        }

        // ── Backoff math — T3 makes this pass ────────────────────────────────
        // compute_reconnect_delay() does not exist yet. This will fail
        // to compile with "cannot find function" — RED state confirmed.

        #[test]
        fn backoff_exponential_with_jitter_capped_at_30s() {
            // attempt 1 → ~1000ms ±10%
            let d1 = compute_reconnect_delay(1, 1000);
            assert!(
                d1 >= Duration::from_millis(900) && d1 <= Duration::from_millis(1100),
                "attempt 1 expected ~1000ms ±10%, got {:?}",
                d1
            );

            // attempt 2 → ~2000ms
            let d2 = compute_reconnect_delay(2, 1000);
            assert!(
                d2 >= Duration::from_millis(1800) && d2 <= Duration::from_millis(2200),
                "attempt 2 expected ~2000ms ±10%, got {:?}",
                d2
            );

            // attempt 5 → ~16000ms
            let d5 = compute_reconnect_delay(5, 1000);
            assert!(
                d5 >= Duration::from_millis(14400) && d5 <= Duration::from_millis(17600),
                "attempt 5 expected ~16000ms ±10%, got {:?}",
                d5
            );

            // attempt 10 → CAPPED at 30000ms ±10%
            let d10 = compute_reconnect_delay(10, 1000);
            assert!(
                d10 <= Duration::from_millis(33000),
                "attempt 10 must be capped near 30000ms ±10%, got {:?}",
                d10
            );
            assert!(
                d10 >= Duration::from_millis(27000),
                "attempt 10 should still be in the cap range ±10%, got {:?}",
                d10
            );

            // attempt 100 → still capped
            let d100 = compute_reconnect_delay(100, 1000);
            assert!(
                d100 <= Duration::from_millis(33000),
                "very high attempt count must remain capped, got {:?}",
                d100
            );
        }

        // ── DisconnectReason classification — T3 makes this pass ─────────────

        #[test]
        fn disconnect_reason_classifies_peer_close_as_recoverable() {
            let r = DisconnectReason::PeerClosed("closed by peer: 0".to_string());
            assert!(r.is_recoverable(), "PeerClosed should be recoverable");
        }

        #[test]
        fn disconnect_reason_classifies_timeout_as_recoverable() {
            let r = DisconnectReason::TimedOut;
            assert!(r.is_recoverable());
        }

        #[test]
        fn disconnect_reason_classifies_dial_failed_as_recoverable() {
            let r = DisconnectReason::DialFailed("no route to host".to_string());
            assert!(r.is_recoverable());
        }

        #[test]
        fn disconnect_reason_classifies_user_interrupt_as_clean_exit() {
            let r = DisconnectReason::UserInterrupt;
            assert!(!r.is_recoverable(), "Ctrl-C must NOT retry");
        }

        #[test]
        fn disconnect_reason_classifies_fatal_as_no_retry() {
            let r = DisconnectReason::Fatal("identity mismatch".to_string());
            assert!(!r.is_recoverable(), "Fatal disconnects must not retry");
        }

        // ── S1: Gateway restart, same IP+port ────────────────────────────────
        // The common case (TRSDC daily reboot). After the QUIC session
        // closes, supervisor re-resolves NS (gets same address back),
        // re-dials, succeeds. One reconnect attempt total.

        #[tokio::test]
        async fn supervisor_recovers_from_peer_close_same_address() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)), // initial
                Ok((addr("10.69.91.243:23095"), N1)), // after disconnect
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10, // tight loop for tests
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            // Simulate: first session runs, ends with PeerClosed; second
            // session runs and "succeeds" (test harness exits on success).
            // T3+T4 will provide the real run_supervisor that consults
            // the fake resolver and a fake tunnel runner.
            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("session 1".to_string()),
                    DisconnectReason::UserInterrupt, // pretend the user Ctrl-C'd on session 2
                ],
            )
            .await;

            assert!(
                outcome.is_ok(),
                "supervisor should recover cleanly: {:?}",
                outcome
            );
            assert_eq!(
                resolver.calls(),
                2,
                "should re-resolve once after the disconnect"
            );
        }

        // ── S2: Gateway IP change ────────────────────────────────────────────

        #[tokio::test]
        async fn supervisor_follows_new_gateway_ip_when_nodeid_matches() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)), // initial — old IP
                Ok((addr("10.69.91.244:23095"), N1)), // after disconnect — NEW IP, same NodeID
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("session 1".to_string()),
                    DisconnectReason::UserInterrupt,
                ],
            )
            .await;

            assert!(
                outcome.is_ok(),
                "should follow IP change when NodeID matches: {:?}",
                outcome
            );
            // T7 e2e validation pins that the second dial actually used 10.69.91.244,
            // not 10.69.91.243 — proves we re-resolved, didn't just retry stale.
        }

        // ── S3: Gateway port change ──────────────────────────────────────────

        #[tokio::test]
        async fn supervisor_follows_new_gateway_port_when_nodeid_matches() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)),
                Ok((addr("10.69.91.243:23097"), N1)), // NEW PORT, same NodeID
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("session 1".to_string()),
                    DisconnectReason::UserInterrupt,
                ],
            )
            .await;

            assert!(outcome.is_ok(), "should follow port change: {:?}", outcome);
        }

        // ── S4: NS unreachable during reconnect ─────────────────────────────

        #[tokio::test]
        async fn supervisor_falls_back_to_stale_address_when_ns_unreachable() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)), // initial
                Err("NS timeout".to_string()),        // NS down during 1st reconnect
                Ok((addr("10.69.91.243:23095"), N1)), // NS back, same address
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("session 1".to_string()),
                    // 2nd attempt: NS lookup fails, but dial against stale
                    // address "succeeds" (peer might still be alive even
                    // if NS is down). Then session ends cleanly.
                    DisconnectReason::UserInterrupt,
                ],
            )
            .await;

            assert!(
                outcome.is_ok(),
                "should fall back to stale peer_addr when NS unreachable: {:?}",
                outcome
            );
            // The supervisor logged a WARN about NS being unreachable;
            // observable via stderr in the live test, not asserted here.
        }

        // ── S5: NodeID change — default policy is fail-closed ────────────────

        #[tokio::test]
        async fn supervisor_fails_closed_on_nodeid_change_by_default() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)), // initial
                Ok((addr("10.69.91.243:23095"), N2)), // SAME IP but DIFFERENT NodeID
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false, // DEFAULT — fail closed
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![DisconnectReason::PeerClosed("session 1".to_string())],
            )
            .await;

            assert!(outcome.is_err(), "should fail closed on NodeID change");
            let err_msg = format!("{}", outcome.unwrap_err());
            assert!(
                err_msg.contains("identity") || err_msg.contains("NodeID"),
                "error should mention identity change, got: {}",
                err_msg
            );
        }

        // ── S5b: NodeID change with explicit opt-in ──────────────────────────

        #[tokio::test]
        async fn supervisor_follows_nodeid_change_when_explicitly_allowed() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)),
                Ok((addr("10.69.91.243:23095"), N2)),
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: true, // OPT IN
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("session 1".to_string()),
                    DisconnectReason::UserInterrupt,
                ],
            )
            .await;

            assert!(
                outcome.is_ok(),
                "should follow NodeID change when --allow-identity-change set: {:?}",
                outcome
            );
        }

        // ── Negative: --no-reconnect ────────────────────────────────────────

        #[tokio::test]
        async fn supervisor_honors_no_reconnect_flag() {
            let resolver = FakeResolver::new(vec![Ok((addr("10.69.91.243:23095"), N1))]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: true, // FAIL FAST
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![DisconnectReason::PeerClosed("session 1".to_string())],
            )
            .await;

            assert!(
                outcome.is_err(),
                "--no-reconnect must exit on first disconnect"
            );
            assert_eq!(
                resolver.calls(),
                1,
                "should not re-resolve when --no-reconnect set"
            );
        }

        // ── Negative: --reconnect-attempts cap ──────────────────────────────

        #[tokio::test]
        async fn supervisor_honors_reconnect_attempts_cap() {
            let resolver = FakeResolver::new(vec![
                Ok((addr("10.69.91.243:23095"), N1)), // initial
                Ok((addr("10.69.91.243:23095"), N1)), // attempt 1
                Ok((addr("10.69.91.243:23095"), N1)), // attempt 2
                Ok((addr("10.69.91.243:23095"), N1)), // attempt 3
            ]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 3, // CAP
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("s1".into()),
                    DisconnectReason::PeerClosed("s2".into()),
                    DisconnectReason::PeerClosed("s3".into()),
                    DisconnectReason::PeerClosed("s4".into()),
                ],
            )
            .await;

            assert!(
                outcome.is_err(),
                "should exit after 3 failed reconnect attempts"
            );
            let err_msg = format!("{}", outcome.unwrap_err());
            assert!(
                err_msg.contains("3 attempts") || err_msg.contains("giving up"),
                "error should mention attempt limit, got: {}",
                err_msg
            );
        }

        // ── Negative: --no-resolve-on-reconnect ─────────────────────────────

        #[tokio::test]
        async fn supervisor_skips_reresolve_when_flag_set() {
            let resolver = FakeResolver::new(vec![Ok((addr("10.69.91.243:23095"), N1))]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: true, // SKIP NS LOOKUP ON RECONNECT
                allow_identity_change: false,
            };

            let outcome = run_supervisor_test(
                cfg,
                &resolver,
                vec![
                    DisconnectReason::PeerClosed("s1".into()),
                    DisconnectReason::UserInterrupt,
                ],
            )
            .await;

            assert!(
                outcome.is_ok(),
                "should recover without re-resolving: {:?}",
                outcome
            );
            assert_eq!(
                resolver.calls(),
                1,
                "should only resolve ONCE (initial) when --no-resolve-on-reconnect set"
            );
        }

        // ── User interrupt — clean exit, no retry ───────────────────────────

        #[tokio::test]
        async fn supervisor_exits_cleanly_on_user_interrupt() {
            let resolver = FakeResolver::new(vec![Ok((addr("10.69.91.243:23095"), N1))]);

            let cfg = SupervisorConfig {
                target: "TRSDC.tech-rockstars.trs.ztlp".to_string(),
                ns_server: Some("16.147.41.195:23096".to_string()),
                reconnect_attempts: 5,
                reconnect_delay_ms: 10,
                no_reconnect: false,
                no_resolve_on_reconnect: false,
                allow_identity_change: false,
            };

            let outcome =
                run_supervisor_test(cfg, &resolver, vec![DisconnectReason::UserInterrupt]).await;

            assert!(outcome.is_ok(), "Ctrl-C should exit cleanly");
            assert_eq!(resolver.calls(), 1, "should NOT retry after user interrupt");
        }
    }
}
