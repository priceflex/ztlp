//! ZTLP Agent — background daemon with DNS resolver, TCP proxy, and SSH integration.
//!
//! The agent makes ZTLP connections seamless and transparent. Instead of
//! manually running `ztlp connect` with IP addresses, users simply use
//! ZTLP names (or custom domain names) as regular hostnames.
//!
//! ## Components
//!
//! - **config** — Agent configuration (TOML)
//! - **domain_map** — Custom domain → ZTLP zone mapping
//! - **proxy** — SSH ProxyCommand (stdin/stdout ↔ ZTLP tunnel)
//! - **vip_pool** — Virtual IP allocator
//! - **dns** — DNS resolver for `*.ztlp` + custom zones
//! - **control** — Unix socket control interface
//! - **daemon** — Agent daemon main loop
//! - **stream** — Stream multiplexing over ZTLP tunnels
//! - **tunnel_pool** — Managed tunnel lifecycle with auto-reconnect

pub mod ca_trust;
pub mod cert_install;
pub mod cert_mint;
pub mod config;
pub mod control;
pub mod daemon;
pub mod discovery;
pub mod dns;
#[cfg(unix)]
pub mod dns_setup;
// dns_setup_windows defines the NrptApi trait + FakeNrptApi used everywhere
// (so the agent crate builds on Linux/macOS CI). The production WindowsNrptApi
// inside it is gated to `cfg(windows)` in D4.T2.
pub mod dns_setup_windows;
pub mod domain_map;
pub mod hardware_key;
pub mod local_tls;
// macOS root-LaunchDaemon planning (pure) + executor. Compiles on every
// platform so the plan/plist tests run in Linux CI; only invoked from
// daemon.rs behind cfg!(target_os = "macos").
#[cfg(unix)]
pub mod macos_daemon;
pub mod proxy;
pub mod renewal;
pub mod session_lock;
pub mod stream;
pub mod tunnel_pool;
pub mod user_binding;
pub mod vip_pool;
pub mod windows_service_install;

/// Shared standby-then-full-daemon startup sequence (Task B1 of the
/// Windows/Linux desktop parity plan,
/// docs/plans/2026-09-21-windows-linux-desktop-parity.md).
///
/// Extracted out of the CLI's `cmd_agent_start` (`ztlp-cli.rs`) so BOTH the
/// CLI's `ztlp agent start` (foreground/background) AND the Windows Service
/// host (`ztlp-winsvc.rs`) can share the exact same B4 unenrolled-standby
/// sequencing instead of the service reimplementing it. Refactor-only —
/// behavior is unchanged from the pre-extraction `cmd_agent_start` body,
/// verified by the existing `unenrolled_standby` test suite in
/// `agent::daemon` still passing unchanged after the extraction.
///
/// Sequence:
/// 1. If already running (PID file), return `Ok(())` immediately (no-op).
/// 2. If `config_path` is `None`, run the B4 unenrolled-standby wait — a
///    fresh service/unit with no `identity.json` answers status/enroll on
///    the control socket instead of exiting 1, and hands over into the
///    same process once enrollment completes (`daemon::run_unenrolled_standby`).
/// 3. Load the config (merged `agent.toml`+`config.toml`, or an explicit
///    path) and run the full daemon loop (`daemon::run_daemon`).
pub async fn run_agent_lifecycle(
    config_path: Option<&std::path::Path>,
    foreground: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use config::AgentConfig;

    // Check if already running.
    if let Some(pid) = daemon::get_agent_pid() {
        tracing::warn!("Agent already running (PID {})", pid);
        return Ok(());
    }

    // B4 (macOS, HANDOFF-2026-09-20; cross-platform since Task A2): a fresh
    // service/unit has no identity yet. Instead of exiting 1 (KeepAlive/SCM
    // crash-loop, GUI can never reach the control socket to deliver
    // `enroll`), wait in UNENROLLED STANDBY serving status/enroll on the
    // control socket. Done HERE, before the config load below, so the
    // agent.toml/config.toml that `ztlp setup` + ca-init just wrote (zone,
    // NS, relay secret, tls=true) are picked up by the very same process —
    // no restart.
    if config_path.is_none() {
        let pre = AgentConfig::load();
        let identity_path = pre.identity_path();
        if daemon::should_enter_unenrolled_standby(&identity_path) {
            let proceed = daemon::run_unenrolled_standby(
                &pre.ipc.listen,
                &identity_path,
                &config::default_token_path(),
                std::time::Duration::from_secs(1),
            )
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
            if !proceed {
                return Ok(());
            }
            tracing::info!("Enrollment detected — starting full agent");
        }
    }

    let config = if let Some(path) = config_path {
        AgentConfig::load_from_path(path)
    } else {
        // v0.36 fix: `agent start` used to read only `~/.ztlp/agent.toml`,
        // a file `ztlp setup` never writes. A freshly-enrolled device's
        // agent silently started against AgentConfig::default()
        // (127.0.0.1:23096, no relay) instead of the zone the operator
        // just joined via `ztlp setup --token ... --yes`. load_merged
        // backfills ns_server/relay/identity from `~/.ztlp/config.toml`
        // (the file `setup` DOES write) whenever agent.toml leaves those
        // fields at their bare default — see agent::config for the full
        // rationale and unit tests.
        let agent_path = dirs::home_dir()
            .map(|h| h.join(".ztlp").join("agent.toml"))
            .unwrap_or_else(|| std::path::PathBuf::from(".ztlp/agent.toml"));
        let cli_path = dirs::home_dir()
            .map(|h| h.join(".ztlp").join("config.toml"))
            .unwrap_or_else(|| std::path::PathBuf::from(".ztlp/config.toml"));
        AgentConfig::load_merged(&agent_path, &cli_path)
    };

    daemon::run_daemon(&config, foreground)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}
