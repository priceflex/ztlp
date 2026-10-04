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
// Linux system-service token sharing (PR #112 review fix). Pure planners
// compile everywhere; the executor is cfg(target_os = "linux").
pub mod linux_daemon;
pub mod local_tls;
// macOS root-LaunchDaemon planning (pure) + executor. Compiles on every
// platform so the plan/plist tests run in Linux CI; only invoked from
// daemon.rs behind cfg!(target_os = "macos").
#[cfg(unix)]
pub mod macos_daemon;
pub mod proxy;
pub mod renewal;
pub mod session_lock;
pub mod splash;
pub mod splash_gate;
pub mod stream;
pub mod tunnel_pool;
pub mod user_binding;
pub mod vip_pool;
// Windows service-tier locations/planning (pure) + executor. Compiles on
// every platform so the plan/path tests run in Linux CI; only invoked from
// daemon.rs behind cfg(windows) + a real "are we the service" check.
// Phase D plan: docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md
pub mod windows_daemon;
pub mod windows_service_install;

/// Install `ring` as the process-level rustls `CryptoProvider` if none is
/// installed yet. Safe to call any number of times from any host binary.
/// Returns `true` once a provider is in place (either just installed or
/// already present).
pub fn ensure_rustls_crypto_provider() -> bool {
    let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::crypto::CryptoProvider::get_default().is_some()
}

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

    // Bug D (HANDOFF-2026-09-21-session5): both `ring` and `aws-lc-rs` are
    // in the dep tree, so rustls cannot auto-select a process-level
    // CryptoProvider and PANICS the first time local TLS builds a config
    // ("Could not automatically determine the process-level
    // CryptoProvider"). The CLI's `main()` installs ring up front, so a
    // foreground `ztlp agent start` never hit it — but `ztlp-winsvc.exe`
    // has its own `main()` and never did. Caught live 2026-09-28 by the
    // winsvc panic hook, right after post-enroll handover
    // (tls.enabled=true). Installing here covers EVERY host of the shared
    // lifecycle. Idempotent: `Err` just means one is already installed.
    ensure_rustls_crypto_provider();

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
        // D5 live-test fix (2026-09-21): must resolve through
        // `config::ztlp_state_dir()` (ZTLP_HOME-aware, D1), not
        // dirs::home_dir() directly — this is the SAME process that just
        // ran the pre-standby check and (via `ztlp setup`'s subprocess)
        // wrote agent.toml/config.toml under the Windows service's
        // ProgramData state dir. Reproduced live on 10.170.3.207: a fresh
        // enroll wrote everything correctly to
        // C:\ProgramData\ZTLP\.ztlp\{agent,config}.toml, `enroll` reported
        // tls_provisioned: true, standby handed over — and then the
        // service crashed (exit 1067) because THIS code loaded
        // agent.toml/config.toml from LocalSystem's real profile dir
        // instead, where neither file exists.
        let state_dir = config::ztlp_state_dir();
        let agent_path = state_dir.join(".ztlp").join("agent.toml");
        let cli_path = state_dir.join(".ztlp").join("config.toml");
        AgentConfig::load_merged(&agent_path, &cli_path)
    };

    daemon::run_daemon(&config, foreground)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}

#[cfg(test)]
mod crypto_provider_tests {
    /// Bug D regression: the agent lifecycle must leave a process-level
    /// rustls CryptoProvider installed. Without it, the first
    /// `ServerConfig::builder()` in local TLS panics under any host binary
    /// whose own main() didn't install one (the Windows service).
    #[test]
    fn ensure_rustls_crypto_provider_installs_and_is_idempotent() {
        assert!(super::ensure_rustls_crypto_provider());
        assert!(super::ensure_rustls_crypto_provider());
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        // The exact call that panicked live must now succeed.
        let _ = rustls::ServerConfig::builder().with_no_client_auth();
    }
}
