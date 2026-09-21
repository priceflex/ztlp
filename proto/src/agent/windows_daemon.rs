//! Windows service-tier support for the ZTLP agent — the Windows analogue
//! of `macos_daemon.rs`. See that file's module doc for the shared design
//! this mirrors: a fixed, service-owned config dir so every `~/.ztlp/...`
//! lookup in the agent lands in the same place regardless of who's asking,
//! with NO code changes at the call sites (Phase D plan,
//! `docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md`, D1).
//!
//! Split the same way as the macOS module:
//! - **pure planning / path math** (this file's "Locations" section, plus
//!   `windows_startup_plan` added in D2) — no I/O, unit-tested on every
//!   platform;
//! - **execution** (`WindowsAction::execute`, added in D3) — shells out to
//!   PowerShell / certutil / icacls; only ever invoked from `daemon.rs`
//!   behind `cfg(windows)` AND a real "are we the service" check.
//!
//! Nothing here is reachable from the macOS LaunchDaemon path or the Linux
//! systemd installer; their behavior is byte-identical to before.

use std::path::PathBuf;

// ─── Locations ──────────────────────────────────────────────────────────────

/// Fixed ProgramData root for everything the `ZtlpAgent` service owns.
/// Windows analogue of macOS's `MACOS_SYSTEM_CONFIG_DIR`
/// (`/Library/Application Support/ZTLP`). LocalSystem's `dirs::home_dir()`
/// resolves to `C:\Windows\System32\config\systemprofile`, not a real user
/// profile — every agent state file must live here instead (blocker 1,
/// Phase D plan D1).
pub const WINDOWS_SYSTEM_CONFIG_DIR: &str = r"C:\ProgramData\ZTLP";

/// `<ProgramData>\.ztlp` — mirrors the `~/.ztlp` layout exactly (agent.toml,
/// identity.json, ca/, agent.token, vip_state.json) so every existing
/// `dirs::home_dir().join(".ztlp")` call site keeps working unchanged once
/// it's routed through [`ztlp_state_dir`] instead.
///
/// Built via string concatenation with an explicit `\`, NOT `Path::join`:
/// this value represents a Windows path but the pure planning code in this
/// module must stay unit-testable on Linux CI, where `Path::join` would use
/// `/` as the host separator and produce a mixed-separator path that's
/// wrong on both platforms.
pub fn windows_system_ztlp_dir() -> PathBuf {
    PathBuf::from(format!(r"{}\.ztlp", WINDOWS_SYSTEM_CONFIG_DIR))
}

/// Where the non-elevated GUI reads the control-API bearer token from.
/// Windows analogue of `macos_system_token_path`.
pub fn windows_system_token_path() -> PathBuf {
    PathBuf::from(format!(
        r"{}\agent.token",
        windows_system_ztlp_dir().display()
    ))
}

/// Env var checked by [`crate::agent::config::ztlp_state_dir`] before
/// falling back to `dirs::home_dir()`. Set unconditionally by
/// `ztlp-winsvc.rs`'s `main()` on Windows so the service process (and only
/// the service process) resolves all state under [`WINDOWS_SYSTEM_CONFIG_DIR`]
/// with no other code changes — the same trick the macOS LaunchDaemon plist
/// achieves by pinning `HOME`.
pub const ZTLP_HOME_ENV_VAR: &str = "ZTLP_HOME";

// ─── Startup plan (pure) — Phase D plan D2 ─────────────────────────────────

/// One privileged, idempotent step of the Windows service startup. Windows
/// analogue of `macos_daemon::MacosAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsAction {
    /// `install_ca_cert_with_scope(path, CertStoreScope::Machine)`
    /// (`ca_trust.rs`, already exists — D3 wires this).
    InstallCaCertMachine(PathBuf),
    /// `dns_setup_windows::setup_zones(api, zones, agent_resolver)`.
    /// `listen` must be the EFFECTIVE bound DNS address (post-fallback);
    /// D3's executor strips the port before calling `setup_zones` — NRPT
    /// silently drops the rule if handed `host:port` instead of a bare IP
    /// (`ztlp-cli.rs:13506-13526`).
    SetupNrpt { listen: String, zones: Vec<String> },
    /// ACL the token file so Administrators + the interactive console user
    /// can read it (via `icacls`, executed in D3). Windows analogue of
    /// `MacosAction::TokenGuiReadable`.
    TokenGuiReadable(PathBuf),
}

/// Everything the planner needs; gathered by `daemon.rs` at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsStartupInputs {
    /// Only the SCM service should run privileged startup steps. A
    /// foreground `ztlp.exe agent start` for dev/debug must NOT touch
    /// `LocalMachine\Root` or NRPT rules without elevation — mirrors
    /// macOS's `is_root` guard on `MacosStartupInputs`.
    pub is_service: bool,
    /// EFFECTIVE DNS listen (post-fallback), e.g. "127.0.0.53:5353".
    pub dns_listen: String,
    pub zones: Vec<String>,
    pub ca_root_pem: PathBuf,
    pub ca_root_pem_exists: bool,
    pub ca_already_trusted: bool,
    pub token_path: PathBuf,
}

/// Compute the ordered list of privileged steps. Empty when not running as
/// the service — a foreground `ztlp.exe agent start` on Windows behaves
/// exactly as before. Mirrors `macos_startup_plan`'s `!i.is_root` guard.
///
/// Order: CA install (if needed) before NRPT setup before the token ACL —
/// matches the macOS plan's ordering rationale (cheapest/most
/// prerequisite-free steps first, token-sharing step last since it depends
/// on nothing else finishing).
pub fn windows_startup_plan(i: &WindowsStartupInputs) -> Vec<WindowsAction> {
    if !i.is_service {
        return Vec::new();
    }
    let mut plan = Vec::new();
    if i.ca_root_pem_exists && !i.ca_already_trusted {
        plan.push(WindowsAction::InstallCaCertMachine(i.ca_root_pem.clone()));
    }
    plan.push(WindowsAction::SetupNrpt {
        listen: i.dns_listen.clone(),
        zones: i.zones.clone(),
    });
    plan.push(WindowsAction::TokenGuiReadable(i.token_path.clone()));
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_system_ztlp_dir_is_programdata_ztlp() {
        assert_eq!(
            windows_system_ztlp_dir(),
            PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp")
        );
    }

    #[test]
    fn windows_system_token_path_is_under_system_dir() {
        assert_eq!(
            windows_system_token_path(),
            PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\agent.token")
        );
    }

    // ── windows_startup_plan() (Phase D plan D2) ───────────────────────

    fn base_inputs() -> WindowsStartupInputs {
        WindowsStartupInputs {
            is_service: true,
            dns_listen: "127.0.0.53:5353".into(),
            zones: vec!["defcon.ztlp".into()],
            ca_root_pem: PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\ca\root.pem"),
            ca_root_pem_exists: true,
            ca_already_trusted: false,
            token_path: PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\agent.token"),
        }
    }

    #[test]
    fn windows_startup_plan_is_empty_when_not_service() {
        let mut i = base_inputs();
        i.is_service = false;
        assert!(windows_startup_plan(&i).is_empty());
    }

    #[test]
    fn windows_startup_plan_installs_ca_when_present_and_untrusted() {
        let i = base_inputs();
        let plan = windows_startup_plan(&i);
        assert!(plan.contains(&WindowsAction::InstallCaCertMachine(i.ca_root_pem.clone())));
    }

    #[test]
    fn windows_startup_plan_skips_ca_install_when_already_trusted() {
        let mut i = base_inputs();
        i.ca_already_trusted = true;
        let plan = windows_startup_plan(&i);
        assert!(
            !plan
                .iter()
                .any(|a| matches!(a, WindowsAction::InstallCaCertMachine(_))),
            "must not re-install a CA that's already trusted"
        );
    }

    #[test]
    fn windows_startup_plan_skips_ca_install_when_cert_does_not_exist_yet() {
        // Mirrors the macOS plan: no cert on disk means ca-init hasn't run
        // yet (e.g. still in unenrolled standby) — nothing to install.
        let mut i = base_inputs();
        i.ca_root_pem_exists = false;
        i.ca_already_trusted = false;
        let plan = windows_startup_plan(&i);
        assert!(!plan
            .iter()
            .any(|a| matches!(a, WindowsAction::InstallCaCertMachine(_))));
    }

    #[test]
    fn windows_startup_plan_always_sets_up_nrpt_when_service() {
        let i = base_inputs();
        let plan = windows_startup_plan(&i);
        assert!(
            plan.iter()
                .any(|a| matches!(a, WindowsAction::SetupNrpt { .. })),
            "NRPT setup must run even when CA install is skipped (already trusted)"
        );
    }

    #[test]
    fn windows_startup_plan_nrpt_carries_effective_listen_and_zones() {
        let i = base_inputs();
        let plan = windows_startup_plan(&i);
        let nrpt = plan
            .iter()
            .find_map(|a| match a {
                WindowsAction::SetupNrpt { listen, zones } => Some((listen.clone(), zones.clone())),
                _ => None,
            })
            .expect("plan must contain a SetupNrpt action");
        assert_eq!(nrpt.0, "127.0.0.53:5353");
        assert_eq!(nrpt.1, vec!["defcon.ztlp".to_string()]);
    }

    #[test]
    fn windows_startup_plan_ends_with_token_gui_readable() {
        let i = base_inputs();
        let plan = windows_startup_plan(&i);
        assert!(
            matches!(plan.last(), Some(WindowsAction::TokenGuiReadable(_))),
            "token ACL must be the last step, mirroring the macOS plan"
        );
    }

    #[test]
    fn windows_startup_plan_is_deterministic_for_same_inputs() {
        let i = base_inputs();
        assert_eq!(windows_startup_plan(&i), windows_startup_plan(&i));
    }
}
