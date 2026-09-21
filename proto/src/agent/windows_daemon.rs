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
}
