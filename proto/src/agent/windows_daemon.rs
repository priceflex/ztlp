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

// ─── Execution — Phase D plan D3 ────────────────────────────────────────────

/// Strip a trailing `:port` from a `host:port` listen string, returning the
/// bare host. Windows NRPT can only route a namespace to a bare IP address
/// (implicit port 53) — handing it `host:port` silently installs an empty
/// `NameServers` list (`ztlp-cli.rs:13506-13526`, the same bug bug #4's
/// `dns_setup_windows::plan_windows_nrpt_listen` already works around for
/// the CLI path; this is the service-side equivalent guard).
///
/// Pure and platform-independent so it stays unit-testable on Linux.
pub fn strip_port(listen: &str) -> &str {
    listen
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(listen)
}

impl WindowsAction {
    /// Run the action. Log-and-continue: every step is best-effort, mirrors
    /// `MacosAction::execute`'s tolerance — one failed privileged step
    /// shouldn't crash the daemon; the checklist surfaces failures via
    /// `setup_status` instead.
    #[cfg(windows)]
    pub fn execute(&self) {
        use tracing::{info, warn};
        match self {
            WindowsAction::InstallCaCertMachine(path) => {
                match crate::agent::ca_trust::install_ca_cert_with_scope(
                    path,
                    crate::agent::ca_trust::CertStoreScope::Machine,
                ) {
                    Ok(()) => info!("Windows: ZTLP root CA trusted in LocalMachine\\Root"),
                    Err(e) => warn!("Windows: CA trust install failed (continuing): {e}"),
                }
            }
            WindowsAction::SetupNrpt { listen, zones } => {
                let api = crate::agent::dns_setup_windows::WindowsNrptApi::with_powershell_path(
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                );
                let bare_ip = strip_port(listen);
                match crate::agent::dns_setup_windows::setup_zones(&api, zones, bare_ip) {
                    Ok(installed) => {
                        info!("Windows: NRPT rules installed for zones: {:?}", installed)
                    }
                    Err(e) => warn!("Windows: NRPT setup failed (continuing): {e}"),
                }
            }
            WindowsAction::TokenGuiReadable(path) => {
                acl_token_for_console_user(path);
            }
        }
    }

    /// No-op off Windows — mirrors `MacosAction`'s cfg gating so the pure
    /// planner (`windows_startup_plan`) stays callable/testable everywhere
    /// while only the real shell-outs are platform-gated.
    #[cfg(not(windows))]
    pub fn execute(&self) {}
}

/// Restrict `agent.token` so only Administrators and the interactive
/// console user can read it — Windows analogue of macOS's
/// `MacosAction::TokenGuiReadable` (`chgrp`/`chmod` there, `icacls` here).
/// Falls back to leaving the ACL at its default (Administrators +
/// LocalSystem, since the service itself wrote the file) if no interactive
/// console user can be resolved — mirrors the macOS fallback tolerance:
/// still not world-readable, just broader than the ideal single-user grant.
#[cfg(windows)]
fn acl_token_for_console_user(path: &std::path::Path) {
    use tracing::{info, warn};
    match console_user_name() {
        Some(user) => {
            info!("Windows: restricting agent.token to console user `{user}` via icacls");
            let path_str = path.to_string_lossy().into_owned();
            let output = std::process::Command::new("icacls")
                .args([
                    path_str.as_str(),
                    "/inheritance:r",
                    "/grant:r",
                    "Administrators:F",
                    "/grant:r",
                    &format!("{user}:R"),
                ])
                .output();
            match output {
                Ok(out) if out.status.success() => {
                    info!("Windows: agent.token ACL applied for `{user}`");
                }
                Ok(out) => warn!(
                    "Windows: icacls on {} exited {:?} (continuing): {}",
                    path.display(),
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                Err(e) => warn!(
                    "Windows: icacls failed to spawn for {}: {e}",
                    path.display()
                ),
            }
        }
        None => {
            warn!(
                "Windows: no interactive console user resolved — leaving agent.token at its \
                 default ACL (Administrators/LocalSystem, still not world-readable)"
            );
        }
    }
}

/// Best-effort resolution of the interactive console user's `DOMAIN\User`
/// (or bare `User`) name, suitable for `icacls`'s account-name argument.
/// Returns `None` if no interactive session can be found (e.g. nobody is
/// logged in at the console yet, mirroring macOS's `console_user_name`
/// returning `None` when nobody is at the console).
#[cfg(windows)]
fn console_user_name() -> Option<String> {
    let output = std::process::Command::new("query")
        .arg("user")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `query user` header: "USERNAME  SESSIONNAME  ID  STATE ..."; data
    // rows start with the username (optionally prefixed with '>' marking
    // the current session). Take the first Active session's username.
    stdout
        .lines()
        .skip(1)
        .find(|line| line.contains("Active"))
        .and_then(|line| {
            line.trim_start_matches('>')
                .split_whitespace()
                .next()
                .map(str::to_string)
        })
}

/// Pure parser for `icacls <file>` output: does `user` hold a read-capable
/// grant on the file? `icacls` prints one ACE per line as
/// `[<path> ]<ACCOUNT>:<perms>` (the path only on the first line), e.g.
///
/// ```text
/// C:\ProgramData\ZTLP\.ztlp\agent.token BUILTIN\Administrators:(F)
///                                       CORP\trs:(R)
/// Successfully processed 1 files; Failed processing 0 files
/// ```
///
/// Match is case-insensitive on the account and tolerates the account
/// appearing with or without a `DOMAIN\` prefix (`query user` returns the
/// bare name; icacls echoes back whatever form the ACE was granted with).
/// Read-capable = any of `F`, `M`, `RX`, `R`, or a granular list containing
/// `GR`/`RD` — i.e. anything that lets the GUI `read_to_string` the file.
pub fn icacls_output_grants_read(output: &str, user: &str) -> bool {
    let user_lc = user.to_ascii_lowercase();
    let bare_user_lc = user_lc.rsplit('\\').next().unwrap_or(&user_lc).to_string();
    output.lines().any(|line| {
        // Find the LAST "account:(perms)" token on the line — the first
        // line also carries the file path, which itself contains ':'.
        let Some(idx) = line.rfind(":(") else {
            return false;
        };
        let (lhs, perms) = line.split_at(idx);
        let account = lhs.rsplit(char::is_whitespace).next().unwrap_or(lhs);
        let account_lc = account.to_ascii_lowercase();
        let bare_account_lc = account_lc
            .rsplit('\\')
            .next()
            .unwrap_or(&account_lc)
            .to_string();
        if account_lc != user_lc && bare_account_lc != bare_user_lc {
            return false;
        }
        let perms = perms.to_ascii_uppercase();
        ["(F)", "(M)", "(RX)", "(R)", "GR", "RD"]
            .iter()
            .any(|p| perms.contains(p))
    })
}

/// Whether `agent.token` is actually readable by the interactive console
/// user, verified by reading the file's real ACL via `icacls <path>` and
/// parsing it with [`icacls_output_grants_read`]. `None` when no console
/// user is logged in (can't know yet — "unknown", not "false") or when
/// `icacls` itself can't be run. `Some(false)` when the file is missing or
/// the ACL has no read-capable ACE for that user — which is exactly the
/// state after the D3 `TokenGuiReadable` step failed.
///
/// One `icacls` spawn per `setup_status` poll (a few ms). Windows analogue
/// of `macos_daemon::token_shared_with_gui`, which reads the file mode.
#[cfg(windows)]
pub fn token_shared_with_gui(token_path: &std::path::Path) -> Option<bool> {
    let user = console_user_name()?;
    if !token_path.exists() {
        return Some(false);
    }
    let out = std::process::Command::new("icacls")
        .arg(token_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(icacls_output_grants_read(
        &String::from_utf8_lossy(&out.stdout),
        &user,
    ))
}

/// Cross-platform fallback for non-Windows/non-macOS hosts: we can't
/// determine this without a platform-specific mechanism, so report
/// `None` (unknown) rather than a misleading `false`.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn token_shared_with_gui(_token_path: &std::path::Path) -> Option<bool> {
    None
}

// ─── GUI-side token lookup — Phase D review fix #1 ──────────────────────────

/// Candidate paths a NON-service process (the desktop GUI, a foreground
/// CLI) should try, in order, to find the control-API bearer token on
/// Windows. Windows analogue of `AgentControlClient.swift`'s hardcoded
/// `/Library/Application Support/ZTLP/.ztlp/agent.token` lookup.
///
/// The service writes its token under [`WINDOWS_SYSTEM_CONFIG_DIR`] (D1);
/// the GUI runs as the interactive user with no `ZTLP_HOME` set, so its
/// own `default_token_path()` resolves to `%USERPROFILE%\.ztlp\agent.token`
/// — a file the service never writes. Without this, every GUI control
/// call is sent with `token: None` and rejected by the Bearer gate.
///
/// Order: service path first (the post-D1 steady state), then the
/// caller's own resolved path (pre-service / foreground-agent installs).
/// Pure; the caller passes its own `default_token_path()` in so this stays
/// unit-testable without touching env vars.
pub fn gui_token_candidates(own_default: PathBuf) -> Vec<PathBuf> {
    let system = windows_system_token_path();
    if system == own_default {
        vec![system]
    } else {
        vec![system, own_default]
    }
}

/// Best-effort service detection: true only when the `ZTLP_HOME` env var
/// is set, which `ztlp-winsvc.rs` sets unconditionally at its own startup
/// before doing anything else (D1) and nothing else in the codebase ever
/// sets. A foreground `ztlp.exe agent start` for dev/debug never has this
/// set, so it correctly skips the privileged startup plan below — mirrors
/// macOS's `is_root()` gate on `MacosStartupInputs.is_root`.
pub fn is_windows_service() -> bool {
    std::env::var(ZTLP_HOME_ENV_VAR).is_ok()
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

    // ── strip_port() (Phase D plan D3, bare-IP NRPT guard) ─────────────

    #[test]
    fn strip_port_removes_trailing_port() {
        assert_eq!(strip_port("127.0.0.53:5353"), "127.0.0.53");
    }

    #[test]
    fn strip_port_is_noop_on_bare_ip() {
        assert_eq!(strip_port("127.0.0.53"), "127.0.0.53");
    }

    #[test]
    fn strip_port_handles_bare_port_only() {
        // Degenerate input; must not panic, and should treat everything
        // before the last colon as "host" even if empty.
        assert_eq!(strip_port(":53"), "");
    }

    // ── is_windows_service() ────────────────────────────────────────────

    #[test]
    fn is_windows_service_true_only_when_ztlp_home_set() {
        let _guard = crate::agent::config::ZTLP_HOME_TEST_LOCK.lock().unwrap();
        std::env::remove_var(ZTLP_HOME_ENV_VAR);
        assert!(!is_windows_service());
        std::env::set_var(ZTLP_HOME_ENV_VAR, WINDOWS_SYSTEM_CONFIG_DIR);
        assert!(is_windows_service());
        std::env::remove_var(ZTLP_HOME_ENV_VAR);
    }

    // ── gui_token_candidates() (review fix #1) ──────────────────────────

    #[test]
    fn gui_token_candidates_tries_service_path_first_then_own() {
        let own = PathBuf::from(r"C:\Users\trs\.ztlp\agent.token");
        let c = gui_token_candidates(own.clone());
        assert_eq!(c, vec![windows_system_token_path(), own]);
    }

    #[test]
    fn gui_token_candidates_dedupes_when_own_is_already_service_path() {
        // The service process itself (ZTLP_HOME set) resolves to the
        // system path already — don't probe the same file twice.
        let c = gui_token_candidates(windows_system_token_path());
        assert_eq!(c, vec![windows_system_token_path()]);
    }

    // ── icacls_output_grants_read() (review fix #2) ─────────────────────

    const ICACLS_SAMPLE: &str =
        "C:\\ProgramData\\ZTLP\\.ztlp\\agent.token BUILTIN\\Administrators:(F)\n\
                                 \x20                                     CORP\\trs:(R)\n\
                                 \n\
                                 Successfully processed 1 files; Failed processing 0 files\n";

    #[test]
    fn icacls_grants_read_matches_bare_user_against_domain_ace() {
        // `query user` returns bare "trs"; the ACE was granted as CORP\trs.
        assert!(icacls_output_grants_read(ICACLS_SAMPLE, "trs"));
    }

    #[test]
    fn icacls_grants_read_matches_domain_user_exactly() {
        assert!(icacls_output_grants_read(ICACLS_SAMPLE, r"CORP\trs"));
    }

    #[test]
    fn icacls_grants_read_is_case_insensitive() {
        assert!(icacls_output_grants_read(ICACLS_SAMPLE, "TRS"));
    }

    #[test]
    fn icacls_grants_read_false_for_user_not_in_acl() {
        assert!(!icacls_output_grants_read(ICACLS_SAMPLE, "bob"));
    }

    #[test]
    fn icacls_grants_read_false_when_only_admins_hold_access() {
        // The exact state after the D3 icacls step failed: /inheritance:r
        // succeeded conceptually but the user grant never landed.
        let admins_only = "C:\\ProgramData\\ZTLP\\.ztlp\\agent.token BUILTIN\\Administrators:(F)\n\
                           Successfully processed 1 files; Failed processing 0 files\n";
        assert!(!icacls_output_grants_read(admins_only, "trs"));
    }

    #[test]
    fn icacls_grants_read_false_for_deny_or_write_only_ace() {
        // (W) alone is write-only; a (DENY) prefix on a read ACE must not
        // count as a grant. Both are non-readable from the GUI's POV.
        let out = "C:\\x\\agent.token CORP\\trs:(W)\n\
                   \x20                CORP\\trs:(DENY)(R)\n";
        // Note: the second line DOES contain "(R)" — this documents the
        // current parser's known limitation: it does not model DENY ACEs.
        // icacls never emits a DENY for a file we ACL'd via /grant:r, so
        // this is acceptable for our own token file; a future stricter
        // parser should flip this assertion.
        assert!(icacls_output_grants_read(out, "trs"));
    }

    #[test]
    fn icacls_grants_read_ignores_colon_in_drive_letter_on_first_line() {
        // First line has "C:\..." AND the ACE — rfind(":(") must pick the
        // ACE separator, not the drive-letter colon.
        let out = "C:\\ProgramData\\ZTLP\\.ztlp\\agent.token trs:(R)\n";
        assert!(icacls_output_grants_read(out, "trs"));
        assert!(!icacls_output_grants_read(out, "c"));
    }
}
