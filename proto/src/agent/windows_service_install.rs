//! Windows Service (SCM) install/uninstall planning — Task B2 of the
//! Windows/Linux desktop parity plan.
//!
//! Mirrors `dns_setup.rs`'s `service_install_target`/`install_service`
//! split: a PURE, unit-testable planner function decides WHAT to install
//! (service name, display name, binary path, start type), and a thin,
//! not-really-testable wrapper actually calls the real `windows-service`
//! crate API. SCM operations aren't easily fakeable, so — same reasoning
//! as `generate_systemd_unit`/`install_service` — only the planner is
//! covered by `cargo test`; the real install/uninstall is proven live on a
//! real Windows box (Task D1).

use std::path::{Path, PathBuf};

/// Service name registered with the SCM. MUST match `ztlp-winsvc.rs`'s
/// `SERVICE_NAME` constant — the CLI installs the entry, the winsvc binary
/// answers to it.
pub const WINDOWS_SERVICE_NAME: &str = "ZtlpAgent";
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = "ZTLP Agent";
pub const WINDOWS_SERVICE_DESCRIPTION: &str =
    "ZTLP Agent — Encrypted Network Overlay background service";

/// What `windows_service_install`/`windows_service_uninstall` will do,
/// computed without touching the SCM (unit-testable on every platform).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceDefinition {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    /// Full path to `ztlp-winsvc.exe` — NOT `ztlp.exe`. The winsvc binary
    /// is the SCM entry point; it calls into the SAME
    /// `ztlp_proto::agent::run_agent_lifecycle` the CLI's `ztlp agent
    /// start` uses (Task B1), but via the `service_dispatcher` FFI shim
    /// the SCM requires, which `ztlp.exe` does not implement.
    pub binary_path: PathBuf,
    /// `AutoStart` — the service must survive reboot/logout with no
    /// desktop GUI ever having run, mirroring the Linux systemd unit's
    /// `WantedBy=multi-user.target` / macOS LaunchDaemon's `RunAtLoad`.
    pub start_on_boot: bool,
    /// No service dependencies today; kept explicit so a future dependency
    /// (e.g. `Tcpip`) is a one-line addition, not a new field.
    pub dependencies: Vec<String>,
}

/// Pure planner: given the winsvc binary's path, what should be registered
/// with the SCM. Sibling of `dns_setup::service_install_target` — the
/// Windows leg of the same "one service per platform" idea.
pub fn windows_service_definition(winsvc_binary: &Path) -> WindowsServiceDefinition {
    WindowsServiceDefinition {
        service_name: WINDOWS_SERVICE_NAME.to_string(),
        display_name: WINDOWS_SERVICE_DISPLAY_NAME.to_string(),
        description: WINDOWS_SERVICE_DESCRIPTION.to_string(),
        binary_path: winsvc_binary.to_path_buf(),
        start_on_boot: true,
        dependencies: Vec::new(),
    }
}

/// Resolve the winsvc binary's expected install path given the `ztlp.exe`
/// binary's own path — they're always shipped side by side in the same
/// install directory (NSIS/MSI bundle), so `ztlp-winsvc.exe` is just
/// `ztlp.exe`'s sibling with a different file name.
pub fn winsvc_sibling_path(ztlp_binary: &Path) -> PathBuf {
    ztlp_binary
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("ztlp-winsvc.exe")
}

/// Register the service with the SCM (real, not unit-tested — see module
/// doc comment). Requires one UAC elevation, same privilege tier as
/// macOS's `SMAppService.daemon().register()` / Linux's `pkexec systemctl
/// enable --now`.
#[cfg(windows)]
pub fn windows_service_install(
    def: &WindowsServiceDefinition,
) -> Result<(), Box<dyn std::error::Error>> {
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_info = ServiceInfo {
        name: std::ffi::OsString::from(&def.service_name),
        display_name: std::ffi::OsString::from(&def.display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if def.start_on_boot {
            ServiceStartType::AutoStart
        } else {
            ServiceStartType::OnDemand
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: def.binary_path.clone(),
        launch_arguments: Vec::new(),
        dependencies: Vec::new(),
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(&def.description)?;
    Ok(())
}

/// Unregister the service from the SCM (real, not unit-tested).
#[cfg(windows)]
pub fn windows_service_uninstall(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        service_name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;

    // Best-effort stop before delete — an already-stopped service returns
    // an error here that we deliberately ignore (delete still proceeds).
    let _ = service.stop();
    service.delete()?;
    Ok(())
}

// ─── Phase D plan D5: post-install ACL + pre-enroll + uninstall cleanup ────

/// The fixed ProgramData root for everything the `ZtlpAgent` service owns
/// (re-exported from `windows_daemon` so the installer and the service
/// share one source of truth for the path — never two separate constants
/// that could drift apart).
pub use crate::agent::windows_daemon::WINDOWS_SYSTEM_CONFIG_DIR;

/// `icacls` argv that grants `Administrators` full control on
/// [`WINDOWS_SYSTEM_CONFIG_DIR`] with inheritance reset (so the grant
/// sticks even if the directory's inherited ACL from
/// `C:\ProgramData` doesn't already include it). Computed as a pure
/// `Vec<Vec<String>>` so the exact argv is unit-testable on Linux; the
/// actual spawn is a thin `#[cfg(windows)]` wrapper below.
///
/// Why this is needed at all (per the Phase D plan, blocker 3): the
/// service runs as `LocalSystem`, but the interactive admin who runs
/// `ztlp install` and later needs to `icacls`-inspect, copy, or remove
/// the token/config files must also be able to — a `LocalSystem`-only ACL
/// would lock the human out of their own box's ZTLP state. `icacls`
/// (not raw `CreateFile`/`SetNamedSecurityInfoW`) is used for the same
/// reason `dns_setup_windows` already uses it: it's the one documented,
/// stable Windows API surface for ad-hoc ACL edits, no FFI needed.
pub fn programdata_acl_grant_commands() -> Vec<Vec<String>> {
    vec![vec![
        "icacls".to_string(),
        WINDOWS_SYSTEM_CONFIG_DIR.to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        "Administrators:(OI)(CI)F".to_string(),
    ]]
}

/// `rmdir`-equivalent argv for removing the whole ProgramData state dir
/// (and only it — never the binary install dir, which is a different
/// location and belongs to the installer/NSIS uninstaller, not to us)
/// during `ztlp uninstall`. Pure, unit-testable.
pub fn programdata_cleanup_commands() -> Vec<Vec<String>> {
    vec![vec![
        "rmdir".to_string(),
        "/s".to_string(),
        "/q".to_string(),
        WINDOWS_SYSTEM_CONFIG_DIR.to_string(),
    ]]
}

/// Actually run the post-install ACL grant. Best-effort: a failure here
/// doesn't fail the install itself (the service is already registered and
/// running correctly at this point) — it's logged and surfaced so the
/// operator can rerun the exact same `icacls` command by hand if needed.
#[cfg(windows)]
pub fn apply_programdata_acl() {
    use tracing::{info, warn};
    if let Err(e) = std::fs::create_dir_all(WINDOWS_SYSTEM_CONFIG_DIR) {
        warn!("D5: failed to create {WINDOWS_SYSTEM_CONFIG_DIR}: {e}");
        return;
    }
    for cmd in programdata_acl_grant_commands() {
        let argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
        match std::process::Command::new(argv[0])
            .args(&argv[1..])
            .output()
        {
            Ok(out) if out.status.success() => {
                info!(
                    "D5: {} ok: {:?}",
                    argv[0],
                    String::from_utf8_lossy(&out.stdout).trim()
                )
            }
            Ok(out) => warn!(
                "D5: {} failed (exit {:?}): {}",
                argv[0],
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => warn!("D5: failed to spawn {}: {e}", argv[0]),
        }
    }
}

/// No-op off Windows — mirrors the rest of this module's `cfg(windows)`
/// gating so the pure planner functions stay callable/testable everywhere.
#[cfg(not(windows))]
pub fn apply_programdata_acl() {}

/// Best-effort removal of the ProgramData state dir during `ztlp
/// uninstall`. Idempotent (missing dir is fine). Never touches the
/// binary install dir.
#[cfg(windows)]
pub fn remove_programdata_dir() {
    use tracing::{info, warn};
    for cmd in programdata_cleanup_commands() {
        let argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
        match std::process::Command::new(argv[0])
            .args(&argv[1..])
            .output()
        {
            Ok(out) if out.status.success() => {
                info!("D5: removed {WINDOWS_SYSTEM_CONFIG_DIR}")
            }
            Ok(out) => warn!(
                "D5: {WINDOWS_SYSTEM_CONFIG_DIR} removal returned exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => warn!(
                "D5: failed to spawn {rmdir} for cleanup: {e}",
                rmdir = argv[0]
            ),
        }
    }
}

/// No-op off Windows.
#[cfg(not(windows))]
pub fn remove_programdata_dir() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_service_definition_has_the_expected_shape() {
        // Use forward slashes: std::path only treats '\' as a separator on
        // the windows target, so a literal backslash path is NOT portable
        // for a test that also runs on this Linux dev box. Path::join
        // behavior itself is what's under test here, not Windows-specific
        // separator parsing (that's exercised for real only by running on
        // an actual Windows box — Task D1).
        let def = windows_service_definition(Path::new("C:/Program Files/ZTLP/ztlp-winsvc.exe"));
        assert_eq!(def.service_name, "ZtlpAgent");
        assert_eq!(def.display_name, "ZTLP Agent");
        assert!(
            def.start_on_boot,
            "must survive reboot with no GUI ever run"
        );
        assert!(def.dependencies.is_empty());
        assert_eq!(
            def.binary_path,
            PathBuf::from("C:/Program Files/ZTLP/ztlp-winsvc.exe")
        );
    }

    #[test]
    fn winsvc_sibling_path_lives_next_to_the_cli_binary() {
        let ztlp = Path::new("C:/Program Files/ZTLP/ztlp.exe");
        assert_eq!(
            winsvc_sibling_path(ztlp),
            PathBuf::from("C:/Program Files/ZTLP/ztlp-winsvc.exe")
        );
    }

    #[test]
    fn winsvc_sibling_path_falls_back_to_cwd_when_no_parent() {
        // Path::new("ztlp.exe").parent() is Some("") (not None) for a bare
        // filename with no directory component, so the join produces a
        // bare relative name here, not a "./"-prefixed one.
        let ztlp = Path::new("ztlp.exe");
        assert_eq!(winsvc_sibling_path(ztlp), PathBuf::from("ztlp-winsvc.exe"));
    }

    // ── D5 (Phase D plan): post-install ACL + uninstall cleanup ──────────

    #[test]
    fn programdata_acl_grant_targets_programdata_ztlp_and_grants_administrators_full() {
        let cmds = programdata_acl_grant_commands();
        assert_eq!(cmds.len(), 1, "exactly one icacls invocation");
        let cmd = &cmds[0];
        assert_eq!(cmd[0], "icacls");
        assert_eq!(cmd[1], WINDOWS_SYSTEM_CONFIG_DIR);
        // Inheritance must be reset before the grant, or the grant could
        // be shadowed by an inherited ACE from C:\ProgramData.
        assert!(cmd.contains(&"/inheritance:r".to_string()));
        assert!(cmd.contains(&"/grant:r".to_string()));
        // (OI)(CI) = Object Inherit + Container Inherit — the grant must
        // propagate to files and subdirectories created later, not just
        // the top-level dir.
        assert!(cmd.contains(&"Administrators:(OI)(CI)F".to_string()));
    }

    #[test]
    fn programdata_cleanup_targets_programdata_ztlp_and_only_it() {
        let cmds = programdata_cleanup_commands();
        assert_eq!(cmds.len(), 1, "exactly one rmdir invocation");
        let cmd = &cmds[0];
        assert_eq!(cmd[0], "rmdir");
        assert!(cmd.contains(&"/s".to_string()), "recursive");
        assert!(cmd.contains(&"/q".to_string()), "quiet, no prompts");
        assert_eq!(cmd[cmd.len() - 1], WINDOWS_SYSTEM_CONFIG_DIR);
        // Explicit regression guard: the binary install dir (a completely
        // different path, e.g. C:\Program Files\ZTLP) must never appear
        // in a cleanup argv — deleting the binary install dir is the
        // NSIS/MSI uninstaller's job, not this one.
        assert!(
            !cmd.iter().any(|arg| arg.contains("Program Files")),
            "cleanup must never touch the binary install dir"
        );
    }
}
