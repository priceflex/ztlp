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
}
