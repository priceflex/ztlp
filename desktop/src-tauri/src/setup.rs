//! Setup-wizard commands (D6).
//!
//! These power the "Setup" screen in the desktop UI. Each command is a
//! `#[tauri::command]` that the JS frontend invokes through
//! `window.__TAURI__.core.invoke('setup_xxx', { ... })`.
//!
//! There are two flavors of work the wizard has to do:
//!
//! 1. **Daemon-mediated reads** (`setup_status`) — read-only filesystem
//!    + cert-store inspection. We ask the running daemon for this so the
//!    UI never has to know paths or platform-specific store names.
//!
//! 2. **Privileged writes** (`setup_install_ca`, `setup_install_dns`)  —
//!    these actually modify the Windows machine trust store / NRPT rules
//!    and require Administrator. We *never* run the desktop app as
//!    admin; instead we shell out to `ztlp.exe` with the appropriate
//!    subcommand via `ShellExecute("runas", ...)` so Windows pops a UAC
//!    prompt. Unix builds just shell out normally and let sudo
//!    askpass / pkexec handle elevation (Linux machines aren't the
//!    primary D6 target — Windows is).
//!
//! 3. **Identity-only initialization** (`setup_run_ca_init`) — runs
//!    `ztlp admin ca-init` to generate the on-disk PEM chain. No
//!    admin needed; the chain lives in `~/.ztlp/ca/`.
//!
//! 4. **Browser smoke test** (`setup_test_browse`) — fires a single HTTPS
//!    GET at a configurable hostname and reports the outcome to the UI
//!    so the user sees "Green Lock" in plain English.

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::ipc;

/// Mirror of `ztlp_proto::agent::control::SetupStatus`, but using
/// plain JSON-friendly shapes so the JS layer can read the fields
/// without depending on proto types.
///
/// We re-declare it here (instead of re-exporting) so the desktop crate
/// stays decoupled from the proto crate's serde wire format. If the
/// underlying SetupStatus shape evolves, this struct is the seam we
/// update.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SetupStatusUi {
    pub identity_present: bool,
    pub identity_enrolled: bool,
    pub ca_initialized: bool,
    pub ca_installed_system_trust: Option<bool>,
    pub dns_configured: Option<bool>,
    pub daemon_running: bool,
    pub zone: String,
    pub ca_root_pem_path: String,
    pub identity_path: String,
}

/// Build a `std::process::Command` for the ztlp binary, hiding the
/// console window on Windows so the user never sees a flash of cmd.exe
/// when the GUI shells out.
fn ztlp_cmd() -> Command {
    #[allow(unused_mut)]
    let mut cmd = if cfg!(target_os = "windows") {
        Command::new("ztlp.exe")
    } else {
        Command::new("ztlp")
    };
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd
}

/// Ask the running daemon for the current wizard status.
///
/// If the daemon isn't running yet we return a default `SetupStatusUi`
/// with `daemon_running: false` so the UI can render a "Start agent"
/// banner instead of an error. This is the only command in this module
/// that's safe to call before anything else — the others assume the
/// daemon is up.
///
/// We retry once on failure: a transient connect hiccup (the daemon busy
/// accepting a tunnel connection) must not permanently flip the wizard to
/// "agent not running" when the daemon is in fact up. A genuinely-down
/// daemon still fails both attempts fast (OS RST) and returns the default.
#[tauri::command]
pub fn setup_status() -> SetupStatusUi {
    for attempt in 0..2 {
        match ipc::ipc_request("setup_status", None) {
            Ok(v) => return serde_json::from_value(v).unwrap_or_default(),
            Err(_) if attempt == 0 => {
                // brief backoff, then retry once
                std::thread::sleep(std::time::Duration::from_millis(150));
                continue;
            }
            Err(_) => {
                return SetupStatusUi {
                    daemon_running: false,
                    ..Default::default()
                }
            }
        }
    }
    // Unreachable (the loop always returns), but keep the compiler happy.
    SetupStatusUi {
        daemon_running: false,
        ..Default::default()
    }
}

/// Run `ztlp admin ca-init` to generate the on-disk CA chain.
///
/// No admin required — writes to `~/.ztlp/ca/`. Idempotent: if the
/// chain already exists, `ca-init` no-ops cleanly. We return the
/// stdout/stderr blob so the UI can show progress text in a collapsible
/// pane.
#[tauri::command]
pub fn setup_run_ca_init(zone: String) -> Result<String, String> {
    if zone.trim().is_empty() {
        return Err("zone is required (enroll first)".into());
    }
    let out = ztlp_cmd()
        .args(["admin", "ca-init", "--zone", zone.trim()])
        .output()
        .map_err(|e| format!("failed to spawn ztlp: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if out.status.success() {
        Ok(format!("{stdout}\n{stderr}"))
    } else {
        Err(format!(
            "ca-init failed (exit {}): {stderr}",
            out.status.code().unwrap_or(-1)
        ))
    }
}

/// Install the root CA into the Windows `LocalMachine\Root` store.
///
/// On Windows this requires Administrator. We use `ShellExecuteExW` with
/// `lpVerb = "runas"` so the OS pops a UAC prompt; the user gets the
/// standard "ZTLP wants to make changes to your computer" dialog. The
/// shell-out is `ztlp.exe agent install-ca-cert --machine-scope`.
///
/// On non-Windows platforms we just shell out without elevation — the
/// underlying `install_ca_cert` in `ca_trust.rs` handles macOS keychain
/// / Linux NSS as the current user.
#[tauri::command]
pub fn setup_install_ca() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        runas_ztlp(&["agent", "install-ca-cert", "--machine-scope"])
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Installing the root CA into the system trust store
        // (/usr/local/share/ca-certificates on Linux, System keychain on
        // macOS) requires root. We elevate via pkexec/sudo — the wizard's
        // equivalent of the Windows UAC prompt.
        //
        // GOTCHA: under `sudo`/`pkexec` the child process's HOME becomes
        // root's, so a bare `ztlp agent install-ca-cert` would look for the
        // cert at /root/.ztlp/ca/root.pem and fail with "root CA cert not
        // found". We sidestep that by resolving the cert path in the
        // *current user's* home FIRST, then passing it explicitly via
        // `--cert` so the elevated process reads the right file regardless
        // of whose HOME it runs under.
        let ca_path = setup_status().ca_root_pem_path;
        if ca_path.is_empty() {
            return Err("could not resolve CA cert path from daemon (run ca-init first)".into());
        }

        let elevator = if which("pkexec") {
            Some("pkexec")
        } else if which("sudo") {
            Some("sudo")
        } else {
            None
        };

        let out = match elevator {
            Some(e) => Command::new(e)
                .args(["ztlp", "agent", "install-ca-cert", "--cert", &ca_path])
                .output(),
            None => ztlp_cmd()
                .args(["agent", "install-ca-cert", "--cert", &ca_path])
                .output(),
        }
        .map_err(|e| format!("failed to spawn ztlp: {e}"))?;

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if out.status.success() {
            Ok(format!("{stdout}\n{stderr}"))
        } else {
            Err(format!("install-ca-cert failed: {stderr}"))
        }
    }
}

/// Install NRPT rules for the device's zone (Windows only).
///
/// Requires Administrator. We elevate via the same `runas` shell-out
/// pattern as `setup_install_ca`. On non-Windows platforms this command
/// returns an explanatory error — system DNS rerouting on macOS/Linux
/// is already handled by the daemon's `dns_setup.rs` and doesn't need
/// a wizard step.
#[tauri::command]
pub fn setup_install_dns(zone: String) -> Result<String, String> {
    let z = zone.trim();
    if z.is_empty() {
        return Err("zone is required (enroll first)".into());
    }
    #[cfg(target_os = "windows")]
    {
        runas_ztlp(&["agent", "dns-setup", "--zone", z])
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On macOS/Linux the daemon's dns_setup.rs handles the actual
        // resolver reconfiguration. It needs root to write into
        // /etc/systemd/resolved.conf.d or /etc/resolver, so we shell out
        // via pkexec/sudo (whichever is available) and let the OS prompt
        // for elevation — the wizard's equivalent of the Windows UAC pop.
        let elevator = if which("pkexec") {
            Some("pkexec")
        } else if which("sudo") {
            Some("sudo")
        } else {
            None
        };

        let ztlp_bin = if cfg!(target_os = "windows") {
            "ztlp.exe"
        } else {
            "ztlp"
        };
        let out = match elevator {
            Some(e) => Command::new(e)
                .args([ztlp_bin, "agent", "dns-setup", "--zones", z])
                .output(),
            None => ztlp_cmd()
                .args(["agent", "dns-setup", "--zones", z])
                .output(),
        }
        .map_err(|err| format!("failed to spawn dns-setup: {err}"))?;

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if out.status.success() {
            Ok(format!("{stdout}\n{stderr}"))
        } else {
            Err(format!(
                "dns-setup failed (exit {}): {stderr}",
                out.status.code().unwrap_or(-1)
            ))
        }
    }
}

/// Return true if `bin` is found on PATH. Small helper so the DNS wizard
/// can pick pkexec (GUI-friendly) over sudo (terminal-only) when elevating.
#[cfg(not(target_os = "windows"))]
fn which(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Smoke-test that a ZTLP hostname loads over HTTPS with the installed CA.
///
/// We do a single GET via `curl --cacert <root.pem> --max-time 10
/// https://<hostname>/` and report the HTTP status code. This is the
/// final "Green Lock" check — if it returns 2xx, the user knows the
/// whole stack (CA trust → NRPT → daemon → tunnel) is working. We use
/// `--cacert` so the test works even if the machine-trust install
/// hasn't propagated to the curl bundle yet — we're testing the cert
/// chain, not the system trust integration (which the UI also reports
/// separately as `ca_installed_system_trust`).
#[tauri::command]
pub fn setup_test_browse(hostname: String) -> Result<String, String> {
    let h = hostname.trim();
    if h.is_empty() {
        return Err("hostname is required".into());
    }

    // Get the CA path from the daemon's setup_status response so the
    // test always uses the right per-zone CA, not a hard-coded path.
    let status = setup_status();
    if status.ca_root_pem_path.is_empty() {
        return Err("could not resolve CA path from daemon".into());
    }

    let url = format!("https://{}/", h);
    let mut cmd = if cfg!(target_os = "windows") {
        Command::new("curl.exe")
    } else {
        Command::new("curl")
    };
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let out = cmd
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--cacert",
            &status.ca_root_pem_path,
            "-o",
            "NUL",
            "-w",
            "%{http_code}",
            &url,
        ])
        .output()
        .map_err(|e| format!("failed to spawn curl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if out.status.success() {
        Ok(format!("HTTP {} from {}", stdout, url))
    } else {
        Err(format!(
            "curl failed (exit {}): stdout=[{}] stderr=[{}]",
            out.status.code().unwrap_or(-1),
            stdout,
            stderr
        ))
    }
}

// ── Identity creation (B: first-run "create identity as admin in the NS") ──
//
// These power the new "Create identity" step in the Setup wizard. From a
// clean machine the user wants: create an admin identity in the NS, bind
// this device to it, and have the app pick it up — so the device gets a
// real identity without needing a pre-issued enrollment token string.
//
// We shell out to `ztlp admin create-user --json` and `ztlp admin
// link-device --json` (both support machine-readable JSON + resolve the NS
// server from `~/.ztlp/agent.toml`, so the GUI never needs to know the NS
// address). No elevation required — creating NS records is a user-scoped
// operation (the NS registration path authenticates by the caller's key).

/// Parsed result of `ztlp admin create-user --json`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateUserResult {
    pub status: String,
    pub name: String,
    pub role: String,
    pub pubkey: String,
    pub key_file: String,
}

/// Parsed result of `ztlp admin link-device --json`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinkDeviceResult {
    pub status: String,
    pub device: String,
    pub owner: String,
}

/// Combined result the UI shows after a first-run identity create.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityCreateResult {
    pub user: CreateUserResult,
    pub device: Option<LinkDeviceResult>,
    /// Human-readable summary the UI can show verbatim.
    pub message: String,
}

fn parse_create_user_json(raw: &str) -> Result<CreateUserResult, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty create-user output".into());
    }
    serde_json::from_str::<CreateUserResult>(raw)
        .map_err(|e| format!("could not parse create-user JSON: {e}"))
}

fn parse_link_device_json(raw: &str) -> Result<LinkDeviceResult, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty link-device output".into());
    }
    serde_json::from_str::<LinkDeviceResult>(raw)
        .map_err(|e| format!("could not parse link-device JSON: {e}"))
}

/// The NS `UserRole` values the CLI accepts (mirrors `role_to_str` in the
/// CLI). The GUI validates against this so a bad role never reaches the CLI.
const VALID_ROLES: [&str; 3] = ["admin", "tech", "user"];

/// Create an identity in the NS (role: admin/tech/user) and, when a
/// `device_name` is given, link the local device to it. This is the
/// "start from scratch" first-run step: no enrollment token string needed.
///
/// `name` is the identity name (e.g. `steve@trs.ztlp`). `role` defaults to
/// `admin` for the first-run case. `device_name` is optional — when empty,
/// only the user identity is created (the device link can be done later).
/// `ns_server` is optional; the CLI resolves it from config when omitted.
#[tauri::command]
pub fn setup_create_identity(
    name: String,
    role: String,
    device_name: String,
    ns_server: String,
) -> Result<IdentityCreateResult, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("identity name is required".into());
    }
    let role = role.trim().to_lowercase();
    if !VALID_ROLES.contains(&role.as_str()) {
        return Err(format!(
            "invalid role '{role}' (use one of admin/tech/user)"
        ));
    }

    // ── Step 1: create the user identity ────────────────────────────────
    let mut cmd = ztlp_cmd();
    cmd.args([
        "admin",
        "create-user",
        name.as_str(),
        "--role",
        role.as_str(),
        "--json",
    ]);
    if !ns_server.trim().is_empty() {
        cmd.args(["--ns-server", ns_server.trim()]);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to spawn ztlp for create-user: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        return Err(format!(
            "create-user failed (exit {}): {stderr}",
            out.status.code().unwrap_or(-1)
        ));
    }
    let user = parse_create_user_json(&stdout)?;

    // ── Step 2: link the device (optional) ──────────────────────────────
    let device = if device_name.trim().is_empty() {
        None
    } else {
        let dev = device_name.trim();
        let mut dcmd = ztlp_cmd();
        dcmd.args([
            "admin",
            "link-device",
            dev,
            "--owner",
            name.as_str(),
            "--json",
        ]);
        if !ns_server.trim().is_empty() {
            dcmd.args(["--ns-server", ns_server.trim()]);
        }
        match dcmd.output() {
            Ok(dout) if dout.status.success() => {
                parse_link_device_json(&String::from_utf8_lossy(&dout.stdout)).ok()
            }
            _ => None,
        }
    };

    let message = match &device {
        Some(d) if d.status == "linked" => {
            format!(
                "✓ identity '{name}' (role {role}) created; device '{dev}' linked.",
                dev = device_name.trim()
            )
        }
        Some(d) => format!(
            "⚠ identity '{name}' (role {role}) created, but device link reported: {}",
            d.status
        ),
        None => format!("✓ identity '{name}' (role {role}) created in the NS."),
    };

    Ok(IdentityCreateResult {
        user,
        device,
        message,
    })
}

/// Windows-only: elevate `ztlp.exe <args>` via ShellExecuteExW("runas").
///
/// Pops a UAC prompt. We don't capture stdout/stderr (ShellExecute
/// doesn't give us those reliably across UAC); instead we re-query the
/// daemon's `setup_status` after the call returns and the UI re-renders
/// the checkmarks based on the new state. That's the right model
/// anyway — the user wants to see "✓ Installed" in the wizard, not a
/// console-style stdout dump.
#[cfg(target_os = "windows")]
fn runas_ztlp(args: &[&str]) -> Result<String, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let exe = wide("ztlp.exe");
    let verb = wide("runas");
    let params = wide(&args.join(" "));

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut std::ffi::c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }

    // SAFETY: ShellExecuteW takes nullable UTF-16 wide-string pointers
    // and returns an HINSTANCE-shaped integer. We pass null for hwnd
    // and lpDirectory (both nullable), and properly NUL-terminated
    // UTF-16 buffers for the rest. Return values > 32 indicate success
    // per MSDN.
    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            1, // SW_SHOWNORMAL
        )
    };
    if rc > 32 {
        Ok(format!("elevated `ztlp {}` (rc={})", args.join(" "), rc))
    } else {
        Err(format!(
            "UAC elevation failed (ShellExecuteW rc={}); user cancelled or admin denied",
            rc
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `setup_status` must NEVER panic and must always return a value the
    /// UI can render — even when the daemon socket is closed. The default
    /// returned should signal `daemon_running: false` so the UI knows to
    /// show the "Start agent" banner.
    #[test]
    fn setup_status_returns_default_when_daemon_unreachable() {
        // The default IPC address is 127.100.255.1:4433, which is not
        // expected to be listening during `cargo test`. We assert that
        // we get the daemon-unreachable default back, not a panic.
        let s = setup_status();
        assert!(
            !s.daemon_running,
            "expected daemon_running=false during unit tests (no daemon listening)"
        );
        assert!(s.zone.is_empty());
    }

    /// `setup_run_ca_init` with an empty zone must error fast, not
    /// shell out to `ztlp.exe`. This is the cheapest input-validation
    /// guard the wizard has.
    #[test]
    fn setup_run_ca_init_rejects_empty_zone() {
        let r = setup_run_ca_init(String::new());
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("zone is required"));

        let r2 = setup_run_ca_init("   \t  ".to_string());
        assert!(r2.is_err());
    }

    /// `setup_install_dns` with empty zone errors fast.
    #[test]
    fn setup_install_dns_rejects_empty_zone() {
        let r = setup_install_dns(String::new());
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("zone is required"));
    }

    /// `setup_test_browse` with empty hostname errors fast (no spawn).
    #[test]
    fn setup_test_browse_rejects_empty_hostname() {
        let r = setup_test_browse(String::new());
        assert!(r.is_err());
    }

    // ── setup_create_identity (B: first-run identity in the NS) ─────────
    //
    // These tests lock the input-validation guards + the JSON parsing of the
    // `ztlp admin create-user --json` / `link-device --json` output. They
    // do NOT shell out (no daemon / NS during `cargo test`), so they exercise
    // the pure logic that the UI depends on.

    /// An empty identity name must be rejected before any spawn.
    #[test]
    fn setup_create_identity_rejects_empty_name() {
        let r = setup_create_identity(
            String::new(),
            "admin".to_string(),
            String::new(),
            String::new(),
        );
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("identity name is required"));
    }

    /// A whitespace-only name must be rejected the same way.
    #[test]
    fn setup_create_identity_rejects_whitespace_name() {
        let r = setup_create_identity(
            "   \t  ".to_string(),
            "admin".to_string(),
            String::new(),
            String::new(),
        );
        assert!(r.is_err());
    }

    /// The `--json` output of `create-user` parses into the result struct
    /// with the expected fields. This is the seam the UI reads, so a
    /// regression in the parser shape shows up here before it reaches the UI.
    #[test]
    fn test_parse_create_user_json() {
        let raw = r#"{"status":"created","name":"steve@trs.ztlp","role":"admin","pubkey":"0a1b","key_file":"/h/.ztlp/users/steve_at_trs.ztlp.json"}"#;
        let parsed = parse_create_user_json(raw).expect("should parse");
        assert_eq!(parsed.status, "created");
        assert_eq!(parsed.name, "steve@trs.ztlp");
        assert_eq!(parsed.role, "admin");
        assert_eq!(parsed.pubkey, "0a1b");
        assert!(parsed.key_file.ends_with("steve_at_trs.ztlp.json"));
    }

    /// A malformed / non-JSON `create-user` output is an error, not a panic.
    #[test]
    fn parse_create_user_json_rejects_garbage() {
        assert!(parse_create_user_json("not json at all").is_err());
        assert!(parse_create_user_json("").is_err());
    }

    /// The `--json` output of `link-device` parses into the result struct.
    #[test]
    fn test_parse_link_device_json() {
        let raw = r#"{"status":"linked","device":"laptop-01.trs.ztlp","owner":"steve@trs.ztlp"}"#;
        let parsed = parse_link_device_json(raw).expect("should parse");
        assert_eq!(parsed.status, "linked");
        assert_eq!(parsed.device, "laptop-01.trs.ztlp");
        assert_eq!(parsed.owner, "steve@trs.ztlp");
    }

    /// Role validation: only admin/tech/user are accepted (mirrors the NS
    /// UserRole). Prevents the UI from passing a garbage role to the CLI.
    #[test]
    fn setup_create_identity_rejects_bad_role() {
        let r = setup_create_identity(
            "steve@trs.ztlp".to_string(),
            "superuser".to_string(),
            String::new(),
            String::new(),
        );
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid role"));
    }
}
