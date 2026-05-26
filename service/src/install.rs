//! Service install / uninstall helpers.
//!
//! On Windows these wrap `sc.exe create` / `sc.exe delete` for the
//! `ZtlpAgent` service. On every other platform they return a clean
//! "unsupported on this platform" error so consumers can fail fast without
//! ambiguous panics.

use anyhow::Result;

// Re-export the canonical SERVICE_NAME from the crate root so existing
// `install::SERVICE_NAME` callers keep working while there's exactly one
// definition (in `lib.rs`) shared with the SCM dispatcher in `service.rs`.
pub use crate::SERVICE_NAME;

/// Human-readable display name shown in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "ZTLP Agent";

/// Long-form description shown in services.msc.
pub const SERVICE_DESCRIPTION: &str = "Zero Trust Layer Protocol background agent";

/// Register the ZTLP agent as a Windows service.
///
/// On non-Windows targets this returns Err with a message containing
/// "only supported on Windows" so callers can degrade gracefully.
///
/// Steps (in order):
/// 1. `harden_token_file_acl()` — ensure `C:\ProgramData\ZTLP\agent.token`
///    exists with an ACL granting {SYSTEM:F, BUILTIN\Administrators:R,
///    current-user:R}. This runs FIRST so a failure here means no service
///    ever gets registered.
/// 2. `sc.exe create` — register the service with the SCM.
/// 3. `sc.exe description` — set the friendly description.
///
/// Rollback contract: `sc.exe create` then `sc.exe description` form a
/// two-phase commit. If `create` succeeds but `description` fails, the
/// service would otherwise be left half-configured in the SCM registry,
/// which makes the next `install` call fail with "service already exists".
/// To preserve the installed-state invariant (`install()` either fully
/// registers the service or leaves the SCM untouched), a failed
/// `description` triggers a compensating `sc.exe delete` to roll back the
/// partial registration. If the rollback itself fails, both errors are
/// surfaced via anyhow's context chain.
///
/// Note: the ACL hardening step is NOT rolled back on a later SCM failure.
/// The token file and its ACL are valid independently of service
/// registration, the operation is idempotent, and the daemon (next time
/// it starts) will rotate the token contents anyway.
pub fn install() -> Result<()> {
    install_impl()
}

/// Remove the ZTLP agent Windows service.
///
/// Idempotent on Windows: if the service does not exist (sc.exe exit 1060)
/// this is treated as success. On non-Windows targets returns Err with a
/// message containing "only supported on Windows".
///
/// Does NOT delete the token file or alter its ACL — the file persists
/// across reinstalls so the daemon can rotate the same token rather than
/// invalidating every existing client session on every reinstall.
pub fn uninstall() -> Result<()> {
    uninstall_impl()
}

/// Ensure `C:\ProgramData\ZTLP\agent.token` exists with the hardened ACL
/// that lets the LocalSystem daemon write it and the install-time user
/// (plus Administrators) read it.
///
/// Idempotent: running twice is safe (icacls overwrites the explicit ACEs).
///
/// On non-Windows targets this is a no-op returning `Ok(())`. Rationale:
/// `install()` already bails out with "only supported on Windows" before
/// reaching this step, so the only callers on Linux are tests that want
/// to confirm the function is harmless.
pub fn harden_token_file_acl() -> Result<()> {
    harden_token_file_acl_impl()
}

#[cfg(target_os = "windows")]
fn harden_token_file_acl_impl() -> Result<()> {
    use anyhow::Context;
    use std::fs::OpenOptions;
    use std::path::Path;

    let dir = Path::new(crate::TOKEN_DIR);
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating token directory {}", dir.display()))?;

    let token_path = crate::TOKEN_FILE;
    // Touch the file if it doesn't exist. We deliberately do NOT truncate;
    // the daemon's `ensure_token_file` is the authority on contents.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(token_path)
        .with_context(|| format!("touching token file {token_path}"))?;

    // Identify the currently-logged-on user (the principal running the
    // installer). Prefer environment variables — set by every interactive
    // login — and fall back to `whoami` if either is unset (e.g. weird
    // service-account installer scenarios).
    let current_user =
        resolve_current_user().context("resolving current user for token-file ACL grant")?;

    // 1) Strip inherited ACEs so we start from a known baseline.
    run_icacls(token_path, &["/inheritance:r"]).context("icacls /inheritance:r")?;

    // 2) SYSTEM gets full control (the daemon runs as LocalSystem and
    //    must be able to rotate the token).
    run_icacls(token_path, &["/grant", "SYSTEM:(F)"]).context("icacls grant SYSTEM:F")?;

    // 3) Administrators get read access (operator can audit / recover).
    run_icacls(token_path, &["/grant", r"BUILTIN\Administrators:(R)"])
        .context("icacls grant BUILTIN\\Administrators:R")?;

    // 4) The user who ran the installer gets read access — this is what
    //    lets the Tauri UI (running in that user's session) read the
    //    token and authenticate to the LocalSystem-owned daemon.
    let user_grant = format!("{current_user}:(R)");
    run_icacls(token_path, &["/grant", &user_grant])
        .with_context(|| format!("icacls grant {current_user}:R"))?;

    tracing::info!(
        token_file = token_path,
        user = %current_user,
        "hardened token-file ACL"
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_icacls(path: &str, extra_args: &[&str]) -> Result<()> {
    use anyhow::anyhow;
    use std::process::Command;

    let mut cmd = Command::new("icacls");
    cmd.arg(path);
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd
        .output()
        .map_err(|e| anyhow!("failed to spawn icacls: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(anyhow!(
            "icacls {} {:?} failed (exit {:?}): stdout={} stderr={}",
            path,
            extra_args,
            out.status.code(),
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
}

/// Resolve the install-time user as `DOMAIN\USER` (icacls accepts both
/// DOMAIN\USER and bare USER on a local machine).
///
/// Strategy: try `USERNAME` + `USERDOMAIN` env vars first (set by every
/// interactive Windows login). If either is missing, fall back to
/// `whoami` and trust whatever it returns.
#[cfg(target_os = "windows")]
fn resolve_current_user() -> Result<String> {
    use anyhow::{anyhow, Context};
    use std::process::Command;

    if let (Ok(domain), Ok(user)) = (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        if !domain.is_empty() && !user.is_empty() {
            return Ok(format!("{domain}\\{user}"));
        }
    }

    let out = Command::new("whoami")
        .output()
        .context("failed to spawn whoami for current-user resolution")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "whoami failed (exit {:?}): stderr={}",
            out.status.code(),
            stderr.trim()
        ));
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        return Err(anyhow!("whoami returned empty output"));
    }
    Ok(name)
}

#[cfg(not(target_os = "windows"))]
fn harden_token_file_acl_impl() -> Result<()> {
    // No-op stub. `install()` on non-Windows already bails with
    // "only supported on Windows" before this is reachable from the
    // public install flow; tests rely on this being a safe Ok return.
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_impl() -> Result<()> {
    use anyhow::{anyhow, Context};
    use std::process::Command;

    // Step 1: harden the token-file ACL BEFORE registering the service.
    // If this fails, no service gets registered and the operator sees
    // the icacls error directly.
    harden_token_file_acl().context("hardening token-file ACL before service registration")?;

    let exe = std::env::current_exe().context("locating current executable for service binPath")?;
    // The SCM stores binPath as a single string and later launches it via
    // CreateProcess(NULL, binPath, ...), which tokenizes using Windows'
    // unquoted-path rules. If the exe lives under e.g.
    // `C:\Program Files\ZTLP\ztlp-service.exe` and the path is NOT quoted,
    // the SCM will try `C:\Program.exe` first (the classic "unquoted
    // service path" issue — both a functional break on Program Files
    // installs and a known privilege-escalation surface). Wrap with
    // literal double quotes so the stored value is e.g.
    // `"C:\Program Files\ZTLP\ztlp-service.exe" run`.
    let bin_path = format!("\"{}\" run", exe.display());

    let create = Command::new("sc.exe")
        .args([
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            SERVICE_DISPLAY_NAME,
        ])
        .output()
        .context("failed to spawn sc.exe create")?;

    if !create.status.success() {
        let stderr = String::from_utf8_lossy(&create.stderr);
        let stdout = String::from_utf8_lossy(&create.stdout);
        return Err(anyhow!(
            "sc.exe create {SERVICE_NAME} failed (exit {:?}): stdout={} stderr={}",
            create.status.code(),
            stdout.trim(),
            stderr.trim()
        ));
    }

    let describe = Command::new("sc.exe")
        .args(["description", SERVICE_NAME, SERVICE_DESCRIPTION])
        .output()
        .context("failed to spawn sc.exe description")?;

    if !describe.status.success() {
        let stderr = String::from_utf8_lossy(&describe.stderr);
        let stdout = String::from_utf8_lossy(&describe.stdout);
        let describe_err = anyhow!(
            "sc.exe description {SERVICE_NAME} failed (exit {:?}): stdout={} stderr={}",
            describe.status.code(),
            stdout.trim(),
            stderr.trim()
        );

        // Roll back the partial `sc.exe create` so the host is returned
        // to its pre-install state and a subsequent `install()` call
        // does not collide with a half-configured service registration.
        let rollback = Command::new("sc.exe")
            .args(["delete", SERVICE_NAME])
            .output();
        match rollback {
            Ok(out) if out.status.success() => {
                tracing::warn!(
                    service = SERVICE_NAME,
                    "rolled back partial service registration after sc.exe description failure"
                );
                return Err(
                    describe_err.context("rolled back sc.exe create after description failure")
                );
            }
            Ok(out) => {
                let r_stderr = String::from_utf8_lossy(&out.stderr);
                let r_stdout = String::from_utf8_lossy(&out.stdout);
                return Err(describe_err.context(format!(
                    "rollback sc.exe delete {SERVICE_NAME} also failed (exit {:?}): stdout={} stderr={}",
                    out.status.code(),
                    r_stdout.trim(),
                    r_stderr.trim()
                )));
            }
            Err(e) => {
                return Err(
                    describe_err.context(anyhow!("failed to spawn rollback sc.exe delete: {e}"))
                );
            }
        }
    }

    tracing::info!(service = SERVICE_NAME, "installed Windows service");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_impl() -> Result<()> {
    use anyhow::{anyhow, Context};
    use std::process::Command;

    // Win32 error 1060 = ERROR_SERVICE_DOES_NOT_EXIST. Treat as success for
    // idempotent uninstall flows (re-running uninstall after a fresh box, etc).
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    let output = Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output()
        .context("failed to spawn sc.exe delete")?;

    if output.status.success() {
        tracing::info!(service = SERVICE_NAME, "uninstalled Windows service");
        return Ok(());
    }

    if output.status.code() == Some(ERROR_SERVICE_DOES_NOT_EXIST) {
        tracing::info!(
            service = SERVICE_NAME,
            "service was not installed; treating as success"
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "sc.exe delete {SERVICE_NAME} failed (exit {:?}): stdout={} stderr={}",
        output.status.code(),
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(not(target_os = "windows"))]
fn install_impl() -> Result<()> {
    Err(anyhow::anyhow!(
        "ztlp-service install is only supported on Windows; current target: {}",
        std::env::consts::OS
    ))
}

#[cfg(not(target_os = "windows"))]
fn uninstall_impl() -> Result<()> {
    Err(anyhow::anyhow!(
        "ztlp-service uninstall is only supported on Windows; current target: {}",
        std::env::consts::OS
    ))
}
