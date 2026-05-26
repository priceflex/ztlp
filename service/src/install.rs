//! Service install / uninstall helpers.
//!
//! On Windows these wrap `sc.exe create` / `sc.exe delete` for the
//! `ZtlpAgent` service. On every other platform they return a clean
//! "unsupported on this platform" error so consumers can fail fast without
//! ambiguous panics.

use anyhow::Result;

/// Windows service name registered with the SCM.
pub const SERVICE_NAME: &str = "ZtlpAgent";

/// Human-readable display name shown in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "ZTLP Agent";

/// Long-form description shown in services.msc.
pub const SERVICE_DESCRIPTION: &str = "Zero Trust Layer Protocol background agent";

/// Register the ZTLP agent as a Windows service.
///
/// On non-Windows targets this returns Err with a message containing
/// "only supported on Windows" so callers can degrade gracefully.
///
/// Rollback contract: install() is two SCM calls (`sc.exe create` then
/// `sc.exe description`). If `create` succeeds but `description` fails,
/// the service would otherwise be left half-configured in the SCM
/// registry, which makes the next `install` call fail with
/// "service already exists". To preserve the installed-state invariant
/// (`install()` either fully registers the service or leaves the host
/// untouched), a failed `description` triggers a compensating
/// `sc.exe delete` to roll back the partial registration. If the
/// rollback itself fails, both errors are surfaced via anyhow's context
/// chain.
pub fn install() -> Result<()> {
    install_impl()
}

/// Remove the ZTLP agent Windows service.
///
/// Idempotent on Windows: if the service does not exist (sc.exe exit 1060)
/// this is treated as success. On non-Windows targets returns Err with a
/// message containing "only supported on Windows".
pub fn uninstall() -> Result<()> {
    uninstall_impl()
}

#[cfg(target_os = "windows")]
fn install_impl() -> Result<()> {
    use anyhow::{anyhow, Context};
    use std::process::Command;

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
