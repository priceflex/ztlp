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
    let bin_path = format!("{} run", exe.display());

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
        return Err(anyhow!(
            "sc.exe description {SERVICE_NAME} failed (exit {:?}): stdout={} stderr={}",
            describe.status.code(),
            stdout.trim(),
            stderr.trim()
        ));
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
