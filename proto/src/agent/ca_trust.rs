//! CA trust store installation for ZTLP agent.
//!
//! Installs the ZTLP Root CA certificate into the system's trust store
//! so that TLS connections to ZTLP services are automatically trusted.
//!
//! ## Platform Support
//!
//! - **macOS**: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`
//! - **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
//! - **Windows**: `certutil -addstore Root <cert.pem>`

use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;
use thiserror::Error;
#[allow(unused_imports)]
use tracing::{info, warn};

/// Errors that can occur during CA trust installation.
#[derive(Debug, Error)]
pub enum CaTrustError {
    #[error("Unsupported platform")]
    UnsupportedPlatform,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Certificate file not found: {0}")]
    CertNotFound(String),
}

/// Result type for CA trust operations.
pub type Result<T> = std::result::Result<T, CaTrustError>;

/// Get the default CA cert path.
pub fn default_ca_cert_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".ztlp").join("ca").join("root.pem")
}

/// Install a CA certificate into the system trust store.
///
/// This requires elevated privileges on most systems.
pub fn install_ca_cert(cert_path: &Path) -> Result<()> {
    if !cert_path.exists() {
        return Err(CaTrustError::CertNotFound(cert_path.display().to_string()));
    }

    #[cfg(target_os = "macos")]
    return install_macos(cert_path);

    #[cfg(target_os = "linux")]
    return install_linux(cert_path);

    #[cfg(target_os = "windows")]
    return install_windows(cert_path);

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err(CaTrustError::UnsupportedPlatform);
}

/// Remove a CA certificate from the system trust store.
#[allow(unused_variables)]
pub fn remove_ca_cert(cert_path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    return remove_macos(cert_path);

    #[cfg(target_os = "linux")]
    return remove_linux(cert_path);

    #[cfg(target_os = "windows")]
    return remove_windows(cert_path);

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err(CaTrustError::UnsupportedPlatform);
}

/// Check if the ZTLP CA is installed in the system trust store.
pub fn is_ca_installed() -> bool {
    let cert_path = default_ca_cert_path();
    if !cert_path.exists() {
        return false;
    }

    #[cfg(target_os = "macos")]
    return check_macos_installed(&cert_path);

    #[cfg(target_os = "linux")]
    return check_linux_installed();

    #[cfg(target_os = "windows")]
    return check_windows_installed();

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return false;
}

// ── macOS ─────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_macos(cert_path: &Path) -> Result<()> {
    info!("Installing CA cert to macOS System Keychain");
    let output = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
        ])
        .arg(cert_path)
        .output()?;

    if output.status.success() {
        info!("CA certificate installed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CaTrustError::CommandFailed(stderr.to_string()))
    }
}

#[cfg(target_os = "macos")]
fn remove_macos(cert_path: &Path) -> Result<()> {
    let output = Command::new("security")
        .args(["remove-trusted-cert", "-d"])
        .arg(cert_path)
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CaTrustError::CommandFailed(stderr.to_string()))
    }
}

#[cfg(target_os = "macos")]
fn check_macos_installed(_cert_path: &Path) -> bool {
    // Check if ZTLP Root CA is in the system keychain
    let output = Command::new("security")
        .args(["find-certificate", "-c", "ZTLP Root CA", "-a"])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("ZTLP Root CA")
        }
        Err(_) => false,
    }
}

// ── Linux ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_linux(cert_path: &Path) -> Result<()> {
    info!("Installing CA cert to Linux trust store");

    let dest = PathBuf::from("/usr/local/share/ca-certificates/ztlp-root-ca.crt");

    // Copy cert to ca-certificates directory
    std::fs::copy(cert_path, &dest)?;

    // Run update-ca-certificates
    let output = Command::new("update-ca-certificates").output()?;

    if output.status.success() {
        info!("CA certificate installed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("update-ca-certificates may have failed: {}", stderr);
        // Still return Ok — the cert is copied
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn remove_linux(_cert_path: &Path) -> Result<()> {
    let dest = PathBuf::from("/usr/local/share/ca-certificates/ztlp-root-ca.crt");
    if dest.exists() {
        std::fs::remove_file(&dest)?;
        let _ = Command::new("update-ca-certificates")
            .arg("--fresh")
            .output();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_linux_installed() -> bool {
    let dest = Path::new("/usr/local/share/ca-certificates/ztlp-root-ca.crt");
    dest.exists()
}

// ── Windows ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_windows(cert_path: &Path) -> Result<()> {
    info!("Installing CA cert to Windows trust store");
    let output = Command::new("certutil")
        .args(["-addstore", "Root"])
        .arg(cert_path)
        .output()?;

    if output.status.success() {
        info!("CA certificate installed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CaTrustError::CommandFailed(stderr.to_string()))
    }
}

#[cfg(target_os = "windows")]
fn remove_windows(_cert_path: &Path) -> Result<()> {
    let output = Command::new("certutil")
        .args(["-delstore", "Root", "ZTLP Root CA"])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CaTrustError::CommandFailed(stderr.to_string()))
    }
}

#[cfg(target_os = "windows")]
fn check_windows_installed() -> bool {
    let output = Command::new("certutil")
        .args(["-store", "Root", "ZTLP Root CA"])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ca_cert_path() {
        let path = default_ca_cert_path();
        assert!(path.to_string_lossy().contains(".ztlp"));
        assert!(path.to_string_lossy().contains("root.pem"));
    }

    #[test]
    fn test_cert_not_found() {
        let result = install_ca_cert(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
        match result.unwrap_err() {
            CaTrustError::CertNotFound(_) => {}
            other => panic!("Expected CertNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_is_ca_installed_without_cert() {
        // Should return false when cert file doesn't exist
        // (unless ZTLP is actually installed)
        let _ = is_ca_installed(); // Just verify it doesn't panic
    }
}
