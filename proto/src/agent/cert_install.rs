//! Client certificate installation for ZTLP agent.
//!
//! Installs ZTLP client certificates into the browser certificate store
//! for mTLS authentication. Certificates are converted to PKCS#12 format
//! for cross-platform browser compatibility.
//!
//! ## Platform Support
//!
//! - **macOS**: Import to login Keychain via `security import`
//! - **Linux**: Import to NSS database (used by Firefox/Chrome)
//! - **Windows**: Import to Current User cert store via `certutil`

use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::info;

/// Errors that can occur during certificate installation.
#[derive(Debug, Error)]
pub enum CertInstallError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Certificate file not found: {0}")]
    CertNotFound(String),

    #[error("Key file not found: {0}")]
    KeyNotFound(String),

    #[error("PKCS#12 conversion failed: {0}")]
    Pkcs12Failed(String),

    #[error("Unsupported platform")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, CertInstallError>;

/// Client certificate files for installation.
pub struct ClientCertFiles {
    /// PEM-encoded client certificate
    pub cert_pem: PathBuf,
    /// PEM-encoded private key
    pub key_pem: PathBuf,
    /// PEM-encoded CA chain (intermediate + root)
    pub chain_pem: PathBuf,
    /// Friendly name for the certificate (e.g., "ZTLP - steve-laptop")
    pub friendly_name: String,
}

/// Convert PEM cert+key to PKCS#12 format for browser import.
///
/// Uses OpenSSL command-line tool (available on all platforms).
pub fn create_pkcs12(
    cert_pem: &Path,
    key_pem: &Path,
    chain_pem: &Path,
    output: &Path,
    friendly_name: &str,
    password: &str,
) -> Result<()> {
    if !cert_pem.exists() {
        return Err(CertInstallError::CertNotFound(
            cert_pem.display().to_string(),
        ));
    }
    if !key_pem.exists() {
        return Err(CertInstallError::KeyNotFound(key_pem.display().to_string()));
    }

    let mut args = vec!["pkcs12", "-export", "-inkey"];
    let key_str = key_pem.to_string_lossy().to_string();
    let cert_str = cert_pem.to_string_lossy().to_string();
    let out_str = output.to_string_lossy().to_string();

    args.push(&key_str);
    args.push("-in");
    args.push(&cert_str);

    let chain_str = chain_pem.to_string_lossy().to_string();
    if chain_pem.exists() {
        args.push("-certfile");
        args.push(&chain_str);
    }

    args.push("-out");
    args.push(&out_str);
    args.push("-name");
    args.push(friendly_name);
    args.push("-passout");

    let pass_arg = format!("pass:{}", password);
    args.push(&pass_arg);

    let output_result = Command::new("openssl").args(&args).output()?;

    if output_result.status.success() {
        info!("Created PKCS#12 file: {}", output.display());
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output_result.stderr);
        Err(CertInstallError::Pkcs12Failed(stderr.to_string()))
    }
}

/// Install a client certificate into the browser certificate store.
pub fn install_client_cert(files: &ClientCertFiles, password: &str) -> Result<PathBuf> {
    // First, create PKCS#12
    let p12_path = files.cert_pem.with_extension("p12");
    create_pkcs12(
        &files.cert_pem,
        &files.key_pem,
        &files.chain_pem,
        &p12_path,
        &files.friendly_name,
        password,
    )?;

    // Then import to system store
    #[cfg(target_os = "macos")]
    install_macos(&p12_path, password)?;

    #[cfg(target_os = "linux")]
    install_linux(&p12_path, password)?;

    #[cfg(target_os = "windows")]
    install_windows(&p12_path, password)?;

    Ok(p12_path)
}

#[cfg(target_os = "macos")]
fn install_macos(p12_path: &Path, password: &str) -> Result<()> {
    info!("Importing client cert to macOS login Keychain");
    let output = Command::new("security")
        .args(["import"])
        .arg(p12_path)
        .args(["-k", "login.keychain-db", "-P", password, "-A"])
        .output()?;

    if output.status.success() {
        info!("Client certificate imported to login Keychain");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CertInstallError::CommandFailed(stderr.to_string()))
    }
}

#[cfg(target_os = "linux")]
fn install_linux(p12_path: &Path, _password: &str) -> Result<()> {
    info!("Importing client cert to NSS database");

    // Find NSS database
    let nss_db = dirs::home_dir()
        .map(|h| h.join(".pki/nssdb"))
        .unwrap_or_else(|| PathBuf::from(".pki/nssdb"));

    if !nss_db.exists() {
        warn!(
            "NSS database not found at {:?}, skipping browser import",
            nss_db
        );
        return Ok(());
    }

    let db_str = format!("sql:{}", nss_db.display());
    let output = Command::new("pk12util")
        .args(["-i"])
        .arg(p12_path)
        .args(["-d", &db_str])
        .output()?;

    if output.status.success() {
        info!("Client certificate imported to NSS database");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("NSS import may have failed: {}", stderr);
        Ok(()) // Non-fatal
    }
}

#[cfg(target_os = "windows")]
fn install_windows(p12_path: &Path, _password: &str) -> Result<()> {
    info!("Importing client cert to Windows cert store");
    let output = Command::new("certutil")
        .args(["-importpfx", "-user", "-p", "\"\""])
        .arg(p12_path)
        .output()?;

    if output.status.success() {
        info!("Client certificate imported to Windows cert store");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CertInstallError::CommandFailed(stderr.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_cert_not_found() {
        let result = create_pkcs12(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            Path::new("/nonexistent/chain.pem"),
            Path::new("/tmp/test.p12"),
            "test",
            "password",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_key_not_found() {
        // Create a temp cert file but no key file
        let temp_dir = std::env::temp_dir().join("ztlp_cert_test");
        let _ = fs::create_dir_all(&temp_dir);
        let cert_path = temp_dir.join("test_cert.pem");
        fs::write(&cert_path, "fake cert").unwrap();

        let result = create_pkcs12(
            &cert_path,
            Path::new("/nonexistent/key.pem"),
            Path::new("/nonexistent/chain.pem"),
            &temp_dir.join("test.p12"),
            "test",
            "password",
        );
        assert!(result.is_err());

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_client_cert_files_struct() {
        let files = ClientCertFiles {
            cert_pem: PathBuf::from("/tmp/cert.pem"),
            key_pem: PathBuf::from("/tmp/key.pem"),
            chain_pem: PathBuf::from("/tmp/chain.pem"),
            friendly_name: "ZTLP - test".to_string(),
        };
        assert_eq!(files.friendly_name, "ZTLP - test");
    }
}
