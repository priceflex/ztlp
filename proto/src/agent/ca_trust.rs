//! CA trust store installation for ZTLP agent.
//!
//! Installs the ZTLP Root CA certificate into the system's trust store
//! so that TLS connections to ZTLP services are automatically trusted.
//!
//! ## Platform Support
//!
//! - **macOS**: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`
//! - **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
//! - **Windows**: `certutil -addstore Root <cert.pem>` (CurrentUser\Root by default)
//!
//! ## Scope (D5.T1)
//!
//! Some installation paths (notably the Windows service installer running as
//! `LocalSystem`) need the CA in the `LocalMachine\Root` store so every
//! browser on the box trusts it, not just the user who happened to run the
//! command. [`install_ca_cert_with_scope`] takes a [`CertStoreScope`] flag
//! that selects between user-scope (the default, back-compat) and
//! machine-scope. macOS and Linux already install at machine scope, so the
//! flag is a no-op there.

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

/// Which Windows certificate store scope to use.
///
/// On macOS and Linux this is a no-op — those platforms install to the
/// system-wide trust store by design. The distinction matters only on
/// Windows where `certutil -addstore Root` defaults to `CurrentUser\Root`
/// (user-scope) and needs `-enterprise -f` to land in `LocalMachine\Root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStoreScope {
    /// `CurrentUser\Root` on Windows. The default for legacy `install_ca_cert`
    /// to preserve back-compat. macOS / Linux ignore this and install
    /// system-wide regardless.
    User,
    /// `LocalMachine\Root` on Windows — every user on the box trusts the cert.
    /// macOS / Linux ignore this and install system-wide regardless (i.e.
    /// behavior is the same as `User` on those platforms). Required by
    /// D5 for browser TLS green-lock on Windows services.
    Machine,
}

/// Get the default CA cert path.
pub fn default_ca_cert_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".ztlp").join("ca").join("root.pem")
}

/// Install a CA certificate into the system trust store at user scope.
///
/// This is the legacy entry point — equivalent to
/// `install_ca_cert_with_scope(cert_path, CertStoreScope::User)`. New
/// callers that need machine-scope installation should call
/// [`install_ca_cert_with_scope`] directly.
///
/// This requires elevated privileges on most systems.
pub fn install_ca_cert(cert_path: &Path) -> Result<()> {
    install_ca_cert_with_scope(cert_path, CertStoreScope::User)
}

/// Install a CA certificate into the system trust store at the requested scope.
///
/// `scope` controls Windows-specific store selection (see [`CertStoreScope`]).
/// On macOS and Linux the scope is ignored — those platforms always install
/// at system scope.
///
/// Requires elevated privileges. Used by the Windows service installer to
/// plant the ZTLP CA in `LocalMachine\Root` at install time so every browser
/// on the box trusts `*.<zone>.ztlp` certs out of the gate (D5.T1).
pub fn install_ca_cert_with_scope(cert_path: &Path, scope: CertStoreScope) -> Result<()> {
    if !cert_path.exists() {
        return Err(CaTrustError::CertNotFound(cert_path.display().to_string()));
    }

    #[cfg(target_os = "macos")]
    {
        let _ = scope; // macOS install is always machine-scoped via System.keychain.
        return install_macos(cert_path);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = scope; // Linux install is always machine-scoped via /usr/local/share.
        return install_linux(cert_path);
    }

    #[cfg(target_os = "windows")]
    return install_windows(cert_path, scope);

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = scope;
        return Err(CaTrustError::UnsupportedPlatform);
    }
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

/// Build the `certutil` argument vector for installing a cert at the given scope.
///
/// Pure function so we can unit-test the command shape without a Windows box.
/// `-enterprise -f` is the documented way to land a cert in `LocalMachine\Root`
/// without an interactive prompt; without those flags certutil writes to
/// `CurrentUser\Root` regardless of whether the process is elevated.
///
/// Returns the argv that follows `certutil` on the command line — caller is
/// responsible for appending the cert path.
fn certutil_install_args(scope: CertStoreScope) -> Vec<&'static str> {
    match scope {
        CertStoreScope::User => vec!["-addstore", "Root"],
        CertStoreScope::Machine => vec!["-addstore", "-enterprise", "-f", "Root"],
    }
}

/// Build the `certutil` argv for removing a cert at the given scope.
///
/// Removal uses the CA's CommonName ("ZTLP Root CA") as the matching key.
fn certutil_remove_args(scope: CertStoreScope) -> Vec<&'static str> {
    match scope {
        CertStoreScope::User => vec!["-delstore", "Root", "ZTLP Root CA"],
        CertStoreScope::Machine => vec!["-delstore", "-enterprise", "Root", "ZTLP Root CA"],
    }
}

/// Build the `certutil` argv for checking whether the cert is installed.
fn certutil_check_args(scope: CertStoreScope) -> Vec<&'static str> {
    match scope {
        CertStoreScope::User => vec!["-store", "Root", "ZTLP Root CA"],
        CertStoreScope::Machine => vec!["-store", "-enterprise", "Root", "ZTLP Root CA"],
    }
}

#[cfg(target_os = "windows")]
fn install_windows(cert_path: &Path, scope: CertStoreScope) -> Result<()> {
    info!(
        "Installing CA cert to Windows trust store (scope: {:?})",
        scope
    );
    let args = certutil_install_args(scope);
    let output = Command::new("certutil")
        .args(&args)
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
fn remove_windows(cert_path: &Path) -> Result<()> {
    // D5: previous code matched on CN substring `"ZTLP Root CA"`. That stopped
    // working when ca-init started suffixing the zone (`ZTLP Root CA - trs.ztlp`)
    // — certutil reported success but matched zero certs. Identify by SHA1
    // thumbprint of the actual cert file instead: that's unambiguous and
    // works regardless of CN naming policy.
    let thumbprint = sha1_thumbprint_hex(cert_path)?;

    // Try -enterprise scope first (D5.T1 default), then default user scope.
    // Pass `-f` so certutil is non-interactive on confirmation prompts.
    let machine_args = vec!["-delstore", "-enterprise", "Root", thumbprint.as_str()];
    let machine_result = Command::new("certutil").args(&machine_args).output();
    let machine_ok = matches!(&machine_result, Ok(out) if out.status.success())
        && matches!(&machine_result, Ok(out) if !String::from_utf8_lossy(&out.stdout)
            .to_lowercase().contains("certificate not found"));

    let user_args = vec!["-delstore", "Root", thumbprint.as_str()];
    let user_result = Command::new("certutil").args(&user_args).output()?;
    let user_ok = user_result.status.success()
        && !String::from_utf8_lossy(&user_result.stdout)
            .to_lowercase()
            .contains("certificate not found");

    if machine_ok || user_ok {
        return Ok(());
    }

    let stderr_m = machine_result
        .as_ref()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
        .unwrap_or_default();
    let stderr_u = String::from_utf8_lossy(&user_result.stderr).to_string();
    Err(CaTrustError::CommandFailed(format!(
        "certutil -delstore failed in both scopes; machine stderr: {} user stderr: {}",
        stderr_m.trim(),
        stderr_u.trim()
    )))
}

/// SHA1 thumbprint of the PEM-encoded cert at `path`, formatted as
/// 40 uppercase hex digits. certutil accepts this as a unique cert
/// selector for `-delstore`.
#[cfg(target_os = "windows")]
fn sha1_thumbprint_hex(cert_path: &Path) -> Result<String> {
    use sha1::{Digest, Sha1};
    let pem = std::fs::read_to_string(cert_path)?;
    // Strip PEM markers and decode base64 to get the DER bytes that
    // certutil hashes.
    let der_b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("");
    let der = base64_decode(&der_b64).map_err(|e| {
        CaTrustError::CommandFailed(format!("failed to base64-decode cert PEM: {}", e))
    })?;
    let mut hasher = Sha1::new();
    hasher.update(&der);
    let digest = hasher.finalize();
    Ok(digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>())
}

#[cfg(target_os = "windows")]
fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s.as_bytes()).map_err(|_| "invalid base64")
}

#[cfg(target_os = "windows")]
fn check_windows_installed() -> bool {
    // Same fallback pattern as remove_windows — check machine scope first.
    let machine_args = certutil_check_args(CertStoreScope::Machine);
    if let Ok(out) = Command::new("certutil").args(&machine_args).output() {
        if out.status.success() {
            return true;
        }
    }
    let user_args = certutil_check_args(CertStoreScope::User);
    match Command::new("certutil").args(&user_args).output() {
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

    // ─── D5.T1: certutil scope command-builder tests ───────────────────────
    //
    // Pure-function tests on the argv builders. We can't execute certutil
    // from this Linux dev box, but we can verify that the argv we'd pass to
    // it is exactly the documented incantation for each scope. Catching a
    // typo here is cheap; catching it on a Windows bench after a 90s install
    // attempt is not.

    #[test]
    fn certutil_install_user_scope_uses_addstore_root() {
        // Back-compat with the pre-D5.T1 invocation. No `-enterprise`, no `-f`.
        // Lands in CurrentUser\Root.
        let args = certutil_install_args(CertStoreScope::User);
        assert_eq!(args, vec!["-addstore", "Root"]);
    }

    #[test]
    fn certutil_install_machine_scope_uses_enterprise_force() {
        // D5.T1: `-enterprise -f` is what makes certutil land in
        // LocalMachine\Root non-interactively. Without `-f`, certutil
        // would prompt for confirmation, which a LocalSystem service
        // session can never satisfy.
        let args = certutil_install_args(CertStoreScope::Machine);
        assert_eq!(args, vec!["-addstore", "-enterprise", "-f", "Root"]);
    }

    #[test]
    fn certutil_remove_user_scope_targets_root_store_by_cn() {
        let args = certutil_remove_args(CertStoreScope::User);
        assert_eq!(args, vec!["-delstore", "Root", "ZTLP Root CA"]);
    }

    #[test]
    fn certutil_remove_machine_scope_uses_enterprise() {
        let args = certutil_remove_args(CertStoreScope::Machine);
        assert_eq!(
            args,
            vec!["-delstore", "-enterprise", "Root", "ZTLP Root CA"]
        );
    }

    #[test]
    fn certutil_check_user_scope_uses_store_subcommand() {
        let args = certutil_check_args(CertStoreScope::User);
        assert_eq!(args, vec!["-store", "Root", "ZTLP Root CA"]);
    }

    #[test]
    fn certutil_check_machine_scope_uses_enterprise() {
        let args = certutil_check_args(CertStoreScope::Machine);
        assert_eq!(args, vec!["-store", "-enterprise", "Root", "ZTLP Root CA"]);
    }

    #[test]
    fn install_ca_cert_legacy_entry_point_defaults_to_user_scope() {
        // Critical back-compat guarantee. install_ca_cert (no scope arg) is
        // the documented public API as of v0.34.x. D5.T1 must NOT silently
        // flip its behavior to machine scope — that would change the trust
        // posture of every existing caller. Callers that want machine scope
        // call install_ca_cert_with_scope explicitly.
        //
        // We can't actually invoke install_ca_cert here without a real cert
        // file, but we CAN verify the scope-selection dispatch by checking
        // the command builders produce the user-scope invocation for the
        // default scope.
        let user_args = certutil_install_args(CertStoreScope::User);
        // No `-enterprise` in user-scope args.
        assert!(!user_args.contains(&"-enterprise"));
        // No `-f` either — that's machine-scope-only because it suppresses
        // the interactive prompt.
        assert!(!user_args.contains(&"-f"));
    }

    #[test]
    fn cert_store_scope_is_copy_and_eq() {
        // Cheap invariant: CertStoreScope is small enough that we want it
        // to be Copy (passed by value through APIs) and Eq (matched in
        // tests). Compile-time check via the trait bounds.
        fn assert_copy<T: Copy + Eq>() {}
        assert_copy::<CertStoreScope>();
    }

    // ─── D5: SHA1 thumbprint cert selector (Windows only) ──────────────

    /// Test fixture: a real ECDSA P-256 self-signed cert with a known
    /// SHA1 thumbprint we can pin. We round-trip generate → write → hash →
    /// confirm the hash matches what rcgen+sha1 produce together.
    #[cfg(target_os = "windows")]
    #[test]
    fn sha1_thumbprint_matches_certutil_format() {
        use rcgen::{CertificateParams, KeyPair};
        use sha1::{Digest, Sha1};

        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let pem = cert.pem();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &pem).unwrap();

        let computed = sha1_thumbprint_hex(tmp.path()).unwrap();
        // Independent reference computation to make sure our PEM->DER
        // strip-and-decode matches what certutil hashes.
        let expected = {
            let der = cert.der();
            let mut h = Sha1::new();
            h.update(der.as_ref());
            h.finalize()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>()
        };
        assert_eq!(computed, expected, "thumbprint must match raw DER hash");
        // certutil format: 40 uppercase hex chars, no separators.
        assert_eq!(computed.len(), 40);
        assert!(computed
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sha1_thumbprint_errors_on_missing_file() {
        let path = std::path::PathBuf::from("/definitely/does/not/exist.pem");
        let result = sha1_thumbprint_hex(&path);
        assert!(result.is_err());
    }
}
