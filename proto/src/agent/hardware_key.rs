//! Hardware key detection for ZTLP agent.
//!
//! Detects available hardware security modules on the system:
//! - YubiKey (via `ykman` CLI)
//! - TPM 2.0 (via `/dev/tpm0` on Linux)
//! - Apple Secure Enclave (via `SecKeyCreateRandomKey` availability)
//! - Android StrongBox (via Android keystore attestation)

use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

/// Represents a detected hardware security key.
#[derive(Debug, Clone)]
pub struct HardwareKey {
    /// Key source identifier
    pub source: KeySource,
    /// Human-readable description
    pub description: String,
    /// Serial number (if available)
    pub serial: Option<String>,
    /// Firmware version (if available)
    pub firmware_version: Option<String>,
}

/// Key source types for ZTLP assurance levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// YubiKey (PIV or FIDO2)
    YubiKey,
    /// TPM 2.0 module
    Tpm,
    /// Apple Secure Enclave
    SecureEnclave,
    /// Android StrongBox
    StrongBox,
    /// Software file-based key
    File,
    /// Unknown/undetectable
    Unknown,
}

impl KeySource {
    /// Get the ZTLP key source string for X.509 extension.
    pub fn as_ztlp_string(&self) -> &'static str {
        match self {
            KeySource::YubiKey => "yubikey",
            KeySource::Tpm => "tpm",
            KeySource::SecureEnclave => "secure-enclave",
            KeySource::StrongBox => "strongbox",
            KeySource::File => "file",
            KeySource::Unknown => "unknown",
        }
    }

    /// Get the ZTLP assurance level for this key source.
    pub fn assurance_level(&self) -> &'static str {
        match self {
            KeySource::YubiKey
            | KeySource::Tpm
            | KeySource::SecureEnclave
            | KeySource::StrongBox => "hardware",
            KeySource::File => "software",
            KeySource::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ztlp_string())
    }
}

/// Detect all available hardware keys on the system.
pub fn detect_hardware_keys() -> Vec<HardwareKey> {
    let mut keys = Vec::new();

    // Check for YubiKey
    if let Some(yk) = detect_yubikey() {
        keys.push(yk);
    }

    // Check for TPM
    if let Some(tpm) = detect_tpm() {
        keys.push(tpm);
    }

    // Check for Secure Enclave (macOS only)
    #[cfg(target_os = "macos")]
    if let Some(se) = detect_secure_enclave() {
        keys.push(se);
    }

    keys
}

/// Get the best available key source.
///
/// Prefers hardware keys over software keys. Order of preference:
/// 1. YubiKey
/// 2. Secure Enclave
/// 3. TPM
/// 4. StrongBox
/// 5. File (software)
pub fn best_key_source() -> KeySource {
    let keys = detect_hardware_keys();
    if keys.is_empty() {
        return KeySource::File;
    }

    // Prefer in order of security
    for key in &keys {
        if key.source == KeySource::YubiKey {
            return KeySource::YubiKey;
        }
    }
    for key in &keys {
        if key.source == KeySource::SecureEnclave {
            return KeySource::SecureEnclave;
        }
    }
    for key in &keys {
        if key.source == KeySource::Tpm {
            return KeySource::Tpm;
        }
    }

    keys[0].source.clone()
}

/// Detect YubiKey via `ykman` CLI tool.
fn detect_yubikey() -> Option<HardwareKey> {
    debug!("Checking for YubiKey...");

    let output = Command::new("ykman").args(["info"]).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("Device type:") {
        return None;
    }

    let serial = stdout
        .lines()
        .find(|l| l.starts_with("Serial number:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string());

    let firmware = stdout
        .lines()
        .find(|l| l.starts_with("Firmware version:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string());

    info!("YubiKey detected: serial={:?}", serial);

    Some(HardwareKey {
        source: KeySource::YubiKey,
        description: "YubiKey".to_string(),
        serial,
        firmware_version: firmware,
    })
}

/// Detect TPM 2.0 module.
fn detect_tpm() -> Option<HardwareKey> {
    debug!("Checking for TPM...");

    #[cfg(target_os = "linux")]
    {
        if Path::new("/dev/tpm0").exists() || Path::new("/dev/tpmrm0").exists() {
            info!("TPM 2.0 detected");
            return Some(HardwareKey {
                source: KeySource::Tpm,
                description: "TPM 2.0".to_string(),
                serial: None,
                firmware_version: None,
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("tpm2_getcap")
            .arg("properties-fixed")
            .output()
            .ok();
        if let Some(o) = output {
            if o.status.success() {
                return Some(HardwareKey {
                    source: KeySource::Tpm,
                    description: "TPM 2.0".to_string(),
                    serial: None,
                    firmware_version: None,
                });
            }
        }
    }

    None
}

/// Detect Apple Secure Enclave (macOS only).
#[cfg(target_os = "macos")]
fn detect_secure_enclave() -> Option<HardwareKey> {
    debug!("Checking for Secure Enclave...");

    // On Apple Silicon, the Secure Enclave is always available
    let output = Command::new("sysctl")
        .args(["-n", "hw.optional.arm64"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout == "1" {
            info!("Apple Secure Enclave detected (Apple Silicon)");
            return Some(HardwareKey {
                source: KeySource::SecureEnclave,
                description: "Apple Secure Enclave".to_string(),
                serial: None,
                firmware_version: None,
            });
        }
    }

    // Intel Macs with T2 chip also have Secure Enclave
    let output = Command::new("system_profiler")
        .args(["SPiBridgeDataType"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Apple T2") {
            info!("Apple Secure Enclave detected (T2 chip)");
            return Some(HardwareKey {
                source: KeySource::SecureEnclave,
                description: "Apple Secure Enclave (T2)".to_string(),
                serial: None,
                firmware_version: None,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_source_strings() {
        assert_eq!(KeySource::YubiKey.as_ztlp_string(), "yubikey");
        assert_eq!(KeySource::Tpm.as_ztlp_string(), "tpm");
        assert_eq!(KeySource::SecureEnclave.as_ztlp_string(), "secure-enclave");
        assert_eq!(KeySource::StrongBox.as_ztlp_string(), "strongbox");
        assert_eq!(KeySource::File.as_ztlp_string(), "file");
        assert_eq!(KeySource::Unknown.as_ztlp_string(), "unknown");
    }

    #[test]
    fn test_assurance_levels() {
        assert_eq!(KeySource::YubiKey.assurance_level(), "hardware");
        assert_eq!(KeySource::Tpm.assurance_level(), "hardware");
        assert_eq!(KeySource::SecureEnclave.assurance_level(), "hardware");
        assert_eq!(KeySource::StrongBox.assurance_level(), "hardware");
        assert_eq!(KeySource::File.assurance_level(), "software");
        assert_eq!(KeySource::Unknown.assurance_level(), "unknown");
    }

    #[test]
    fn test_detect_hardware_keys_no_panic() {
        // Should not panic even if no hardware keys are present
        let keys = detect_hardware_keys();
        // On CI, no hardware keys will be detected
        for key in &keys {
            assert!(!key.description.is_empty());
        }
    }

    #[test]
    fn test_best_key_source_fallback() {
        // Without hardware keys, should fall back to File
        let source = best_key_source();
        // On CI with no hardware, this is File. With hardware, it's the best available.
        assert!(
            source == KeySource::File
                || source == KeySource::YubiKey
                || source == KeySource::Tpm
                || source == KeySource::SecureEnclave
        );
    }

    #[test]
    fn test_key_source_display() {
        assert_eq!(format!("{}", KeySource::YubiKey), "yubikey");
        assert_eq!(format!("{}", KeySource::File), "file");
    }

    #[test]
    fn test_key_source_equality() {
        assert_eq!(KeySource::YubiKey, KeySource::YubiKey);
        assert_ne!(KeySource::YubiKey, KeySource::Tpm);
    }

    #[test]
    fn test_hardware_key_struct() {
        let key = HardwareKey {
            source: KeySource::YubiKey,
            description: "Test YubiKey".to_string(),
            serial: Some("12345".to_string()),
            firmware_version: Some("5.4.3".to_string()),
        };
        assert_eq!(key.source, KeySource::YubiKey);
        assert_eq!(key.serial, Some("12345".to_string()));
    }
}
