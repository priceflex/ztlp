// proto/src/client_profile.rs
use serde::{Deserialize, Serialize};

/// Client profile sent in the Noise_XX message 3 encrypted payload.
/// The gateway uses this to select per-client congestion control parameters.
///
/// Wire format: CBOR-encoded, typically 15-80 bytes.
/// Backward compatible: gateway treats empty/unparseable payload as Unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// What kind of device this is.
    #[serde(rename = "c")]
    pub client_class: ClientClass,

    /// Network interface type at connection time.
    #[serde(rename = "i")]
    pub interface_type: InterfaceType,

    /// Cellular radio technology (only meaningful when interface_type = Cellular).
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub radio_tech: Option<RadioTech>,

    /// iOS Low Data Mode or equivalent bandwidth constraint.
    #[serde(rename = "l", default)]
    pub is_constrained: bool,

    /// Software identity string (e.g., "ztlp-cli/0.24.0" or "ztlp-ios/0.24.0").
    #[serde(rename = "s")]
    pub software_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ClientClass {
    #[serde(rename = "u")]
    Unknown,
    #[serde(rename = "m")]
    Mobile,
    #[serde(rename = "d")]
    Desktop,
    #[serde(rename = "v")]
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum InterfaceType {
    #[serde(rename = "u")]
    Unknown,
    #[serde(rename = "c")]
    Cellular,
    #[serde(rename = "w")]
    WiFi,
    #[serde(rename = "e")]
    Wired,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RadioTech {
    #[serde(rename = "2")]
    Gen2,       // 2G (GPRS/EDGE)
    #[serde(rename = "3")]
    Gen3,       // 3G (WCDMA/HSPA)
    #[serde(rename = "4")]
    LTE,        // 4G LTE
    #[serde(rename = "5n")]
    NrNsa,      // 5G Non-Standalone
    #[serde(rename = "5s")]
    NrSa,       // 5G Standalone
}

impl ClientProfile {
    /// Serialize to CBOR bytes for inclusion in Noise_XX msg3 payload.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization cannot fail");
        buf
    }

    /// Deserialize from CBOR bytes. Returns None if payload is empty or invalid.
    pub fn from_cbor(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        ciborium::from_reader(data).ok()
    }

    /// Default profile for desktop CLI clients.
    pub fn desktop(software_id: String) -> Self {
        Self {
            client_class: ClientClass::Desktop,
            interface_type: InterfaceType::Unknown,
            radio_tech: None,
            is_constrained: false,
            software_id,
        }
    }

    /// Default profile for iOS clients (interface_type set by caller).
    pub fn mobile(software_id: String, interface_type: InterfaceType) -> Self {
        Self {
            client_class: ClientClass::Mobile,
            interface_type,
            radio_tech: None,
            is_constrained: false,
            software_id,
        }
    }
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            client_class: ClientClass::Unknown,
            interface_type: InterfaceType::Unknown,
            radio_tech: None,
            is_constrained: false,
            software_id: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_roundtrip() {
        let profile = ClientProfile::desktop("ztlp-cli/0.24.0".into());
        let cbor = profile.to_cbor();
        let decoded = ClientProfile::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.client_class, ClientClass::Desktop);
        assert_eq!(decoded.software_id, "ztlp-cli/0.24.0");
    }

    #[test]
    fn test_mobile_cellular_roundtrip() {
        let mut profile = ClientProfile::mobile("ztlp-ios/0.24.0".into(), InterfaceType::Cellular);
        profile.radio_tech = Some(RadioTech::LTE);
        profile.is_constrained = true;
        let cbor = profile.to_cbor();
        assert!(cbor.len() < 80, "CBOR should be compact, got {} bytes", cbor.len());
        let decoded = ClientProfile::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.client_class, ClientClass::Mobile);
        assert_eq!(decoded.interface_type, InterfaceType::Cellular);
        assert_eq!(decoded.radio_tech, Some(RadioTech::LTE));
        assert!(decoded.is_constrained);
    }

    #[test]
    fn test_empty_payload_returns_none() {
        assert!(ClientProfile::from_cbor(&[]).is_none());
    }

    #[test]
    fn test_garbage_payload_returns_none() {
        assert!(ClientProfile::from_cbor(&[0xFF, 0xFE, 0xFD]).is_none());
    }
}
