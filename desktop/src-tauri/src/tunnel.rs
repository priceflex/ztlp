//! VPN tunnel management.
//!
//! This module wraps the ZTLP C FFI library calls for tunnel operations.
//! Currently uses mock implementations — replace the body of each function
//! with real FFI calls when linking against libztlp_proto.
//!
//! ## Real FFI integration (future)
//!
//! ```ignore
//! extern "C" {
//!     fn ztlp_init() -> i32;
//!     fn ztlp_shutdown() -> i32;
//!     fn ztlp_identity_generate() -> *mut std::ffi::c_void;
//!     fn ztlp_identity_load(path: *const std::os::raw::c_char) -> *mut std::ffi::c_void;
//!     fn ztlp_client_new(identity: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
//!     fn ztlp_client_connect(client: *mut std::ffi::c_void, ...) -> i32;
//!     fn ztlp_client_disconnect(client: *mut std::ffi::c_void) -> i32;
//!     fn ztlp_client_free(client: *mut std::ffi::c_void);
//! }
//! ```

use crate::state::{ConnectionState, ConnectionStatus, EnrollResult, TrafficStats};

/// Start a tunnel connection to the given relay/zone.
///
/// TODO: Call ztlp_client_new() + ztlp_client_connect() via FFI.
pub fn start_tunnel(relay: &str, zone: &str) -> Result<ConnectionStatus, String> {
    // Mock: instantly "connect"
    let now = chrono::Utc::now().timestamp();
    Ok(ConnectionStatus {
        state: ConnectionState::Connected,
        relay: relay.to_string(),
        zone: zone.to_string(),
        connected_since: Some(now),
    })
}

/// Tear down the active tunnel.
///
/// TODO: Call ztlp_client_disconnect() via FFI.
pub fn stop_tunnel() -> Result<(), String> {
    // Mock: always succeeds
    Ok(())
}

/// Process an enrollment token URI.
///
/// TODO: Parse the ztlp://enroll/... URI, extract relay + zone + token,
///       call the enrollment API, then persist identity and zone config.
pub fn process_enrollment(token_uri: &str) -> Result<EnrollResult, String> {
    if !token_uri.starts_with("ztlp://enroll/") {
        return Err("Invalid enrollment URI — must start with ztlp://enroll/".into());
    }

    // Mock: parse zone from URI
    let parts: Vec<&str> = token_uri
        .trim_start_matches("ztlp://enroll/")
        .split('/')
        .collect();

    let zone_name = parts.first().unwrap_or(&"default-zone").to_string();

    Ok(EnrollResult {
        success: true,
        zone_name: Some(zone_name),
        relay_address: Some("relay.ztlp.net:4433".into()),
        message: "Enrollment successful".into(),
    })
}

/// Get current traffic statistics.
///
/// TODO: Call ztlp_client_stats() via FFI to get real numbers.
pub fn get_traffic() -> TrafficStats {
    // Mock: return some plausible numbers
    TrafficStats {
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
    }
}
