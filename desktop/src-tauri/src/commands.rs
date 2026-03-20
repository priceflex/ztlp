//! Tauri command handlers — these are the bridge between the JS frontend
//! and the Rust backend. Each `#[tauri::command]` becomes an IPC endpoint
//! callable from `window.__TAURI__.invoke("command_name", { args })`.

use tauri::State;

use crate::state::{
    AppConfig, AppState, ConnectionStatus, EnrollResult, IdentityInfo, ServiceInfo, TrafficStats,
};
use crate::tunnel;

// ── Connection ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn connect(relay: String, zone: String, state: State<'_, AppState>) -> Result<(), String> {
    let result = tunnel::start_tunnel(&relay, &zone)?;
    let mut status = state.status.lock().map_err(|e| e.to_string())?;
    *status = result;
    Ok(())
}

#[tauri::command]
pub fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    tunnel::stop_tunnel()?;
    let mut status = state.status.lock().map_err(|e| e.to_string())?;
    *status = ConnectionStatus::default();
    Ok(())
}

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> ConnectionStatus {
    state
        .status
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default()
}

// ── Identity ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_identity(state: State<'_, AppState>) -> Option<IdentityInfo> {
    state
        .identity
        .lock()
        .ok()
        .and_then(|id| id.clone())
}

// ── Enrollment ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn enroll(token_uri: String, state: State<'_, AppState>) -> Result<EnrollResult, String> {
    let result = tunnel::process_enrollment(&token_uri)?;

    if result.success {
        // Update identity with zone info
        if let Ok(mut identity) = state.identity.lock() {
            if let Some(ref mut id) = *identity {
                id.zone_name = result.zone_name.clone();
                id.enrolled = true;
            }
        }
        // Update config with relay address
        if let Ok(mut config) = state.config.lock() {
            if let Some(ref relay) = result.relay_address {
                config.relay_address = relay.clone();
            }
        }
    }

    Ok(result)
}

// ── Services ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_services(state: State<'_, AppState>) -> Vec<ServiceInfo> {
    state
        .services
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default()
}

// ── Configuration ───────────────────────────────────────────────────────

#[tauri::command]
pub fn get_config(state: State<'_, AppState>) -> AppConfig {
    state
        .config
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default()
}

#[tauri::command]
pub fn save_config(config: AppConfig, state: State<'_, AppState>) -> Result<(), String> {
    let mut current = state.config.lock().map_err(|e| e.to_string())?;
    *current = config;
    // TODO: Persist to disk (serde_json → config file)
    Ok(())
}

// ── Traffic ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_traffic_stats(state: State<'_, AppState>) -> TrafficStats {
    // Merge live FFI stats with stored state
    let live = tunnel::get_traffic();
    if let Ok(mut stored) = state.traffic.lock() {
        stored.bytes_sent = stored.bytes_sent.max(live.bytes_sent);
        stored.bytes_received = stored.bytes_received.max(live.bytes_received);
        stored.packets_sent = stored.packets_sent.max(live.packets_sent);
        stored.packets_received = stored.packets_received.max(live.packets_received);
        stored.clone()
    } else {
        live
    }
}
