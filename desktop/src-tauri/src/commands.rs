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
    state.status.lock().map(|s| s.clone()).unwrap_or_default()
}

// ── Identity ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_identity(state: State<'_, AppState>) -> Option<IdentityInfo> {
    state.identity.lock().ok().and_then(|id| id.clone())
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
    if let Ok(response) = crate::ipc::ipc_request("tunnels", None) {
        if let Some(tunnels) = response.as_array() {
            let mut result = Vec::new();
            for t in tunnels {
                if let Some(obj) = t.as_object() {
                    let local_port = obj.get("local_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let target = obj.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let service_type = obj.get("protocol").and_then(|v| v.as_str()).unwrap_or("TCP").to_string();
                    
                    // Derive a standard name if none was given
                    let name = obj.get("name").and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| format!("{}: {}", service_type, target.split(':').next().unwrap_or("unknown")));

                    result.push(ServiceInfo {
                        id: obj.get("id").and_then(|v| v.as_str()).unwrap_or(&target).to_string(),
                        name,
                        hostname: target,
                        port: local_port,
                        protocol_type: service_type,
                        host_node_id: "".to_string(),
                        is_reachable: obj.get("active").and_then(|v| v.as_bool()).unwrap_or(true),
                        description: None,
                        tags: vec![],
                    });
                }
            }
            return result;
        }
    }
    state.services.lock().map(|s| s.clone()).unwrap_or_default()
}

// ── Configuration ───────────────────────────────────────────────────────

#[tauri::command]
pub fn get_config(state: State<'_, AppState>) -> AppConfig {
    state.config.lock().map(|c| c.clone()).unwrap_or_default()
}

pub fn save_config_internal(
    config: &AppConfig,
    mut current: std::sync::MutexGuard<'_, AppConfig>,
    mut config_path: std::path::PathBuf,
) -> Result<(), String> {
    *current = config.clone();
    std::fs::create_dir_all(&config_path).map_err(|e| format!("Failed to create config directory: {}", e))?;
    config_path.push("agent.toml");

    // Write back the basic TOML parameters that the frontend might have touched.
    // E.g., overriding the default relay address or specific port mappings
    let toml_string = format!(
        r#"[agent]
relay_address = "{}"
auto_connect = {}
[agent.ports]
{}
"#,
        config.relay_address,
        config.auto_connect,
        // serialize key-value pairs
        config
            .port_mappings
            .iter()
            .map(|pm| format!("\"{}\" = {}", pm.local_port, pm.remote_port))
            .collect::<Vec<String>>()
            .join("\n")
    );

    std::fs::write(&config_path, toml_string).map_err(|e| format!("Failed to save config file at {:?}: {}", config_path, e))?;
    Ok(())
}

#[tauri::command]
pub fn save_config(config: AppConfig, state: State<'_, AppState>) -> Result<(), String> {
    let current = state.config.lock().map_err(|e| e.to_string())?;

    let mut config_path = dirs::home_dir().ok_or("Could not find home directory")?;
    config_path.push(".ztlp");
    save_config_internal(&config, current, config_path)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use crate::state::PortMapping;

    #[test]
    fn test_save_config_internal() {
        let temp_dir = env::temp_dir().join("ztlp_test_config_dir");
        
        let config = AppConfig {
            relay_address: "relay.example.com".to_string(),
            stun_server: "stun.example.com".to_string(),
            tunnel_address: "10.0.0.2".to_string(),
            dns_servers: vec![],
            port_mappings: vec![
                PortMapping { local_port: 8080, remote_host: "1.2.3.4".into(), remote_port: 80 },
                PortMapping { local_port: 8443, remote_host: "5.6.7.8".into(), remote_port: 443 },
            ],
            mtu: 1420,
            auto_connect: true,
        };

        let app_state = AppState::default();
        let current = app_state.config.lock().unwrap();

        let res = save_config_internal(&config, current, temp_dir.clone());
        assert!(res.is_ok(), "save_config_internal failed");

        let agent_file = temp_dir.join("agent.toml");
        assert!(agent_file.exists(), "agent.toml was not created");

        let content = std::fs::read_to_string(&agent_file).unwrap();
        assert!(content.contains(r#"relay_address = "relay.example.com""#));
        assert!(content.contains("auto_connect = true"));
        assert!(content.contains("[agent.ports]"));
        assert!(content.contains("\"8080\" = 80"));
        assert!(content.contains("\"8443\" = 443"));

        std::fs::remove_dir_all(temp_dir).unwrap();
    }
}
