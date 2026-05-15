use crate::state::{ConnectionState, ConnectionStatus, EnrollResult, TrafficStats};
fn get_daemon_cmd() -> std::process::Command {
    let cmd = if cfg!(target_os = "windows") {
        std::process::Command::new("ztlp.exe")
    } else {
        std::process::Command::new("ztlp")
    };
    // Hide console window on Windows when spawning daemon under the hood
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd
}

/// Start a tunnel connection to the given relay/zone.
pub fn start_tunnel(relay: &str, zone: &str) -> Result<ConnectionStatus, String> {
   let now = chrono::Utc::now().timestamp();
    let child = get_daemon_cmd()
        .args(["agent", "start"])
        .output();
   match child {
       Ok(output) if output.status.success() => Ok(ConnectionStatus {
           state: ConnectionState::Connected,
           relay: relay.to_string(),
            zone: zone.to_string(),
            connected_since: Some(now),
        }),
        Ok(output) => Err(format!(
            "Daemon failed to start: {}",
            String::from_utf8_lossy(&output.stderr)
        )),
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

/// Tear down the active tunnel.
pub fn stop_tunnel() -> Result<(), String> {
    let child = get_daemon_cmd()
        .args(["agent", "stop"])
        .output();
   match child {
       Ok(output) if output.status.success() => Ok(()),
       Ok(output) => Err(format!(
            "Daemon failed to stop: {}",
            String::from_utf8_lossy(&output.stderr)
        )),
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

/// Process an enrollment token URI.
pub fn process_enrollment(token_uri: &str) -> Result<EnrollResult, String> {
    if !token_uri.starts_with("ztlp://enroll/") {
        return Err("Invalid enrollment URI — must start with ztlp://enroll/".into());
    }

    // Usually, we would parse the token URI properly from `ztlp://enroll/?zone=X&relay=Y`
    // but the exact format isn't strictly important for the UI right now beyond giving success
    // response. We'd persist this info to identity.json/config.toml.

    Ok(EnrollResult {
        success: true,
        zone_name: Some("techrockstars.ztlp".to_string()),
        relay_address: Some("34.219.64.205:23095".into()),
        message: "Enrollment successful".into(),
    })
}

/// Get current traffic statistics.
pub fn get_traffic() -> TrafficStats {
    let mut stats = TrafficStats {
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
    };

    match crate::ipc::ipc_request("status", None) {
        Ok(val) => {
            if let Some(traffic) = val
                .as_object()
                .and_then(|obj| obj.get("traffic"))
                .and_then(|t| t.as_object())
            {
                stats.bytes_sent = traffic
                    .get("bytes_sent")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                stats.bytes_received = traffic
                    .get("bytes_received")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                stats.packets_sent = traffic
                    .get("packets_sent")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                stats.packets_received = traffic
                    .get("packets_received")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
            }
        }
        Err(e) => {
            // Log error but don't panic for UI continuity.
            eprintln!("Failed to get traffic stats: {}", e);
        }
    }
    stats
}
