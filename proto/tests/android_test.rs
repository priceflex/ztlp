use std::net::Ipv4Addr;
use ztlp_proto::android::*;

// ── AndroidTunnelConfig ────────────────────────────────────────────

#[test]
fn config_default_has_correct_values() {
    let cfg = AndroidTunnelConfig::default();
    assert!(cfg.relay_server.is_empty());
    assert_eq!(cfg.relay_port, 23095);
    assert!(cfg.gateway_server.is_empty());
    assert_eq!(cfg.gateway_port, 23097);
    assert!(cfg.ns_server.is_none());
    assert_eq!(cfg.ns_port, 23096);
    assert_eq!(cfg.service_name, "default");
    assert!(cfg.zone_name.is_empty());
    assert_eq!(cfg.tunnel_addr, Ipv4Addr::new(10, 122, 0, 1));
    assert_eq!(cfg.tunnel_netmask, Ipv4Addr::new(255, 255, 0, 0));
    assert!(cfg.dns_servers.is_empty());
    assert_eq!(cfg.mtu, 1280);
    assert!(cfg.use_relay);
    assert!(cfg.allowed_apps.is_empty());
    assert!(cfg.disallowed_apps.is_empty());
}

#[test]
fn config_validate_succeeds_with_valid_config() {
    let cfg = AndroidTunnelConfig {
        gateway_server: "gw.example.com".into(),
        zone_name: "example.zone".into(),
        service_name: "web".into(),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn config_validate_rejects_empty_gateway_server() {
    let cfg = AndroidTunnelConfig {
        zone_name: "z".into(),
        ..Default::default()
    };
    assert_eq!(
        cfg.validate().unwrap_err(),
        ConfigError::MissingField("gateway_server")
    );
}

#[test]
fn config_validate_rejects_empty_zone_name() {
    let cfg = AndroidTunnelConfig {
        gateway_server: "gw".into(),
        ..Default::default()
    };
    assert_eq!(
        cfg.validate().unwrap_err(),
        ConfigError::MissingField("zone_name")
    );
}

#[test]
fn config_validate_rejects_empty_service_name() {
    let cfg = AndroidTunnelConfig {
        gateway_server: "gw".into(),
        zone_name: "z".into(),
        service_name: String::new(),
        ..Default::default()
    };
    assert_eq!(
        cfg.validate().unwrap_err(),
        ConfigError::MissingField("service_name")
    );
}

#[test]
fn config_validate_rejects_mtu_below_576() {
    let cfg = AndroidTunnelConfig {
        gateway_server: "gw".into(),
        zone_name: "z".into(),
        mtu: 500,
        ..Default::default()
    };
    assert_eq!(cfg.validate().unwrap_err(), ConfigError::InvalidMtu(500));
}

#[test]
fn config_validate_rejects_mtu_above_9000() {
    let cfg = AndroidTunnelConfig {
        gateway_server: "gw".into(),
        zone_name: "z".into(),
        mtu: 10000,
        ..Default::default()
    };
    assert_eq!(cfg.validate().unwrap_err(), ConfigError::InvalidMtu(10000));
}

// ── TunnelState ────────────────────────────────────────────────────

#[test]
fn tunnel_state_as_str_from_str_roundtrip() {
    let states = [
        TunnelState::Disconnected,
        TunnelState::Connecting,
        TunnelState::Connected,
        TunnelState::Reconnecting,
        TunnelState::Disconnecting,
        TunnelState::Failed,
    ];
    for state in &states {
        let s = state.as_str();
        let parsed = TunnelState::from_str(s).unwrap();
        assert_eq!(*state, parsed, "roundtrip failed for {s}");
    }
}

#[test]
fn tunnel_state_is_active_for_connected_and_reconnecting() {
    assert!(TunnelState::Connected.is_active());
    assert!(TunnelState::Reconnecting.is_active());
}

#[test]
fn tunnel_state_is_active_false_for_disconnected() {
    assert!(!TunnelState::Disconnected.is_active());
    assert!(!TunnelState::Connecting.is_active());
    assert!(!TunnelState::Disconnecting.is_active());
    assert!(!TunnelState::Failed.is_active());
}

#[test]
fn tunnel_state_transition_disconnected_to_connecting() {
    assert!(TunnelState::Disconnected.can_transition_to(&TunnelState::Connecting));
}

#[test]
fn tunnel_state_transition_connecting_to_connected() {
    assert!(TunnelState::Connecting.can_transition_to(&TunnelState::Connected));
}

#[test]
fn tunnel_state_transition_connected_to_disconnected_not_allowed() {
    assert!(!TunnelState::Connected.can_transition_to(&TunnelState::Disconnected));
}

#[test]
fn tunnel_state_transition_failed_to_connecting_allowed() {
    assert!(TunnelState::Failed.can_transition_to(&TunnelState::Connecting));
}

// ── AtomicTunnelStats ──────────────────────────────────────────────

#[test]
fn atomic_stats_record_send_increments() {
    let stats = AtomicTunnelStats::new();
    stats.record_send(1024);
    stats.record_send(512);
    let snap = stats.snapshot();
    assert_eq!(snap.bytes_sent, 1536);
    assert_eq!(snap.packets_sent, 2);
}

#[test]
fn atomic_stats_record_recv_increments() {
    let stats = AtomicTunnelStats::new();
    stats.record_recv(2048);
    stats.record_recv(256);
    let snap = stats.snapshot();
    assert_eq!(snap.bytes_received, 2304);
    assert_eq!(snap.packets_received, 2);
}

#[test]
fn atomic_stats_snapshot_returns_current_values() {
    let stats = AtomicTunnelStats::new();
    stats.record_send(100);
    stats.record_recv(200);
    stats.record_handshake();
    stats.record_reconnect();
    stats.set_rtt(42);
    stats.set_active_streams(3);
    let snap = stats.snapshot();
    assert_eq!(snap.bytes_sent, 100);
    assert_eq!(snap.bytes_received, 200);
    assert_eq!(snap.packets_sent, 1);
    assert_eq!(snap.packets_received, 1);
    assert_eq!(snap.handshakes_completed, 1);
    assert_eq!(snap.reconnects, 1);
    assert_eq!(snap.current_rtt_ms, 42);
    assert_eq!(snap.active_streams, 3);
}

#[test]
fn atomic_stats_reset_zeros_everything() {
    let stats = AtomicTunnelStats::new();
    stats.record_send(999);
    stats.record_recv(888);
    stats.record_handshake();
    stats.record_reconnect();
    stats.set_rtt(50);
    stats.set_active_streams(7);
    stats.set_start_time(1_000_000);
    stats.reset();
    let snap = stats.snapshot();
    assert_eq!(snap.bytes_sent, 0);
    assert_eq!(snap.bytes_received, 0);
    assert_eq!(snap.packets_sent, 0);
    assert_eq!(snap.packets_received, 0);
    assert_eq!(snap.handshakes_completed, 0);
    assert_eq!(snap.reconnects, 0);
    assert_eq!(snap.current_rtt_ms, 0);
    assert_eq!(snap.active_streams, 0);
    assert_eq!(snap.uptime_secs, 0);
}

#[test]
fn atomic_stats_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AtomicTunnelStats>();
}

// ── VipTable ───────────────────────────────────────────────────────

#[test]
fn vip_table_add_and_lookup() {
    let mut table = VipTable::new();
    let ip = Ipv4Addr::new(10, 122, 1, 1);
    table.add(ip, "web-service", Some(8080));
    let mapping = table.lookup(ip).expect("should find mapping");
    assert_eq!(mapping.service_name, "web-service");
    assert_eq!(mapping.port, Some(8080));
}

#[test]
fn vip_table_remove() {
    let mut table = VipTable::new();
    let ip = Ipv4Addr::new(10, 122, 1, 2);
    table.add(ip, "svc", None);
    assert_eq!(table.len(), 1);
    table.remove(ip);
    assert!(table.lookup(ip).is_none());
    assert_eq!(table.len(), 0);
}

#[test]
fn vip_table_lookup_returns_none_for_unknown() {
    let table = VipTable::new();
    assert!(table.lookup(Ipv4Addr::new(192, 168, 1, 1)).is_none());
}

#[test]
fn vip_table_len_and_is_empty() {
    let mut table = VipTable::new();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
    table.add(Ipv4Addr::new(10, 0, 0, 1), "a", None);
    table.add(Ipv4Addr::new(10, 0, 0, 2), "b", None);
    assert!(!table.is_empty());
    assert_eq!(table.len(), 2);
}

// ── PerAppConfig ───────────────────────────────────────────────────

#[test]
fn per_app_allow_all_routes_everything() {
    let cfg = PerAppConfig::allow_all();
    assert!(cfg.should_route_app("com.example.any"));
    assert!(cfg.should_route_app("org.other.app"));
}

#[test]
fn per_app_only_apps_includes_listed() {
    let cfg = PerAppConfig::only_apps(vec![
        "com.example.vpnapp".into(),
        "com.example.browser".into(),
    ]);
    assert!(cfg.should_route_app("com.example.vpnapp"));
    assert!(cfg.should_route_app("com.example.browser"));
    assert!(!cfg.should_route_app("com.other.excluded"));
}

#[test]
fn per_app_exclude_apps_excludes_listed() {
    let cfg = PerAppConfig::exclude_apps(vec!["com.example.streaming".into()]);
    assert!(!cfg.should_route_app("com.example.streaming"));
    assert!(cfg.should_route_app("com.example.other"));
}

#[test]
fn per_app_is_split_tunnel() {
    assert!(!PerAppConfig::allow_all().is_split_tunnel());
    assert!(PerAppConfig::only_apps(vec!["a".into()]).is_split_tunnel());
    assert!(PerAppConfig::exclude_apps(vec!["b".into()]).is_split_tunnel());
}

// ── jni_function_name ──────────────────────────────────────────────

#[test]
fn jni_function_name_generates_correct_names() {
    assert_eq!(
        jni_function_name("com.ztlp.vpn.native", "ZtlpNative", "initialize"),
        "Java_com_ztlp_vpn_native_ZtlpNative_initialize"
    );
    assert_eq!(
        jni_function_name("com.ztlp.vpn.native", "ZtlpNative", "version"),
        "Java_com_ztlp_vpn_native_ZtlpNative_version"
    );
}

// ── ConfigError display ────────────────────────────────────────────

#[test]
fn config_error_display_messages() {
    let e1 = ConfigError::MissingField("gateway_server");
    assert_eq!(e1.to_string(), "missing required field: gateway_server");

    let e2 = ConfigError::InvalidMtu(100);
    assert_eq!(e2.to_string(), "invalid MTU: 100 (must be 576-9000)");

    let e3 = ConfigError::InvalidAddress("bad".into());
    assert_eq!(e3.to_string(), "invalid address: bad");
}

// ── KOTLIN_CLASS_SPEC ──────────────────────────────────────────────

#[test]
fn kotlin_class_spec_is_not_empty() {
    assert!(!KOTLIN_CLASS_SPEC.is_empty());
    assert!(KOTLIN_CLASS_SPEC.contains("ZtlpNative"));
    assert!(KOTLIN_CLASS_SPEC.contains("System.loadLibrary"));
}
