//! D1.T1 — Failing tests for the optional `token` field on `ControlCommand`.
//!
//! The agent's loopback TCP control plane (`127.100.255.1:4433`) currently
//! accepts unauthenticated requests from any process on the host. D1 layers
//! Bearer-token auth on top so that once the agent runs as a Windows
//! LocalSystem service (D2), only the legitimate user-session UI can drive
//! it — every other user-session process is locked out.
//!
//! These tests pin the wire shape: `ControlCommand` gains an optional
//! `token` field, serde-skipped when `None` so existing CLIs that haven't
//! been updated yet still produce identical JSON.

use ztlp_proto::agent::control::ControlCommand;

#[test]
fn control_command_serializes_with_token() {
    let cmd = ControlCommand {
        cmd: "status".into(),
        name: None,
        token: Some("abc123".into()),
    };
    let json = serde_json::to_string(&cmd).expect("serialize");
    assert!(
        json.contains("\"token\":\"abc123\""),
        "token must appear in serialized form, got: {json}"
    );
}

#[test]
fn control_command_omits_token_when_none() {
    let cmd = ControlCommand {
        cmd: "status".into(),
        name: None,
        token: None,
    };
    let json = serde_json::to_string(&cmd).expect("serialize");
    assert!(
        !json.contains("\"token\""),
        "token field must be omitted when None for wire-compat, got: {json}"
    );
}

#[test]
fn control_command_round_trips_with_token() {
    let cmd = ControlCommand {
        cmd: "tunnels".into(),
        name: Some("vault.techrockstars.ztlp".into()),
        token: Some("deadbeefcafef00d".into()),
    };
    let json = serde_json::to_string(&cmd).expect("serialize");
    let back: ControlCommand = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.cmd, "tunnels");
    assert_eq!(back.name.as_deref(), Some("vault.techrockstars.ztlp"));
    assert_eq!(back.token.as_deref(), Some("deadbeefcafef00d"));
}

#[test]
fn control_command_deserializes_legacy_without_token() {
    // Wire snapshot from before D1 — older CLI binaries will keep sending this.
    // Server must still accept it (the daemon decides whether to require a
    // token based on its own configuration, not on the wire shape).
    let legacy = r#"{"cmd":"status"}"#;
    let cmd: ControlCommand = serde_json::from_str(legacy).expect("legacy parse");
    assert_eq!(cmd.cmd, "status");
    assert!(cmd.name.is_none());
    assert!(cmd.token.is_none());
}
