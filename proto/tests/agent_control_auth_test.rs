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

// ─── D1.T2: handler gate tests ───────────────────────────────────────────

use std::sync::Arc;
use ztlp_proto::agent::control::{handle_request_line, AgentState, ControlResponse};

fn make_cmd_json(cmd: &str, token: Option<&str>) -> String {
    let c = ControlCommand {
        cmd: cmd.into(),
        name: None,
        token: token.map(String::from),
    };
    serde_json::to_string(&c).unwrap()
}

fn parse_resp(s: &str) -> ControlResponse {
    serde_json::from_str(s).expect("daemon must return well-formed ControlResponse JSON")
}

#[tokio::test]
async fn rejects_when_token_required_but_missing() {
    let state = AgentState::test_with_token(Arc::new("secret-abc".into()));
    let line = make_cmd_json("status", None);
    let resp = parse_resp(&handle_request_line(&state, &line).await);
    assert!(!resp.ok, "expected ok=false, got {:?}", resp);
    assert_eq!(resp.error.as_deref(), Some("unauthorized"));
}

#[tokio::test]
async fn rejects_when_token_wrong() {
    let state = AgentState::test_with_token(Arc::new("secret-abc".into()));
    let line = make_cmd_json("status", Some("not-the-secret"));
    let resp = parse_resp(&handle_request_line(&state, &line).await);
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("unauthorized"));
}

#[tokio::test]
async fn accepts_when_token_matches() {
    let state = AgentState::test_with_token(Arc::new("secret-abc".into()));
    let line = make_cmd_json("status", Some("secret-abc"));
    let resp = parse_resp(&handle_request_line(&state, &line).await);
    assert!(
        resp.ok,
        "expected ok=true with matching token, got error={:?}",
        resp.error
    );
}

#[tokio::test]
async fn no_check_when_state_has_no_token() {
    let state = AgentState::test_without_token();
    let line = make_cmd_json("status", None);
    let resp = parse_resp(&handle_request_line(&state, &line).await);
    assert!(
        resp.ok,
        "expected ok=true in legacy mode, got error={:?}",
        resp.error
    );
}

#[tokio::test]
async fn invalid_json_returns_parse_error_not_unauthorized() {
    // Confirms the parse-error path doesn't leak whether the token would have been right.
    let state = AgentState::test_with_token(Arc::new("secret-abc".into()));
    let resp = parse_resp(&handle_request_line(&state, "not-json-at-all").await);
    assert!(!resp.ok);
    let err = resp.error.unwrap();
    assert!(err.starts_with("invalid command:"), "got {err}");
}
