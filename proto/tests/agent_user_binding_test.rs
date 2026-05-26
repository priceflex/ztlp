//! Tests for D3.T1: SID-bind on enrollment.
//!
//! These tests exercise `agent::user_binding::{current_user_sid, verify_user_binding,
//! BindingError}` and confirm `NodeIdentity` remains backward-compatible with
//! existing identity.json files that do not contain the new `bound_user_sid` field.

use ztlp_proto::agent::user_binding::{current_user_sid, verify_user_binding, BindingError};
use ztlp_proto::identity::NodeIdentity;

fn identity_with_binding(bound: Option<&str>) -> NodeIdentity {
    let mut ident = NodeIdentity::generate().expect("identity generation");
    ident.bound_user_sid = bound.map(|s| s.to_string());
    ident
}

#[test]
fn test_no_binding_returns_ok() {
    let ident = identity_with_binding(None);
    assert!(verify_user_binding(&ident, "uid:1000").is_ok());
    assert!(verify_user_binding(&ident, "S-1-5-21-anything").is_ok());
    assert!(verify_user_binding(&ident, "").is_ok());
}

#[test]
fn test_matching_binding_returns_ok() {
    let ident = identity_with_binding(Some("S-1-5-21-abc"));
    assert!(verify_user_binding(&ident, "S-1-5-21-abc").is_ok());

    let ident_unix = identity_with_binding(Some("uid:1000"));
    assert!(verify_user_binding(&ident_unix, "uid:1000").is_ok());
}

#[test]
fn test_mismatched_binding_errors() {
    let ident = identity_with_binding(Some("S-1-5-21-abc"));
    let err = verify_user_binding(&ident, "S-1-5-21-xyz").expect_err("should mismatch");
    match err {
        BindingError::Mismatch { expected, actual } => {
            assert_eq!(expected, "S-1-5-21-abc");
            assert_eq!(actual, "S-1-5-21-xyz");
        }
        other => panic!("expected Mismatch, got {:?}", other),
    }
}

#[test]
fn test_identity_deserializes_without_bound_user_sid() {
    // Simulate an old-style identity.json (pre-D3.T1) that has no bound_user_sid field.
    let legacy_json = r#"{
        "node_id": "0102030405060708090a0b0c0d0e0f10",
        "static_private_key": "0000000000000000000000000000000000000000000000000000000000000000",
        "static_public_key":  "1111111111111111111111111111111111111111111111111111111111111111"
    }"#;

    let ident: NodeIdentity =
        serde_json::from_str(legacy_json).expect("legacy identity.json must deserialize");
    assert!(
        ident.bound_user_sid.is_none(),
        "old identity should default to no binding"
    );
}

#[test]
fn test_current_user_sid_returns_something() {
    // On Linux/macOS CI, current_user_sid() shells out to `id -u` and returns "uid:N".
    // On Windows, it would return an "S-1-5-..." string. Either way, non-empty.
    let sid = current_user_sid().expect("current_user_sid should succeed on a sane test host");
    assert!(!sid.is_empty(), "current_user_sid returned empty string");

    #[cfg(unix)]
    {
        assert!(
            sid.starts_with("uid:"),
            "unix current_user_sid should start with 'uid:', got {:?}",
            sid
        );
        // The portion after "uid:" should parse as an integer.
        let n: u32 = sid["uid:".len()..]
            .parse()
            .expect("uid suffix should be numeric");
        // sanity: most users have uid < 1_000_000; root is 0.
        assert!(n < 10_000_000, "uid looks bogus: {}", n);
    }
}
