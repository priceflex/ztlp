//! D3.T3: integration smoke for the session-lockdown teardown path.
//!
//! This test exercises the public surface of `agent::session_lock` end to
//! end without spinning up the full daemon. It confirms:
//! 1. `LockdownReason::as_str` returns the documented values (which become
//!    log fields and dashboards rely on the spelling being stable).
//! 2. `spawn_listener` is a no-op on the test platform (Linux CI) — installs
//!    nothing and returns Ok.
//! 3. A broadcast channel of `LockdownReason` round-trips a value cleanly,
//!    which is the contract `daemon.rs::run_daemon` depends on.
//!
//! The actual teardown logic lives inside `daemon.rs::run_daemon` and
//! requires the full runtime (DNS state, tunnel pool, real signal plumbing).
//! That path is covered by the manual D2.T5 / D3.T3 device smoke; here we
//! verify the wire contracts a producer in `service/src/session.rs` will
//! eventually depend on.

use tokio::sync::broadcast;
use ztlp_proto::agent::session_lock::{spawn_listener, LockdownReason};

#[test]
fn reason_strings_are_documented_audit_keys() {
    // Pinned: the structured `reason` field in `lockdown_teardown` events
    // uses these exact strings. Changing them breaks log queries.
    assert_eq!(LockdownReason::SessionLock.as_str(), "session_lock");
    assert_eq!(LockdownReason::SessionLogoff.as_str(), "session_logoff");
    assert_eq!(
        LockdownReason::ConsoleDisconnect.as_str(),
        "console_disconnect"
    );
    assert_eq!(
        LockdownReason::RemoteDisconnect.as_str(),
        "remote_disconnect"
    );
}

#[test]
fn spawn_listener_no_op_on_linux() {
    // On Unix the producer side is intentionally absent — the function
    // installs nothing and returns Ok so the daemon plumbing is uniform
    // across platforms.
    let (tx, _rx) = broadcast::channel::<LockdownReason>(8);
    assert!(
        spawn_listener(tx).is_ok(),
        "spawn_listener must return Ok on every supported target"
    );
}

#[tokio::test]
async fn broadcast_round_trip_delivers_all_four_reasons() {
    // Verifies the channel shape daemon.rs uses: a tokio broadcast carrying
    // LockdownReason. If a producer in service/ ever lands, this is the
    // type-level contract it has to honor.
    let (tx, mut rx) = broadcast::channel::<LockdownReason>(8);

    let reasons = [
        LockdownReason::SessionLock,
        LockdownReason::SessionLogoff,
        LockdownReason::ConsoleDisconnect,
        LockdownReason::RemoteDisconnect,
    ];
    for r in reasons {
        tx.send(r)
            .expect("send must succeed with one active receiver");
    }

    for expected in reasons {
        let got = rx
            .recv()
            .await
            .expect("recv must yield each sent reason in order");
        assert_eq!(got, expected);
    }
}
