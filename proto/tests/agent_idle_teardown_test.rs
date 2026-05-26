//! D3.T2: Idle teardown contract test.
//!
//! Exercises the surface that the daemon's GC loop relies on:
//! `TunnelPool::with_timeouts(...)` lets us configure a custom idle threshold,
//! `idle_tunnels()` lists tunnels exceeding it, and `remove(name)` actually
//! removes them. This tests the contract — the daemon-level wiring (tokio,
//! real handshakes) is not worth the test-infra cost here.

use std::net::SocketAddr;
use std::time::Duration;

use ztlp_proto::agent::tunnel_pool::TunnelPool;

#[tokio::test]
async fn idle_tunnels_are_listed_and_removable_after_timeout() {
    // 50 ms idle threshold, 1 s keepalive (unused here).
    let mut pool = TunnelPool::with_timeouts(8, Duration::from_millis(50), Duration::from_secs(1));

    let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    pool.register("test.peer.ztlp", peer).expect("register");
    // idle_tunnels() only considers Active tunnels — must mark active first.
    pool.mark_active("test.peer.ztlp");

    // Immediately, no tunnel is idle.
    assert!(
        pool.idle_tunnels().is_empty(),
        "expected no idle tunnels just after activation"
    );

    // Sleep past the 50 ms idle threshold.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let idle = pool.idle_tunnels();
    assert_eq!(idle.len(), 1, "expected exactly one idle tunnel");
    assert_eq!(idle[0], "test.peer.ztlp");

    // Removing the idle tunnel must succeed and return the ManagedTunnel.
    let removed = pool.remove("test.peer.ztlp");
    assert!(removed.is_some(), "remove() should return the tunnel");

    // And after removal, nothing is idle.
    assert!(pool.idle_tunnels().is_empty());
    assert!(pool.remove("test.peer.ztlp").is_none());
}
