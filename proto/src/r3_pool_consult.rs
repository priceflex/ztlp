//! R3: relay-pool consultation helper for the connect handshake.
//!
//! This module exposes a tiny, pure helper that mirrors the per-handshake-
//! attempt relay selection logic now wired into `cmd_connect` in the CLI
//! binary. Keeping the helper here (rather than only inline in the bin)
//! lets us drive it from library tests and assert the pool-driven failover
//! behaviour without spinning up real UDP sockets.
//!
//! The contract:
//!   * If the orchestrator's pool has a healthy primary, return it.
//!   * Otherwise, fall back to the caller-supplied `default_addr` (which in
//!     the binary is the original `send_addr` derived from `--relay`/peer).
//!
//! The bin doesn't *have* to call this helper; it inlines the same two
//! lines. The helper exists primarily so the selection logic is testable in
//! `cargo test --lib`.
//!
//! NOTE: this file deliberately does NOT modify `relay_pool.rs`. It only
//! consumes the already-public `FailoverOrchestrator::pool().primary()` API
//! that R2 stabilised.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::relay_pool::FailoverOrchestrator;

/// Resolve the address that a single handshake attempt should target.
///
/// Consults `orchestrator.pool().primary()` when an orchestrator is
/// supplied; otherwise returns `default_addr` unchanged. The returned
/// `SocketAddr` MUST be reused across handshake retransmits so that the
/// relay's per-source state machine doesn't reset mid-flow.
pub async fn resolve_handshake_attempt_addr(
    orchestrator: Option<&Arc<Mutex<FailoverOrchestrator>>>,
    default_addr: SocketAddr,
) -> SocketAddr {
    match orchestrator {
        Some(arc) => {
            let guard = arc.lock().await;
            guard.pool().primary().unwrap_or(default_addr)
        }
        None => default_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_pool::{RelayPool, RelayPoolConfig};
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn addr(s: &str) -> SocketAddr {
        SocketAddr::from_str(s).unwrap()
    }

    // BDD: GIVEN no orchestrator WHEN we resolve THEN we get the fallback.
    #[tokio::test]
    async fn no_orchestrator_returns_default() {
        let default = addr("203.0.113.1:9000");
        let got = resolve_handshake_attempt_addr(None, default).await;
        assert_eq!(got, default);
    }

    // BDD: GIVEN a pool with a healthy primary WHEN we resolve THEN we get
    // the pool's primary, NOT the fallback.
    #[tokio::test]
    async fn primary_overrides_default() {
        let default = addr("203.0.113.1:9000");
        let primary = addr("198.51.100.10:9000");

        let mut pool = RelayPool::new(RelayPoolConfig {
            failover_enabled: true,
            ..Default::default()
        });
        pool.add_relay(primary);
        let orch = Arc::new(Mutex::new(FailoverOrchestrator::new(pool)));

        let got = resolve_handshake_attempt_addr(Some(&orch), default).await;
        assert_eq!(got, primary, "pool.primary() should be preferred");
    }

    // BDD: GIVEN two relays where the original primary is reported failing
    // enough times to be demoted, WHEN we resolve THEN we get the backup
    // relay's addr (this exercises the failover path R3 relies on).
    #[tokio::test]
    async fn failed_primary_shifts_to_backup() {
        let default = addr("203.0.113.1:9000");
        let primary = addr("198.51.100.10:9000");
        let backup = addr("198.51.100.20:9000");

        let mut pool = RelayPool::new(RelayPoolConfig {
            failover_enabled: true,
            ..Default::default()
        });
        pool.add_relay(primary); // first added becomes primary
        pool.add_relay(backup);

        // Sanity: before any failure, primary() is the first relay.
        assert_eq!(pool.primary(), Some(primary));

        // Drive the primary into a failed state via the probe path. We use
        // probe_failure (the loop-driven one) because handshake failure
        // alone may not cross the demotion threshold in a single shot;
        // record_probe_failure flips the primary as soon as the addr is
        // unhealthy + a healthier peer exists. This mirrors what the relay
        // probe task would do in production.
        for _ in 0..16 {
            pool.record_probe_failure(primary);
        }

        let orch = Arc::new(Mutex::new(FailoverOrchestrator::new(pool)));

        let got = resolve_handshake_attempt_addr(Some(&orch), default).await;
        assert_ne!(
            got, primary,
            "after sustained failures the dead primary must NOT be returned"
        );
        assert_eq!(
            got, backup,
            "the surviving backup should be returned as the new primary"
        );
    }

    // BDD: GIVEN a pool whose primary is empty (no relays added) WHEN we
    // resolve THEN we still get the fallback default (Option::unwrap_or).
    #[tokio::test]
    async fn empty_pool_falls_back_to_default() {
        let default = addr("203.0.113.1:9000");
        let pool = RelayPool::new(RelayPoolConfig {
            failover_enabled: true,
            ..Default::default()
        });
        let orch = Arc::new(Mutex::new(FailoverOrchestrator::new(pool)));

        let got = resolve_handshake_attempt_addr(Some(&orch), default).await;
        assert_eq!(got, default);
    }
}
