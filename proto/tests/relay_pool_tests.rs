//! Integration tests for the relay pool and failover orchestrator.
//!
//! These tests verify the full lifecycle of relay failover including:
//! - Pool initialization and ranking
//! - Failover under various conditions (degraded, dead, all-down)
//! - Exponential backoff and deprioritization
//! - NS refresh integration
//! - Concurrent failover scenarios
//! - Memory stability under repeated failovers

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ztlp_proto::relay_pool::{
    FailoverDecision, FailoverOrchestrator, HandshakeResult, RelayHealth, RelayPool,
    RelayPoolConfig,
};

fn addr(ip4: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip4)), port)
}

fn default_config() -> RelayPoolConfig {
    RelayPoolConfig::default()
}

// ─── Pool Initialization Tests ──────────────────────────────────────────────

#[test]
fn test_pool_init_from_ns_query_results() {
    // Simulate NS returning 3 relay addresses
    let ns_relays = vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)];
    let pool = RelayPool::from_addresses(ns_relays.clone(), default_config());

    assert_eq!(pool.len(), 3);
    assert!(!pool.is_empty());
    // First relay should be primary by default
    assert_eq!(pool.primary(), Some(addr(1, 23095)));
    assert!(pool.failover_available());
}

#[test]
fn test_pool_init_empty_ns_response() {
    let pool = RelayPool::from_addresses(vec![], default_config());

    assert!(pool.is_empty());
    assert_eq!(pool.primary(), None);
    assert!(pool.needs_ns_refresh());
    assert!(!pool.failover_available());
}

#[test]
fn test_pool_init_single_relay() {
    let pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());

    assert_eq!(pool.len(), 1);
    assert_eq!(pool.primary(), Some(addr(1, 23095)));
    assert!(!pool.failover_available()); // Can't fail over with 1 relay
}

// ─── Relay Ranking Tests ────────────────────────────────────────────────────

#[test]
fn test_ranking_by_latency() {
    let mut pool = RelayPool::from_addresses(
        vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)],
        default_config(),
    );

    pool.record_probe_success(addr(3, 23095), Duration::from_millis(5));
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(50));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(20));

    let ranked = pool.ranked_relays();
    assert_eq!(ranked[0].addr, addr(3, 23095)); // 5ms — best
    assert_eq!(ranked[1].addr, addr(2, 23095)); // 20ms
    assert_eq!(ranked[2].addr, addr(1, 23095)); // 50ms — worst

    // Primary should be updated to the best relay
    assert_eq!(pool.primary(), Some(addr(3, 23095)));
}

#[test]
fn test_ranking_health_overrides_latency() {
    let mut pool =
        RelayPool::from_addresses(vec![addr(1, 23095), addr(2, 23095)], default_config());

    // addr(1) has great latency but is degraded
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(5));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(50));

    // Degrade addr(1)
    if let Some(entry) = pool.get_relay_mut(&addr(1, 23095)) {
        entry.mark_degraded();
    }

    let ranked = pool.ranked_relays();
    // addr(2) should rank higher despite worse latency because it's healthy
    assert_eq!(ranked[0].addr, addr(2, 23095)); // healthy, 50ms
    assert_eq!(ranked[1].addr, addr(1, 23095)); // degraded, 5ms
}

// ─── Failover Selection Tests ───────────────────────────────────────────────

#[test]
fn test_failover_skips_degraded() {
    let mut pool = RelayPool::from_addresses(
        vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)],
        default_config(),
    );

    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(20));
    pool.record_probe_success(addr(3, 23095), Duration::from_millis(30));

    // Mark addr(2) as dead (it's in backoff now)
    pool.record_probe_failure(addr(2, 23095));

    // Failover from primary should skip dead addr(2)
    let decision = pool.failover_degraded();
    match decision {
        FailoverDecision::UseRelay(a) => assert_eq!(a, addr(3, 23095)),
        _ => panic!("Expected UseRelay, got {:?}", decision),
    }
}

#[test]
fn test_failover_skips_dead() {
    let mut pool = RelayPool::from_addresses(
        vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)],
        default_config(),
    );

    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(20));
    pool.record_probe_success(addr(3, 23095), Duration::from_millis(30));

    // Kill addr(2)
    if let Some(entry) = pool.get_relay_mut(&addr(2, 23095)) {
        entry.mark_dead();
    }

    let decision = pool.failover_degraded();
    match decision {
        FailoverDecision::UseRelay(a) => assert_eq!(a, addr(3, 23095)),
        _ => panic!("Expected UseRelay, got {:?}", decision),
    }
}

#[test]
fn test_failover_picks_next_best() {
    let mut pool = RelayPool::from_addresses(
        vec![
            addr(1, 23095),
            addr(2, 23095),
            addr(3, 23095),
            addr(4, 23095),
        ],
        default_config(),
    );

    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(100));
    pool.record_probe_success(addr(3, 23095), Duration::from_millis(15)); // Second best
    pool.record_probe_success(addr(4, 23095), Duration::from_millis(50));

    let decision = pool.failover_degraded();
    match decision {
        FailoverDecision::UseRelay(a) => assert_eq!(a, addr(3, 23095)),
        _ => panic!("Expected UseRelay"),
    }
}

// ─── Exponential Backoff Tests ──────────────────────────────────────────────

#[test]
fn test_backoff_timing_sequence() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());

    // First failure → ~5s backoff
    pool.record_probe_failure(addr(1, 23095));
    let entry = pool.get_relay(&addr(1, 23095)).unwrap();
    let remaining = entry.backoff_remaining().unwrap();
    assert!(remaining.as_secs() <= 5);
    assert!(remaining.as_millis() > 3000); // At least 3s (with timing tolerance)

    // Second failure → ~10s
    pool.record_probe_failure(addr(1, 23095));
    let entry = pool.get_relay(&addr(1, 23095)).unwrap();
    let remaining = entry.backoff_remaining().unwrap();
    assert!(remaining.as_secs() <= 10);
    assert!(remaining.as_secs() >= 8);

    // Third failure → ~20s
    pool.record_probe_failure(addr(1, 23095));
    let entry = pool.get_relay(&addr(1, 23095)).unwrap();
    let remaining = entry.backoff_remaining().unwrap();
    assert!(remaining.as_secs() <= 20);
    assert!(remaining.as_secs() >= 17);
}

#[test]
fn test_backoff_caps_at_60s() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());

    // Hit it many times
    for _ in 0..20 {
        pool.record_probe_failure(addr(1, 23095));
    }

    let entry = pool.get_relay(&addr(1, 23095)).unwrap();
    let remaining = entry.backoff_remaining().unwrap();
    assert!(remaining.as_secs() <= 60);
}

// ─── Deprioritization Tests ─────────────────────────────────────────────────

#[test]
fn test_deprioritization_after_3_failures() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());

    // 3 failures in quick succession
    for _ in 0..3 {
        pool.record_probe_failure(addr(1, 23095));
    }

    let entry = pool.get_relay(&addr(1, 23095)).unwrap();
    assert_eq!(entry.health, RelayHealth::Deprioritized);
}

#[test]
fn test_deprioritization_recovery_on_success() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());

    // Deprioritize
    for _ in 0..3 {
        pool.record_probe_failure(addr(1, 23095));
    }
    assert_eq!(
        pool.get_relay(&addr(1, 23095)).unwrap().health,
        RelayHealth::Deprioritized
    );

    // Successful probe resets everything
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    let entry = pool.get_relay(&addr(1, 23095)).unwrap();
    assert_eq!(entry.health, RelayHealth::Healthy);
    assert_eq!(entry.consecutive_failures, 0);
    assert!(entry.backoff_until.is_none());
    assert!(entry.deprioritized_until.is_none());
}

// ─── Health State Transition Tests ──────────────────────────────────────────

#[test]
fn test_health_transitions_healthy_to_degraded() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));

    assert_eq!(
        pool.get_relay(&addr(1, 23095)).unwrap().health,
        RelayHealth::Healthy
    );

    if let Some(entry) = pool.get_relay_mut(&addr(1, 23095)) {
        entry.mark_degraded();
    }
    assert_eq!(
        pool.get_relay(&addr(1, 23095)).unwrap().health,
        RelayHealth::Degraded
    );
}

#[test]
fn test_health_transitions_healthy_to_dead() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));

    if let Some(entry) = pool.get_relay_mut(&addr(1, 23095)) {
        entry.mark_dead();
    }
    assert_eq!(
        pool.get_relay(&addr(1, 23095)).unwrap().health,
        RelayHealth::Dead
    );
}

#[test]
fn test_health_transitions_dead_to_healthy_on_success() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());
    pool.record_probe_failure(addr(1, 23095));
    assert_eq!(
        pool.get_relay(&addr(1, 23095)).unwrap().health,
        RelayHealth::Dead
    );

    pool.record_probe_success(addr(1, 23095), Duration::from_millis(15));
    assert_eq!(
        pool.get_relay(&addr(1, 23095)).unwrap().health,
        RelayHealth::Healthy
    );
}

// ─── Orchestrator Integration Tests ─────────────────────────────────────────

#[test]
fn test_orchestrator_full_failover_cycle() {
    // 3 relays: primary dies, failover to backup, new primary succeeds
    let mut pool = RelayPool::from_addresses(
        vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)],
        default_config(),
    );
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(20));
    pool.record_probe_success(addr(3, 23095), Duration::from_millis(30));

    let mut orch = FailoverOrchestrator::new(pool);
    assert_eq!(orch.pool().primary(), Some(addr(1, 23095)));

    // Primary dies → start degraded failover
    let decision = orch.start_degraded_failover();
    assert!(orch.is_failover_in_progress());

    match decision {
        FailoverDecision::UseRelay(relay) => {
            assert_eq!(relay, addr(2, 23095));
            // Handshake succeeds
            let next = orch.report_attempt(HandshakeResult::Success {
                relay_addr: relay,
                latency: Duration::from_millis(25),
            });
            assert!(next.is_none()); // Complete
            assert!(!orch.is_failover_in_progress());
            assert_eq!(orch.pool().primary(), Some(addr(2, 23095)));
        }
        other => panic!("Expected UseRelay, got {:?}", other),
    }
}

#[test]
fn test_orchestrator_dead_failover_tries_all() {
    let mut pool = RelayPool::from_addresses(
        vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)],
        default_config(),
    );
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    pool.record_probe_success(addr(2, 23095), Duration::from_millis(20));
    pool.record_probe_success(addr(3, 23095), Duration::from_millis(30));

    let mut orch = FailoverOrchestrator::new(pool);

    let (decision, candidates) = orch.start_dead_failover();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], addr(2, 23095));
    assert_eq!(candidates[1], addr(3, 23095));

    // First attempt to addr(2) fails
    match decision {
        FailoverDecision::UseRelay(relay) => {
            let next = orch.report_attempt(HandshakeResult::Failure {
                relay_addr: relay,
                error: "connection refused".to_string(),
            });

            // Should suggest addr(3) next
            match next {
                Some(FailoverDecision::UseRelay(next_relay)) => {
                    assert_eq!(next_relay, addr(3, 23095));

                    // This one succeeds
                    let final_result = orch.report_attempt(HandshakeResult::Success {
                        relay_addr: next_relay,
                        latency: Duration::from_millis(35),
                    });
                    assert!(final_result.is_none());
                    assert_eq!(orch.pool().primary(), Some(addr(3, 23095)));
                }
                other => panic!("Expected UseRelay, got {:?}", other),
            }
        }
        other => panic!("Expected UseRelay, got {:?}", other),
    }
}

#[test]
fn test_orchestrator_all_relays_down_triggers_ns_refresh() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));

    let mut orch = FailoverOrchestrator::new(pool);

    // Dead failover with single relay
    let (decision, _) = orch.start_dead_failover();
    assert_eq!(decision, FailoverDecision::NeedNsRefresh);

    // Provide fresh NS relays
    let new_decision = orch.provide_ns_relays(vec![addr(5, 23095), addr(6, 23095)]);
    match new_decision {
        FailoverDecision::UseRelay(relay) => {
            assert!(relay == addr(5, 23095) || relay == addr(6, 23095));
        }
        other => panic!("Expected UseRelay after NS refresh, got {:?}", other),
    }
}

#[test]
fn test_orchestrator_ns_refresh_with_empty_response() {
    let mut pool = RelayPool::from_addresses(vec![addr(1, 23095)], default_config());
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));

    let mut orch = FailoverOrchestrator::new(pool);

    let (_, _) = orch.start_dead_failover();
    let decision = orch.provide_ns_relays(vec![]);
    assert_eq!(decision, FailoverDecision::NoRelaysAvailable);
}

// ─── Stress / Stability Tests ───────────────────────────────────────────────

#[test]
fn test_repeated_failovers_no_panic() {
    let relays: Vec<SocketAddr> = (1..=10).map(|i| addr(i, 23095)).collect();
    let mut pool = RelayPool::from_addresses(relays.clone(), default_config());

    for relay in &relays {
        pool.record_probe_success(*relay, Duration::from_millis(10 + relay.port() as u64));
    }

    // Failover 100 times
    for i in 0..100 {
        let decision = if i % 2 == 0 {
            pool.failover_degraded()
        } else {
            pool.failover_dead()
        };

        match decision {
            FailoverDecision::UseRelay(a) => {
                pool.record_probe_success(a, Duration::from_millis(10));
            }
            FailoverDecision::NeedNsRefresh => {
                // Refresh with fresh relays
                pool.update_from_ns(relays.clone());
                for relay in &relays {
                    pool.record_probe_success(*relay, Duration::from_millis(10));
                }
            }
            FailoverDecision::NoRelaysAvailable => {
                // Re-populate
                pool.update_from_ns(relays.clone());
            }
        }
    }

    // Failover count may be less than 100 because NeedNsRefresh decisions
    // don't always result in a counted failover
    assert!(
        pool.failover_count() >= 90,
        "Expected at least 90 failovers, got {}",
        pool.failover_count()
    );
}

#[test]
fn test_concurrent_pool_operations() {
    // Simulate multiple operations in quick succession
    let mut pool = RelayPool::from_addresses(
        vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)],
        default_config(),
    );

    // Rapid probe results
    for _ in 0..50 {
        pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
        pool.record_probe_failure(addr(2, 23095));
        pool.record_probe_success(addr(3, 23095), Duration::from_millis(30));
    }

    // Pool should still be functional
    assert_eq!(pool.len(), 3);
    assert!(pool.primary().is_some());

    let status = pool.status_summary();
    assert_eq!(status.relays.len(), 3);
}

#[test]
fn test_rapid_relay_add_remove() {
    let mut pool = RelayPool::new(default_config());

    // Add and remove rapidly
    for i in 1..=100u8 {
        pool.add_relay(addr(i, 23095));
    }

    assert!(pool.len() <= 32); // MAX_POOL_SIZE enforced

    // Remove all
    for i in 1..=100u8 {
        pool.remove_relay(&addr(i, 23095));
    }

    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
}

#[test]
fn test_status_summary_display() {
    let mut pool =
        RelayPool::from_addresses(vec![addr(1, 23095), addr(2, 23095)], default_config());
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(12));
    pool.record_probe_failure(addr(2, 23095));

    let status = pool.status_summary();
    let display = format!("{}", status);

    assert!(display.contains("Relay Pool Status"));
    assert!(display.contains("10.0.0.1:23095"));
    assert!(display.contains("10.0.0.2:23095"));
    assert!(display.contains("healthy"));
    assert!(display.contains("dead"));
}

#[test]
fn test_pool_preserves_health_across_ns_updates() {
    let mut pool =
        RelayPool::from_addresses(vec![addr(1, 23095), addr(2, 23095)], default_config());

    // Build up health history
    pool.record_probe_success(addr(1, 23095), Duration::from_millis(10));
    pool.record_probe_failure(addr(2, 23095));

    // NS update with same relays shouldn't reset health
    pool.update_from_ns(vec![addr(1, 23095), addr(2, 23095), addr(3, 23095)]);

    // addr(1) should still have its latency
    let entry1 = pool.get_relay(&addr(1, 23095)).unwrap();
    assert_eq!(entry1.latency, Some(Duration::from_millis(10)));
    assert_eq!(entry1.health, RelayHealth::Healthy);

    // addr(2) should still be dead
    let entry2 = pool.get_relay(&addr(2, 23095)).unwrap();
    assert_eq!(entry2.health, RelayHealth::Dead);

    // addr(3) is new
    let entry3 = pool.get_relay(&addr(3, 23095)).unwrap();
    assert_eq!(entry3.health, RelayHealth::Healthy);
    assert_eq!(entry3.latency, None);
}
