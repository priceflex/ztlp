//! H10 — Default flip for `--punch` and `--relay-pool`.
//!
//! v0.30.12 changes the user-facing CLI so that whenever `--ns-server` is
//! provided, both NS-coordinated hole punching and multi-relay failover are
//! turned on by default. Two new escape hatches — `--no-punch` and
//! `--no-relay-pool` — let advanced users opt out without giving up the rest
//! of the NS-coordinated experience.
//!
//! This file deliberately contains ONLY a pure, side-effect-free helper plus
//! its BDD-style test suite. The clap layer (in `proto/src/bin/ztlp-cli.rs`)
//! parses the four flags and the conflict guards (`conflicts_with`), then
//! delegates the resolution of the *effective* state to this helper.
//!
//! Behaviour matrix:
//!
//! | --ns-server | --punch | --no-punch | --relay-pool | --no-relay-pool | (punch, pool) |
//! |-------------|---------|------------|--------------|-----------------|---------------|
//! | unset       | false   | false      | false        | false           | (false, false)|
//! | set         | false   | false      | false        | false           | (true , true) |
//! | set         | false   | true       | false        | false           | (false, true) |
//! | set         | false   | false      | false        | true            | (true , false)|
//! | unset       | true    | false      | false        | false           | (true , false)|
//! | unset       | false   | false      | true         | false           | (false, true) |
//!
//! The `conflicts_with` clap attribute is what prevents `--punch` AND
//! `--no-punch` (or the equivalent `--relay-pool` pair) from reaching this
//! helper simultaneously, so the function intentionally treats `no_*` as
//! an unconditional veto.

/// Resolve the *effective* state of `--punch` and `--relay-pool` after taking
/// the v0.30.12 H10 default-flip and the `--no-*` escape hatches into account.
///
/// Returns `(punch_active, relay_pool_active)`.
pub fn resolve_punch_and_pool_flags(
    ns_server_set: bool,
    punch: bool,
    no_punch: bool,
    relay_pool: bool,
    no_relay_pool: bool,
) -> (bool, bool) {
    let punch_active = if no_punch {
        false
    } else {
        punch || ns_server_set
    };
    let relay_pool_active = if no_relay_pool {
        false
    } else {
        relay_pool || ns_server_set
    };
    (punch_active, relay_pool_active)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BDD: GIVEN no --ns-server and no flags
    //       WHEN  we resolve effective flags
    //       THEN  both punch and relay_pool are OFF (no behaviour change)
    #[test]
    fn test_no_ns_server_no_flags_returns_both_false() {
        let (punch, pool) = resolve_punch_and_pool_flags(false, false, false, false, false);
        assert!(!punch, "punch should be OFF without --ns-server");
        assert!(!pool, "relay_pool should be OFF without --ns-server");
    }

    // BDD: GIVEN --ns-server set and no other flags
    //       WHEN  we resolve
    //       THEN  both punch and relay_pool auto-flip to ON
    #[test]
    fn test_ns_server_alone_turns_both_on() {
        let (punch, pool) = resolve_punch_and_pool_flags(true, false, false, false, false);
        assert!(punch, "punch should auto-ON when --ns-server is set");
        assert!(pool, "relay_pool should auto-ON when --ns-server is set");
    }

    // BDD: GIVEN --ns-server set and --no-punch
    //       WHEN  we resolve
    //       THEN  punch is OFF, relay_pool remains ON
    #[test]
    fn test_no_punch_overrides_auto_on() {
        let (punch, pool) = resolve_punch_and_pool_flags(true, false, true, false, false);
        assert!(!punch, "--no-punch must veto the auto-ON behaviour");
        assert!(pool, "--no-punch must NOT affect relay_pool");
    }

    // BDD: GIVEN --ns-server set and --no-relay-pool
    //       WHEN  we resolve
    //       THEN  punch remains ON, relay_pool is OFF
    #[test]
    fn test_no_relay_pool_overrides_auto_on() {
        let (punch, pool) = resolve_punch_and_pool_flags(true, false, false, false, true);
        assert!(punch, "--no-relay-pool must NOT affect punch");
        assert!(!pool, "--no-relay-pool must veto the auto-ON behaviour");
    }

    // BDD: GIVEN --ns-server set and --no-punch
    //       WHEN  we resolve
    //       THEN  --no-punch alone doesn't disable relay_pool (independence)
    #[test]
    fn test_no_punch_does_not_affect_relay_pool() {
        let (_, pool) = resolve_punch_and_pool_flags(true, false, true, false, false);
        assert!(pool, "relay_pool must stay ON when only --no-punch is set");
    }

    // BDD: GIVEN --ns-server set and --no-relay-pool
    //       WHEN  we resolve
    //       THEN  --no-relay-pool alone doesn't disable punch (independence)
    #[test]
    fn test_no_relay_pool_does_not_affect_punch() {
        let (punch, _) = resolve_punch_and_pool_flags(true, false, false, false, true);
        assert!(punch, "punch must stay ON when only --no-relay-pool is set");
    }

    // BDD: GIVEN --punch explicit, no --ns-server (legacy v0.30.11 path)
    //       WHEN  we resolve
    //       THEN  punch is ON, relay_pool stays OFF
    #[test]
    fn test_explicit_punch_without_ns_works() {
        let (punch, pool) = resolve_punch_and_pool_flags(false, true, false, false, false);
        assert!(punch, "explicit --punch must work without --ns-server");
        assert!(
            !pool,
            "relay_pool stays OFF without --ns-server or --relay-pool"
        );
    }

    // BDD: GIVEN --relay-pool explicit, no --ns-server (legacy v0.30.11 path)
    //       WHEN  we resolve
    //       THEN  relay_pool is ON, punch stays OFF
    #[test]
    fn test_explicit_relay_pool_without_ns_works() {
        let (punch, pool) = resolve_punch_and_pool_flags(false, false, false, true, false);
        assert!(!punch, "punch stays OFF without --ns-server or --punch");
        assert!(pool, "explicit --relay-pool must work without --ns-server");
    }

    // BDD: GIVEN --ns-server set and BOTH --no-punch + --no-relay-pool
    //       WHEN  we resolve
    //       THEN  both effective flags are OFF (full opt-out, NS used only
    //             for name resolution and identity glue)
    #[test]
    fn test_both_escape_hatches_disable_everything() {
        let (punch, pool) = resolve_punch_and_pool_flags(true, false, true, false, true);
        assert!(!punch, "--no-punch must veto auto-ON");
        assert!(!pool, "--no-relay-pool must veto auto-ON");
    }

    // BDD: GIVEN no --ns-server and --no-punch alone (degenerate case)
    //       WHEN  we resolve
    //       THEN  both effective flags are OFF (no-op for --no-punch since
    //             punch was already off; relay_pool stays off too)
    #[test]
    fn test_no_punch_alone_without_ns_is_noop() {
        let (punch, pool) = resolve_punch_and_pool_flags(false, false, true, false, false);
        assert!(!punch);
        assert!(!pool);
    }
}
