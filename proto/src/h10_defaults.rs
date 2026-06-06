//! H10 — Default flip for `--punch`, `--relay-pool`, and `--multi-candidate`.
//!
//! v0.30.12 changes the user-facing CLI so that whenever `--ns-server` is
//! provided, both NS-coordinated hole punching and multi-relay failover are
//! turned on by default. Two new escape hatches — `--no-punch` and
//! `--no-relay-pool` — let advanced users opt out without giving up the rest
//! of the NS-coordinated experience.
//!
//! v0.32.3 extends the same pattern to `--multi-candidate`: when `--ns-server`
//! is set, multi-candidate auto-enables so the connect attempt takes the QUIC
//! routing path (which works end-to-end against v0.32.x relays) instead of the
//! legacy `--punch` UDP path (which is broken against v0.32.x relays and fails
//! before sending HELLO with "Invalid argument (os error 22)"). The
//! `--no-multi-candidate` escape hatch lets advanced users opt out for the
//! rare case where they explicitly want the legacy path (debugging, etc.).
//!
//! This file deliberately contains ONLY pure, side-effect-free helpers plus
//! their BDD-style test suites. The clap layer (in `proto/src/bin/ztlp-cli.rs`)
//! parses the flags and the conflict guards (`conflicts_with`), then delegates
//! the resolution of the *effective* state to these helpers.
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

/// Resolve the *effective* state of `--multi-candidate` after taking the
/// v0.32.3 default-flip and the `--no-multi-candidate` escape hatch into
/// account.
///
/// Behaviour:
///
/// | --ns-server | --multi-candidate | --no-multi-candidate | multi_candidate_active |
/// |-------------|-------------------|----------------------|------------------------|
/// | unset       | false             | false                | false (unchanged)      |
/// | unset       | true              | false                | true  (explicit)       |
/// | set         | false             | false                | true  (auto-flip)      |
/// | set         | true              | false                | true  (explicit)       |
/// | set         | false             | true                 | false (opt-out)        |
///
/// `--no-multi-candidate` is an unconditional veto. clap's `conflicts_with`
/// is what prevents `--multi-candidate` AND `--no-multi-candidate` from
/// reaching this helper simultaneously.
pub fn resolve_multi_candidate_flag(
    ns_server_set: bool,
    multi_candidate: bool,
    no_multi_candidate: bool,
) -> bool {
    if no_multi_candidate {
        false
    } else {
        multi_candidate || ns_server_set
    }
}

/// Resolve whether the auto-reconnect supervisor should engage for this
/// `ztlp connect` invocation.
///
/// v0.34.10: the supervisor is **default-on** regardless of whether
/// `--ns-server` was supplied. The only opt-out is the explicit
/// `--no-reconnect` flag (which clap's `conflicts_with` already prevents
/// from co-existing with the tuning flags).
///
/// Background: v0.34.9 introduced the supervisor but gated it behind
/// `ns_server.is_some()` on the theory that the supervisor "needs NS to
/// re-resolve via". In practice the supervisor already falls back to the
/// last-known peer address when re-resolve is unavailable, so the gate
/// was a false-precondition. Raw-IP connects (e.g. `ztlp connect <ip>:<port>`)
/// silently fell through to one-shot mode and exited code=1 on the first
/// idle-timeout — observed in production on 2026-06-01 with a 30h bootstrap
/// tunnel that died at idle-timeout and never reconnected.
///
/// Behaviour:
///
/// | --ns-server | --no-reconnect | supervisor_active |
/// |-------------|----------------|-------------------|
/// | unset       | false          | true  (v0.34.10 default-on)   |
/// | set         | false          | true  (unchanged from v0.34.9)|
/// | unset       | true           | false (explicit fail-fast)    |
/// | set         | true           | false (explicit fail-fast)    |
pub fn resolve_supervisor_flag(_ns_server_set: bool, no_reconnect: bool) -> bool {
    !no_reconnect
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

    // ── v0.32.3 multi-candidate tests ────────────────────────────────────

    // BDD: GIVEN no --ns-server and no flags
    //       WHEN  we resolve multi-candidate
    //       THEN  it stays OFF (no behaviour change for non-NS paths)
    #[test]
    fn test_mc_no_ns_no_flags_returns_false() {
        let mc = resolve_multi_candidate_flag(false, false, false);
        assert!(!mc, "multi-candidate must stay OFF without --ns-server");
    }

    // BDD: GIVEN --ns-server set and no multi-candidate flags
    //       WHEN  we resolve
    //       THEN  multi-candidate auto-flips to ON (v0.32.3 default flip)
    //
    // This is THE regression test for the v0.32.3 fix. v0.32.2 users hitting
    // a v0.32.x relay via `ztlp connect --ns-server <ns> <name>` got dropped
    // into the broken legacy --punch path because punch auto-flipped without
    // multi-candidate also auto-flipping.
    #[test]
    fn test_mc_ns_alone_auto_enables() {
        let mc = resolve_multi_candidate_flag(true, false, false);
        assert!(mc, "multi-candidate must auto-ON when --ns-server is set");
    }

    // BDD: GIVEN --ns-server set and --no-multi-candidate
    //       WHEN  we resolve
    //       THEN  multi-candidate is OFF (explicit opt-out wins)
    #[test]
    fn test_mc_no_mc_overrides_auto_on() {
        let mc = resolve_multi_candidate_flag(true, false, true);
        assert!(!mc, "--no-multi-candidate must veto the auto-ON behaviour");
    }

    // BDD: GIVEN --multi-candidate explicit, no --ns-server
    //       WHEN  we resolve
    //       THEN  multi-candidate is ON (explicit opt-in works in non-NS mode)
    #[test]
    fn test_mc_explicit_without_ns_works() {
        let mc = resolve_multi_candidate_flag(false, true, false);
        assert!(
            mc,
            "explicit --multi-candidate must work without --ns-server"
        );
    }

    // BDD: GIVEN --ns-server set and --multi-candidate (belt-and-suspenders)
    //       WHEN  we resolve
    //       THEN  multi-candidate is ON (no-op for the redundant flag)
    #[test]
    fn test_mc_explicit_with_ns_is_idempotent() {
        let mc = resolve_multi_candidate_flag(true, true, false);
        assert!(
            mc,
            "explicit --multi-candidate with --ns-server stays ON (idempotent)"
        );
    }

    // BDD: GIVEN no --ns-server and --no-multi-candidate (degenerate)
    //       WHEN  we resolve
    //       THEN  multi-candidate is OFF (already-off, --no-* is no-op)
    #[test]
    fn test_mc_no_mc_alone_without_ns_is_noop() {
        let mc = resolve_multi_candidate_flag(false, false, true);
        assert!(!mc, "--no-multi-candidate without --ns-server is a no-op");
    }

    // ── v0.34.10 supervisor default-on tests ─────────────────────────────
    //
    // Background: v0.34.9 introduced the auto-reconnect supervisor, but
    // gated it behind `ns_server.is_some()`. That meant raw-IP connect
    // (e.g. `ztlp connect <ip>:<port>` with no --ns-server) silently
    // fell back to the one-shot path with NO reconnect on disconnect.
    //
    // Real-world hit (2026-06-01): bootstrap tunnel via direct relay
    // address timed out after ~30h idle and exited code=1, because the
    // dispatcher saw `ns_server == None` and skipped the supervisor.
    //
    // v0.34.10 makes the supervisor default-on regardless of ns_server.
    // The supervisor's reconnect path falls back to last-known peer_addr
    // when re-resolve is unavailable (already-implemented behavior), so
    // there is no functional reason to gate on ns_server.
    //
    // Escape hatch: `--no-reconnect` remains an unconditional fail-fast
    // veto for users who want v0.34.8-style one-shot behavior.

    // BDD: GIVEN raw-IP connect (no --ns-server) and no --no-reconnect
    //       WHEN  we resolve supervisor flag
    //       THEN  supervisor is ENGAGED (v0.34.10 default-on)
    #[test]
    fn test_supervisor_raw_ip_default_engages() {
        let active = resolve_supervisor_flag(false, false);
        assert!(
            active,
            "v0.34.10: supervisor must engage on raw-IP connect by default"
        );
    }

    // BDD: GIVEN --ns-server connect and no --no-reconnect
    //       WHEN  we resolve supervisor flag
    //       THEN  supervisor is ENGAGED (unchanged from v0.34.9)
    #[test]
    fn test_supervisor_ns_default_engages() {
        let active = resolve_supervisor_flag(true, false);
        assert!(
            active,
            "supervisor must engage on NS-resolved connect by default"
        );
    }

    // BDD: GIVEN raw-IP connect and --no-reconnect set
    //       WHEN  we resolve supervisor flag
    //       THEN  supervisor is SKIPPED (explicit fail-fast)
    #[test]
    fn test_supervisor_no_reconnect_vetoes_raw_ip() {
        let active = resolve_supervisor_flag(false, true);
        assert!(
            !active,
            "--no-reconnect must veto supervisor even on raw-IP connect"
        );
    }

    // BDD: GIVEN --ns-server connect and --no-reconnect set
    //       WHEN  we resolve supervisor flag
    //       THEN  supervisor is SKIPPED (explicit fail-fast)
    #[test]
    fn test_supervisor_no_reconnect_vetoes_ns() {
        let active = resolve_supervisor_flag(true, true);
        assert!(
            !active,
            "--no-reconnect must veto supervisor even on NS-resolved connect"
        );
    }
}
