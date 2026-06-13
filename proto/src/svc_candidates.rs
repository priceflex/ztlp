//! Stage-2 multi-candidate SVC record helpers (v0.35.x).
//!
//! Background: a gateway bound to `0.0.0.0` (required for multi-NIC /
//! split-tunnel-VPN hosts) historically published a SVC record carrying a
//! single `address`, or — when bound to the wildcard — surrendered and
//! published KEY only (no SVC), leaving whole customer fleets undialable.
//!
//! Stage 2 makes the gateway enumerate every reachable address (all NICs +
//! the relay backstop) and publish them ALL as an ordered candidate set, so
//! the CLIENT can rank them against its own local subnets (ICE-style) and
//! dial the reachable one. The SVC wire record stays backward compatible:
//!
//! - `address`  — the single best candidate (UNCHANGED; old clients read it).
//! - `addresses`— comma-joined `ip:port` list of ALL candidates, best-first
//!                (NEW; new clients split + rank + race/failover over it).
//!
//! The NS stores SVC `data` as an opaque CBOR map and re-encodes it verbatim
//! on serve (`validate_record_data(:svc,_) -> :ok`), so adding the `addresses`
//! key requires NO NS (Elixir) change. Back-compat matrix:
//!
//! | gateway \ client | OLD (reads `address`)        | NEW (reads `addresses`)      |
//! |------------------|------------------------------|------------------------------|
//! | OLD (no `addresses`) | single addr (today)      | absent → falls back to `address` |
//! | NEW (`addresses`)    | reads `address`=best, ignores unknown key | full list → rank → dial |
//!
//! This module holds the PURE, dependency-light pieces so they're trivially
//! unit-testable; the gateway-publish and client-resolve call sites in
//! `ztlp-cli.rs` wire them into the live NS heartbeat / connect paths.

use std::net::SocketAddr;

/// Hard cap on advertised candidates (mirrors `local_candidates::MAX_CANDIDATES`
/// plus one slot for the relay backstop). Keeps the SVC CBOR comfortably under
/// the NS UDP response budget even with long IPv6 literals.
pub const MAX_ADVERTISED: usize = 9;

/// Assemble the ordered advertised-candidate set a gateway publishes in its
/// SVC record.
///
/// `local` is the gateway's enumerated, already-filtered local NIC addresses
/// (from `local_candidates::enumerate_local_candidates`), in deterministic OS
/// order. `relay` is the optional relay backstop the box registers with.
///
/// Ordering: locals first (a same-LAN operator should prefer them), relay
/// LAST (it's the universal backstop — class `Relay` on the client ranker).
/// De-duplicated (stable, first occurrence wins) and capped at
/// [`MAX_ADVERTISED`]. Returns the addresses as `ip:port` strings ready for
/// the CBOR `addresses` field; element 0 is also used as the legacy single
/// `address` field for old clients.
///
/// May return empty (wildcard bind, no usable NIC, no relay) — the caller
/// then publishes KEY only, exactly as before, so this never regresses a box
/// that genuinely has nothing routable to advertise.
pub fn assemble_advertised(local: &[SocketAddr], relay: Option<SocketAddr>) -> Vec<String> {
    let mut ordered: Vec<SocketAddr> = Vec::with_capacity(local.len() + 1);
    for a in local {
        ordered.push(*a);
    }
    if let Some(r) = relay {
        ordered.push(r);
    }
    // Stable de-dup preserving first-seen order.
    let mut seen: Vec<SocketAddr> = Vec::with_capacity(ordered.len());
    let mut out: Vec<String> = Vec::with_capacity(ordered.len());
    for a in ordered {
        if seen.contains(&a) {
            continue;
        }
        seen.push(a);
        out.push(a.to_string());
        if out.len() >= MAX_ADVERTISED {
            break;
        }
    }
    out
}

/// Encode a candidate list into the SVC `addresses` CBOR field value
/// (comma-joined `ip:port`). The inverse of [`parse_addresses_field`].
pub fn encode_addresses_field(candidates: &[String]) -> String {
    candidates.join(",")
}

/// Parse the SVC `addresses` field value back into socket addresses.
///
/// Splits on commas, trims whitespace, parses each as a `SocketAddr`, and
/// SKIPS any element that doesn't parse (forward-compat: a future gateway
/// could append a candidate shape an older client doesn't understand without
/// breaking the whole list). Order is preserved (best-first as published).
pub fn parse_addresses_field(value: &str) -> Vec<SocketAddr> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<SocketAddr>().ok())
        .collect()
}

/// Resolve the effective ordered candidate list from a parsed SVC record's
/// two fields, applying back-compat precedence:
///
/// 1. If `addresses` is present and yields ≥1 parseable candidate, use it.
/// 2. Otherwise fall back to the single `address` (old-gateway records).
/// 3. Otherwise empty.
///
/// Pass the raw field strings exactly as extracted from the CBOR map
/// (`None` when the key is absent).
pub fn resolve_candidates(address: Option<&str>, addresses: Option<&str>) -> Vec<SocketAddr> {
    if let Some(list) = addresses {
        let parsed = parse_addresses_field(list);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    match address.and_then(|a| a.trim().parse::<SocketAddr>().ok()) {
        Some(a) => vec![a],
        None => Vec::new(),
    }
}

/// Rank a resolved candidate list client-side using the shared ICE-style
/// priority ladder ([`crate::candidate_priority`]) against the client's own
/// local subnets, returning addresses ordered best-first (highest priority
/// dialed first). A stable sort preserves publish order within a priority
/// tier. This is the "only the client can judge reachability" half of the
/// ICE design: the same published set ranks differently for a same-LAN
/// operator (LAN candidate → 250) vs a remote operator (relay/public → lower).
pub fn rank_candidates(
    candidates: &[SocketAddr],
    client_subnets: &[(std::net::IpAddr, u8)],
) -> Vec<SocketAddr> {
    let ranked = crate::candidate_priority::prioritize(candidates, None, None, client_subnets);
    ranked.into_iter().map(|c| c.addr).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

    fn sa(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    // ── assemble_advertised ──────────────────────────────────────────

    #[test]
    fn assemble_locals_then_relay_in_order() {
        let local = vec![sa(10, 69, 94, 151, 23095), sa(192, 168, 1, 5, 23095)];
        let relay = Some(sa(44, 230, 7, 100, 23095));
        let out = assemble_advertised(&local, relay);
        assert_eq!(
            out,
            vec![
                "10.69.94.151:23095".to_string(),
                "192.168.1.5:23095".to_string(),
                "44.230.7.100:23095".to_string(),
            ]
        );
    }

    #[test]
    fn assemble_dedups_relay_that_equals_a_local() {
        // A box bound concretely to the relay's own addr shouldn't list it twice.
        let local = vec![sa(44, 230, 7, 100, 23095)];
        let relay = Some(sa(44, 230, 7, 100, 23095));
        let out = assemble_advertised(&local, relay);
        assert_eq!(out, vec!["44.230.7.100:23095".to_string()]);
    }

    #[test]
    fn assemble_relay_only_when_no_locals() {
        // NAT'd box bound 0.0.0.0 with no routable NIC enumerated but a relay
        // configured → publishes the relay as its sole candidate (this is what
        // replaces the decaying out-of-band `ns register --address relay` hack).
        let out = assemble_advertised(&[], Some(sa(44, 230, 7, 100, 23095)));
        assert_eq!(out, vec!["44.230.7.100:23095".to_string()]);
    }

    #[test]
    fn assemble_empty_when_nothing_to_advertise() {
        // Wildcard bind, no NIC, no relay → empty → caller publishes KEY only
        // (no regression vs today's surrender path).
        assert!(assemble_advertised(&[], None).is_empty());
    }

    #[test]
    fn assemble_caps_at_max_advertised() {
        let local: Vec<SocketAddr> = (0..20).map(|i| sa(10, 0, 0, i as u8 + 1, 23095)).collect();
        let out = assemble_advertised(&local, Some(sa(44, 230, 7, 100, 23095)));
        assert_eq!(out.len(), MAX_ADVERTISED);
    }

    // ── encode / parse round-trip ────────────────────────────────────

    #[test]
    fn encode_then_parse_round_trips() {
        let cands = vec![
            "10.69.94.151:23095".to_string(),
            "44.230.7.100:23095".to_string(),
        ];
        let field = encode_addresses_field(&cands);
        assert_eq!(field, "10.69.94.151:23095,44.230.7.100:23095");
        let parsed = parse_addresses_field(&field);
        assert_eq!(parsed, vec![sa(10, 69, 94, 151, 23095), sa(44, 230, 7, 100, 23095)]);
    }

    #[test]
    fn parse_skips_unparseable_elements_forward_compat() {
        // A future gateway appends a candidate shape we don't grok; we keep the
        // ones we DO understand rather than discarding the whole list.
        let parsed = parse_addresses_field("10.0.0.1:23095,garbage,192.168.1.9:23095");
        assert_eq!(parsed, vec![sa(10, 0, 0, 1, 23095), sa(192, 168, 1, 9, 23095)]);
    }

    #[test]
    fn parse_tolerates_whitespace_and_empties() {
        let parsed = parse_addresses_field(" 10.0.0.1:23095 , ,192.168.1.9:23095,");
        assert_eq!(parsed, vec![sa(10, 0, 0, 1, 23095), sa(192, 168, 1, 9, 23095)]);
    }

    // ── resolve_candidates back-compat precedence ────────────────────

    #[test]
    fn resolve_prefers_addresses_list_when_present() {
        let out = resolve_candidates(
            Some("44.230.7.100:23095"),
            Some("10.69.94.151:23095,44.230.7.100:23095"),
        );
        assert_eq!(out, vec![sa(10, 69, 94, 151, 23095), sa(44, 230, 7, 100, 23095)]);
    }

    #[test]
    fn resolve_falls_back_to_single_address_when_no_addresses_key() {
        // OLD gateway record: only `address`. NEW client must still resolve it.
        let out = resolve_candidates(Some("10.69.94.151:23095"), None);
        assert_eq!(out, vec![sa(10, 69, 94, 151, 23095)]);
    }

    #[test]
    fn resolve_falls_back_when_addresses_all_unparseable() {
        let out = resolve_candidates(Some("10.69.94.151:23095"), Some("garbage,more-garbage"));
        assert_eq!(out, vec![sa(10, 69, 94, 151, 23095)]);
    }

    #[test]
    fn resolve_empty_when_nothing_resolvable() {
        assert!(resolve_candidates(None, None).is_empty());
        assert!(resolve_candidates(Some("not-an-addr"), Some("also-bad")).is_empty());
    }

    // ── rank_candidates (client-side ICE ranking) ────────────────────

    #[test]
    fn rank_same_lan_operator_prefers_lan_over_relay() {
        // Operator on 10.69.94.0/24; box published [10.69.94.151 (LAN), relay].
        let cands = vec![sa(44, 230, 7, 100, 23095), sa(10, 69, 94, 151, 23095)];
        let subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 69, 94, 10)), 24u8)];
        let ranked = rank_candidates(&cands, &subnets);
        // LAN (same-subnet, 250) must rank ahead of the public relay (160).
        assert_eq!(ranked[0], sa(10, 69, 94, 151, 23095));
        assert_eq!(ranked[1], sa(44, 230, 7, 100, 23095));
    }

    #[test]
    fn rank_remote_operator_still_includes_relay_path() {
        // Remote operator: no matching local subnet. Both candidates survive so
        // a failover dial can still reach the box via the relay even though the
        // published LAN addr is unroutable for this operator.
        let cands = vec![sa(192, 168, 1, 5, 23095), sa(44, 230, 7, 100, 23095)];
        let ranked = rank_candidates(&cands, &[]);
        assert_eq!(ranked.len(), 2);
        assert!(ranked.contains(&sa(44, 230, 7, 100, 23095)));
    }
}
