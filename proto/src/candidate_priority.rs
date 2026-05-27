//! Client-side candidate priority calculator — Steve's 7-tier ICE-style ladder.
//!
//! The dialer ranks candidate addresses before parallel-dial so the
//! highest-priority paths fire first. Tiers (priority value in parens):
//!
//! - 250 `HostSameSubnet`     — client and gateway share a subnet (LAN win).
//! - 200 `HostOtherRfc1918`   — RFC1918 v4 outside the client's subnet, **and**
//!   all IPv6 (ULA + global) in v0.32. IPv6 subnet detection is deferred to v0.33.
//! - 180 `HostVpnOverlay`     — Tailscale / CGNAT 100.64.0.0/10 only in v0.32.
//! - 160 `HostPublicV4`       — any other globally-routable IPv4.
//! - 140 `HostLinkLocalV6`    — fe80::/10 (rare; M1 filters most).
//! - 100 `ServerReflexive`    — NS-observed public addr.
//! -  50 `Relay`              — backstop.
//!
//! See `docs/plans/2026-05-28-multi-candidate-discovery-v0.32.md`
//! ("Where priority lives") for the design rationale.
//!
//! ## Scope notes (v0.32)
//! - VPN-overlay detection is **exactly** 100.64.0.0/10. Other overlay
//!   schemes (WireGuard, Nebula custom ranges) currently fall through to
//!   `HostPublicV4` or `HostOtherRfc1918`.
//! - IPv6 ULA (fc00::/7) and global v6 both classify as
//!   `HostOtherRfc1918` (priority 200) because we lack v6 subnet
//!   matching today; future work in v0.33 will add it.

use std::net::{IpAddr, SocketAddr};

/// Class of a candidate addr in the ICE-style priority ladder.
/// Higher u32 = higher priority = dial first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateClass {
    /// Relay backstop — only used when nothing else works.
    Relay = 50,
    /// NS-observed server-reflexive (the gateway's NAT'd public address).
    ServerReflexive = 100,
    /// IPv6 link-local (fe80::/10).
    HostLinkLocalV6 = 140,
    /// Public IPv4 host candidate (globally routable).
    HostPublicV4 = 160,
    /// VPN / overlay (Tailscale 100.64/10).
    HostVpnOverlay = 180,
    /// RFC1918 v4 outside the client's subnet + all IPv6 (ULA + global) in v0.32.
    HostOtherRfc1918 = 200,
    /// Same-subnet RFC1918 — highest priority. Client and gateway share a subnet.
    HostSameSubnet = 250,
}

impl CandidateClass {
    /// Numeric priority — higher means dial earlier.
    pub fn priority(self) -> u32 {
        self as u32
    }
}

/// A candidate with its classification and runtime priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedCandidate {
    pub addr: SocketAddr,
    pub class: CandidateClass,
    /// Equal to `class.priority()` today; M5 may add tie-breakers.
    pub priority: u32,
}

/// Test whether `ip` lies inside the subnet `(subnet_ip, prefix)`.
fn ip_in_subnet(ip: IpAddr, subnet_ip: IpAddr, prefix: u8) -> bool {
    match (ip, subnet_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if prefix > 32 {
                return false;
            }
            let mask: u32 = if prefix == 0 {
                0
            } else {
                !0u32 << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if prefix > 128 {
                return false;
            }
            let a_bytes = a.octets();
            let b_bytes = b.octets();
            let full_bytes = (prefix / 8) as usize;
            let remainder = prefix % 8;
            if a_bytes[..full_bytes] != b_bytes[..full_bytes] {
                return false;
            }
            if remainder == 0 {
                return true;
            }
            let mask = !0u8 << (8 - remainder);
            (a_bytes[full_bytes] & mask) == (b_bytes[full_bytes] & mask)
        }
        _ => false,
    }
}

/// True if `ip` is in any of the supplied subnets.
fn ip_in_any_subnet(ip: IpAddr, subnets: &[(IpAddr, u8)]) -> bool {
    subnets
        .iter()
        .any(|(net, prefix)| ip_in_subnet(ip, *net, *prefix))
}

/// True for IPv4 RFC1918: 10/8, 172.16/12, 192.168/16.
fn is_rfc1918_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    matches!(o, [10, ..])
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

/// True for IPv4 100.64.0.0/10 (Tailscale / CGNAT).
fn is_cgnat_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    // 100.64.0.0/10 = 01100100.01xxxxxx.x.x = 100.64–100.127
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// True for IPv4 169.254/16.
fn is_link_local_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 169 && o[1] == 254
}

/// Classify a single candidate addr given the client's local subnets.
///
/// `client_subnets` is the set of `(IpAddr, prefix_len)` pairs for the
/// client's own interfaces — used to detect "same subnet" for the top tier.
pub fn classify(addr: SocketAddr, client_subnets: &[(IpAddr, u8)]) -> CandidateClass {
    match addr.ip() {
        IpAddr::V4(v4) => {
            // Same-subnet trumps everything.
            if ip_in_any_subnet(IpAddr::V4(v4), client_subnets) {
                return CandidateClass::HostSameSubnet;
            }
            if is_rfc1918_v4(v4) {
                return CandidateClass::HostOtherRfc1918;
            }
            if is_cgnat_v4(v4) {
                return CandidateClass::HostVpnOverlay;
            }
            // Loopback / link-local / multicast / unspecified → treat as public-v4
            // (shouldn't see them as remote candidates; M1 filters loopback).
            // Anything else globally-routable.
            let _ = is_link_local_v4(v4);
            CandidateClass::HostPublicV4
        }
        IpAddr::V6(v6) => {
            // fe80::/10 — link-local
            let seg0 = v6.segments()[0];
            if (seg0 & 0xffc0) == 0xfe80 {
                return CandidateClass::HostLinkLocalV6;
            }
            // ULA fc00::/7 and global v6 both → priority 200 in v0.32.
            CandidateClass::HostOtherRfc1918
        }
    }
}

/// Build a priority-ranked candidate list from raw inputs.
///
/// Sorted descending by priority. Same-priority candidates retain input order
/// (stable sort).
pub fn prioritize(
    host_candidates: &[SocketAddr],
    srflx: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    client_subnets: &[(IpAddr, u8)],
) -> Vec<RankedCandidate> {
    let mut out: Vec<RankedCandidate> = Vec::with_capacity(
        host_candidates.len() + srflx.is_some() as usize + relay.is_some() as usize,
    );
    for addr in host_candidates {
        let class = classify(*addr, client_subnets);
        out.push(RankedCandidate {
            addr: *addr,
            class,
            priority: class.priority(),
        });
    }
    if let Some(addr) = srflx {
        out.push(RankedCandidate {
            addr,
            class: CandidateClass::ServerReflexive,
            priority: CandidateClass::ServerReflexive.priority(),
        });
    }
    if let Some(addr) = relay {
        out.push(RankedCandidate {
            addr,
            class: CandidateClass::Relay,
            priority: CandidateClass::Relay.priority(),
        });
    }
    // Stable sort descending by priority.
    out.sort_by_key(|c| std::cmp::Reverse(c.priority));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn sa4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    fn sa6(s: &str, port: u16) -> SocketAddr {
        let ip: Ipv6Addr = s.parse().unwrap();
        SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
    }

    // ---------- Test 1 ----------
    #[test]
    fn same_subnet_v4_gets_priority_250() {
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 170, 3, 5)), 24u8)];
        let cand = sa4(10, 170, 3, 111, 23095);
        assert_eq!(
            classify(cand, &client_subnets),
            CandidateClass::HostSameSubnet
        );
        assert_eq!(CandidateClass::HostSameSubnet.priority(), 250);
    }

    // ---------- Test 2 ----------
    #[test]
    fn other_rfc1918_v4_outside_client_subnet_gets_priority_200() {
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 24u8)];
        let cand = sa4(192, 168, 1, 5, 23095);
        assert_eq!(
            classify(cand, &client_subnets),
            CandidateClass::HostOtherRfc1918
        );
        assert_eq!(CandidateClass::HostOtherRfc1918.priority(), 200);
    }

    // ---------- Test 3 ----------
    #[test]
    fn tailscale_100_64_gets_priority_180_vpn_overlay() {
        let cand = sa4(100, 64, 1, 5, 23095);
        assert_eq!(classify(cand, &[]), CandidateClass::HostVpnOverlay);
        assert_eq!(CandidateClass::HostVpnOverlay.priority(), 180);
    }

    // ---------- Test 4 ----------
    #[test]
    fn public_v4_gets_priority_160() {
        let cand = sa4(1, 2, 3, 4, 23095);
        assert_eq!(classify(cand, &[]), CandidateClass::HostPublicV4);
        assert_eq!(CandidateClass::HostPublicV4.priority(), 160);
    }

    // ---------- Test 5 ----------
    #[test]
    fn ipv6_link_local_fe80_gets_priority_140() {
        let cand = sa6("fe80::1", 23095);
        assert_eq!(classify(cand, &[]), CandidateClass::HostLinkLocalV6);
        assert_eq!(CandidateClass::HostLinkLocalV6.priority(), 140);
    }

    // ---------- Test 6 ----------
    #[test]
    fn prioritize_orders_descending_by_priority() {
        let host = vec![
            sa4(10, 0, 0, 5, 23095),    // same-subnet → 250
            sa4(192, 168, 1, 5, 23095), // other rfc1918 → 200
            sa4(1, 2, 3, 4, 23095),     // public → 160
        ];
        let srflx = Some(sa4(8, 8, 8, 8, 23095));
        let relay = Some(sa4(34, 218, 240, 106, 23095));
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 24u8)];

        let ranked = prioritize(&host, srflx, relay, &client_subnets);
        assert_eq!(ranked.len(), 5);
        assert_eq!(ranked[0].addr, sa4(10, 0, 0, 5, 23095));
        assert_eq!(ranked[0].priority, 250);
        assert_eq!(ranked[1].addr, sa4(192, 168, 1, 5, 23095));
        assert_eq!(ranked[1].priority, 200);
        assert_eq!(ranked[2].addr, sa4(1, 2, 3, 4, 23095));
        assert_eq!(ranked[2].priority, 160);
        assert_eq!(ranked[3].addr, sa4(8, 8, 8, 8, 23095));
        assert_eq!(ranked[3].priority, 100);
        assert_eq!(ranked[4].addr, sa4(34, 218, 240, 106, 23095));
        assert_eq!(ranked[4].priority, 50);
    }

    // ---------- Test 7 ----------
    #[test]
    fn prioritize_preserves_input_order_for_same_priority() {
        let host = vec![sa4(10, 0, 0, 1, 23095), sa4(10, 0, 0, 2, 23095)];
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 24u8)];
        let ranked = prioritize(&host, None, None, &client_subnets);
        assert_eq!(ranked.len(), 2);
        // Both same-subnet → both priority 250 → input order preserved.
        assert_eq!(ranked[0].addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ranked[1].addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(ranked[0].priority, 250);
        assert_eq!(ranked[1].priority, 250);
    }

    // ---------- Test 8 ----------
    #[test]
    fn prioritize_empty_inputs_returns_empty_vec() {
        let ranked = prioritize(&[], None, None, &[]);
        assert!(ranked.is_empty());
    }

    // ---------- Test 9 ----------
    #[test]
    fn prioritize_handles_only_relay() {
        let relay = Some(sa4(34, 218, 240, 106, 23095));
        let ranked = prioritize(&[], None, relay, &[]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].class, CandidateClass::Relay);
        assert_eq!(ranked[0].priority, 50);
        assert_eq!(ranked[0].addr, sa4(34, 218, 240, 106, 23095));
    }

    // ---------- Test 10 ----------
    #[test]
    fn same_subnet_match_handles_class_a_prefix_8() {
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 8u8)];
        let cand = sa4(10, 255, 255, 255, 23095);
        assert_eq!(
            classify(cand, &client_subnets),
            CandidateClass::HostSameSubnet
        );
    }

    // ---------- Test 11 ----------
    #[test]
    fn subnet_mismatch_handles_class_c_boundary() {
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 24u8)];
        let cand = sa4(192, 168, 2, 5, 23095);
        let class = classify(cand, &client_subnets);
        assert_ne!(class, CandidateClass::HostSameSubnet);
        assert_eq!(class, CandidateClass::HostOtherRfc1918);
    }

    // ---------- Test 12 ----------
    #[test]
    fn prefix_zero_matches_everything() {
        let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0u8)];
        let cand = sa4(1, 2, 3, 4, 23095);
        assert_eq!(
            classify(cand, &client_subnets),
            CandidateClass::HostSameSubnet
        );
    }

    // ---------- Test 13 ----------
    #[test]
    fn ipv6_global_gets_other_rfc1918_equivalent_priority() {
        let cand = sa6("2001:db8::1", 23095);
        assert_eq!(classify(cand, &[]), CandidateClass::HostOtherRfc1918);
        assert_eq!(classify(cand, &[]).priority(), 200);
    }

    // ---------- Test 14 ----------
    #[test]
    fn ipv6_ula_gets_other_rfc1918_equivalent_priority() {
        let cand = sa6("fd12:3456::1", 23095);
        assert_eq!(classify(cand, &[]), CandidateClass::HostOtherRfc1918);
        assert_eq!(classify(cand, &[]).priority(), 200);
    }

    // ---------- Test 15 ----------
    #[test]
    fn ip_in_subnet_v4_basic_math() {
        // 10.0.0.5 in 10.0.0.0/24 → true
        assert!(ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            24
        ));
        // 10.0.1.5 in 10.0.0.0/24 → false
        assert!(!ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            24
        ));
        // 10.0.0.5 in 10.0.0.0/8 → true
        assert!(ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8
        ));
        // /32 exact match
        assert!(ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            32
        ));
        // /32 mismatch
        assert!(!ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
            32
        ));
        // /0 always true
        assert!(ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0
        ));
    }
}
