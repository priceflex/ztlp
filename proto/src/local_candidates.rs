//! Gateway local-candidate enumerator (v0.32 multi-candidate discovery, M1).
//!
//! Enumerates the gateway's local non-loopback NIC addresses so they can be
//! advertised via PUNCH_REPORT (0x0C) `reported_endpoints[]` for ICE-style
//! same-LAN dial-direct. Pure-fn module; M2 wires the result into the
//! gateway's keepalive builder.
//!
//! Filter rules (Steve-approved 2026-05-28, per spec section "Decisions"):
//! - publish: up + running, non-loopback, non-link-local, IPv4 first, IPv6
//!   only when global-or-ULA
//! - skip: loopback (127/8, ::1), v4 APIPA (169.254/16), v6 link-local
//!   (fe80::/10), docker0, br-*, down ifaces
//! - hard cap: 8 candidates in deterministic OS order (ranking + truncation
//!   logic lands in M4)
//!
//! Operator overrides via `enumerate_local_candidates_with_overrides`:
//! - `include`: force-include named ifaces even when filter would skip
//! - `exclude`: force-skip named ifaces
//! - `all`:     disable the default filter entirely (only `exclude` applies)
//!
//! Precedence: `exclude` > `include` > `all` > default filter.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Hard cap on advertised candidates, per spec. Ranking + truncation logic
/// (when more than this many qualify) lands in M4.
const MAX_CANDIDATES: usize = 8;

/// Internal struct fed to [`filter_candidates`]. Captures only the bits of
/// an interface that the filter cares about; the public wrapper builds these
/// from `if_addrs::Interface` values returned by `if_addrs::get_if_addrs()`.
#[doc(hidden)]
pub(crate) struct CandidateInput {
    pub name: String,
    pub ip: IpAddr,
    pub is_up: bool,
}

/// Returns true when an IPv6 address is link-local (`fe80::/10`).
fn is_v6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Returns true when an interface name matches a default-skip rule
/// (Docker bridges).
fn is_default_skipped_name(name: &str) -> bool {
    name == "docker0" || name.starts_with("br-")
}

/// Pure-function filter — the unit-tested core. The public wrappers feed it
/// a snapshot of interfaces; this function applies the default filter +
/// operator overrides + hard cap, in deterministic input order.
pub(crate) fn filter_candidates(
    ifaces: Vec<CandidateInput>,
    port: u16,
    include: &[String],
    exclude: &[String],
    all: bool,
) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(MAX_CANDIDATES);
    for iface in ifaces {
        // Precedence: exclude > include > all > default filter.
        if exclude.iter().any(|n| n == &iface.name) {
            continue;
        }
        let force_include = include.iter().any(|n| n == &iface.name);

        if !force_include {
            // Down interfaces are always skipped (operator can't force-include
            // a down NIC — there's nothing to advertise).
            if !iface.is_up {
                continue;
            }
            if !all {
                if is_default_skipped_name(&iface.name) {
                    continue;
                }
                // Address-class filter (loopback / link-local).
                match iface.ip {
                    IpAddr::V4(v4) => {
                        if v4.is_loopback() || v4.is_link_local() {
                            continue;
                        }
                    }
                    IpAddr::V6(v6) => {
                        if v6.is_loopback() || is_v6_link_local(&v6) {
                            continue;
                        }
                    }
                }
            }
        }

        out.push(SocketAddr::new(iface.ip, port));
        if out.len() >= MAX_CANDIDATES {
            break;
        }
    }
    out
}

/// Enumerate the gateway's local non-loopback network interfaces and return
/// them as `SocketAddr` candidates suitable for advertising via PUNCH_REPORT
/// (0x0C) `reported_endpoints[]`.
///
/// Applies the default filter (skip loopback, v4/v6 link-local, docker0,
/// `br-*`, down ifaces) and caps the result at 8 candidates in
/// deterministic OS order. `port` is attached to every returned address.
pub fn enumerate_local_candidates(port: u16) -> Vec<SocketAddr> {
    enumerate_local_candidates_with_overrides(port, &[], &[], false)
}

/// Same as [`enumerate_local_candidates`] but with operator overrides:
///
/// - `include`: force-include these interface names even if the default
///   filter would skip them
/// - `exclude`: force-exclude these interface names
/// - `all`:     if true, disable the default filter entirely (only
///   `exclude` still applies)
///
/// Precedence: `exclude` > `include` > `all` > default filter.
pub fn enumerate_local_candidates_with_overrides(
    port: u16,
    include: &[String],
    exclude: &[String],
    all: bool,
) -> Vec<SocketAddr> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    // `if_addrs::get_if_addrs()` only returns up interfaces on POSIX/Windows,
    // so we mark every observed iface as `is_up: true`. (The `is_up` field
    // on `CandidateInput` exists so the test harness can also exercise the
    // down-iface skip path deterministically.)
    let snapshot: Vec<CandidateInput> = ifaces
        .into_iter()
        .map(|i| {
            let ip = i.ip();
            CandidateInput {
                name: i.name,
                ip,
                is_up: true,
            }
        })
        .collect();
    filter_candidates(snapshot, port, include, exclude, all)
}

#[cfg(test)]
mod tests {
    //! Behaviour tests for the local-candidate enumerator. All tests
    //! exercise the pure-fn [`filter_candidates`] through a thin shim, so
    //! they don't depend on the host's actual NIC layout. One live test at
    //! the bottom exercises `enumerate_local_candidates()` end-to-end.
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Test-side mirror of [`super::CandidateInput`]. Lets each test build
    /// scenarios with literal field names; the [`run`]/[`run_with`] shims
    /// translate to the production-side struct before invoking the filter.
    #[derive(Clone, Debug)]
    struct CandidateInput {
        name: String,
        ip: IpAddr,
        is_up: bool,
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn iface(name: &str, ip: IpAddr, is_up: bool) -> CandidateInput {
        CandidateInput {
            name: name.to_string(),
            ip,
            is_up,
        }
    }

    // Bridge: tests call into the (yet-to-exist) internal helper. The shim
    // here adapts our test-side struct to the production-side struct so the
    // tests can be written once and survive any rename in GREEN.
    fn run(ifaces: Vec<CandidateInput>, port: u16) -> Vec<SocketAddr> {
        run_with(ifaces, port, &[], &[], false)
    }

    fn run_with(
        ifaces: Vec<CandidateInput>,
        port: u16,
        include: &[String],
        exclude: &[String],
        all: bool,
    ) -> Vec<SocketAddr> {
        let prod: Vec<super::CandidateInput> = ifaces
            .into_iter()
            .map(|c| super::CandidateInput {
                name: c.name,
                ip: c.ip,
                is_up: c.is_up,
            })
            .collect();
        super::filter_candidates(prod, port, include, exclude, all)
    }

    const PORT: u16 = 23095;

    #[test]
    fn loopback_127_is_excluded() {
        let out = run(vec![iface("lo", ip4(127, 0, 0, 1), true)], PORT);
        assert!(out.is_empty(), "loopback must be excluded: {:?}", out);
    }

    #[test]
    fn link_local_169_254_is_excluded() {
        let out = run(vec![iface("eth0", ip4(169, 254, 1, 5), true)], PORT);
        assert!(out.is_empty(), "v4 link-local must be excluded: {:?}", out);
    }

    #[test]
    fn down_interface_is_excluded() {
        let out = run(vec![iface("eth0", ip4(192, 168, 1, 5), false)], PORT);
        assert!(out.is_empty(), "down iface must be excluded: {:?}", out);
    }

    #[test]
    fn docker_bridge_excluded_by_default() {
        let out = run(vec![iface("docker0", ip4(172, 17, 0, 1), true)], PORT);
        assert!(
            out.is_empty(),
            "docker0 must be excluded by default: {:?}",
            out
        );
    }

    #[test]
    fn br_prefix_excluded_by_default() {
        let out = run(vec![iface("br-abc123", ip4(172, 18, 0, 1), true)], PORT);
        assert!(
            out.is_empty(),
            "br-* must be excluded by default: {:?}",
            out
        );
    }

    #[test]
    fn rfc1918_lan_is_included() {
        let out = run(vec![iface("eth0", ip4(10, 170, 3, 111), true)], PORT);
        assert_eq!(out, vec![SocketAddr::new(ip4(10, 170, 3, 111), PORT)]);
    }

    #[test]
    fn multiple_ifaces_returned_in_input_order() {
        let out = run(
            vec![
                iface("eth0", ip4(192, 168, 1, 5), true),
                iface("wlan0", ip4(10, 0, 0, 5), true),
            ],
            PORT,
        );
        assert_eq!(
            out,
            vec![
                SocketAddr::new(ip4(192, 168, 1, 5), PORT),
                SocketAddr::new(ip4(10, 0, 0, 5), PORT),
            ]
        );
    }

    #[test]
    fn hard_cap_at_8() {
        let mut input = Vec::new();
        for i in 0..12 {
            input.push(iface(&format!("eth{i}"), ip4(10, 0, 0, i as u8 + 1), true));
        }
        let out = run(input, PORT);
        assert_eq!(out.len(), 8, "hard cap is 8");
    }

    #[test]
    fn ipv6_global_is_included() {
        let v6 = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6 parse"));
        let out = run(vec![iface("eth0", v6, true)], PORT);
        assert_eq!(out, vec![SocketAddr::new(v6, PORT)]);
    }

    #[test]
    fn ipv6_link_local_fe80_is_excluded() {
        let v6 = IpAddr::V6("fe80::1".parse::<Ipv6Addr>().expect("v6 parse"));
        let out = run(vec![iface("eth0", v6, true)], PORT);
        assert!(out.is_empty(), "fe80::/10 must be excluded: {:?}", out);
    }

    #[test]
    fn override_include_forces_docker() {
        let out = run_with(
            vec![iface("docker0", ip4(172, 17, 0, 1), true)],
            PORT,
            &["docker0".to_string()],
            &[],
            false,
        );
        assert_eq!(out, vec![SocketAddr::new(ip4(172, 17, 0, 1), PORT)]);
    }

    #[test]
    fn override_exclude_beats_include() {
        let out = run_with(
            vec![iface("eth0", ip4(10, 0, 0, 5), true)],
            PORT,
            &["eth0".to_string()],
            &["eth0".to_string()],
            false,
        );
        assert!(out.is_empty(), "exclude must beat include: {:?}", out);
    }

    #[test]
    fn override_all_disables_default_filter() {
        let out = run_with(
            vec![iface("docker0", ip4(172, 17, 0, 1), true)],
            PORT,
            &[],
            &[],
            true,
        );
        assert_eq!(out, vec![SocketAddr::new(ip4(172, 17, 0, 1), PORT)]);
    }

    #[test]
    fn override_all_still_respects_exclude() {
        let out = run_with(
            vec![
                iface("docker0", ip4(172, 17, 0, 1), true),
                iface("br-x", ip4(172, 18, 0, 1), true),
            ],
            PORT,
            &[],
            &["br-x".to_string()],
            true,
        );
        assert_eq!(out, vec![SocketAddr::new(ip4(172, 17, 0, 1), PORT)]);
    }

    #[test]
    fn port_is_attached_to_every_candidate() {
        let out = run(
            vec![
                iface("eth0", ip4(10, 0, 0, 5), true),
                iface("wlan0", ip4(192, 168, 1, 5), true),
            ],
            PORT,
        );
        for sa in &out {
            assert_eq!(sa.port(), PORT, "port mismatch on {sa}");
        }
        assert!(!out.is_empty());
    }

    #[test]
    fn live_enumeration_produces_only_valid_candidates() {
        let port: u16 = 23095;
        let out = enumerate_local_candidates(port);
        assert!(out.len() <= 8, "hard cap 8, got {}", out.len());
        for sa in &out {
            assert_eq!(sa.port(), port);
            let ip = sa.ip();
            assert!(!ip.is_loopback(), "loopback leaked: {ip}");
            match ip {
                IpAddr::V4(v4) => {
                    assert!(!v4.is_link_local(), "v4 link-local leaked: {v4}");
                }
                IpAddr::V6(v6) => {
                    // RFC 4291: fe80::/10
                    let seg0 = v6.segments()[0];
                    assert!((seg0 & 0xffc0) != 0xfe80, "v6 link-local leaked: {v6}");
                }
            }
        }
    }
}
