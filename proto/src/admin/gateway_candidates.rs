//! `ztlp gateway candidates <name>` — pretty-printers (v0.32 M7).
//!
//! Closes the v0.31 debugging gap (documented in
//! `docs/v0.31.0-relay-deployment-investigation.md`) where it took two
//! days to realise NS only had the WAN address for Z2LS. With this
//! command an operator can see the full candidate set in 5 seconds.
//!
//! This module is intentionally pure: NS lookup + classification happens
//! in the CLI handler, then the resulting `(name, node_id, Vec<RankedCandidate>)`
//! is handed to one of the formatters here. That keeps the unit tests
//! socket-free.
//!
//! ## Output shape (table mode)
//!
//! ```text
//! Gateway: z2ls (node_id: 6d82769c38054da6...)
//!
//! Candidates:
//!   PRIO  CLASS  ADDR
//!   200   host   10.170.3.111:23095
//!   100   srflx  204.16.122.24:55712
//! ```
//!
//! ## Output shape (JSON mode)
//!
//! ```json
//! {
//!   "gateway": "z2ls",
//!   "node_id": "6d82769c38054da6...",
//!   "candidates": [
//!     {"priority": 200, "class": "HostOtherRfc1918", "addr": "10.170.3.111:23095"}
//!   ]
//! }
//! ```

use crate::candidate_priority::{CandidateClass, RankedCandidate};
use crate::identity::NodeId;

/// Short, lowercase, operator-friendly name for a candidate class.
///
/// Maps the 7 v0.32 priority tiers down onto the three buckets an
/// operator usually cares about:
///
/// - `host`  — any directly-routable host candidate (same-subnet, other
///   RFC1918, public-v4, VPN overlay, IPv6 link-local).
/// - `srflx` — NS-observed server-reflexive (NAT'd public).
/// - `relay` — relay backstop.
pub fn class_short_name(class: CandidateClass) -> &'static str {
    match class {
        CandidateClass::HostSameSubnet
        | CandidateClass::HostOtherRfc1918
        | CandidateClass::HostVpnOverlay
        | CandidateClass::HostPublicV4
        | CandidateClass::HostLinkLocalV6 => "host",
        CandidateClass::ServerReflexive => "srflx",
        CandidateClass::Relay => "relay",
        CandidateClass::Loopback => "lo",
    }
}

/// Truncate a hex node_id to its first 16 hex chars + `…`-style ellipsis.
///
/// We use ASCII `"..."` rather than `…` so the output is grep-friendly
/// on legacy terminals. Anything shorter than 16 chars is returned
/// verbatim (defensive — `NodeId` Display always produces 32).
fn truncate_node_id(node_id_hex: &str) -> String {
    if node_id_hex.len() <= 16 {
        node_id_hex.to_string()
    } else {
        format!("{}...", &node_id_hex[..16])
    }
}

/// Format candidates as a human-readable table.
///
/// Sorts input descending by priority (stable for equal priorities) so
/// the operator always sees the "best" path first.
pub fn format_candidates_table(
    name: &str,
    node_id: &NodeId,
    candidates: &[RankedCandidate],
) -> String {
    let node_id_hex = node_id.to_string();
    let node_id_short = truncate_node_id(&node_id_hex);

    let mut out = String::new();
    out.push_str(&format!("Gateway: {} (node_id: {})\n", name, node_id_short));
    out.push('\n');

    if candidates.is_empty() {
        out.push_str("No candidates known for this gateway.\n");
        return out;
    }

    // Sort a local copy descending by priority. Stable sort preserves
    // input order for equal priorities (matches `prioritize()`).
    let mut sorted: Vec<&RankedCandidate> = candidates.iter().collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));

    // Build rows so we can compute column widths in one pass.
    let header = ["PRIO", "CLASS", "ADDR"];
    let rows: Vec<[String; 3]> = sorted
        .iter()
        .map(|c| {
            [
                c.priority.to_string(),
                class_short_name(c.class).to_string(),
                c.addr.to_string(),
            ]
        })
        .collect();

    // Column widths = max(header_len, max row cell len).
    let mut widths = [header[0].len(), header[1].len(), header[2].len()];
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    out.push_str("Candidates:\n");
    // Header
    out.push_str(&format!(
        "  {:<w0$}  {:<w1$}  {:<w2$}\n",
        header[0],
        header[1],
        header[2],
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
    ));
    // Data rows
    for r in &rows {
        out.push_str(&format!(
            "  {:<w0$}  {:<w1$}  {:<w2$}\n",
            r[0],
            r[1],
            r[2],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
        ));
    }

    out
}

/// Format candidates as machine-readable JSON (pretty-printed).
///
/// Shape:
/// ```json
/// {
///   "gateway": "<name>",
///   "node_id": "<hex>",
///   "candidates": [
///     {"priority": 200, "class": "HostOtherRfc1918", "addr": "10.170.3.111:23095"}
///   ]
/// }
/// ```
///
/// The `class` field uses the full Rust variant name (e.g.
/// `HostOtherRfc1918`) so machine consumers can reverse-map onto the
/// priority ladder without ambiguity. The human table uses
/// `class_short_name()` instead.
pub fn format_candidates_json(
    name: &str,
    node_id: &NodeId,
    candidates: &[RankedCandidate],
) -> String {
    // Sort descending by priority for stable output ordering.
    let mut sorted: Vec<&RankedCandidate> = candidates.iter().collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));

    let arr: Vec<serde_json::Value> = sorted
        .iter()
        .map(|c| {
            serde_json::json!({
                "priority": c.priority,
                "class": format!("{:?}", c.class),
                "addr": c.addr.to_string(),
            })
        })
        .collect();

    let obj = serde_json::json!({
        "gateway": name,
        "node_id": node_id.to_string(),
        "candidates": arr,
    });

    serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

    fn sa4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    fn nid(byte: u8) -> NodeId {
        NodeId([byte; 16])
    }

    fn cand(addr: SocketAddr, class: CandidateClass) -> RankedCandidate {
        RankedCandidate {
            addr,
            class,
            priority: class.priority(),
        }
    }

    // ---------- Test 1 ----------
    /// Empty input → output explicitly tells the operator "no candidates"
    /// instead of just printing the header. (Behavioural assertion so we
    /// don't silently regress to a bare-header surprise.)
    #[test]
    fn format_table_empty_candidates_prints_no_candidates() {
        let out = format_candidates_table("z2ls", &nid(0x6d), &[]);
        assert!(
            out.contains("No candidates known"),
            "expected 'No candidates known' in output, got:\n{}",
            out,
        );
        // Header line still present so operators know which gateway was queried.
        assert!(out.contains("Gateway: z2ls"));
    }

    // ---------- Test 2 ----------
    /// Single candidate → header row + exactly one data row, both
    /// containing the data we passed in.
    #[test]
    fn format_table_single_candidate_alignment() {
        let c = cand(sa4(10, 0, 0, 1, 23095), CandidateClass::HostOtherRfc1918);
        let out = format_candidates_table("z2ls", &nid(0x6d), &[c]);

        // Header columns must all be present.
        assert!(out.contains("PRIO"), "missing PRIO header");
        assert!(out.contains("CLASS"), "missing CLASS header");
        assert!(out.contains("ADDR"), "missing ADDR header");

        // Data row content.
        assert!(out.contains("200"), "missing priority 200");
        assert!(out.contains("host"), "missing 'host' class short-name");
        assert!(out.contains("10.0.0.1:23095"), "missing addr");

        // Sanity: exactly one PRIO header line + one data line under
        // "Candidates:". We assert by checking the data line exists
        // immediately after a header line via simple substring search:
        // the addr appears exactly once.
        assert_eq!(out.matches("10.0.0.1:23095").count(), 1);
    }

    // ---------- Test 3 ----------
    /// Multiple candidates supplied out of priority order → output rows
    /// must appear sorted descending by priority (250, 200, 100). We
    /// assert by checking each addr's index in the output string.
    #[test]
    fn format_table_multiple_candidates_sorted_by_priority_desc() {
        // Build subnet so 10.0.0.1 lands in HostSameSubnet (250).
        let _client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 24u8)];
        let c_low = cand(sa4(8, 8, 8, 8, 23095), CandidateClass::ServerReflexive); // 100
        let c_mid = cand(sa4(192, 168, 1, 5, 23095), CandidateClass::HostOtherRfc1918); // 200
        let c_high = cand(sa4(10, 0, 0, 1, 23095), CandidateClass::HostSameSubnet); // 250

        // Supplied in scrambled order.
        let out = format_candidates_table(
            "z2ls",
            &nid(0x6d),
            &[c_low.clone(), c_high.clone(), c_mid.clone()],
        );

        let i_high = out.find("10.0.0.1:23095").expect("missing high-prio addr");
        let i_mid = out
            .find("192.168.1.5:23095")
            .expect("missing mid-prio addr");
        let i_low = out.find("8.8.8.8:23095").expect("missing low-prio addr");

        assert!(
            i_high < i_mid && i_mid < i_low,
            "rows not sorted desc by priority:\n{}",
            out,
        );
    }

    // ---------- Test 4 ----------
    /// node_id display is truncated to 16 hex chars + "..." so 128-bit
    /// hex doesn't blow the header line.
    #[test]
    fn format_table_truncates_long_node_id_to_16_chars() {
        // NodeId([0x6d; 16]) → "6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d" (32 chars)
        let out = format_candidates_table("z2ls", &nid(0x6d), &[]);
        // First 16 chars present...
        assert!(
            out.contains("6d6d6d6d6d6d6d6d..."),
            "expected truncated node_id, got:\n{}",
            out,
        );
        // ...and the full 32-char hex is NOT present.
        assert!(
            !out.contains("6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d"),
            "full 32-char node_id leaked into output:\n{}",
            out,
        );
    }

    // ---------- Test 5 ----------
    /// JSON output basic shape: top-level fields + candidate fields.
    #[test]
    fn format_json_basic_shape() {
        let c = cand(sa4(10, 0, 0, 1, 23095), CandidateClass::HostOtherRfc1918);
        let raw = format_candidates_json("z2ls", &nid(0x6d), &[c]);
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

        assert_eq!(v["gateway"], "z2ls");
        assert!(v["node_id"].is_string());
        assert!(v["candidates"].is_array());

        let arr = v["candidates"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let c0 = &arr[0];
        assert_eq!(c0["priority"], 200);
        assert_eq!(c0["class"], "HostOtherRfc1918");
        assert_eq!(c0["addr"], "10.0.0.1:23095");
    }

    // ---------- Test 6 ----------
    /// Empty candidates list → valid JSON with `candidates: []`. We
    /// don't want an "(empty)" string or null sneaking in here because
    /// machine consumers branch on `len() == 0`.
    #[test]
    fn format_json_empty_candidates_returns_valid_json() {
        let raw = format_candidates_json("z2ls", &nid(0x6d), &[]);
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        assert_eq!(v["gateway"], "z2ls");
        let arr = v["candidates"].as_array().expect("candidates is array");
        assert!(arr.is_empty(), "expected empty array, got {:?}", arr);
    }

    // ---------- Test 7 ----------
    /// Table output uses the operator-friendly short class names
    /// ("host", "srflx", "relay") rather than the Rust variant names.
    /// This pins the class_short_name mapping for all 7 variants.
    #[test]
    fn format_table_includes_v0_32_priority_legend_or_class_names() {
        // One candidate per "bucket" — host / srflx / relay.
        let host = cand(sa4(10, 0, 0, 1, 23095), CandidateClass::HostOtherRfc1918);
        let srflx = cand(sa4(8, 8, 8, 8, 23095), CandidateClass::ServerReflexive);
        let relay = cand(sa4(34, 218, 240, 106, 23095), CandidateClass::Relay);
        let out = format_candidates_table("z2ls", &nid(0x6d), &[host, srflx, relay]);

        assert!(out.contains("host"), "missing 'host' short-name\n{}", out);
        assert!(out.contains("srflx"), "missing 'srflx' short-name\n{}", out);
        assert!(out.contains("relay"), "missing 'relay' short-name\n{}", out);

        // Also pin the full mapping at the unit level so refactors of
        // CandidateClass variants don't silently break short names.
        assert_eq!(class_short_name(CandidateClass::HostSameSubnet), "host");
        assert_eq!(class_short_name(CandidateClass::HostOtherRfc1918), "host");
        assert_eq!(class_short_name(CandidateClass::HostVpnOverlay), "host");
        assert_eq!(class_short_name(CandidateClass::HostPublicV4), "host");
        assert_eq!(class_short_name(CandidateClass::HostLinkLocalV6), "host");
        assert_eq!(class_short_name(CandidateClass::ServerReflexive), "srflx");
        assert_eq!(class_short_name(CandidateClass::Relay), "relay");
    }
}
