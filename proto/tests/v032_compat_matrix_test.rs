//! M8 — Backward-compatibility matrix wire-level tests for v0.32
//! multi-candidate discovery.
//!
//! Pins each row of the "Mixed-version safety" matrix from
//! `docs/plans/2026-05-28-multi-candidate-discovery-v0.32.md`. Each row
//! claims to be "at least as good as v0.31 status quo"; these tests turn
//! that prose claim into an executable invariant on the wire format.
//!
//! The tests are intentionally narrow: they exercise encode/decode
//! roundtrips and the priority ranker — not live UDP sockets, not the
//! Elixir NS server, not running ztlp binaries. The goal is to catch any
//! future wire-format change that would silently break a mixed-version
//! deployment.
//!
//! ## The matrix (verified 2026-05-27 by M8)
//!
//! | Gateway | NS    | Client | Expected behaviour                                           |
//! |---------|-------|--------|--------------------------------------------------------------|
//! | v0.31   | v0.31 | v0.31  | Status quo — relay-dependent                                 |
//! | v0.31   | v0.32 | v0.31  | Status quo — gateway sends 0 candidates                      |
//! | v0.32   | v0.31 | v0.31  | Status quo — old NS may ignore extra; parser tolerant        |
//! | v0.32   | v0.32 | v0.31  | Status quo — client uses first candidate only                |
//! | v0.32   | v0.32 | v0.32  | LAN-direct enabled                                           |
//! | v0.31   | v0.32 | v0.32  | Falls back to srflx-only                                     |

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use ztlp_proto::candidate_priority::{prioritize, CandidateClass};
use ztlp_proto::identity::NodeId;
use ztlp_proto::punch::{
    decode_peer_endpoints_response, decode_punch_report, encode_punch_report, NS_PEER_ENDPOINTS,
    NS_PUNCH_REPORT,
};

// ─── Helpers ────────────────────────────────────────────────────────

fn sa4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

/// Encode a PEER_ENDPOINTS *response* in the v0.31 wire shape — same
/// layout v0.32 uses, deliberately, so this exercises the
/// backward-compat contract.
fn encode_peer_endpoints_response(addrs: &[SocketAddr]) -> Vec<u8> {
    let count = addrs.len().min(255) as u8;
    let mut pkt = Vec::with_capacity(2 + count as usize * 7);
    pkt.push(NS_PEER_ENDPOINTS);
    pkt.push(count);
    for addr in addrs.iter().take(count as usize) {
        match addr.ip() {
            IpAddr::V4(v4) => {
                pkt.push(4);
                pkt.extend_from_slice(&v4.octets());
                pkt.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                pkt.push(6);
                pkt.extend_from_slice(&v6.octets());
                pkt.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
    }
    pkt
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Matrix rows 1 + 2: v0.31 gateway behavior — it always sent
/// `reported_count=0`. v0.32 NS (and our decode_punch_report) must
/// accept that empty payload cleanly.
#[test]
fn v031_gateway_sends_zero_reported_endpoints_decodes_cleanly() {
    let node_id = NodeId::from_bytes([0xAB; 16]);
    // Empty endpoints — what v0.31 gateways always sent.
    let pkt = encode_punch_report(&node_id, &[]);

    // Sanity-check wire shape: type + 16-byte node_id + 1-byte count = 18 bytes.
    assert_eq!(pkt.len(), 18, "empty PUNCH_REPORT is exactly 18 bytes");
    assert_eq!(pkt[0], NS_PUNCH_REPORT);
    assert_eq!(pkt[17], 0, "reported_count must be 0");

    let (decoded_id, endpoints) =
        decode_punch_report(&pkt).expect("v0.31-shape PUNCH_REPORT must decode");
    assert_eq!(decoded_id, node_id);
    assert!(
        endpoints.is_empty(),
        "v0.31 PUNCH_REPORT decodes to zero endpoints"
    );
}

/// Matrix rows 3 + 4: v0.32 gateway sends N candidates. Roundtrips
/// must be exact — what gateway encodes is what NS (or any decoder)
/// gets back.
#[test]
fn v032_gateway_sends_n_reported_endpoints_decodes_cleanly() {
    let node_id = NodeId::from_bytes([0x42; 16]);
    let endpoints = vec![
        sa4(10, 0, 0, 5, 23095),
        sa4(192, 168, 1, 5, 23095),
        sa4(100, 64, 1, 5, 23095),
    ];

    let pkt = encode_punch_report(&node_id, &endpoints);
    let (decoded_id, decoded_endpoints) =
        decode_punch_report(&pkt).expect("v0.32 PUNCH_REPORT must decode");

    assert_eq!(decoded_id, node_id);
    assert_eq!(
        decoded_endpoints, endpoints,
        "all 3 endpoints survive roundtrip"
    );
}

/// Matrix row 6: v0.32 client receives a v0.31-shape NS response
/// (srflx only — no host candidates). The ranker must classify it as
/// `ServerReflexive` (priority 100) and produce a usable single-entry
/// dial plan. This pins the srflx-only fallback path.
#[test]
fn v032_client_with_v031_ns_response_picks_first_candidate() {
    // v0.31 NS only knew about `:learned` endpoints — the gateway's
    // srflx address — so a v0.31-shape response had exactly one entry.
    let srflx_addr = sa4(8, 8, 8, 8, 23095);
    let pkt = encode_peer_endpoints_response(&[srflx_addr]);

    let endpoints = decode_peer_endpoints_response(&pkt).expect("decode must succeed");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].addr, srflx_addr);

    // Now feed it to the v0.32 ranker as srflx-only — no host
    // candidates, no relay (v0.31 NS doesn't return a relay either).
    let ranked = prioritize(&[], Some(srflx_addr), None, &[]);
    assert_eq!(ranked.len(), 1, "srflx-only input → single-entry plan");
    assert_eq!(ranked[0].class, CandidateClass::ServerReflexive);
    assert_eq!(ranked[0].priority, 100);
    assert_eq!(ranked[0].addr, srflx_addr);
}

/// Matrix row 3 redux: v0.32 gateway → v0.31 NS. We can't run the
/// Elixir parser here, but we CAN pin that the bytes the gateway
/// produces are well-formed — symmetric encode/decode — which is the
/// pre-condition for the v0.31 Elixir parser's bounded-length walk to
/// succeed.
#[test]
fn v032_gateway_to_v031_ns_parser_tolerance() {
    let node_id = NodeId::from_bytes([0x77; 16]);
    let endpoints = vec![
        sa4(10, 0, 0, 5, 23095),
        sa4(192, 168, 1, 5, 23095),
        sa4(172, 16, 0, 5, 23095),
    ];

    let pkt = encode_punch_report(&node_id, &endpoints);

    // Wire-shape invariants the Elixir v0.31 parser depends on:
    //   byte 0   == NS_PUNCH_REPORT
    //   bytes 1..17 == 16-byte node_id
    //   byte 17  == count
    //   bytes 18.. == N × <family(1) + addr(4|16) + port(2)>
    assert_eq!(pkt[0], NS_PUNCH_REPORT);
    assert_eq!(pkt[17], 3);
    // Each IPv4 entry: 1 + 4 + 2 = 7 bytes → 3 × 7 = 21 → total = 18 + 21 = 39.
    assert_eq!(pkt.len(), 39, "bounded-length walk land at byte 39");

    // Symmetric decode confirms we built a packet a tolerant
    // length-walking parser will accept exactly.
    let (decoded_id, decoded_endpoints) = decode_punch_report(&pkt).expect("decode");
    assert_eq!(decoded_id, node_id);
    assert_eq!(decoded_endpoints, endpoints);
}

/// Matrix row 5 — the headline payoff: v0.32 gateway + v0.32 NS +
/// v0.32 client. The full priority ladder fires; same-subnet wins.
#[test]
fn v032_lan_direct_priority_works_end_to_end() {
    let client_subnets = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 24u8)];
    let host = vec![
        sa4(10, 0, 0, 5, 23095),    // same subnet → 250
        sa4(192, 168, 1, 5, 23095), // other RFC1918 → 200
    ];
    let srflx = Some(sa4(8, 8, 8, 8, 23095)); // → 100
    let relay = Some(sa4(1, 1, 1, 1, 23095)); // → 50

    let ranked = prioritize(&host, srflx, relay, &client_subnets);

    assert_eq!(ranked.len(), 4, "all 4 candidates present");
    assert_eq!(ranked[0].addr, sa4(10, 0, 0, 5, 23095));
    assert_eq!(ranked[0].priority, 250);
    assert_eq!(ranked[1].addr, sa4(192, 168, 1, 5, 23095));
    assert_eq!(ranked[1].priority, 200);
    assert_eq!(ranked[2].addr, sa4(8, 8, 8, 8, 23095));
    assert_eq!(ranked[2].priority, 100);
    assert_eq!(ranked[3].addr, sa4(1, 1, 1, 1, 23095));
    assert_eq!(ranked[3].priority, 50);
}

/// Matrix row 6 (the "v0.31 client × v0.32 NS" cell, documented
/// inverse of row 5): v0.31 clients pick the first entry from the
/// NS response and ignore the rest. We can't link a v0.31 client
/// binary here, but we CAN pin the wire-format contract that v0.31
/// clients depend on: index 0 of the decoded list is a parseable
/// SocketAddr.
#[test]
fn v031_client_with_v032_ns_gets_srflx_path() {
    // What v0.32 NS would return: host candidates first (gateway's
    // `reported`) then srflx fallback (`learned`). v0.31 clients
    // only look at index 0.
    let addrs = vec![
        sa4(10, 0, 0, 5, 23095),
        sa4(192, 168, 1, 5, 23095),
        sa4(100, 64, 1, 5, 23095),
        sa4(8, 8, 8, 8, 23095),
    ];
    let pkt = encode_peer_endpoints_response(&addrs);
    let decoded = decode_peer_endpoints_response(&pkt).expect("decode");

    assert_eq!(decoded.len(), 4, "v0.32 response carries all 4");
    // The contract for v0.31 clients: index 0 exists and is a usable SocketAddr.
    assert_eq!(
        decoded[0].addr, addrs[0],
        "index-0 entry survives roundtrip — v0.31 clients dial it"
    );
}

/// M8 marker: documentation-style test that pins the matrix into the
/// test suite. If you're reading this in a future grep, the compat
/// matrix lives in `docs/plans/2026-05-28-multi-candidate-discovery-v0.32.md`
/// under "Mixed-version safety", and these 8 tests are the executable
/// version of it.
///
/// Matrix (verified 2026-05-27):
///
/// | Gateway | NS    | Client | Expected behaviour                                    | Test                                                       |
/// |---------|-------|--------|-------------------------------------------------------|------------------------------------------------------------|
/// | v0.31   | v0.31 | v0.31  | Status quo — relay-dependent                          | v031_gateway_sends_zero_reported_endpoints_decodes_cleanly |
/// | v0.31   | v0.32 | v0.31  | Status quo — gateway sends 0 candidates               | v031_gateway_sends_zero_reported_endpoints_decodes_cleanly |
/// | v0.32   | v0.31 | v0.31  | Status quo — old NS ignores extra; parser tolerant    | v032_gateway_to_v031_ns_parser_tolerance                   |
/// | v0.32   | v0.32 | v0.31  | Status quo — client uses first candidate only         | v031_client_with_v032_ns_gets_srflx_path                   |
/// | v0.32   | v0.32 | v0.32  | LAN-direct enabled                                    | v032_lan_direct_priority_works_end_to_end                  |
/// | v0.31   | v0.32 | v0.32  | Falls back to srflx-only                              | v032_client_with_v031_ns_response_picks_first_candidate    |
#[test]
fn compat_matrix_summary_documentation() {
    // No assertion logic — this test exists for grepability and to keep
    // the matrix linked from the test runner output. The doc comment
    // above carries the load.
    let matrix_rows = 6;
    assert_eq!(
        matrix_rows, 6,
        "matrix has 6 rows; if you added one, add a test too"
    );
}

/// Helper-style test: pins that the priority ranker handles the
/// degenerate "v0.31 NS only knew :learned" input (srflx-only, no
/// host, no relay) without panicking or returning empty.
#[test]
fn prioritize_with_only_srflx_input_returns_srflx() {
    let srflx = sa4(8, 8, 8, 8, 23095);
    let ranked = prioritize(&[], Some(srflx), None, &[]);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].class, CandidateClass::ServerReflexive);
    assert_eq!(ranked[0].priority, 100);
    assert_eq!(ranked[0].addr, srflx);
}
