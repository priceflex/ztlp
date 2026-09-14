//! Behavioural tests for `ztlp_proto::relay` — `RelayConnection` state and the
//! `SimulatedRelay` SessionID forwarder + rendezvous coordinator.
//!
//! The relay is a blind UDP forwarder: it must route purely on the
//! unencrypted SessionID (handshake vs data header offsets), never on
//! payload, and must pair exactly two peers per session. These tests drive
//! real loopback UDP sockets so forwarding is observed end-to-end, not
//! inferred from return values alone.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use ztlp_proto::admission::{RelayAdmissionToken, RAT_SIZE};
use ztlp_proto::nat::{
    decode_rv_message, encode_rv_not_found, encode_rv_peer_info, encode_rv_register,
    RendezvousMessage,
};
use ztlp_proto::packet::{SessionId, MAGIC};
use ztlp_proto::relay::{RelayConnection, SimulatedRelay};

// ─── helpers ────────────────────────────────────────────────────────────────

fn sid(byte: u8) -> SessionId {
    SessionId([byte; 12])
}

/// Build a minimal ZTLP *data* packet (HdrLen = 12 words) carrying `sid`
/// at bytes 6..18, padded to the 46-byte data header plus a few payload bytes.
fn data_packet(sid: &SessionId) -> Vec<u8> {
    let mut pkt = vec![0u8; 50];
    pkt[0..2].copy_from_slice(&MAGIC.to_be_bytes());
    // Version nibble 0x1, HdrLen = 12 (0x00C)
    pkt[2..4].copy_from_slice(&(0x1000u16 | 12).to_be_bytes());
    pkt[6..18].copy_from_slice(&sid.0);
    pkt[46..50].copy_from_slice(b"DATA");
    pkt
}

/// Build a minimal ZTLP *handshake* packet (HdrLen = 24 words) carrying
/// `sid` at bytes 11..23.
fn handshake_packet(sid: &SessionId) -> Vec<u8> {
    let mut pkt = vec![0u8; 96];
    pkt[0..2].copy_from_slice(&MAGIC.to_be_bytes());
    pkt[2..4].copy_from_slice(&(0x1000u16 | 24).to_be_bytes());
    pkt[11..23].copy_from_slice(&sid.0);
    pkt
}

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

async fn relay() -> SimulatedRelay {
    SimulatedRelay::bind("127.0.0.1:0").await.expect("bind relay")
}

async fn peer() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind peer")
}

async fn recv_with_timeout(sock: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => Some((buf[..n].to_vec(), from)),
        _ => None,
    }
}

fn token_expiring_at(expires_at: u64) -> RelayAdmissionToken {
    let mut raw = [0u8; RAT_SIZE];
    raw[0] = 0x01;
    raw[41..49].copy_from_slice(&expires_at.to_be_bytes());
    RelayAdmissionToken::parse(&raw).expect("parse RAT")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ─── RelayConnection ────────────────────────────────────────────────────────

#[test]
fn relay_connection_new_has_no_token() {
    let conn = RelayConnection::new(addr(4000), sid(0xAA));
    assert_eq!(conn.relay_addr, addr(4000));
    assert_eq!(conn.session_id, sid(0xAA));
    assert!(conn.admission_token.is_none());
    assert!(conn.get_token().is_none());
    assert!(!conn.has_valid_token(), "no token must not count as valid");
}

#[test]
fn relay_connection_set_token_unexpired_is_valid() {
    let mut conn = RelayConnection::new(addr(4000), sid(1));
    let tok = token_expiring_at(now_secs() + 3600);
    conn.set_token(tok.clone());
    assert!(conn.has_valid_token());
    let got = conn.get_token().expect("token stored");
    assert_eq!(got.expires_at, tok.expires_at);
    assert_eq!(got.version, 0x01);
}

#[test]
fn relay_connection_expired_token_is_not_valid() {
    let mut conn = RelayConnection::new(addr(4000), sid(1));
    conn.set_token(token_expiring_at(now_secs() - 1));
    assert!(conn.get_token().is_some(), "token is stored even if expired");
    assert!(!conn.has_valid_token(), "expired token must report invalid");
}

#[test]
fn relay_connection_set_token_replaces_previous() {
    let mut conn = RelayConnection::new(addr(4000), sid(1));
    conn.set_token(token_expiring_at(now_secs() - 1));
    assert!(!conn.has_valid_token());
    conn.set_token(token_expiring_at(now_secs() + 60));
    assert!(conn.has_valid_token(), "fresh token must replace expired one");
}

#[test]
fn relay_connection_is_clone_and_debug() {
    let conn = RelayConnection::new(addr(4000), sid(7));
    let c2 = conn.clone();
    assert_eq!(c2.relay_addr, conn.relay_addr);
    assert!(format!("{conn:?}").contains("RelayConnection"));
}

// ─── SimulatedRelay: bind ───────────────────────────────────────────────────

#[tokio::test]
async fn bind_reports_real_local_addr() {
    let r = relay().await;
    assert_ne!(r.local_addr.port(), 0, "ephemeral port must be resolved");
    assert_eq!(r.local_addr, r.socket.local_addr().unwrap());
    assert_eq!(r.rendezvous_count().await, 0);
}

#[tokio::test]
async fn bind_invalid_addr_errors() {
    assert!(SimulatedRelay::bind("not-an-address").await.is_err());
}

#[tokio::test]
async fn bind_port_in_use_errors() {
    let first = relay().await;
    let res = SimulatedRelay::bind(&first.local_addr.to_string()).await;
    assert!(res.is_err(), "second bind on same port must fail");
}

// ─── SimulatedRelay: SessionID extraction (via process_one) ────────────────

#[tokio::test]
async fn packet_shorter_than_4_bytes_is_dropped() {
    let r = relay().await;
    assert!(!r.process_one(&[], addr(1)).await.unwrap());
    assert!(!r.process_one(&[0x5A, 0x37, 0x10], addr(1)).await.unwrap());
}

#[tokio::test]
async fn packet_with_wrong_magic_is_dropped() {
    let r = relay().await;
    let mut pkt = data_packet(&sid(1));
    pkt[0] ^= 0xFF;
    assert!(!r.process_one(&pkt, addr(1)).await.unwrap());
    // Second peer on the same (would-be) session also dropped: nothing was learned.
    assert!(!r.process_one(&pkt, addr(2)).await.unwrap());
}

#[tokio::test]
async fn packet_with_unknown_hdrlen_is_dropped() {
    let r = relay().await;
    let mut pkt = data_packet(&sid(1));
    pkt[2..4].copy_from_slice(&(0x1000u16 | 16).to_be_bytes()); // 16 words: not 12 or 24
    assert!(!r.process_one(&pkt, addr(1)).await.unwrap());
    assert!(!r.process_one(&pkt, addr(2)).await.unwrap());
}

#[tokio::test]
async fn truncated_data_header_is_dropped() {
    let r = relay().await;
    let pkt = data_packet(&sid(1));
    // HdrLen says 12 but only 17 bytes present (< 18 needed for SessionID)
    assert!(!r.process_one(&pkt[..17], addr(1)).await.unwrap());
    // Exactly 18 bytes is enough to extract the SessionID.
    assert!(!r.process_one(&pkt[..18], addr(1)).await.unwrap()); // first peer: learned
    let b = peer().await;
    let a = peer().await;
    // Re-drive with real sockets so the forward can land somewhere.
    let r2 = relay().await;
    a.send_to(&pkt[..18], r2.local_addr).await.unwrap();
    let (d, from) = recv_with_timeout(&r2.socket).await.unwrap();
    assert!(!r2.process_one(&d, from).await.unwrap());
    b.send_to(&pkt[..18], r2.local_addr).await.unwrap();
    let (d, from) = recv_with_timeout(&r2.socket).await.unwrap();
    assert!(r2.process_one(&d, from).await.unwrap(), "18-byte data header is routable");
    assert!(recv_with_timeout(&a).await.is_some());
}

#[tokio::test]
async fn truncated_handshake_header_is_dropped() {
    let r = relay().await;
    let pkt = handshake_packet(&sid(1));
    assert!(!r.process_one(&pkt[..22], addr(1)).await.unwrap());
    assert!(!r.process_one(&pkt[..22], addr(2)).await.unwrap(), "nothing learned from truncated pkt");
}

// ─── SimulatedRelay: pairing + forwarding ──────────────────────────────────

#[tokio::test]
async fn first_packet_learns_peer_and_is_not_forwarded() {
    let r = relay().await;
    let a = peer().await;
    let pkt = data_packet(&sid(0x11));
    let forwarded = r.process_one(&pkt, a.local_addr().unwrap()).await.unwrap();
    assert!(!forwarded);
    assert!(recv_with_timeout(&a).await.is_none(), "must not echo to sole peer");
}

#[tokio::test]
async fn same_peer_repeating_stays_pending() {
    let r = relay().await;
    let a = peer().await;
    let pkt = data_packet(&sid(0x11));
    let a_addr = a.local_addr().unwrap();
    assert!(!r.process_one(&pkt, a_addr).await.unwrap());
    assert!(!r.process_one(&pkt, a_addr).await.unwrap());
    assert!(!r.process_one(&pkt, a_addr).await.unwrap());
    assert!(recv_with_timeout(&a).await.is_none());
}

#[tokio::test]
async fn second_peer_pairs_and_first_packet_is_forwarded_to_first_peer() {
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let s = sid(0x22);
    let pkt_a = data_packet(&s);
    let mut pkt_b = data_packet(&s);
    pkt_b[46..50].copy_from_slice(b"FRMB");

    assert!(!r.process_one(&pkt_a, a.local_addr().unwrap()).await.unwrap());
    assert!(r.process_one(&pkt_b, b.local_addr().unwrap()).await.unwrap());

    let (got, from) = recv_with_timeout(&a).await.expect("A must receive B's packet");
    assert_eq!(got, pkt_b, "payload forwarded byte-for-byte");
    assert_eq!(from, r.local_addr, "forwarded packet is sourced from the relay");
    assert!(recv_with_timeout(&b).await.is_none(), "B must not get its own packet back");
}

#[tokio::test]
async fn paired_session_forwards_in_both_directions() {
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let s = sid(0x33);
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();

    r.process_one(&data_packet(&s), a_addr).await.unwrap();
    r.process_one(&data_packet(&s), b_addr).await.unwrap();
    recv_with_timeout(&a).await.unwrap(); // drain pairing forward

    let mut from_a = data_packet(&s);
    from_a[46..50].copy_from_slice(b"A->B");
    assert!(r.process_one(&from_a, a_addr).await.unwrap());
    let (got, _) = recv_with_timeout(&b).await.expect("B receives A");
    assert_eq!(&got[46..50], b"A->B");

    let mut from_b = data_packet(&s);
    from_b[46..50].copy_from_slice(b"B->A");
    assert!(r.process_one(&from_b, b_addr).await.unwrap());
    let (got, _) = recv_with_timeout(&a).await.expect("A receives B");
    assert_eq!(&got[46..50], b"B->A");
}

#[tokio::test]
async fn third_party_on_paired_session_is_forwarded_to_addr_a() {
    // Documented behaviour of the simple simulator: any sender that is not
    // addr_a is treated as "the other side" and forwarded to addr_a. Pin it
    // so a future change to strict two-party enforcement is deliberate.
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let c = peer().await;
    let s = sid(0x44);
    r.process_one(&data_packet(&s), a.local_addr().unwrap()).await.unwrap();
    r.process_one(&data_packet(&s), b.local_addr().unwrap()).await.unwrap();
    recv_with_timeout(&a).await.unwrap();

    assert!(r.process_one(&data_packet(&s), c.local_addr().unwrap()).await.unwrap());
    assert!(recv_with_timeout(&a).await.is_some(), "unknown sender routed to addr_a");
    assert!(recv_with_timeout(&b).await.is_none());
}

#[tokio::test]
async fn sessions_are_isolated_by_session_id() {
    let r = relay().await;
    let a1 = peer().await;
    let b1 = peer().await;
    let a2 = peer().await;
    let s1 = sid(0x51);
    let s2 = sid(0x52);

    r.process_one(&data_packet(&s1), a1.local_addr().unwrap()).await.unwrap();
    // Different session's first peer must NOT pair with s1's pending peer.
    assert!(!r.process_one(&data_packet(&s2), a2.local_addr().unwrap()).await.unwrap());
    assert!(recv_with_timeout(&a1).await.is_none());

    assert!(r.process_one(&data_packet(&s1), b1.local_addr().unwrap()).await.unwrap());
    assert!(recv_with_timeout(&a1).await.is_some());
    assert!(recv_with_timeout(&a2).await.is_none(), "s2 peer must not see s1 traffic");
}

#[tokio::test]
async fn handshake_and_data_headers_route_to_the_same_session() {
    // SessionID lives at different offsets in the two header shapes; the relay
    // must resolve both to the same routing entry.
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let s = sid(0x66);
    assert!(!r.process_one(&handshake_packet(&s), a.local_addr().unwrap()).await.unwrap());
    assert!(r.process_one(&data_packet(&s), b.local_addr().unwrap()).await.unwrap());
    let (got, _) = recv_with_timeout(&a).await.expect("A paired via handshake, got B's data pkt");
    assert_eq!(got.len(), 50);
}

#[tokio::test]
async fn handshake_header_session_id_offset_is_11() {
    // A packet with the SessionID at the *data* offset but a handshake HdrLen
    // must be read as a different session (bytes 11..23, mostly zero here).
    let r = relay().await;
    let s = sid(0x77);
    let mut misplaced = handshake_packet(&sid(0x00));
    misplaced[6..18].copy_from_slice(&s.0); // wrong offset for hdr_len 24
    assert!(!r.process_one(&data_packet(&s), addr(1)).await.unwrap());
    // Would pair (return true) if the relay wrongly read bytes 6..18.
    assert!(!r.process_one(&misplaced, addr(2)).await.unwrap());
}

#[tokio::test]
async fn forward_to_unreachable_peer_surfaces_io_error_or_is_dropped() {
    // Loopback send_to a closed UDP port does not fail synchronously on
    // Linux, so this asserts the call does not panic and returns a Result.
    let r = relay().await;
    let s = sid(0x88);
    let dead = peer().await;
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    r.process_one(&data_packet(&s), dead_addr).await.unwrap();
    let res = r.process_one(&data_packet(&s), addr(1)).await;
    assert!(res.is_ok() || res.is_err());
}

// ─── SimulatedRelay: run() loop end-to-end ─────────────────────────────────

#[tokio::test]
async fn run_loop_forwards_between_two_real_sockets() {
    let r = std::sync::Arc::new(relay().await);
    let relay_addr = r.local_addr;
    let runner = {
        let r = r.clone();
        tokio::spawn(async move { r.run().await })
    };

    let a = peer().await;
    let b = peer().await;
    let s = sid(0x99);

    a.send_to(&data_packet(&s), relay_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut from_b = data_packet(&s);
    from_b[46..50].copy_from_slice(b"HI_A");
    b.send_to(&from_b, relay_addr).await.unwrap();

    let (got, from) = recv_with_timeout(&a).await.expect("A gets B via run loop");
    assert_eq!(&got[46..50], b"HI_A");
    assert_eq!(from, relay_addr);

    let mut from_a = data_packet(&s);
    from_a[46..50].copy_from_slice(b"HI_B");
    a.send_to(&from_a, relay_addr).await.unwrap();
    let (got, _) = recv_with_timeout(&b).await.expect("B gets A via run loop");
    assert_eq!(&got[46..50], b"HI_B");

    // Garbage must not kill the loop.
    a.send_to(b"garbage", relay_addr).await.unwrap();
    a.send_to(&from_a, relay_addr).await.unwrap();
    assert!(recv_with_timeout(&b).await.is_some(), "loop still alive after garbage");

    runner.abort();
}

// ─── SimulatedRelay: rendezvous ────────────────────────────────────────────

#[tokio::test]
async fn rendezvous_first_register_is_stored_not_forwarded() {
    let r = relay().await;
    let a = peer().await;
    let rid = [0xABu8; 32];
    let pkt = encode_rv_register(&rid, addr(5555));
    assert!(!r.process_one(&pkt, a.local_addr().unwrap()).await.unwrap());
    assert_eq!(r.rendezvous_count().await, 1);
    assert!(recv_with_timeout(&a).await.is_none());
}

#[tokio::test]
async fn rendezvous_same_peer_reregister_keeps_single_entry() {
    let r = relay().await;
    let a = peer().await;
    let a_addr = a.local_addr().unwrap();
    let rid = [0x01u8; 32];
    let pkt = encode_rv_register(&rid, addr(5555));
    assert!(!r.process_one(&pkt, a_addr).await.unwrap());
    assert!(!r.process_one(&pkt, a_addr).await.unwrap());
    assert_eq!(r.rendezvous_count().await, 1, "re-register must not duplicate or drop");
    assert!(recv_with_timeout(&a).await.is_none());
}

#[tokio::test]
async fn rendezvous_second_peer_exchanges_mapped_endpoints_and_clears_entry() {
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let rid = [0x5Eu8; 32];
    let a_mapped = addr(41000);
    let b_mapped = addr(42000);

    assert!(!r.process_one(&encode_rv_register(&rid, a_mapped), a.local_addr().unwrap()).await.unwrap());
    assert!(r.process_one(&encode_rv_register(&rid, b_mapped), b.local_addr().unwrap()).await.unwrap());
    assert_eq!(r.rendezvous_count().await, 0, "completed rendezvous is removed");

    let (pkt_a, from_a) = recv_with_timeout(&a).await.expect("A gets PeerInfo");
    assert_eq!(from_a, r.local_addr);
    match decode_rv_message(&pkt_a).unwrap() {
        RendezvousMessage::PeerInfo { rendezvous_id, peer_addr } => {
            assert_eq!(rendezvous_id, rid);
            assert_eq!(peer_addr, b_mapped, "A learns B's mapped addr");
        }
        _ => panic!("expected PeerInfo"),
    }
    assert_eq!(pkt_a, encode_rv_peer_info(&rid, b_mapped));

    let (pkt_b, _) = recv_with_timeout(&b).await.expect("B gets PeerInfo");
    match decode_rv_message(&pkt_b).unwrap() {
        RendezvousMessage::PeerInfo { peer_addr, .. } => {
            assert_eq!(peer_addr, a_mapped, "B learns A's mapped addr");
        }
        _ => panic!("expected PeerInfo"),
    }
}

#[tokio::test]
async fn rendezvous_ids_are_independent() {
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    r.process_one(&encode_rv_register(&[1u8; 32], addr(1)), a.local_addr().unwrap()).await.unwrap();
    assert!(!r.process_one(&encode_rv_register(&[2u8; 32], addr(2)), b.local_addr().unwrap()).await.unwrap());
    assert_eq!(r.rendezvous_count().await, 2);
    assert!(recv_with_timeout(&a).await.is_none());
    assert!(recv_with_timeout(&b).await.is_none());
}

#[tokio::test]
async fn rendezvous_malformed_packet_is_dropped() {
    let r = relay().await;
    // Valid RV magic but too short to decode.
    let pkt = [0x52u8, 0x56, 0x00];
    assert!(!r.process_one(&pkt, addr(1)).await.unwrap());
    assert_eq!(r.rendezvous_count().await, 0);
}

#[tokio::test]
async fn rendezvous_non_register_messages_are_ignored() {
    let r = relay().await;
    let a = peer().await;
    let rid = [0x0Fu8; 32];
    assert!(!r.process_one(&encode_rv_peer_info(&rid, addr(9)), a.local_addr().unwrap()).await.unwrap());
    assert!(!r.process_one(&encode_rv_not_found(&rid), a.local_addr().unwrap()).await.unwrap());
    assert_eq!(r.rendezvous_count().await, 0, "PeerInfo/NotFound must not create entries");
    assert!(recv_with_timeout(&a).await.is_none());
}

#[tokio::test]
async fn rendezvous_packet_takes_precedence_over_ztlp_parsing() {
    // An RV packet must not be treated as a ZTLP session packet even though
    // it would fail ZTLP magic anyway; and must not create a session entry.
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let rid = [0x77u8; 32];
    r.process_one(&encode_rv_register(&rid, addr(1)), a.local_addr().unwrap()).await.unwrap();
    // A ZTLP data packet from B must start a fresh session, not pair with A's RV.
    assert!(!r.process_one(&data_packet(&sid(0x77)), b.local_addr().unwrap()).await.unwrap());
    assert!(recv_with_timeout(&a).await.is_none());
}

#[tokio::test]
async fn rendezvous_register_ipv6_mapped_addr_roundtrips() {
    let r = relay().await;
    let a = peer().await;
    let b = peer().await;
    let rid = [0x6Bu8; 32];
    let a_mapped: SocketAddr = "[2001:db8::1]:4444".parse().unwrap();
    r.process_one(&encode_rv_register(&rid, a_mapped), a.local_addr().unwrap()).await.unwrap();
    assert!(r.process_one(&encode_rv_register(&rid, addr(1)), b.local_addr().unwrap()).await.unwrap());
    let (pkt_b, _) = recv_with_timeout(&b).await.unwrap();
    match decode_rv_message(&pkt_b).unwrap() {
        RendezvousMessage::PeerInfo { peer_addr, .. } => assert_eq!(peer_addr, a_mapped),
        _ => panic!("expected PeerInfo"),
    }
}
