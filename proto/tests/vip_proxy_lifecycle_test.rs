//! Lifecycle tests for `ztlp_proto::vip::VipProxy` — real loopback TCP
//! listeners, real client connections, tunnel->TCP delivery through the
//! `StreamDispatcher`, hot-swap, stop, and the TLS acceptor path with a
//! generated cert in an isolated HOME.
//!
//! The TCP->tunnel direction lands in the Nebula-pivot R1 `SendController`
//! stub (which drops everything), so those assertions are limited to "does
//! not error / counters move"; see `r1_stub_contract_test.rs`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ztlp_proto::packet::SessionId;
use ztlp_proto::transport::TransportNode;
use ztlp_proto::vip::{DispatchError, StreamDispatcher, TunnelSession, VipProxy};

// ─── helpers ────────────────────────────────────────────────────────────

/// Reserve a free port on `ip` by binding :0 and releasing it.
async fn free_port(ip: Ipv4Addr) -> u16 {
    let l = TcpListener::bind(SocketAddr::new(ip.into(), 0)).await.unwrap();
    l.local_addr().unwrap().port()
}

async fn transport() -> Arc<TransportNode> {
    Arc::new(TransportNode::bind("127.0.0.1:0").await.unwrap())
}

fn peer() -> SocketAddr {
    "127.0.0.1:9".parse().unwrap()
}

async fn started_proxy(vip: Ipv4Addr, ports: &[u16]) -> (VipProxy, Arc<AtomicU64>, Arc<AtomicU64>) {
    let mut proxy = VipProxy::new();
    for &p in ports {
        proxy.add_service("svc".into(), vip, p).unwrap();
    }
    let data_seq = Arc::new(AtomicU64::new(0));
    let bytes_sent = Arc::new(AtomicU64::new(0));
    proxy
        .start(transport().await, SessionId([1u8; 12]), peer(), data_seq.clone(), bytes_sent.clone())
        .await
        .expect("start");
    (proxy, data_seq, bytes_sent)
}

async fn connect(vip: Ipv4Addr, port: u16) -> TcpStream {
    let mut last = None;
    for _ in 0..20 {
        match TcpStream::connect(SocketAddr::new(vip.into(), port)).await {
            Ok(s) => return s,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
    panic!("connect failed: {:?}", last);
}

/// Wait until the dispatcher shows `n` streams (connection handshake is async).
async fn wait_streams(d: &StreamDispatcher, n: usize) {
    for _ in 0..100 {
        if d.stream_count() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected {} streams, have {}", n, d.stream_count());
}

// ─── construction / registry ────────────────────────────────────────────

#[test]
fn default_and_new_are_equivalent_and_empty() {
    let a = VipProxy::default();
    let b = VipProxy::new();
    assert!(a.services().is_empty() && b.services().is_empty());
    assert_eq!(a.dispatcher().stream_count(), 0);
    assert!(a.resolve("nope").is_none());
}

#[test]
fn add_service_updates_vip_when_re_added_with_new_address() {
    let mut p = VipProxy::new();
    p.add_service("s".into(), Ipv4Addr::new(127, 0, 55, 1), 80).unwrap();
    p.add_service("s".into(), Ipv4Addr::new(127, 0, 55, 2), 443).unwrap();
    let s = &p.services()["s"];
    assert_eq!(s.vip, Ipv4Addr::new(127, 0, 55, 2), "VIP is updated on re-add");
    assert_eq!(s.ports, vec![80, 443]);
    assert_eq!(s.name, "s");
    assert_eq!(p.resolve("s"), Some(Ipv4Addr::new(127, 0, 55, 2)));
}

#[test]
fn add_service_rejects_every_non_loopback_class() {
    let mut p = VipProxy::new();
    for bad in [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(126, 255, 255, 255),
        Ipv4Addr::new(128, 0, 0, 1),
    ] {
        let err = p.add_service("x".into(), bad, 80).unwrap_err();
        assert!(err.contains("not a loopback"), "{bad}: {err}");
    }
    assert!(p.services().is_empty());
}

#[tokio::test]
async fn session_ref_is_none_before_start_and_some_after() {
    let mut p = VipProxy::new();
    assert!(p.session_ref().read().await.is_none());
    let (ack_tx, enq_tx) = p
        .start(transport().await, SessionId([2u8; 12]), peer(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        .await
        .unwrap();
    let sess = p.session_ref();
    let guard = sess.read().await;
    let s = guard.as_ref().expect("session stored even with zero services");
    assert_eq!(s.session_id, SessionId([2u8; 12]));
    assert_eq!(s.peer_addr, peer());
    // Channels are live: sending must not error even though the stub drops.
    assert!(enq_tx.send(vec![1]).is_ok());
    // ack_rx is dropped by the stub SendController, so the ack channel is closed.
    assert!(ack_tx.send(1).is_err());
    drop(guard);
    p.stop();
}

#[tokio::test]
async fn start_with_no_services_spawns_no_listeners_and_stop_is_idempotent() {
    let mut p = VipProxy::new();
    p.start(transport().await, SessionId([3u8; 12]), peer(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        .await
        .unwrap();
    p.stop();
    p.stop();
}

// ─── TunnelSession ──────────────────────────────────────────────────────

#[tokio::test]
async fn tunnel_session_new_stores_fields() {
    let t = transport().await;
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let sc = Arc::new(tokio::sync::Mutex::new(ztlp_proto::send_controller::SendController::new(
        t.clone(),
        SessionId([4u8; 12]),
        peer(),
        rx,
    )));
    let ds = Arc::new(AtomicU64::new(7));
    let bs = Arc::new(AtomicU64::new(8));
    let s = TunnelSession::new(t.clone(), SessionId([4u8; 12]), peer(), ds.clone(), bs.clone(), sc);
    assert_eq!(s.session_id, SessionId([4u8; 12]));
    assert_eq!(s.peer_addr, peer());
    assert_eq!(s.data_seq.load(Ordering::Relaxed), 7);
    assert_eq!(s.bytes_sent.load(Ordering::Relaxed), 8);
    assert!(Arc::ptr_eq(&s.transport, &t));
}

// ─── StreamDispatcher edge cases ────────────────────────────────────────

#[tokio::test]
async fn dispatcher_reports_channel_full_under_backpressure() {
    let d = StreamDispatcher::new();
    let _rx = d.register(1); // never drained
    let mut full = false;
    for _ in 0..1000 {
        match d.dispatch(1, vec![0u8; 8]) {
            Ok(()) => {}
            Err(DispatchError::ChannelFull) => {
                full = true;
                break;
            }
            Err(DispatchError::NoStream) => panic!("stream is registered"),
        }
    }
    assert!(full, "bounded channel must eventually report ChannelFull");
    assert!(format!("{:?}", DispatchError::ChannelFull).contains("ChannelFull"));
}

#[tokio::test]
async fn dispatcher_re_register_replaces_sender() {
    let d = StreamDispatcher::new();
    let mut rx1 = d.register(5);
    let mut rx2 = d.register(5);
    d.dispatch(5, b"x".to_vec()).unwrap();
    assert_eq!(rx2.recv().await.unwrap(), b"x");
    assert!(rx1.recv().await.is_none(), "old receiver's sender was dropped");
    assert_eq!(d.stream_count(), 1);
}

// ─── real listener lifecycle ────────────────────────────────────────────

#[tokio::test]
async fn listener_accepts_connection_and_tunnel_data_reaches_tcp_client() {
    let vip = Ipv4Addr::new(127, 0, 77, 1);
    let port = free_port(vip).await;
    let (mut proxy, data_seq, bytes_sent) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();

    let mut client = connect(vip, port).await;
    wait_streams(&dispatcher, 1).await;

    // Stream IDs start at 1.
    dispatcher.dispatch(1, b"HTTP/1.1 200 OK\r\n\r\nhi".to_vec()).expect("stream 1 registered");
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"HTTP/1.1 200 OK\r\n\r\nhi");

    // TCP -> tunnel: counters advance even though the stub drops the frames.
    client.write_all(&[0u8; 3000]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(bytes_sent.load(Ordering::Relaxed) >= 3000, "bytes_sent tracks TCP reads");
    // 3000 bytes / 1135 max mux payload = 3 frames.
    assert!(data_seq.load(Ordering::Relaxed) >= 3, "one data_seq per mux frame");

    proxy.stop();
}

#[tokio::test]
async fn in_band_fin_sentinel_closes_tcp_to_client() {
    let vip = Ipv4Addr::new(127, 0, 77, 2);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();

    let mut client = connect(vip, port).await;
    wait_streams(&dispatcher, 1).await;

    // Single-byte 0x02 = FIN sentinel: write task exits, then when the client
    // side reads EOF... actually the read loop keeps running until the client
    // closes, so verify the write half stops delivering instead.
    dispatcher.dispatch(1, vec![0x02]).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Anything dispatched after the sentinel must not reach the client.
    let _ = dispatcher.dispatch(1, b"late".to_vec());
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf)).await;
    assert!(
        matches!(r, Err(_)) || matches!(r, Ok(Ok(0))),
        "no data after FIN sentinel, got {:?}",
        r.map(|x| x.map(|n| buf[..n].to_vec()))
    );
    proxy.stop();
}

#[tokio::test]
async fn close_sentinel_also_stops_delivery() {
    let vip = Ipv4Addr::new(127, 0, 77, 3);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();
    let mut client = connect(vip, port).await;
    wait_streams(&dispatcher, 1).await;
    dispatcher.dispatch(1, vec![0x05]).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = dispatcher.dispatch(1, b"late".to_vec());
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf)).await;
    assert!(matches!(r, Err(_)) || matches!(r, Ok(Ok(0))));
    proxy.stop();
}

#[tokio::test]
async fn client_close_unregisters_stream() {
    let vip = Ipv4Addr::new(127, 0, 77, 4);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();
    let client = connect(vip, port).await;
    wait_streams(&dispatcher, 1).await;
    drop(client);
    wait_streams(&dispatcher, 0).await;
    assert!(matches!(dispatcher.dispatch(1, vec![1]), Err(DispatchError::NoStream)));
    proxy.stop();
}

#[tokio::test]
async fn multiple_concurrent_connections_get_distinct_stream_ids() {
    let vip = Ipv4Addr::new(127, 0, 77, 5);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();

    let mut c1 = connect(vip, port).await;
    let mut c2 = connect(vip, port).await;
    let mut c3 = connect(vip, port).await;
    wait_streams(&dispatcher, 3).await;

    dispatcher.dispatch(1, b"one".to_vec()).unwrap();
    dispatcher.dispatch(2, b"two".to_vec()).unwrap();
    dispatcher.dispatch(3, b"three".to_vec()).unwrap();

    let mut got = Vec::new();
    for c in [&mut c1, &mut c2, &mut c3] {
        let mut b = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut b)).await.unwrap().unwrap();
        got.push(String::from_utf8_lossy(&b[..n]).to_string());
    }
    got.sort();
    assert_eq!(got, vec!["one", "three", "two"]);
    proxy.stop();
}

#[tokio::test]
async fn multiple_ports_on_same_vip_each_get_a_listener() {
    let vip = Ipv4Addr::new(127, 0, 77, 6);
    let p1 = free_port(vip).await;
    let p2 = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[p1, p2]).await;
    let dispatcher = proxy.dispatcher();
    let _a = connect(vip, p1).await;
    let _b = connect(vip, p2).await;
    wait_streams(&dispatcher, 2).await;
    proxy.stop();
}

#[tokio::test]
async fn start_fails_cleanly_when_port_is_taken() {
    let vip = Ipv4Addr::new(127, 0, 77, 7);
    let holder = TcpListener::bind(SocketAddr::new(vip.into(), 0)).await.unwrap();
    let port = holder.local_addr().unwrap().port();
    let mut proxy = VipProxy::new();
    proxy.add_service("svc".into(), vip, port).unwrap();
    let err = proxy
        .start(transport().await, SessionId([5u8; 12]), peer(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        .await
        .unwrap_err();
    assert!(err.contains("failed to bind"), "{err}");
    proxy.stop();
}

#[tokio::test]
async fn stop_makes_listener_refuse_new_connections() {
    let vip = Ipv4Addr::new(127, 0, 77, 8);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let _c = connect(vip, port).await;
    proxy.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(SocketAddr::new(vip.into(), port))).await;
    assert!(
        matches!(r, Ok(Err(_))) || matches!(r, Err(_)),
        "listener socket must be closed after stop"
    );
    // Services survive stop (they are config).
    assert_eq!(proxy.services().len(), 1);
}

// BUG (found 2026-09-13, lib fix pending go-ahead): `VipProxy::start()` on an
// already-started proxy ("hot-swap") replaces `self.dispatcher` with a fresh
// `StreamDispatcher`, but the running `vip_listener_task`s captured an `Arc`
// of the OLD dispatcher at spawn time. New TCP connections therefore register
// in the old dispatcher, while `proxy.dispatcher()` (what the FFI recv_loop
// uses to route tunnel data) points at the new, permanently-empty one. Every
// connection accepted after a reconnect is a black hole for downloads.
// Worse: `next_stream_id` is reset to 1, so the first post-swap connection
// re-registers stream_id 1 in the old dispatcher and hijacks the channel of
// whichever pre-swap connection still holds that id.
// Fix: share the dispatcher through `Arc<RwLock<Arc<StreamDispatcher>>>` (or
// don't replace it; clear it instead) so listeners and recv_loop agree.
#[tokio::test]
#[ignore = "exposes hot-swap dispatcher split-brain in VipProxy::start — see comment"]
async fn second_start_hot_swaps_session_and_resets_dispatcher() {
    let vip = Ipv4Addr::new(127, 0, 77, 9);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let d1 = proxy.dispatcher();
    let _c = connect(vip, port).await;
    wait_streams(&d1, 1).await;

    proxy
        .start(transport().await, SessionId([9u8; 12]), peer(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        .await
        .expect("hot-swap start");
    let d2 = proxy.dispatcher();
    assert_eq!(proxy.session_ref().read().await.as_ref().unwrap().session_id, SessionId([9u8; 12]));

    let mut c2 = connect(vip, port).await;
    wait_streams(&d2, 1).await;
    d2.dispatch(1, b"after-swap".to_vec()).unwrap();
    let mut b = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut b)).await.unwrap().unwrap();
    assert_eq!(&b[..n], b"after-swap");
    proxy.stop();
}

#[tokio::test]
async fn second_start_currently_orphans_new_connections_in_old_dispatcher() {
    let vip = Ipv4Addr::new(127, 0, 77, 12);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let d1 = proxy.dispatcher();
    let _c = connect(vip, port).await;
    wait_streams(&d1, 1).await;

    proxy
        .start(transport().await, SessionId([9u8; 12]), peer(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        .await
        .expect("hot-swap start");
    let d2 = proxy.dispatcher();
    assert!(!Arc::ptr_eq(&d1, &d2), "start() swapped in a fresh dispatcher");
    assert_eq!(proxy.session_ref().read().await.as_ref().unwrap().session_id, SessionId([9u8; 12]));

    let _c2 = connect(vip, port).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The listener still registers into d1 (captured at spawn), never d2 —
    // AND next_stream_id was reset to 1, so the new connection re-registers
    // stream_id 1 in d1, silently stealing the first connection's channel.
    assert_eq!(d1.stream_count(), 1, "second connection collided onto stream_id 1 in the OLD dispatcher");
    assert_eq!(d2.stream_count(), 0, "new dispatcher never sees the connection (pins the bug)");
    assert!(d1.dispatch(1, vec![1]).is_ok());
    assert!(matches!(d2.dispatch(1, vec![1]), Err(DispatchError::NoStream)));
    proxy.stop();
}

#[tokio::test]
async fn update_session_swaps_without_touching_dispatcher() {
    let vip = Ipv4Addr::new(127, 0, 77, 10);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let d1 = proxy.dispatcher();
    let _c = connect(vip, port).await;
    wait_streams(&d1, 1).await;

    let (ack_tx, enq_tx) = proxy
        .update_session(transport().await, SessionId([7u8; 12]), peer(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        .await;
    assert!(enq_tx.send(vec![0]).is_ok());
    assert!(ack_tx.send(0).is_err(), "stub SendController drops ack_rx");
    assert!(Arc::ptr_eq(&d1, &proxy.dispatcher()), "update_session keeps dispatcher");
    assert_eq!(d1.stream_count(), 1, "existing streams survive");
    assert_eq!(proxy.session_ref().read().await.as_ref().unwrap().session_id, SessionId([7u8; 12]));
    proxy.stop();
}

#[tokio::test]
async fn connection_before_any_session_is_rejected() {
    // Manually assemble: start() always stores a session, so simulate by
    // clearing it after start.
    let vip = Ipv4Addr::new(127, 0, 77, 11);
    let port = free_port(vip).await;
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    *proxy.session_ref().write().await = None;
    let dispatcher = proxy.dispatcher();

    let mut c = connect(vip, port).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(dispatcher.stream_count(), 0, "no stream registered without a session");
    let mut b = [0u8; 4];
    let r = tokio::time::timeout(Duration::from_secs(2), c.read(&mut b)).await;
    assert!(matches!(r, Ok(Ok(0))) || matches!(r, Ok(Err(_))), "server dropped the socket: {:?}", r);
    proxy.stop();
}

// ─── TLS acceptor path ──────────────────────────────────────────────────

fn write_self_signed(cert_dir: &std::path::Path, name: &str) {
    std::fs::create_dir_all(cert_dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec![format!("{name}.techrockstars.ztlp")]).unwrap();
    std::fs::write(cert_dir.join(format!("{name}.pem")), ck.cert.pem()).unwrap();
    std::fs::write(cert_dir.join(format!("{name}.key")), ck.key_pair.serialize_pem()).unwrap();
}

/// Runs a TLS-port scenario with HOME pointed at a temp dir. Serialised via a
/// static mutex because HOME is process-global.
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::test]
async fn tls_port_without_cert_falls_back_to_plain_tcp() {
    let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", tmp.path());

    let vip = Ipv4Addr::new(127, 0, 78, 1);
    // 8443 is a TLS port; may be in use on the box, so skip if we can't bind.
    let port = 8443u16;
    if TcpListener::bind(SocketAddr::new(vip.into(), port)).await.is_err() {
        eprintln!("skipping: {vip}:{port} not bindable");
        return;
    }
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();
    // No cert -> acceptor None -> plain TCP works.
    let mut c = connect(vip, port).await;
    wait_streams(&dispatcher, 1).await;
    dispatcher.dispatch(1, b"plain".to_vec()).unwrap();
    let mut b = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut b)).await.unwrap().unwrap();
    assert_eq!(&b[..n], b"plain");
    proxy.stop();
}

#[tokio::test]
async fn tls_port_with_cert_terminates_tls_and_rejects_plaintext_client() {
    let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", tmp.path());
    write_self_signed(&tmp.path().join(".ztlp").join("certs"), "svc");

    let vip = Ipv4Addr::new(127, 0, 78, 2);
    let port = 8443u16;
    if TcpListener::bind(SocketAddr::new(vip.into(), port)).await.is_err() {
        eprintln!("skipping: {vip}:{port} not bindable");
        return;
    }
    let (mut proxy, _, _) = started_proxy(vip, &[port]).await;
    let dispatcher = proxy.dispatcher();

    // A plaintext client speaking garbage must fail the TLS handshake and
    // never get a stream registered.
    let mut c = connect(vip, port).await;
    c.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dispatcher.stream_count(), 0, "handshake failure must not register a stream");

    // A real TLS client (no verification) completes the handshake.
    let mut root = rustls::RootCertStore::empty();
    let pem = std::fs::read(tmp.path().join(".ztlp/certs/svc.pem")).unwrap();
    for c in rustls_pemfile::certs(&mut pem.as_slice()) {
        root.add(c.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder().with_root_certificates(root).with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = connect(vip, port).await;
    let name = rustls::pki_types::ServerName::try_from("svc.techrockstars.ztlp").unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .expect("handshake timeout")
        .expect("TLS handshake");
    wait_streams(&dispatcher, 1).await;
    // stream_id is allocated BEFORE the TLS handshake, so the failed
    // plaintext client consumed id 1; the TLS client is id 2.
    assert!(matches!(dispatcher.dispatch(1, vec![0]), Err(DispatchError::NoStream)));
    dispatcher.dispatch(2, b"over-tls".to_vec()).unwrap();
    let mut b = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut b)).await.unwrap().unwrap();
    assert_eq!(&b[..n], b"over-tls");
    proxy.stop();
}
