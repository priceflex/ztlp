//! Integration tests for the experimental QUIC + Noise transport.

#![cfg(feature = "quic-transport")]

use ztlp_proto::quic_transport::{QuicEndpointConfig, SansIoConnection, ZTLP_ALPN};

#[test]
fn alpn_constant_is_reachable_from_integration_test() {
    assert_eq!(ZTLP_ALPN, b"ztlp/1");
}

#[cfg(feature = "tokio-runtime")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_stream_loopback_roundtrip() {
    use ztlp_proto::quic_transport::tokio_endpoint::QuicEndpoint;

    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let server = QuicEndpoint::bind(server_cfg).await.expect("bind server");
    let server_addr = server.inner.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        let mut handles = vec![];
        for _ in 0..8 {
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 16];
                recv.read_exact(&mut buf).await.expect("server read");
                send.write_all(&buf).await.expect("server echo");
                send.finish().expect("server finish");
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        std::future::pending::<()>().await;
    });

    let client = QuicEndpoint::connect(QuicEndpointConfig::default(), server_addr, "localhost")
        .await
        .expect("client connect");

    let mut client_tasks = vec![];
    for i in 0..8u8 {
        let conn_clone = client.clone();
        client_tasks.push(tokio::spawn(async move {
            let (mut send, mut recv) = conn_clone.open_bi().await.expect("open_bi");
            let payload = vec![i; 16];
            send.write_all(&payload).await.expect("client send");
            send.finish().expect("client finish");

            let mut resp = vec![0u8; 16];
            recv.read_exact(&mut resp).await.expect("client recv");
            assert_eq!(payload, resp);
        }));
    }

    for t in client_tasks {
        t.await.unwrap();
    }
    server_task.abort();
}

#[cfg(feature = "tokio-runtime")]
#[tokio::test]
async fn noise_handshake_over_quic_stream_zero() {
    use ztlp_proto::identity::NodeIdentity;
    use ztlp_proto::quic_transport::noise_stream::{
        run_initiator_handshake, run_responder_handshake,
    };
    use ztlp_proto::quic_transport::tokio_endpoint::QuicEndpoint;

    let init_id = NodeIdentity::generate().unwrap();
    let resp_id = NodeIdentity::generate().unwrap();

    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let server = QuicEndpoint::bind(server_cfg).await.expect("server bind");
    let server_addr = server.inner.local_addr().unwrap();

    let resp_id_clone = resp_id.clone();
    let init_node_id = init_id.node_id.clone();
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        run_responder_handshake(&conn, &resp_id_clone, init_node_id)
            .await
            .expect("responder handshake")
    });

    let client = QuicEndpoint::connect(QuicEndpointConfig::default(), server_addr, "localhost")
        .await
        .expect("client connect");

    let init_result = run_initiator_handshake(&client, &init_id, resp_id.node_id, [0; 16])
        .await
        .unwrap();
    let resp_result = server_task.await.unwrap();
}

#[test]
fn sans_io_path_compiles_without_tokio() {
    // Phase 4 placeholder: SansIoConnection::new currently returns Ok with
    // an empty inner. iOS FFI will populate it later. This test exists to
    // guarantee the sans-io type compiles in the test crate without pulling
    // tokio in. Once the real init lands (Phase 5), this test should assert
    // on observable state of the returned connection.
    let conn = SansIoConnection::new(QuicEndpointConfig::default())
        .expect("SansIoConnection placeholder should construct cleanly");
    assert!(
        conn.inner.is_none(),
        "Phase 4 placeholder has no inner conn"
    );
}
