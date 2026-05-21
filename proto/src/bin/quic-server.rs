#![cfg(feature = "quic-transport")]

use tokio::runtime::Runtime;
use ztlp_proto::quic_transport::{QuicEndpointConfig, tokio_endpoint::QuicEndpoint};

fn main() {
    let rt = Runtime::new().unwrap();
    let server_cfg = QuicEndpointConfig {
        bind: Some("0.0.0.0:23097".parse().unwrap()),
        ..Default::default()
    };
    
    let server = rt.block_on(QuicEndpoint::bind(server_cfg)).unwrap();
    println!("Server listening on {}", server.inner.local_addr().unwrap());

    rt.block_on(async move {
        loop {
            let conn = server.accept().await.unwrap();
            tokio::spawn(async move {
                loop {
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65536];
                            loop {
                                match recv.read(&mut buf).await {
                                    Ok(Some(_)) => {},
                                    Ok(None) | Err(_) => break,
                                }
                            }
                            let _ = send.write_all(b"ACK").await;
                            let _ = send.finish();
                        });
                    } else {
                        break;
                    }
                }
            });
        }
    });
}
