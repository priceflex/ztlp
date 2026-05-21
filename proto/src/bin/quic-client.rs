#![cfg(feature = "quic-transport")]

use tokio::runtime::Runtime;
use std::time::Instant;
use ztlp_proto::quic_transport::{QuicEndpointConfig, tokio_endpoint::QuicEndpoint};

fn main() {
    let rt = Runtime::new().unwrap();
    let target = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:23097".to_string());
    let server_addr = target.parse().unwrap();
    
    let client = rt.block_on(QuicEndpoint::connect(QuicEndpointConfig::default(), server_addr, "localhost")).unwrap();

    let num_streams = 8;
    let payload_size = 105 * 1024;
    
    rt.block_on(async move {
        println!("Sending 8 parallel 105KB streams to {}...", server_addr);
        let start = Instant::now();
        let mut client_tasks = vec![];
        for _ in 0..num_streams {
            let conn_clone = client.clone();
            client_tasks.push(tokio::spawn(async move {
                let (mut send, mut recv) = conn_clone.open_bi().await.unwrap();
                let payload = vec![0xABu8; payload_size]; 
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();

                let mut buf = vec![0u8; 16];
                let _ = recv.read(&mut buf).await;
            }));
        }

        for t in client_tasks {
            let _ = t.await;
        }
        let elapsed = start.elapsed();
        let mb = (num_streams * payload_size) as f64 / 1_048_576.0;
        let p = elapsed.as_secs_f64();
        println!("Transferred {:.2} MB in {:.2} ms ({:.2} MB/s)", mb, p * 1000.0, mb / p);
    });
}
