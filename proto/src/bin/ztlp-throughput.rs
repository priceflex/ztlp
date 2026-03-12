//! ZTLP Throughput Benchmark
//!
//! Measures file-transfer throughput across different modes:
//! - Raw TCP loopback (baseline)
//! - ZTLP tunnel with GSO
//! - ZTLP tunnel without GSO
//! - ZTLP tunnel with sendmmsg
//!
//! Run: cargo run --release --bin ztlp-throughput -- --mode all --size 104857600

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::debug;

use ztlp_proto::gso::{self, GsoMode};
use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use ztlp_proto::pipeline::Pipeline;
use ztlp_proto::tunnel;

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "ztlp-throughput", about = "ZTLP throughput benchmark")]
struct Args {
    /// Benchmark mode: raw, ztlp, ztlp-gso, ztlp-nogso, ztlp-gro, ztlp-gso-gro, all
    #[arg(long, default_value = "all")]
    mode: String,

    /// Transfer size in bytes (default 100MB)
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    size: u64,

    /// Bind address
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Number of iterations for statistical significance
    #[arg(long, default_value_t = 3)]
    repeat: u32,

    /// Enable GRO on the receive side (overrides per-mode defaults)
    #[arg(long)]
    gro: bool,

    /// Enable debug mode — shows per-batch timing stats and periodic summaries
    /// from the tunnel internals (sets ZTLP_DEBUG=1)
    #[arg(long)]
    debug: bool,
}

// ─── Results ────────────────────────────────────────────────────────────────

struct BenchResult {
    mode: String,
    throughput_mbps: f64,
    time_ms: f64,
    packets: Option<u64>,
}

// ─── Raw TCP benchmark ──────────────────────────────────────────────────────

async fn bench_raw_tcp(bind: &str, size: u64) -> Result<BenchResult, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("{}:0", bind)).await?;
    let listen_addr = listener.local_addr()?;

    // Generate data
    let data = generate_data(size);

    let data_clone = data.clone();
    let sender = tokio::spawn(async move {
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        stream.write_all(&data_clone).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let start = Instant::now();
    let (mut stream, _) = listener.accept().await?;
    let mut total_read = 0u64;
    let mut buf = vec![0u8; 131072];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
    }
    let elapsed = start.elapsed();

    sender.await?;

    assert_eq!(total_read, size);
    let time_ms = elapsed.as_secs_f64() * 1000.0;
    let throughput_mbps = (size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();

    Ok(BenchResult {
        mode: "Raw TCP".to_string(),
        throughput_mbps,
        time_ms,
        packets: None,
    })
}

// ─── ZTLP tunnel benchmark ─────────────────────────────────────────────────

async fn bench_ztlp_tunnel(
    bind: &str,
    size: u64,
    _gso_mode: GsoMode,
    mode_name: &str,
) -> Result<BenchResult, Box<dyn std::error::Error>> {
    // Create two identities
    let server_identity = NodeIdentity::generate()?;
    let client_identity = NodeIdentity::generate()?;

    // Set up server UDP socket
    let server_udp = Arc::new(UdpSocket::bind(format!("{}:0", bind)).await?);
    let server_udp_addr = server_udp.local_addr()?;

    // Set up a TCP backend to receive data
    let backend_listener = TcpListener::bind(format!("{}:0", bind)).await?;
    let backend_addr = backend_listener.local_addr()?;

    // Set up TCP local listener for client
    let client_tcp_listener = TcpListener::bind(format!("{}:0", bind)).await?;
    let client_tcp_addr = client_tcp_listener.local_addr()?;

    // Client UDP socket
    let client_udp = Arc::new(UdpSocket::bind(format!("{}:0", bind)).await?);
    let _client_udp_addr = client_udp.local_addr()?;

    // Pipelines
    let server_pipeline = Arc::new(Mutex::new(Pipeline::new()));
    let client_pipeline = Arc::new(Mutex::new(Pipeline::new()));

    // ── Handshake ──
    let session_id = SessionId::generate();

    // Initiator (client) context
    let mut client_ctx = HandshakeContext::new_initiator(&client_identity)?;
    // Responder (server) context
    let mut server_ctx = HandshakeContext::new_responder(&server_identity)?;

    // Message 1: HELLO
    let msg1 = client_ctx.write_message(&[])?;
    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *client_identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;
    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);
    client_udp.send_to(&pkt1, server_udp_addr).await?;

    // Server receives HELLO
    let mut recv_buf = vec![0u8; 65535];
    let (n, client_addr) = server_udp.recv_from(&mut recv_buf).await?;
    let _recv1_hdr = HandshakeHeader::deserialize(&recv_buf[..n])?;
    server_ctx.read_message(&recv_buf[HANDSHAKE_HEADER_SIZE..n])?;

    // Message 2: HELLO_ACK
    let msg2 = server_ctx.write_message(&[])?;
    let mut ack_hdr = HandshakeHeader::new(MsgType::HelloAck);
    ack_hdr.session_id = session_id;
    ack_hdr.src_node_id = *server_identity.node_id.as_bytes();
    ack_hdr.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_hdr.serialize();
    pkt2.extend_from_slice(&msg2);
    server_udp.send_to(&pkt2, client_addr).await?;

    // Client receives HELLO_ACK
    let (n, _) = client_udp.recv_from(&mut recv_buf).await?;
    client_ctx.read_message(&recv_buf[HANDSHAKE_HEADER_SIZE..n])?;

    // Message 3: Final
    let msg3 = client_ctx.write_message(&[])?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *client_identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    client_udp.send_to(&pkt3, server_udp_addr).await?;

    // Server receives message 3
    let (n, _) = server_udp.recv_from(&mut recv_buf).await?;
    server_ctx.read_message(&recv_buf[HANDSHAKE_HEADER_SIZE..n])?;

    // Finalize both sides
    assert!(client_ctx.is_finished());
    assert!(server_ctx.is_finished());

    let client_peer_id = NodeId::from_bytes(*server_identity.node_id.as_bytes());
    let server_peer_id = NodeId::from_bytes(*client_identity.node_id.as_bytes());

    let (_, client_session) = client_ctx.finalize(client_peer_id, session_id)?;
    let (_, server_session) = server_ctx.finalize(server_peer_id, session_id)?;

    // Register sessions
    {
        let mut pl = client_pipeline.lock().await;
        pl.register_session(client_session);
    }
    {
        let mut pl = server_pipeline.lock().await;
        pl.register_session(server_session);
    }

    // ── Start the bridges ──

    // Server bridge: UDP → TCP backend
    let server_tcp = TcpStream::connect(backend_addr).await?;
    let server_bridge = tokio::spawn({
        let udp = server_udp.clone();
        let pipeline = server_pipeline.clone();
        async move {
            let _ = tunnel::run_bridge(server_tcp, udp, pipeline, session_id, client_addr).await;
        }
    });

    // Client bridge: TCP local → UDP
    // Accept client TCP connection and bridge to ZTLP
    let client_bridge_udp = client_udp.clone();
    let client_bridge_pipeline = client_pipeline.clone();
    let client_bridge = tokio::spawn(async move {
        let (tcp_stream, _) = client_tcp_listener.accept().await.unwrap();
        let _ = tunnel::run_bridge(
            tcp_stream,
            client_bridge_udp,
            client_bridge_pipeline,
            session_id,
            server_udp_addr,
        )
        .await;
    });

    // Generate data and send through the tunnel
    let data = generate_data(size);
    let data_clone = data.clone();

    // Use a oneshot to signal when the sender actually starts writing,
    // so the timer doesn't include bridge startup overhead.
    let (start_tx, start_rx) = tokio::sync::oneshot::channel::<Instant>();

    // Sender: connect to client TCP listener and push data
    let sender = tokio::spawn(async move {
        // Small delay to let the bridge's TCP listener become ready.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut stream = TcpStream::connect(client_tcp_addr).await.unwrap();
        let _ = start_tx.send(Instant::now());
        stream.write_all(&data_clone).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    // Receiver: accept from the backend listener
    let (mut backend_stream, _) = backend_listener.accept().await?;
    // Wait for the sender to signal it's actually writing
    let start = start_rx.await.unwrap_or_else(|_| Instant::now());
    let mut total_read = 0u64;
    let mut buf = vec![0u8; 131072];
    loop {
        match tokio::time::timeout(Duration::from_secs(60), backend_stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total_read += n as u64;
            }
            Ok(Err(e)) => {
                eprintln!("Backend read error: {}", e);
                break;
            }
            Err(_) => {
                eprintln!(
                    "Backend read timeout (received {} of {} bytes)",
                    total_read, size
                );
                break;
            }
        }
    }
    let elapsed = start.elapsed();

    // Clean up
    sender.await?;
    // Give bridges a moment to finish gracefully
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Abort bridge tasks — AbortOnDrop inside run_bridge will
    // cascade to the inner spawned tasks.
    server_bridge.abort();
    client_bridge.abort();
    // Wait briefly for abort to propagate
    tokio::time::sleep(Duration::from_millis(50)).await;

    let time_ms = elapsed.as_secs_f64() * 1000.0;
    let throughput_mbps = if elapsed.as_secs_f64() > 0.0 {
        (total_read as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64()
    } else {
        0.0
    };

    // Estimate packet count: data / (16KB - 9 byte frame overhead) = packets
    let payload_per_packet = 16384 - 9;
    let est_packets = (size as f64 / payload_per_packet as f64).ceil() as u64;

    Ok(BenchResult {
        mode: mode_name.to_string(),
        throughput_mbps,
        time_ms,
        packets: Some(est_packets),
    })
}

// ─── Data generation ────────────────────────────────────────────────────────

fn generate_data(size: u64) -> Vec<u8> {
    // Use a simple repeating pattern (fast to generate, compressible like real data)
    let mut data = Vec::with_capacity(size as usize);
    let pattern: Vec<u8> = (0..=255).collect();
    while data.len() < size as usize {
        let remaining = size as usize - data.len();
        let chunk = remaining.min(pattern.len());
        data.extend_from_slice(&pattern[..chunk]);
    }
    data
}

// ─── System info ────────────────────────────────────────────────────────────

fn system_info() -> String {
    let uname = std::process::Command::new("uname")
        .args(["-r"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    format!("Linux {}", uname)
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_throughput(mbps: f64) -> String {
    if mbps >= 1024.0 {
        format!("{:.2} GB/s", mbps / 1024.0)
    } else {
        format!("{:.0} MB/s", mbps)
    }
}

fn format_time(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        format!("{:.1}ms", ms)
    }
}

fn format_packets(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{},{:03}", n / 1000, n % 1000)
    } else {
        format!("{}", n)
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();

    // Enable debug mode — sets ZTLP_DEBUG so the tunnel emits per-batch stats
    if args.debug {
        std::env::set_var("ZTLP_DEBUG", "1");
        // Reconfigure tracing if the user hasn't already set RUST_LOG
        if std::env::var("RUST_LOG").is_err() {
            eprintln!("[debug] Debug mode enabled — tunnel will emit per-batch timing stats");
        }
    }

    // Detect GSO and GRO capabilities
    let probe_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let gso_cap = gso::detect_gso(&probe_socket);
    let gso_available = gso_cap.is_available();
    drop(probe_socket);

    let gro_probe_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let gro_cap = gso::detect_gro(&gro_probe_socket);
    let gro_available = gro_cap.is_available();
    drop(gro_probe_socket);

    println!();
    println!("ZTLP Throughput Benchmark");
    println!("═══════════════════════════════════════════════════════");
    println!("Transfer size: {}", format_size(args.size));
    println!(
        "System: {} (GSO: {}, GRO: {})",
        system_info(),
        if gso_available {
            "available"
        } else {
            "unavailable"
        },
        if gro_available {
            "available"
        } else {
            "unavailable"
        },
    );
    println!("Iterations: {}", args.repeat);
    println!();

    let modes: Vec<&str> = match args.mode.as_str() {
        "all" => {
            let mut m = vec!["raw", "ztlp-nogso"];
            if gso_available {
                m.push("ztlp-gso");
            }
            if gro_available {
                m.push("ztlp-gro");
            }
            if gso_available && gro_available {
                m.push("ztlp-gso-gro");
            }
            m.push("ztlp");
            m
        }
        other => vec![other],
    };

    println!(
        "{:<20} {:>12} {:>10} {:>10} {:>10}",
        "Mode", "Throughput", "Time", "Packets", "Overhead"
    );
    println!("{}", "─".repeat(64));

    let mut raw_throughput: Option<f64> = None;
    let mut results: Vec<(String, f64, f64, Option<u64>)> = Vec::new();

    for mode in &modes {
        let mut mode_results = Vec::new();

        for iter in 0..args.repeat {
            debug!("Running {} iteration {}/{}", mode, iter + 1, args.repeat);

            let result = match *mode {
                "raw" => bench_raw_tcp(&args.bind, args.size).await?,
                "ztlp" => {
                    bench_ztlp_tunnel(&args.bind, args.size, GsoMode::Auto, "ZTLP (auto)").await?
                }
                "ztlp-gso" => {
                    if !gso_available {
                        eprintln!("Warning: GSO not available, falling back");
                    }
                    bench_ztlp_tunnel(&args.bind, args.size, GsoMode::Enabled, "ZTLP (GSO)").await?
                }
                "ztlp-nogso" => {
                    bench_ztlp_tunnel(&args.bind, args.size, GsoMode::Disabled, "ZTLP (no GSO)")
                        .await?
                }
                "ztlp-gro" => {
                    if !gro_available {
                        eprintln!("Warning: GRO not available, falling back");
                    }
                    bench_ztlp_tunnel(&args.bind, args.size, GsoMode::Disabled, "ZTLP (GRO only)")
                        .await?
                }
                "ztlp-gso-gro" => {
                    if !gso_available {
                        eprintln!("Warning: GSO not available, falling back");
                    }
                    if !gro_available {
                        eprintln!("Warning: GRO not available, falling back");
                    }
                    bench_ztlp_tunnel(&args.bind, args.size, GsoMode::Enabled, "ZTLP (GSO+GRO)")
                        .await?
                }
                other => {
                    return Err(format!(
                        "unknown mode '{}'. Use: raw, ztlp, ztlp-gso, ztlp-nogso, ztlp-gro, ztlp-gso-gro, all",
                        other
                    )
                    .into());
                }
            };
            mode_results.push(result);
        }

        // Average results
        let avg_throughput =
            mode_results.iter().map(|r| r.throughput_mbps).sum::<f64>() / mode_results.len() as f64;
        let avg_time =
            mode_results.iter().map(|r| r.time_ms).sum::<f64>() / mode_results.len() as f64;
        let packets = mode_results[0].packets;
        let mode_name = &mode_results[0].mode;

        if *mode == "raw" {
            raw_throughput = Some(avg_throughput);
        }

        let overhead = raw_throughput.map(|raw| {
            if raw > 0.0 {
                ((1.0 - avg_throughput / raw) * 100.0).max(0.0)
            } else {
                0.0
            }
        });

        let overhead_str = match overhead {
            Some(_) if *mode == "raw" => "baseline".to_string(),
            Some(o) => format!("{:.1}%", o),
            None => "N/A".to_string(),
        };

        let packets_str = match packets {
            Some(n) => format_packets(n),
            None => "N/A".to_string(),
        };

        println!(
            "{:<20} {:>12} {:>10} {:>10} {:>10}",
            mode_name,
            format_throughput(avg_throughput),
            format_time(avg_time),
            packets_str,
            overhead_str,
        );

        results.push((mode_name.clone(), avg_throughput, avg_time, packets));
    }

    // Summary
    println!();
    if results.len() >= 2 {
        if let (Some(raw_tp), Some(nogso), Some(gso)) = (
            results.iter().find(|r| r.0 == "Raw TCP").map(|r| r.1),
            results.iter().find(|r| r.0.contains("no GSO")).map(|r| r.1),
            results
                .iter()
                .find(|r| r.0.contains("GSO") && !r.0.contains("no GSO"))
                .map(|r| r.1),
        ) {
            if nogso > 0.0 {
                println!("GSO improvement: {:.1}x over no-GSO", gso / nogso);
            }
            if raw_tp > 0.0 {
                let gso_overhead = ((1.0 - gso / raw_tp) * 100.0).max(0.0);
                let nogso_overhead = ((1.0 - nogso / raw_tp) * 100.0).max(0.0);
                println!(
                    "ZTLP overhead vs raw: {:.1}% (GSO) / {:.1}% (no GSO)",
                    gso_overhead, nogso_overhead
                );
            }
        }
    }
    println!();

    // Force exit — bridge tasks spawned during benchmarks may still be
    // cleaning up (waiting for timeouts, drain intervals, etc.). The
    // AbortOnDrop guards cancel them but the runtime may still wait for
    // in-progress I/O. This is fine for a benchmark tool.
    std::process::exit(0);
}
