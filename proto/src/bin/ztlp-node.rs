//! ZTLP Node — main binary that can act as initiator or responder.
//!
//! Usage:
//!   ztlp-node --listen 0.0.0.0:5A37
//!   ztlp-node --connect <peer-addr> --identity node.json

#![deny(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::transport::TransportNode;

/// ZTLP Node — Zero Trust Layer Protocol node.
#[derive(Parser, Debug)]
#[command(name = "ztlp-node", about = "ZTLP protocol node")]
struct Args {
    /// Address to listen on (e.g., 0.0.0.0:23095).
    #[arg(short, long, default_value = "0.0.0.0:23095")]
    listen: String,

    /// Path to identity JSON file. If not provided, generates a new identity.
    #[arg(short, long)]
    identity: Option<PathBuf>,

    /// Peer address to connect to (initiator mode).
    #[arg(short, long)]
    connect: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ztlp_proto=info".parse()?),
        )
        .init();

    let args = Args::parse();

    // Load or generate identity
    let identity = if let Some(path) = &args.identity {
        info!("loading identity from {}", path.display());
        NodeIdentity::load(path)?
    } else {
        info!("generating new identity");
        let ident = NodeIdentity::generate()?;
        info!("node ID: {}", ident.node_id);
        ident
    };

    info!("node ID: {}", identity.node_id);

    // Bind transport
    let node = TransportNode::bind(&args.listen).await?;
    info!("listening on {}", node.local_addr);

    if let Some(peer_addr) = &args.connect {
        info!("initiator mode — connecting to {}", peer_addr);
        // TODO: implement full handshake flow over the network
        info!("full network handshake not yet implemented in ztlp-node");
        info!("use ztlp-demo for the complete demonstration");
    } else {
        info!("responder mode — waiting for connections");
        // Simple receive loop
        loop {
            match node.recv_data().await {
                Ok(Some((data, from))) => {
                    info!(
                        "received {} bytes from {}: {}",
                        data.len(),
                        from,
                        String::from_utf8_lossy(&data)
                    );
                }
                Ok(None) => {
                    // Packet dropped by pipeline
                }
                Err(e) => {
                    tracing::error!("receive error: {}", e);
                }
            }
        }
    }

    Ok(())
}
