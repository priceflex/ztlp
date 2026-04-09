# ZTLP iOS Session 5 Status: Strip Tokio

## Completed (Session 5A — Rust side)

### Feature-gating (commit db188f8)
- Added [features] section to proto/Cargo.toml:
  - tokio-runtime (default): full async runtime + CLI deps  
  - ios-sync: builds without tokio for iOS NE
- 17 tokio-dependent modules gated in lib.rs
- 30+ async FFI functions gated in ffi.rs
- Both builds compile clean:
  - `cargo check --lib` (default) ✓
  - `cargo check --lib --no-default-features --features ios-sync` ✓

### Standalone PacketRouter FFI (new)
- Added ZtlpPacketRouter opaque handle
- New sync functions (no ZtlpClient needed):
  - ztlp_router_new_sync(tunnel_addr) → *ZtlpPacketRouter
  - ztlp_router_add_service_sync(router, vip, service_name)
  - ztlp_router_write_packet_sync(router, data, len, action_buf, action_buf_len, action_written) → action_count
  - ztlp_router_read_packet_sync(router, buf, buf_len) → bytes_written
  - ztlp_router_gateway_data_sync(router, stream_id, data, len)
  - ztlp_router_gateway_close_sync(router, stream_id)
  - ztlp_router_stop_sync(router)
- Action serialization format: [1B type][4B stream_id BE][2B data_len BE][data...]
  - Type 0=OpenStream, 1=SendData, 2=CloseStream

### Existing sync FFI (unchanged, all available in ios-sync builds)
- ztlp_connect_sync() — Noise_XX handshake via std::net::UdpSocket
- ztlp_encrypt_packet() / ztlp_decrypt_packet()
- ztlp_frame_data() / ztlp_parse_frame() / ztlp_build_ack()
- ztlp_identity_* / ztlp_config_* / ztlp_init / ztlp_shutdown
- ztlp_crypto_context_* accessors

## New Swift Files (written, need Xcode integration)
- ZTLPTunnelConnection.swift — NWConnection recv/send loop + sync FFI
- ZTLPVIPProxy.swift — NWListener replacing tokio TcpListener

## Remaining (Session 5B — on Steve's Mac)
1. Update ztlp.h with new standalone router declarations
2. Add Swift files to Xcode project
3. Update PacketTunnelProvider.swift:
   - Replace bridge.connect() with ztlp_connect_sync() 
   - Replace bridge recv loop with ZTLPTunnelConnection
   - Replace bridge VIP proxy with ZTLPVIPProxy
   - Add GCD timers for ACK flush (10ms) and RTO retransmit
4. Build libztlp_proto.a with: cargo build --target aarch64-apple-ios --release --lib --no-default-features --features ios-sync
5. Check TEXT segment size (target: ~2.5-3MB, down from 4.7MB)
6. Deploy to device, run memory check
7. Run 11-test benchmark
8. Tag result: v0.24.2-no-tokio-NofN

## Key Architecture Decisions
- PacketRouter stays in Rust (2061 lines, fully sync, battle-tested)
- mobile.rs was ungated — has zero actual tokio deps
- encode_service_name duplicated in ffi.rs (12-line pure fn) since tunnel.rs is gated
- Standalone router FFI serializes RouterActions into a flat byte buffer for Swift parsing
- VIP proxy on 127.0.0.1 runs via NWListener (Swift) alongside the utun packet router (Rust)

## Rollback
- Pre-tokio-strip: git checkout v0.24.2-pre-tokio-strip
- Baseline: git checkout v0.24.1-baseline-8of11

## Build Commands
```
# iOS staticlib (no tokio)
cargo build --target aarch64-apple-ios --release --lib --no-default-features --features ios-sync

# Check TEXT segment
size target/aarch64-apple-ios/release/libztlp_proto.a

# Server/CLI (full tokio, default)
cargo build --release
```
