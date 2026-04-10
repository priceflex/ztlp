# Relay VIP Architecture with NS-driven Relay Selection

Date: 2026-04-10
Status: Design

## Goal

Move VIP proxy / TCP termination out of the iOS Network Extension to relay servers.
NS drives relay discovery and selection. The NE becomes a pure packet encryptor/decryptor
with zero NWListeners, saving ~5-8MB and dropping NE memory from 18-21MB to ~10-13MB.

## Existing Infrastructure

### What already exists
- **relay_pool.rs** (sync, no tokio): `RelayPool`, `RelayEntry`, `RelayHealth`, `RelayPoolConfig`,
  `FailoverDecision`, exponential backoff, failover, score-based selection. No FFI exposure yet.
- **NS wire protocol**: RELAY record type 3 with `"endpoints"` CBOR key already defined
- **ZTLPNSClient.swift**: Full sync NS client using BSD sockets (SVC + KEY queries)
- **ZtlpConfig**: Already has `relay_address` field
- **relay.rs** (tokio-gated): `RelayConnection`, `SimulatedRelay` — not usable in ios-sync builds
- **Current relay server**: 34.219.64.205 (UDP relay for ZTLP protocol)

### What needs to be built
- Sync NS resolver in Rust (`ztlp_ns_resolve_sync` using `std::net::UdpSocket`)
- NS RELAY record querying (type 3) in Rust sync path + Swift NSClient
- FFI functions for RelayPool (select, update, failover)
- Relay-side TCP termination and service routing
- Extended NS protocol for relay stats (latency, load, health)

## Architecture

### Current flow (VIP proxy in NE)
```
App → TCP connect 127.0.0.1:443 → NWListener accepts → NWConnection
  → read data → ztlp_frame_data() → ztlp_encrypt_packet() → sendPacket()
  Gateway response → decrypt → parse_frame → deliverData → NWConnection write → App

NE components: 5 NWListeners + ZTLPVIPProxy + ZTLPTunnelConnection + PacketRouter
NE memory: ~18-21 MB
```

### New flow (relay-side TCP termination)
```
1. NE connects → handshake with gateway
2. NE queries NS: "what relays are available?"
3. NS responds with relay list + stats
4. NE picks best relay via RelayPool selection
5. App traffic captured by packetFlow → NE encrypts → sends to relay via UDP tunnel
6. Relay decrypts → terminates TCP to backend → receives response
7. Relay encrypts response → sends back through tunnel
8. NE decrypts → writes to packetFlow → App receives response

NE components: packetFlow + 1 NWConnection (UDP) + encrypt/decrypt
NE memory: ~10-13 MB
```

### Failover flow
```
1. Relay drops or becomes unhealthy
2. NE detects failure (timeout / no ACK advance)
3. NE calls RelayPool.failover (marks primary dead/degraded)
4. If FailoverDecision::NeedNsRefresh → re-query NS for fresh relay list
5. NS returns updated list (may exclude failed relay)
6. NE picks next best relay from pool
7. NE reconnects tunnel through new relay
8. If FailoverDecision::NoRelaysAvailable → error, stop tunnel
```

## NS Relay Discovery Protocol

### Current NS wire protocol
- Query: `[0x01] [name_len: u16 BE] [name bytes] [record_type: u8]`
- Response: `[opcode: u8] [record_type: u8] [name_len: u16 BE] [name] [data_len: u32 BE] [data: CBOR]`
- Opcodes: 0x02=FOUND, 0x03=NOT_FOUND, 0x04=REVOKED
- Existing record types: KEY(1), SVC(2), RELAY(3), POLICY(4), REVOKE(5), BOOTSTRAP(6), OPERATOR(7)

### Current RELAY record (type 3)
- CBOR data: `{"endpoints": "<comma-separated ip:port list>"}`

This is too limited for relay selection. We need stats.

### Extended RELAY record format

Two approaches:

**Option A: Rich CBOR in NS response (recommended)**
```json
{
  "endpoints": [
    {
      "address": "34.219.64.205:23095",
      "region": "us-west-2",
      "latency_ms": 12,
      "load_pct": 35,
      "active_connections": 42,
      "health": "healthy"
    },
    {
      "address": "10.0.1.50:23095",
      "region": "us-east-1",
      "latency_ms": 45,
      "load_pct": 80,
      "active_connections": 156,
      "health": "degraded"
    }
  ]
}
```

Pros: One NS query gives everything. Client has all info for selection.
Cons: Larger NS response. NS must track relay stats.

**Option B: Minimal endpoints in NS, separate stats endpoint**
NS returns just addresses. NE queries each relay or a stats endpoint for load/latency.
Pros: Smaller NS response. Stats can be real-time.
Cons: More round trips. Can't filter before selecting.

**Recommendation: Option A.** One round trip to NS, all selection data available.
NS already tracks relay health for routing. The extra CBOR is ~100-200 bytes per relay.
For 3-5 relays that's <1KB — trivial for a UDP response.

### Backward compatibility
- Old clients that only understand `"endpoints": "ip:port,ip:port"` still work
- New clients that see `"endpoints": [...]` (array of objects) use the rich format
- NS can detect client version or serve both formats
- Or: NS always serves the rich format, old string format is deprecated

### CBOR encoding for rich endpoints
```
A1                     -- map(1)
  6A 65 6E 64 70 6F 69 6E 74 73  -- key: "endpoints"
  82                   -- array(2)
    A5                 -- map(5)
      67 61 64 64 72 65 73 73  -- key: "address"
      72 33 34 2E 32 31 39 2E 36 34 2E 32 30 35 3A 32 33 30 39 35  -- value: "34.219.64.205:23095"
      66 72 65 67 69 6F 6E     -- key: "region"
      69 75 73 2D 77 65 73 74 2D 32  -- value: "us-west-2"
      6A 6C 61 74 65 6E 63 79 5F 6D 73  -- key: "latency_ms"
      0C                        -- value: 12
      68 6C 6F 61 64 5F 70 63 74  -- key: "load_pct"
      18 23                     -- value: 35
      6C 61 63 74 69 76 65 5F 63 6F 6E 6E 65 63 74 69 6F 6E 73  -- key: "active_connections"
      18 2A                     -- value: 42
```

## Relay Selection Algorithm

Implemented in `RelayPool` (relay_pool.rs), already sync-safe.

### Current algorithm (relay_pool.rs)
- `RelayEntry.score()`: `latency_ms + health_penalty`
  - Healthy: 0 penalty
  - Deprioritized: +200ms penalty
  - Degraded: +500ms penalty
  - Dead: excluded from selection

### Proposed enhancement
Replace simple score with: `latency_ms * (1 + load_pct / 100)`

This penalizes loaded relays proportionally:
- Relay A: 20ms latency, 10% load → score = 20 * 1.10 = 22
- Relay B: 15ms latency, 80% load → score = 15 * 1.80 = 27
- Relay A wins despite higher latency — it's less loaded

Additional tiebreakers:
1. Same region as gateway → -10ms bonus
2. Fewer active connections → preferred

### Implementation plan
1. Extend `RelayEntry` with `region`, `load_pct`, `active_connections` fields
2. Update `RelayEntry.score()` to use load-adjusted formula
3. Add `region` match bonus in selection
4. Add FFI: `ztlp_relay_pool_new`, `ztlp_relay_pool_update_from_ns`,
   `ztlp_relay_pool_select`, `ztlp_relay_pool_failover`,
   `ztlp_relay_pool_needs_refresh`, `ztlp_relay_pool_free`
5. Add tests for selection algorithm (pure computation, Linux-testable)

## Sync NS Resolution

### Implementation: ztlp_ns_resolve_sync

Pattern: same as `ztlp_connect_sync` — `std::net::UdpSocket`, no tokio.

```rust
#[no_mangle]
pub extern "C" fn ztlp_ns_resolve_sync(
    ns_server: *const c_char,   // "ip:port"
    name: *const c_char,        // service name to resolve
    record_type: u8,            // 1=KEY, 2=SVC, 3=RELAY
    timeout_ms: u32,
) -> *mut ZtlpNsResult
```

Returns a new `ZtlpNsResult` type:
```rust
pub struct ZtlpNsResult {
    pub records: Vec<NsRecord>,   // parsed records
    pub error: Option<String>,    // error message if failed
}

pub struct NsRecord {
    pub record_type: u8,
    pub name: String,
    pub data: Vec<u8>,   // raw CBOR data
}
```

CBOR parsing: reuse the minimal `cbor_extract_string()` from `agent/proxy.rs`
or implement a lightweight CBOR map parser that can extract string/integer values.

### For relay discovery specifically
```rust
#[no_mangle]
pub extern "C" fn ztlp_ns_resolve_relays_sync(
    ns_server: *const c_char,
    name: *const c_char,        // zone or service name
    timeout_ms: u32,
) -> *mut ZtlpRelayList
```

Returns parsed `ZtlpRelayList` with `RelayInfo` structs ready for `RelayPool.update_from_ns()`.

This is a convenience wrapper that:
1. Calls `ztlp_ns_resolve_sync` with record_type=3 (RELAY)
2. Parses CBOR "endpoints" array
3. Returns typed `RelayInfo` structs

### Wire into RelayPool
```rust
// In PacketTunnelProvider.swift:
// 1. Resolve relays from NS
let relayList = ztlp_ns_resolve_relays_sync(nsServer, zone, 5000)
// 2. Update relay pool
ztlp_relay_pool_update_from_ns(pool, relayList)
// 3. Select best relay
let selected = ztlp_relay_pool_select(pool)
// 4. Connect to selected relay via existing tunnel
```

## Relay-side TCP Termination

### What the relay needs to do
1. Accept ZTLP-encrypted UDP packets from NE
2. Decrypt using session keys (same as gateway)
3. Parse mux frames to extract service name + TCP payload
4. Make TCP connection to the actual backend service
5. Forward payload to backend
6. Receive backend response
7. Wrap in mux frame, encrypt, send back through tunnel

### Relay service routing
The relay needs a service registry:
```
vault   → 127.0.0.1:8080  (or gateway VIP:8080)
web     → 127.0.0.1:80
api     → 127.0.0.1:8443
```

This is similar to what `ZTLPVIPProxy.swift` does today, but on the server side
where memory is unlimited.

### Relay crypto
The relay already handles ZTLP encryption for relayed packets. For VIP proxying,
the relay needs to:
- Decrypt incoming mux frames from the NE
- Read the service name from the mux header
- Route to the correct backend
- Encrypt responses back to the NE

This reuses the existing `ZtlpCryptoContext` encrypt/decrypt functions.

### Implementation
Add to the existing relay binary or create a relay-side VIP proxy module:
```rust
// proto/src/relay_vip.rs (new module, not feature-gated for NE)
// Server-side VIP proxy: decrypt → TCP connect → forward → encrypt response

pub struct RelayVIPProxy {
    services: HashMap<String, SocketAddr>,  // service name → backend addr
    crypto: ZtlpCryptoContext,
}

impl RelayVIPProxy {
    pub fn handle_frame(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        // 1. Parse mux frame: extract service name + payload
        // 2. Lookup backend address for service
        // 3. TCP connect + send payload + read response
        // 4. Wrap response in mux frame
        // 5. Return encrypted frame
    }
}
```

This module runs on the relay server (Linux), NOT in the NE.
Fully testable on Linux with real TCP backends.

## Migration Plan

### Phase 1: Sync NS resolver + relay selection (no NE changes yet)
1. Implement `ztlp_ns_resolve_sync` in Rust FFI
2. Implement `ztlp_ns_resolve_relays_sync` convenience function
3. Extend `RelayEntry` with `region`, `load_pct`, `active_connections`
4. Update `RelayEntry.score()` with load-adjusted formula
5. Add `RelayPool` FFI functions
6. Add selection algorithm tests
7. Build and test on Linux — zero iOS changes needed

### Phase 2: Relay-side VIP proxy
1. Implement `relay_vip.rs` module
2. Add service routing config to relay server
3. Test with local fake backends on Linux
4. Deploy to relay server

### Phase 3: NE changes
1. Remove ZTLPVIPProxy.swift from ZTLPTunnel target
2. Remove 5 NWListener port registrations
3. Wire relay selection: NS → RelayPool → select → connect
4. Wire failover: detect failure → RelayPool.failover → reconnect
5. Route VIP traffic through packetFlow → tunnel → relay
6. Verify NE memory drops to ~10-13MB
7. Verify end-to-end service access works

### Phase 4: Swift NSClient update
1. Add RELAY record type (3) query support to ZTLPNSClient.swift
2. Parse rich "endpoints" array CBOR format
3. Return typed RelayInfo structs to Swift
4. Wire into PacketTunnelProvider for relay discovery

## Files to Create/Modify

### New files
- `proto/src/ns_sync.rs` — sync NS resolver using std::net::UdpSocket
- `proto/src/relay_vip.rs` — server-side VIP proxy (runs on relay, not NE)

### Modified files
- `proto/src/lib.rs` — add `ns_sync` module
- `proto/src/relay_pool.rs` — extend RelayEntry with region/load/connections, update score
- `proto/src/ffi.rs` — add ztlp_ns_resolve_sync, ztlp_ns_resolve_relays_sync,
  ztlp_relay_pool_* FFI functions
- `proto/include/ztlp.h` — C header updates for new FFI
- `ios/ZTLP/Libraries/ztlp.h` — iOS copy of C header
- `ios/ZTLP/ZTLPTunnel/ZTLPNSClient.swift` — add RELAY query support
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — wire relay selection, remove VIP proxy

### Test files
- `proto/src/ns_sync.rs` (inline tests) — NS wire protocol parsing, query construction
- `proto/src/relay_pool.rs` (extend existing tests) — selection algorithm with load/region
- `proto/tests/ns_resolve_sync_integration.rs` — integration test against fake NS server

## Memory Budget After Migration

```
FIXED COSTS (~8-9 MB):
  Rust staticlib TEXT (ios-sync):   ~1.65 MB
  Rust DATA + heap:                  ~2-3 MB
  Swift runtime:                    ~2-3 MB
  Foundation framework:             ~1 MB
  Network.framework (1 NWConnection): ~0.5-1 MB  ← was ~1-2 MB with 5 NWListeners

VARIABLE COSTS (~1-2 MB):
  Outbound queue (128 × 1.4KB):     ~175 KB
  Reassembly (256 × 1.2KB):        ~300 KB
  SendController queues:           ~600 KB
  seenSequences (2K entries):       ~32 KB
  Channels + misc:                  ~500 KB

TOTAL: ~10-11 MB (comfortably under 15 MB)

SAVINGS vs current:
  Removed: 5 NWListeners             -1-2 MB
  Removed: VIPProxy connections      -0.5-1 MB
  Removed: NWConnection.send() queues (VIP)  -3-5 MB
  Removed: Network.framework (NWListener)    -0.5-1 MB
  Net savings:                       -5-8 MB
```
