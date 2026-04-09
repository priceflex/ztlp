# Client-Type Detection — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Gateway detects mobile vs desktop clients and applies per-client CC profiles,
giving iOS the conservative CC it needs while desktop/server clients get full speed.

**Architecture:** Client self-reports its type in the Noise_XX message 3 encrypted
payload (currently empty). Gateway parses it and selects one of 4 CC profiles.
Backward compatible — old clients send empty payload, gateway defaults to mobile CC.

**Tech Stack:** Rust (proto crate), Elixir (gateway), Swift (iOS NE), CBOR serialization

---

## Current State (what exists today)

### Handshake Flow
```
Client                          Gateway
  |                                |
  |── msg1: HELLO (ephemeral) ───→ |  write_message(&[])
  |                                |
  |←── msg2: HELLO_ACK ──────────|  write_message(&[])
  |                                |
  |── msg3: CONFIRM ─────────────→ |  write_message(&[])  ← EMPTY PAYLOAD
  |   [encrypted_s: 48B]          |
  |   [encrypted_payload: 16B]    |  ← just AEAD tag, 0 bytes plaintext
  |                                |
  |   Session established          |  CC: hardcoded @initial_cwnd 10.0, @max_cwnd 32
```

### Key Code Locations

**Rust (client side):**
- `proto/src/handshake.rs:452` — `initiator.write_message(&[])` (msg3, lib API)
- `proto/src/ffi.rs:894-895` — `ctx.write_message(&[])` (msg3, tokio-runtime FFI)
- `proto/src/ffi.rs:4339-4340` — `ctx.write_message(&[])` (msg3, sync FFI for iOS)

**Elixir (gateway side):**
- `gateway/lib/ztlp_gateway/handshake.ex:307` — `create_msg3(state, payload \\ <<>>)`
- `gateway/lib/ztlp_gateway/handshake.ex:436` — parses msg3, returns `{hs, payload}`
- `gateway/lib/ztlp_gateway/session.ex:1267-1279` — receives msg3, DISCARDS payload (`_payload`)
- `gateway/lib/ztlp_gateway/session.ex:440-488` — CC constants (module attributes)
- `gateway/lib/ztlp_gateway/session.ex:555+` — session state init with CC values

**Swift (iOS):**
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift:140+` — `ztlp_connect_sync()` call
- No client metadata is sent currently

**Existing serialization:**
- Rust: `serde` + `serde_json` in Cargo.toml. No CBOR crate yet.
- Gateway: `ZtlpGateway.Cbor` module (hand-rolled RFC 8949 encoder/decoder, used for NS records)

---

## Target State

```
Client                          Gateway
  |                                |
  |── msg1: HELLO ───────────────→ |
  |←── msg2: HELLO_ACK ──────────|
  |── msg3: CONFIRM ─────────────→ |  write_message(&client_profile_cbor)
  |   [encrypted_s: 48B]          |
  |   [encrypted_payload: ~30B]   |  ← ClientProfile CBOR (6-80 bytes)
  |                                |
  |   Session established          |  CC: selected by client_class + interface_type
```

---

## Task 1: Add CBOR dependency to Rust proto crate

**Objective:** Add the `ciborium` crate for CBOR serialization (integrates with serde).

**Files:**
- Modify: `proto/Cargo.toml`

**Steps:**

1. Add `ciborium` to `[dependencies]` (NOT optional — needed for all builds including iOS):
```toml
ciborium = "0.2"
```

2. Verify both builds compile:
```bash
cd proto && cargo check
cd proto && cargo check --target aarch64-apple-ios --no-default-features --features ios-sync --lib
```

3. Commit:
```bash
git add proto/Cargo.toml
git commit -m "feat: add ciborium CBOR dependency for client profile serialization"
```

---

## Task 2: Define ClientProfile struct in Rust

**Objective:** Create the ClientProfile data structure that clients will send in msg3.

**Files:**
- Create: `proto/src/client_profile.rs`
- Modify: `proto/src/lib.rs` (add module)

**ClientProfile struct:**

```rust
// proto/src/client_profile.rs
use serde::{Deserialize, Serialize};

/// Client profile sent in the Noise_XX message 3 encrypted payload.
/// The gateway uses this to select per-client congestion control parameters.
///
/// Wire format: CBOR-encoded, typically 15-80 bytes.
/// Backward compatible: gateway treats empty/unparseable payload as Unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// What kind of device this is.
    #[serde(rename = "c")]
    pub client_class: ClientClass,

    /// Network interface type at connection time.
    #[serde(rename = "i")]
    pub interface_type: InterfaceType,

    /// Cellular radio technology (only meaningful when interface_type = Cellular).
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub radio_tech: Option<RadioTech>,

    /// iOS Low Data Mode or equivalent bandwidth constraint.
    #[serde(rename = "l", default)]
    pub is_constrained: bool,

    /// Software identity string (e.g., "ztlp-cli/0.24.0" or "ztlp-ios/0.24.0").
    #[serde(rename = "s")]
    pub software_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ClientClass {
    #[serde(rename = "u")]
    Unknown,
    #[serde(rename = "m")]
    Mobile,
    #[serde(rename = "d")]
    Desktop,
    #[serde(rename = "v")]
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum InterfaceType {
    #[serde(rename = "u")]
    Unknown,
    #[serde(rename = "c")]
    Cellular,
    #[serde(rename = "w")]
    WiFi,
    #[serde(rename = "e")]
    Wired,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RadioTech {
    #[serde(rename = "2")]
    Gen2,       // 2G (GPRS/EDGE)
    #[serde(rename = "3")]
    Gen3,       // 3G (WCDMA/HSPA)
    #[serde(rename = "4")]
    LTE,        // 4G LTE
    #[serde(rename = "5n")]
    NR_NSA,     // 5G Non-Standalone
    #[serde(rename = "5s")]
    NR_SA,      // 5G Standalone
}

impl ClientProfile {
    /// Serialize to CBOR bytes for inclusion in Noise_XX msg3 payload.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization cannot fail");
        buf
    }

    /// Deserialize from CBOR bytes. Returns None if payload is empty or invalid.
    pub fn from_cbor(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        ciborium::from_reader(data).ok()
    }

    /// Default profile for desktop CLI clients.
    pub fn desktop(software_id: String) -> Self {
        Self {
            client_class: ClientClass::Desktop,
            interface_type: InterfaceType::Unknown,
            radio_tech: None,
            is_constrained: false,
            software_id,
        }
    }

    /// Default profile for iOS clients (interface_type set by caller).
    pub fn mobile(software_id: String, interface_type: InterfaceType) -> Self {
        Self {
            client_class: ClientClass::Mobile,
            interface_type,
            radio_tech: None,
            is_constrained: false,
            software_id,
        }
    }
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            client_class: ClientClass::Unknown,
            interface_type: InterfaceType::Unknown,
            radio_tech: None,
            is_constrained: false,
            software_id: String::new(),
        }
    }
}
```

**Add module to lib.rs:**
```rust
pub mod client_profile;
```
This is NOT gated behind any feature — both tokio-runtime and ios-sync builds need it.

**Tests (in client_profile.rs):**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_roundtrip() {
        let profile = ClientProfile::desktop("ztlp-cli/0.24.0".into());
        let cbor = profile.to_cbor();
        let decoded = ClientProfile::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.client_class, ClientClass::Desktop);
        assert_eq!(decoded.software_id, "ztlp-cli/0.24.0");
    }

    #[test]
    fn test_mobile_cellular_roundtrip() {
        let mut profile = ClientProfile::mobile("ztlp-ios/0.24.0".into(), InterfaceType::Cellular);
        profile.radio_tech = Some(RadioTech::LTE);
        profile.is_constrained = true;
        let cbor = profile.to_cbor();
        assert!(cbor.len() < 80, "CBOR should be compact, got {} bytes", cbor.len());
        let decoded = ClientProfile::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.client_class, ClientClass::Mobile);
        assert_eq!(decoded.interface_type, InterfaceType::Cellular);
        assert_eq!(decoded.radio_tech, Some(RadioTech::LTE));
        assert!(decoded.is_constrained);
    }

    #[test]
    fn test_empty_payload_returns_none() {
        assert!(ClientProfile::from_cbor(&[]).is_none());
    }

    #[test]
    fn test_garbage_payload_returns_none() {
        assert!(ClientProfile::from_cbor(&[0xFF, 0xFE, 0xFD]).is_none());
    }
}
```

**Verify:**
```bash
cargo test client_profile
```

**Commit:**
```bash
git add proto/src/client_profile.rs proto/src/lib.rs
git commit -m "feat: ClientProfile struct with CBOR serialization for handshake"
```

---

## Task 3: Send ClientProfile in Rust handshake (library + tokio FFI)

**Objective:** Include ClientProfile CBOR in the Noise_XX msg3 payload.

**Files:**
- Modify: `proto/src/handshake.rs:452` — library-level handshake
- Modify: `proto/src/ffi.rs:894-895` — tokio-runtime FFI connect
- Modify: `proto/src/ffi.rs` — add client_profile field to ZtlpClientInner or connect params

**Changes to handshake.rs:**

The `HandshakeContext::write_msg3()` method currently calls `write_message(&[])`.
Add an optional payload parameter:

```rust
// Change: pub fn write_msg3(&mut self) -> Result<Vec<u8>>
// To:     pub fn write_msg3(&mut self, payload: &[u8]) -> Result<Vec<u8>>
//
// Then internally: self.noise.write_message(payload)
```

All existing callers must be updated to pass either `&[]` (backward compat)
or `&profile.to_cbor()`.

**Changes to ffi.rs (tokio-runtime path, ~line 894):**

```rust
// Before:
let msg3 = ctx.write_message(&[]).map_err(|e| ...)?;

// After:
let profile = ClientProfile::desktop(format!("ztlp/{}", env!("CARGO_PKG_VERSION")));
let profile_cbor = profile.to_cbor();
let msg3 = ctx.write_message(&profile_cbor).map_err(|e| ...)?;
```

**Verify:** `cargo check` and `cargo test`

**Commit:**
```bash
git commit -am "feat: send ClientProfile in Noise_XX msg3 payload (desktop default)"
```

---

## Task 4: Send ClientProfile from iOS sync FFI

**Objective:** iOS sync connect sends mobile ClientProfile with interface_type.

**Files:**
- Modify: `proto/src/ffi.rs:4339-4340` — sync FFI connect (ztlp_connect_sync)
- Modify: `proto/src/ffi.rs` — add new FFI function for setting client profile
- Modify: `proto/include/ztlp.h` — add C header declaration

**New FFI function:**

```rust
/// Set the client profile for the next connection.
/// Call BEFORE ztlp_connect_sync().
/// interface_type: 0=Unknown, 1=Cellular, 2=WiFi, 3=Wired
/// radio_tech: 0=Unknown, 1=2G, 2=3G, 3=LTE, 4=5G-NSA, 5=5G-SA
/// is_constrained: 0=false, 1=true
#[no_mangle]
pub extern "C" fn ztlp_set_client_profile(
    interface_type: u8,
    radio_tech: u8,
    is_constrained: u8,
) {
    // Store in thread-local or static for ztlp_connect_sync to pick up
}
```

**Change in ztlp_connect_sync (~line 4339):**
```rust
// Before:
let msg3 = ctx.write_message(&[]).map_err(|e| ...)?;

// After:
let profile = build_mobile_profile(/* from stored values */);
let msg3 = ctx.write_message(&profile.to_cbor()).map_err(|e| ...)?;
```

**Add to ztlp.h:**
```c
void ztlp_set_client_profile(uint8_t interface_type, uint8_t radio_tech, uint8_t is_constrained);
```

**Verify:** `cargo check --target aarch64-apple-ios --no-default-features --features ios-sync --lib`

**Commit:**
```bash
git commit -am "feat: iOS sync FFI sends mobile ClientProfile in handshake"
```

---

## Task 5: Call ztlp_set_client_profile from Swift

**Objective:** iOS PacketTunnelProvider populates client profile from NWPath before connecting.

**Files:**
- Modify: `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — before ztlp_connect_sync() call

**Add before the connect call (~line 170, before ztlp_connect_sync):**

```swift
// Detect network type for client profile
let pathMonitor = NWPathMonitor()
let currentPath = pathMonitor.currentPath

let interfaceType: UInt8
if currentPath.usesInterfaceType(.cellular) {
    interfaceType = 1  // Cellular
} else if currentPath.usesInterfaceType(.wifi) {
    interfaceType = 2  // WiFi
} else if currentPath.usesInterfaceType(.wiredEthernet) {
    interfaceType = 3  // Wired
} else {
    interfaceType = 0  // Unknown
}

// Detect radio technology
var radioTech: UInt8 = 0  // Unknown
if #available(iOS 14.0, *) {
    let teleInfo = CTTelephonyNetworkInfo()
    if let radioAccess = teleInfo.serviceCurrentRadioAccessTechnology?.values.first {
        switch radioAccess {
        case CTRadioAccessTechnologyGPRS, CTRadioAccessTechnologyEdge:
            radioTech = 1  // 2G
        case CTRadioAccessTechnologyWCDMA, CTRadioAccessTechnologyHSDPA, CTRadioAccessTechnologyHSUPA:
            radioTech = 2  // 3G
        case CTRadioAccessTechnologyLTE:
            radioTech = 3  // LTE
        default:
            if radioAccess.contains("NR") {
                radioTech = 4  // 5G
            }
        }
    }
}

let isConstrained: UInt8 = currentPath.isConstrained ? 1 : 0

ztlp_set_client_profile(interfaceType, radioTech, isConstrained)

// Then the existing ztlp_connect_sync() call follows...
```

**Add import at top of file:**
```swift
import CoreTelephony
```

**Verify:** Build in Xcode (can't build via SSH due to codesign).

**Commit:**
```bash
git commit -am "feat: iOS NE reports network type in client profile"
```

---

## Task 6: Gateway parses ClientProfile from msg3 payload

**Objective:** Gateway extracts and stores ClientProfile from the handshake.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/session.ex:1267-1279` — stop discarding `_payload`
- Modify: `gateway/lib/ztlp_gateway/session.ex` — add `client_profile` to session state

**Parse the msg3 payload (~line 1273):**

```elixir
# Before:
{hs, _payload} = ...

# After:
{hs, profile_payload} = ...
client_profile = parse_client_profile(profile_payload)
```

**Add parser function:**

```elixir
defp parse_client_profile(<<>>) do
  # Empty payload = legacy client, default to conservative mobile
  %{client_class: :unknown, interface_type: :unknown, radio_tech: nil,
    is_constrained: false, software_id: ""}
end

defp parse_client_profile(payload) when is_binary(payload) do
  case Cbor.decode(payload) do
    {:ok, map} when is_map(map) ->
      %{
        client_class: parse_client_class(map["c"]),
        interface_type: parse_interface_type(map["i"]),
        radio_tech: parse_radio_tech(map["r"]),
        is_constrained: map["l"] == true,
        software_id: map["s"] || ""
      }
    _ ->
      # Unparseable = treat as legacy
      %{client_class: :unknown, interface_type: :unknown, radio_tech: nil,
        is_constrained: false, software_id: ""}
  end
end

defp parse_client_class("m"), do: :mobile
defp parse_client_class("d"), do: :desktop
defp parse_client_class("v"), do: :server
defp parse_client_class(_), do: :unknown

defp parse_interface_type("c"), do: :cellular
defp parse_interface_type("w"), do: :wifi
defp parse_interface_type("e"), do: :wired
defp parse_interface_type(_), do: :unknown

defp parse_radio_tech("4"), do: :lte
defp parse_radio_tech("5n"), do: :nr_nsa
defp parse_radio_tech("5s"), do: :nr_sa
defp parse_radio_tech("3"), do: :gen3
defp parse_radio_tech("2"), do: :gen2
defp parse_radio_tech(_), do: nil
```

**Store in session state (in init or after handshake):**

Add `client_profile: nil` to the initial state struct (~line 555), then set it
after msg3 is processed.

**Verify:** `cd gateway && mix test`

**Commit:**
```bash
git commit -am "feat: gateway parses ClientProfile from msg3 payload"
```

---

## Task 7: Gateway selects CC profile based on ClientProfile

**Objective:** Replace hardcoded CC constants with per-session values selected by client type.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/session.ex` — add CC profile selection
- Modify: `gateway/lib/ztlp_gateway/session.ex` — use selected profile in session init

**CC profile selection function:**

```elixir
defp select_cc_profile(%{client_class: :mobile, interface_type: :cellular}) do
  %{initial_cwnd: 5.0, max_cwnd: 16, initial_ssthresh: 32,
    pacing_interval_ms: 6, burst_size: 2, loss_beta: 0.7}
end

defp select_cc_profile(%{client_class: :mobile, interface_type: :wifi}) do
  %{initial_cwnd: 10.0, max_cwnd: 32, initial_ssthresh: 64,
    pacing_interval_ms: 4, burst_size: 3, loss_beta: 0.7}
end

defp select_cc_profile(%{client_class: :mobile}) do
  # Mobile with unknown interface → use wifi profile (safe middle ground)
  %{initial_cwnd: 10.0, max_cwnd: 32, initial_ssthresh: 64,
    pacing_interval_ms: 4, burst_size: 3, loss_beta: 0.7}
end

defp select_cc_profile(%{client_class: :desktop}) do
  %{initial_cwnd: 64.0, max_cwnd: 256, initial_ssthresh: 128,
    pacing_interval_ms: 1, burst_size: 8, loss_beta: 0.7}
end

defp select_cc_profile(%{client_class: :server}) do
  %{initial_cwnd: 64.0, max_cwnd: 512, initial_ssthresh: 256,
    pacing_interval_ms: 1, burst_size: 16, loss_beta: 0.7}
end

defp select_cc_profile(_unknown) do
  # Legacy client or unknown → conservative mobile-wifi (no regression)
  %{initial_cwnd: 10.0, max_cwnd: 32, initial_ssthresh: 64,
    pacing_interval_ms: 4, burst_size: 3, loss_beta: 0.7}
end
```

**Apply profile after handshake completes:**

After parsing client_profile in the msg3 handler, call:
```elixir
cc = select_cc_profile(client_profile)
state = %{state |
  cwnd: cc.initial_cwnd,
  ssthresh: cc.initial_ssthresh,
  recovery_cwnd: cc.initial_cwnd,
  client_profile: client_profile,
  cc_profile: cc
}
```

**Update pacing_tick and loss handlers to use `state.cc_profile` instead of module attributes:**
- `@max_cwnd` → `state.cc_profile.max_cwnd`
- `@burst_size` → `state.cc_profile.burst_size`
- `@pacing_interval_ms` → `state.cc_profile.pacing_interval_ms`
- `@loss_beta` → `state.cc_profile.loss_beta`

Keep `@max_payload_bytes`, `@stall_timeout_ms`, `@max_rto_ms`, `@min_cwnd`,
`@min_ssthresh` as module attributes — these are the same for all clients.

**Add logging:**
```elixir
Logger.info("[Session] Client profile: class=#{client_profile.client_class} " <>
  "interface=#{client_profile.interface_type} → CC: cwnd=#{cc.initial_cwnd}/#{cc.max_cwnd} " <>
  "pacing=#{cc.pacing_interval_ms}ms×#{cc.burst_size}")
```

**Verify:** `cd gateway && mix test`

**Commit:**
```bash
git commit -am "feat: gateway selects CC profile from client type — mobile/desktop/server"
```

---

## Task 8: End-to-end testing

**Objective:** Verify the complete flow works for both iOS and desktop.

**Tests:**

1. **Linux build + unit tests:**
```bash
cd proto && cargo test
```
All 1,253+ tests pass, including new client_profile tests.

2. **iOS lib build:**
```bash
cd proto && cargo check --target aarch64-apple-ios --no-default-features --features ios-sync --lib
```

3. **Gateway tests:**
```bash
cd gateway && mix test
```

4. **Deploy gateway with new image:**
```bash
# Build locally
docker build -f gateway/Dockerfile -t ztlp-gateway:client-type .
# Transfer and deploy to 44.246.33.34
docker save ztlp-gateway:client-type | gzip > /tmp/gw.tar.gz
scp -i /tmp/old_gw_key.pem /tmp/gw.tar.gz ubuntu@44.246.33.34:/tmp/
ssh -i /tmp/old_gw_key.pem ubuntu@44.246.33.34 "
  gunzip -c /tmp/gw.tar.gz | docker load
  docker stop ztlp-gateway && docker rm ztlp-gateway
  docker run -d --name ztlp-gateway --network host --restart unless-stopped \
    -e ZTLP_GATEWAY_PORT=23097 ... ztlp-gateway:client-type"
```

5. **iOS benchmark (must build via Xcode GUI on Steve's Mac):**
   - Build and deploy to phone
   - Run HTTP benchmark
   - Expected: 11/11 (mobile CC applied)
   - Check gateway logs for: `[Session] Client profile: class=mobile interface=...`

6. **Linux CLI test against gateway:**
   - Run ztlp-demo or ztlp-bench
   - Check gateway logs for: `[Session] Client profile: class=desktop`
   - Verify higher throughput than mobile

**Commit:**
```bash
git commit -am "test: verify client-type detection end-to-end"
```

---

## Summary: Files Changed Per Task

| Task | Files | Description |
|------|-------|-------------|
| 1 | `proto/Cargo.toml` | Add ciborium dependency |
| 2 | `proto/src/client_profile.rs`, `proto/src/lib.rs` | ClientProfile struct + tests |
| 3 | `proto/src/handshake.rs`, `proto/src/ffi.rs` | Send profile in msg3 (desktop) |
| 4 | `proto/src/ffi.rs`, `proto/include/ztlp.h` | iOS sync FFI + set_client_profile |
| 5 | `PacketTunnelProvider.swift` | Swift calls set_client_profile |
| 6 | `gateway/session.ex` | Parse client profile from msg3 |
| 7 | `gateway/session.ex` | Select CC profile per client type |
| 8 | — | Integration testing + deploy |

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Old clients send empty msg3 | Gateway defaults to mobile-wifi CC (no regression) |
| Malformed CBOR in msg3 | from_cbor returns None → fallback to unknown |
| ciborium bloats iOS binary | Monitor TEXT segment size; if too large, use hand-rolled CBOR (6 fields only) |
| Gateway Cbor.decode fails | Wrap in try/catch, default to conservative |
| Profile not ready before connect | set_client_profile stores in static; connect reads it |

## Future Work (not in this plan)

- **Phase 2:** Mid-session NetworkStatusUpdate (WiFi↔cellular transitions)
- **Phase 3:** Passive RTT-based fallback for legacy clients
- **Phase 4:** Telemetry — log actual throughput per CC profile for tuning
