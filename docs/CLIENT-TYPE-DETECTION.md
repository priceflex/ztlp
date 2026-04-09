# ZTLP Client-Type Detection — Design Spec

**Date:** 2026-04-09
**Status:** Proposed
**Author:** Steve Price / Hermes Agent

## Problem

The gateway uses one CC profile for all clients. Mobile iOS clients need
conservative parameters (max_cwnd=32, pacing=4ms×3) to avoid overwhelming
the NE's 15MB memory limit and cellular buffers. Desktop/server clients
need aggressive parameters (max_cwnd=256, pacing=1ms×8) for throughput.

Currently: mobile CC is hardcoded for everyone, throttling desktop to ~6.8 Mbps.

## Prior Art

| Protocol   | Detection Method          | Works? |
|-----------|---------------------------|--------|
| WireGuard | None — no metadata at all | N/A    |
| Tailscale | Client self-reports OS via HTTPS control plane | Yes |
| Nebula    | Device class baked into certificate (groups field) | Yes |
| QUIC      | No explicit detect — BBR naturally adapts | Partially |
| iOS APIs  | NWPath (cellular/wifi/wired), CoreTelephony (LTE/5G) | Rich data |

**Key insight:** No protocol detects mobile vs desktop from the crypto
handshake alone. The universal pattern is **client self-reports**.

## Design: Client Self-Report in Handshake

ZTLP already sends a `software_id` string during connection. Extend this
to a structured `ClientProfile` sent in the first encrypted payload of
the Noise_XX handshake (message 3).

### Wire Format

```
ClientProfile (inside encrypted Noise_XX message 3):

Byte 0:     Version (0x01)
Byte 1:     client_class   (0=Unknown, 1=Mobile, 2=Desktop, 3=Server)
Byte 2:     interface_type (0=Unknown, 1=Cellular, 2=WiFi, 3=Wired)
Byte 3:     radio_tech     (0=Unknown, 1=2G, 2=3G, 3=LTE, 4=5G-NSA, 5=5G-SA)
Byte 4:     flags          (bit 0=is_constrained, bit 1=is_expensive)
Bytes 5-6:  preferred_mtu  (u16 big-endian)
Bytes 7-8:  software_version (u16: major*256+minor)
Bytes 9+:   software_id string (length-prefixed, max 64 bytes)

Total: ~15-80 bytes
```

### CC Profiles

The gateway selects one of these based on `client_class` + `interface_type`:

```
Profile          | cwnd_init | cwnd_max | ssthresh | pacing   | burst | loss_β
-----------------+-----------+----------+----------+----------+-------+-------
mobile_cellular  |     5     |    16    |    32    |   6ms    |   2   |  0.7
mobile_wifi      |    10     |    32    |    64    |   4ms    |   3   |  0.7
desktop          |    64     |   256    |   128    |   1ms    |   8   |  0.7
server           |    64     |   512    |   256    |  0.5ms   |  16   |  0.7
```

Selection logic:
- `Mobile` + `Cellular` → mobile_cellular
- `Mobile` + `WiFi`     → mobile_wifi
- `Mobile` + anything else → mobile_wifi (safe default)
- `Desktop` → desktop
- `Server`  → server
- `Unknown` or missing → mobile_wifi (conservative fallback)

### Client-Side Population

**Rust CLI (Linux/macOS/Windows):**
```rust
ClientProfile {
    client_class: ClientClass::Desktop,
    interface_type: detect_interface_type(), // sysfs/networksetup
    radio_tech: RadioTech::Unknown,
    is_constrained: false,
    preferred_mtu: 1500,
}
```

**iOS (Swift → Rust FFI):**
```swift
let path = NWPathMonitor().currentPath
let radio = CTTelephonyNetworkInfo()
    .serviceCurrentRadioAccessTechnology?.values.first

let profile = ZtlpClientProfile(
    clientClass: .mobile,
    interfaceType: path.usesInterfaceType(.cellular) ? .cellular : .wifi,
    radioTech: radioTechFromString(radio),
    isConstrained: path.isConstrained,
    preferredMtu: 1280
)
ztlp_set_client_profile(profile)
```

### Gateway-Side (Elixir)

```elixir
defp select_cc_profile(%{client_class: :mobile, interface_type: :cellular}) do
  %{initial_cwnd: 5, max_cwnd: 16, pacing_ms: 6, burst: 2}
end

defp select_cc_profile(%{client_class: :mobile}) do
  %{initial_cwnd: 10, max_cwnd: 32, pacing_ms: 4, burst: 3}
end

defp select_cc_profile(%{client_class: :desktop}) do
  %{initial_cwnd: 64, max_cwnd: 256, pacing_ms: 1, burst: 8}
end

defp select_cc_profile(%{client_class: :server}) do
  %{initial_cwnd: 64, max_cwnd: 512, pacing_ms: 1, burst: 16}
end

defp select_cc_profile(_unknown) do
  # Conservative fallback for legacy clients
  %{initial_cwnd: 10, max_cwnd: 32, pacing_ms: 4, burst: 3}
end
```

## Phase 2: Mid-Session Network Updates

When iOS detects a WiFi↔cellular transition (NWPathMonitor callback),
send a `NetworkStatusUpdate` control message:

```
NetworkStatusUpdate (control message, 8 bytes):

Byte 0:     msg_type = 0x10
Byte 1:     interface_type
Byte 2:     radio_tech
Byte 3:     flags
Bytes 4-5:  observed_rtt_ms (u16, client-measured)
Bytes 6-7:  reserved
```

Gateway transitions:
- WiFi → Cellular: immediately cap cwnd to min(cwnd, 16), lower max_cwnd
- Cellular → WiFi: enter slow-start from current cwnd up to new max_cwnd

## Phase 3: Passive Fallback

For legacy clients that don't send ClientProfile:
- Start with conservative CC (mobile_wifi profile)
- After 10-20 RTT samples, classify by RTT + jitter:
  - RTT > 50ms, jitter > 10ms → cellular
  - RTT > 10ms, jitter > 3ms → wifi/mobile
  - RTT < 5ms, jitter < 1ms → wired/desktop
- Promote to aggressive CC only if classified as wired/desktop

## Implementation Order

| Phase | What | Effort | Impact |
|-------|------|--------|--------|
| 1a | ClientProfile struct in proto crate | 2 hrs | Foundation |
| 1b | Populate in Rust CLI + iOS FFI | 3 hrs | Client-side done |
| 1c | Gateway reads and selects CC profile | 3 hrs | Full mobile/desktop split |
| 2  | NetworkStatusUpdate for transitions | 1 day | Handles WiFi↔cellular |
| 3  | Passive RTT-based fallback | 1 day | Legacy client support |

## Backward Compatibility

- Old clients that don't send ClientProfile → gateway uses conservative
  fallback (current mobile CC). No regression.
- Old gateways that don't parse ClientProfile → ignore unknown payload
  bytes. No regression.
- The ClientProfile is inside the encrypted handshake payload, so it
  can't be sniffed or spoofed by middleboxes.
