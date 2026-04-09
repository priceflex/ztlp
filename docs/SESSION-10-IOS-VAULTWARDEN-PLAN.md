# Session 10: iOS Vaultwarden Access Plan

## Goal
Get Vaultwarden accessible from the iOS ZTLP app on Steve's iPhone,
matching the macOS experience: enroll → connect → browse to vault.

## Current State

### What's Working
- **Vaultwarden** running on gateway (44.246.33.34), port 8080, healthy
- **Gateway** routes `vault` service → 127.0.0.1:8080
- **macOS app** fully working: enrollment, connect, DNS, VIP proxy, HTTPS certs
- **iOS app** has VPN tunnel with PacketTunnelProvider, VIP proxy (ZTLPVIPProxy),
  packet router, and DNS routing for `.ztlp` domains
- **GitHub** fully synced (commit 866b9a0)

### What Needs Work for iOS
The iOS app currently registers only the `svcName` (from config, defaults to
"beta") and "http" services. Vault is not registered. The iOS uses a different
architecture than macOS:

| Feature | macOS | iOS |
|---------|-------|-----|
| Tunnel | Userspace (Direct Connect) | PacketTunnelProvider (NE) |
| VIP range | 127.0.55.x (loopback) | 10.122.0.x (TUN interface) |
| DNS | Local UDP server on 127.0.55.53:5354 | NEDNSSettings matchDomains=["ztlp"] |
| VIP proxy | ZTLPBridge.vipAddService() | ZTLPVIPProxy (NWListener) |
| TLS certs | mkcert + local CA in Keychain | iOS certificate profile (or skip — HTTP-only over tunnel is already encrypted) |
| Service routing | pf redirect 80→8080, 443→8443 | Packet router: IP→service name mapping |
| Admin auth | osascript admin dialog | N/A (no admin needed) |

## Implementation Steps

### Phase 1: Register Vault Service in iOS Network Extension

**File:** `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

1. Add vault to the services array (around line 240):
```swift
let services: [(vip: String, name: String)] = [
    ("10.122.0.2", svcName),    // existing (beta/default)
    ("10.122.0.3", "http"),     // existing
    ("10.122.0.4", "vault"),    // NEW — Vaultwarden
]
```

2. Register vault ports on VIP proxy (after line 250):
```swift
proxy.addService(name: "vault", port: 8080)
proxy.addService(name: "vault", port: 8443)
```

3. Add DNS mapping so `vault.techrockstars.ztlp` resolves to `10.122.0.4`.
   Check how the DNS resolver on iOS handles this — the NEDNSSettings point
   to 127.0.55.53 but the iOS NE may not run a DNS server. Need to verify
   whether the packet router handles DNS or if NEDNSSettings needs a
   proxyDNSSettings or matchDomains approach.

### Phase 2: Verify DNS Resolution on iOS

The iOS tunnel sets:
```swift
let dns = NEDNSSettings(servers: ["127.0.55.53"])
dns.matchDomains = ["ztlp"]
```

This means iOS routes `.ztlp` DNS queries to 127.0.55.53. But the NE needs to
run a DNS responder there, or the packet router needs to intercept DNS for
10.122.0.x addresses and return the right VIP.

**Check:** Does `ztlp_router_add_service_sync` also register DNS mappings?
If not, we need a minimal DNS responder in the NE, or use the simpler approach
of hardcoding DNS in the NEDNSSettings:

```swift
// Alternative: use NEDNSOverHTTPSSettings or add static DNS
// Or: point DNS to the NS server and let it resolve
let dns = NEDNSSettings(servers: ["34.217.62.46"])  // NS server
dns.matchDomains = ["ztlp"]
```

### Phase 3: Enrollment Token for iPhone

1. Create a new enrollment token in bootstrap (the macOS token was 1-use):
```ruby
# On bootstrap (10.69.95.12)
docker exec -w /rails bootstrap_web_1 bin/rails runner '
  t = EnrollmentToken.create!(
    network_id: 1,
    token_id: SecureRandom.hex(8),
    max_uses: 1,
    current_uses: 0,
    expires_at: 24.hours.from_now,
    status: "active",
    notes: "iPhone enrollment"
  )
  puts t.token_id
'
```

2. Build the enrollment URI:
```
ztlp://enroll/?zone=techrockstars.ztlp&ns=34.217.62.46:23096&relay=34.219.64.205:23095&token=<TOKEN_ID>&expires=<UNIX_TS>
```

3. Generate QR code or paste directly — iOS app has QR scanner.

### Phase 4: Build and Deploy to iPhone

1. Pull latest on Mac: `cd ~/ztlp && git pull`
2. Build iOS libs:
   - `libztlp_proto.a` (main app — with tokio)
   - `libztlp_proto_ne.a` (NE — no tokio, sync FFI)
   - Copy `ztlp.h` to `ios/ZTLP/Libraries/`
3. Open `ios/ZTLP/` in Xcode
4. Build & deploy to Steve's iPhone (39659E7B-0554-518C-94B1-094391466C12)
   - Must use Xcode GUI for codesign (SSH deploy fails)
5. Verify app launches, enrollment screen appears

### Phase 5: End-to-End Test

1. **Enroll** — scan QR or paste enrollment URI
2. **Connect** — tap connect button, VPN tunnel establishes
3. **DNS test** — in Safari, navigate to `http://vault.techrockstars.ztlp`
4. **Vaultwarden** — create account or login
5. **Bitwarden app** — install Bitwarden from App Store, set server URL to
   `http://vault.techrockstars.ztlp`, create/login to account
6. **Sync test** — add a password on phone, verify it shows on macOS Bitwarden

### Phase 6: HTTPS on iOS (Optional — Lower Priority)

On iOS, the tunnel is already end-to-end encrypted (Noise_XX). Adding TLS
on top (browser ↔ VIP proxy) is defense-in-depth but not strictly needed.
If we want it:

- iOS doesn't have mkcert. Options:
  a. Bundle a pre-generated CA cert in the app, install via Settings profile
  b. Generate certs on the Mac, transfer via shared iCloud or AirDrop
  c. Use the ZTLP CA infrastructure (ztlp admin cert-issue) and install
     the root CA as a configuration profile on iOS
- The VIP proxy on iOS already has port 8443 registered, so TLS termination
  would work if certs are available

**Recommendation:** Start with HTTP over the tunnel (already encrypted).
Add HTTPS later if needed for Bitwarden app compatibility (some Bitwarden
features may require HTTPS URLs).

## Known Pitfalls

1. **NE 15MB memory limit** — the Network Extension must stay under 15MB
   resident memory or iOS jetsams it. The sync FFI + stripped tokio keeps
   it at ~8-10MB. Adding vault service shouldn't increase memory.

2. **Codesign from SSH fails** — must build and deploy from Xcode GUI on
   the Mac. The agent can prepare code but Steve deploys from Xcode.

3. **Gateway restart kills sessions** — tell Steve BEFORE any gateway
   restart. His phone tunnel will disconnect.

4. **NAT rebinding on cellular** — the relay handles this now, but
   cellular carriers can still cause brief stalls when switching towers.

5. **iOS VPN permission** — first connect prompts "ZTLP would like to
   add VPN configurations." User must allow this.

6. **Enrollment token expiry** — generate fresh tokens with correct
   Unix timestamps (2026, not 2025).

## Files to Modify

| File | Change |
|------|--------|
| `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` | Add vault to services array + VIP proxy |
| `ios/ZTLP/ZTLP/Models/ZTLPConfiguration.swift` | Verify serviceName default |
| `ios/ZTLP/ZTLP/ViewModels/TunnelViewModel.swift` | May need vault service awareness |
| Bootstrap DB | New enrollment token for iPhone |

## Success Criteria

- [ ] iPhone enrolled in techrockstars.ztlp zone
- [ ] VPN tunnel connects and stays stable
- [ ] `http://vault.techrockstars.ztlp` loads in Safari on iPhone
- [ ] Can create Vaultwarden account from iPhone
- [ ] Bitwarden iOS app syncs with self-hosted Vaultwarden
- [ ] Password created on iPhone visible on macOS (and vice versa)
- [ ] Tunnel survives WiFi ↔ cellular handoff
- [ ] NE memory stays under 15MB

## Infrastructure Reference

| Component | Address | Notes |
|-----------|---------|-------|
| Gateway | 44.246.33.34:23097/udp | Vaultwarden on :8080 |
| Relay | 34.219.64.205:23095/udp | NAT traversal |
| NS | 34.217.62.46:23096/udp | Identity resolution |
| Bootstrap | 10.69.95.12:3000 | Web UI, admin@ztlp.local / changeme123 |
| Vaultwarden admin | /admin | Token: l+/tLht4K5qsyjft6YTuYZG8+L9WVZA/VpNiIhBs9f4= |
| iPhone | 39659E7B-0554-518C-94B1-094391466C12 | Steve's device |
| Mac Studio | 10.78.72.234 | Build machine, stevenprice@ |
