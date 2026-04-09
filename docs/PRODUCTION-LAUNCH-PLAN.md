# ZTLP Production Launch Plan

**Date:** 2026-04-09
**Author:** Steve Price / Hermes Agent
**Goal:** Ship production iOS + macOS apps to App Store

---

## Architecture Overview

```
                    ┌──────────────┐
                    │   ZTLP-NS    │  Name server — knows everybody
                    │  :23096      │  Records: KEY, SVC, RELAY, POLICY
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼────┐ ┌────▼─────┐
        │  Gateway   │ │ Relay  │ │ Gateway  │
        │  :23097    │ │ :23095 │ │  :23097  │
        │ (prod-gw)  │ │        │ │ (future) │
        └─────┬──────┘ └────────┘ └──────────┘
              │
    ┌─────────┼──────────┐
    │ Backends (local)   │
    │  Bitwarden :8443   │
    │  SSH       :22     │
    │  RDP       :3389   │
    └────────────────────┘
```

**Flow:**
1. App enrolls → gets identity + NS address + relay info
2. App queries NS → discovers gateways, services, relays
3. App connects gateway via relay (or direct) using Noise_XX
4. Gateway terminates tunnel → forwards to backend (Bitwarden, SSH, RDP)
5. Local TLS on device: app presents cert to Bitwarden over localhost HTTPS

---

## Phase 1: Infrastructure (Sessions 9-10)

### 1A. Stand up NS server
- [ ] Deploy NS on this host (already at ns/)
- [ ] Generate zone: `ztlp admin init-zone --zone clients.techrockstars.ztlp`
- [ ] Configure NS persistence (Mnesia disc mode)
- [ ] Verify: `ztlp ns lookup` works

### 1B. Stand up relay
- [ ] Start relay: `cd relay && mix run --no-halt`
- [ ] Register relay with NS
- [ ] Verify relay forwards traffic

### 1C. Register gateway with NS
- [ ] Set ZTLP_NS_SERVER and ZTLP_GATEWAY_PUBLIC_ADDR on gateway
- [ ] Gateway auto-registers SVC records with NS
- [ ] Verify: `ztlp ns lookup prod-gw.clients.techrockstars.ztlp`

### 1D. Deploy Bitwarden (Vaultwarden)
- [ ] Docker: `docker run -d --name vaultwarden -p 8443:80 vaultwarden/server`
- [ ] Or with HTTPS: Use ROCKET_TLS config for self-signed + ZTLP CA cert
- [ ] Register as backend in gateway config:
      `%{name: "bitwarden", host: {127, 0, 0, 1}, port: 8443}`
- [ ] Register SVC record in NS:
      `ztlp admin register-service --name bitwarden --zone clients.techrockstars.ztlp --port 8443`

### 1E. TLS certificate infrastructure
- [ ] Initialize CA: `ztlp admin ca-init --zone clients.techrockstars.ztlp`
- [ ] Issue cert for Bitwarden hostname: 
      `ztlp admin cert-issue --hostname vault.clients.techrockstars.ztlp`
- [ ] Place cert in ~/.ztlp/certs/ for local TLS termination
- [ ] Verify: agent daemon serves HTTPS on localhost

### 1F. Generate enrollment tokens
- [ ] `ztlp admin enroll --zone clients.techrockstars.ztlp --max-uses 10 --expires 7d --qr`
- [ ] Test enrollment from CLI: `ztlp setup --token <token>`
- [ ] Verify: enrolled client can query NS, reach gateway, connect to Bitwarden

---

## Phase 2: Complete iOS App (Sessions 11-14)

### What exists already (good news):
- Full SwiftUI app with 5 tabs (Home, Services, Logs, Bench, Settings)
- EnrollmentView with QR scanner + manual entry (AVFoundation)
- HomeView with connect toggle + VIP proxy card
- ServicesView UI (list, search, pull-to-refresh)
- PacketTunnelProvider with sync FFI, VIP proxy, reconnect logic
- ZTLPBridge FFI wrapper with nsResolve(), vipAddService(), etc.
- 8 test files covering core functionality
- App group data sharing between app and NE

### What needs finishing:
- [ ] **2A. Wire up ServicesViewModel** — currently a stub
  - Call nsResolve() or new ns_list_services FFI to get real service list from NS
  - Parse SVC records (name, host, port, protocol, hostNodeId)
  - Show gateway→service mapping with reachability indicators
  
- [ ] **2B. Complete EnrollmentViewModel** — step 5 is stubbed
  - Wire ztlp_ns_register FFI to actually register identity with NS
  - After enrollment: fetch CA root cert, install trust profile
  - Save relay addresses and NS endpoint in config
  
- [ ] **2C. Service connection flow**
  - User taps service → app configures VIP proxy for that service
  - Bitwarden: VIP proxy on 127.0.0.1:8443 with TLS (ZTLP CA cert)
  - SSH: VIP proxy on 127.0.0.1:2222
  - RDP: VIP proxy on 127.0.0.1:3389
  
- [ ] **2D. On-demand connect rules**
  - Auto-connect on untrusted WiFi
  - Per-service always-on option
  - NEOnDemandRuleConnect / NEOnDemandRuleDisconnect

- [ ] **2E. Polish UI for App Store**
  - Professional app icon (ZTLP shield / lock motif)
  - Launch screen
  - Proper about/version info
  - Privacy policy view (link to ztlp.org/privacy)
  - Settings: identity export, CA trust, log level, on-demand rules

---

## Phase 3: macOS App (Sessions 15-16)

### What exists already:
- Full macOS app structure at macos/ZTLP/
- MenuBarExtra (system tray dropdown) + main window
- Views: Home, Services, Settings, Enrollment, Identity
- SystemExtensionManager for NE activation
- PacketTunnelProvider (uses async FFI — needs sync migration)

### What needs finishing:
- [ ] **3A. Migrate macOS PacketTunnelProvider to sync FFI**
  - Match iOS's v5C sync architecture
  - Keeps code in sync between platforms
  
- [ ] **3B. Wire up service discovery** (same as iOS)
- [ ] **3C. System Extension activation flow**
  - First-launch prompt to approve system extension
  - Handle "allow in System Preferences" flow
  - Re-activation after macOS updates
  
- [ ] **3D. Menu bar UX**
  - Quick toggle from menu bar
  - Show connected services
  - One-click service access (open Bitwarden in browser, etc.)

---

## Phase 4: Production Services (Sessions 17-18)

### 4A. Bitwarden via ZTLP
- [ ] Deploy Vaultwarden behind gateway
- [ ] Local TLS with ZTLP CA cert
- [ ] Test from iOS: install ZTLP CA → configure Bitwarden app → vault.ztlp.local
- [ ] Test from macOS: same flow
- [ ] Test from Linux CLI: `ztlp agent start` → curl https://vault.ztlp.local

### 4B. RDP via ZTLP
- [ ] Register RDP service (TCP + UDP)
- [ ] Configure VIP proxy for RDP ports (3389 TCP + UDP)
- [ ] Test streaming/interactive performance
- [ ] Verify UDP path works for RDP over ZTLP

### 4C. SSH via ZTLP
- [ ] Already partially working from demo
- [ ] Production config: `ztlp proxy` as SSH ProxyCommand
- [ ] Verify: `ssh -o ProxyCommand='ztlp proxy %h %p' myserver.ztlp`

---

## Phase 5: App Store Submission (Sessions 19-20)

### Prerequisites:
- [ ] **Network Extension entitlement** — must request from Apple
  → https://developer.apple.com/contact/network-extension/
  → Describe: "Packet Tunnel Provider for zero-trust encrypted networking"
  → Request ASAP — takes 1-7 business days

- [ ] **Privacy policy** — publish at ztlp.org/privacy
  - Disclose: identity info (public keys), connection metadata
  - Disclose: no traffic logging, no DNS logging
  - Data retention: only local on device

- [ ] **App Store Connect setup**
  - Bundle ID: com.techrockstars.ztlp (app) + com.techrockstars.ztlp.tunnel (NE)
  - App group: group.com.ztlp.shared (already in use)
  - Category: Utilities or Productivity
  - Export compliance: declare encryption (Noise/ChaCha20/BLAKE2)

- [ ] **Build & archive**
  - XCFramework with Rust libs (aarch64-apple-ios, aarch64-apple-ios-sim)
  - Strip debug symbols, opt-level=z for NE
  - Two-lib build: libztlp_proto.a (main app) + libztlp_proto_ne.a (NE)

- [ ] **TestFlight**
  - Internal testing first
  - External beta (up to 10K testers)

- [ ] **Screenshots & metadata**
  - 6.7" (iPhone 15 Pro Max), 6.1" (iPhone 15), 5.5" (iPhone 8 Plus)
  - iPad screenshots if supporting iPad
  - App description, keywords, what's new

---

## Key Design Decisions

### 1. NS-first architecture
```
App start → query NS for zone → get:
  - Gateways (SVC records with endpoints)
  - Relays (RELAY records with endpoints)  
  - Services (SVC records behind gateways)
  - Policies (who can access what)
```
The NS is the directory. Everything is discoverable.

### 2. Enrollment flow
```
Scan QR / paste token
  → Parse enrollment token (zone + NS addr + relay + gateway)
  → Generate identity (Secure Enclave on iOS, software on macOS/Linux)
  → Register identity with NS
  → Fetch CA root certificate
  → Install CA trust profile (iOS Settings prompt)
  → Save config locally
  → Auto-connect
```

### 3. Service access pattern
```
App queries NS: "What services are in my zone?"
NS returns: [{bitwarden, vault.zone.ztlp, gateway-id, port 8443},
             {ssh, server.zone.ztlp, gateway-id, port 22},
             {rdp, desktop.zone.ztlp, gateway-id, port 3389}]

User taps service → NE establishes tunnel to gateway (via relay if needed)
  → VIP proxy binds localhost port → local app connects there
  → Traffic: local TLS → ZTLP Noise → gateway → backend
```

### 4. TLS over ZTLP
```
Bitwarden requires HTTPS. The stack:

  Bitwarden app → https://127.0.0.1:8443
    → ZTLP agent/NE terminates TLS locally (ZTLP CA cert)
    → Extracts plaintext HTTP
    → Encrypts with Noise_XX → sends over ZTLP tunnel
    → Gateway decrypts → forwards plain HTTP to Vaultwarden:80
    → Response goes back the same way
```
The ZTLP CA cert must be trusted on the device. On iOS this means
installing a configuration profile. The app should guide the user through this.

### 5. Cross-platform targets
| Platform | App          | Tunnel          | Distribution     |
|----------|-------------|-----------------|------------------|
| iOS      | SwiftUI     | Network Ext     | App Store        |
| macOS    | SwiftUI     | System Ext      | App Store / DMG  |
| Linux    | CLI         | ztlp agent      | Binary / .deb    |
| Windows  | TBD (GUI?)  | TBD (Wintun?)   | .msi / Store     |

---

## Questions / Decisions Needed

1. **Zone naming**: `clients.techrockstars.ztlp`? Or something else?

2. **Bitwarden deployment**: Vaultwarden (lightweight, Docker) or full 
   Bitwarden server? Vaultwarden is simpler and works great for small teams.

3. **Windows timeline**: Windows requires a different tunnel driver 
   (Wintun or WireGuard-NT). Do we defer Windows to after App Store launch?

4. **macOS distribution**: App Store, or Developer ID + notarization 
   (avoids App Store review but requires user to approve system extension)?
   Both is possible.

5. **Network Extension entitlement**: Have you already requested this from 
   Apple? If not, we should submit the request TODAY — it can take up to 
   a week and blocks everything.

6. **Domain for NS**: Is this running on a public-facing server, or 
   LAN-only for now? For App Store demo, Apple reviewers need to be able 
   to connect (or we use a test token that works on demo infrastructure).

7. **Bootstrap server**: The existing enrollment supports a bootstrap 
   callback URL. Do we want a web-based enrollment portal 
   (enroll.ztlp.org) or is QR + manual token sufficient?

---

## Immediate Next Steps (This Session)

If you're ready to start now, the highest-impact items are:

1. Stand up NS + relay + register gateway (30 min)
2. Deploy Vaultwarden behind gateway (15 min)
3. Generate enrollment token + test from CLI (15 min)
4. Wire up iOS ServicesViewModel to real NS data (1-2 hours)
5. Complete iOS enrollment NS registration (1 hour)

That gives us a working end-to-end demo: 
  enroll phone → discover Bitwarden → connect → use vault
