# ZTLP iOS App

Native iOS client for the **Zero Trust Layer Protocol (ZTLP)**. Provides encrypted peer-to-peer connectivity via a system VPN tunnel backed by Noise_XX handshakes and hardware-secured identity keys.

## Architecture

Current production-ish iOS architecture is in transition from an in-extension VIP proxy to an iOS-first relay-side VIP model.

### Current implementation

```
┌───────────────────────────────────────────────┐
│  ZTLP App (Main Process)                      │
│  ┌─────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ SwiftUI │←│ViewModels│←│  ZTLPBridge    │  │
│  │  Views  │ │  (MVVM)  │ │  (C FFI)      │  │
│  └─────────┘ └──────────┘ └───────┬───────┘  │
│                                    │          │
│  ┌─────────────┐  ┌───────────────┐│          │
│  │  Keychain   │  │Secure Enclave ││          │
│  │  Service    │  │   Service     ││          │
│  └──────┬──────┘  └──────┬────────┘│          │
│         │                │         │          │
│    [App Group Keychain + UserDefaults]        │
│         │                │         │          │
├─────────┴────────────────┴─────────┴──────────┤
│  ZTLPTunnel (Network Extension Process)       │
│  ┌────────────────────────────────────────┐   │
│  │     PacketTunnelProvider               │   │
│  │  ┌──────────┐  ┌─────────────────┐    │   │
│  │  │ TUN R/W  │  │  ztlp C FFI     │    │   │
│  │  │ (packet  │←→│  (Rust static   │    │   │
│  │  │  flow)   │  │   library)      │    │   │
│  │  └──────────┘  └─────────────────┘    │   │
│  │  ┌──────────┐                         │   │
│  │  │VIP proxy │  NWListener x5 on       │   │
│  │  │(Swift)   │  127.0.0.1:80/443/...   │   │
│  │  └──────────┘                         │   │
│  └────────────────────────────────────────┘   │
└───────────────────────────────────────────────┘
```

### Target architecture: relay-side VIP for iOS first

```
App → packetFlow → PacketTunnelProvider → encrypted UDP tunnel → relay
                                                     │
                                                     ▼
                                        relay-side VIP termination
                                                     │
                                                     ▼
                                              backend TCP service
```

In the target design, the iOS Network Extension stops hosting `NWListener` VIP ports entirely. It becomes a pure packet encrypt/decrypt tunnel endpoint plus relay-selection client. The relay terminates VIP traffic on behalf of the phone.

This is iOS-first because the immediate problem is the iOS Network Extension memory ceiling (~15 MB jetsam budget). Moving VIP proxying off-device is expected to recover roughly 5-8 MB and bring the extension back into a safe operating range.

Reference design: `docs/RELAY-VIP-ARCHITECTURE.md`

### Key Design Decisions

### Relay-side VIP notes

- NS is the control-plane source of truth for relay discovery and selection
- iOS queries NS for `ZTLP_RELAY` records, then selects the best relay using latency/load-aware scoring
- The NE keeps only packet flow, one UDP tunnel connection, sync crypto, ACK handling, and failover logic
- The relay now performs the TCP termination work that used to live in `ZTLPVIPProxy.swift`
- This changes relay trust properties for iOS VIP traffic: the relay can see plaintext unless relay→backend is re-encrypted
- Recommended defense-in-depth is relay→backend TLS/mTLS, with future upgrade paths for double-encryption or relay mesh

### Security model for iOS relay-side VIP

For ordinary ZTLP relay mode, the relay only forwards opaque ciphertext by SessionID. For the new iOS relay-side VIP path, the relay becomes an application proxy for selected VIP services and therefore can inspect plaintext for that proxied traffic. That is an intentional tradeoff to fit inside Apple's Network Extension memory limits.

What the relay still cannot do:
- Forge a client identity without the client's device keys
- Bypass ZTLP admission/authentication for tunnel establishment
- Read traffic that remains ordinary end-to-end ZTLP relay traffic

What changes:
- The relay can see proxied VIP payloads for services it terminates
- The relay becomes part of the trusted computing base for those iOS VIP sessions

Use relay→backend TLS or mTLS wherever possible.

### Migration status

- Current code still contains `ZTLPVIPProxy.swift` and `NWListener`-based localhost VIP ports
- `PacketTunnelProvider.swift` still falls back to a configured gateway address because sync NS relay resolution is being wired in
- `docs/RELAY-VIP-ARCHITECTURE.md` is the active design for the next iOS memory-reduction step

### Key Design Decisions

- **MVVM + SwiftUI** — All views are declarative SwiftUI (iOS 16+), driven by `@Published` ViewModels
- **Two-process architecture** — Main app handles UI; Network Extension handles the actual VPN tunnel in a sandboxed process
- **Shared state via App Group** — Keychain (identity), UserDefaults (config/stats), and file container are shared between processes via `group.com.ztlp.shared`
- **Rust FFI via C** — The ZTLP protocol library is written in Rust, compiled to a static library, and exposed via a C header (`ztlp.h`)
- **Hardware-backed keys** — Secure Enclave P-256 keys on supported devices, with software fallback

## Project Structure

```
ios/
├── build-ios.sh                    # Cross-compile Rust → iOS static lib
├── README.md                       # This file
└── ZTLP/
    ├── ZTLP/                       # Main app target
    │   ├── App/
    │   │   ├── ZTLPApp.swift       # @main entry point
    │   │   └── AppDelegate.swift   # UIKit adapter for lifecycle events
    │   ├── Models/
    │   │   ├── ConnectionStatus.swift
    │   │   ├── ZTLPConfiguration.swift
    │   │   ├── ZTLPIdentity.swift
    │   │   └── ZTLPService.swift
    │   ├── ViewModels/
    │   │   ├── TunnelViewModel.swift
    │   │   ├── SettingsViewModel.swift
    │   │   ├── EnrollmentViewModel.swift
    │   │   └── ServicesViewModel.swift
    │   ├── Views/
    │   │   ├── ContentView.swift       # Root tab navigation
    │   │   ├── HomeView.swift          # Connect/disconnect with status ring
    │   │   ├── ServicesView.swift       # Service discovery list
    │   │   ├── IdentityView.swift       # Node ID, keys, enrollment
    │   │   ├── SettingsView.swift       # Configuration
    │   │   ├── EnrollmentView.swift     # QR scanner + enrollment flow
    │   │   └── OnboardingView.swift     # First-run experience
    │   ├── Services/
    │   │   ├── ZTLPBridge.swift        # Swift ↔ C FFI bridge
    │   │   ├── KeychainService.swift   # Keychain wrapper
    │   │   ├── SecureEnclaveService.swift # SE key ops
    │   │   └── NetworkMonitor.swift    # NWPathMonitor
    │   ├── Extensions/
    │   │   └── Color+ZTLP.swift       # Brand colors
    │   ├── Resources/
    │   │   ├── Info.plist
    │   │   └── Assets.xcassets/
    │   └── ZTLP-Bridging-Header.h
    ├── ZTLPTunnel/                 # Network Extension target
    │   ├── PacketTunnelProvider.swift
    │   ├── TunnelConfiguration.swift
    │   ├── Info.plist
    │   └── ZTLPTunnel-Bridging-Header.h
    ├── ZTLPTests/                  # Unit tests
    │   ├── ZTLPBridgeTests.swift
    │   ├── KeychainServiceTests.swift
    │   ├── EnrollmentViewModelTests.swift
    │   └── ConnectionStatusTests.swift
    └── Libraries/                  # Output from build-ios.sh
        ├── libztlp_proto.a
        ├── libztlp_proto.xcframework/
        └── ztlp.h
```

## Build Instructions

### Prerequisites

1. **Xcode 15+** with iOS 16.0 SDK
2. **Rust** (via [rustup](https://rustup.rs/))
3. iOS cross-compilation targets:
   ```bash
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   ```

### Step 1: Build the Rust Library

```bash
cd ios
./build-ios.sh release
```

This compiles `proto/` for all iOS architectures, creates a universal static library, and copies it + the header to `ZTLP/Libraries/`.

### Step 2: Open in Xcode

```bash
open ZTLP/ZTLP.xcodeproj
```

### Step 3: Configure Signing

1. Select the **ZTLP** target → Signing & Capabilities
2. Set your Team and Bundle Identifier
3. Repeat for the **ZTLPTunnel** target
4. Ensure both targets use the same App Group: `group.com.ztlp.shared`

### Step 4: Link the Library

1. Both targets: Build Settings → **Library Search Paths** → `$(PROJECT_DIR)/Libraries`
2. Both targets: Build Settings → **Header Search Paths** → `$(PROJECT_DIR)/Libraries`
3. Both targets: Build Settings → **Other Linker Flags** → `-lztlp_proto -lresolv`
4. Both targets: Build Settings → **Objective-C Bridging Header** → set to the respective `*-Bridging-Header.h` path

### Step 5: Build & Run

Select your device/simulator and build (⌘B) / run (⌘R).

## Entitlements

Both targets require:

| Entitlement | Key | Value |
|---|---|---|
| App Groups | `com.apple.security.application-groups` | `group.com.ztlp.shared` |
| Keychain Sharing | `keychain-access-groups` | `group.com.ztlp.shared` |

**Main app additionally:**
| Entitlement | Key | Value |
|---|---|---|
| Network Extensions | `com.apple.developer.networking.networkextension` | `packet-tunnel-provider` |
| Personal VPN | `com.apple.developer.networking.vpn.api` | `allow-vpn` |

**Network Extension additionally:**
| Entitlement | Key | Value |
|---|---|---|
| Network Extensions | `com.apple.developer.networking.networkextension` | `packet-tunnel-provider` |

## Enrollment Flow

1. Admin generates an enrollment token via the ZTLP control plane
2. Token is encoded as a QR code with URI scheme `ztlp://enroll/...`
3. User scans QR in-app → token is validated → identity is generated
4. Device is registered with the zone's Name Service
5. App stores identity in shared keychain → tunnel extension can access it

## Key Concepts

- **Node ID** — 16-byte identifier derived from the public key (hex-encoded, 32 chars)
- **Zone** — A logical network of ZTLP nodes that can discover and communicate with each other
- **Relay** — A server that forwards ZTLP traffic and, for the iOS-first relay-side VIP design, may also terminate selected VIP TCP services on behalf of the phone
- **Name Service (NS)** — Zone-scoped service for node registration and service discovery

## Development Notes

- The C header is at `proto/include/ztlp.h` and must be copied to `ios/ZTLP/Libraries/ztlp.h` after FFI changes
- Current tunnel code still includes `ZTLPVIPProxy.swift`, but the direction is to remove localhost VIP listeners from the NE for iOS and send VIP traffic through a selected relay instead
- Sync NS relay discovery and `RelayPool` selection are the next required pieces for the iOS-first relay-side VIP architecture
- FFI callbacks fire on the Rust tokio thread where tokio-backed paths still exist — always dispatch to main before touching UI
- The `ZTLPBridge` singleton manages all C pointer lifecycle with RAII wrappers
- Identity ownership transfers to `ztlp_client_new()` — don't use the handle after
- Strings from C accessors are library-owned — copy immediately, don't free

## License

See repository root for license information.
