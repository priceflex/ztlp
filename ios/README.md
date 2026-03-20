# ZTLP iOS App

Native iOS client for the **Zero Trust Layer Protocol (ZTLP)**. Provides encrypted peer-to-peer connectivity via a system VPN tunnel backed by Noise_XX handshakes and hardware-secured identity keys.

## Architecture

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
│  └────────────────────────────────────────┘   │
└───────────────────────────────────────────────┘
```

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
- **Relay** — A server that facilitates NAT traversal when direct P2P isn't possible
- **Name Service (NS)** — Zone-scoped service for node registration and service discovery

## Development Notes

- The C header is at `proto/include/ztlp.h` (~630 lines)
- FFI callbacks fire on the Rust tokio thread — always dispatch to main before touching UI
- The `ZTLPBridge` singleton manages all C pointer lifecycle with RAII wrappers
- Identity ownership transfers to `ztlp_client_new()` — don't use the handle after
- Strings from C accessors are library-owned — copy immediately, don't free

## License

See repository root for license information.
