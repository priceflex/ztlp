# ZTLP Network Extension Setup

## Xcode Project Changes Required

After pulling this commit, the following files need to be added to the
**ZTLPTunnel** (Network Extension) target in Xcode if they aren't already:

### Files to add to ZTLPTunnel target membership:

1. **`ZTLP/Services/ZTLPBridge.swift`** — FFI wrapper (required)
2. **`ZTLP/Services/TunnelLogger.swift`** — Shared logging (required)
3. **`ZTLP/Models/ConnectionStatus.swift`** — Status enum (if referenced)
4. **`ZTLP/Models/ZTLPIdentity.swift`** — Identity model (if referenced by bridge)
5. **`ZTLP/Services/SecureEnclaveService.swift`** — For hardware identity (optional)

### How to add files to the extension target:

1. Open `ios/ZTLP/ZTLP.xcodeproj` in Xcode
2. Select each file in the Project Navigator
3. In the File Inspector (right panel), under "Target Membership":
   - Ensure **ZTLPTunnel** checkbox is ✅ checked
   - The main **ZTLP** target should already be checked

### Linker setup:

Both targets (ZTLP and ZTLPTunnel) must link:
- `libztlp_proto.a` — The Rust static library
- `NetworkExtension.framework`
- `Security.framework` (for Secure Enclave)

The `ztlp.h` bridging header must be accessible to both targets.

### Entitlements:

The **ZTLPTunnel** target needs these entitlements:
- `com.apple.developer.networking.networkextension` → `packet-tunnel-provider`
- `com.apple.security.application-groups` → `group.com.ztlp.shared`
- `keychain-access-groups` → include shared group

### Important: No UIApplication in Extension

The extension process **cannot** use `UIApplication`. If `ZTLPBridge.swift`
or any shared file references `UIApplication`, wrap it:

```swift
#if canImport(UIKit) && !os(watchOS)
import UIKit
// Only use UIApplication in the main app target
#if !EXTENSION_TARGET
UIApplication.shared.beginBackgroundTask(...)
#endif
#endif
```

Or better: the PacketTunnelProvider doesn't need `UIApplication` at all
since the extension process manages its own lifecycle.

### Architecture

```
┌─────────────────┐        ┌─────────────────────────────┐
│   Main App      │        │  ZTLPTunnel Extension       │
│   (ZTLP)       │        │  (PacketTunnelProvider)      │
│                 │        │                              │
│ TunnelViewModel │──NE──→│ ZTLPBridge → Rust FFI        │
│ (start/stop)    │ Mgr   │ VIP Proxy (127.0.0.1:8080)   │
│                 │        │ DNS (127.0.55.53:5354)        │
│ Stats polling   │←msg──│ handleAppMessage               │
└────────┬────────┘        └──────────────────────────────┘
         │                              ↑
         │                    Safari connects to
         │                    127.0.0.1:8080
         │                              │
         └──── User taps ──────────────→┘
              "Open in Safari"
```

The extension stays alive as long as the VPN is enabled, even when the
main app is suspended. This solves the "Safari timeout" problem.
