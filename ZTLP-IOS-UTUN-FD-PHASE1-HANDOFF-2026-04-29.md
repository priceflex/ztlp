# ZTLP iOS utun FD Phase 1 Handoff — 2026-04-29

## Purpose

This handoff captures the current state after validating the Nebula-style iOS utun fd discovery path, fixing the related build errors, and reproducing the remaining Network Extension drop/crash behavior.

Use this at the start of the next session to continue the iOS data-plane migration.

## Background

The working architecture note is:

`/home/trs/ztlp/ZTLP-IOS-NEBULA-STYLE-UTUN-FD-ARCHITECTURE-2026-04-29.md`

The recommended direction from that note was:

1. Add Nebula-style `tunnelFileDescriptor` helper to `PacketTunnelProvider.swift`.
2. After `setTunnelNetworkSettings`, log the fd.
3. Add Rust FFI skeleton types/functions for `ZtlpIosTunnelEngine` behind an iOS feature gate.
4. Add a Rust `IosUtun` wrapper module with read/write header handling and tests.
5. Do not switch production packet I/O until the fd wrapper and lifecycle are validated.

Phase 1 is now validated on-device.

## Skills / Context to Load Next Session

Load these skills at the start of the next session:

- `ztlp-session-health-recovery`
- `ztlp-ios-build-debugging`
- `ztlp-ffi-layer`

Useful memory/context:

- Steve's Mac is `stevenprice@10.78.72.234`.
- iOS build repo is `~/ztlp` on Steve's Mac.
- There is also `~/code/ztlp`, but for iOS/Xcode work use `~/ztlp`.
- Phone device id: `39659E7B-0554-518C-94B1-094391466C12`.
- Pull app-group log from Mac:

```bash
xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log \
  --destination /tmp/ztlp-phone.log
```

Run syslog capture:

```bash
/home/trs/ztlp/scripts/ios-syslog-capture.sh 300
```

## Files Changed / Added

Local Linux repo and Mac `~/ztlp` were updated.

### Swift / iOS

- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnel-Bridging-Header.h`
- `ios/ZTLP/Libraries/ztlp.h`

### Rust proto

- `proto/src/ios_tunnel_engine.rs` — new file
- `proto/src/lib.rs`
- `proto/src/ffi.rs`
- `proto/include/ztlp.h`

### Mac backup

Before syncing Linux changes into Steve's Mac repo, a backup was made at:

`/tmp/ztlp-pre-sync-20260429-000751`

This backup is on Steve's Mac.

## Phase 1 Implementation Details

### 1. Swift fd discovery marker

In `PacketTunnelProvider.swift`, after `setTunnelNetworkSettings` succeeds, we now log:

```text
utun fd acquired fd=N (Rust fd engine scaffold not started; Swift packetFlow still owns data plane)
```

If fd lookup fails, it logs:

```text
utun fd not found after tunnel settings applied
```

The production packet path is unchanged. Swift `packetFlow.readPackets` / `writePackets` still owns the data plane.

### 2. Darwin C structs not visible in Swift

Initial attempt directly used these in Swift:

- `ctl_info`
- `sockaddr_ctl`
- `CTLIOCGINFO`

That failed on iOS build:

```text
PacketTunnelProvider.swift:942:23: error: cannot find 'ctl_info' in scope
PacketTunnelProvider.swift:950:24: error: cannot find 'sockaddr_ctl' in scope
PacketTunnelProvider.swift:962:33: error: cannot find 'CTLIOCGINFO' in scope
```

Fix was to move the fd scan into the ZTLPTunnel bridging header as a C helper.

### 3. Bridging header helper

File:

`ios/ZTLP/ZTLPTunnel/ZTLPTunnel-Bridging-Header.h`

Added C helper:

```c
#include "ztlp.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#ifndef MAX_KCTL_NAME
#define MAX_KCTL_NAME 96
#endif

#ifndef AF_SYS_CONTROL
#define AF_SYS_CONTROL 2
#endif

struct ztlp_ctl_info {
    uint32_t ctl_id;
    char ctl_name[MAX_KCTL_NAME];
};

struct ztlp_sockaddr_ctl {
    uint8_t sc_len;
    uint8_t sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
    uint32_t sc_reserved[5];
};

#ifndef ZTLP_CTLIOCGINFO
#define ZTLP_CTLIOCGINFO _IOWR('N', 3, struct ztlp_ctl_info)
#endif

static inline int32_t ztlp_find_utun_fd(void) {
    struct ztlp_ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strncpy(ctlInfo.ctl_name, "com.apple.net.utun_control", MAX_KCTL_NAME - 1);

    for (int32_t fd = 0; fd <= 1024; fd++) {
        struct ztlp_sockaddr_ctl addr;
        memset(&addr, 0, sizeof(addr));
        socklen_t len = (socklen_t)sizeof(addr);
        int ret = getpeername(fd, (struct sockaddr *)&addr, &len);
        if (ret != 0 || addr.sc_family != AF_SYSTEM) {
            continue;
        }
        if (ctlInfo.ctl_id == 0) {
            ret = ioctl(fd, ZTLP_CTLIOCGINFO, &ctlInfo);
            if (ret != 0) {
                continue;
            }
        }
        if (addr.sc_id == ctlInfo.ctl_id) {
            return fd;
        }
    }
    return -1;
}
```

Then Swift simply calls:

```swift
private var tunnelFileDescriptor: Int32? {
    let fd = ztlp_find_utun_fd()
    return fd >= 0 ? fd : nil
}
```

### 4. Rust iOS tunnel engine scaffold

New file:

`proto/src/ios_tunnel_engine.rs`

Contains:

- `IosUtun`
- `IosTunnelEngine`
- `read_packet()` that strips 4-byte utun header
- `write_packet()` that prepends 4-byte utun header
- unit tests for IPv4/IPv6 header construction and invalid fd handling

Important behavior:

- utun header follows Nebula's iOS style: byte 3 is set to Darwin AF value.
- IPv4 packet: header `[0, 0, 0, AF_INET]`
- IPv6 packet: header `[0, 0, 0, AF_INET6]`

### 5. Rust FFI scaffold

Added opaque handle:

```rust
#[cfg(any(target_os = "ios", feature = "ios-sync"))]
#[repr(C)]
pub struct ZtlpIosTunnelEngine {
    _private: [u8; 0],
}
```

Added FFI functions:

```c
int32_t ztlp_ios_tunnel_engine_start(
    int32_t utun_fd,
    ZtlpIosTunnelEngine **out_engine
);

int32_t ztlp_ios_tunnel_engine_stop(ZtlpIosTunnelEngine *engine);

int32_t ztlp_ios_tunnel_engine_reconnect(
    ZtlpIosTunnelEngine *engine,
    const char *reason
);

void ztlp_ios_tunnel_engine_free(ZtlpIosTunnelEngine *engine);
```

Important: these are scaffolding only. Production packet I/O has not been moved.

## Validation Completed

### Local Linux Rust checks

These passed:

```bash
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml \
  --no-default-features --features ios-sync --lib

cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml \
  --features ios-sync ios_tunnel_engine --lib
```

Result: fd-wrapper tests passed, 4/4.

### Mac build fixes

After syncing Linux changes to Steve's Mac, initial Xcode build failed because Swift couldn't see `ctl_info`, `sockaddr_ctl`, `CTLIOCGINFO`. Fixed by C helper in bridging header.

Next build failed with linker errors:

```text
Undefined symbols for architecture arm64:
  _ztlp_ios_tunnel_engine_free
  _ztlp_ios_tunnel_engine_stop
```

Root cause: header had new FFI declarations, but `libztlp_proto_ne.a` had not been rebuilt.

Fixed by rebuilding the NE lib on the Mac:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/proto &&
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib &&
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a &&
  cp include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h &&
  if [ -f ~/ztlp/ios/ZTLP/ZTLP/ztlp.h ]; then cp include/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h; fi
'
```

Verified symbols:

```bash
strings ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a | grep -E "ztlp_ios_tunnel_engine_(stop|free|start)"
```

Output included:

```text
_ztlp_ios_tunnel_engine_free
_ztlp_ios_tunnel_engine_start
_ztlp_ios_tunnel_engine_stop
```

Unsigned Xcode build then passed:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/ios/ZTLP &&
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" \
    -configuration Debug build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
'
```

Result:

```text
** BUILD SUCCEEDED **
```

## On-Device Phase 1 Result

After Steve deployed and started VPN, the pulled phone log showed:

```text
[2026-04-29T07:11:25.292Z] [INFO] [Tunnel] Tunnel network settings applied
[2026-04-29T07:11:25.293Z] [INFO] [Tunnel] utun fd acquired fd=5 (Rust fd engine scaffold not started; Swift packetFlow still owns data plane)
[2026-04-29T07:11:25.293Z] [INFO] [Tunnel] Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3 queue=healthQueue
[2026-04-29T07:11:25.293Z] [INFO] [Tunnel] TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)
```

Second run also confirmed:

```text
[2026-04-29T07:13:29.225Z] [INFO] [Tunnel] Tunnel network settings applied
[2026-04-29T07:13:29.225Z] [INFO] [Tunnel] utun fd acquired fd=5 (Rust fd engine scaffold not started; Swift packetFlow still owns data plane)
```

Conclusion: Phase 1 fd discovery works on real device. The fd was consistently `5` in these tests.

## Remaining Failure

Even with fd discovery working, production data plane still uses Swift packetFlow and still drops/crashes.

### Run 1

```text
[2026-04-29T07:11:25.293Z] TUNNEL ACTIVE
[2026-04-29T07:11:27.248Z] Mux summary gwData=0/0B open=1 close=0 send=0/0B
[2026-04-29T07:11:27.297Z] Health eval: flows=1 ... highSeq=0 stuckTicks=1
[2026-04-29T07:11:28.255Z] Mux summary gwData=87/63004B open=1 close=0 send=2/646B
[2026-04-29T07:11:29.297Z] Advertised rwnd=4 reason=browser burst flows=2 streamMaps=2 healthyTicks=0
[2026-04-29T07:11:31.297Z] Health eval: flows=2 outbound=0 streamMaps=2 sendBuf=0 oldestMs=1676 rwnd=4 highSeq=393 stuckTicks=0 usefulRxAge=0.0s outboundRecent=true replayDelta=0 probeOutstanding=false
[2026-04-29T07:11:33.826Z] Benchmark run started category=Tunnel
[2026-04-29T07:11:37.365Z] VPN status changed: 5
[2026-04-29T07:11:37.738Z] VPN status changed: 1
```

### Run 2

```text
[2026-04-29T07:13:29.227Z] TUNNEL ACTIVE
[2026-04-29T07:13:31.232Z] Health eval: flows=0 ...
[2026-04-29T07:13:33.852Z] Mux summary gwData=0/0B open=1 close=0 send=0/0B
[2026-04-29T07:13:38.965Z] VPN status changed: 5
[2026-04-29T07:13:39.416Z] VPN status changed: 1
```

There are no session-health suspect/probe/reconnect markers before the status flips. This suggests the NE process/provider is being dropped before our health ladder can run.

## Syslog / Crash Analysis

A 300-second syslog capture was started before Steve reproduced the drop:

```bash
/home/trs/ztlp/scripts/ios-syslog-capture.sh 300
```

The capture session was:

`proc_0970c22aa551`

The Mac-side files were:

```text
/tmp/ztlp-ios-syslog/ztlp-ios-syslog-20260429T071318Z.raw.log
/tmp/ztlp-ios-syslog/ztlp-ios-syslog-20260429T071318Z.filtered.log
```

Targeted searches were run for:

- `ZTLPTunnel`
- `com.ztlp.app.tunnel`
- `ReportCrash`
- `CORPSE`
- `jetsam`
- `memorystatus`
- `RunningBoard termination`
- `NetworkExtension`
- `packet tunnel`
- `provider exit`

Findings:

- No current `ZTLPTunnel` crash report was available for the 2026-04-29 runs.
- `pymobiledevice3 crash ls` only showed ZTLPTunnel crash reports from 2026-04-28.
- Pulling crash reports did not produce a 2026-04-29 ZTLPTunnel `.ips`.
- Syslog did not show a clean `ReportCrash`, `CORPSE`, `jetsam`, or explicit provider crash line for the 07:13 drop.
- Syslog did show app/WebKit activity and WebKit Networking data usage around the event, but not an extension crash stack.

Crash pull command used:

```bash
ssh stevenprice@10.78.72.234 '
  rm -rf /tmp/ztlp-crashes-new && mkdir -p /tmp/ztlp-crashes-new &&
  /Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 crash pull /tmp/ztlp-crashes-new
'
```

Relevant list result:

```text
/ZTLPTunnel-2026-04-28-175549.ips
/ZTLPTunnel-2026-04-28-202619.ips
...
```

No 2026-04-29 `ZTLPTunnel` report.

Interpretation: latest failures may be clean provider termination/detach or an iOS NE lifecycle kill that does not generate an `.ips`, or the crash report was not flushed. App-group log stops at status flip.

## Important Interpretation

The fd discovery proof succeeded. The remaining issue is not fd lookup.

The remaining issue is that the Swift `NEPacketTunnelFlow` packetFlow data plane can still disappear under traffic before health recovery can act. This is consistent with the original reason for moving toward Nebula-style fd ownership.

Given:

- fd discovery works (`fd=5`)
- Swift packetFlow still drops with no useful crash report
- health timer does not get to suspect/probe/reconnect before drop

The next implementation should proceed to Phase 2 / Phase 3 rather than continuing to patch the Swift packetFlow hot path.

## Recommended Next-Session Starting Point

Start with a controlled Rust fd-engine lifecycle smoke test, not full data-plane switch.

### Step A — Add startup marker for Rust engine scaffold

When/if starting the Rust engine scaffold from Swift, log something unmistakable:

```text
Rust iOS tunnel engine scaffold started fd=N mode=lifecycle_only
```

### Step B — Start/stop lifecycle only

Add a compile/runtime flag or hard-coded disabled-by-default switch so we can start the Rust engine without reading from the fd.

Important: do NOT have Swift packetFlow and Rust both read the utun fd. Two consumers will race.

Safe first step:

- Swift still owns packetFlow.
- Rust engine is allowed to store fd and log lifecycle only.
- Rust must not call `read()` / `write()` on fd yet.

Current FFI skeleton already supports `ztlp_ios_tunnel_engine_start`, `stop`, `free`.

Swift currently does not call `ztlp_ios_tunnel_engine_start`; it only logs fd.

### Step C — Decide transition pattern

Options:

1. Add a debug flag to bypass Swift `startPacketLoop()` and start Rust fd engine read loop instead.
2. Initially make Rust read only one packet and log metadata, then stop. This is risky if Swift packetFlow is also active.
3. Better: add a `useRustFdDataPlane` flag. If true:
   - do not call `startPacketLoop()`
   - do not use Swift `packetFlow.readPackets`
   - start Rust engine with fd
   - Rust owns fd reads

### Step D — Move minimal packet I/O into Rust

The durable direction is:

- Rust owns utun read loop
- Rust owns utun write loop
- Rust owns PacketRouter
- Swift remains lifecycle/settings/config only

But do it incrementally:

1. Rust lifecycle-only engine starts/stops with fd.
2. Rust fd read loop logs packet metadata only in debug mode.
3. Rust owns PacketRouter but Swift still owns transport callbacks only if necessary.
4. Final: Rust owns full ZTLP transport too.

## Commands for Next Session

### Check Mac repo status

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git status --short'
```

Expected dirty files include at least:

```text
 M ios/ZTLP/Libraries/ztlp.h
 M ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
 M ios/ZTLP/ZTLPTunnel/ZTLPTunnel-Bridging-Header.h
 M proto/include/ztlp.h
 M proto/src/ffi.rs
 M proto/src/lib.rs
?? proto/src/ios_tunnel_engine.rs
```

Note: `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift` was already dirty on the Mac before this work. Do not overwrite it accidentally.

### Build NE lib on Mac

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/proto &&
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib &&
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a &&
  cp include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h &&
  if [ -f ~/ztlp/ios/ZTLP/ZTLP/ztlp.h ]; then cp include/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h; fi
'
```

### Verify symbols

```bash
ssh stevenprice@10.78.72.234 '
  strings ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a |
  grep -E "ztlp_ios_tunnel_engine_(start|stop|free)"
'
```

### Unsigned Xcode build

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/ios/ZTLP &&
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" \
    -configuration Debug build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO 2>&1 |
  grep -E "error:|warning:|BUILD SUCCEEDED|BUILD FAILED" | head -100
'
```

### Pull app logs

```bash
ssh stevenprice@10.78.72.234 '
  xcrun devicectl device copy from \
    --device 39659E7B-0554-518C-94B1-094391466C12 \
    --domain-type appGroupDataContainer \
    --domain-identifier group.com.ztlp.shared \
    --source ztlp.log \
    --destination /tmp/ztlp-phone.log &&
  tail -200 /tmp/ztlp-phone.log
'
```

### Pull crash reports

```bash
ssh stevenprice@10.78.72.234 '
  /Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 crash ls |
  grep -iE "ZTLPTunnel|ztlp|com.ztlp" |
  tail -30
'
```

### Syslog capture

```bash
/home/trs/ztlp/scripts/ios-syslog-capture.sh 300
```

## Gotchas / Lessons Learned

1. Do not use Swift `ctl_info`, `sockaddr_ctl`, `CTLIOCGINFO` directly. They are not visible in Swift on iOS. Use a C helper in the bridging header or a small C file.

2. After adding FFI functions, rebuild `libztlp_proto_ne.a`. Header sync alone causes linker errors.

3. Sync both header copies:

```bash
cp ~/ztlp/proto/include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h
if [ -f ~/ztlp/ios/ZTLP/ZTLP/ztlp.h ]; then cp ~/ztlp/proto/include/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h; fi
```

4. Xcode GUI deploy still needs Clean Build Folder after Rust lib changes.

5. App-group logs prove source deployment only if the new marker appears. In this case, marker appeared, so code was live.

6. Latest drops do not generate fresh `.ips` crash reports, so do not block on crash reports before moving to fd-owned design.

## Current High-Level Status

- Phase 1 fd discovery: DONE and validated on iPhone.
- Rust fd wrapper scaffold: DONE and unit-tested.
- FFI skeleton: DONE and link-tested after rebuilding NE lib.
- Production packet I/O moved to Rust: NOT DONE.
- Current Swift packetFlow path: still drops under browser/benchmark traffic.
- Next best move: Phase 2 lifecycle-only Rust engine start, then controlled Rust fd data-plane flag.
