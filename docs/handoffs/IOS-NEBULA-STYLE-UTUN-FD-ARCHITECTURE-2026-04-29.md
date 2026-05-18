# ZTLP iOS Nebula-Style utun FD Architecture — 2026-04-29

## Executive summary

The current ZTLP iOS Network Extension still routes high-volume packet I/O through Swift `NEPacketTunnelFlow.readPackets` / `writePackets` callbacks. Under Vaultwarden/WKWebView burst load, this has now produced a hard crash in the extension:

```text
Exception: EXC_BREAKPOINT / SIGTRAP
Faulting queue: NEPacketTunnelFlow queue
swift_unknownObjectRetain
initializeWithCopy for ArraySlice
specialized Data.init<A>(_:)
Data.init<A>(_:)
PacketTunnelProvider.flushOutboundPackets(maxPackets:)
closure #1 in PacketTunnelProvider.readPacketLoop()
NEPacketTunnelFlow readPacketsWithCompletionHandler
```

The crash confirms a fundamental design issue: packet/router/utun work is not actually serialized on our `tunnelQueue`. Apple invokes `NEPacketTunnelFlow` callbacks on its own queue, and our Swift hot path uses shared mutable buffers (`readPacketBuffer`, `actionBuffer`, mux counters, rwnd state) plus `Data(ArraySlice(...))` copies. Under browser fan-out, this can race and trap.

Nebula's iOS architecture avoids this class entirely: Swift only configures the Network Extension and extracts the utun file descriptor. The core engine owns direct fd read/write. There is no Swift packetFlow callback hot path.

Recommended long-term solution for ZTLP: move iOS packet I/O into Rust using the utun file descriptor, following Nebula's model.

## Source architecture reference: mobile_nebula

Repo:

```text
https://github.com/DefinedNet/mobile_nebula.git
```

Relevant files:

```text
mobile_nebula/ios/NebulaNetworkExtension/PacketTunnelProvider.swift
mobile_nebula/nebula/control.go
slackhq/nebula/overlay/tun_ios.go
```

### What Nebula does in Swift

Nebula's `PacketTunnelProvider.swift` does not run a packet loop using `packetFlow.readPackets`.

Instead, after applying `NEPacketTunnelNetworkSettings`, it scans process file descriptors to find the utun fd:

```swift
private var tunnelFileDescriptor: Int32? {
  var ctlInfo = ctl_info()
  withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
    $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
      _ = strcpy($0, "com.apple.net.utun_control")
    }
  }

  for fd: Int32 in 0...1024 {
    var addr = sockaddr_ctl()
    var ret: Int32 = -1
    var len = socklen_t(MemoryLayout.size(ofValue: addr))
    withUnsafeMutablePointer(to: &addr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        ret = getpeername(fd, $0, &len)
      }
    }
    if ret != 0 || addr.sc_family != AF_SYSTEM {
      continue
    }
    if ctlInfo.ctl_id == 0 {
      ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
      if ret != 0 {
        continue
      }
    }
    if addr.sc_id == ctlInfo.ctl_id {
      return fd
    }
  }
  return nil
}
```

Then it passes that fd to Go:

```swift
guard let fileDescriptor = self.tunnelFileDescriptor else {
  throw VPNStartError.noTunFileDescriptor
}
let tunFD = Int(fileDescriptor)

self.nebula = MobileNebulaNewNebula(
  String(data: config, encoding: .utf8),
  key,
  self.site!.logFile,
  tunFD,
  &nebulaErr
)

self.nebula!.start()
```

Swift remains responsible for:

- lifecycle (`startTunnel`, `stopTunnel`)
- settings (`setTunnelNetworkSettings`)
- config loading / app IPC
- network path monitor and rebind notification

Swift is not responsible for packet reads/writes.

### What Nebula does in Go

`mobile_nebula/nebula/control.go` calls Nebula with an fd-backed device:

```go
ctrl, err := nebula.Main(c, false, "", l, overlay.NewFdDeviceFromConfig(&tunFd))
```

Nebula's iOS tun implementation wraps the fd:

```go
func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
    file := os.NewFile(uintptr(deviceFd), "/dev/tun")
    t := &tun{
        vpnNetworks:     vpnNetworks,
        ReadWriteCloser: &tunReadCloser{f: file},
        l:               l,
    }
    ...
    return t, nil
}
```

The iOS fd wrapper uses separate read/write buffers protected by separate mutexes:

```go
type tunReadCloser struct {
    f io.ReadWriteCloser

    rMu  sync.Mutex
    rBuf []byte

    wMu  sync.Mutex
    wBuf []byte
}
```

Read path strips the 4-byte utun header:

```go
func (tr *tunReadCloser) Read(to []byte) (int, error) {
    tr.rMu.Lock()
    defer tr.rMu.Unlock()

    if cap(tr.rBuf) < len(to)+4 {
        tr.rBuf = make([]byte, len(to)+4)
    }
    tr.rBuf = tr.rBuf[:len(to)+4]

    n, err := tr.f.Read(tr.rBuf)
    copy(to, tr.rBuf[4:])
    return n - 4, err
}
```

Write path prepends the 4-byte utun family header:

```go
func (tr *tunReadCloser) Write(from []byte) (int, error) {
    if len(from) == 0 {
        return 0, syscall.EIO
    }

    tr.wMu.Lock()
    defer tr.wMu.Unlock()

    if cap(tr.wBuf) < len(from)+4 {
        tr.wBuf = make([]byte, len(from)+4)
    }
    tr.wBuf = tr.wBuf[:len(from)+4]

    ipVer := from[0] >> 4
    if ipVer == 4 {
        tr.wBuf[3] = syscall.AF_INET
    } else if ipVer == 6 {
        tr.wBuf[3] = syscall.AF_INET6
    } else {
        return 0, errors.New("unable to determine IP version from packet")
    }

    copy(tr.wBuf[4:], from)

    n, err := tr.f.Write(tr.wBuf)
    return n - 4, err
}
```

Nebula explicitly does not use multiqueue on iOS:

```go
func (t *tun) SupportsMultiqueue() bool {
    return false
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
    return nil, fmt.Errorf("TODO: multiqueue not implemented for ios")
}
```

## Proposed ZTLP architecture

### High-level model

Current:

```text
iOS packetFlow.readPackets callback
  -> Swift parses IP/DNS/router path
  -> Swift calls Rust PacketRouter FFI
  -> Swift builds mux frames / sends encrypted ZTLP frames
  -> Rust router queues outbound packets
  -> Swift flushOutboundPackets reads router packets into shared buffer
  -> packetFlow.writePackets
```

Proposed Nebula-style:

```text
Swift PacketTunnelProvider
  -> apply NEPacketTunnelNetworkSettings
  -> get utun fd
  -> pass fd + config to Rust FFI
  -> lifecycle/control only

Rust iOS tunnel engine
  -> owns utun fd read loop
  -> owns utun fd write loop
  -> owns PacketRouter
  -> owns DNS responder or calls Rust DNS service map
  -> owns gateway/relay ZTLP transport
  -> owns ACK/rwnd/session-health integration
  -> writes app-group log via FFI callback or file writer
```

### Rust ownership boundaries

Rust should own all packet hot-path mutable state:

- utun read buffer
- utun write buffer
- PacketRouter
- service map
- flow maps
- stream maps
- outbound router queue
- ZTLP transport receive/decrypt state
- ACK/rwnd state
- session-health useful-RX baselines, if feasible

Swift should own:

- Network Extension lifecycle
- applying route/DNS settings
- extracting fd
- user/app IPC
- high-level status reporting
- optional log export plumbing
- reconnect UI state

The main rule:

```text
No high-volume packet bytes should cross Swift as Data / ArraySlice in steady state.
```

## FFI shape

Add an iOS fd-backed engine API in `proto` / iOS FFI layer.

Sketch:

```c
typedef struct ZtlpIosTunnelEngine ZtlpIosTunnelEngine;

typedef void (*ztlp_ios_log_cb)(int32_t level, const char *source, const char *message, void *ctx);
typedef void (*ztlp_ios_status_cb)(int32_t event, const char *detail, void *ctx);

typedef struct ZtlpIosTunnelConfig {
    int32_t utun_fd;
    const char *node_id;
    const char *identity_json;
    const char *relay_addr;
    const char *gateway_addr;
    const char *ns_addr;
    const char *service_map_json;
    const char *app_group_log_path;
    ztlp_ios_log_cb log_cb;
    ztlp_ios_status_cb status_cb;
    void *callback_ctx;
} ZtlpIosTunnelConfig;

int32_t ztlp_ios_tunnel_engine_start(
    const ZtlpIosTunnelConfig *config,
    ZtlpIosTunnelEngine **out_engine
);

int32_t ztlp_ios_tunnel_engine_stop(ZtlpIosTunnelEngine *engine);

int32_t ztlp_ios_tunnel_engine_reconnect(
    ZtlpIosTunnelEngine *engine,
    const char *reason
);

void ztlp_ios_tunnel_engine_free(ZtlpIosTunnelEngine *engine);
```

If keeping Swift-owned `ZTLPTunnelConnection` temporarily, a transition FFI can be smaller:

```c
int32_t ztlp_ios_packet_engine_start(
    int32_t utun_fd,
    ZtlpPacketRouter *router,
    ...
);
```

But the clean final design is for Rust to own the ZTLP transport too.

## utun fd handling in Swift

ZTLP can copy the proven Nebula fd lookup pattern.

Add to `PacketTunnelProvider.swift`:

```swift
private var tunnelFileDescriptor: Int32? {
    var ctlInfo = ctl_info()
    withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
        $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
            _ = strcpy($0, "com.apple.net.utun_control")
        }
    }

    for fd: Int32 in 0...1024 {
        var addr = sockaddr_ctl()
        var ret: Int32 = -1
        var len = socklen_t(MemoryLayout.size(ofValue: addr))
        withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                ret = getpeername(fd, $0, &len)
            }
        }
        if ret != 0 || addr.sc_family != AF_SYSTEM {
            continue
        }
        if ctlInfo.ctl_id == 0 {
            ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
            if ret != 0 {
                continue
            }
        }
        if addr.sc_id == ctlInfo.ctl_id {
            return fd
        }
    }
    return nil
}
```

Important Swift lifecycle sequence:

1. Build `NEPacketTunnelNetworkSettings`.
2. `setTunnelNetworkSettings` completes successfully.
3. Extract utun fd.
4. Start Rust engine with fd.
5. Do not call `packetFlow.readPackets` or `packetFlow.writePackets` for data-plane traffic.

## Rust utun wrapper

Rust should mirror Nebula's explicit single-fd read/write wrapper.

Pseudo-Rust:

```rust
struct IosUtun {
    fd: RawFd,
    read_lock: Mutex<Vec<u8>>,
    write_lock: Mutex<Vec<u8>>,
}

impl IosUtun {
    fn read_packet(&self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = self.read_lock.lock().unwrap();
        let need = out.len() + 4;
        if buf.len() < need { buf.resize(need, 0); }

        let n = nix_read(self.fd, &mut buf[..need])?;
        if n < 4 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        let payload_len = n - 4;
        out[..payload_len].copy_from_slice(&buf[4..n]);
        Ok(payload_len)
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        if packet.is_empty() { return Err(io::ErrorKind::InvalidInput.into()); }

        let family = match packet[0] >> 4 {
            4 => libc::AF_INET,
            6 => libc::AF_INET6,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };

        let mut buf = self.write_lock.lock().unwrap();
        buf.resize(packet.len() + 4, 0);
        // utun header is 4 bytes. Darwin examples put AF in byte 3 for host-order small values.
        buf[3] = family as u8;
        buf[4..].copy_from_slice(packet);

        let n = nix_write(self.fd, &buf[..])?;
        Ok(n.saturating_sub(4))
    }
}
```

Need to confirm AF header byte ordering on iOS matches Nebula (`wBuf[3] = syscall.AF_INET`). Use Nebula as reference.

## Threading model

Recommended first implementation:

```text
Rust engine thread/task A: utun read loop
  read fd packet
  handle DNS locally if applicable
  packet_router.write_packet_sync
  emit mux actions to transport send queue

Rust engine task B: transport receive loop
  receive/decrypt gateway frames
  feed PacketRouter gateway_data/gateway_close
  flush outbound packets to utun fd

Rust engine task C: session-health timer
  monitor useful RX / active flows
  send encrypted ping
  request reconnect/reset

Rust engine task D: transport send/ACK path
  serializes encrypted sends to NW/UDP equivalent or Rust socket
```

But avoid data races by choosing one of two patterns:

### Pattern 1: actor-owned router

One Rust actor owns `PacketRouter` and all mutable routing state. Other tasks send commands through channels:

```text
UtunReadPacket(packet)
GatewayData(stream_id, bytes)
GatewayClose(stream_id)
HealthEvaluate
ResetRuntimeState(reason)
FlushOutbound
```

This is the cleanest model. It prevents router FFI/state races by construction.

### Pattern 2: mutex-owned router

Wrap PacketRouter and related buffers in a mutex. Simpler but riskier for latency.

```rust
struct EngineState {
    router: Mutex<PacketRouter>,
    ...
}
```

Given the iOS NE memory/latency constraints, actor-owned router is preferable.

## Migration plan

### Phase 0: stabilize current code if needed

Before the full fd move, a short-term patch can stop the current crash:

- dispatch `readPackets` completion body onto `tunnelQueue`
- make `flushOutboundPackets` use local packet buffers
- add browser-burst rwnd hysteresis so rwnd=5 cannot sneak in during active browser mode

This is tactical only.

### Phase 1: fd extraction proof of concept

- Add Nebula-style `tunnelFileDescriptor` helper to Swift.
- After network settings apply, log fd:

```text
utun fd acquired fd=N
```

- Do not start Rust fd engine yet.
- Verify existing tunnel still works.

### Phase 2: Rust utun read/write smoke test

- Add FFI function that accepts fd and does a controlled non-invasive test if possible.
- Alternatively create a debug build mode where Rust reads a packet and logs metadata only.
- Be careful: two consumers cannot safely read the same utun fd simultaneously. Do not run Swift packetFlow loop and Rust read loop at the same time except in a tightly controlled experiment.

### Phase 3: Rust owns packet router + utun, Swift still owns transport

Intermediate option:

- Rust reads utun fd and owns PacketRouter.
- Rust calls Swift/FFI callbacks for mux frames to send.
- Swift passes gateway frames into Rust.

This reduces Swift packetFlow risk but still has cross-language transport callbacks.

### Phase 4: Rust owns full iOS data plane

Final target:

- Rust owns utun fd.
- Rust owns PacketRouter.
- Rust owns ZTLP transport socket/session.
- Swift only starts/stops/configures.

This is closest to Nebula and should eliminate Swift packet I/O crash class.

## Validation checklist

Before asking Steve to test:

```bash
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml packet_router --lib
ssh stevenprice@10.78.72.234 'cd ~/ztlp/ios/ZTLP && xcodebuild -project ZTLP.xcodeproj \
  -scheme ZTLP -destination "generic/platform=iOS" -configuration Debug build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO'
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Preflight must end:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Phone validation sequence:

```text
1. Clean Build Folder in Xcode.
2. Deploy to iPhone.
3. Start VPN.
4. Fresh benchmark: expect 8/8.
5. Open Vaultwarden/OpenVault in in-app browser.
6. Do not manually restart VPN.
7. Wait for recovery if a stall occurs.
8. Post-browser benchmark.
9. Send Logs.
10. Capture syslog/crash reports if VPN status flips 5 -> 1.
```

Expected success markers after full fd migration:

```text
utun fd acquired fd=N
Rust iOS tunnel engine started
Rust utun read loop started
Rust utun write loop started
Session health manager enabled ...
Benchmark upload complete ... score=8/8
```

Expected absence:

```text
ZTLPTunnel CORPSE
EXC_BREAKPOINT in Data.init(ArraySlice)
PacketTunnelProvider.flushOutboundPackets crash
NEPacketTunnelFlow queue fault
```

## Risks / open questions

1. File descriptor lifetime
   - Swift must not close fd while Rust engine is running.
   - Rust must stop cleanly before NE shutdown completes.

2. Blocking reads and stopTunnel
   - Rust fd read loop needs a cancellation mechanism.
   - Closing fd or shutting down engine should unblock reads.

3. iOS permissions / App Store policy
   - Nebula uses this approach successfully, so it is a known viable Network Extension pattern.

4. DNS responder
   - Current Swift DNS responder may need to move into Rust if Swift no longer sees packets.
   - Since split DNS for `*.ztlp` is core to WKWebView working, this must be included in the Rust data-plane design.

5. Logging
   - Rust needs to write to the app-group log file or call Swift log callback.
   - Avoid high-frequency cross-language callbacks for packet logs.

6. Transport ownership
   - Full Nebula-style cleanup means Rust should own UDP/NW-equivalent transport too.
   - If Swift keeps `NWConnection`, packet bytes still cross Swift/FFI and some queue risks remain.

## Current evidence motivating this move

Latest reproduced crash:

```text
Syslog:
ReportCrash: Parsing corpse data for pid 35889
osa_update: Pid 35889 'ZTLPTunnel' CORPSE
wifid: com.ztlp.app.tunnel exited

Crash report:
Exception: EXC_BREAKPOINT / SIGTRAP
Termination: Trace/BPT trap: 5
Faulting thread: NEPacketTunnelFlow queue
Frame: PacketTunnelProvider.flushOutboundPackets(maxPackets:)
```

This confirms the hard Vaultwarden drop is a local extension crash, not just gateway congestion, not just rwnd tuning, and not a clean system VPN stop.

## Recommended next-session starting point

Start with Phase 1 + design scaffolding:

1. Add Nebula-style `tunnelFileDescriptor` helper to `PacketTunnelProvider.swift`.
2. After `setTunnelNetworkSettings`, log the fd.
3. Add Rust FFI skeleton types/functions for `ZtlpIosTunnelEngine` behind an iOS feature gate.
4. Add a Rust `IosUtun` wrapper module with read/write header handling and tests for header construction.
5. Do not switch production packet I/O until the fd wrapper and lifecycle are validated.

If time is short and Steve needs immediate stability before architecture migration, apply the tactical current-architecture crash fix first:

- hop `readPackets` body to `tunnelQueue`
- local buffers in `flushOutboundPackets`
- browser-burst rwnd hysteresis

But treat that as a bridge, not the final architecture.
