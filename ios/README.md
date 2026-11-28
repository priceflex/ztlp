# ZTLP for iOS

An iPhone app plus a packet tunnel extension that hosts the same Rust agent
the Mac runs. Enroll once; after that any `http://` or `https://` site under
`.ztlp` opens in Safari with the app closed. There is no Connect button: ZTLP
is an identity network, not a VPN, and iOS keeps the tunnel up on demand.

Status: in development. It runs on a real iPhone: enrollment by QR code,
`.ztlp` sites over HTTPS in Safari with the app closed, and recovery when the
phone moves between Wi-Fi and cellular. Design, device measurements and open
issues are in
[`docs/plans/2026-11-27-ios-native-agent.md`](../docs/plans/2026-11-27-ios-native-agent.md).

## How it works

iOS delivers loopback traffic from other apps to sockets the extension binds,
and it hands `.ztlp` DNS queries to the extension as packets. The design
follows from those two facts:

- `ZTLPTunnel` (packet tunnel extension) starts the Rust agent in-process on
  `127.0.0.1`: resolver on port 53, web on 80 and 443, health on 8443. It
  gives iOS one routed DNS server address for the `ztlp` domain only; the
  queries arrive as packets and are passed to the agent's resolver, which
  answers every site with `127.0.0.1`. Nothing else is routed through the
  tunnel.
- Loopback has one address, so all sites share it. The agent picks the site
  from the TLS server name or the HTTP `Host` header. This covers web
  applications; other protocols by `.ztlp` name are not supported yet.
- The extension watches the device's network and tells the agent when it
  changes or the phone wakes, so connections made on the old network are
  dropped and re-made at once (directly when the gateway is reachable,
  through a relay otherwise).
- `ZTLP` (the app) is one page with three rows: Enrolled, Tunnel running,
  HTTPS trusted. It enrolls the device, saves the VPN configuration with an
  on-demand rule, and walks the user through trusting the device's own
  certificate.
- Both link `libztlp_proto.a` and talk to it through the C functions in
  `ZTLP/Libraries/ztlp_ios.h`. Agent state lives in the App Group container
  (`group.com.ztlp.shared`) under `.ztlp/`.

## Build and install

You need a Mac with Xcode, Rust (`rustup target add aarch64-apple-ios`), an
Apple ID in Xcode for team `5527A7TH5P`, and an iPhone with Developer Mode
on, connected by cable and unlocked.

Run this in Terminal on the Mac itself (not over SSH: signing needs the
unlocked login keychain):

```sh
ios/build-and-install.sh --launch
```

It builds the Rust agent, checks it exports the contract, builds and signs
the app, and installs it on the connected iPhone.

| Option | What it does |
| --- | --- |
| `--rust-dir <path>` | Rust crate to build (default `proto/` in this repo; also `ZTLP_RUST_DIR`) |
| `--device <udid or name>` | Pick a phone when more than one is connected |
| `--launch` | Start the app after installing |
| `--no-sign` | Compile check only: no signing, nothing installed. Works over SSH |
| `--no-sign --stub` | Compile check against a stub library, no Rust needed |
| `--test` | Run the unit tests on an iOS Simulator (stub library) |

### From Xcode instead

1. Run `ios/build-and-install.sh --no-sign` once so
   `ios/ZTLP/Libraries/libztlp_proto.a` exists.
2. Open `ios/ZTLP/ZTLP.xcodeproj`.
3. Pick the `ZTLP` scheme and your iPhone, then Run.

## First run on the phone

1. Open ZTLP. Tap **Scan QR code** and scan the code from the admin panel,
   or tap **Paste code** and paste the `ztlp://enroll/...` text. Scanning the
   code with the Camera app also opens ZTLP with the code filled in.
2. Tap **Allow** when iOS asks to add a VPN configuration.
3. Tap **Show steps** on the HTTPS row and follow the three steps: download
   the certificate in Safari, install it under Settings > General > VPN &
   Device Management, then turn on full trust for it under Settings > General >
   About > Certificate Trust Settings. The last step is a separate switch and
   is required: browsers go to HTTPS first.
4. Open `https://name.zone.ztlp` in Safari.

The gear button shows the device name, zone, the last 200 log lines (agent
log and extension log) and **Remove this device**.

## Layout

```
ios/
  build-and-install.sh        build, sign, install; also --no-sign and --test
  scripts/
    make-stub-lib.sh          stub libztlp_proto.a for compile checks and tests
    ztlp_ios_stub.c
    regen-project.sh          regenerate the Xcode project from project.yml
  ZTLP/
    project.yml               source of truth for ZTLP.xcodeproj (XcodeGen)
    ZTLP.xcodeproj            generated, committed
    Libraries/ztlp_ios.h      C contract; libztlp_proto.a lands here (not committed)
    Shared/                   compiled into both targets
      AddressPlan.swift       the address plan, in one place
      PacketCodec.swift       IPv4/UDP for DNS queries delivered as packets
      NetDiag.swift           on-device path probes (diag.log)
      ZTLPAgent.swift         Swift wrapper over ztlp_ios.h
    ZTLP/                     the app (SwiftUI, iOS 16+)
    ZTLPTunnel/               the packet tunnel extension
    ZTLPTests/                unit tests for the pure logic
```

`ZTLP.xcodeproj` is generated. After adding, removing or renaming a source
file, or editing `project.yml`, run `ios/scripts/regen-project.sh` and commit
the result. XcodeGen builds from source without Homebrew; the script says how.

`ZTLP/Libraries/ztlp_ios.h` must stay identical to `proto/include/ztlp_ios.h`.
`build-and-install.sh` copies the Rust header over it when that file exists.

## Memory

iOS kills a packet tunnel extension above 50 MiB. The extension's Swift code
buffers nothing, and the agent runs with small flow-control windows and one
shared connection per site. Measured on an iPhone 15 Pro Max, the extension
sits at about 4 MiB when idle. Every 30 seconds it writes a line like
`memory footprint=4.0MiB` to its log (Settings > Log > Extension in the app,
and the unified log under subsystem `com.ztlp.app.tunnel`).

## Logs from a connected phone

With the phone paired to the Mac, the logs can be copied without opening the
app:

```sh
xcrun devicectl device copy from --device <id> \
  --domain-type appGroupDataContainer --domain-identifier group.com.ztlp.shared \
  --source .ztlp/agent.log --destination agent.log
```

`extension.log` (start, stop, network changes, memory) and `diag.log` (path
and certificate trust probes) sit next to `.ztlp/` in the same container.

## Known limits

- A download or upload in progress when the network changes is cut and has to
  be retried.
- Only web traffic is carried by name; SSH or remote desktop to a `.ztlp` name
  is not available on iOS yet.
- The path probes that run when the app opens are development aids and will be
  removed before a release.
