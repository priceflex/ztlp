# iOS native agent: design, plan and device findings

The iPhone app is a SwiftUI app plus a packet-tunnel Network Extension that
hosts the same Rust agent the desktops run (`proto/src/ios_agent.rs`, C
interface `proto/include/ztlp_ios.h`). This document is the working record:
the original plan, what each side implemented, and what was measured on a
real device. Later sections supersede earlier ones where they differ; the
per-site address pool described under "Architecture" was replaced by the
single-address design after device testing.

## Goal of milestone 1

On a real iPhone: open the ZTLP app once, enroll (scan the panel's QR code or
paste the `ztlp://enroll/...` string), close the app, open Safari, load
`http://speedtest.example.ztlp` and then `https://speedtest.example.ztlp` with no port
in the URL. Same experience as the Mac app. Nothing else is in scope.

## Architecture

The Network Extension (packet tunnel) hosts the SAME Rust agent the Mac runs
(`proto/src/agent/`, tokio + quinn), linked as a static library. No second
implementation. The old in-extension stack (`ios_tunnel_engine.rs`, the
`ios-sync` feature, `ZTLPVIPProxy.swift`, `ZTLPTunnelConnection.swift`,
`ZTLPNSClient.swift`, `ZTLPDNSResponder.swift`, `ZTLPBridge`) is superseded and
must not be extended.

Delivery path, option 1 (the one this milestone tests):

- The extension gives the tunnel interface a set of LOCAL addresses:
  `100.64.77.1` (agent DNS + control) and the VIP pool `100.64.77.33-62`
  (`100.64.77.32/27`), each as its own /32 in `NEIPv4Settings`.
- `NEDNSSettings(servers: ["100.64.77.1"])` with `matchDomains = ["ztlp"]`:
  only `.ztlp` lookups go to the agent. No default route, no included routes.
- The agent binds UDP+TCP 53 on `100.64.77.1`, answers `*.ztlp` with a VIP from
  the pool, and binds kernel TCP listeners on `VIP:80` and `VIP:443` (and the
  other usual ports). Safari connects to the VIP; iOS's own TCP stack carries
  it; the agent terminates TLS with a leaf from the device-local CA and
  tunnels to the gateway. No packet parsing, no userspace TCP.
- On-demand rule keeps the tunnel up so it works with the app closed.

Unknown that only a device can answer: whether iOS delivers another app's
connection to a listener the extension bound on the tunnel's own address. If
not, fallback is a userspace TCP stack fed from `packetFlow`, or a local HTTP
CONNECT proxy via `NEProxySettings`. Not in this milestone.

## Memory profile (mandatory on iOS)

The extension is killed at 50 MiB. Measured on macOS with the stock agent:
101 MB with 20 slow readers, 92 MB with 10 parallel uploads. With the profile
below: 25 MB peak under 30 parallel 20 MB uploads + 20 parallel 20 MB downloads.

- one QUIC connection per (service, port), shared by all requests (a new bidi
  stream per client connection; the gateway already loops `accept_bi`)
- stream receive window 256 KiB, connection receive window 8 MiB
- send window 256 KiB
- no global stream cap (a cap starves unrelated sites behind slow readers)

Desktop behaviour must not change: the profile is selected by config, default
is today's values.

## Rust / C contract (`proto/include/ztlp_ios.h`)

All functions are thread-safe, return 0 on success and a negative code on
failure unless noted. Strings are UTF-8, NUL-terminated. `home_dir` is the App
Group container path; everything the agent normally keeps in `~/.ztlp` lives in
`<home_dir>/.ztlp` (same trick as the macOS daemon's pinned HOME).

```c
// Call once per process before anything else. Sets the home dir, starts
// logging to <home_dir>/.ztlp/agent.log (size-capped), installs the iOS
// memory profile.
int32_t ztlp_ios_init(const char *home_dir);

// 1 if a complete enrollment exists under home_dir, else 0.
int32_t ztlp_ios_is_enrolled(void);

// Enroll with a ztlp://enroll/... URI. Blocking (network). Writes identity,
// agent config and name-server trust under home_dir, exactly as
// `ztlp setup --token <uri> --name <device_name> --yes` does on the desktop.
int32_t ztlp_ios_enroll(const char *enrollment_uri, const char *device_name);

// Create the device-local CA if missing (same chain the desktop builds:
// root with .ztlp name constraints + intermediate). Idempotent.
int32_t ztlp_ios_ensure_ca(void);

// Copy the root CA certificate (PEM) into buf. Returns bytes written
// (excluding NUL), or negative; -2 = buffer too small.
int32_t ztlp_ios_ca_root_pem(char *buf, uint32_t buf_len);

// Start the agent in this process on its own threads. dns_ip is the tunnel
// address for the resolver (port 53) and control endpoint; vip_cidr is the
// pool the extension assigned to the tunnel. Returns once listeners are bound
// or failed. Calling it while running returns 0.
int32_t ztlp_ios_agent_start(const char *dns_ip, const char *vip_cidr);

// Stop the agent and free its listeners. Safe to call when not running.
int32_t ztlp_ios_agent_stop(void);

// JSON status into buf: {"running":bool,"enrolled":bool,"node_name":str,
// "zone":str,"vips":int,"tunnels":int,"ca_ready":bool,"last_error":str}.
// Returns bytes written or negative; -2 = buffer too small.
int32_t ztlp_ios_status_json(char *buf, uint32_t buf_len);

// Text of the last error on this thread ("" if none). Valid until the next
// call on the same thread.
const char *ztlp_ios_last_error(void);
```

Library: `proto/target/aarch64-apple-ios/release/libztlp_proto.a`
(`cargo build --release --lib --target aarch64-apple-ios`, default features).
Both the app and the extension link it (the app only uses init / enroll / CA /
status; the extension uses init / agent_start / agent_stop / status).

## App (SwiftUI) requirements

- One page, modelled on the Mac app: logo, 3-row readiness checklist
  (Enrolled / Tunnel running / HTTPS trusted), one line "open any
  https://name.zone.ztlp in Safari". NO Connect button. Gear -> Settings
  (identity name, zone, log tail, Remove this device).
- Not enrolled: "Scan QR code" (camera) and "Paste code". The QR payload is the
  `ztlp://enroll/...` string the admin panel shows. Also handle the
  `ztlp://` URL scheme so the iPhone Camera app can open the app directly.
- After enrollment: save and enable the VPN configuration with an on-demand
  connect rule; the user sees one iOS permission prompt.
- HTTPS trusted: guide the user through installing the CA (serve the root
  certificate from a local listener, open it in Safari, then Settings ->
  General -> VPN & Device Management, then About -> Certificate Trust
  Settings). Detect trust by loading an `https://` URL on the agent's health
  name and show the row green when it validates.
- Bundle ids / team / App Group: keep the ones the existing `ios/ZTLP` project
  uses.

## Out of scope for milestone 1

Proxy fallback, userspace TCP, non-web apps, relay-path tuning, connection
pool/BBR, Android, App Store work, benchmark/battery/services pages.

## Rust side: implementation notes (2026-11-27)

State of `feat/ios-native-agent` after the Rust work for milestone 1. Read
this before coding the Swift side against the contract above.

### What exists

- `proto/include/ztlp_ios.h` and `proto/src/ios_agent.rs`: all nine contract
  functions, same names and signatures. The module is compiled on every
  target and unit-tested on Linux and macOS (including a loopback start /
  stop of the real daemon with a DNS query over UDP and TCP).
- The agent itself is unchanged code: `ztlp_ios_agent_start` writes
  `<home_dir>/.ztlp/agent.toml` and runs `agent::daemon::run_daemon_with_hooks`
  on a tokio runtime with 2 worker threads (at most 4 blocking threads).
  `ztlp_ios_agent_stop` signals the daemon, waits up to 5 s, then drops the
  runtime, which closes every listener and connection.
- Enrollment core moved out of the CLI into `proto/src/agent/enroll.rs`
  (`enroll_with_token`); `ztlp setup --token` calls it and prints the same
  lines as before. `ztlp_ios_enroll` calls the same function.
- State relocation: `proto/src/state_home.rs`, an in-process override that
  `ztlp_state_dir()`, the QUIC pin directory and the NS cache honour. No
  environment variable is modified.

### Return codes

`0` OK, `-1` general (text in `ztlp_ios_last_error()`), `-2` buffer too
small, `-3` invalid argument (NULL, bad UTF-8, bad address), `-4` not
initialised, `-5` not enrolled, `-6` already enrolled. The contract only
fixed `0`, "negative" and `-2`; the rest are additions.

### Config keys added (agent.toml; desktop defaults unchanged)

| Key | Default | iOS value | Meaning |
|---|---|---|---|
| `[tunnel] profile` | `"desktop"` | `"mobile"` | `desktop`: 4 MiB stream / 16 MiB connection receive windows, quinn default send window. `mobile`: 256 KiB / 8 MiB receive, 256 KiB send. |
| `[tunnel] reuse_connections` | unset (profile decides: mobile on, desktop off) | `true` | One QUIC connection per (name, port); each client connection is a new stream on it. |
| `[dns] tcp` | `false` | `true` | Resolver also answers DNS over TCP on the same address and port. |
| `[tls] health_ip` | unset (127.100.255.2 on Windows/macOS, no responder elsewhere) | `dns_ip` | Address of the HTTPS health responder (port 8443) and the A record for `ztlp-health.ztlp`. |

`ztlp_ios_agent_start(dns_ip, vip_cidr)` rewrites these keys at every start,
plus `[dns] enabled/listen = dns_ip:53`, `[dns] vip_range = vip_cidr`,
`[ipc] listen = dns_ip:4433`, `[tls] enabled = true` and
`[identity] path = <home_dir>/.ztlp/identity.json`. Everything else that
enrollment wrote (name server, relays, relay secret, zones) is kept.
Comments in the file are not preserved.

A VIP pool outside 127.0.0.0/8 also changes which clients the VIP listeners
accept: loopback, or a source address that is one of this device's own
interface addresses (loopback pools keep the loopback-only check).

### Files under `<home_dir>/.ztlp` the app may use

- `enrolled_name`: the name the device enrolled as (also `node_name` in the
  status JSON).
- `enroll_callback.json`: see deviation 2.
- `ca/root.pem`: the certificate `ztlp_ios_ca_root_pem` returns.
- `agent.log`, `agent.log.1`: 1 MiB each, rotated. App and extension are two
  processes writing the same file; lines interleave and each process
  rotates on its own count.

There is no "remove enrollment" function in the contract. To remove the
device: stop the tunnel, delete `identity.json`, `config.toml`, `agent.toml`,
`ns_trust.toml`, `enrolled_name` (keep `ca/` so an already trusted root
stays valid).

### Deviations from the contract

1. `ztlp_ios_init` does not install the memory profile itself. The profile
   is written into `agent.toml` by `ztlp_ios_agent_start` and installed by
   the daemon when it starts. Only the agent opens tunnels, so the effect
   is the same; nothing for Swift to do.
2. Enrollment does not send the Bootstrap/Launch callback (the desktop does
   it by running `curl`, which iOS cannot). When the token carries a
   callback URL, `ztlp_ios_enroll` writes
   `{"url","method":"POST","content_type":"application/x-www-form-urlencoded","body"}`
   to `enroll_callback.json`. The app should send that request with
   URLSession and delete the file. Without it the device is enrolled at the
   name server but the panel still shows the token as unused and the
   passwordless-sign-in auto-bind does not happen. The body holds
   identifiers and the device public key only.
3. `device_name` is reduced to a DNS label before enrollment ("Steve's
   iPhone" becomes "steves-iphone"; NULL or empty becomes "iphone"). The
   desktop passes `--name` through unchanged.
4. The shared connection is keyed by (full ZTLP name, port), not
   (service label, port): the same label in two zones is two gateways.
5. `ztlp_ios_agent_start` fails (it does not fall back) when the resolver
   cannot bind exactly `dns_ip:53`. A control-socket or TCP-DNS bind
   failure is logged and the start still succeeds.
6. `ztlp_ios_is_enrolled` returns 0 (not a negative code) before init.

### Not verified, open issues

- Nothing has run on an iPhone. Proven: the library builds for
  `aarch64-apple-ios`, a C program calling all nine functions links against
  it for iOS, and the unit tests pass on Linux and macOS. Unproven on a
  device: binding `dns_ip:53` and `VIP:80/443` on tunnel addresses from the
  extension, whether iOS delivers other apps' connections to those
  listeners, and which source address such a connection has (if it is not
  one of the device's own addresses the agent rejects it and logs
  `Rejected VIP connection from non-local peer`).
- Memory is not measured on iOS. The 25 MB figure is from the macOS
  prototype with the same window values.
- Linking: the app/extension must link `Foundation` and `Security` (the
  legacy `ffi.rs` in the same library calls `NSLog`). Set
  `IPHONEOS_DEPLOYMENT_TARGET` when running `cargo build`, otherwise the C
  objects (aws-lc) are built for the newest SDK and the linker warns. The
  archive still contains the old `ztlp_ios_tunnel_engine_*` symbols.
- VIP listeners are bound up to 50 ms after the DNS answer that allocated
  the VIP (same as desktop), 8 ports per name. `ztlp_ios_init` raises the
  open-file soft limit towards 4096 because iOS starts at 256.
- The shared connection sends a QUIC keep-alive every 15 s and is never
  closed for being idle: battery cost not assessed. After a network change
  a dead shared connection is dropped when a request on it hits the
  first-byte deadline (plain HTTP path) or a stream cannot be opened;
  otherwise only when QUIC's 60 s idle timeout fires. The TLS/splash-gated
  path does not drop it early.
- The control socket (`dns_ip:4433`, bearer token in `agent.token`) answers
  on iOS but its `enroll` command is refused and `setup_status` probes that
  run desktop tools report failure. The app should use this C interface.
- The status field `tunnels` counts open shared connections, not streams.
- `cargo check --no-default-features --features ios-sync` and
  `--features tokio-runtime` alone were already broken on `main` and still
  are; the iOS library is built with default features.
- On a machine that has a real `~/.ztlp`, four existing daemon tests read
  its `ns_trust.toml`; run the suite with `HOME` pointed at an empty
  directory (and `CARGO_HOME`/`RUSTUP_HOME` set explicitly).

## Swift side: what was built and what it expects from Rust (branch `feat/ios-native-app`)

Code is under `ios/`; `ios/README.md` covers build, install and layout. This
section records the points where the Swift side leans on the Rust side, and
what is still unproven.

### How the contract is used

- Header: `ios/ZTLP/Libraries/ztlp_ios.h` is a copy of the contract above. It
  must stay identical to `proto/include/ztlp_ios.h`; `ios/build-and-install.sh`
  copies the Rust header over it when that file exists, and refuses to
  continue when the built library lacks any of the nine `ztlp_ios_*` symbols.
- Extension (`ZTLPTunnel/PacketTunnelProvider.swift`): `ztlp_ios_init`,
  `ztlp_ios_is_enrolled` (start fails with a clear error when 0),
  `setTunnelNetworkSettings`, then `ztlp_ios_ensure_ca` and
  `ztlp_ios_agent_start("100.64.77.1", "100.64.77.32/27")`. `stopTunnel` calls
  `ztlp_ios_agent_stop`. `handleAppMessage` returns `ztlp_ios_status_json`.
  A failing `ensure_ca` is logged and does not stop the tunnel (HTTP still
  works); a failing `agent_start` fails the tunnel start with the library's
  error text.
- App: `ztlp_ios_init`, `ztlp_ios_status_json` (for enrolled / node name /
  zone when the tunnel is down), `ztlp_ios_enroll`, `ztlp_ios_ensure_ca`,
  `ztlp_ios_ca_root_pem`. It never starts the agent.
- Address plan: `ios/ZTLP/Shared/AddressPlan.swift`, used by both targets.

### What the Rust side must satisfy

1. **Health name over HTTPS on port 443.** The app decides "HTTPS trusted" by
   loading `https://ztlp-health.ztlp/` (`TrustProbe.healthURL()`, one
   function). On the desktop that name resolves to a loopback address and its
   TLS responder listens on 8443. On iOS the agent must answer the name with
   an address the phone can reach (the DNS address or a pool VIP) and serve
   TLS on **443** with a leaf from the device-local CA. This was not found in
   the Rust worktree when the Swift side was written. Until it exists the
   HTTPS row stays at "Could not check" (the install button is still
   offered).
2. **Two processes share one home directory.** The app and the extension
   both call `ztlp_ios_init` with the same container path, possibly at the
   same time. Logging to `<home>/.ztlp/agent.log`, the size cap, and
   `ztlp_ios_ensure_ca` (the app calls it for "Install certificate" while the
   extension may be calling it at start) must be safe across processes.
3. **`ztlp_ios_init` in the app must stay cheap**: it must not bind sockets
   or start the agent, only set the home and logging.
4. **`ztlp_ios_status_json` in the app process** must report `enrolled`,
   `node_name` and `zone` from disk (with `running:false`), because the app
   shows them when the tunnel is down.
5. **"Remove this device" deletes `<home>/.ztlp` while the app process is
   still initialised.** A later `ztlp_ios_enroll` in the same process must
   recreate the directory, and logging must cope with its file having been
   deleted.
6. **`ztlp_ios_last_error` is read on the calling thread right after the
   failing call.** The Swift wrapper does that; the text is shown to the user
   as is, so it should be a short plain sentence and must not contain the
   enrollment string.
7. **Leaf certificates must meet iOS's rules for user-trusted roots**:
   SAN with the DNS name, ExtendedKeyUsage serverAuth, validity of 825 days
   or less, RSA 2048+ or ECDSA P-256/P-384, SHA-2. A name-constrained root is
   fine.
8. **Linker inputs.** Both targets link `-lztlp_proto -lresolv` plus the
   Security, SystemConfiguration, CoreFoundation and NetworkExtension
   frameworks. If the Rust library needs anything else
   (`cargo rustc -- --print native-static-libs`), add it to
   `ios/ZTLP/project.yml` and regenerate the project.
9. **Device name.** The app sends a single lowercase label
   (`[a-z0-9-]`, at most 40 characters, default from the phone's name; on
   iOS 16+ that is usually just `iphone`).

### iOS behaviour to check on the first device run

- `NEIPv4Settings` gets 31 addresses (`100.64.77.1` and `.33` to `.62`), each
  with mask `255.255.255.255`, and no included routes. Whether iOS accepts
  that many addresses on one tunnel interface is untested.
- `NEDNSSettings(servers: ["100.64.77.1"])` with `matchDomains = ["ztlp"]`
  points the system resolver at an address the tunnel interface itself owns,
  with no route to it. Whether queries reach the agent's port 53 is the same
  open question as the TCP delivery path.
- The extension drains `packetFlow` and drops what it reads; it never parses
  packets.
- The certificate is served to Safari from an `NWListener` on `127.0.0.1` in
  the app. The app holds a background task while Safari is in front. iOS
  shows the profile prompt only in Safari, not in other browsers.
- The extension logs its physical footprint every 30 s to
  `<container>/extension.log` (shown in the app under Settings > Log >
  Extension) and to the unified log.


## Desktop impact audit (2026-11-27)

The branch is not iOS-only by file count: 17 files under `proto/` changed,
because the phone runs the same agent. Desktop behaviour is unchanged by
default. Nothing outside `proto/`, `ios/` and `docs/` is touched.

Evidence:

- `cargo test --lib`: 1847 passed, 0 failed. `cargo test --bin ztlp`: 151 passed.
- `cargo check --target x86_64-pc-windows-gnu --lib --bin ztlp`: clean.
- macOS `ztlp` built from plain `origin/main` and from this branch: `--help`
  output identical for the top level, `setup`, `agent`, `agent start`,
  `connect`, `listen`.
- Same Mac, same desktop config, each binary run as the per-user agent:
  20 MB download 0.56 s vs 0.53 s; 10 parallel 20 MB downloads 51 s vs 59 s;
  60 small requests 4.9 s vs 6.5 s; 5 parallel 20 MB uploads 2.8 s vs 2.5 s;
  peak footprint with 10 slow readers 93 MB vs 88 MB (so the desktop windows
  and per-request connections are still in effect). One run each. Config and
  identity files unchanged by either.

Desktop-visible differences:

1. `ztlp setup --token` runs the enrollment core from `agent::enroll` (moved
   out of the CLI; 525 of 575 significant lines verbatim, the rest are
   visibility/path edits and progress lines routed through `EnrollUi`).
   A live desktop enrollment with this build has NOT been run.
2. The control socket is bound just before its task is spawned instead of
   inside it. Same address, same error handling.
3. New config keys, all off/unset by default: `[tunnel] profile`,
   `[tunnel] reuse_connections`, `[dns] tcp`, `[tls] health_ip`. An unknown
   `profile` value is a config error.
4. One new startup log line (transport profile).
5. `ios_agent` is compiled on every platform (so it is testable on Linux);
   the desktop binary is about 116 KB larger.


## Single-address (name-routed) mode

Why: on the device (iOS 27) traffic addressed to the tunnel's own addresses
is handed to the extension as raw packets, so sockets bound on a VIP pool
are unreachable, and loopback has only 127.0.0.1 (no aliases). What does
reach a socket in the extension is 127.0.0.1. So all sites share that one
address and the agent tells them apart by name.

### Config

| Key | Default | iOS value | Meaning |
|---|---|---|---|
| `[dns] single_address` | unset (off) | `"127.0.0.1"` | IPv4 address every site name resolves to. Turns the mode on. |
| `[dns] single_address_https_port` | `443` | not written | Listen port for HTTPS. Carried to the site's port 443 whatever it is. |
| `[dns] single_address_http_port` | `80` | not written | Listen port for HTTP, carried to the site's port 80. |

`ztlp_ios_agent_start(dns_ip, vip_cidr)` selects the mode by the prefix
length of `vip_cidr`: `a.b.c.d/32` writes `single_address = "a.b.c.d"` and
removes `vip_range`; a wider prefix writes `vip_range` and removes the
`single_address*` keys (the old pool behaviour, unchanged). Resolver,
control and health stay on `dns_ip`; TLS on, mobile profile, shared
connections on, as before. The app passes `"127.0.0.1"` and
`"127.0.0.1/32"`.

With the key unset nothing changes: no new listener, same answers, same
log and CLI output.

### What the agent does when the mode is on

- Resolver: a name it would have given a VIP (a `*.ztlp` name or a
  `[dns] domain_map` name, found at the name server) gets an A record for
  the single address, TTL 300 s. No VIP is allocated, none is restored from
  `vip_state.json`, and the VIP proxy (the per-VIP listeners) is not
  started. A name the name server does not know, AAAA, other record types,
  the health name (`ztlp-health.ztlp` -> `[tls] health_ip`, responder on
  8443) and a locked session are answered exactly as in VIP mode (a test
  compares the bytes).
- Startup: binds the address on 443 and 80 before the PID file is written.
  443 not bindable = the start fails with `single-address mode ... cannot
  listen on <addr>:443 for HTTPS: <os error>`. 80 not bindable = one
  warning, https still works.
- Port 443: the TLS server name is read from the ClientHello with
  `MSG_PEEK` (nothing is consumed; at most about 16 KiB, 5 s). Port 80:
  the `Host` header is read the same way (at most 8 KiB, 5 s; port and
  trailing dot stripped, lower-cased; found as soon as its line is
  complete).
- The name goes through the resolver's own mapping (`DomainMapper`), so a
  custom-domain form reaches the same site a DNS query for it would. A
  site resolved in the last 300 s (by a DNS query or an earlier
  connection) is used as is; otherwise the name server is asked once, and
  a failure is remembered for 10 s.
- The untouched connection is then passed to `carry_client_connection`,
  the function the VIP listeners use (extracted from `run_tcp_proxy`, body
  unchanged): local TLS termination with the device CA and on-demand leaf
  for the server name, port policy, first-byte deadline, splash/504 pages,
  `X-Forwarded-Proto`, direct-first dial with relay fallback, mobile
  profile, one shared connection per (name, port).
- Refused without dialing, one log line each, at most 5 lines a minute
  (the next line says how many were left out): no server name, a name that
  is not a ZTLP name, a name that does not resolve, bytes that are not TLS
  (443) or HTTP/1.x (80). On 443 the connection is closed before any
  ServerHello, so the client's handshake fails and no certificate is
  minted. On 80 the client gets a short plain answer: 400 (no or bad
  `Host`, not HTTP), 421 (not a ZTLP name), 404 (does not resolve), 431
  (no `Host` in the first 8 KiB), 408 (too slow).
- Same client checks as a VIP listener: loopback clients only for a
  loopback address; nothing new while the session is locked.

Code: `proto/src/agent/name_route.rs` (name extraction, site table, accept
loop), `SingleAddressCarrier` and `carry_client_connection` in
`agent/daemon.rs`, the single-address branch in `agent/dns.rs`.

### Memory

- Site table: at most 64 names (resolved and failed together); expired
  entries go first, then the one expiring soonest. Evicting a site also
  drops its entry in the dialer's per-name address and certificate caches.
- Looking for the name uses one scratch buffer per connection (1 to 8 KiB
  for HTTP, 2 to about 16 KiB for TLS), allocated only once the client has
  sent something, freed before the connection is carried; at most 64
  connections are in that step at a time (about 1 MiB worst case), the
  rest wait. After that a connection costs what a VIP connection costs.
- A connection that sends nothing is closed after 60 s.
- Not bounded, as in VIP mode: the number of concurrent client
  connections (limited by the open-file limit).

### Limits

- Web only. A name can only be read from TLS (SNI) and HTTP (`Host`), so
  SSH, RDP, databases and every other VIP port (22, 3306, 5432, 3389,
  8080, 8443, custom `vip_ports`) are not reachable by name in this mode.
  `https://name:8443/` reaches the health responder, not the site.
- A connection belongs to the site named first. Later requests on the same
  kept-alive HTTP connection go to that site whatever their `Host` says
  (browsers do not reuse a connection across host names).
- A TLS client that sends no server name (connecting by IP address, very
  old clients) is refused. Encrypted ClientHello is not handled.
- `[[tunnel.vip_ports]]` overrides for 443/80 still apply to how the
  connection is carried (e.g. 443 as `passthrough` forwards the TLS bytes
  untouched after the name was read). With `[tls] enabled = false`, 443 is
  passed through undecrypted, as on a VIP, and a warning is logged at
  start.
- Status: `vips` counts site names resolved in the last 300 s; the
  control socket's VIP list is empty.

### Not verified, open issues

- Nothing in this section has run on an iPhone. Proven on Linux: unit and
  loopback tests (name extraction, site table, resolver answers, both
  listeners with a stub name server; `Host` routing through the real VIP
  carrier up to the dial of each site's own gateway address; a `/32` start
  through the C interface on unprivileged ports). Proven on the Mac: the
  library builds for `aarch64-apple-ios`. Not proven: binding 127.0.0.1:443
  and :80 from the extension together with this agent, and a page load.
- No test completes a request through a real gateway in this mode. The
  TLS listener test stops at a stub that performs the agent's TLS accept;
  the real-carrier test uses port 80 and ends at the dial.
- A first connection for a name the agent has not resolved (agent
  restarted while the browser still holds the DNS answer) waits for one
  name-server lookup; several such connections at once each ask.
- A site that was removed stays reachable by name for up to 300 s after
  its last successful resolution (same window as a VIP entry).
- The name is found by polling `MSG_PEEK` (1 to 50 ms steps) because a
  peek does not wait for additional bytes. A ClientHello larger than
  about 16 KiB is refused.
- The startup log still prints the unused `VIP pool:` line.


## Network changes and reconnecting

Measured on the phone: after leaving Wi-Fi, requests were handed the old
shared connection for up to 60 s (QUIC's idle timeout) before anything
dialed again. This section is what the agent does about it. All of it is
active only with shared connections (`[tunnel] reuse_connections`, which
the mobile profile turns on); with the desktop default none of this code
runs. It replaces the bullet "The shared connection sends a QUIC
keep-alive ... does not drop it early" in the Rust notes above.

Code: `proto/src/agent/reconnect.rs` (the logic, tested without a
network), wired in `agent/daemon.rs` (`connect_tunnel`,
`connect_and_open`, `walk_dial_plan`, `proxy_dial_phase`, `bridge_tunnel`,
`apply_network_change`), `agent/conn_cache.rs`, `ztlp_ios_network_changed`
in `ios_agent.rs`.

### What triggers a reconnect

1. `ztlp_ios_network_changed()` (new in `ztlp_ios.h`; the extension calls
   it on every NWPathMonitor update and on wake). Always returns 0, never
   blocks, does not take the lock `start`/`stop` hold, and is a no-op
   before init and while stopped. While the agent runs: every shared
   connection is closed and forgotten; every name must be resolved again
   before its next dial (the ranking of a gateway's addresses is computed
   against the device's current subnets, and the address a listener holds
   for a site may be the one that just became unreachable); the memory of
   which path won last is cleared; the sites that had an open shared
   connection, at most 8 (those in use first), are dialed again in the
   background at once. Listeners, resolver, site table and certificates
   are not touched. Calls are coalesced: the first acts immediately,
   everything in the next 250 ms is one more run. One log line per run
   (`network changed: N shared tunnel(s) closed, M being dialed again
   ...`).
2. A reused shared connection that shows no sign of life (below). No OS
   event is needed for this one.
3. A stream that cannot be opened on a reused shared connection (closed,
   or no stream within 3 s): the connection is forgotten and one new dial
   is made for the request.

### Liveness window and replay

Applies only to a client connection that was given a shared connection
which already existed, never to one dialed for that request, on both
paths: port 443 after the local TLS handshake (`bridge_tunnel`) and port
80 (`proxy_dial_phase`). Before this, port 80 dropped a dead shared
connection only at the 15 s first-byte deadline and port 443 never did.

- The request bytes forwarded so far are kept: at most 64 KiB per client
  connection and 4 MiB in the whole process, freed as soon as the first
  backend byte arrives or a replay stops being possible. On port 443 they
  are the bytes as sent (with `X-Forwarded-Proto` already added).
- The connection is declared dead when, counted from the first forwarded
  request byte, 3 s pass (or the stream fails) with no backend byte AND
  not a single datagram received from the gateway on that connection.
  Then it is closed, which also ends every other stream on it at once,
  and the same bytes are sent on a freshly dialed connection. Once per
  client connection. The client's local connection stays open the whole
  time; requests waiting on the same dead connection share one new dial.
- Never replayed: after any backend byte; when the client sent more than
  64 KiB before the first backend byte (the connection then behaves as
  before); when the gateway acknowledged anything since the request was
  forwarded. The last rule is the difference from "no first byte within
  3 s": a live gateway with a slow backend is left alone, so a request is
  not run twice because the backend took four seconds.
- Why 3 s: a live gateway acknowledges within one round trip plus 25 ms
  and QUIC retransmits several times inside 3 s; it leaves 12 s of the
  default first-byte deadline for the new dial.

### When the dial itself fails

In shared mode a failed dial is retried inside the single-flight slot of
its (name, port), so waiting requests share the one dial: pauses of
250 ms, 500 ms, then 1 s; a single try is abandoned after 5 s; a network
change abandons the running try and starts the next at once. The budget
is the request's first-byte deadline, counted from when the request asked
for the tunnel. Not retried: certificate or pin mismatch, a bad relay
address, a name with no dialable endpoint. At the deadline the client
gets what a deadline gives today (504 page on port 80; on port 443 the
splash page after 1 s for a page load, a close otherwise).

### Direct and relay

With a relay configured (and `prefer_relay` off) the direct candidates
keep their order and their 750 ms each, but the relay is started 200 ms
after them instead of after all of them, and the first finished handshake
is taken; direct wins when both are ready together; the loser is dropped.
A name whose last connection was won by the relay starts both together
next time (that memory is per name, cleared by a network change and when
the name is evicted). Before this change there was no memory of the
winning path at all. Measured on loopback against an in-process gateway
(`cargo test --lib -- --nocapture reconnect_wiring`): direct alive 5 to
6 ms; direct dead and relay alive 260 ms (was 750 ms + relay), 59 ms for
the same name again; both dead: held until the deadline.

### Idle behaviour (mobile profile)

A shared connection that no client connection has used for 120 s is
closed (checked every 15 s); the next request dials. "Used" means a
client connection holds a stream on it, so an open but quiet websocket or
a long poll is never cut. The transport values are unchanged (keep-alive
15 s, idle timeout 60 s): the keep-alive is what keeps a relay mapping and
a NAT binding alive under an open stream. Trade-off: after two minutes
without any connection to a site the next request pays one dial (about
0.3 s through the relay in the phone log; with a dead direct candidate
first, about 0.5 s the first time), which for a page load can be longer
than the splash page's 1 s grace only if the dial is slow. In exchange
the keep-alive stops two minutes after the last use instead of never.

### What is still lost

- A download or upload in progress when the network changes: its stream
  is cut and the browser sees the connection close. Only requests still
  waiting for their first byte are carried over, and of those only the
  ones the gateway had not acknowledged.
- Later requests on a kept-alive browser connection whose first request
  was already answered: when the path dies without a
  `ztlp_ios_network_changed` call they wait for QUIC's idle timeout
  (60 s). With the call they are closed at once and the browser retries.
- A request body larger than 64 KiB sent before any answer.

### Not verified, open issues

- Nothing in this section has run on a phone or against a real relay,
  gateway or name server. Proven: unit tests with in-memory streams and
  virtual time, and loopback tests against an in-process QUIC + Noise
  gateway behind UDP forwarders that can be switched off, plus a stub name
  server; the library builds for `aarch64-apple-ios`.
- Dialing direct and relay at the same time means a gateway can see two
  handshakes from one device, one of them abandoned. Not tried against
  the real gateway and relay.
- Every NWPathMonitor update closes all shared connections, also when the
  path in use did not change (for example cellular coming up while Wi-Fi
  stays). The extension should call only when the usable path changed
  (status, or the set or order of interfaces) and on wake.
- Asymmetric loss (the gateway receives, nothing comes back for 3 s) could
  still run a replayed request twice.
- After a network change each name costs one name-server lookup before
  its next dial. If the name server is not reachable on the new network
  no site connects until it is.
- The first-byte-deadline handler on port 80 still forgets the shared
  connection by name, so a backend slower than the deadline makes the
  next request dial a new connection (as before this work).
- The battery effect of the idle close is not measured.

## Desktop impact audit, final branch state (2026-11-27, after single-address and reconnect work)

Re-run on the branch head after all iOS work. Nothing outside `proto/`,
`ios/` and `docs/` is touched.

- `cargo test --lib`: 1933 passed, 0 failed. `cargo test --bin ztlp`: 151 passed.
  `cargo fmt -- --check` clean. `cargo check --target x86_64-pc-windows-gnu
  --lib --bin ztlp` clean.
- macOS `ztlp` from plain `origin/main` vs this branch: `--help` identical
  for the top level, `setup`, `agent`, `agent start`, `connect`, `listen`,
  `admin`.
- Same Mac, same desktop config, each binary run as the per-user agent
  (one run each): 20 MB download 0.54 s vs 0.54 s; 10 parallel 20 MB
  downloads 60 s vs 50 s; 60 small requests 4.8 s vs 4.8 s; 5 parallel 20 MB
  uploads 2.5 s vs 2.5 s; peak footprint with 10 slow readers 94 MB vs 84 MB
  (desktop windows and per-request connections still in effect; no shared
  connection was reused; no warnings). Config and identity files unchanged.

Still not done: a live desktop enrollment (`ztlp setup --token`) with a
build from this branch. The enrollment core moved from the CLI into
`agent::enroll`; its tests pass, but run one real enrollment before merging.
