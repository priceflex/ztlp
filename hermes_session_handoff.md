# Hermes Session Handoff — SSH over ZTLP Relay

## Status: ✅ COMPLETE — 2026-05-18

End-to-end SSH from Hermes → relay (34.219.64.205) → Windows gateway
(47.180.216.203 → 10.170.3.111) **works reliably**. Verified 10/10
consecutive `ssh trs@10.170.3.111 'echo OK'` invocations through the
production relay.

### Final command that works

```
ssh -o ProxyCommand="ztlp proxy win 22 --key ~/.ztlp/identity.json --relay 34.219.64.205:23095" \
    trs@10.170.3.111
```

(`win` resolves via `~/.ztlp/agent.toml` to NodeID
`ff59a6f3bf3f4412c3a7007d137ad214` at `10.170.3.111:23095`.)

---

## Bugs fixed this session (commit `24938e4`)

Three independent bugs were combining to break the data plane.

### 1. Proxy emitted oversized UDP datagrams
`proto/src/agent/proxy.rs` had `MAX_PLAINTEXT_PER_PACKET = 16384 - 9`
(≈16KB), so the proxy was emitting UDP packets up to ~16KB on the wire.
Consumer NATs (and Windows Defender Firewall in particular) silently drop
the resulting IP fragments. SSH KEXINIT (the first multi-KB
client→server frame) hung. **Fix:** cap at `tunnel::MAX_PLAINTEXT_PER_PACKET`
(1200 bytes) so the encrypted UDP stays under the 1500-byte Ethernet MTU
after ZTLP/UDP/IP overhead.

### 2. Gateway dropped every inbound packet under multi-session listener
`tunnel::run_bridge_inner` had `if from != peer_addr { continue; }`.
In multi-session mode (`cmd_listen_multi_session`), the dispatcher
demuxes packets via mpsc and re-injects them through a per-session
loopback UDP socket pair, so the bridge's recv `from` is
`127.0.0.1:nnnnn` — never the real peer. Every client→server data frame
was dropped at this filter. The reason it APPEARED that the SSH banner
sometimes flowed: sshd volunteers its banner before reading any client
bytes, so the gateway's TX path (banner-back-to-client) worked once,
masking the inbound-drop bug. **Fix:** skip the peer filter in demuxed
mode (when an `udp_recv_override` socket is supplied). The dispatcher
and pipeline layer-2/layer-3 admission still verify session id + auth
tag on every packet. Two regression tests added under `tunnel::tests`.

### 3. Endianness mismatch in nonce construction
`proto/src/agent/proxy.rs` used `packet_seq.to_be_bytes()` to build the
ChaCha20-Poly1305 nonce. Every other site in the codebase
(`tunnel.rs`, `ztlp-cli.rs` multi-session listener, `ffi.rs`,
`transport.rs`, `ack_socket.rs`) uses `to_le_bytes()`. BE and LE only
collide at `seq=0`, so the very first packet decrypted fine (SSH banner)
and every subsequent packet failed AEAD verification. The symptom was
`tunnel established` + `Connection timed out during banner exchange` on
every SSH attempt past the banner. **Fix:** use `to_le_bytes()` in
both proxy encrypt and decrypt sites.

The third bug is the one that mattered most in practice — bugs #1 and #2
had been masked by it for a long time (the banner exchange "almost"
worked because seq=0 decrypted, so the surface failure was always
"banner timed out").

---

## Verified components

- Relay (`ztlp-relay:ssh-fix` Docker image at `34.219.64.205`) — healthy,
  blocklist excludes `172.26.11.164:23097`, Windows gateway registers
  every 10s as `service=win addr={47.180.216.203, 1218} ttl=60s`.
- Windows gateway (`ztlp.exe` at `C:\Users\TRS\ztlp.exe`, md5
  `5BC765BB6BA4E1FEE2F3D463D92F905B`) — running under
  `Scheduled Task "ZTLP-Listen"`; survives SSH disconnect; persists via
  `start_ztlp.bat`.
- Hermes proxy (`/home/trs/ztlp/proto/target/release/ztlp`) — latest
  build from `main` includes the nonce fix.

---

## Known minor caveats

1. **Windows OpenSSH `MaxStartups`** — rapid repeat SSH attempts that
   never complete auth (e.g. `BatchMode=yes` with no pubkey on Windows)
   can fill sshd's pending-session table within ~10 attempts. sshd
   then briefly refuses new connections with `kex_exchange_identification:
   read: Connection reset by peer`. Real interactive sessions don't hit
   this because they complete auth and free the slot.

2. **Gateway TCP socket cleanup** — every ZTLP session opens a TCP
   socket to `127.0.0.1:22` and the gateway doesn't always close it
   promptly. Over many sessions this accumulates ESTABLISHED entries
   in netstat. A future cleanup pass on `run_bridge_inner` /
   `run_session_bridge` ought to drop the TCP side explicitly when
   the ZTLP session ends. Not a blocker; restart the gateway
   periodically (or accept the ESTABLISHED count growing) if it
   becomes annoying.

---

## Skill updates
Pitfall #22 (nonce endianness) added to `ztlp-relay-gateway-forwarding`
so a future session catches this faster.

## Cleanup performed
- Removed `gateway/lib/ztlp_gateway/session.ex.{orig,rej}` (leftover
  failed patch artifacts).
- Removed stale `proto/proxy.log`.
