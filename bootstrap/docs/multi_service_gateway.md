# Multi-Service Gateway (TCP + UDP backends in one listener)

## What

A single ZTLP gateway process (UDP `:23097`) can front many backend
services simultaneously — SSH, MySQL, HTTP, DNS, syslog, anything that
speaks plain TCP or plain UDP. Clients pick the service they want via
the 16-byte service hash inside the HELLO packet, and the gateway
demuxes by hash to the configured backend.

**This document covers the operator-facing config: how to wire up
multiple services behind one gateway, and the protocol-prefix syntax
introduced in v0.30.0 for UDP backends.**

## Why

Before v0.30.0 the gateway only spoke TCP on the backend side, even
though the gateway's *ingress* side has always been UDP (ZTLP + QUIC).
DNS, NTP, syslog, and most game-traffic protocols are UDP-only on the
server side and were therefore unreachable through a ZTLP gateway.

v0.30.0 adds `ZtlpGateway.UdpBackend` plus a small dispatch helper in
`ZtlpGateway.Session`, so a single gateway listener can now serve a
mix of TCP and UDP backends concurrently — no second process, no port
juggling.

## How it works

```
                            ┌────────────────────────────────────────┐
                            │ ZTLP Gateway (single process)          │
                            │                                        │
  client                    │  UdpServer.open(23097)                 │     backends
  ──────► UDP 23097 ───────►│  ↓                                     │──────────────────►
  (encrypted ZTLP frame)    │  Session decrypts + finds backend by   │   TCP 127.0.0.1:22
                            │  the 16-byte service hash              │   TCP 127.0.0.1:3306
                            │  ↓                                     │   UDP 8.8.8.8:53
                            │  Session.start_backend_for(backend_map)│
                            │     ├ :protocol == :tcp → Backend      │
                            │     └ :protocol == :udp → UdpBackend   │
                            └────────────────────────────────────────┘
```

The dispatcher (`ZtlpGateway.Session.start_backend_for/2`) looks at the
`:protocol` field on the resolved backend map and picks the right
connector. Both connector modules deliver replies to the Session as
`{:backend_data, data}`, so the upstream pipeline (encryption, framing,
flow control, send queue) stays protocol-agnostic.

## How to configure it

### Env var format (production)

`ZTLP_GATEWAY_BACKENDS` is a comma-separated list of
`service:host:port` entries. The host segment optionally carries a
protocol prefix:

```
ZTLP_GATEWAY_BACKENDS=ssh:127.0.0.1:22,mysql:127.0.0.1:3306,dns:udp/8.8.8.8:53
```

| Host syntax       | Resolves to                                  |
|-------------------|----------------------------------------------|
| `127.0.0.1`       | TCP backend at `127.0.0.1` (default)         |
| `tcp/127.0.0.1`   | TCP backend at `127.0.0.1` (explicit marker) |
| `udp/8.8.8.8`     | UDP backend at `8.8.8.8` (Model A, see below) |
| `weird/host`      | Logged warning, defaults to TCP              |

Pair with `ZTLP_GATEWAY_POLICIES` to ACL each service to specific
ZTLP identities:

```
ZTLP_GATEWAY_POLICIES=admin.acme.ztlp:ssh,app.acme.ztlp:mysql,*:dns
```

Wildcard `*:service` allows any authenticated ZTLP identity to reach
that service.

### Bootstrap dashboard

The bootstrap UI's per-machine **Gateway backends** textarea takes
newline-separated entries in the same shape, e.g.

```
ssh:127.0.0.1:22
mysql:127.0.0.1:3306
dns:udp/8.8.8.8:53
```

`SshProvisioner` joins them with commas before emitting the env var
on the deploy target, so the on-disk `/etc/ztlp/gateway.env` matches
the production format.

### Elixir `config.exs` (dev)

```elixir
config :ztlp_gateway, :backends, [
  %{name: "ssh",   host: {127, 0, 0, 1}, port: 22},                # implicit :tcp
  %{name: "mysql", host: {127, 0, 0, 1}, port: 3306, protocol: :tcp},
  %{name: "dns",   host: {8, 8, 8, 8},   port: 53,   protocol: :udp}
]
```

`:protocol` defaults to `:tcp` when omitted, so existing configs keep
working without edits.

## UDP backend semantics (Model A — request/response)

The v0.30.0 UDP backend is a **request/response** connector
(`ZtlpGateway.UdpBackend`). For each client send:

1. The gateway opens an ephemeral UDP socket via `:gen_udp.open/2`.
2. Forwards the decrypted payload to the configured `host:port` via
   `:gen_udp.send/4`.
3. Forwards the first reply back to the client, then closes the
   ephemeral socket.
4. If no reply arrives within the per-call timeout (default 5_000 ms),
   the client gets `:backend_timeout` and the session is closed.

This matches what stub resolvers do for DNS and is the right model for
NTP, SNMP gets, syslog with ACK, etc.

**Out of scope for Model A:** long-lived UDP streams where the backend
sends many datagrams per client query (RTP voice/video, multiplayer
game traffic, syslog *without* ACK). These need a future
`UdpBackend.Stream` (Model B) that keeps the ephemeral socket open
across many request/reply cycles and ties its lifecycle to the
ZTLP session rather than the individual datagram.

## How to test it

### Local dev: SSH + MySQL + Google DNS through one gateway

```bash
# 1. Start something to be the SSH backend (or use sshd):
nc -l -k -p 22220 &

# 2. Start a UDP echo on a known port to stand in for DNS:
socat -v UDP4-LISTEN:55353,fork EXEC:'cat' &

# 3. Run the gateway with three backends configured:
ZTLP_GATEWAY_BACKENDS='ssh:127.0.0.1:22220,mysql:127.0.0.1:3306,dns:udp/127.0.0.1:55353' \
  ZTLP_GATEWAY_POLICIES='*:ssh,*:mysql,*:dns' \
  mix run --no-halt

# 4. From another shell, exercise each service with the ztlp CLI:
ztlp connect --service ssh   --gateway 127.0.0.1:23097
ztlp connect --service mysql --gateway 127.0.0.1:23097
ztlp connect --service dns   --gateway 127.0.0.1:23097
```

### Unit-test reference

* `gateway/test/ztlp_gateway/udp_backend_test.exs` (6 tests) —
  the UDP connector in isolation.
* `gateway/test/ztlp_gateway/service_router_test.exs` —
  `parse_backend_config` prefix recognition (5 tests).
* `gateway/test/ztlp_gateway/config_test.exs` — env-var-driven config
  with the protocol prefix (4 tests).
* `gateway/test/ztlp_gateway/session_backend_dispatch_test.exs` —
  the `start_backend_for/2` dispatcher (4 tests).

## Known limitations

* **UDP backends are request/response only (Model A).** A single
  reply ends the in-flight transaction. See "out of scope" above.
* **No source-port preservation across sessions.** Each ZTLP session
  gets a fresh ephemeral local UDP port. Some application protocols
  (very old SIP, some game-server NAT-traversal hacks) require the
  client's source port to stay stable — those won't work today.
* **No UDP backend health checking.** UDP has no in-band "backend is
  down" signal. The gateway will keep forwarding datagrams into the
  void until either the application protocol times out or the
  per-call reply timeout fires.
* **No multi-reply timeout config from env yet.** The 5_000 ms reply
  timeout is constant per `UdpBackend.start_link/1`'s `timeout_ms`
  option but currently not surfaced as an env var. Add
  `ZTLP_GATEWAY_UDP_TIMEOUT_MS` if/when needed.

## Operational concerns

* **MTU.** ZTLP framing adds ~60 bytes of overhead per datagram. If
  a UDP backend can send datagrams up to `N` bytes, the path MTU
  between the gateway and the ZTLP client must be at least `N + 60`,
  otherwise the gateway-side fragmentation logic will kick in (or the
  datagram will be dropped, depending on `IP_MTU_DISCOVER` settings).
  This matters for DNS-over-UDP with large RRSets and for syslog
  messages that exceed 1432 bytes.
* **Policy granularity is per-service-name, not per-protocol.** A
  policy entry `*:dns` lets any identity reach the `dns` service
  regardless of whether the backend is TCP or UDP. If you want
  different policies for TCP and UDP variants of the same logical
  service, configure them under different service names
  (`dns-tcp`, `dns-udp`).
* **Audit log.** Both TCP and UDP backend sessions are recorded by
  `ZtlpGateway.AuditLog.session_established/4` (see `session.ex:1551`).
  The audit event includes the resolved service name; the protocol is
  not yet logged separately. Add it to the audit fields if you need
  to slice traffic by protocol — the `state.backend_protocol` field
  carries the value.

## Troubleshooting

| Symptom                                            | Likely cause + fix                                    |
|----------------------------------------------------|--------------------------------------------------------|
| `[ServiceRouter] Invalid backend config: ...`     | Entry missing the `service:host:port` triple. Check commas. |
| `[ServiceRouter] Unknown backend protocol "xyz"; defaulting to :tcp` | Typo in protocol prefix; only `tcp/` and `udp/` are recognized. |
| Client gets `:backend_timeout` on a UDP service    | Backend never replied within 5_000 ms. Check the backend is bound, reachable, and not firewalled. Lower the timeout via `UdpBackend.start_link({h, p, owner, [timeout_ms: 1_500]})` for protocols with tighter SLAs. |
| TCP backend works, UDP backend doesn't on the same gateway | Check the env var prefix — `dns:8.8.8.8:53` is parsed as TCP. It must be `dns:udp/8.8.8.8:53`. |
| `[Session] Legacy backend reconnect failed: :unsupported_protocol` | `state.backend_protocol` carries a value other than `:tcp` or `:udp`. This is a defensive guard — if you see it, file a bug; it means a backend map was built with a malformed `:protocol` field. |

## See also

* `gateway/lib/ztlp_gateway/udp_backend.ex` — the UDP connector module
  with full module-doc on the lifecycle model.
* `gateway/lib/ztlp_gateway/session.ex` — `start_backend_for/2` and
  `close_backend_pid/2` are the only protocol-aware entry points;
  everything else stays protocol-agnostic.
* `bootstrap/app/services/ssh_provisioner.rb` — the dashboard-side
  `gateway_backends` textarea is concatenated into the env var
  format documented above.
