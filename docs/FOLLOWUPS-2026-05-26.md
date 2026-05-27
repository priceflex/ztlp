# GitHub Issues to File — 2026-05-26 e2e Debug Session

These are surfaced as a result of the bench debugging on 2026-05-26. Each one stands
on its own as a GitHub issue. Filing them is a follow-up task; this doc captures the
content so they're not lost.

---

## Issue 1: CLI passes `:port` as QUIC transport, not service forward port

**Severity:** 🔴 high — confuses every new user

**Repro:**
```bash
./ztlp connect mygw.example.ztlp:22 --ns-server <ns>
```

**Expected:** the `:22` is interpreted as the user-facing service port (forwarded by
the gateway to its `--forward NAME:HOST:22` mapping). QUIC transport goes to the
relay's `:23095` from the SVC record.

**Actual:** client logs `Resolved: <relay-ip>:22` and tries to open a QUIC handshake
to `:22` on the relay box. Hangs in PTO retries forever because `:22` is SSH, not ZTLP.

**Fix:** in `resolve_target()` (probably `proto/src/bin/ztlp-cli.rs`), the user-supplied
port should be stored as `service_port` and used in the route packet, not as the QUIC
transport address. The transport address always comes from the SVC record's `address`
field.

---

## Issue 2: NS-resolved code path bypasses NAT-traversal and punch logic

**Severity:** 🔴 high — `--punch` silently does nothing in the common case

**Repro:**
```bash
./ztlp connect mygw.example.ztlp --ns-server <ns> --punch --nat-assist
# (no explicit --relay)
```

**Expected:** punch and nat-assist run, just like when `--relay` is explicit.

**Actual:** the entire NAT-traversal / punch block is gated on `if relay.is_some()` at
`proto/src/bin/ztlp-cli.rs:2259`. Without `--relay`, the punch block is skipped — even
though the relay address was just resolved from NS one line earlier.

**Fix:** restructure the cmd_connect function so the NAT-traversal logic runs in both
NS-resolved and explicit-relay cases. The relay address is known either way.

---

## Issue 3: `--service` semantics are contextual (relay vs direct)

**Severity:** 🟡 medium — user confusion

**Description:** When the client talks via relay, `--service` must be the gateway's
registered `--service-name` (e.g., `z2ls-desktop-lrc8dkh-dcc1e2`). When the client
talks LAN-direct, `--service` must be the forward name (e.g., `ssh`). The CLI doesn't
make this distinction documented or detectable.

**Fix options:**
1. Auto-detect: if relay is in path, route by service-name; if direct, route by
   forward name. (Probably what users expect.)
2. Rename: `--service` → `--gateway-name` for the relay case, `--forward` for the
   direct case. (More explicit but more typing.)
3. Document loudly in `--help` text.

---

## Issue 4: Gateway should auto-publish SVC record to NS on startup

**Severity:** 🟡 medium — current behavior causes name drift

**Description:** When `ztlp listen --service-name FOO --zone ZONE` runs, the gateway
registers with the relay under `FOO`, but the NS SVC record under `FOO.ZONE` is NOT
created. Operators have to bootstrap NS records manually with the right name. If the
gateway's `--service-name` changes (Chef pushes new config, etc.), the NS record
drifts out of sync.

**Fix:** gateway should send an unsigned-registration packet to NS on startup, similar
to how the SaaS Launch container does it for tenant gateways. The record would contain
the gateway's NodeID + relay address.

---

## Issue 5: `--stun-server` doesn't accept hostnames, only `IP:port`

**Severity:** 🟢 low — works once you know

**Repro:**
```bash
./ztlp connect ... --stun-server stun.l.google.com:19302
# → error: invalid --stun-server 'stun.l.google.com:19302': invalid socket address syntax
```

**Fix:** DNS-resolve the hostname before parsing as SocketAddr. Or bundle a default
STUN server list (Google, Cloudflare, Mozilla) in the binary so users don't have to
configure one at all.

---

## Issue 6: NS-coordinated hole-punching is client-side stub only

**Severity:** 🔴 high — the feature doesn't work end-to-end

**Description:** The `--punch` flag on `ztlp connect` exists and emits a punch
invitation, but:
- `ztlp listen` has no corresponding `--punch` flag — the gateway can't participate.
- The NS has no protocol handler for forwarding punch invitations between client and
  gateway.

**Status:** Listed in `docs/NAT-TRAVERSAL.md` as the critical-path work needed to make
hole-punching the default.

**Fix:** substantial implementation work. See `docs/NAT-TRAVERSAL.md` for the full
design discussion.

---

## Issue 7: NSSM rebind-loop on Windows service restart

**Severity:** 🟢 low — cosmetic but ugly

**Description:** When the `ztlp_listener` Windows service restarts, NSSM launches the
new ztlp.exe before the previous process has released UDP/23095. The new process
emits 10+ `error: failed to bind UDP socket: error 10048` lines before succeeding.

**Fix:** set `AppRestartDelay=5000` in the NSSM configuration. This is a Chef cookbook
change, not a code change. See `docs/CHEF-COOKBOOK-CHANGES.md`.

---

## Issue 8: v0.30.13 relay binary wire-incompatible with v0.30.11 SaaS

**Severity:** 🔴 high — pins the relay to v0.30.11

**Description:** When `priceflex/ztlp-relay:v0.30.13` (or equivalent raw binary) runs
on the relay, gateway registration packets from `priceflex/ztlp-launch:v0.30.11` (the
SaaS-side gateway-spawning service) are rejected:

```
WARN unknown header length: 3612
WARN unknown header length: 2720
WARN relay: could not extract SessionID from packet
```

Source addresses are the SaaS box's NAT'd outbound (e.g., `16.147.41.195:40274` was
producing valid v0.30.11 registrations). The same source IP works fine against
`priceflex/ztlp-relay:v0.30.11`.

**Reproduction:** the rogue v0.30.13 binary is quarantined at
`/tmp/rogue-ztlp-v0.30.13-quarantined.<unixtime>/` on `34.218.240.106` for forensics.

**Fix:** diff the wire format between v0.30.11 and v0.30.13 on the relay's
gateway-registration path. Either fix the wire compat or document the breaking change.

---

## Issue 9: ztlp emits ANSI escape sequences in stderr even when not a TTY

**Severity:** 🟢 low — log readability

**Description:** NSSM-captured stderr on Windows contains mojibake like `�o` at the
start of lines:

```
�o" gateway registered with 34.218.240.106:23095 (service: z2ls-desktop-lrc8dkh-dcc1e2)
```

These are ANSI color codes (e.g., `\x1b[33m`) being interpreted as UTF-8 by the log
viewer. Most CLI tools detect non-TTY stderr and disable color.

**Fix:** check `atty::is(atty::Stream::Stderr)` and disable color when false.

---

## Issue 10: SaaS box has no Elastic IP, rotates on stop/start

**Severity:** 🟡 medium — every IP rotation breaks all Chef-managed customers

**Description:** The SaaS box (NS + Launch + ngrok) doesn't have an EIP. When AWS
stops/starts it (rare but happens for maintenance), the public IP rotates. Today it's
`16.147.41.195`. Last week it was `35.91.88.177`. Every customer's Chef-managed
`config.toml` has `ns_server = "<old IP>:23096"` baked in, and they all need a Chef
converge to recover.

**Fix:** allocate an Elastic IP for the SaaS instance via AWS console.
Cost: ~$3.65/month for a stable IP. Trivial fix, Steve to do via console.

---

## Priority order for filing

1. **Issue 2** (NS-resolved bypasses punch) — blocks future default-on punch
2. **Issue 8** (v0.30.13 relay wire breakage) — pins our infra to v0.30.11 forever
3. **Issue 1** (port parsing bug) — confuses every new user
4. **Issue 6** (punch stub) — needs design + impl, larger work
5. **Issue 4** (gateway should publish SVC) — operational reliability
6. **Issue 3** (`--service` UX) — UX cleanup
7. **Issue 10** (EIP) — Steve to action via AWS console, not a code issue
8. **Issues 5, 7, 9** — quality-of-life