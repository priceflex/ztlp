# Nebula Pivot — Status & Next Session
**Date:** 2026-05-03 (evening, ~22:35 UTC)
**Branch:** `nebula-style-pivot`
**HEAD:** `d47e218` (benchmark: per-request timeout + failure-count surfacing)

---

### TL;DR

- **Nebula pivot code is complete, committed, pushed, and verified green on Mac** (both iOS schemes xcodebuild at `fc7ef3e`, full Rust build + 1140 tests pass). Cumulative delta: 29 files, **-16,218 / +813 LOC**.
- **Phone still runs the OLD pre-pivot binary.** Tonight's vault failure is NOT a pivot regression — it's the well-known gateway **session-replacement replay-storm race** firing on the old code path. Phone log clearly shows deleted-in-pivot codepaths (`ztlp_mux_tick_rwnd hold`, `Health eval`, `Health watchdog late`) and `v5D-SYNC` startup banner.
- **Benchmark now has real per-request timeouts** (`d47e218`). Root-cause bonus: Darwin blocking `connect()` ignored `SO_SNDTIMEO`, which is why tests HUNG instead of timing out. Switched to non-blocking connect + `poll(POLLOUT, ms)`. Stuck tests now fail fast with URL + reason in the submitted `errors` field and `ztlp.log`.

---

### Timeline of current symptom (22:29–22:31 UTC 2026-05-03)

Source: `/tmp/ztlp-phone.log` (2929 lines, 22:21–22:33 UTC).

```
22:29:38.165  [Tunnel] Connecting to 44.246.33.34:23097 via relay 34.219.64.205:23095
22:29:38.643  [Tunnel] Tunnel connection ready
22:29:40.938  [Browser] WKWebView load http://vault.techrockstars.ztlp
22:29:42.137  [Browser] didCommit url=http://vault.techrockstars.ztlp/          ← page briefly loaded
22:29:42.438  [Tunnel] ZTLP RX summary packets=10 payload=7350B replay=1        ← real data flowed
22:29:43.611  [Tunnel] ZTLP RX summary packets=0  payload=0B   replay=20        ← replay storm begins
22:29:44.633  ...replay=10
22:29:46+     ...replay=10 /sec indefinitely — ALL inbound rejected
22:29:47.051  WKWebView NSURLErrorDomain code=-999 "The operation couldn't be…"
              (vault stuck at progress=0.10, reloadTapped loop w/ provisional failures)
22:30:03+     Benchmark HTTP GET http://10.122.0.4/alive, http://10.122.0.2/ all hit 10s timeout
22:31:08.656  Benchmark run timed out after 75s, score posted 6/9
```

Corroborating gateway evidence: `/tmp/gateway-30m.log` (14,496 lines) shows
`Received 72 bytes in phase=awaiting_msg1` + `Buffering 72 byte packet during msg1 phase`
repeating every ~25s across the whole window. Per
`ztlp-gateway-session-debugging` skill, **72 bytes == ACK frame with 0 SACK blocks**
— i.e. the old session's ACK frames arriving at a gateway session that is back
in fresh-handshake state. Classic session-replacement race.

---

### Diagnosis: gateway SessionRegistry replacement race (NOT a pivot bug)

Pattern is textbook per `ztlp-gateway-session-debugging` **Finding 0zz / 0r**:

1. iOS reconnect (or health-watchdog-driven new HELLO) creates a new session.
2. Gateway replaces the old session keyed by client address.
3. Cleanup in `SessionRegistry` is NOT pid-scoped.
4. The stale-session forwarding overlaps the replacement session briefly.
5. Phone's anti-replay window (correctly) rejects the stale packets → storm.
6. All traffic from gateway rejected → WKWebView stalls → `NSURLErrorDomain -999`.

The skill also documents the **fix** (reportedly landed 2026-04-13):
- `SessionRegistry.unregister/2` made pid-scoped.
- `listener.ex:start_new_session/3` pre-unregisters the old pid **before**
  `DynamicSupervisor.terminate_child`.

**Action item:** confirm running gateway image actually contains that fix. The
72-byte-msg1-buffering signature above strongly suggests it does NOT, or that
another reconnect path still bypasses pid scoping.

Evidence lines worth grepping:
- Phone: `grep -E 'replay=|reconnect|HELLO' /tmp/ztlp-phone.log`
- Gateway: `grep -E 'awaiting_msg1|Buffering.*phase=msg1|session.*replac' /tmp/gateway-30m.log`

---

### What changed this session (commits)

```
d47e218  benchmark: per-request timeout + failure-count surfacing
fc7ef3e  nebula-pivot S1.5: nuclear-delete ZTLPBridge
3b3cbf1  B1 fixes
6117041  ztlp.h regen
a98e162  S1 Swift NE cleanup
b7b468e  R4 FFI surface delete
5565157  R3 tunnel.rs surgery
3b88c62  R2 mux.rs surgery
531d69f  R1 module deletes
98f70f6  gateway bbr gating              (pre-pivot)
c4943da  gateway bbr_test fix            (pre-pivot)
```

The pivot proper is R1…R4 (Rust) + S1…S1.5 + B1 (Swift/build) + `ztlp.h` regen,
plus tonight's `d47e218` benchmark surfacing.

---

### Branch status at handoff

- **Branch:** `nebula-style-pivot`
- **HEAD:** `d47e218`
- **LOC delta cumulative:** 29 files, -16,218 / +813
- **Rust:** both builds green, 1140 tests pass
- **Swift/iOS:** both schemes (ZTLP + ZTLPTunnel) xcodebuild GREEN on Mac @ `fc7ef3e`
- **Artifacts:**
  - `libztlp_proto_ne.a` = 25.8 MB (-0.7%)
  - `libztlp_proto.a`    = 46.3 MB (-3.3%)
  - `ZTLPTunnel.appex`   = 4.4 MB  (vs 15 MB ceiling)
- **Gateway:** UNCHANGED (still runs full reliability layer). Nebula client
  ignores ACKs silently; gateway does some wasted retransmits but traffic is OK.
  Gateway demolition is phase 2.

---

### To test on device (exact steps for Steve)

1. **Xcode → Product → Clean Build Folder** (⌘⇧K). Do NOT skip this — stale
   derived-data has bitten us on prior pivots.
2. **Build + Run on iPhone** (real device, not sim). Both targets.
3. **Verify new NE binary is live** — open `ztlp.log` via the sharing extension
   or devicectl pull and confirm:
   - Startup banner NO LONGER prints `v5D-SYNC`.
   - NO lines matching `ztlp_mux_tick_rwnd`, `Health eval`, `Health watchdog`.
   - (Those codepaths were nuked in R2/R3.)
4. **Connect VPN**, then in the in-app WKWebView load
   `http://vault.techrockstars.ztlp`. Expect page to actually render now that
   the client isn't generating reconnect storms.
5. **Run benchmark** from the app. With `d47e218` any stuck test fails fast with
   a clear URL + reason string. Look for:
   - `TCP bench connect timeout`
   - `HTTP bench GET timeout`
   - `HTTP bench GET fail`
   - `Benchmark failures: <summary>` (also surfaces in the submitted `errors`
     free-text field server-side — no Rails migration needed).
6. **Pull the phone log:**
   ```
   xcrun devicectl device copy from \
     --device 39659E7B-0554-518C-94B1-094391466C12 \
     --domain-type appGroupDataContainer \
     --domain-identifier group.com.ztlp.shared \
     --source ztlp.log \
     --destination /tmp/ztlp-phone.log
   ```
7. **Pull the gateway log:**
   ```
   ssh ubuntu@44.246.33.34 'docker logs ztlp-gateway --since 10m' > /tmp/gw.log
   ```
8. **Grep both for replay storm signature:**
   ```
   grep -E 'replay=[0-9]+' /tmp/ztlp-phone.log | awk '$NF !~ /replay=0/'
   grep -E 'awaiting_msg1|Buffering.*phase=msg1' /tmp/gw.log
   ```
   If either is non-empty the race is still live.

---

### If vault still fails after Nebula deploy

1. **Most likely:** the session-replacement race is also triggered by
   **fresh-connect** handshakes (not just reconnects), OR the documented fix
   from `ztlp-gateway-session-debugging` **Finding 0zz** never actually landed
   on the running container. Deploy the pid-scoped
   `SessionRegistry.unregister/2` + pre-unregister-old-pid patch from the skill.
   Verification: no more 72-byte `awaiting_msg1` buffering lines after
   reconnect.
2. **If NOT replay** — cite these signatures in the next diagnosis:
   - `decrypt fail rc=-99` → key/nonce mismatch, not race.
   - `FRAME_ACK arms silently drop` → EXPECTED under Nebula pivot; client no
     longer has reliability layer. Not an error.
   - `NSURLErrorDomain code=-999` → request was cancelled (usually by reload
     tap or tab close). `-1001` = timeout, `-1003` = host not found,
     `-1004` = cannot connect to host. Different failure modes point to
     different layers.
3. **Gateway wire-size reference:** replay-reject packet wire sizes `1202` and
   `408` are the two MTU-bucket signatures of stale data frames. `72` = ACK, 0
   SACK. If you see 72-byte rejects on the phone side the gateway is ACK'ing
   into dead sessions.

---

### Known follow-ups (R5+)

- **Gateway reliability-layer deletion** — symmetric Nebula pivot on server
  side. Big win: eliminates the retransmit/cwnd/stall code that interacts
  poorly with the dumb-pipe client.
- **`proto/src/send_controller.rs` stub** still referenced by `vip.rs`
  (~20 callsites). R5 follow-up to finish the nuke.
- **~193 xcodebuild warnings** — orphaned post-pivot Swift helpers. Cosmetic
  cleanup once device testing confirms no regressions.
- **Main-app enrollment** has inline `TODO` markers where identity-generation
  moved to the extension (S1.5 stubs). Functional but needs wiring polish.
- **`ztlp.h`** has 3 benign stale mentions of deleted fns INSIDE doc comments
  for still-existing fns. Purely cosmetic.

---

### Files to read first next session

- **This doc** — `/home/trs/ztlp/docs/plans/2026-05-03-nebula-pivot-STATUS-AND-NEXT.md`
- `/home/trs/ztlp/docs/plans/nebula-pivot-audit/01-rust-proto.md`
- `/home/trs/ztlp/docs/plans/nebula-pivot-audit/02-ffi.md`
- `/home/trs/ztlp/docs/plans/nebula-pivot-audit/03-ios-swift.md`
- `/home/trs/ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` (post-pivot shape)
- `/home/trs/ztlp/proto/src/mux.rs` (Nebula-style)
- `/home/trs/ztlp/proto/src/tunnel.rs` (Nebula-style)

Also relevant: skill `ztlp-gateway-session-debugging` (Findings 0r, 0zz).

---

### Infra reference block

```
Phone (iPhone):        39659E7B-0554-518C-94B1-094391466C12
Gateway:               ubuntu@44.246.33.34         docker ztlp-gateway    udp/23097
Relay:                 ubuntu@34.219.64.205                                udp/23095
Name Service:          ubuntu@34.217.62.46         docker ztlp-ns          udp/23096
Bootstrap:             trs@10.69.95.12             port 3000
Mac (dev/build host):  stevenprice@10.78.72.234
Preflight script:      /home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Quick-check sequence for a cold start next session:

```
bash /home/trs/ztlp/scripts/ztlp-server-preflight.sh
ssh ubuntu@44.246.33.34 'docker ps --filter name=ztlp-gateway'
ssh ubuntu@34.217.62.46 'docker ps --filter name=ztlp-ns'
git -C /home/trs/ztlp log --oneline -12
git -C /home/trs/ztlp status
```

---

### Important: DO NOT COMMIT THIS DOC

Steve will review and commit himself. This file is intentionally left
uncommitted in the working tree at handoff.
