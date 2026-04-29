# ZTLP iOS Performance/Recovery Handoff — 2026-04-29

## Current main top

```text
625b930 ios: cap adaptive receive window at five
c8afd73 ios: reset session health baselines after reconnect
172da8d ios: add conservative adaptive receive window
8fb6147 docs: write up iOS Vaultwarden recovery breakthrough
```

## Known-good baseline

- `rwnd=4` is the stable/survivable floor.
- The original “Vaultwarden poisons tunnel and only manual VPN toggle recovers it” bug is fixed in principle.
- Session-health recovery works end-to-end:
  - candidate
  - suspect
  - probe timeout
  - router reset
  - reconnect
  - benchmark recovers

## Latest tested behavior

- `rwnd=6` was too aggressive / risky.
- `rwnd=5` is better and can survive/recover, but still causes pressure under browser/Vaultwarden fan-out.
- Current code caps adaptive rwnd to `4–5`.

Latest successful evidence:

```text
ID 208: Tunnel benchmark 8/8
ID 209: Tunnel benchmark 8/8
ID 210: HTTP category 6/6
ID 211: Network category 3/3
ID 212: Local category 4/4

After browser/pressure/reconnect:
ID 214: 8/8
ID 215: manual log dump 8/8
```

## Critical log findings

Cap=5 build installed and running:

```text
PacketTunnelProvider: rwndAdaptiveMax = 5
ZTLPTunnelConnection clamps rwnd 4–5
```

Fresh build reset health baselines correctly:

```text
highSeq=0
usefulRxAge≈2s
```

During browser/Vaultwarden pressure:

```text
rwnd ramped to 5 with flows=2
oldest_ms rose
rwnd dropped back to 4
replayDelta rose
health candidate/suspect fired
reconnect succeeded
benchmark recovered to 8/8
```

Remaining user-visible problem:

- Health recovery can take about 10–12s.
- HTTP `/alive` requests can timeout during recovery.
- Need faster recovery and smarter browser-burst gating, not higher rwnd.

## Recommended next work

### 1. Add browser-burst rwnd gating

Policy:

```text
If flows >= 2 or streamMaps >= 2:
  force rwnd=4

Only allow rwnd=5 when:
  flows <= 1
  streamMaps <= 1
  no pressure signals are present
```

Purpose:

- Avoid ramping during Vaultwarden/OpenVault multi-flow bursts.
- Preserve the known-good `rwnd=4` behavior under browser fan-out.
- Still allow a small performance bump for simpler/single-flow traffic.

### 2. Tighten session-health recovery timing for active stuck flows

Current behavior:

```text
suspect after ~5s no useful RX
probe timeout after ~5s
```

Proposed behavior:

```text
if active flow and oldest_ms > 3000 and no highSeq progress:
  suspect after ~3s
  probe timeout after ~3s
```

Goal:

- Reconnect before the 10s HTTP benchmark timeout fires.
- Reduce user-visible stalls during post-Vaultwarden poisoned sessions.

### 3. Do not raise rwnd beyond 5 yet

Current conclusion:

```text
rwnd=4 is safe
rwnd=5 is cautiously useful
rwnd=6+ is not justified until pacing/backpressure improves
```

### 4. After browser-burst gating + faster recovery

Before asking Steve to test, run:

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Required result:

```text
PRECHECK GREEN
```

Then test sequence:

1. Fresh benchmark.
2. Vaultwarden/OpenVault browser sequence.
3. Post-burst benchmark.
4. Manual log dump.

## Expected success markers

Fresh benchmark:

```text
8/8
```

During browser burst:

```text
rwnd should stay 4 if flows/streamMaps >= 2
```

If session poisons:

```text
Session health candidate
Session health suspect
probe timeout within faster window
Router reset runtime state removed=1
Reconnect gen=N succeeded via relay ... reset health/rwnd baselines
```

Post-reconnect:

```text
no stale usefulRxAge from old session
highSeq resets
benchmark recovers to 8/8
```

## Important operational notes

Steve’s Mac build repo:

```text
~/ztlp
```

Notes:

- The Mac repo can be dirty/behind git; verify source markers directly before Xcode deploy.
- Codesign/deploy from SSH generally fails; build/deploy from Xcode GUI.
- Before asking Steve to test, always run:

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

- Do not redeploy/restart gateway while Steve is testing.

## Current performance reality

Current safe throughput is limited by small rwnd.

With ~1140-byte payload packets, approximate throughput is:

```text
rwnd=4–5 gives roughly 0.4–1.1 Mbps depending on RTT
```

Interpretation:

- We are not at the theoretical ZTLP/iOS limit.
- We are at the current safe limit of the packet-window approach.
- To go faster later, need smarter architecture, not simply larger rwnd.

Future speed work likely requires:

- smoother gateway pacing/token bucket
- smarter receiver-window signals
- browser-burst mode
- faster recovery
- eventually more QUIC-like stream flow control

## Current conclusion

The architecture is now survivable:

```text
adaptive rwnd tries 5
pressure drops to 4
health detects stuck flow
router resets
transport reconnects
benchmark recovers to 8/8
```

The next best improvement is not raw speed. It is reducing visible recovery time and preventing rwnd ramp during browser fan-out.
