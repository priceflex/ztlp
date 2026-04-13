# Plan: Fix Mobile+Unknown RTO Profile
## Date: 2026-04-12

---

## What We Know (Code Audit)

### The bug — exactly where it is

File: `gateway/lib/ztlp_gateway/session.ex`

There are three `select_cc_profile` clauses for mobile clients:

```
# clause 1 — mobile + cellular  → gets @mobile_initial_rto_ms (1500) / @mobile_min_rto_ms (500) ✅
defp select_cc_profile(%{client_class: :mobile, interface_type: :cellular})

# clause 2 — mobile + wifi      → calls mobile_wifi_profile() which uses @initial_rto_ms (300) / @min_rto_ms (100) ❌
defp select_cc_profile(%{client_class: :mobile, interface_type: :wifi})

# clause 3 — mobile + unknown   → ALSO calls mobile_wifi_profile() — same weak defaults ❌
defp select_cc_profile(%{client_class: :mobile})
```

`mobile_wifi_profile()` hardcodes `initial_rto_ms: @initial_rto_ms` (300) and
`min_rto_ms: @min_rto_ms` (100) — the same as the desktop defaults. Completely wrong for
a mobile client on an unknown (likely cellular) interface.

### Why interface_type is always :unknown for the benchmark

File: `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`, line 246:

```swift
ztlp_set_client_profile(0, 0, 0)  // mobile + unknown interface
```

This is a hardcoded placeholder that was put in during the initial FFI plumbing. There is
already a working `NetworkMonitor` in the main app (`NetworkMonitor.swift`) that correctly
detects wifi/cellular via `NWPathMonitor`, but the NE (Network Extension) is a separate
process — it does NOT have access to `NetworkMonitor.shared`.

The NE can query the current path independently using `NWPathMonitor` or by checking
`defaultPath` on the tunnel. That's a separate (secondary) fix.

---

## Root Cause Summary

TWO independent issues compound each other:

1. **Gateway (primary)**: `mobile + unknown` maps to `mobile_wifi_profile()` which uses
   the weak 300ms/100ms RTO. Fix is trivial — one Elixir clause change.

2. **iOS NE (secondary)**: The NE hardcodes `interface_type=0` (unknown) instead of
   querying the real path type. This means even if we fix issue #1 above, a cellular
   client can still advertise `unknown` if NE doesn't detect properly.

Both should be fixed, but #1 is highest priority and can ship immediately.

---

## Fix 1: Gateway — mobile+unknown gets safe mobile RTO (PRIMARY)

### File
`gateway/lib/ztlp_gateway/session.ex`

### Change

Split clause 3 so `mobile + unknown` gets its own profile with safe RTO values,
while `mobile + wifi` keeps the wifi-optimized CC params (but also deserves better RTO).

Option A (minimal — just fix the unknown case):
```elixir
# Before (current):
defp select_cc_profile(%{client_class: :mobile}) do
  # mobile + other interface (unknown/wired) — same as wifi
  mobile_wifi_profile()
end

# After:
defp select_cc_profile(%{client_class: :mobile, interface_type: :unknown}) do
  # mobile + unknown interface — treat conservatively, assume could be cellular
  %{
    initial_cwnd: 5.0,
    max_cwnd: 16,
    ssthresh: 32,
    pacing_interval_ms: 6,
    burst_size: 2,
    loss_beta: 0.7,
    initial_rto_ms: @mobile_initial_rto_ms,   # 1500ms
    min_rto_ms: @mobile_min_rto_ms             # 500ms
  }
end

defp select_cc_profile(%{client_class: :mobile}) do
  # mobile + wired or other
  mobile_wifi_profile()
end
```

Option B (also fix wifi RTO while here):
Same as A, but also update `mobile_wifi_profile()` to use safer RTO:
```elixir
defp mobile_wifi_profile do
  %{
    ...
    initial_rto_ms: 800,    # was 300
    min_rto_ms: 250         # was 100
  }
end
```

### Recommendation
Option A first — it's the safe minimal fix with no wifi regression risk.
Option B can follow if wifi benchmark also shows RTO stalls.

### Note on clause ordering in Elixir
Elixir pattern matches top-to-bottom. The new `%{client_class: :mobile, interface_type: :unknown}`
clause MUST be placed BEFORE the catch-all `%{client_class: :mobile}` clause. The cellular
and wifi clauses already exist above it, so just insert the new unknown clause before the
existing catch-all mobile clause.

---

## Fix 2: iOS NE — detect real interface type (SECONDARY)

### File
`ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

### Change
Replace the hardcoded `ztlp_set_client_profile(0, 0, 0)` call with actual interface
detection using NWPathMonitor inside the NE process:

```swift
// Before:
ztlp_set_client_profile(0, 0, 0)  // mobile + unknown interface

// After:
let pathMonitor = NWPathMonitor()
let pathSemaphore = DispatchSemaphore(value: 0)
var detectedInterface: UInt8 = 0  // default: unknown
pathMonitor.pathUpdateHandler = { path in
    if path.usesInterfaceType(.cellular) {
        detectedInterface = 1
    } else if path.usesInterfaceType(.wifi) {
        detectedInterface = 2
    } else if path.usesInterfaceType(.wiredEthernet) {
        detectedInterface = 3
    }
    pathMonitor.cancel()
    pathSemaphore.signal()
}
pathMonitor.start(queue: DispatchQueue.global(qos: .utility))
_ = pathSemaphore.wait(timeout: .now() + 0.5)  // 500ms timeout

let isConstrained: UInt8 = 0  // Low Data Mode not implemented yet
ztlp_set_client_profile(detectedInterface, 0, isConstrained)
self.logger.info("Client profile: mobile interface=\(detectedInterface)", source: "Tunnel")
```

### Why this is safe
- NWPathMonitor is available in Network Extensions on iOS 12+
- 500ms timeout is safe — we're already on a background queue before the handshake
- If timeout fires with no update, falls back to unknown (existing behavior)
- No FFI changes needed, just Swift changes

### After this fix
With the gateway fix (#1) in place, cellular clients will advertise `interface_type=1`
and hit the explicit cellular branch (already correct). The gateway fix handles the
unknown case as a safety net.

---

## Fix 3: Also fix mobile_wifi_profile RTO (OPTIONAL, LOW RISK)

`mobile_wifi_profile()` uses `@initial_rto_ms` (300ms) which is the same as desktop.
WiFi on mobile has more jitter than wired desktop. A modest increase makes sense:

```elixir
defp mobile_wifi_profile do
  %{
    initial_cwnd: 10.0,
    max_cwnd: 32,
    ssthresh: 64,
    pacing_interval_ms: 4,
    burst_size: 3,
    loss_beta: 0.7,
    initial_rto_ms: 800,    # was @initial_rto_ms (300)
    min_rto_ms: 250         # was @min_rto_ms (100)
  }
end
```

Do this only after Fix 1 is verified working.

---

## Execution Order

1. Fix 1 (gateway Elixir change) — ~5 lines of code, redeploy gateway
2. Run benchmark — should stop stalling
3. Fix 2 (iOS NE Swift change) — build + deploy iOS
4. Run benchmark again — confirm interface_type is now cellular in gateway log
5. Fix 3 (optional wifi RTO) — only if needed

---

## Deploy Steps

### Gateway redeploy (Fix 1)
```bash
# On this machine — edit, commit, push to gateway
cd /home/trs/ztlp
# ... edit gateway/lib/ztlp_gateway/session.ex ...
git add gateway/lib/ztlp_gateway/session.ex
git commit -m "fix: mobile+unknown gets safe mobile RTO (1500/500ms)"
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push origin main

# On gateway (44.246.33.34)
ssh ubuntu@44.246.33.34 'cd ~/ztlp && git pull && docker-compose -f docker-compose.gateway.yml build && docker-compose -f docker-compose.gateway.yml down && docker-compose -f docker-compose.gateway.yml up -d'
```

### iOS rebuild (Fix 2)
Requires Steve to run build on Mac + Xcode deploy. See ios/BUILD-GUIDE.md.

---

## Verification

After gateway redeploy, check log for:
```
ClientProfile: class=mobile iface=unknown ... rto=1500/min=500
```
(currently shows rto=300/min=100 — that's the bug indicator)

After iOS fix, check log for:
```
ClientProfile: class=mobile iface=cellular ... rto=1500/min=500
```

Benchmark target: 8/8, no stalls, no retransmit storms.

---

## Session Opening Prompt

"Continue from /home/trs/ztlp/.hermes/plans/2026-04-12-mobile-rto-fix-plan.md.
Start with Fix 1: edit gateway/lib/ztlp_gateway/session.ex to add a new
select_cc_profile clause for mobile+unknown that uses @mobile_initial_rto_ms and
@mobile_min_rto_ms (1500/500ms). Insert it BEFORE the existing mobile catch-all clause.
Commit, push to gateway, redeploy, verify the ClientProfile log line shows rto=1500/min=500."
