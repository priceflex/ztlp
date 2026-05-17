# 03 — iOS Swift layer: Nebula-pivot blast radius

Scope: only two files.
- ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift (2383 LOC)
- ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift (965 LOC)

Premise: client becomes a dumb pipe (Nebula/mobile_nebula-style). Inner TCP does congestion control. All reliability-layer machinery in Swift — ACK framing, duplicate detection, advertised receive windows, RTT/BDP shadow observation, session-health probing, mux rwnd autotune — goes away.

---

## CALLSITES TO DELETE OR SIMPLIFY

### ZTLPTunnelConnection.swift

- `ZTLPTunnelConnection.swift:37-43` — `ZTLPTunnelConnectionDelegate` protocol methods `didReceiveData(..., sequence:)` and `didReceiveAck(sequence:)`.
  Current: delegate receives per-frame data_seq; ACK callback fires for cumulative ACKs.
  Post-pivot: SIMPLIFY. Drop `sequence:` from the data callback (no longer meaningful). DELETE `didReceiveAck` entirely.

- `ZTLPTunnelConnection.swift:79-85` — `onDataFrameSent` closure property (fires after each framed DATA so PTP can feed `ztlp_mux_observe_sent`).
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:115-125` — `useByteRwnd` flag + `advertisedWindowKb` + `advertisedReceiveWindow` (phase-B byte-rwnd config).
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:372` — `stop()` calls `flushPendingAcks()` on shutdown.
  Post-pivot: DELETE that line.

- `ZTLPTunnelConnection.swift:377-378` — `stop()` clears `seenSequences` / `pendingAcks`.
  Post-pivot: DELETE.

- `ZTLPTunnelConnection.swift:390-434` — `sendData(_:)` path frames with ztlp_frame_data, assigns `seq = nextSendSequence()`, fires `onDataFrameSent?(seq, frameWritten)`.
  Post-pivot: SIMPLIFY. Drop the sequence assignment and the observe-sent hook. The Rust frame builder should either stop emitting a sequence field or the client should pass a dummy zero. Encrypt + ship; that's it.

- `ZTLPTunnelConnection.swift:425-430` — Phase-A shadow RTT hook comment + `onDataFrameSent?` invocation in sendData.
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:495-505` — `queueAck(for:)` and `setAdvertisedReceiveWindow(_:)`.
  Current: appends a sequence to pendingAcks and immediately triggers flush; exposes rwnd setter.
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:507-511` — `setAdvertisedWindowKb(_:)`.
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:525-564` — `flushPendingAcks()` (V1 and V2 FRAME_ACK emit path, including `ztlp_build_ack_v2` / `ztlp_build_ack_with_rwnd`).
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:715-741` — Inbound FRAME_ACK (0x01) and FRAME_ACK_V2 (0x10) branches in `handleReceivedPacket`.
  Current: parses cumulative_ack, invokes `delegate?.tunnelConnection(_, didReceiveAck:)`.
  Post-pivot: DELETE ENTIRELY. Gateway should stop emitting ACKs; client treats them as unknown → drop silently.

- `ZTLPTunnelConnection.swift:773-826` — mux-format + legacy FRAME_DATA decode in `handleReceivedPacket` that pulls out `data_seq` and calls `handleDataFrame(sequence:payload:)`.
  Post-pivot: SIMPLIFY. Frame still has a type byte, but data_seq bytes become unused (or the wire format drops them). Route payload straight to delegate, no sequence extraction.

- `ZTLPTunnelConnection.swift:830-849` — Unknown-frame fallback via `ztlp_parse_frame` that still funnels into `handleDataFrame`.
  Post-pivot: SIMPLIFY. Keep the parse for forward-compat but deliver payload directly; drop the sequence arg.

- `ZTLPTunnelConnection.swift:852-876` — `handleDataFrame(sequence:payload:)` (dup-check via seenSequences, `duplicatesDropped++`, `queueAck(for:)`, `recordSequence`, then delegate).
  Post-pivot: DELETE and inline a 3-line "deliver payload to delegate" in handleReceivedPacket. See pseudocode below.

- `ZTLPTunnelConnection.swift:878-893` — `recordSequence(_:)` (seenSequences insert + prune).
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:895-900` — `nextSendSequence()` helper.
  Post-pivot: DELETE ENTIRELY.

- `ZTLPTunnelConnection.swift:904-914` — rxSummary aggregation including `rxSummaryAckCount` and `rxSummaryHighestSeq`.
  Post-pivot: SIMPLIFY. Keep packet/byte counters, drop ACK-count and highest-seq fields.

- `ZTLPTunnelConnection.swift:956-965` — `resetCounters()` — zeroes `duplicatesDropped`.
  Post-pivot: SIMPLIFY — remove the duplicatesDropped line.

### PacketTunnelProvider.swift

- `PacketTunnelProvider.swift:163-198` — Nebula-collapse cutover comment block + `useRustMux` / `useRustHealth` / `useRttInstrumentation` / `useByteRwnd` flags + `rustMux` / `rustHealth` / `rustHealthReasonBuffer` properties.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:213-214` — `ackFlushTimer: DispatchSourceTimer?`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:229-254` — All rwnd tunables (`rwndFloor`, `rwndAdaptiveMax`, `rwndBrowserBurstTarget`, `rwndHealthyTicksToIncrease`, `rwndReplayDeltaBad/Reconnect`, `rwndPressureCooldown`, `rwndRouterOutboundBad`, `rwndSendBufBytesBad`, `rwndOldestMsBad`, `rwndBrowserBurstFlowThreshold`).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:255-259` — `advertisedRwnd`, `consecutiveFullFlushes`, `consecutiveRwndHealthyTicks`, `lastRwndLogAt`, `rwndPressureUntil`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:264-295` — Entire session-health tunable + state block (`healthCheckInterval`, `healthSuspectThreshold`, `probeTimeoutThreshold`, `fastStuckOldestMsThreshold`, `fastStuckTicksBeforeSuspect`, `noProgressTicksBeforeSuspect`, `healthLateThreshold`, `healthQueue`, `healthTimer`, `lastUsefulRxAt`, `lastOutboundDemandAt`, `lastHealthCheckAt`, `lastHealthWatchdogFireAt`, `sessionSuspectSince`, `probeOutstandingSince`, `lastProbeResponseAt`, `consecutiveNoProgressChecks`, `consecutiveStuckHighSeqTicks`, `lastHighSeqSeen`, `priorHighSeqSnapshot`, `lastReplayRejectCount`, `lastRouterFlows`, `lastRouterOutbound`, `lastRouterStreamMappings`, `lastHealthHeartbeatAt`, `healthProbeNonce`, `pendingReconnectReason`).
  Post-pivot: DELETE ENTIRELY. Hard-network-loss reconnect (NWConnection `.failed`) does not need any of this — the scheduleReconnect path keyed off transport failure remains (see KEEP).

- `PacketTunnelProvider.swift:331-344` — `markOutboundDemand()` (calls `ztlp_mux_mark_outbound_demand`) and `markUsefulRx(sequence:payloadLength:)`.
  Post-pivot: DELETE ENTIRELY. (Or demote markOutboundDemand to a no-op and remove callers.)

- `PacketTunnelProvider.swift:346-356` — `refreshReplayRejectBaseline()` + `clearSessionHealthState()`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:393-403` — `startHealthTimer()`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:406-423` — `handleHealthWatchdogTick()`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:425-434` — `sendSessionProbe(reason:)` (PING nonce emit).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:436-458` — `handleProbeSuccess(nonce:)`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:460-465` — `resetPacketRouterRuntimeState(reason:)` (only called from health/reconnect paths).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:467-652` — `evaluateSessionHealth()` (the whole ~185-line state machine: rwnd policy via `ztlp_mux_tick_rwnd`, Rust health tick via `ztlp_health_tick` with SEND_PROBE / RECONNECT actions, legacy suspect/probe-timeout fallback, `maybeLogRttSnapshot()` call).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:1002-1020` — `ackFlushTimer?.cancel()`, `healthTimer?.cancel()`, `ztlp_health_free`, `ztlp_mux_free` in the stopTunnel teardown.
  Post-pivot: SIMPLIFY — remove ackFlushTimer/healthTimer cancels and the Rust mux/health frees.

- `PacketTunnelProvider.swift:1587-1605` — `updateAdvertisedRwnd(_:reason:)` + `reduceAdvertisedRwnd(reason:)`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:1607-1689` — `maybeRampAdvertisedRwnd(stats:replayDelta:highSeqAdvanced:hasActiveFlows:)` (legacy rwnd ramp/pressure, browser-burst handling, replay-delta reconnect trigger).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:1702-1705` — `startAckFlushTimer()`.
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:2278-2289` — `ZTLPTunnelConnectionDelegate.tunnelConnection(_:didReceiveAck:)` impl (feeds `ztlp_mux_observe_ack_cumulative`).
  Post-pivot: DELETE ENTIRELY (protocol method goes with it, see Connection:43).

- `PacketTunnelProvider.swift:2291-2331` — `wireRttInstrumentationHook(on:)` (phase-B useByteRwnd plumbing, `ztlp_mux_note_peer_sent_v2`, shadow observe-sent closure install).
  Post-pivot: DELETE ENTIRELY. Remove both call sites (`:858`, `:937`, `:2004`).

- `PacketTunnelProvider.swift:2333-2373` — `maybeLogRttSnapshot()` (srtt/rttvar/goodput/bdp/adv_kb/autotune snapshot logger).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:2375-2382` — `tunnelConnection(_:didReceiveProbeResponse:)` (on_pong / handleProbeSuccess).
  Post-pivot: DELETE ENTIRELY.

- `PacketTunnelProvider.swift:2263-2269` — `didReceiveData` delegate impl: drops `markUsefulRx` call.
  Post-pivot: SIMPLIFY — keep `markDataActivity()` and `handleGatewayMuxPayload(data)`; drop `markUsefulRx`.

- `PacketTunnelProvider.swift:1614-1624`, `:648-650`, `:1919-1921` — `scheduleReconnect()` invocations from replay-storm / probe-timeout / session-health paths.
  Post-pivot: DELETE those callers. The NWConnection-failure path (`:2271-2276 didFailWithError → scheduleReconnect`) stays — that is the legit Apple-path-loss trigger.

Total distinct callsites/blocks to delete-or-simplify: **34**.

---

## STATE VARIABLES TO DELETE

Reliability-only stored properties — every one of these goes.

### ZTLPTunnelConnection.swift
- `:85`  `var onDataFrameSent: ((UInt64, Int) -> Void)?`
- `:94`  `private var sendSequence: UInt64 = 0`
- `:98`  `private var seenSequences = Set<UInt64>()`
- `:102` `private static let maxSeenSequences = 2_000`
- `:105` `private var highestSeenSequence: UInt64 = 0`
- `:108` `private var pendingAcks: [UInt64] = []`
- `:109` `private static let maxPendingAcks = 64`
- `:113` `private var advertisedReceiveWindow: UInt16 = 4`
- `:119` `var useByteRwnd: Bool = false`
- `:125` `private var advertisedWindowKb: UInt16 = 16`
- `:152` `private(set) var duplicatesDropped: UInt64 = 0`
- `:161` `private var rxSummaryAckCount: UInt64 = 0`
- `:162` `private var rxSummaryHighestSeq: UInt64 = 0`

### PacketTunnelProvider.swift
- `:184` `private static let useRttInstrumentation = true`
- `:186` `private var lastRttLogAt: Date = .distantPast`
- `:193` `private static let useByteRwnd = true`
- `:194` `private var rustMux: OpaquePointer?`
- `:195` `private var rustHealth: OpaquePointer?`
- `:198` `private var rustHealthReasonBuffer = [CChar]...`
- `:214` `private var ackFlushTimer: DispatchSourceTimer?`
- `:175-176` `useRustMux` / `useRustHealth` flags
- `:241-250` `rwndFloor`, `rwndAdaptiveMax`, `rwndBrowserBurstTarget`, `rwndHealthyTicksToIncrease`, `rwndReplayDeltaBad`, `rwndReplayDeltaReconnect`, `rwndPressureCooldown`, `rwndRouterOutboundBad`, `rwndSendBufBytesBad`, `rwndOldestMsBad`
- `:254` `rwndBrowserBurstFlowThreshold`
- `:255` `private var advertisedRwnd: UInt16 = 4`
- `:256` `private var consecutiveFullFlushes = 0`
- `:257` `private var consecutiveRwndHealthyTicks = 0`
- `:258` `private var lastRwndLogAt: Date = .distantPast`
- `:259` `private var rwndPressureUntil: Date = .distantPast`
- `:266-275` `healthCheckInterval`, `healthSuspectThreshold`, `probeTimeoutThreshold`, `fastStuckOldestMsThreshold`, `fastStuckTicksBeforeSuspect`, `noProgressTicksBeforeSuspect`, `healthLateThreshold`
- `:276` `private let healthQueue = DispatchQueue(...)`
- `:277` `private var healthTimer: DispatchSourceTimer?`
- `:278-281` `lastUsefulRxAt`, `lastOutboundDemandAt`, `lastHealthCheckAt`, `lastHealthWatchdogFireAt`
- `:282-284` `sessionSuspectSince`, `probeOutstandingSince`, `lastProbeResponseAt`
- `:285-286` `consecutiveNoProgressChecks`, `consecutiveStuckHighSeqTicks`
- `:287-288` `lastHighSeqSeen`, `priorHighSeqSnapshot`
- `:289` `lastReplayRejectCount`
- `:290-292` `lastRouterFlows`, `lastRouterOutbound`, `lastRouterStreamMappings`
- `:293` `lastHealthHeartbeatAt`
- `:294` `healthProbeNonce`
- `:295` `pendingReconnectReason`

Total state vars/tunables to delete: **51**.

---

## KEEP

These functions and subsystems stay. They become the dumb-pipe core.

### Lifecycle (PacketTunnelProvider.swift)
- `override func startTunnel(options:completionHandler:)` @ `:669` — identity load, relay discovery, NWConnection construction, handshake orchestration, utun fd handoff.
- `override func stopTunnel(with:completionHandler:)` @ `:983` — after trimming the ackFlushTimer/healthTimer/rustMux/rustHealth cleanup.
- `override func handleAppMessage(_:completionHandler:)` @ `:1079` — IPC with the app.
- `scheduleReconnect()` / `scheduleReconnect(reason:)` @ `:1846-1850` — KEEP as the Apple-path-loss recovery path. Only wired to `didFailWithError` (`:2271-2276`) after the pivot.
- Identity / relay / cleanupTimer paths (`:1710 startCleanupTimer`, `discoverRelays` etc.) — unrelated to reliability.

### utun fd + Rust engine handoff
- `iosTunnelEngine` property + `useRustFdDataPlane` gate (`:157-161`) — Rust owns the fd post-pivot, exactly like mobile_nebula. This stays.
- `actionBuffer` / `readPacketBuffer` — still needed as long as Swift is involved in the data plane at all; likely shrink or remove during the pivot but not reliability-coupled.

### Handshake (ZTLPTunnelConnection.swift)
- `performHandshake(identity:config:target:timeoutMs:completion:)` @ `:222` — Noise FFI orchestration. KEEP.
- `receiveOnce(timeout:completion:)` @ `:191` — single-shot datagram receive used only by handshake. KEEP.
- `start(queue:)` (implied, called @ `:364`) and `stop()` @ `:368` — NE lifecycle for the UDP socket, with the ACK-flush and seenSequences cleanup lines removed.

### Crypto send path
- `sendData(_:)` @ `:391` — SIMPLIFY (drop nextSendSequence + onDataFrameSent, but keep frame-and-encrypt).
- `sendRaw(_:)` @ `:567` — already dumb; KEEP as-is.
- `sendEncryptedFrame(plaintext:cryptoContext:conn:)` helper — KEEP.
- Inbound PING/PONG handling (`:743-770`) — KEEP the PING→PONG echo (harmless, useful as a liveness probe for apps that want it). Drop the PONG handler's probe-response delegate call post-pivot if session health is gone; purely optional.

### Decrypt + deliver path
- `handleReceivedPacket(_:)` @ `:671` — KEEP, but collapse FRAME_DATA parsing to "decrypt, check type, deliver payload to delegate." See pseudocode.
- `ZTLPTunnelConnectionDelegate.tunnelConnection(_:didReceiveData:)` on PacketTunnelProvider @ `:2263` — SIMPLIFY (drop sequence arg, drop markUsefulRx).

### NWConnection lifecycle + Apple-level reconnect
- NWConnection stateUpdateHandler and `didFailWithError` bridging (`:2271-2276`) — KEEP. This is Apple path loss, not session_health; it's a legit reason to rebuild the socket.
- Reconnect exponential backoff state (`reconnectAttempt`, `reconnectScheduled`, `reconnectInProgress`, `reconnectGeneration`, `maxReconnectAttempts`, `baseReconnectDelay`, `maxReconnectDelay`) @ `:116-132` — KEEP (different from session-health state).

### Logging bridge
- `TunnelLogger.shared` (`:104`) and all `logger.info/debug/warn/error` call sites — KEEP. Remove only the reliability-specific log lines that reference deleted state.

### Crypto counters worth keeping
- `bytesSent`, `bytesReceived`, `packetsReceived`, `packetsSent`, `replayRejectedCount` — KEEP (operational metrics, not reliability-layer state).

---

## POST-PIVOT DATA FLOW

Pseudocode for the collapsed `handleReceivedPacket` / `handleDataFrame` replacement:

```
handleIncomingPacket(wireData):
  plaintext = ztlp_decrypt_packet(crypto, wireData)
  if plaintext == REPLAY_REJECTED:
    replayRejectedCount += 1
    return
  if plaintext fails:
    log decrypt error; return
  if plaintext.len < 1: return

  frameType = plaintext[0]
  switch frameType:
    case DATA (0x00):
      # no data_seq extraction, no dup check, no ACK
      payload = plaintext[1..]              # or [5..] if mux stream_id prefix kept
      delegate.didReceiveData(payload)      # straight to PTP → gateway mux demux
    case PING (0x02):
      echo PONG(nonce) back                  # optional, cheap liveness
    case OPEN / CLOSE / mux control:
      route to mux dispatch as today
    default:
      drop silently
  # no queueAck, no seenSequences, no recordSequence, no RTT observe, no rwnd update
```

Parallel send-side sketch for `sendData`:

```
sendData(payload):
  frame = ztlp_frame_data(payload)          # seq arg becomes 0 or FFI drops it
  wire  = ztlp_encrypt_packet(crypto, frame)
  nwConnection.send(wire)
  # no nextSendSequence, no onDataFrameSent, no shadow-inflight
```

---

## Summary

Printed to stdout by this audit:

- Total callsites-to-delete-or-simplify: **34**
- Total state-vars-to-delete: **51**
- Estimated Swift LOC removed:
  - ZTLPTunnelConnection.swift: ~150 LOC (state ~25 + ACK/rwnd/dup-detect/handleDataFrame/recordSequence/flushPendingAcks/delegate-ack plumbing ~125)
  - PacketTunnelProvider.swift: ~750 LOC (state + constants ~60; evaluateSessionHealth+helpers 467-652 = 185; maybeRampAdvertisedRwnd+updateAdvertisedRwnd+reduceAdvertisedRwnd 1587-1689 ≈ 103; wireRttInstrumentationHook+maybeLogRttSnapshot 2291-2373 ≈ 83; handleHealthWatchdogTick+sendSessionProbe+handleProbeSuccess+resetPacketRouterRuntimeState 393-465 ≈ 73; timer scaffolding + delegate ack + probe delegate + constants block 160-198 ≈ 40; callsite removals scattered ≈ 30; log/stat lines ≈ 20; comment blocks ≈ 150)
  - **Total ≈ 900 Swift LOC removed** out of 3348 (~27% of the two files).
