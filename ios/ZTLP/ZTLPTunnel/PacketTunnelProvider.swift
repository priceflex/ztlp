// PacketTunnelProvider.swift
// ZTLPTunnel (Network Extension)
//
// Session 5D: RELAY-SIDE VIP ARCHITECTURE.
// Uses sync FFI (ztlp_connect_sync, ztlp_encrypt_packet, etc.) and
// standalone PacketRouter — no tokio runtime, no VIP proxy listeners.
//
// Architecture:
//   Identity + Config -> ztlp_connect_sync() -> ZtlpCryptoContext
//   ZTLPTunnelConnection (NWConnection UDP) handles encrypt/decrypt via context
//   Standalone PacketRouter (ztlp_router_*_sync) handles utun <-> ZTLP routing
//   RelayPool FFI -> query NS for RELAY records -> select best relay
//   VIP traffic: packetFlow.writePackets() -> encrypted tunnel -> relay
//
// Memory: TEXT segment ~1.65 MB. NO NWListeners — ~10-13 MB total.

import NetworkExtension
import Network
import Foundation
import Darwin

/// App Group identifier shared between the main app and this extension.
private let appGroupId = "group.com.ztlp.shared"

/// UDP port used for relay communication.
private let defaultRelayPort: UInt16 = 4433

/// NS record type for RELAY records.
private let NS_RECORD_TYPE_RELAY: UInt8 = 3

private func rustRouterActionCallback(
    userData: UnsafeMutableRawPointer?,
    actionType: UInt8,
    streamID: UInt32,
    data: UnsafePointer<UInt8>?,
    dataLen: Int
) {
    guard let userData else { return }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(userData).takeUnretainedValue()
    let payload: [UInt8]
    if let data, dataLen > 0 {
        payload = Array(UnsafeBufferPointer(start: data, count: dataLen))
    } else {
        payload = []
    }
    if actionType == 250 {
        if let message = String(bytes: payload, encoding: .utf8) {
            provider.handleRustFdIngressDiagnostic(message)
        }
        return
    }
    if actionType == 251 {
        if let message = String(bytes: payload, encoding: .utf8) {
            provider.handleRustFdOutboundDiagnostic(message)
        }
        return
    }
    provider.handleRustRouterAction(actionType: actionType, streamID: streamID, payload: payload)
}

/// UserDefaults keys for shared state.
private enum SharedKey {
    static let connectionState = "ztlp_connection_state"
    static let connectedSince = "ztlp_connected_since"
    static let bytesSent = "ztlp_bytes_sent"
    static let bytesReceived = "ztlp_bytes_received"
    static let peerAddress = "ztlp_peer_address"
    static let lastError = "ztlp_last_error"
    static let selectedRelay = "ztlp_selected_relay"
    static let neMemoryMB = "ztlp_ne_memory_mb"
    static let neVirtualMB = "ztlp_ne_virtual_mb"
    static let replayRejectCount = "ztlp_replay_reject_count"
}

/// Messages the main app can send to the extension.
enum AppToTunnelMessage: UInt8 {
    case getStatus = 1
    case getStats = 2
    case resetCounters = 3
}

/// Connection state values written to shared UserDefaults.
enum TunnelConnectionState: Int {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case reconnecting = 3
    case disconnecting = 4
}

class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Properties

    /// Serial queue for ZTLP operations.
    private let tunnelQueue = DispatchQueue(label: "com.ztlp.tunnel.queue", qos: .userInitiated)

    /// Shared UserDefaults for communicating state to the main app.
    private lazy var sharedDefaults: UserDefaults? = {
        UserDefaults(suiteName: appGroupId)
    }()

    /// Shared logger (writes to app group container).
    private let logger = TunnelLogger.shared

    /// Connection start time (for duration display).
    private var connectedSince: Date?

    /// Whether we're currently in a tunnel session.
    private var isTunnelActive = false

    /// The tunnel configuration (cached for reconnects).
    private var currentConfig: TunnelConfiguration?

    /// Current reconnect attempt counter.
    private var reconnectAttempt = 0

    /// Reconnect scheduling state. NWConnection can report one socket failure
    /// through both stateUpdateHandler and receiveMessage; keep reconnects
    /// idempotent so a single failure cannot consume multiple attempts.
    private var reconnectScheduled = false
    private var reconnectInProgress = false
    private var reconnectGeneration = 0

    /// Maximum reconnect attempts before giving up.
    private static let maxReconnectAttempts = 10

    /// Base reconnect delay in seconds (exponential backoff).
    private static let baseReconnectDelay: TimeInterval = 1.0

    /// Maximum reconnect delay cap.
    private static let maxReconnectDelay: TimeInterval = 60.0

    // MARK: - Sync Architecture (no tokio)

    /// Identity handle — persists across reconnects.
    private var identity: OpaquePointer?  // ZtlpIdentity*

    /// The NWConnection-based tunnel connection (replaces tokio recv/send loop).
    private var tunnelConnection: ZTLPTunnelConnection?

    /// Relay pool for relay-side VIP selection and failover.
    private var relayPool: OpaquePointer?  // ZtlpRelayPool*

    /// Currently selected relay address ("host:port").
    private var currentRelayAddress: String?

    /// The address of the relay we're currently connected through.
    private var activeRelayAddress: String?

    /// Standalone packet router handle (replaces ZtlpClient-based router).
    private var packetRouter: OpaquePointer?  // ZtlpPacketRouter*

    /// Future Nebula-style Rust owner for the utun fd. In this Phase 2 smoke
    /// test the Rust engine is lifecycle-only: it stores the fd but does not
    /// read/write it, so Swift packetFlow remains the sole data-plane owner.
    private var iosTunnelEngine: OpaquePointer?  // ZtlpIosTunnelEngine*
    private static let enableRustIosTunnelEngineLifecycleSmokeTest = true
    /// Phase 2 fd-owner smoke test. When true, Swift does NOT call packetFlow.readPackets;
    /// Rust owns the utun fd and logs/drops packet metadata only.
    private static let useRustFdDataPlane = true

    // MARK: - Nebula collapse cutover (Phase 2.7 + 3.3)
    //
    // When useRustMux is true, the advertised-rwnd policy is computed by the
    // Rust MuxEngine (proto::mux) instead of Swift's maybeRampAdvertisedRwnd.
    // This gives the Vaultwarden hold=12 fix on device without swapping the
    // full mux implementation — send buffer, retransmit, and codec remain in
    // Swift for this cutover.
    //
    // When useRustHealth is true, the session-health state machine is the
    // Rust SessionHealth (proto::session_health) instead of the Swift
    // suspect/probe/dead logic. PONG deliveries drive on_pong; successful
    // reconnects drive reset_after_reconnect.
    private static let useRustMux = true
    private static let useRustHealth = true

    /// Phase A of "modern flow control" — purely passive instrumentation.
    /// When true, the NE feeds the Rust MuxEngine's shadow RTT/goodput
    /// observation path (`ztlp_mux_observe_sent` /
    /// `ztlp_mux_observe_ack_cumulative`) and logs the resulting
    /// smoothed_rtt_ms / goodput_bps / bdp_kb every health tick. No wire
    /// change, no behaviour change — just numbers to drive Phase B+.
    private static let useRttInstrumentation = true
    /// Last time we logged an RTT/BDP snapshot. Throttled to ~2s.
    private var lastRttLogAt: Date = .distantPast

    /// Phase B of "modern flow control" — FRAME_ACK_V2 (byte-unit KB
    /// receive window). When true, `ZTLPTunnelConnection` emits 0x10
    /// FRAME_ACK_V2 frames instead of 0x01 FRAME_ACK. Requires the
    /// matching gateway deploy (session.ex handles @frame_ack_v2).
    /// Default true — we cut over both sides together.
    private static let useByteRwnd = true
    private var rustMux: OpaquePointer?      // ZtlpMuxEngine*
    private var rustHealth: OpaquePointer?   // ZtlpSessionHealth*
    /// Scratch buffer for ztlp_health_tick's out_reason. 32 bytes is what
    /// the Rust side documents as the recommended minimum.
    private var rustHealthReasonBuffer = [CChar](repeating: 0, count: 32)

    /// DNS responder for *.ztlp queries (answers directly on utun, no tokio).
    private var dnsResponder: ZTLPDNSResponder?

    /// Keepalive timer.
    private var keepaliveTimer: DispatchSourceTimer?

    /// Periodic timer to flush outbound packets from the router.
    private var writePacketTimer: DispatchSourceTimer?

    /// Periodic cleanup timer for stale TCP flows (reclaims memory).
    private static let cleanupInterval: TimeInterval = 10.0
    private var cleanupTimer: DispatchSourceTimer?

    /// ACK flush timer (10ms for low-latency ACKs).
    private var ackFlushTimer: DispatchSourceTimer?

    /// Rate-limit diagnostic work and shared-defaults churn while idle.
    private var lastMemoryDiagnosticsAt: Date = .distantPast
    private var lastStoredResidentMemoryMB: Int?
    private var lastStoredVirtualMemoryMB: Int?
    private var lastAvailableMemoryWarningAt: Date = .distantPast
    private static let memoryDiagnosticsInterval: TimeInterval = 60.0

    /// Action buffer for router write results (reusable, 64KB).
    /// Previous value 256KB was excessive — max mux payload is 1135 bytes
    /// per action with 64 actions/cycle = ~73KB theoretical max, so 64KB
    /// covers the common case and overflows gracefully at the action count limit.
    private var actionBuffer = [UInt8](repeating: 0, count: 65536)

    // MARK: - Mux Frame Constants
    private static let MUX_FRAME_DATA: UInt8 = 0x00
    private static let MUX_FRAME_OPEN: UInt8 = 0x06
    private static let MUX_FRAME_CLOSE: UInt8 = 0x05
    private static let MAX_MUX_PAYLOAD: Int = 1135  // 1140 - 5 byte mux header
    private static let maxRouterActionsPerCycle: Int = 64
    private static let maxPacketsPerReadCycle: Int = 32
    private static let maxOutboundPacketsPerFlush: Int = 64
    private static let browserModeMaxOutboundPacketsPerFlush: Int = 32

    /// Adaptive advertised receive window. rwnd=4 remains the recovery floor,
    /// but the Rust-fd path can safely test a larger browser burst window.
    private static let rwndFloor: UInt16 = 4
    private static let rwndAdaptiveMax: UInt16 = 16
    private static let rwndBrowserBurstTarget: UInt16 = 16
    private static let rwndHealthyTicksToIncrease = 3
    private static let rwndReplayDeltaBad = 2
    private static let rwndReplayDeltaReconnect = 8
    private static let rwndPressureCooldown: TimeInterval = 15.0
    private static let rwndRouterOutboundBad = 128
    private static let rwndSendBufBytesBad = 16_384
    private static let rwndOldestMsBad = 4_000
    /// Browser/WKWebView bursts fan out multiple streams. With Rust-fd enabled,
    /// test a larger rwnd=16 burst now that DNS and CloseStream cleanup are in
    /// Rust and gateway queues remain shallow.
    private static let rwndBrowserBurstFlowThreshold = 2
    private var advertisedRwnd: UInt16 = 4
    private var consecutiveFullFlushes = 0
    private var consecutiveRwndHealthyTicks = 0
    private var lastRwndLogAt: Date = .distantPast
    private var rwndPressureUntil: Date = .distantPast

    /// Cached service map so the packet router can be rebuilt/reset during health recovery.
    private var configuredServices: [(vip: String, name: String)] = []

    /// Session-health tracking for browser-burst recovery.
    /// Detector needs to fire BEFORE the gateway stall-timeout (30s) tears the session down.
    private static let healthCheckInterval: TimeInterval = 2.0
    private static let healthSuspectThreshold: TimeInterval = 5.0
    private static let probeTimeoutThreshold: TimeInterval = 5.0
    private static let fastStuckOldestMsThreshold = 3_000
    private static let fastStuckTicksBeforeSuspect = 2
    /// Number of consecutive ticks with active flows and no highSeq progress before
    /// we treat the session as suspect (independent of usefulRxAge), to catch the
    /// "alive but stuck" replay-storm pattern where RX still arrives but nothing advances.
    private static let noProgressTicksBeforeSuspect = 3
    private static let healthLateThreshold: TimeInterval = 4.0
    private let healthQueue = DispatchQueue(label: "com.ztlp.tunnel.health", qos: .utility)
    private var healthTimer: DispatchSourceTimer?
    private var lastUsefulRxAt: Date = .distantPast
    private var lastOutboundDemandAt: Date = .distantPast
    private var lastHealthCheckAt: Date = .distantPast
    private var lastHealthWatchdogFireAt: Date = .distantPast
    private var sessionSuspectSince: Date?
    private var probeOutstandingSince: Date?
    private var lastProbeResponseAt: Date = .distantPast
    private var consecutiveNoProgressChecks = 0
    private var consecutiveStuckHighSeqTicks = 0
    private var lastHighSeqSeen: UInt64 = 0
    private var priorHighSeqSnapshot: UInt64 = 0
    private var lastReplayRejectCount = 0
    private var lastRouterFlows = 0
    private var lastRouterOutbound = 0
    private var lastRouterStreamMappings = 0
    private var lastHealthHeartbeatAt: Date = .distantPast
    private var healthProbeNonce: UInt64 = 0
    private var pendingReconnectReason: String?

    /// Aggregate mux/router hot-path diagnostics instead of logging per packet.
    private var muxSummaryLastLogAt: Date = .distantPast
    private var muxSummaryDataFrames = 0
    private var muxSummaryDataBytes = 0
    private var muxSummaryOpen = 0
    private var muxSummaryClose = 0
    private var muxSummarySendData = 0
    private var muxSummarySendBytes = 0
    private var rustActionCallbackOpen = 0
    private var rustActionCallbackSend = 0
    private var rustActionCallbackClose = 0
    private var rustActionCallbackUnknown = 0
    private var rustActionCallbackBytes = 0
    private var rustActionCallbackLastLogAt = Date.distantPast
    private var rustFdIngressDiagCount = 0
    private var rustFdIngressDiagLastLogAt = Date.distantPast
    private var rustFdOutboundDiagCount = 0
    private var rustFdOutboundDiagLastLogAt = Date.distantPast

    /// Packet read buffer (reusable, MTU-sized).
    private var readPacketBuffer = [UInt8](repeating: 0, count: 2048)

    // MARK: - Activity Tracking

    private var lastDataActivity: Date = Date()
    private static let activityGracePeriod: TimeInterval = 60.0
    private var consecutiveKeepaliveFailures = 0
    private static let keepaliveFailureThreshold = 3

    private func markDataActivity() {
        lastDataActivity = Date()
        consecutiveKeepaliveFailures = 0
    }

    private func markOutboundDemand() {
        lastOutboundDemandAt = Date()
        if Self.useRustMux, let mux = rustMux {
            _ = ztlp_mux_mark_outbound_demand(mux)
        }
    }

    private func markUsefulRx(sequence: UInt64, payloadLength: Int) {
        guard payloadLength > 0 else { return }
        if sequence > lastHighSeqSeen {
            lastHighSeqSeen = sequence
            lastUsefulRxAt = Date()
        }
    }

    private func refreshReplayRejectBaseline() {
        let replayRejectCount = sharedDefaults?.integer(forKey: "ztlp_replay_reject_count") ?? 0
        lastReplayRejectCount = replayRejectCount
    }

    private func clearSessionHealthState() {
        sessionSuspectSince = nil
        probeOutstandingSince = nil
        consecutiveNoProgressChecks = 0
        consecutiveStuckHighSeqTicks = 0
    }

    private struct RouterStatsSnapshot {
        let flows: Int
        let outbound: Int
        let streamToFlow: Int
        let sendBufBytes: Int
        let sendBufFlows: Int
        let oldestMs: Int
        let stale: Int
        let stats: String
    }

    private func parseRouterStats() -> RouterStatsSnapshot? {
        guard let router = packetRouter, let statsPtr = ztlp_router_stats(router) else { return nil }
        let stats = String(cString: statsPtr)
        ztlp_free_string(statsPtr)

        var values: [String: Int] = [:]
        for token in stats.split(separator: " ") {
            let parts = token.split(separator: "=", maxSplits: 1)
            guard parts.count == 2, let value = Int(parts[1]) else { continue }
            values[String(parts[0])] = value
        }

        return RouterStatsSnapshot(
            flows: values["flows"] ?? 0,
            outbound: values["outbound"] ?? 0,
            streamToFlow: values["stream_to_flow"] ?? 0,
            sendBufBytes: values["send_buf_bytes"] ?? 0,
            sendBufFlows: values["send_buf_flows"] ?? 0,
            oldestMs: values["oldest_ms"] ?? 0,
            stale: values["stale"] ?? 0,
            stats: stats
        )
    }

    private func startHealthTimer() {
        healthTimer?.cancel()
        lastHealthWatchdogFireAt = .distantPast
        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(deadline: .now() + Self.healthCheckInterval, repeating: Self.healthCheckInterval)
        timer.setEventHandler { [weak self] in
            self?.handleHealthWatchdogTick()
        }
        timer.resume()
        healthTimer = timer
        logger.info("Session health manager enabled interval=\(Self.healthCheckInterval)s suspectRx=\(Self.healthSuspectThreshold)s probeTimeout=\(Self.probeTimeoutThreshold)s stuckTicks=\(Self.noProgressTicksBeforeSuspect) queue=healthQueue", source: "Tunnel")
    }

    private func handleHealthWatchdogTick() {
        let now = Date()
        let delay = now.timeIntervalSince(lastHealthWatchdogFireAt)
        if lastHealthWatchdogFireAt != .distantPast && delay > Self.healthLateThreshold {
            logger.warn("Health watchdog late delay=\(String(format: "%.1f", delay))s", source: "Tunnel")
        }
        lastHealthWatchdogFireAt = now

        let scheduledAt = Date()
        tunnelQueue.async { [weak self] in
            guard let self = self else { return }
            let queueDelay = Date().timeIntervalSince(scheduledAt)
            if queueDelay > Self.healthLateThreshold {
                self.logger.warn("Health eval delayed on tunnelQueue delay=\(String(format: "%.1f", queueDelay))s", source: "Tunnel")
            }
            self.evaluateSessionHealth()
        }
    }

    private func sendSessionProbe(reason: String) {
        let nonce = UInt64(Date().timeIntervalSince1970 * 1000)
        healthProbeNonce = nonce
        guard tunnelConnection?.sendProbe(nonce: nonce) == true else {
            logger.warn("Session health probe send failed nonce=\(nonce) reason=\(reason)", source: "Tunnel")
            return
        }
        probeOutstandingSince = Date()
        logger.warn("Session health suspect: reason=\(reason) activeFlows=\(lastRouterFlows) streamMaps=\(lastRouterStreamMappings) highSeq=\(lastHighSeqSeen) stuckTicks=\(consecutiveStuckHighSeqTicks) noUsefulRxFor=\(String(format: "%.1f", Date().timeIntervalSince(lastUsefulRxAt)))s sending probe nonce=\(nonce)", source: "Tunnel")
    }

    private func handleProbeSuccess(nonce: UInt64) {
        lastProbeResponseAt = Date()
        let statsTuple = parseRouterStats()
        let statsString = statsTuple?.stats ?? "unknown"
        if let router = packetRouter {
            let removed = ztlp_router_cleanup_stale_flows(router)
            logger.info("Session health probe ok nonce=\(nonce) cleanup_removed=\(removed) stats=\(statsString)", source: "Tunnel")
            if removed <= 0 && (statsTuple?.flows ?? 0) > 0 {
                // Probe success proves the gateway session is alive. Do NOT reset the
                // local router or reconnect here: resetting without a gateway session
                // reset reuses stream IDs, and reconnect from this callback can block
                // tunnelQueue long enough to wedge benchmarks/WKWebView. Leave the
                // live session intact and let normal TCP/browser retry or the true
                // probe-timeout path handle dead sessions.
                reduceAdvertisedRwnd(reason: "probe ok suspect flows; hold session stats=\(statsString)")
                logger.warn("Session health probe ok but flows still suspect; preserving live session stats=\(statsString) no_router_reset no_reconnect", source: "Tunnel")
                clearSessionHealthState()
                return
            }
        }
        clearSessionHealthState()
        flushOutboundPackets(maxPackets: currentOutboundFlushLimit())
    }

    private func resetPacketRouterRuntimeState(reason: String) {
        guard let router = packetRouter else { return }
        let removed = ztlp_router_reset_runtime_state(router)
        logger.warn("Router reset runtime state removed=\(removed) reason=\(reason)", source: "Tunnel")
        clearSessionHealthState()
    }

    private func evaluateSessionHealth() {
        guard isTunnelActive else { return }
        lastHealthCheckAt = Date()
        guard let statsTuple = parseRouterStats() else { return }

        lastRouterFlows = statsTuple.flows
        lastRouterOutbound = statsTuple.outbound
        lastRouterStreamMappings = statsTuple.streamToFlow

        let now = Date()
        let hasActiveFlows = statsTuple.flows > 0 || statsTuple.streamToFlow > 0
        let outboundRecent = now.timeIntervalSince(lastOutboundDemandAt) < 15
        let usefulRxAge = now.timeIntervalSince(lastUsefulRxAt)
        let replayRejectCount = sharedDefaults?.integer(forKey: "ztlp_replay_reject_count") ?? 0
        let replayDelta = replayRejectCount - lastReplayRejectCount
        lastReplayRejectCount = replayRejectCount

        // Track consecutive ticks where we have active demand but highSeq isn't advancing.
        // We snapshot highSeq via markUsefulRx; it only updates when NEW payload arrives AND
        // the sequence advances. Here we just observe whether it moved since the last tick.
        let currentHighSeqSnapshot = lastHighSeqSeen
        let highSeqAdvanced = currentHighSeqSnapshot > priorHighSeqSnapshot
        priorHighSeqSnapshot = currentHighSeqSnapshot

        if hasActiveFlows && !highSeqAdvanced {
            consecutiveStuckHighSeqTicks += 1
        } else {
            consecutiveStuckHighSeqTicks = 0
        }

        // Phase 2.7: Rust MuxEngine rwnd policy (Vaultwarden hold=12 fix).
        // Falls back to the legacy Swift ramp when useRustMux=false or the
        // handle is somehow missing.
        if Self.useRustMux, let mux = rustMux {
            var rustStats = ZtlpRouterStatsSnapshot(
                flows: UInt32(statsTuple.flows),
                outbound: UInt32(statsTuple.outbound),
                stream_to_flow: UInt32(statsTuple.streamToFlow),
                send_buf_bytes: statsTuple.sendBufBytes,
                oldest_ms: UInt64(statsTuple.oldestMs)
            )
            var signals = ZtlpRwndPressureSignals(
                consecutive_full_flushes: UInt32(consecutiveFullFlushes),
                consecutive_stuck_high_seq_ticks: UInt32(consecutiveStuckHighSeqTicks),
                session_suspect: sessionSuspectSince != nil ? 1 : 0,
                probe_outstanding: probeOutstandingSince != nil ? 1 : 0,
                high_seq_advanced: highSeqAdvanced ? 1 : 0,
                has_active_flows: hasActiveFlows ? 1 : 0
            )
            let rustRwnd = ztlp_mux_tick_rwnd(mux, &rustStats, Int32(replayDelta), &signals)
            if rustRwnd > 0 {
                let clamped = UInt16(min(Int(UInt16.max), max(0, Int(rustRwnd))))
                if clamped != advertisedRwnd {
                    advertisedRwnd = clamped
                    tunnelConnection?.setAdvertisedReceiveWindow(clamped)
                    lastRwndLogAt = now
                    logger.debug("ztlp_mux_tick_rwnd applied rwnd=\(clamped) flows=\(statsTuple.flows) outbound=\(statsTuple.outbound) oldestMs=\(statsTuple.oldestMs) replayDelta=\(replayDelta) suspect=\(signals.session_suspect) probe=\(signals.probe_outstanding)", source: "Tunnel")
                } else if now.timeIntervalSince(lastRwndLogAt) >= 2.0 {
                    lastRwndLogAt = now
                    logger.debug("ztlp_mux_tick_rwnd hold rwnd=\(clamped) flows=\(statsTuple.flows) replayDelta=\(replayDelta)", source: "Tunnel")
                }
                // Phase B: keep the connection's byte-window synced with
                // the Rust engine's view. The set_rwnd path inside the
                // engine updates advertised_window_bytes whenever the V1
                // ladder moves (V1 × 1140 hint) OR when autotune updates
                // it directly in Phase D.
                if Self.useByteRwnd {
                    let kb = ztlp_mux_advertised_window_kb(mux)
                    if kb > 0 {
                        tunnelConnection?.setAdvertisedWindowKb(kb)
                    }
                }
            } else {
                logger.warn("ztlp_mux_tick_rwnd returned \(rustRwnd); falling back to legacy ramp for this tick", source: "Tunnel")
                maybeRampAdvertisedRwnd(stats: statsTuple, replayDelta: replayDelta, highSeqAdvanced: highSeqAdvanced, hasActiveFlows: hasActiveFlows)
            }
        } else {
            maybeRampAdvertisedRwnd(stats: statsTuple, replayDelta: replayDelta, highSeqAdvanced: highSeqAdvanced, hasActiveFlows: hasActiveFlows)
        }

        // Phase A: periodic RTT / goodput / BDP snapshot log.
        maybeLogRttSnapshot()

        // Emit a rate-limited heartbeat so we can always see what the detector sees.
        if now.timeIntervalSince(lastHealthHeartbeatAt) >= 4.0 {
            lastHealthHeartbeatAt = now
            logger.debug("Health eval: flows=\(statsTuple.flows) outbound=\(statsTuple.outbound) streamMaps=\(statsTuple.streamToFlow) sendBuf=\(statsTuple.sendBufBytes) oldestMs=\(statsTuple.oldestMs) rwnd=\(advertisedRwnd) highSeq=\(currentHighSeqSnapshot) stuckTicks=\(consecutiveStuckHighSeqTicks) usefulRxAge=\(String(format: "%.1f", usefulRxAge))s outboundRecent=\(outboundRecent) replayDelta=\(replayDelta) probeOutstanding=\(probeOutstandingSince != nil)", source: "Tunnel")
        }

        // Phase 3.3: Rust SessionHealth state machine.
        if Self.useRustHealth, let health = rustHealth {
            var inputs = ZtlpHealthTickInputs(
                has_active_flows: hasActiveFlows ? 1 : 0,
                useful_rx_age_ms: UInt64(max(0.0, usefulRxAge) * 1000.0),
                oldest_outbound_ms: UInt64(statsTuple.oldestMs),
                consecutive_stuck_high_seq_ticks: UInt32(consecutiveStuckHighSeqTicks)
            )
            var nonce: UInt64 = 0
            // Reset scratch buffer before each tick so a stale reason from a
            // previous RECONNECT action can't leak into a later log line.
            for i in 0..<rustHealthReasonBuffer.count { rustHealthReasonBuffer[i] = 0 }
            let action = rustHealthReasonBuffer.withUnsafeMutableBufferPointer { reasonBuf -> Int32 in
                guard let base = reasonBuf.baseAddress else { return 0 }
                return ztlp_health_tick(health, &inputs, &nonce, base, reasonBuf.count)
            }
            switch action {
            case ZTLP_HEALTH_ACTION_SEND_PROBE:
                healthProbeNonce = nonce
                sessionSuspectSince = sessionSuspectSince ?? now
                consecutiveNoProgressChecks += 1
                if tunnelConnection?.sendProbe(nonce: nonce) == true {
                    probeOutstandingSince = Date()
                    logger.warn("ztlp_health_tick SEND_PROBE nonce=\(nonce) activeFlows=\(lastRouterFlows) highSeq=\(lastHighSeqSeen) stuckTicks=\(consecutiveStuckHighSeqTicks) usefulRxAge=\(String(format: "%.1f", usefulRxAge))s", source: "Tunnel")
                } else {
                    logger.warn("ztlp_health_tick SEND_PROBE failed nonce=\(nonce) (sendProbe returned false)", source: "Tunnel")
                }
            case ZTLP_HEALTH_ACTION_RECONNECT:
                let reason = String(cString: rustHealthReasonBuffer)
                let finalReason = reason.isEmpty ? "session_health_rust" : "session_health_\(reason)"
                logger.warn("ztlp_health_tick RECONNECT reason=\(finalReason) flows=\(statsTuple.flows) streamMaps=\(statsTuple.streamToFlow) usefulRxAge=\(String(format: "%.1f", usefulRxAge))s stuckTicks=\(consecutiveStuckHighSeqTicks) stats=\(statsTuple.stats)", source: "Tunnel")
                resetPacketRouterRuntimeState(reason: finalReason)
                pendingReconnectReason = finalReason
                scheduleReconnect()
            default:
                // No action: the detector considers the session healthy or
                // still observing. Clear suspect markers when appropriate.
                if !hasActiveFlows && !outboundRecent {
                    clearSessionHealthState()
                }
            }
            return
        }

        // Only suspect the session when there is ACTIVE DEMAND (flows open or recent outbound).
        // If there are no active flows AND no recent outbound, there is nothing to worry about,
        // regardless of how long ago we last received something.
        guard hasActiveFlows || outboundRecent else {
            clearSessionHealthState()
            return
        }

        // Two independent paths to "suspect":
        //   1) Active flows AND no useful RX for healthSuspectThreshold — classic "silent
        //      tunnel with pending work" case.
        //   2) Active flows AND highSeq not advancing for noProgressTicksBeforeSuspect
        //      consecutive ticks — "alive but stuck" pattern where RX (retransmits/replay)
        //      is arriving but nothing is making progress.
        //
        // Important: we do NOT probe based solely on "outbound was recent". An idle tunnel
        // with no flows shouldn't burn encrypt/crypto cycles on probes just because some
        // bytes went out a few seconds ago.
        let silentTooLong = hasActiveFlows && usefulRxAge >= Self.healthSuspectThreshold
        let stuckTooLong = hasActiveFlows && consecutiveStuckHighSeqTicks >= Self.noProgressTicksBeforeSuspect
        let fastStuckTooLong = hasActiveFlows &&
            statsTuple.oldestMs >= Self.fastStuckOldestMsThreshold &&
            consecutiveStuckHighSeqTicks >= Self.fastStuckTicksBeforeSuspect
        guard silentTooLong || stuckTooLong || fastStuckTooLong else {
            clearSessionHealthState()
            return
        }

        sessionSuspectSince = sessionSuspectSince ?? now
        consecutiveNoProgressChecks += 1

        if probeOutstandingSince == nil {
            let reason: String
            if silentTooLong {
                reason = "no_useful_rx_\(String(format: "%.1f", usefulRxAge))s"
            } else if fastStuckTooLong {
                reason = "fast_stuck_highseq_\(consecutiveStuckHighSeqTicks)_ticks_oldest_\(statsTuple.oldestMs)ms"
            } else {
                reason = "stuck_highseq_\(consecutiveStuckHighSeqTicks)_ticks"
            }
            logger.warn("Session health candidate: flows=\(statsTuple.flows) outbound=\(statsTuple.outbound) streamMaps=\(statsTuple.streamToFlow) highSeq=\(currentHighSeqSnapshot) noUsefulRxFor=\(String(format: "%.1f", usefulRxAge))s replayDelta=\(replayDelta) stats=\(statsTuple.stats)", source: "Tunnel")
            sendSessionProbe(reason: reason)
            return
        }

        let activeProbeTimeout = fastStuckTooLong ? min(Self.probeTimeoutThreshold, 3.0) : Self.probeTimeoutThreshold
        if let probeOutstandingSince, now.timeIntervalSince(probeOutstandingSince) > activeProbeTimeout {
            logger.warn("Session health dead: probe timeout flows=\(statsTuple.flows) streamMaps=\(statsTuple.streamToFlow) noUsefulRxFor=\(String(format: "%.1f", usefulRxAge))s stuckTicks=\(consecutiveStuckHighSeqTicks) stats=\(statsTuple.stats)", source: "Tunnel")
            resetPacketRouterRuntimeState(reason: "session_health_probe_timeout")
            pendingReconnectReason = "session_health_probe_timeout"
            scheduleReconnect()
        }
    }

    private var isDataActive: Bool {
        return Date().timeIntervalSince(lastDataActivity) < Self.activityGracePeriod
    }

    private func shouldThrottleRouterWork() -> Bool {
        if let tunnelConnection, tunnelConnection.isOverloaded {
            logger.debug("Router throttle: tunnelConnection overloaded, yielding read loop", source: "Tunnel")
            return true
        }

        return false
    }

    // MARK: - NEPacketTunnelProvider Overrides

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        updateConnectionState(.connecting)
        logger.info("═══════════════════════════════════════════", source: "Tunnel")
        logger.info("ZTLP NE v5D — RELAY-SIDE VIP (no NWListeners)", source: "Tunnel")
        logger.info("Build: \(Date())", source: "Tunnel")
        logger.info("═══════════════════════════════════════════", source: "Tunnel")

        tunnelQueue.async { [weak self] in
            guard let self = self else {
                completionHandler(NSError(
                    domain: "com.ztlp.tunnel", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Provider deallocated"]
                ))
                return
            }

            do {
                // Step 1: Read tunnel configuration
                self.logger.info("Loading tunnel config...", source: "Tunnel")
                let config = try self.loadTunnelConfiguration()
                self.currentConfig = config
                self.logger.info(
                    "Config: target=\(config.targetNodeId) relay=\(config.relayAddress ?? "none") ns=\(config.nsServer ?? "none") service=\(config.serviceName ?? "none")",
                    source: "Tunnel"
                )

                // Step 2: Initialize library + identity (sync, no bridge)
                self.logger.info("Initializing ZTLP library...", source: "Tunnel")
                let initResult = ztlp_init()
                if initResult != 0 {
                    throw self.makeNSError("ztlp_init failed: \(self.lastError())")
                }

                let identityPtr = try self.loadOrCreateIdentitySync(config: config)
                self.identity = identityPtr

                let nodeId = ztlp_identity_node_id(identityPtr)
                if let nodeId = nodeId {
                    self.logger.info("Node ID: \(String(cString: nodeId))", source: "Tunnel")
                }

                // Step 3: Build config
                let cfgPtr = ztlp_config_new()
                guard let cfgPtr = cfgPtr else {
                    throw self.makeNSError("ztlp_config_new failed")
                }
                defer { ztlp_config_free(cfgPtr) }

                if let relay = config.relayAddress, !relay.isEmpty {
                    relay.withCString { ztlp_config_set_relay(cfgPtr, $0) }
                    self.logger.debug("Config: relay=\(relay)", source: "Tunnel")
                }

                ztlp_config_set_nat_assist(cfgPtr, true)
                ztlp_config_set_timeout_ms(cfgPtr, 60000)

                let svcName = config.serviceName ?? "vault"
                if !svcName.isEmpty {
                    svcName.withCString { ztlp_config_set_service(cfgPtr, $0) }
                    self.logger.debug("Config: service=\(svcName)", source: "Tunnel")
                }

                // Step 4: Discover relays from NS -> RelayPool, then select best
                self.logger.info("Discovering relays from NS...", source: "Relay")
                self.discoverRelays(config: config)
                guard let relayAddr = self.selectRelay(config: config) else {
                    throw self.makeNSError("No relay available. Cannot establish tunnel.")
                }
                self.currentRelayAddress = relayAddr
                self.logger.info("Relay selected: \(relayAddr)", source: "Relay")

                // Build config with selected relay
                let cfgPtr2 = ztlp_config_new()
                guard let cfgPtr2 = cfgPtr2 else {
                    throw self.makeNSError("ztlp_config_new failed for relay tunnel")
                }
                defer { ztlp_config_free(cfgPtr2) }

                relayAddr.withCString { ztlp_config_set_relay(cfgPtr2, $0) }
                ztlp_config_set_nat_assist(cfgPtr2, true)
                ztlp_config_set_timeout_ms(cfgPtr2, 60000)
                if !svcName.isEmpty {
                    svcName.withCString { ztlp_config_set_service(cfgPtr2, $0) }
                }

                // Step 5: Set client profile for CC selection
                let detectedInterface = self.detectClientInterfaceType()
                ztlp_set_client_profile(detectedInterface, 0, 0)
                self.logger.info("Client profile: mobile interface=\(self.interfaceTypeName(detectedInterface)) (\(detectedInterface))", source: "Tunnel")

                // Step 6: Create tunnel connection first, then do handshake on the same NWConnection
                let target = config.targetNodeId  // gateway identity
                self.logger.info("Connecting to \(target) via relay \(relayAddr) using NWConnection handshake...", source: "Tunnel")

                let conn = ZTLPTunnelConnection(
                    gatewayAddress: relayAddr,
                    queue: self.tunnelQueue
                )
                conn.delegate = self
                conn.start()

                let handshakeSemaphore = DispatchSemaphore(value: 0)
                var handshakeError: Error?
                conn.performHandshake(identity: identityPtr, config: cfgPtr2, target: target, timeoutMs: 20000) { result in
                    switch result {
                    case .success:
                        break
                    case .failure(let error):
                        handshakeError = error
                    }
                    handshakeSemaphore.signal()
                }
                handshakeSemaphore.wait()

                if let handshakeError = handshakeError {
                    conn.stop()
                    // Report this relay as failed
                    if let pool = self.relayPool {
                        relayAddr.withCString { ztlp_relay_pool_report_failure(pool, $0) }
                    }
                    throw self.makeNSError("NWConnection handshake failed: \(handshakeError.localizedDescription)")
                }

                self.logger.info("Connected to \(target) via relay \(relayAddr)", source: "Tunnel")
                self.activeRelayAddress = relayAddr

                // Step 7: Discover services via NS, fall back to hardcoded
                let zone = (config.zoneName ?? "").replacingOccurrences(of: ".ztlp", with: "")
                var services: [(vip: String, name: String)] = []

                // Try NS service discovery (sync UDP query)
                if let nsAddr = config.nsServer, !nsAddr.isEmpty {
                    self.logger.info("Querying NS at \(nsAddr) for services...", source: "Tunnel")
                    let nsClient = ZTLPNSClient(timeoutSec: 3)
                    let discovered = nsClient.discoverServices(
                        zoneName: zone,
                        nsServer: nsAddr
                    )
                    if !discovered.isEmpty {
                        // Assign VIPs dynamically: 10.122.0.2, 10.122.0.3, ...
                        var nextVIP: UInt8 = 2
                        for record in discovered {
                            let shortName = record.name
                                .replacingOccurrences(of: ".\(zone).ztlp", with: "")
                                .replacingOccurrences(of: ".ztlp", with: "")
                            let vip = "10.122.0.\(nextVIP)"
                            services.append((vip, shortName))
                            self.logger.info("NS discovered: \(shortName) -> \(record.address) (VIP \(vip))", source: "Tunnel")
                            nextVIP += 1
                            if nextVIP > 254 { break }
                        }
                    }
                }

                // Fall back to hardcoded services if NS discovery found nothing
                if services.isEmpty {
                    self.logger.info("Using default service map (NS unavailable or empty)", source: "Tunnel")
                    services = [
                        ("10.122.0.2", svcName),
                        ("10.122.0.3", "http"),
                        ("10.122.0.4", "vault"),
                    ]
                }

                self.configuredServices = services
                try self.startPacketRouter(services: services)
                self.lastUsefulRxAt = Date()
                self.lastOutboundDemandAt = Date.distantPast
                self.lastProbeResponseAt = Date.distantPast
                self.lastHighSeqSeen = 0
                self.priorHighSeqSnapshot = 0
                self.clearSessionHealthState()
                self.refreshReplayRejectBaseline()

                // Step 7b: Start DNS responder for *.ztlp queries
                self.dnsResponder = ZTLPDNSResponder(
                    services: services.map { ($0.name, $0.vip) },
                    zoneName: zone
                )
                self.logger.info("DNS responder active (\(services.count) services) for *.\(zone.isEmpty ? "" : zone + ".")ztlp", source: "Tunnel")

                // Step 8: Reuse the handshaken ZTLPTunnelConnection (UDP NWConnection to relay)
                // All traffic (including VIP-proxied services) flows through the relay.
                // VIP traffic goes: packetFlow -> router -> send to tunnelConnection -> relay
                self.logger.info("Tunnel connection ready on relay \(relayAddr) with shared handshake/data socket", source: "Tunnel")
                self.tunnelConnection = conn
                self.wireRttInstrumentationHook(on: conn)

                // VIP traffic is now routed through packetFlow -> encrypted tunnel -> relay
                // (relay-side TCP termination replaces in-extension NWListeners)
                self.logger.info("VIP traffic routes: packetFlow -> tunnel -> relay \(relayAddr)", source: "Tunnel")

                // Report successful relay connection
                if let pool = self.relayPool {
                    relayAddr.withCString { ztlp_relay_pool_report_success(pool, $0, 0) }
                }

                // Step 9: Apply tunnel network settings
                let tunSettings = self.createTunnelNetworkSettings(
                    tunnelRemoteAddress: relayAddr,
                    usePacketRouter: true
                )

                let settingsSemaphore = DispatchSemaphore(value: 0)
                var settingsError: Error?

                self.setTunnelNetworkSettings(tunSettings) { error in
                    settingsError = error
                    settingsSemaphore.signal()
                }

                settingsSemaphore.wait()

                if let err = settingsError {
                    self.logger.error("Failed to apply tunnel settings: \(err.localizedDescription)", source: "Tunnel")
                    throw err
                }

                self.logger.info("Tunnel network settings applied", source: "Tunnel")
                if let fd = self.tunnelFileDescriptor {
                    self.logger.info("utun fd acquired fd=\(fd)", source: "Tunnel")
                    self.startRustIosTunnelEngineLifecycleSmokeTest(fd: fd)
                } else {
                    self.logger.warn("utun fd not found after tunnel settings applied", source: "Tunnel")
                }

                // Step 10: Start timers and finalize
                self.isTunnelActive = true
                self.connectedSince = Date()
                self.reconnectAttempt = 0
                self.consecutiveKeepaliveFailures = 0
                self.lastDataActivity = Date()
                self.advertisedRwnd = Self.rwndFloor
                self.consecutiveRwndHealthyTicks = 0
                self.lastUsefulRxAt = Date()
                self.lastHighSeqSeen = 0
                self.priorHighSeqSnapshot = 0
                self.consecutiveStuckHighSeqTicks = 0
                self.refreshReplayRejectBaseline()
                conn.setAdvertisedReceiveWindow(Self.rwndFloor)

                // Phase 2.7 / 3.3: set up Rust MuxEngine + SessionHealth.
                // Free any stragglers from a prior session (shouldn't happen,
                // but be defensive — reconnect paths may reuse the provider).
                if let stale = self.rustMux {
                    ztlp_mux_free(stale)
                    self.rustMux = nil
                }
                if let stale = self.rustHealth {
                    ztlp_health_free(stale)
                    self.rustHealth = nil
                }
                if Self.useRustMux {
                    if let mux = ztlp_mux_new() {
                        self.rustMux = mux
                        self.logger.info("Rust MuxEngine ready (useRustMux=true)", source: "Tunnel")
                        // Re-run the Rtt/Rwnd instrumentation hook now that
                        // `rustMux` exists. The earlier call at step 8
                        // (line ~858) runs before the MuxEngine is created
                        // so its `ztlp_mux_note_peer_sent_v2(mux)` branch
                        // is silently skipped — that's the Phase B "v2=no
                        // stuck" bug surfaced by Phase D logs. Second call
                        // is idempotent on the connection side and makes
                        // the engine's peer_speaks_v2 flag true before the
                        // first tick_rwnd, so autotune engages from tick 1.
                        self.wireRttInstrumentationHook(on: conn)
                    } else {
                        self.logger.warn("ztlp_mux_new returned null; falling back to legacy rwnd ramp", source: "Tunnel")
                    }
                }
                if Self.useRustHealth {
                    if let health = ztlp_health_new() {
                        self.rustHealth = health
                        _ = ztlp_health_reset_after_reconnect(health)
                        self.logger.info("Rust SessionHealth ready (useRustHealth=true)", source: "Tunnel")
                    } else {
                        self.logger.warn("ztlp_health_new returned null; falling back to legacy Swift health", source: "Tunnel")
                    }
                }
                self.startKeepaliveTimer()
                self.startCleanupTimer()
                self.startHealthTimer()
                self.logger.info("Idle quiesce: packet/ACK timers disabled; using demand-driven flush", source: "Tunnel")

                // Update shared state
                self.updateConnectionState(.connected)
                self.sharedDefaults?.set(
                    Date().timeIntervalSince1970,
                    forKey: SharedKey.connectedSince
                )
                self.sharedDefaults?.set(target, forKey: SharedKey.peerAddress)

                self.logger.info("═══════════════════════════════════════════", source: "Tunnel")
                self.logger.info("TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)", source: "Tunnel")
                self.logger.info("TEXT seg: 1.65MB | Crypto: sync FFI", source: "Tunnel")
                self.logger.info("Router: standalone | VIP: relay-terminated", source: "Tunnel")
                self.logger.info("═══════════════════════════════════════════", source: "Tunnel")
                completionHandler(nil)

            } catch {
                self.logger.error("startTunnel failed: \(error.localizedDescription)", source: "Tunnel")
                self.updateConnectionState(.disconnected)
                self.sharedDefaults?.set(
                    error.localizedDescription,
                    forKey: SharedKey.lastError
                )
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.info("Stopping tunnel (reason: \(reason.rawValue))", source: "Tunnel")
        updateConnectionState(.disconnecting)

        tunnelQueue.async { [weak self] in
            guard let self = self else {
                completionHandler()
                return
            }

            self.isTunnelActive = false

            // Stop timers
            self.keepaliveTimer?.cancel()
            self.keepaliveTimer = nil
            self.stopWritePacketTimer()
            self.ackFlushTimer?.cancel()
            self.ackFlushTimer = nil
            self.cleanupTimer?.cancel()
            self.cleanupTimer = nil
            self.healthTimer?.cancel()
            self.healthTimer = nil

            // Free Nebula-collapse Rust handles (Phase 2.7 / 3.3).
            if let mux = self.rustMux {
                ztlp_mux_free(mux)
                self.rustMux = nil
                self.logger.info("Rust MuxEngine freed", source: "Tunnel")
            }
            if let health = self.rustHealth {
                ztlp_health_free(health)
                self.rustHealth = nil
                self.logger.info("Rust SessionHealth freed", source: "Tunnel")
            }

            // Stop DNS responder
            self.dnsResponder = nil
            self.logger.info("DNS responder stopped", source: "Tunnel")

            // Stop future fd-backed Rust engine if Phase 2 starts it.
            if let engine = self.iosTunnelEngine {
                _ = ztlp_ios_tunnel_engine_stop(engine)
                ztlp_ios_tunnel_engine_free(engine)
                self.iosTunnelEngine = nil
                self.logger.info("Rust iOS tunnel engine stopped", source: "Tunnel")
            }

            // Stop packet router
            if let router = self.packetRouter {
                ztlp_router_stop_sync(router)
                self.packetRouter = nil
                self.logger.info("Packet router stopped", source: "Tunnel")
            }

            // Stop tunnel connection (frees crypto context)
            self.tunnelConnection?.stop()
            self.tunnelConnection = nil
            self.logger.info("Tunnel connection stopped", source: "Tunnel")

            // Free identity
            if let id = self.identity {
                ztlp_identity_free(id)
                self.identity = nil
            }

            // Shut down library
            ztlp_shutdown()

            // Update shared state
            self.updateConnectionState(.disconnected)
            self.connectedSince = nil
            self.currentRelayAddress = nil
            self.activeRelayAddress = nil
            self.currentConfig = nil

            // Free relay pool
            if let pool = self.relayPool {
                ztlp_relay_pool_free(pool)
                self.relayPool = nil
            }

            self.sharedDefaults?.removeObject(forKey: SharedKey.connectedSince)
            self.sharedDefaults?.removeObject(forKey: SharedKey.peerAddress)
            self.sharedDefaults?.removeObject(forKey: SharedKey.lastError)
            self.sharedDefaults?.removeObject(forKey: SharedKey.selectedRelay)
            self.sharedDefaults?.removeObject(forKey: SharedKey.neMemoryMB)
            self.sharedDefaults?.removeObject(forKey: SharedKey.neVirtualMB)
            self.logger.info("Tunnel stopped", source: "Tunnel")

            completionHandler()
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let firstByte = messageData.first,
              let messageType = AppToTunnelMessage(rawValue: firstByte) else {
            completionHandler?(nil)
            return
        }

        switch messageType {
        case .getStatus:
            let status: [String: Any] = [
                "connected": isTunnelActive,
                "connectedSince": connectedSince?.timeIntervalSince1970 ?? 0,
                "bytesSent": tunnelConnection?.bytesSent ?? 0,
                "bytesReceived": tunnelConnection?.bytesReceived ?? 0
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))

        case .getStats:
            let stats: [String: Any] = [
                "bytesSent": tunnelConnection?.bytesSent ?? 0,
                "bytesReceived": tunnelConnection?.bytesReceived ?? 0,
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: stats))

        case .resetCounters:
            tunnelConnection?.resetCounters()
            sharedDefaults?.set(0, forKey: SharedKey.bytesSent)
            sharedDefaults?.set(0, forKey: SharedKey.bytesReceived)
            completionHandler?(Data([1]))
        }
    }

    // MARK: - Identity (sync, no bridge)

    private func loadOrCreateIdentitySync(config: TunnelConfiguration) throws -> OpaquePointer {
        let identityPath = config.identityPath ?? defaultIdentityPath()

        // Try loading saved identity first (has node ID from previous session)
        if let path = identityPath, FileManager.default.fileExists(atPath: path) {
            let ptr = path.withCString { ztlp_identity_from_file($0) }
            if let ptr = ptr {
                logger.info("Loaded existing identity from \(path)", source: "Tunnel")
                return ptr
            }
            logger.warn("Failed to load identity from \(path): \(lastError())", source: "Tunnel")
        }

        // Generate software identity (has node ID immediately).
        // NOTE: Secure Enclave identity skipped — ztlp_connect_sync requires
        // a node identity (node ID) which hardware keys don't have until
        // enrollment via ztlp_client_new. Software identity works directly.
        guard let swPtr = ztlp_identity_generate() else {
            throw makeNSError("Failed to generate identity: \(lastError())")
        }

        // Save so we reuse the same node ID on reconnects
        if let path = identityPath {
            let dirPath = (path as NSString).deletingLastPathComponent
            try? FileManager.default.createDirectory(atPath: dirPath, withIntermediateDirectories: true)
            path.withCString { ztlp_identity_save(swPtr, $0) }
            logger.info("Saved new identity to \(path)", source: "Tunnel")
        }

        let nodeId = ztlp_identity_node_id(swPtr)
        let nodeIdStr = nodeId != nil ? String(cString: nodeId!) : "unknown"
        logger.info("Generated software identity: \(nodeIdStr)", source: "Tunnel")
        return swPtr
    }

    // MARK: - Packet Router (standalone sync FFI)

    private func startPacketRouter(services: [(vip: String, name: String)]) throws {
        let router = "10.122.0.1".withCString { ztlp_router_new_sync($0) }
        guard let router = router else {
            throw makeNSError("ztlp_router_new_sync failed: \(lastError())")
        }
        self.packetRouter = router
        logger.info("Packet router initialized (tunnel=10.122.0.1)", source: "Tunnel")

        for svc in services {
            let result = svc.vip.withCString { vipCStr in
                svc.name.withCString { nameCStr in
                    ztlp_router_add_service_sync(router, vipCStr, nameCStr)
                }
            }
            if result != 0 {
                logger.warn("Failed to add service \(svc.name) at \(svc.vip): \(lastError())", source: "Tunnel")
            } else {
                logger.info("Router service: \(svc.vip) → \(svc.name)", source: "Tunnel")
            }
        }

        // Start the utun packet I/O loop unless a later debug build explicitly
        // switches ownership to Rust. For the current lifecycle-only smoke test,
        // Rust stores the fd but does not read/write it, so Swift remains owner.
        if Self.useRustFdDataPlane {
            logger.info("Rust fd data plane requested; Swift packet I/O loop disabled", source: "Tunnel")
        } else {
            startPacketLoop()
        }
    }

    private func startPacketLoop() {
        logger.info("Starting packet I/O loop", source: "Tunnel")
        readPacketLoop()
    }

    private func startRustIosTunnelEngineLifecycleSmokeTest(fd: Int32) {
        guard Self.enableRustIosTunnelEngineLifecycleSmokeTest else {
            logger.info("Rust iOS tunnel engine scaffold disabled mode=swift_packetFlow", source: "Tunnel")
            return
        }
        guard iosTunnelEngine == nil else {
            logger.warn("Rust iOS tunnel engine scaffold already started; ignoring duplicate fd=\(fd)", source: "Tunnel")
            return
        }

        var engine: OpaquePointer?
        let result = ztlp_ios_tunnel_engine_start(fd, &engine)
        guard result == 0, let engine = engine else {
            logger.error("Rust iOS tunnel engine scaffold start failed fd=\(fd): \(lastError())", source: "Tunnel")
            return
        }

        iosTunnelEngine = engine
        if Self.useRustFdDataPlane {
            guard let router = packetRouter else {
                logger.error("Rust iOS tunnel engine router ingress requested but packetRouter is nil", source: "Tunnel")
                return
            }
            let userData = Unmanaged.passUnretained(self).toOpaque()
            let callbackResult = ztlp_ios_tunnel_engine_set_router_action_callback(engine, rustRouterActionCallback, userData)
            if callbackResult == 0 {
                logger.info("Rust router action callback registered", source: "Tunnel")
            } else {
                logger.error("Rust router action callback registration failed fd=\(fd): \(lastError())", source: "Tunnel")
            }

            let readResult = ztlp_ios_tunnel_engine_start_router_ingress_loop(engine, router)
            if readResult == 0 {
                logger.info("Rust iOS tunnel engine scaffold started fd=\(fd) mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback", source: "Tunnel")
            } else {
                logger.error("Rust iOS tunnel engine router ingress start failed fd=\(fd): \(lastError())", source: "Tunnel")
            }
        } else {
            logger.info("Rust iOS tunnel engine scaffold started fd=\(fd) mode=lifecycle_only", source: "Tunnel")
        }
    }

    /// Locate the utun file descriptor created by NEPacketTunnelProvider.
    /// This follows Nebula's iOS pattern: Swift configures NE settings, then
    /// hands the fd to a native data-plane owner. Phase 1 logs only; production
    /// packet I/O still uses packetFlow until the Rust engine is validated.
    private var tunnelFileDescriptor: Int32? {
        let fd = ztlp_find_utun_fd()
        return fd >= 0 ? fd : nil
    }

    /// Recursive readPackets loop: utun → standalone router → ZTLP
    private func readPacketLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isTunnelActive, let router = self.packetRouter else { return }

            var packetsProcessed = 0
            let packetLimit = Self.maxPacketsPerReadCycle
            for (i, packet) in packets.enumerated() {
                if packetsProcessed >= packetLimit {
                    break
                }
                if self.shouldThrottleRouterWork() {
                    break
                }

                let proto = protocols[i]
                if proto.intValue == AF_INET {
                    // Intercept DNS queries for *.ztlp before they hit the router
                    if let dns = self.dnsResponder, dns.isDNSQuery(packet) {
                        if let response = dns.handleQuery(packet) {
                            // Write DNS response directly back to utun
                            self.packetFlow.writePackets([response], withProtocols: [NSNumber(value: AF_INET)])
                            packetsProcessed += 1
                            continue
                        } else {
                            self.logger.warn("DNS query matched but no response generated", source: "DNS")
                        }
                    }

                    var actionWritten: Int = 0

                    let actionCount = packet.withUnsafeBytes { pktPtr -> Int32 in
                        guard let baseAddr = pktPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                            return -1
                        }
                        return ztlp_router_write_packet_sync(
                            router,
                            baseAddr, pktPtr.count,
                            &self.actionBuffer, self.actionBuffer.count,
                            &actionWritten
                        )
                    }

                    // Process router actions (OpenStream, SendData, CloseStream)
                    if actionCount > 0 && actionWritten > 0 {
                        if actionCount > 1 {
                            self.logger.debug("Router: \(actionCount) action(s), \(actionWritten) bytes", source: "Router")
                        }
                        self.processRouterActions(
                            actionBuffer: self.actionBuffer,
                            actionLen: actionWritten,
                            maxActions: Self.maxRouterActionsPerCycle
                        )
                    }

                    packetsProcessed += 1
                }
            }

            if !packets.isEmpty {
                self.markDataActivity()
            }

            // Flush outbound response packets immediately, but in bounded batches.
            self.flushOutboundPackets(maxPackets: self.currentOutboundFlushLimit())

            self.readPacketLoop()
        }
    }



    fileprivate func handleRustFdIngressDiagnostic(_ message: String) {
        tunnelQueue.async { [weak self] in
            guard let self else { return }
            self.rustFdIngressDiagCount += 1
            let now = Date()
            if self.rustFdIngressDiagCount <= 30 || message.contains("tcp_payload=0") == false || now.timeIntervalSince(self.rustFdIngressDiagLastLogAt) >= 1.0 {
                self.logger.debug("Rust fd ingress diag count=\(self.rustFdIngressDiagCount) \(message)", source: "Tunnel")
                self.rustFdIngressDiagLastLogAt = now
            }
        }
    }

    fileprivate func handleRustFdOutboundDiagnostic(_ message: String) {
        tunnelQueue.async { [weak self] in
            guard let self else { return }
            self.rustFdOutboundDiagCount += 1
            let now = Date()
            if self.rustFdOutboundDiagCount <= 30 || now.timeIntervalSince(self.rustFdOutboundDiagLastLogAt) >= 1.0 {
                self.logger.debug("Rust fd outbound diag count=\(self.rustFdOutboundDiagCount) \(message)", source: "Tunnel")
                self.rustFdOutboundDiagLastLogAt = now
            }
        }
    }

    fileprivate func handleRustRouterAction(actionType: UInt8, streamID: UInt32, payload: [UInt8]) {
        tunnelQueue.async { [weak self] in
            guard let self else { return }
            switch actionType {
            case 0:
                self.rustActionCallbackOpen += 1
            case 1:
                self.rustActionCallbackSend += 1
                self.rustActionCallbackBytes += payload.count
            case 2:
                self.rustActionCallbackClose += 1
            default:
                self.rustActionCallbackUnknown += 1
            }
            let now = Date()
            if actionType == 1 || now.timeIntervalSince(self.rustActionCallbackLastLogAt) >= 1.0 {
                self.logger.debug("Rust action callback summary open=\(self.rustActionCallbackOpen) send=\(self.rustActionCallbackSend) close=\(self.rustActionCallbackClose) unknown=\(self.rustActionCallbackUnknown) bytes=\(self.rustActionCallbackBytes) lastType=\(actionType) lastStream=\(streamID) lastLen=\(payload.count)", source: "Tunnel")
                self.rustActionCallbackLastLogAt = now
                self.rustActionCallbackOpen = 0
                self.rustActionCallbackSend = 0
                self.rustActionCallbackClose = 0
                self.rustActionCallbackUnknown = 0
                self.rustActionCallbackBytes = 0
            }
            // Reuse the existing Swift RouterAction -> mux transport path.
            // This keeps packetFlow bytes out of Swift while preserving current transport/session behavior.
            var action = [UInt8]()
            action.reserveCapacity(7 + payload.count)
            action.append(actionType)
            action.append(contentsOf: self.beStreamIdBytes(streamID))
            let len = UInt16(min(payload.count, Int(UInt16.max)))
            action.append(UInt8(len >> 8))
            action.append(UInt8(len & 0xff))
            if len > 0 {
                action.append(contentsOf: payload.prefix(Int(len)))
            }
            self.processRouterActions(actionBuffer: action, actionLen: action.count, maxActions: 1)
        }
    }

    /// Parse and dispatch serialized RouterActions from the standalone router.
    /// Format: [1B type][4B stream_id BE][2B data_len BE][data...]
    /// Type: 0=OpenStream, 1=SendData, 2=CloseStream
    ///
    /// Router actions must be translated into mux payloads for the gateway:
    ///   OPEN  = [0x06 | stream_id(4 BE) | service_name_len(1) | service_name]
    ///   DATA  = [0x00 | stream_id(4 BE) | payload]
    ///   CLOSE = [0x05 | stream_id(4 BE)]
    ///
    /// tunnelConnection.sendData() then wraps those mux payloads in the outer
    /// encrypted FRAME_DATA transport envelope.
    private func processRouterActions(actionBuffer: [UInt8], actionLen: Int, maxActions: Int = Int.max) {
        var offset = 0
        var actionsProcessed = 0
        while offset < actionLen {
            if actionsProcessed >= maxActions {
                break
            }
            if shouldThrottleRouterWork() {
                break
            }
            guard offset + 7 <= actionLen else { break }  // min: 1+4+2 = 7 bytes

            let actionType = actionBuffer[offset]
            offset += 1

            let streamId = UInt32(actionBuffer[offset]) << 24
                | UInt32(actionBuffer[offset + 1]) << 16
                | UInt32(actionBuffer[offset + 2]) << 8
                | UInt32(actionBuffer[offset + 3])
            offset += 4

            let dataLen = Int(actionBuffer[offset]) << 8
                | Int(actionBuffer[offset+1])
            offset += 2

            guard offset + dataLen <= actionLen else { break }

            let actionData: Data? = dataLen > 0 ? Data(actionBuffer[offset..<(offset+dataLen)]) : nil
            offset += dataLen
            actionsProcessed += 1

            switch actionType {
            case 0: // OpenStream
                guard let serviceData = actionData, serviceData.count <= 255 else {
                    logger.warn("Router: OpenStream missing/oversize service name for stream \(streamId)", source: "Router")
                    continue
                }
                var muxOpen = Data(capacity: 6 + serviceData.count)
                muxOpen.append(Self.MUX_FRAME_OPEN)
                muxOpen.append(contentsOf: beStreamIdBytes(streamId))
                muxOpen.append(UInt8(serviceData.count))
                muxOpen.append(serviceData)
                muxSummaryOpen += 1
                maybeLogMuxSummary(force: false)
                markOutboundDemand()
                let sent = tunnelConnection?.sendData(muxOpen) == true
                logger.debug("RouterAction send OpenStream stream=\(streamId) serviceBytes=\(serviceData.count) sent=\(sent)", source: "Router")
                if !sent {
                    logger.warn("Router: OpenStream backpressured for stream \(streamId)", source: "Router")
                    return
                }

            case 1: // SendData
                guard let payload = actionData else { continue }
                var muxData = Data(capacity: 5 + payload.count)
                muxData.append(Self.MUX_FRAME_DATA)
                muxData.append(contentsOf: beStreamIdBytes(streamId))
                muxData.append(payload)
                muxSummarySendData += 1
                muxSummarySendBytes += payload.count
                maybeLogMuxSummary(force: false)
                markOutboundDemand()
                let sent = tunnelConnection?.sendData(muxData) == true
                logger.debug("RouterAction send SendData stream=\(streamId) bytes=\(payload.count) sent=\(sent)", source: "Router")
                if !sent {
                    logger.warn("Router: SendData backpressured for stream \(streamId) bytes=\(payload.count)", source: "Router")
                    return
                }

            case 2: // CloseStream
                var muxClose = Data(capacity: 5)
                muxClose.append(Self.MUX_FRAME_CLOSE)
                muxClose.append(contentsOf: beStreamIdBytes(streamId))
                muxSummaryClose += 1
                maybeLogMuxSummary(force: false)
                markOutboundDemand()
                let sent = tunnelConnection?.sendData(muxClose) == true
                logger.debug("RouterAction send CloseStream stream=\(streamId) sent=\(sent)", source: "Router")
                if !sent {
                    logger.warn("Router: CloseStream backpressured for stream \(streamId)", source: "Router")
                    return
                }

            default:
                logger.warn("Unknown router action type: \(actionType)", source: "Tunnel")
            }
        }
    }

    private func handleGatewayMuxPayload(_ data: Data) {
        guard let router = packetRouter, !data.isEmpty else { return }

        let frameType = data[0]
        switch frameType {
        case Self.MUX_FRAME_DATA:
            guard data.count >= 5 else {
                logger.warn("GW->NE mux DATA too short: \(data.count)", source: "Tunnel")
                return
            }
            let streamId = data.dropFirst().prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let payload = data.dropFirst(5)
            muxSummaryDataFrames += 1
            muxSummaryDataBytes += payload.count
            maybeLogMuxSummary(force: false)
            payload.withUnsafeBytes { ptr in
                guard let baseAddr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                ztlp_router_gateway_data_sync(router, streamId, baseAddr, ptr.count)
            }

        case Self.MUX_FRAME_CLOSE:
            guard data.count >= 5 else {
                logger.warn("GW->NE mux CLOSE too short: \(data.count)", source: "Tunnel")
                return
            }
            let streamId = data.dropFirst().prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            muxSummaryClose += 1
            maybeLogMuxSummary(force: false)
            ztlp_router_gateway_close_sync(router, streamId)

        default:
            data.withUnsafeBytes { ptr in
                guard let baseAddr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                ztlp_router_gateway_data_sync(router, 0, baseAddr, ptr.count)
            }
        }

        flushOutboundPackets(maxPackets: currentOutboundFlushLimit())
    }

    private func maybeLogMuxSummary(force: Bool) {
        let now = Date()
        guard force || now.timeIntervalSince(muxSummaryLastLogAt) >= 1.0 else { return }
        let totalEvents = muxSummaryDataFrames + muxSummaryOpen + muxSummaryClose + muxSummarySendData
        guard totalEvents > 0 else { return }
        muxSummaryLastLogAt = now
        logger.debug(
            "Mux summary gwData=\(muxSummaryDataFrames)/\(muxSummaryDataBytes)B open=\(muxSummaryOpen) close=\(muxSummaryClose) send=\(muxSummarySendData)/\(muxSummarySendBytes)B",
            source: "Tunnel"
        )
        muxSummaryDataFrames = 0
        muxSummaryDataBytes = 0
        muxSummaryOpen = 0
        muxSummaryClose = 0
        muxSummarySendData = 0
        muxSummarySendBytes = 0
    }

    private func beStreamIdBytes(_ streamId: UInt32) -> [UInt8] {
        withUnsafeBytes(of: streamId.bigEndian) { Array($0) }
    }


    private func currentOutboundFlushLimit() -> Int {
        let browserMode = lastRouterFlows >= Self.rwndBrowserBurstFlowThreshold ||
            lastRouterStreamMappings >= Self.rwndBrowserBurstFlowThreshold
        return browserMode ? Self.browserModeMaxOutboundPacketsPerFlush : Self.maxOutboundPacketsPerFlush
    }

    /// Write response packets from the router back to the utun interface.
    private func flushOutboundPackets(maxPackets: Int = Int.max) {
        guard let router = packetRouter else { return }

        var packets: [Data] = []
        var protocols: [NSNumber] = []
        var drained = 0

        // Drain available outbound packets in bounded batches so the runloop can
        // get back to inbound UDP processing and ACK generation.
        while drained < maxPackets {
            let bytesRead = ztlp_router_read_packet_sync(
                router,
                &readPacketBuffer,
                readPacketBuffer.count
            )
            if bytesRead <= 0 { break }

            packets.append(Data(readPacketBuffer[0..<Int(bytesRead)]))
            protocols.append(NSNumber(value: AF_INET))
            drained += 1
        }

        if drained >= maxPackets {
            consecutiveFullFlushes += 1
            if consecutiveFullFlushes >= 2 {
                reduceAdvertisedRwnd(reason: "router flush saturated")
            } else {
                reduceAdvertisedRwnd(reason: "router flush full")
            }
        } else if drained == 0 {
            consecutiveFullFlushes = 0
        } else {
            consecutiveFullFlushes = 0
        }

        if !packets.isEmpty {
            markDataActivity()
            packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    private func updateAdvertisedRwnd(_ rwnd: UInt16, reason: String) {
        let clamped = min(max(rwnd, Self.rwndFloor), Self.rwndAdaptiveMax)
        let changed = clamped != advertisedRwnd
        if changed {
            advertisedRwnd = clamped
            tunnelConnection?.setAdvertisedReceiveWindow(clamped)
        }

        let now = Date()
        if changed || now.timeIntervalSince(lastRwndLogAt) >= 2.0 {
            lastRwndLogAt = now
            logger.debug("Advertised rwnd=\(clamped) reason=\(reason) healthyTicks=\(consecutiveRwndHealthyTicks)", source: "Tunnel")
        }
    }

    private func reduceAdvertisedRwnd(reason: String) {
        consecutiveRwndHealthyTicks = 0
        updateAdvertisedRwnd(Self.rwndFloor, reason: reason)
    }

    private func maybeRampAdvertisedRwnd(stats: RouterStatsSnapshot, replayDelta: Int, highSeqAdvanced: Bool, hasActiveFlows: Bool) {
        guard isTunnelActive else { return }

        let now = Date()
        let browserBurst = stats.flows >= Self.rwndBrowserBurstFlowThreshold ||
            stats.streamToFlow >= Self.rwndBrowserBurstFlowThreshold

        if browserBurst && replayDelta > 0 {
            rwndPressureUntil = now.addingTimeInterval(Self.rwndPressureCooldown)
            if replayDelta >= Self.rwndReplayDeltaReconnect && hasActiveFlows {
                reduceAdvertisedRwnd(reason: "browser replay fast reconnect replayDelta=\(replayDelta)")
                resetPacketRouterRuntimeState(reason: "browser_replay_fast_reconnect_\(replayDelta)")
                pendingReconnectReason = "browser_replay_fast_reconnect_\(replayDelta)"
                scheduleReconnect()
                return
            }
            reduceAdvertisedRwnd(reason: "browser replay backoff replayDelta=\(replayDelta) cooldown=\(Int(Self.rwndPressureCooldown))s")
            return
        }

        if now < rwndPressureUntil {
            let remaining = rwndPressureUntil.timeIntervalSince(now)
            reduceAdvertisedRwnd(reason: "pressure cooldown remaining=\(String(format: "%.1f", remaining))s replayDelta=\(replayDelta)")
            return
        }

        // Do not force rwnd down solely because oldestMs grows while browser
        // data is still flowing. In Rust-fd Vaultwarden runs this caused rwnd=16
        // to last only a couple seconds, then the page spent the whole asset tail
        // at rwnd=4 even with replayDelta=0 and no router backlog. Treat oldestMs
        // as pressure only when paired with actual no-progress/suspect state.
        let oldestIsRealPressure = stats.oldestMs >= Self.rwndOldestMsBad &&
            (consecutiveStuckHighSeqTicks > 0 || sessionSuspectSince != nil || probeOutstandingSince != nil)
        let pressure = stats.outbound >= Self.rwndRouterOutboundBad ||
            stats.sendBufBytes >= Self.rwndSendBufBytesBad ||
            oldestIsRealPressure ||
            consecutiveFullFlushes > 0 ||
            replayDelta >= Self.rwndReplayDeltaBad ||
            probeOutstandingSince != nil ||
            sessionSuspectSince != nil

        if pressure {
            let reason = "pressure outbound=\(stats.outbound) sendBuf=\(stats.sendBufBytes) oldestMs=\(stats.oldestMs) replayDelta=\(replayDelta) fullFlushes=\(consecutiveFullFlushes)"
            reduceAdvertisedRwnd(reason: reason)
            return
        }

        if browserBurst {
            consecutiveRwndHealthyTicks = 0
            updateAdvertisedRwnd(
                Self.rwndBrowserBurstTarget,
                reason: "browser burst target flows=\(stats.flows) streamMaps=\(stats.streamToFlow)"
            )
            return
        }

        let outboundDemandAge = Date().timeIntervalSince(lastOutboundDemandAt)
        let activeOrRecentlyActive = hasActiveFlows || outboundDemandAge < 3.0
        let makingProgress = highSeqAdvanced || stats.outbound == 0
        guard activeOrRecentlyActive && makingProgress else {
            consecutiveRwndHealthyTicks = 0
            updateAdvertisedRwnd(Self.rwndFloor, reason: "not enough progress for ramp active=\(activeOrRecentlyActive) highSeqAdvanced=\(highSeqAdvanced) outbound=\(stats.outbound)")
            return
        }

        // After browser demand, hold a moderate window instead of collapsing to
        // rwnd=4. Queue/backpressure fixes now keep the gateway shallow; a tiny
        // post-demand window leaves long Vaultwarden JS/WASM tails that WebKit
        // cancels/retries. Real pressure above still drops to the floor.
        if outboundDemandAge < 15.0 {
            consecutiveRwndHealthyTicks = 0
            updateAdvertisedRwnd(min(UInt16(12), Self.rwndAdaptiveMax), reason: "recent outbound hold age=\(String(format: "%.1f", outboundDemandAge))s")
            return
        }

        consecutiveRwndHealthyTicks += 1
        if consecutiveRwndHealthyTicks >= Self.rwndHealthyTicksToIncrease && advertisedRwnd < Self.rwndAdaptiveMax {
            consecutiveRwndHealthyTicks = 0
            updateAdvertisedRwnd(advertisedRwnd + 1, reason: "healthy ramp flows=\(stats.flows) outbound=\(stats.outbound) sendBuf=\(stats.sendBufBytes) oldestMs=\(stats.oldestMs)")
        } else {
            updateAdvertisedRwnd(advertisedRwnd, reason: "healthy hold flows=\(stats.flows) outbound=\(stats.outbound) sendBuf=\(stats.sendBufBytes) oldestMs=\(stats.oldestMs)")
        }
    }

    private func startWritePacketTimer() {
        writePacketTimer?.cancel()
        writePacketTimer = nil
    }

    private func stopWritePacketTimer() {
        writePacketTimer?.cancel()
        writePacketTimer = nil
    }

    /// Flush batched ACKs every 10ms for low latency without per-packet overhead.
    private func startAckFlushTimer() {
        ackFlushTimer?.cancel()
        ackFlushTimer = nil
    }

    /// Every 10 seconds, clean up stale TCP flows (120s timeout) to reclaim
    /// flow memory. Each flow has a 48-byte VecDeque struct + send_buf overhead.
    /// Also logs NE memory for diagnostics.
    private func startCleanupTimer() {
        cleanupTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now() + .seconds(10), repeating: .seconds(10))
        timer.setEventHandler { [weak self] in
            guard let self = self, self.isTunnelActive else { return }
            if let router = self.packetRouter {
                let cleaned = ztlp_router_cleanup_stale_flows(router)
                if cleaned > 0 {
                    self.logger.info("Cleaned up \(cleaned) stale TCP flows", source: "Tunnel")
                    if let statsPtr = ztlp_router_stats(router) {
                        let stats = String(cString: statsPtr)
                        ztlp_free_string(statsPtr)
                        self.logger.debug("Router stats: \(stats)", source: "Tunnel")
                    }
                } else if self.isDataActive, let statsPtr = ztlp_router_stats(router) {
                    let stats = String(cString: statsPtr)
                    ztlp_free_string(statsPtr)
                    self.logger.debug("Router stats: \(stats)", source: "Tunnel")
                }
            }
            self.logMemoryDiagnostics()
        }
        timer.resume()
        cleanupTimer = timer
    }

    // MARK: - Relay Discovery and Selection (sync NS + RelayPool FFI)

    /// Discover relays via NS and populate the RelayPool.
    private func discoverRelays(config: TunnelConfiguration) {
        // Free existing pool if present
        if let existing = relayPool {
            ztlp_relay_pool_free(existing)
        }

        // Gateway region for selection tiebreak — derive from config
        let regionStr = config.gatewayRegion ?? ""

        relayPool = regionStr.withCString { ztlp_relay_pool_new($0) }
        guard let pool = relayPool else {
            logger.warn("Failed to create relay pool, will use fallback relay", source: "Relay")
            return
        }

        // Query NS for RELAY records (type 3)
        if let nsAddr = config.nsServer, !nsAddr.isEmpty {
            let zoneName = (config.zoneName ?? "").replacingOccurrences(of: ".ztlp", with: "")
            logger.info("Querying NS for RELAY records at \(nsAddr) (zone=\(zoneName))", source: "Relay")

            let relayList = nsAddr.withCString { nsCStr in
                zoneName.withCString { zoneCStr in
                    ztlp_ns_resolve_relays_sync(nsCStr, zoneCStr, 5000)
                }
            }

            if let relayList = relayList {
                // Check for errors in the result
                if let errMsg = relayList.pointee.error {
                    let errorStr = String(cString: errMsg)
                    logger.warn("NS relay query returned error: \(errorStr)", source: "Relay")
                } else if relayList.pointee.count > 0 {
                    let updateResult = ztlp_relay_pool_update_from_ns(pool, relayList)
                    if updateResult == 0 {
                        let healthy = ztlp_relay_pool_healthy_count(pool)
                        let total = ztlp_relay_pool_total_count(pool)
                        logger.info("Relay pool updated: \(total) total, \(healthy) healthy from NS", source: "Relay")

                        // Log discovered relays
                        for i in 0..<relayList.pointee.count {
                            let addr = relayList.pointee.addresses[i]
                            let region = relayList.pointee.regions[i]
                            let latency = relayList.pointee.latency_ms[i]
                            let load = relayList.pointee.load_pct[i]
                            let health = relayList.pointee.health[i]
                            let healthStr: String
                            switch health {
                                case 0: healthStr = "healthy"
                                case 1: healthStr = "degraded"
                                case 2: healthStr = "dead"
                                case 3: healthStr = "deprioritized"
                                default: healthStr = "unknown"
                            }
                            let regionStr = region.map { String(cString: $0) } ?? "?"
                            let addrStr = addr.map { String(cString: $0) } ?? "?"
                            logger.info("  Relay #\(i+1): \(addrStr) region=\(regionStr) lat=\(latency)ms load=\(load)% health=\(healthStr)", source: "Relay")
                        }
                    } else {
                        logger.warn("Failed to update relay pool from NS", source: "Relay")
                    }
                } else {
                    logger.info("NS returned no relay records", source: "Relay")
                }
                ztlp_relay_list_free(relayList)
            } else {
                logger.warn("NS relay query failed: \(lastError())", source: "Relay")
            }
        } else {
            logger.info("No NS server configured for relay discovery", source: "Relay")
        }
    }

    /// Select the best relay from the pool. Falls back to config relay if pool is empty.
    private func selectRelay(config: TunnelConfiguration) -> String? {
        guard let pool = relayPool, ztlp_relay_pool_healthy_count(pool) > 0 else {
            // Fall back to configured relay or direct gateway
            if let relay = config.relayAddress, !relay.isEmpty {
                logger.info("No relay pool available, using configured fallback: \(relay)", source: "Relay")
                return relay
            }
            logger.warn("No relay available (pool empty, no configured fallback)", source: "Relay")
            return nil
        }

        let selected = ztlp_relay_pool_select(pool)
        defer { if let s = selected { ztlp_string_free(s) } }

        if let relayAddr = selected, let addrStr = String(utf8String: relayAddr), !addrStr.isEmpty {
            logger.info("Selected relay: \(addrStr) (healthy=\(ztlp_relay_pool_healthy_count(pool)))", source: "Relay")
            currentRelayAddress = addrStr
            sharedDefaults?.set(addrStr, forKey: SharedKey.selectedRelay)
            return addrStr
        }

        // Pool has relays but none selected — try configured relay
        if let relay = config.relayAddress, !relay.isEmpty {
            logger.info("Pool returned no relay, using configured fallback: \(relay)", source: "Relay")
            return relay
        }

        logger.warn("No relay available from pool or config", source: "Relay")
        return nil
    }

    // MARK: - Reconnect

    private func scheduleReconnect() {
        scheduleReconnect(reason: pendingReconnectReason ?? "transport_failure")
    }

    private func scheduleReconnect(reason: String) {
        guard isTunnelActive else { return }
        pendingReconnectReason = reason
        guard !reconnectScheduled && !reconnectInProgress else {
            logger.debug("Reconnect already scheduled/in progress; ignoring duplicate trigger reason=\(reason)", source: "Tunnel")
            return
        }

        reconnectAttempt += 1
        reconnectGeneration += 1
        let generation = reconnectGeneration

        if reconnectAttempt > Self.maxReconnectAttempts {
            logger.error("Failed to reconnect after \(Self.maxReconnectAttempts) attempts", source: "Tunnel")
            cancelTunnelWithError(
                makeNSError("Failed to reconnect after \(Self.maxReconnectAttempts) attempts")
            )
            return
        }

        let delay = min(
            Self.baseReconnectDelay * pow(2.0, Double(reconnectAttempt - 1)),
            Self.maxReconnectDelay
        )
        let jitter = delay * Double.random(in: -0.2...0.2)
        let finalDelay = max(0.5, delay + jitter)

        reconnectScheduled = true
        logger.info("Reconnect attempt \(reconnectAttempt)/\(Self.maxReconnectAttempts) gen=\(generation) in \(String(format: "%.1f", finalDelay))s reason=\(reason)", source: "Tunnel")
        updateConnectionState(.reconnecting)

        healthQueue.asyncAfter(deadline: .now() + finalDelay) { [weak self] in
            guard let self = self, self.isTunnelActive else { return }
            self.tunnelQueue.async { [weak self] in
                guard let self = self, self.isTunnelActive else { return }
                guard self.reconnectScheduled && self.reconnectGeneration == generation else { return }
                self.reconnectScheduled = false
                self.attemptReconnect(generation: generation)
            }
        }
    }

    private func attemptReconnect(generation: Int) {
        guard !reconnectInProgress else {
            logger.debug("Reconnect gen=\(generation) ignored; reconnect already in progress", source: "Tunnel")
            return
        }
        reconnectInProgress = true
        let reconnectReason = pendingReconnectReason ?? "transport_failure"
        defer {
            reconnectInProgress = false
            pendingReconnectReason = nil
        }
        logger.info("Reconnect gen=\(generation) starting reason=\(reconnectReason)", source: "Tunnel")

        resetPacketRouterRuntimeState(reason: "reconnect_gen_\(generation)_\(reconnectReason)")

        guard let identityPtr = identity else {
            logger.error("Identity lost during reconnect", source: "Tunnel")
            cancelTunnelWithError(makeNSError("Identity lost during reconnect"))
            return
        }

        // Stop old tunnel connection
        tunnelConnection?.stop()
        tunnelConnection = nil

        // Reload config
        let config = currentConfig ?? (try? loadTunnelConfiguration())
        guard let config = config else {
            logger.error("Failed to load config for reconnect", source: "Tunnel")
            scheduleReconnect()
            return
        }

        // Try to select a NEW relay (different from the failed one)
        // First report the currently active relay as failed
        if let pool = relayPool, let failedRelay = activeRelayAddress {
            failedRelay.withCString { ztlp_relay_pool_report_failure(pool, $0) }
            logger.info("Reported relay failure for \(failedRelay)", source: "Relay")
        }

        // Do NOT perform a blocking plain-UDP NS refresh while the packet tunnel
        // is active. On iOS NE this can route through the tunnel itself and fail
        // with ENETUNREACH, then destroy useful relay state mid-reconnect. Use
        // cached relays/fallback during reconnect; refresh NS on fresh tunnel start.
        if let pool = relayPool, ztlp_relay_pool_needs_refresh(pool) {
            logger.info("Relay pool stale during reconnect; skipping active-tunnel NS refresh and using cached/fallback relay", source: "Relay")
        }

        // Select next best relay from pool
        let svcName = config.serviceName ?? "vault"
        guard let relayAddr = selectRelay(config: config) else {
            logger.error("No relay available for reconnect", source: "Relay")
            scheduleReconnect()
            return
        }

        logger.info("Reconnect gen=\(generation) via relay \(relayAddr)...", source: "Relay")
        currentRelayAddress = relayAddr

        // Build config for reconnect through new relay
        let cfgPtr = ztlp_config_new()
        defer { if let c = cfgPtr { ztlp_config_free(c) } }

        if let cfgPtr = cfgPtr {
            relayAddr.withCString { ztlp_config_set_relay(cfgPtr, $0) }
            ztlp_config_set_nat_assist(cfgPtr, true)
            ztlp_config_set_timeout_ms(cfgPtr, 15000)
            if !svcName.isEmpty {
                svcName.withCString { ztlp_config_set_service(cfgPtr, $0) }
            }
        }

        // Reconnect using handshake on the same NWConnection that will carry data
        let target = config.targetNodeId
        let conn = ZTLPTunnelConnection(
            gatewayAddress: relayAddr,
            queue: tunnelQueue
        )
        conn.delegate = self
        conn.start()

        let handshakeSemaphore = DispatchSemaphore(value: 0)
        var handshakeError: Error?
        conn.performHandshake(identity: identityPtr, config: cfgPtr, target: target, timeoutMs: 15000) { result in
            switch result {
            case .success:
                break
            case .failure(let error):
                handshakeError = error
            }
            handshakeSemaphore.signal()
        }
        let waitResult = handshakeSemaphore.wait(timeout: .now() + 20.0)
        if waitResult == .timedOut {
            conn.stop()
            logger.warn("Reconnect gen=\(generation) handshake wait timed out for relay \(relayAddr), will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        if let handshakeError = handshakeError {
            conn.stop()
            // Report this relay as failed and retry
            if let pool = relayPool {
                relayAddr.withCString { ztlp_relay_pool_report_failure(pool, $0) }
            }
            logger.warn("Reconnect gen=\(generation) to \(relayAddr) failed: \(handshakeError.localizedDescription), will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        tunnelConnection = conn
        wireRttInstrumentationHook(on: conn)

        // Update active relay tracking
        activeRelayAddress = relayAddr

        // Report successful connection to relay
        if let pool = relayPool {
            relayAddr.withCString { ztlp_relay_pool_report_success(pool, $0, 0) }
        }

        // Success
        reconnectAttempt = 0
        consecutiveKeepaliveFailures = 0
        lastDataActivity = Date()
        advertisedRwnd = Self.rwndFloor
        consecutiveRwndHealthyTicks = 0
        lastUsefulRxAt = Date()
        lastHighSeqSeen = 0
        priorHighSeqSnapshot = 0
        consecutiveStuckHighSeqTicks = 0
        refreshReplayRejectBaseline()
        conn.setAdvertisedReceiveWindow(Self.rwndFloor)
        logger.info("Reconnect gen=\(generation) succeeded via relay \(relayAddr); reset health/rwnd baselines", source: "Tunnel")
        updateConnectionState(.connected)
        sharedDefaults?.set(
            Date().timeIntervalSince1970,
            forKey: SharedKey.connectedSince
        )
        sharedDefaults?.set(relayAddr, forKey: SharedKey.selectedRelay)
    }

    // MARK: - Keepalive

    private func startKeepaliveTimer() {
        keepaliveTimer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now() + 25, repeating: 25)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }

            self.logMemoryDiagnostics()

            if self.isDataActive {
                self.consecutiveKeepaliveFailures = 0
                self.logger.debug("Keepalive skipped — data active (\(String(format: "%.0f", Date().timeIntervalSince(self.lastDataActivity)))s ago)", source: "Tunnel")
                return
            }

            // Send keepalive as a minimal encrypted packet
            let keepaliveData = Data([0])
            let sent = self.tunnelConnection?.sendData(keepaliveData) ?? false
            if sent {
                self.consecutiveKeepaliveFailures = 0
            } else {
                self.consecutiveKeepaliveFailures += 1
                let relayInfo = self.activeRelayAddress ?? "unknown"
                self.logger.debug(
                    "Keepalive send failed via relay \(relayInfo) (\(self.consecutiveKeepaliveFailures)/\(Self.keepaliveFailureThreshold))",
                    source: "Tunnel"
                )

                if self.consecutiveKeepaliveFailures >= Self.keepaliveFailureThreshold
                    && !self.isDataActive
                    && self.isTunnelActive {
                    self.logger.warn(
                        "Connection appears dead — \(self.consecutiveKeepaliveFailures) keepalive failures via relay \(relayInfo), no data for \(String(format: "%.0f", Date().timeIntervalSince(self.lastDataActivity)))s",
                        source: "Tunnel"
                    )
                    self.scheduleReconnect()
                }
            }
        }
        timer.resume()
        keepaliveTimer = timer
    }

    // MARK: - Configuration

    private func loadTunnelConfiguration() throws -> TunnelConfiguration {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            throw makeNSError("Invalid protocol configuration")
        }

        guard let providerConfig = proto.providerConfiguration,
              let config = TunnelConfiguration.from(dictionary: providerConfig) else {
            throw makeNSError("Missing or invalid provider configuration")
        }

        return config
    }

    private func defaultIdentityPath() -> String? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupId
        ) else { return nil }
        return containerURL.appendingPathComponent("identity.json").path
    }

    private func createTunnelNetworkSettings(
        tunnelRemoteAddress: String,
        usePacketRouter: Bool = true
    ) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = tunnelRemoteAddress.components(separatedBy: ":").first ?? tunnelRemoteAddress

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        if usePacketRouter {
            let ipv4 = NEIPv4Settings(
                addresses: ["10.122.0.1"],
                subnetMasks: ["255.255.0.0"]
            )
            let vipRoute = NEIPv4Route(
                destinationAddress: "10.122.0.0",
                subnetMask: "255.255.0.0"
            )
            ipv4.includedRoutes = [vipRoute]
            ipv4.excludedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = ipv4
        } else {
            let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
            ipv4.includedRoutes = []
            ipv4.excludedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = ipv4
        }

        let dns = NEDNSSettings(servers: ["10.122.0.1"])
        dns.matchDomains = ["ztlp"]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: 1400)

        return settings
    }

    // MARK: - Shared State

    private func updateConnectionState(_ state: TunnelConnectionState) {
        sharedDefaults?.set(state.rawValue, forKey: SharedKey.connectionState)
        sharedDefaults?.synchronize()
    }

    // MARK: - Memory Diagnostics

    private func logMemoryDiagnostics(force: Bool = false) {
        let now = Date()
        if !force && now.timeIntervalSince(lastMemoryDiagnosticsAt) < Self.memoryDiagnosticsInterval {
            return
        }
        lastMemoryDiagnosticsAt = now

        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }

        var reportedMemoryMB: Double?
        if result == KERN_SUCCESS {
            let residentMB = Double(info.resident_size) / 1_048_576.0
            let virtualMB = Double(info.virtual_size) / 1_048_576.0
            reportedMemoryMB = residentMB
            let residentRounded = Int(residentMB.rounded())
            let virtualRounded = Int(virtualMB.rounded())

            if lastStoredResidentMemoryMB != residentRounded {
                sharedDefaults?.set(residentRounded, forKey: SharedKey.neMemoryMB)
                lastStoredResidentMemoryMB = residentRounded
            }
            if lastStoredVirtualMemoryMB != virtualRounded {
                sharedDefaults?.set(virtualRounded, forKey: SharedKey.neVirtualMB)
                lastStoredVirtualMemoryMB = virtualRounded
            }

            // The NE is stable around ~18-20MB on current builds; avoid noisy
            // warning spam that wakes the process and obscures real failures.
            logger.debug(
                "v5D-SYNC | Memory resident=\(String(format: "%.1f", residentMB))MB virtual=\(String(format: "%.1f", virtualMB))MB",
                source: "Tunnel"
            )
        }

        if #available(iOS 13.0, *) {
            let available = os_proc_available_memory()
            let availableMB = Double(available) / 1_048_576.0
            if availableMB < 20.0 && now.timeIntervalSince(lastAvailableMemoryWarningAt) >= Self.memoryDiagnosticsInterval {
                lastAvailableMemoryWarningAt = now
                logger.warn(
                    "v5B-SYNC | Low available memory: \(String(format: "%.1f", availableMB))MB",
                    source: "Tunnel"
                )
            }
        }

        if let reportedMemoryMB {
            logger.debug("v5D-SYNC | Shared NE memory snapshot stored: \(Int(reportedMemoryMB.rounded()))MB", source: "Tunnel")
        }
    }

    // MARK: - Helpers

    private func lastError() -> String {
        if let err = ztlp_last_error() {
            return String(cString: err)
        }
        return "unknown error"
    }

    private func detectClientInterfaceType() -> UInt8 {
        let pathMonitor = NWPathMonitor()
        let pathSemaphore = DispatchSemaphore(value: 0)
        let monitorQueue = DispatchQueue(label: "com.ztlp.tunnel.path-monitor", qos: .utility)
        var detectedInterface: UInt8 = 0

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

        pathMonitor.start(queue: monitorQueue)
        _ = pathSemaphore.wait(timeout: .now() + 0.5)
        pathMonitor.cancel()

        return detectedInterface
    }

    private func interfaceTypeName(_ interfaceType: UInt8) -> String {
        switch interfaceType {
        case 1:
            return "cellular"
        case 2:
            return "wifi"
        case 3:
            return "wired"
        default:
            return "unknown"
        }
    }

    private func makeNSError(_ message: String) -> NSError {
        NSError(
            domain: "com.ztlp.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

extension PacketTunnelProvider: ZTLPTunnelConnectionDelegate {

    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveData data: Data, sequence: UInt64) {
        guard isTunnelActive else { return }

        markDataActivity()
        markUsefulRx(sequence: sequence, payloadLength: data.count)
        handleGatewayMuxPayload(data)
    }

    func tunnelConnection(_ connection: ZTLPTunnelConnection, didFailWithError error: Error) {
        logger.error("Tunnel connection failed: \(error.localizedDescription)", source: "Tunnel")
        if isTunnelActive {
            scheduleReconnect()
        }
    }

    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveAck sequence: UInt64) {
        // ACK received from gateway — good, connection is alive
        markDataActivity()

        // Phase A: shadow RTT / goodput observation. Feed the Rust
        // MuxEngine the cumulative ACK so it can release its shadow
        // inflight entries and sample RTT. Gated so non-instrumented
        // builds pay zero cost.
        if Self.useRttInstrumentation, let mux = rustMux {
            _ = ztlp_mux_observe_ack_cumulative(mux, sequence)
        }
    }

    // ── Phase A: RTT instrumentation helpers ───────────────────────────

    /// Install the shadow observe-sent hook on a freshly-assigned
    /// ZTLPTunnelConnection so every outbound DATA frame pipes its
    /// (data_seq, encoded_len) through the Rust MuxEngine. Called from
    /// both startTunnel and reconnect paths.
    ///
    /// Safe to call multiple times — installing a new closure replaces
    /// any prior one. The closure captures `self` weakly so a stale
    /// hook after tunnel teardown can't keep the provider alive.
    ///
    /// Also flips `useByteRwnd` on the connection (Phase B), and seeds
    /// the byte-window to the current Rust advertised value so the
    /// first V2 ACK out the door matches what the engine would emit
    /// via `build_ack_frame`.
    private func wireRttInstrumentationHook(on conn: ZTLPTunnelConnection) {
        // Phase B: tell the connection which ACK wire format to emit.
        conn.useByteRwnd = Self.useByteRwnd
        if Self.useByteRwnd, let mux = rustMux {
            // Mark that we're about to speak V2 so the Rust-side
            // advertised_window_bytes moves past the V1 floor for
            // logging. The gateway notes peer_uses_v2 when it
            // receives the first 0x10; this just keeps our local
            // diagnostic consistent.
            _ = ztlp_mux_note_peer_sent_v2(mux)
            let kb = ztlp_mux_advertised_window_kb(mux)
            if kb > 0 {
                conn.setAdvertisedWindowKb(kb)
            }
        }

        guard Self.useRttInstrumentation else {
            conn.onDataFrameSent = nil
            return
        }
        conn.onDataFrameSent = { [weak self] seq, encodedLen in
            guard let self = self, let mux = self.rustMux else { return }
            // encoded_len fits easily in u32 (frame size is ~1200 B max).
            _ = ztlp_mux_observe_sent(mux, seq, UInt32(min(encodedLen, Int(UInt32.max))))
        }
    }

    /// Log the current RTT/goodput/BDP snapshot at most once every
    /// `rttLogIntervalSeconds` seconds. Called from the 2s health tick.
    private func maybeLogRttSnapshot() {
        guard Self.useRttInstrumentation, let mux = rustMux else { return }
        let now = Date()
        if now.timeIntervalSince(lastRttLogAt) < 2.0 { return }
        var snap = ZtlpRttGoodputSnapshot(
            smoothed_rtt_ms: 0,
            rtt_var_ms: 0,
            min_rtt_ms: 0,
            latest_rtt_ms: 0,
            goodput_bps: 0,
            peak_goodput_bps: 0,
            bdp_kb: 0,
            samples_total: 0
        )
        let rc = ztlp_mux_rtt_goodput_snapshot(mux, &snap)
        if rc != 0 { return }
        lastRttLogAt = now
        // Only log when there's something interesting — avoids flooding
        // the log during pre-first-ACK startup.
        if snap.samples_total == 0 && snap.goodput_bps == 0 { return }
        let shadowDepth = ztlp_mux_shadow_inflight_len(mux)
        let peerV2 = ztlp_mux_peer_speaks_v2(mux) == 1 ? "yes" : "no"
        let advKb = ztlp_mux_advertised_window_kb(mux)
        // Phase D: autotune target + reason (null on V1-only sessions).
        let autoTargetKb = ztlp_mux_autotune_target_kb(mux)
        var reasonBuf = [UInt8](repeating: 0, count: 32)
        let reasonLen = reasonBuf.withUnsafeMutableBufferPointer { buf -> Int32 in
            ztlp_mux_autotune_reason(mux, buf.baseAddress, buf.count)
        }
        let autoReason: String = {
            guard reasonLen > 0 else { return "-" }
            let slice = reasonBuf.prefix(Int(reasonLen))
            return String(decoding: slice, as: UTF8.self)
        }()
        logger.info(
            "[rtt-bdp] srtt=\(snap.smoothed_rtt_ms)ms rttvar=\(snap.rtt_var_ms)ms min=\(snap.min_rtt_ms)ms latest=\(snap.latest_rtt_ms)ms goodput=\(snap.goodput_bps)bps peak=\(snap.peak_goodput_bps)bps bdp=\(snap.bdp_kb)KB samples=\(snap.samples_total) shadow_inflight=\(shadowDepth) v2=\(peerV2) adv_kb=\(advKb) auto_target_kb=\(autoTargetKb) auto_reason=\(autoReason)",
            source: "Tunnel"
        )
    }

    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveProbeResponse nonce: UInt64) {
        guard isTunnelActive else { return }
        logger.info("Session health probe response nonce=\(nonce)", source: "Tunnel")
        if Self.useRustHealth, let health = rustHealth {
            _ = ztlp_health_on_pong(health, nonce)
        }
        handleProbeSuccess(nonce: nonce)
    }
}
