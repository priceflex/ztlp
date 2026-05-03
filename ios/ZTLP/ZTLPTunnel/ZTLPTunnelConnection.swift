// ZTLPTunnelConnection.swift
// ZTLPTunnel (Network Extension)
//
// Manages the UDP connection to the ZTLP gateway using NWConnection.
// Replaces the tokio-based recv/send loop with a purely Swift approach
// that calls sync FFI functions (ztlp_encrypt_packet, ztlp_decrypt_packet,
// ztlp_frame_data, ztlp_parse_frame, ztlp_build_ack) for packet processing.
//
// Architecture:
//   NWConnection (UDP) <-> encrypt/decrypt (sync FFI) <-> frame parse/build
//
// This runs entirely on a dedicated DispatchQueue with no tokio runtime,
// keeping memory usage well within the iOS Network Extension ~15MB limit.

import Foundation
import Network

// MARK: - Frame Type Constants

/// ZTLP frame types (matches wire protocol).
private enum ZTLPFrameType: UInt8 {
    case data  = 0x00
    case ack   = 0x01
    case ping  = 0x07
    case pong  = 0x08
    /// Phase B: byte-unit (KB) receive-window ACK.
    /// `[0x10 | cumulative_ack(8 BE) | window_kb(2 BE)]` — 11 bytes.
    case ackV2 = 0x10
}

// MARK: - Delegate Protocol

/// Delegate for receiving decrypted data frames from the tunnel connection.
protocol ZTLPTunnelConnectionDelegate: AnyObject {
    /// Called when a decrypted data payload arrives from the gateway.
    /// The payload is the inner content after frame parsing (no frame header).
    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveData data: Data, sequence: UInt64)

    /// Called when the connection encounters an unrecoverable error.
    func tunnelConnection(_ connection: ZTLPTunnelConnection, didFailWithError error: Error)

    /// Called when an ACK is received for a previously sent data sequence.
    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveAck sequence: UInt64)

    /// Called when a session-health probe response is received.
    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveProbeResponse nonce: UInt64)
}

// MARK: - ZTLPTunnelConnection

/// Manages the NWConnection (UDP) to the ZTLP gateway and handles
/// encrypt/decrypt via sync FFI calls. No tokio runtime needed.
final class ZTLPTunnelConnection {

    private let logger = TunnelLogger.shared
    private let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared")

    // MARK: - Properties

    /// The underlying UDP connection to the gateway.
    private var connection: NWConnection?

    /// Crypto context extracted after handshake (owns session keys).
    private var cryptoContext: OpaquePointer?

    /// Gateway endpoint address string (e.g., "34.219.64.205:23095").
    let gatewayAddress: String

    /// Dedicated serial queue for tunnel state / caller coordination.
    private let queue: DispatchQueue

    /// Separate NWConnection callback queue so PacketTunnelProvider can synchronously
    /// wait for handshake completion on tunnelQueue without deadlocking Network callbacks.
    private let nwQueue = DispatchQueue(label: "com.ztlp.tunnel.connection.nw")

    /// Delegate for delivering decrypted payloads.
    weak var delegate: ZTLPTunnelConnectionDelegate?

    /// Optional hook fired once a DATA frame has been framed (encoded
    /// plaintext, pre-encryption) and handed to the NWConnection send
    /// path. Receives (data_seq, encoded_len). Used by
    /// PacketTunnelProvider to feed the Rust MuxEngine's shadow RTT
    /// observation path (`ztlp_mux_observe_sent`). Nil by default so
    /// non-NE consumers don't pay any overhead.
    var onDataFrameSent: ((UInt64, Int) -> Void)?

    /// Whether the connection is active and receiving.
    private var isActive = false

    /// Ensures one underlying NWConnection failure produces one delegate callback.
    private var didReportFailure = false

    /// Monotonically increasing data sequence for outbound frames.
    private var sendSequence: UInt64 = 0

    /// Set of received data sequences for duplicate detection.
    /// Bounded to prevent unbounded memory growth in the NE.
    private var seenSequences = Set<UInt64>()

    /// Maximum number of seen sequences to track before pruning.
    /// At ~8 bytes per UInt64 + Set overhead, 10K entries ≈ ~160KB.
    private static let maxSeenSequences = 2_000

    /// Highest seen sequence (for pruning old entries).
    private var highestSeenSequence: UInt64 = 0

    /// Pending ACK sequences to batch-send. Reduces NWConnection queue pressure.
    private var pendingAcks: [UInt64] = []
    private static let maxPendingAcks = 64

    /// Receive window advertised to the gateway. Keep this extremely conservative
    /// for iOS browser/page-load traffic until the NE survives Vaultwarden bursts.
    private var advertisedReceiveWindow: UInt16 = 4

    /// Phase B: when true, `flushPendingAcks` emits FRAME_ACK_V2 (byte-unit
    /// KB window) instead of FRAME_ACK (frame-count). Settable by
    /// PacketTunnelProvider during tunnel setup. Starts false so an old
    /// client build can't regress wire compatibility.
    var useByteRwnd: Bool = false

    /// Byte-unit window to advertise in V2 ACKs (KB). Read by
    /// `flushPendingAcks` when `useByteRwnd == true`. Settable via
    /// `setAdvertisedWindowKb`. Default 16 KB matches the Rust
    /// `DEFAULT_INITIAL_WINDOW_KB`.
    private var advertisedWindowKb: UInt16 = 16

    /// Backpressure: track in-flight NWConnection sends.
    private var sendsInFlight: Int = 0
    private static let maxSendsInFlight = 512
    private var lastOverloadLogAt: Date = .distantPast

    /// Reusable decrypt buffer (avoids repeated allocation).
    /// Max ZTLP packet is ~1500 bytes; 4KB is generous.
    private static let bufferSize = 4096

    /// Reusable decrypt output buffer. Only touched by the NW receive callback queue.
    private var decryptBuffer = [UInt8](repeating: 0, count: bufferSize)

    /// Statistics: total bytes sent over the wire.
    private(set) var bytesSent: UInt64 = 0

    /// Statistics: total bytes received over the wire.
    private(set) var bytesReceived: UInt64 = 0

    /// Statistics: packets decrypted successfully.
    private(set) var packetsReceived: UInt64 = 0

    /// Statistics: packets sent.
    private(set) var packetsSent: UInt64 = 0

    /// Statistics: duplicate packets dropped.
    private(set) var duplicatesDropped: UInt64 = 0

    /// Count of anti-replay rejections from duplicate gateway retransmits.
    private(set) var replayRejectedCount: UInt64 = 0

    /// Hot-path diagnostics are aggregated instead of logged per packet.
    private var rxSummaryLastLogAt: Date = .distantPast
    private var rxSummaryPackets: UInt64 = 0
    private var rxSummaryPayloadBytes: UInt64 = 0
    private var rxSummaryAckCount: UInt64 = 0
    private var rxSummaryHighestSeq: UInt64 = 0
    private var rxSummaryReplayCount: UInt64 = 0

    // MARK: - Initialization

    /// Create a tunnel connection.
    ///
    /// - Parameters:
    ///   - cryptoContext: Opaque crypto context from ztlp_connect_sync() or
    ///                    ztlp_crypto_context_extract(). Ownership is transferred
    ///                    to this class — it will be freed on deinit.
    ///   - gatewayAddress: Gateway "host:port" string.
    ///   - queue: Dispatch queue for all I/O (caller should use a dedicated serial queue).
    init(cryptoContext: OpaquePointer? = nil, gatewayAddress: String, queue: DispatchQueue) {
        self.cryptoContext = cryptoContext
        self.gatewayAddress = gatewayAddress
        self.queue = queue
    }

    deinit {
        stop()
        if let cryptoContext {
            ztlp_crypto_context_free(cryptoContext)
        }
    }

    // MARK: - Lifecycle

    /// Simple receive helper for handshake mode. Delivers a single UDP datagram.
    private func receiveOnce(timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) {
        guard isActive, let conn = connection else {
            completion(.failure(makeError("Connection not active")))
            return
        }

        var finished = false
        let timeoutWork = DispatchWorkItem { [weak self] in
            guard let self = self, !finished else { return }
            finished = true
            completion(.failure(self.makeError("Handshake receive timeout")))
        }
        nwQueue.asyncAfter(deadline: .now() + timeout, execute: timeoutWork)

        conn.receiveMessage { [weak self] content, _, _, error in
            guard let self = self, self.isActive, !finished else { return }
            finished = true
            timeoutWork.cancel()

            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = content, !data.isEmpty else {
                completion(.failure(self.makeError("Received empty handshake datagram")))
                return
            }
            completion(.success(data))
        }
    }

    func performHandshake(
        identity: OpaquePointer,
        config: OpaquePointer?,
        target: String,
        timeoutMs: UInt32 = 20_000,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard isActive else {
            completion(.failure(makeError("Connection not started")))
            return
        }
        guard cryptoContext == nil else {
            completion(.success(()))
            return
        }

        let overallDeadline = Date().addingTimeInterval(TimeInterval(timeoutMs) / 1000.0)
        let msgBufferSize = 8192
        let receiveSlice: TimeInterval = 1.0
        var msg1 = [UInt8](repeating: 0, count: msgBufferSize)
        var msg1Written = 0

        let handshakeState: OpaquePointer? = target.withCString { targetCStr in
            ztlp_handshake_start(identity, config, targetCStr, &msg1, msg1.count, &msg1Written)
        }

        guard let handshakeState else {
            completion(.failure(makeError("ztlp_handshake_start failed: \(ztlpLastError())")))
            return
        }

        let sendMsg1 = { [weak self] in
            guard let self = self, let conn = self.connection else { return }
            let data = Data(msg1.prefix(msg1Written))
            conn.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    completion(.failure(error))
                }
            })
        }

        func finishFailure(_ error: Error) {
            ztlp_handshake_free(handshakeState)
            completion(.failure(error))
        }

        func awaitMsg2(retries: Int, retryDelay: TimeInterval) {
            if Date() >= overallDeadline {
                finishFailure(makeError("Handshake timed out waiting for HELLO_ACK"))
                return
            }

            self.receiveOnce(timeout: min(receiveSlice, max(0.05, overallDeadline.timeIntervalSinceNow))) { [weak self] result in
                guard let self = self else { return }
                switch result {
                case .success(let msg2Data):
                    var msg3 = [UInt8](repeating: 0, count: msgBufferSize)
                    var msg3Written = 0
                    let rc = msg2Data.withUnsafeBytes { msg2Ptr -> Int32 in
                        guard let base = msg2Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
                        return ztlp_handshake_process_msg2(
                            handshakeState,
                            base,
                            msg2Ptr.count,
                            &msg3,
                            msg3.count,
                            &msg3Written
                        )
                    }
                    guard rc == 0 else {
                        finishFailure(self.makeError("ztlp_handshake_process_msg2 failed: \(self.ztlpLastError())"))
                        return
                    }

                    let msg3Data = Data(msg3.prefix(msg3Written))
                    self.connection?.send(content: msg3Data, completion: .contentProcessed { error in
                        if let error = error {
                            finishFailure(error)
                            return
                        }

                        let cryptoCtx = ztlp_handshake_finalize(handshakeState, nil, 0)
                        guard let cryptoCtx else {
                            finishFailure(self.makeError("ztlp_handshake_finalize failed: \(self.ztlpLastError())"))
                            return
                        }

                        self.cryptoContext = cryptoCtx
                        self.startReceiveLoop()
                        completion(.success(()))
                    })

                case .failure:
                    guard retries < 6 else {
                        finishFailure(self.makeError("Handshake failed: no HELLO_ACK after retransmits"))
                        return
                    }
                    sendMsg1()
                    self.queue.asyncAfter(deadline: .now() + retryDelay) {
                        awaitMsg2(retries: retries + 1, retryDelay: min(retryDelay * 2, 1.6))
                    }
                }
            }
        }

        sendMsg1()
        awaitMsg2(retries: 0, retryDelay: 0.1)
    }

    /// Start the UDP connection and begin receiving.
    func start() {
        guard !isActive else { return }
        didReportFailure = false

        // Parse host:port from gateway address
        guard let (host, port) = parseHostPort(gatewayAddress) else {
            let err = makeError("Invalid gateway address: \(gatewayAddress)")
            delegate?.tunnelConnection(self, didFailWithError: err)
            return
        }

        // Create NWConnection with UDP
        let params = NWParameters.udp
        params.requiredLocalEndpoint = nil  // Let the system choose
        // Set service class for real-time traffic
        params.serviceClass = .responsiveData

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )

        let conn = NWConnection(to: endpoint, using: params)
        conn.stateUpdateHandler = { [weak self] state in
            self?.handleConnectionState(state)
        }

        self.connection = conn
        self.isActive = true

        // Start the connection on a separate NW callback queue. This avoids a deadlock
        // when PacketTunnelProvider blocks tunnelQueue waiting for handshake completion.
        conn.start(queue: nwQueue)
    }

    /// Stop the connection and clean up.
    func stop() {
        guard isActive else { return }
        isActive = false

        flushPendingAcks()

        connection?.cancel()
        connection = nil

        seenSequences.removeAll()
        pendingAcks.removeAll()
    }

    // MARK: - Send Path

    /// Send a data payload to the gateway.
    ///
    /// Frames the payload with ztlp_frame_data(), encrypts with
    /// ztlp_encrypt_packet(), and sends via NWConnection.
    ///
    /// - Parameter payload: Raw data to send (e.g., mux stream data).
    /// - Returns: true on success, false on error.
    @discardableResult
    func sendData(_ payload: Data) -> Bool {
        guard let cryptoContext else { return false }
        guard isActive, let conn = connection else { return false }
        guard sendsInFlight < Self.maxSendsInFlight else {
            maybeLogOverload(context: "sendData")
            return false
        }

        // Build and encrypt from LOCAL buffers. sendData can be called from
        // PacketTunnelProvider's tunnelQueue while ACK/PONG paths run on the
        // NWConnection callback queue; shared frameBuffer/encryptBuffer races
        // corrupt packets under browser fan-out bursts.
        let seq = nextSendSequence()
        var localFrame = [UInt8](repeating: 0, count: Self.bufferSize)
        var frameWritten: Int = 0

        let frameResult = payload.withUnsafeBytes { payloadPtr -> Int32 in
            guard let baseAddr = payloadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return ztlp_frame_data(
                baseAddr,
                payloadPtr.count,
                &localFrame,
                localFrame.count,
                &frameWritten,
                seq
            )
        }

        guard frameResult == 0, frameWritten > 0 else {
            return false
        }

        // Phase A (modern flow control): shadow RTT / goodput hook.
        // Fires BEFORE encryption so the encoded_len we report matches
        // what the Rust engine's own encoded_len would have been. The
        // gateway's cumulative ACK is over data_seq, so this `seq` is
        // what ztlp_mux_observe_ack_cumulative releases later.
        onDataFrameSent?(seq, frameWritten)

        let plaintext = Array(localFrame.prefix(frameWritten))
        return sendEncryptedFrame(plaintext: plaintext, cryptoContext: cryptoContext, conn: conn)
    }

    @discardableResult
    func sendProbe(nonce: UInt64) -> Bool {
        guard let cryptoContext else { return false }
        guard isActive, let conn = connection else { return false }
        guard sendsInFlight < Self.maxSendsInFlight else {
            maybeLogOverload(context: "sendProbe")
            return false
        }

        // Build PING frame in a LOCAL buffer. All send paths use caller-owned
        // frame/encrypt storage so they are safe across tunnelQueue/nwQueue.
        var pingFrame = [UInt8](repeating: 0, count: 9)
        pingFrame[0] = ZTLPFrameType.ping.rawValue
        let nonceBE = nonce.bigEndian
        withUnsafeBytes(of: nonceBE) { rawPtr in
            for i in 0..<8 { pingFrame[1 + i] = rawPtr[i] }
        }

        return sendEncryptedFrame(plaintext: pingFrame, cryptoContext: cryptoContext, conn: conn)
    }

    /// Encrypt an arbitrary plaintext frame using a local buffer and send it.
    /// Uses caller-owned local storage so this is safe to call from any queue.
    @discardableResult
    private func sendEncryptedFrame(plaintext: [UInt8], cryptoContext: OpaquePointer, conn: NWConnection) -> Bool {
        var localEncrypt = [UInt8](repeating: 0, count: Self.bufferSize)
        var encryptWritten: Int = 0
        let rc = plaintext.withUnsafeBufferPointer { ptPtr -> Int32 in
            guard let base = ptPtr.baseAddress else { return -1 }
            return ztlp_encrypt_packet(
                cryptoContext,
                base,
                plaintext.count,
                &localEncrypt,
                localEncrypt.count,
                &encryptWritten
            )
        }
        guard rc == 0, encryptWritten > 0 else {
            return false
        }

        let wireData = Data(bytes: localEncrypt, count: encryptWritten)
        sendsInFlight += 1
        conn.send(content: wireData, completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            self.sendsInFlight -= 1
            if error == nil {
                self.bytesSent += UInt64(encryptWritten)
                self.packetsSent += 1
            }
        })
        return true
    }


    /// Queue an ACK for sending.
    ///
    /// Response-path reliability matters more than micro-batching here: if ACKs are
    /// delayed or dropped, the gateway stalls with its send window full. Flush on
    /// every received data frame from the same queue that processes inbound packets.
    func queueAck(for sequence: UInt64) {
        pendingAcks.append(sequence)
        rxSummaryAckCount += 1
        flushPendingAcks()
    }

    func setAdvertisedReceiveWindow(_ rwnd: UInt16) {
        advertisedReceiveWindow = min(max(rwnd, 4), 16)
    }

    /// Set the byte-unit window (KB) advertised in FRAME_ACK_V2 frames.
    /// Only used when `useByteRwnd == true`. Clamped to [1, 65535].
    func setAdvertisedWindowKb(_ kb: UInt16) {
        advertisedWindowKb = max(1, kb)
    }

    /// Flush pending ACKs as a single cumulative ACK (highest seq).
    var isOverloaded: Bool {
        sendsInFlight >= (Self.maxSendsInFlight - 32)
    }

    private func maybeLogOverload(context: String) {
        let now = Date()
        guard now.timeIntervalSince(lastOverloadLogAt) >= 1.0 else { return }
        lastOverloadLogAt = now
        logger.warn("ZTLP send overload in \(context): sendsInFlight=\(sendsInFlight)/\(Self.maxSendsInFlight)", source: "Tunnel")
    }

    func flushPendingAcks() {
        guard let cryptoContext else { return }
        guard isActive, let conn = connection, !pendingAcks.isEmpty else { return }
        guard sendsInFlight < Self.maxSendsInFlight else {
            // Do NOT drop pending ACKs under backpressure — keep them queued and
            // retry on the next flush. Dropping ACKs causes gateway-side stalls.
            maybeLogOverload(context: "flushPendingAcks")
            return
        }

        guard let maxSeq = pendingAcks.max() else { return }
        pendingAcks.removeAll(keepingCapacity: true)

        var ackFrame = [UInt8](repeating: 0, count: Self.bufferSize)
        var ackWritten: Int = 0

        let ackResult: Int32
        if useByteRwnd {
            // Phase B: emit FRAME_ACK_V2 with byte-unit (KB) window.
            // The gateway decodes 0x10 and converts back to packets via
            // `div(window_bytes, @max_payload_bytes)`. Setting this to
            // the iOS-side advertised byte-window (tracked in Rust
            // MuxEngine) matches the value the Rust engine would emit
            // via `build_ack_frame` once we do the full mux cutover.
            ackResult = ztlp_build_ack_v2(maxSeq, advertisedWindowKb, &ackFrame, ackFrame.count, &ackWritten)
        } else {
            // Legacy V1: packet-count window. Advertise a receive window
            // derived from actual NE/router pressure.
            let sendWindow = UInt16(max(4, min(Self.maxSendsInFlight - sendsInFlight, 8)))
            let availableWindow = min(advertisedReceiveWindow, sendWindow)
            ackResult = ztlp_build_ack_with_rwnd(maxSeq, availableWindow, &ackFrame, ackFrame.count, &ackWritten)
        }
        guard ackResult == 0, ackWritten > 0 else { return }

        let plaintext = Array(ackFrame.prefix(ackWritten))
        guard sendEncryptedFrame(plaintext: plaintext, cryptoContext: cryptoContext, conn: conn) else {
            logger.error("ZTLP ACK send failed before queueing", source: "Tunnel")
            return
        }
    }

    /// Send a raw pre-encrypted packet (e.g., keepalive already built by caller).
    func sendRaw(_ data: Data) {
        guard isActive, let conn = connection else { return }
        guard sendsInFlight < Self.maxSendsInFlight else { return }
        sendsInFlight += 1
        conn.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            self.sendsInFlight -= 1
            if error == nil {
                self.bytesSent += UInt64(data.count)
            }
        })
    }

    // MARK: - Session Info

    /// The session ID from the crypto context.
    var sessionId: String? {
        guard let cryptoContext,
              let cStr = ztlp_crypto_context_session_id(cryptoContext) else {
            return nil
        }
        return String(cString: cStr)
    }

    /// The peer address from the crypto context.
    var peerAddress: String? {
        guard let cryptoContext,
              let cStr = ztlp_crypto_context_peer_addr(cryptoContext) else {
            return nil
        }
        return String(cString: cStr)
    }

    // MARK: - Connection State Handler

    private func handleConnectionState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            // Connection is ready — caller decides when to start the receive loop.
            break

        case .failed(let error):
            isActive = false
            reportFailureOnce(error, source: "state.failed")

        case .cancelled:
            isActive = false

        case .waiting(let error):
            // Network path not available yet — NWConnection will retry
            _ = error  // Could log for debugging

        default:
            break
        }
    }

    private func reportFailureOnce(_ error: Error, source: String) {
        if didReportFailure {
            logger.debug("Ignoring duplicate tunnel failure from \(source): \(error.localizedDescription)", source: "Tunnel")
            return
        }
        didReportFailure = true
        logger.error("Tunnel connection failure source=\(source): \(error.localizedDescription)", source: "Tunnel")
        delegate?.tunnelConnection(self, didFailWithError: error)
    }

    // MARK: - Receive Loop

    /// Start the recursive receive loop using NWConnection.receiveMessage().
    /// Each call to receiveMessage() delivers one complete UDP datagram.
    func startReceiveLoop() {
        guard isActive, let conn = connection else { return }

        conn.receiveMessage { [weak self] content, _, isComplete, error in
            guard let self = self, self.isActive else { return }

            if let error = error {
                // Check if this is a cancellation (expected on stop)
                if case NWError.posix(let code) = error, code == .ECANCELED {
                    return
                }
                self.reportFailureOnce(error, source: "receiveMessage")
                return
            }

            if let data = content, !data.isEmpty {
                self.bytesReceived += UInt64(data.count)
                self.handleReceivedPacket(data)
            }

            // Continue receiving (recursive tail call on our queue)
            self.startReceiveLoop()
        }
    }

    // MARK: - Packet Processing

    /// Process a received UDP datagram: decrypt -> parse frame -> dispatch.
    ///
    /// Handles both legacy and multiplexed FRAME_DATA formats:
    ///   Legacy: [0x00 | data_seq(8 BE) | payload]
    ///   Mux:    [0x00 | stream_id(4 BE) | data_seq(8 BE) | mux_payload]
    ///   ACK:    [0x01 | cumulative_ack(8 BE) | ...]
    private func handleReceivedPacket(_ wireData: Data) {
        guard let cryptoContext else { return }

        // Step 1: Decrypt the packet
        var decryptWritten: Int = 0

        let decryptResult = wireData.withUnsafeBytes { wirePtr -> Int32 in
            guard let baseAddr = wirePtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return ztlp_decrypt_packet(
                cryptoContext,
                baseAddr,
                wirePtr.count,
                &decryptBuffer,
                decryptBuffer.count,
                &decryptWritten
            )
        }

        guard decryptResult == 0, decryptWritten > 0 else {
            if decryptResult == Int32(ZTLP_REPLAY_REJECTED) {
                replayRejectedCount += 1
                rxSummaryReplayCount += 1
                sharedDefaults?.set(Int(replayRejectedCount), forKey: "ztlp_replay_reject_count")
                maybeLogRxSummary(force: false)
            } else {
                logger.error(
                    "ZTLP decrypt failed rc=\(decryptResult) wire=\(wireData.count) detail=\(ztlpLastError())",
                    source: "Tunnel"
                )
            }
            return
        }

        packetsReceived += 1

        // Step 2: Parse frame manually to handle both mux and legacy formats.
        // We do this in Swift instead of ztlp_parse_frame to correctly detect
        // the multiplexed format where stream_id precedes data_seq.
        guard decryptWritten >= 1 else { return }

        let frameType = decryptBuffer[0]

        if frameType == ZTLPFrameType.ack.rawValue {
            // ACK frame: [0x01 | cumulative_ack(8 BE) | ...]
            guard decryptWritten >= 9 else { return }
            var seq: UInt64 = 0
            for i in 1...8 {
                seq = (seq << 8) | UInt64(decryptBuffer[i])
            }
            delegate?.tunnelConnection(self, didReceiveAck: seq)
            return
        }

        if frameType == ZTLPFrameType.ackV2.rawValue {
            // Phase B: FRAME_ACK_V2 [0x10 | cumulative_ack(8 BE) | window_kb(2 BE)].
            // The gateway does not currently emit V2 (gateway→client ACKs
            // stay on 0x01/SACK), but we decode it defensively so a future
            // symmetric upgrade doesn't need a coordinated client change.
            guard decryptWritten >= 11 else { return }
            var seq: UInt64 = 0
            for i in 1...8 {
                seq = (seq << 8) | UInt64(decryptBuffer[i])
            }
            // window_kb is informational for now — the rwnd ladder on the
            // iOS side is still packet-count driven. Future phases may
            // use it in the send-side congestion math.
            delegate?.tunnelConnection(self, didReceiveAck: seq)
            return
        }

        if frameType == ZTLPFrameType.ping.rawValue {
            guard decryptWritten >= 9 else { return }
            guard let conn = connection else { return }
            var nonce: UInt64 = 0
            for i in 1...8 {
                nonce = (nonce << 8) | UInt64(decryptBuffer[i])
            }

            // Build PONG in a LOCAL buffer. All send paths use caller-owned
            // frame/encrypt storage so they are safe across tunnelQueue/nwQueue.
            var pongFrame = [UInt8](repeating: 0, count: 9)
            pongFrame[0] = ZTLPFrameType.pong.rawValue
            let nonceBE = nonce.bigEndian
            withUnsafeBytes(of: nonceBE) { rawPtr in
                for i in 0..<8 { pongFrame[1 + i] = rawPtr[i] }
            }
            _ = sendEncryptedFrame(plaintext: pongFrame, cryptoContext: cryptoContext, conn: conn)
            return
        }

        if frameType == ZTLPFrameType.pong.rawValue {
            guard decryptWritten >= 9 else { return }
            var nonce: UInt64 = 0
            for i in 1...8 {
                nonce = (nonce << 8) | UInt64(decryptBuffer[i])
            }
            delegate?.tunnelConnection(self, didReceiveProbeResponse: nonce)
            return
        }

        if frameType == ZTLPFrameType.data.rawValue {
            // Detect mux vs legacy FRAME_DATA:
            // Mux:    [0x00 | stream_id(4 BE) | data_seq(8 BE) | payload] (13+ bytes, stream_id > 0)
            // Legacy: [0x00 | data_seq(8 BE) | payload] (9+ bytes)
            var seq: UInt64 = 0
            var payloadData: Data? = nil

            if decryptWritten >= 13 {
                // Check candidate stream_id
                let candidateStreamId = UInt32(decryptBuffer[1]) << 24
                    | UInt32(decryptBuffer[2]) << 16
                    | UInt32(decryptBuffer[3]) << 8
                    | UInt32(decryptBuffer[4])

                if candidateStreamId > 0 {
                    // Mux format: data_seq at bytes [5..13], payload at [13..]
                    for i in 5...12 {
                        seq = (seq << 8) | UInt64(decryptBuffer[i])
                    }
                    let payloadLen = decryptWritten - 13
                    if payloadLen > 0 {
                        // Check for mux sentinel payloads (CLOSE=0x05, FIN=0x04)
                        let firstByte = decryptBuffer[13]
                        if payloadLen <= 2 && (firstByte == 0x05 || firstByte == 0x04) {
                            // Mux CLOSE/FIN sentinel: build close frame for PTP demuxer
                            var muxFrame = Data(capacity: 5)
                            muxFrame.append(firstByte)  // 0x05 close or 0x04 fin
                            muxFrame.append(contentsOf: decryptBuffer[1...4])  // stream_id
                            payloadData = muxFrame
                        } else {
                            // Regular mux data: build [0x00 | stream_id(4) | http_data]
                            var muxFrame = Data(capacity: 5 + payloadLen)
                            muxFrame.append(0x00)  // mux data type
                            muxFrame.append(contentsOf: decryptBuffer[1...4])  // stream_id
                            muxFrame.append(contentsOf: decryptBuffer[13..<decryptWritten])
                            payloadData = muxFrame
                        }
                    }
                    handleDataFrame(sequence: seq, payload: payloadData)
                    return
                }
            }

            // Legacy format: data_seq at bytes [1..9], payload at [9..]
            guard decryptWritten >= 9 else { return }
            for i in 1...8 {
                seq = (seq << 8) | UInt64(decryptBuffer[i])
            }
            let payloadLen = decryptWritten - 9
            if payloadLen > 0 {
                payloadData = Data(decryptBuffer[9..<decryptWritten])
            }
            handleDataFrame(sequence: seq, payload: payloadData)
            return
        }

        // Unknown frame type -- use ztlp_parse_frame for forward compatibility
        var frameTypeOut: UInt8 = 0xFF
        var seq: UInt64 = 0
        var payloadPtr: UnsafePointer<UInt8>? = nil
        var payloadLen: Int = 0

        let parseResult = ztlp_parse_frame(
            &decryptBuffer,
            decryptWritten,
            &frameTypeOut,
            &seq,
            &payloadPtr,
            &payloadLen
        )

        guard parseResult == 0 else { return }

        if let ptr = payloadPtr, payloadLen > 0 {
            let data = Data(bytes: ptr, count: payloadLen)
            handleDataFrame(sequence: seq, payload: data)
        }
    }

    /// Handle a FRAME_DATA: duplicate check, ACK, deliver to delegate.
    private func handleDataFrame(sequence: UInt64, payload: Data?) {
        // Duplicate detection
        if seenSequences.contains(sequence) {
            duplicatesDropped += 1
            // Still send ACK for duplicates (sender may have missed our first ACK)
            queueAck(for: sequence)
            return
        }

        // Track this sequence
        recordSequence(sequence)

        // Send ACK immediately. Avoid per-packet disk logging in the NE hot path;
        // aggregate once per second instead.
        rxSummaryPackets += 1
        rxSummaryPayloadBytes += UInt64(payload?.count ?? 0)
        rxSummaryHighestSeq = max(rxSummaryHighestSeq, sequence)
        queueAck(for: sequence)

        // Deliver payload to delegate
        if let data = payload, !data.isEmpty {
            delegate?.tunnelConnection(self, didReceiveData: data, sequence: sequence)
        }
    }

    // MARK: - Sequence Tracking

    /// Record a seen sequence and prune old entries if needed.
    private func recordSequence(_ seq: UInt64) {
        seenSequences.insert(seq)

        if seq > highestSeenSequence {
            highestSeenSequence = seq
        }

        // Prune if set grows too large (keep recent half)
        if seenSequences.count > Self.maxSeenSequences {
            let cutoff = highestSeenSequence - UInt64(Self.maxSeenSequences / 2)
            seenSequences = seenSequences.filter { $0 >= cutoff }
        }
    }

    /// Get the next send sequence number (atomic increment).
    private func nextSendSequence() -> UInt64 {
        let seq = sendSequence
        sendSequence += 1
        return seq
    }

    private func maybeLogRxSummary(force: Bool) {
        let now = Date()
        guard force || now.timeIntervalSince(rxSummaryLastLogAt) >= 1.0 else { return }
        guard rxSummaryPackets > 0 || rxSummaryAckCount > 0 || rxSummaryReplayCount > 0 else { return }
        rxSummaryLastLogAt = now
        logger.debug(
            "ZTLP RX summary packets=\(rxSummaryPackets) payload=\(rxSummaryPayloadBytes)B acks=\(rxSummaryAckCount) replay=\(rxSummaryReplayCount) highSeq=\(rxSummaryHighestSeq) inflight=\(sendsInFlight)",
            source: "Tunnel"
        )
        rxSummaryPackets = 0
        rxSummaryPayloadBytes = 0
        rxSummaryAckCount = 0
        rxSummaryReplayCount = 0
    }

    // MARK: - Helpers

    /// Parse "host:port" string into components.
    private func parseHostPort(_ address: String) -> (String, UInt16)? {
        // Handle IPv6 [host]:port format
        if address.hasPrefix("[") {
            guard let closeBracket = address.firstIndex(of: "]") else { return nil }
            let host = String(address[address.index(after: address.startIndex)..<closeBracket])
            let afterBracket = address.index(after: closeBracket)
            guard afterBracket < address.endIndex,
                  address[afterBracket] == ":" else { return nil }
            let portStr = String(address[address.index(after: afterBracket)...])
            guard let port = UInt16(portStr) else { return nil }
            return (host, port)
        }

        // IPv4 host:port
        let parts = address.split(separator: ":", maxSplits: 1)
        guard parts.count == 2,
              let port = UInt16(parts[1]) else { return nil }
        return (String(parts[0]), port)
    }

    private func ztlpLastError() -> String {
        if let err = ztlp_last_error() {
            return String(cString: err)
        }
        return "unknown error"
    }

    /// Create an NSError for this domain.
    private func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.ztlp.tunnel.connection",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    // MARK: - Statistics Reset

    /// Reset all counters.
    func resetCounters() {
        bytesSent = 0
        bytesReceived = 0
        packetsSent = 0
        packetsReceived = 0
        duplicatesDropped = 0
    }
}