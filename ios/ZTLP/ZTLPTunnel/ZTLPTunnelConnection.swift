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
    case data = 0x00
    case ack  = 0x01
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
}

// MARK: - ZTLPTunnelConnection

/// Manages the NWConnection (UDP) to the ZTLP gateway and handles
/// encrypt/decrypt via sync FFI calls. No tokio runtime needed.
final class ZTLPTunnelConnection {

    private let logger = TunnelLogger.shared

    // MARK: - Properties

    /// The underlying UDP connection to the gateway.
    private var connection: NWConnection?

    /// Crypto context extracted after handshake (owns session keys).
    private let cryptoContext: OpaquePointer

    /// Gateway endpoint address string (e.g., "34.219.64.205:23095").
    let gatewayAddress: String

    /// Dedicated serial queue for all connection I/O and state.
    private let queue: DispatchQueue

    /// Delegate for delivering decrypted payloads.
    weak var delegate: ZTLPTunnelConnectionDelegate?

    /// Whether the connection is active and receiving.
    private var isActive = false

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

    /// Backpressure: track in-flight NWConnection sends.
    private var sendsInFlight: Int = 0
    private static let maxSendsInFlight = 512

    /// Reusable decrypt buffer (avoids repeated allocation).
    /// Max ZTLP packet is ~1500 bytes; 4KB is generous.
    private static let bufferSize = 4096

    /// Reusable encrypt output buffer.
    private var encryptBuffer = [UInt8](repeating: 0, count: bufferSize)

    /// Reusable decrypt output buffer.
    private var decryptBuffer = [UInt8](repeating: 0, count: bufferSize)

    /// Reusable frame build buffer.
    private var frameBuffer = [UInt8](repeating: 0, count: bufferSize)

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

    // MARK: - Initialization

    /// Create a tunnel connection.
    ///
    /// - Parameters:
    ///   - cryptoContext: Opaque crypto context from ztlp_connect_sync() or
    ///                    ztlp_crypto_context_extract(). Ownership is transferred
    ///                    to this class — it will be freed on deinit.
    ///   - gatewayAddress: Gateway "host:port" string.
    ///   - queue: Dispatch queue for all I/O (caller should use a dedicated serial queue).
    init(cryptoContext: OpaquePointer, gatewayAddress: String, queue: DispatchQueue) {
        self.cryptoContext = cryptoContext
        self.gatewayAddress = gatewayAddress
        self.queue = queue
    }

    deinit {
        stop()
        ztlp_crypto_context_free(cryptoContext)
    }

    // MARK: - Lifecycle

    /// Start the UDP connection and begin receiving.
    func start() {
        guard !isActive else { return }

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

        // Start the connection on our dedicated queue
        conn.start(queue: queue)
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
        guard isActive, let conn = connection else { return false }

        // Step 1: Frame the payload as FRAME_DATA
        let seq = nextSendSequence()
        var frameWritten: Int = 0

        let frameResult = payload.withUnsafeBytes { payloadPtr -> Int32 in
            guard let baseAddr = payloadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return ztlp_frame_data(
                baseAddr,
                payloadPtr.count,
                &frameBuffer,
                frameBuffer.count,
                &frameWritten,
                seq
            )
        }

        guard frameResult == 0, frameWritten > 0 else {
            return false
        }

        // Step 2: Encrypt the framed data
        var encryptWritten: Int = 0
        let encryptResult = ztlp_encrypt_packet(
            cryptoContext,
            &frameBuffer,
            frameWritten,
            &encryptBuffer,
            encryptBuffer.count,
            &encryptWritten
        )

        guard encryptResult == 0, encryptWritten > 0 else {
            return false
        }

        // Step 3: Send via NWConnection
        let wireData = Data(bytes: encryptBuffer, count: encryptWritten)
        guard sendsInFlight < Self.maxSendsInFlight else { return false }
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
        flushPendingAcks()
    }

    /// Flush pending ACKs as a single cumulative ACK (highest seq).
    func flushPendingAcks() {
        guard isActive, let conn = connection, !pendingAcks.isEmpty else { return }
        guard sendsInFlight < Self.maxSendsInFlight else {
            // Do NOT drop pending ACKs under backpressure — keep them queued and
            // retry on the next flush. Dropping ACKs causes gateway-side stalls.
            return
        }

        guard let maxSeq = pendingAcks.max() else { return }
        pendingAcks.removeAll(keepingCapacity: true)

        var ackWritten: Int = 0
        let ackResult = ztlp_build_ack(maxSeq, &frameBuffer, frameBuffer.count, &ackWritten)
        guard ackResult == 0, ackWritten > 0 else { return }

        var encryptWritten: Int = 0
        let encryptResult = ztlp_encrypt_packet(
            cryptoContext, &frameBuffer, ackWritten,
            &encryptBuffer, encryptBuffer.count, &encryptWritten
        )
        guard encryptResult == 0, encryptWritten > 0 else { return }

        let wireData = Data(bytes: encryptBuffer, count: encryptWritten)
        sendsInFlight += 1
        conn.send(content: wireData, completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            self.sendsInFlight -= 1
            if let error = error {
                self.logger.error("ZTLP ACK send failed: \(error)", source: "Tunnel")
            } else {
                self.logger.debug("ZTLP ACK sent seq=\(maxSeq) bytes=\(encryptWritten) inflight=\(self.sendsInFlight)", source: "Tunnel")
            }
        })
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
        guard let cStr = ztlp_crypto_context_session_id(cryptoContext) else {
            return nil
        }
        return String(cString: cStr)
    }

    /// The peer address from the crypto context.
    var peerAddress: String? {
        guard let cStr = ztlp_crypto_context_peer_addr(cryptoContext) else {
            return nil
        }
        return String(cString: cStr)
    }

    // MARK: - Connection State Handler

    private func handleConnectionState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            // Connection is ready — start the receive loop
            startReceiveLoop()

        case .failed(let error):
            isActive = false
            delegate?.tunnelConnection(self, didFailWithError: error)

        case .cancelled:
            isActive = false

        case .waiting(let error):
            // Network path not available yet — NWConnection will retry
            _ = error  // Could log for debugging

        default:
            break
        }
    }

    // MARK: - Receive Loop

    /// Start the recursive receive loop using NWConnection.receiveMessage().
    /// Each call to receiveMessage() delivers one complete UDP datagram.
    private func startReceiveLoop() {
        guard isActive, let conn = connection else { return }

        conn.receiveMessage { [weak self] content, _, isComplete, error in
            guard let self = self, self.isActive else { return }

            if let error = error {
                // Check if this is a cancellation (expected on stop)
                if case NWError.posix(let code) = error, code == .ECANCELED {
                    return
                }
                self.delegate?.tunnelConnection(self, didFailWithError: error)
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
            logger.error("ZTLP decrypt failed rc=\(decryptResult) wire=\(wireData.count)", source: "Tunnel")
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

        // Send ACK immediately
        logger.debug("ZTLP RX data seq=\(sequence) payload=\(payload?.count ?? 0)", source: "Tunnel")
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