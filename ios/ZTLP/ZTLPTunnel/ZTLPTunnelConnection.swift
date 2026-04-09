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
    private static let maxSeenSequences = 10_000

    /// Highest seen sequence (for pruning old entries).
    private var highestSeenSequence: UInt64 = 0

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

        connection?.cancel()
        connection = nil

        seenSequences.removeAll()
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
        conn.send(content: wireData, completion: .contentProcessed { [weak self] error in
            if let error = error {
                // Log but don't fail — UDP is best-effort
                _ = error  // Suppress unused warning; real impl would log
            } else {
                self?.bytesSent += UInt64(encryptWritten)
                self?.packetsSent += 1
            }
        })

        return true
    }

    /// Send an ACK for a received data sequence.
    ///
    /// - Parameter sequence: The data sequence number to acknowledge.
    func sendAck(for sequence: UInt64) {
        guard isActive, let conn = connection else { return }

        // Step 1: Build ACK frame
        var ackWritten: Int = 0
        let ackResult = ztlp_build_ack(
            sequence,
            &frameBuffer,
            frameBuffer.count,
            &ackWritten
        )

        guard ackResult == 0, ackWritten > 0 else { return }

        // Step 2: Encrypt the ACK frame
        var encryptWritten: Int = 0
        let encryptResult = ztlp_encrypt_packet(
            cryptoContext,
            &frameBuffer,
            ackWritten,
            &encryptBuffer,
            encryptBuffer.count,
            &encryptWritten
        )

        guard encryptResult == 0, encryptWritten > 0 else { return }

        // Step 3: Send via NWConnection
        let wireData = Data(bytes: encryptBuffer, count: encryptWritten)
        conn.send(content: wireData, completion: .contentProcessed { _ in })
    }

    /// Send a raw pre-encrypted packet (e.g., keepalive already built by caller).
    func sendRaw(_ data: Data) {
        guard isActive, let conn = connection else { return }
        conn.send(content: data, completion: .contentProcessed { [weak self] error in
            if error == nil {
                self?.bytesSent += UInt64(data.count)
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

    /// Process a received UDP datagram: decrypt → parse frame → dispatch.
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
            // Decryption failed — could be replay, corruption, or wrong key.
            // Drop silently (normal for UDP — stale/replayed packets).
            return
        }

        packetsReceived += 1

        // Step 2: Parse the frame to get type, sequence, and payload.
        // We use the decryptBuffer directly (class property — stable address)
        // and copy payload data inside the unsafe scope to avoid dangling pointers.
        var frameType: UInt8 = 0xFF
        var seq: UInt64 = 0
        var payloadPtr: UnsafePointer<UInt8>? = nil
        var payloadLen: Int = 0

        let parseResult = ztlp_parse_frame(
            &decryptBuffer,
            decryptWritten,
            &frameType,
            &seq,
            &payloadPtr,
            &payloadLen
        )

        guard parseResult == 0 else {
            // Malformed frame — drop
            return
        }

        // Copy payload data immediately (payloadPtr points into decryptBuffer
        // which may be overwritten on next receive)
        var payloadData: Data? = nil
        if let ptr = payloadPtr, payloadLen > 0 {
            payloadData = Data(bytes: ptr, count: payloadLen)
        }

        // Step 3: Dispatch based on frame type
        switch frameType {
        case ZTLPFrameType.data.rawValue:
            handleDataFrame(sequence: seq, payload: payloadData)

        case ZTLPFrameType.ack.rawValue:
            delegate?.tunnelConnection(self, didReceiveAck: seq)

        default:
            // Unknown frame type — ignore (forward compatibility)
            break
        }
    }

    /// Handle a FRAME_DATA: duplicate check, ACK, deliver to delegate.
    private func handleDataFrame(sequence: UInt64, payload: Data?) {
        // Duplicate detection
        if seenSequences.contains(sequence) {
            duplicatesDropped += 1
            // Still send ACK for duplicates (sender may have missed our first ACK)
            sendAck(for: sequence)
            return
        }

        // Track this sequence
        recordSequence(sequence)

        // Send ACK immediately
        sendAck(for: sequence)

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
