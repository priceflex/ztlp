// ZTLPVIPProxy.swift
// ZTLPTunnel (Network Extension)
//
// Native Swift VIP proxy replacing the tokio-based TcpListener in the Rust
// library. Accepts TCP connections on 127.0.0.1:port via NWListener and
// bridges them to ZTLP mux streams through the sync crypto path.
//
// Architecture:
//   App → TCP connect 127.0.0.1:8080 → NWListener accepts → NWConnection
//     → read data → ztlp_frame_data() → ztlp_encrypt_packet() → sendPacket()
//   Gateway response → ztlp_decrypt_packet() → ztlp_parse_frame()
//     → deliverData() → NWConnection write → App receives HTTP response
//
// This avoids spinning up tokio TcpListeners in the extension process,
// saving ~2-3 MB of memory in the 15 MB-limited Network Extension.

import Foundation
import Network

/// Callback for sending encrypted ZTLP packets to the gateway.
/// The VIP proxy calls this with fully encrypted wire bytes.
typealias VIPSendPacket = (Data) -> Void

/// A registered VIP service (name + port).
private struct VIPService {
    let name: String
    let port: UInt16
}

/// Tracks an active TCP client connection and its associated stream state.
private final class VIPConnection {
    let id: UInt64
    let connection: NWConnection
    let serviceName: String
    var dataSeq: UInt64 = 0
    var isActive: Bool = true

    init(id: UInt64, connection: NWConnection, serviceName: String) {
        self.id = id
        self.connection = connection
        self.serviceName = serviceName
    }
}

/// Native Swift VIP proxy for the ZTLP Network Extension.
///
/// Replaces the Rust tokio-based VIP proxy (ztlp_vip_start/stop) with
/// NWListener instances bound to 127.0.0.1. Each accepted TCP connection
/// is bridged to the ZTLP tunnel via the sync crypto context.
final class ZTLPVIPProxy {

    // MARK: - Properties

    /// Serial queue for all proxy operations.
    private let queue = DispatchQueue(label: "com.ztlp.vip-proxy", qos: .userInitiated)

    /// Registered services (before start).
    private var services: [VIPService] = []

    /// Active NWListeners, keyed by port.
    private var listeners: [UInt16: NWListener] = [:]

    /// Port → service name mapping for routing accepted connections.
    private var portServiceMap: [UInt16: String] = [:]

    /// Active client connections, keyed by connection ID.
    private var connections: [UInt64: VIPConnection] = [:]

    /// Monotonic connection ID counter.
    private var nextConnectionId: UInt64 = 1

    /// Crypto context for encrypt/decrypt (set after handshake).
    private var cryptoCtx: OpaquePointer?  // ZtlpCryptoContext*

    /// Callback to send encrypted packets to the gateway.
    private var sendPacket: VIPSendPacket?

    /// Whether the proxy is running.
    private(set) var isRunning = false

    /// Logger reference.
    private let logger = TunnelLogger.shared

    /// Reusable frame buffer (avoids per-call allocation in forwardToGateway).
    private var frameBuf = [UInt8](repeating: 0, count: 16500)
    /// Reusable encrypt buffer.
    private var pktBuf = [UInt8](repeating: 0, count: 16700)

    // MARK: - Configuration

    /// Register a service to proxy. Call before start().
    ///
    /// - Parameters:
    ///   - name: ZTLP service name (e.g., "vault")
    ///   - port: TCP port to listen on (e.g., 8080)
    func addService(name: String, port: UInt16) {
        services.append(VIPService(name: name, port: port))
    }

    // MARK: - Lifecycle

    /// Start all VIP proxy listeners.
    ///
    /// - Parameters:
    ///   - cryptoContext: Sync crypto context from ztlp_connect_sync or ztlp_crypto_context_extract.
    ///   - sendHandler: Callback to send encrypted ZTLP packets to the gateway.
    func start(cryptoContext: OpaquePointer, sendHandler: @escaping VIPSendPacket) throws {
        self.cryptoCtx = cryptoContext
        self.sendPacket = sendHandler

        for svc in services {
            let params = NWParameters.tcp
            params.requiredLocalEndpoint = NWEndpoint.hostPort(
                host: .ipv4(.loopback),
                port: NWEndpoint.Port(rawValue: svc.port)!
            )
            // Allow address reuse for quick restart
            params.allowLocalEndpointReuse = true

            let listener: NWListener
            do {
                listener = try NWListener(using: params)
            } catch {
                logger.error("VIP: Failed to create listener on port \(svc.port): \(error)", source: "VIP")
                throw error
            }

            portServiceMap[svc.port] = svc.name

            listener.stateUpdateHandler = { [weak self] state in
                self?.handleListenerState(port: svc.port, state: state)
            }

            listener.newConnectionHandler = { [weak self] conn in
                self?.handleNewConnection(conn, port: svc.port)
            }

            listener.start(queue: queue)
            listeners[svc.port] = listener
            logger.info("VIP: Listener started on 127.0.0.1:\(svc.port) → \(svc.name)", source: "VIP")
        }

        isRunning = true
    }

    /// Stop all listeners and close all connections.
    func stop() {
        isRunning = false

        for (port, listener) in listeners {
            listener.cancel()
            logger.info("VIP: Listener stopped on port \(port)", source: "VIP")
        }
        listeners.removeAll()

        for (_, conn) in connections {
            conn.isActive = false
            conn.connection.cancel()
        }
        connections.removeAll()

        cryptoCtx = nil
        sendPacket = nil
        portServiceMap.removeAll()
        services.removeAll()

        logger.info("VIP: Proxy stopped", source: "VIP")
    }

    // MARK: - Listener Handling

    private func handleListenerState(port: UInt16, state: NWListener.State) {
        switch state {
        case .ready:
            logger.info("VIP: Listener ready on port \(port)", source: "VIP")
        case .failed(let error):
            logger.error("VIP: Listener failed on port \(port): \(error)", source: "VIP")
            // Attempt restart after brief delay
            queue.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                guard let self = self, self.isRunning else { return }
                self.listeners[port]?.cancel()
                self.listeners.removeValue(forKey: port)
                // Re-register would need full restart; log for now
                self.logger.warn("VIP: Listener on port \(port) not restarted (requires proxy restart)", source: "VIP")
            }
        case .cancelled:
            break
        default:
            break
        }
    }

    // MARK: - Connection Handling

    private func handleNewConnection(_ nwConn: NWConnection, port: UInt16) {
        guard isRunning else {
            nwConn.cancel()
            return
        }

        guard let serviceName = portServiceMap[port] else {
            logger.warn("VIP: No service for port \(port), rejecting", source: "VIP")
            nwConn.cancel()
            return
        }

        let connId = nextConnectionId
        nextConnectionId += 1

        let conn = VIPConnection(id: connId, connection: nwConn, serviceName: serviceName)
        connections[connId] = conn

        logger.info("VIP: Accepted connection #\(connId) on port \(port) → \(serviceName)", source: "VIP")

        nwConn.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.handleConnectionState(connId: connId, state: state)
            }
        }

        nwConn.start(queue: queue)
    }

    private func handleConnectionState(connId: UInt64, state: NWConnection.State) {
        switch state {
        case .ready:
            // Connection established — start reading data from client
            startReading(connId: connId)

        case .failed(let error):
            logger.warn("VIP: Connection #\(connId) failed: \(error)", source: "VIP")
            closeConnection(connId: connId)

        case .cancelled:
            closeConnection(connId: connId)

        default:
            break
        }
    }

    private func closeConnection(connId: UInt64) {
        guard let conn = connections.removeValue(forKey: connId) else { return }
        conn.isActive = false
        conn.connection.cancel()
    }

    // MARK: - Data Flow: Client → Gateway

    /// Read loop for a client TCP connection. Reads data, frames it,
    /// encrypts it, and sends to the gateway.
    private func startReading(connId: UInt64) {
        guard let conn = connections[connId], conn.isActive else { return }

        conn.connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) {
            [weak self] content, _, isComplete, error in
            guard let self = self else { return }

            self.queue.async {
                if let data = content, !data.isEmpty {
                    self.forwardToGateway(connId: connId, data: data)
                }

                if isComplete {
                    self.closeConnection(connId: connId)
                    return
                }

                if let error = error {
                    self.logger.warn("VIP: Read error on #\(connId): \(error)", source: "VIP")
                    self.closeConnection(connId: connId)
                    return
                }

                // Continue reading
                self.startReading(connId: connId)
            }
        }
    }

    /// Encrypt client data and send to gateway via the send callback.
    private func forwardToGateway(connId: UInt64, data: Data) {
        guard let conn = connections[connId], conn.isActive,
              let ctx = cryptoCtx, let send = sendPacket else { return }

        // Step 1: Frame the payload (FRAME_DATA envelope)
        // Ensure reusable buffers are large enough
        let neededFrame = data.count + 16
        if frameBuf.count < neededFrame { frameBuf = [UInt8](repeating: 0, count: neededFrame) }
        var frameLen: Int = 0
        let seq = conn.dataSeq
        conn.dataSeq += 1

        let frameResult = data.withUnsafeBytes { ptr -> Int32 in
            ztlp_frame_data(
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                data.count,
                &frameBuf, frameBuf.count,
                &frameLen,
                seq
            )
        }

        guard frameResult == 0 else {
            logger.warn("VIP: frame_data failed (\(frameResult)) for #\(connId)", source: "VIP")
            return
        }

        // Step 2: Encrypt the framed data
        let neededPkt = frameLen + 128
        if pktBuf.count < neededPkt { pktBuf = [UInt8](repeating: 0, count: neededPkt) }
        var pktLen: Int = 0

        let encResult = ztlp_encrypt_packet(
            ctx,
            &frameBuf, frameLen,
            &pktBuf, pktBuf.count,
            &pktLen
        )

        guard encResult == 0 else {
            logger.warn("VIP: encrypt failed (\(encResult)) for #\(connId)", source: "VIP")
            return
        }

        // Step 3: Send encrypted packet to gateway
        send(Data(pktBuf[..<pktLen]))
    }

    // MARK: - Data Flow: Gateway → Client

    /// Deliver decrypted payload data to the appropriate client connection.
    ///
    /// Called by the tunnel connection handler when a ZTLP data frame
    /// arrives from the gateway and is destined for a VIP proxy stream.
    ///
    /// - Parameters:
    ///   - connId: The VIP connection ID to deliver to.
    ///   - data: Decrypted payload bytes.
    func deliverData(connId: UInt64, data: Data) {
        queue.async { [weak self] in
            guard let self = self,
                  let conn = self.connections[connId],
                  conn.isActive else { return }

            conn.connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    self.logger.warn("VIP: Write error on #\(connId): \(error)", source: "VIP")
                    self.queue.async {
                        self.closeConnection(connId: connId)
                    }
                }
            })
        }
    }

    /// Deliver decrypted data to all connections for a given service.
    /// Used when we don't have per-stream routing yet (single-stream mode).
    ///
    /// - Parameters:
    ///   - serviceName: Target service name.
    ///   - data: Decrypted payload bytes.
    func deliverData(serviceName: String, data: Data) {
        queue.async { [weak self] in
            guard let self = self else { return }
            for (_, conn) in self.connections where conn.serviceName == serviceName && conn.isActive {
                conn.connection.send(content: data, completion: .contentProcessed { error in
                    if let error = error {
                        self.logger.warn("VIP: Write error on #\(conn.id): \(error)", source: "VIP")
                        self.queue.async {
                            self.closeConnection(connId: conn.id)
                        }
                    }
                })
            }
        }
    }

    // MARK: - Diagnostics

    /// Number of active client connections.
    var activeConnectionCount: Int {
        return connections.count
    }

    /// Active listener ports.
    var activePorts: [UInt16] {
        return Array(listeners.keys).sorted()
    }
}