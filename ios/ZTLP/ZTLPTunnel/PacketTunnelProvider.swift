// PacketTunnelProvider.swift
// ZTLPTunnel (Network Extension)
//
// Session 5B: Tokio-free architecture.
// Uses sync FFI (ztlp_connect_sync, ztlp_encrypt_packet, etc.) and
// standalone PacketRouter — no tokio runtime, no ZTLPBridge dependency.
//
// Architecture:
//   Identity + Config → ztlp_connect_sync() → ZtlpCryptoContext
//   ZTLPTunnelConnection (NWConnection UDP) handles encrypt/decrypt via context
//   ZTLPVIPProxy (NWListener TCP) bridges 127.0.0.1:port → ZTLP mux
//   Standalone PacketRouter (ztlp_router_*_sync) handles utun ↔ ZTLP routing
//
// Memory: TEXT segment ~1.65 MB (down from 4.7 MB with tokio).

import NetworkExtension
import Network
import Foundation
import CoreTelephony

/// App Group identifier shared between the main app and this extension.
private let appGroupId = "group.com.ztlp.shared"

/// UserDefaults keys for shared state.
private enum SharedKey {
    static let connectionState = "ztlp_connection_state"
    static let connectedSince = "ztlp_connected_since"
    static let bytesSent = "ztlp_bytes_sent"
    static let bytesReceived = "ztlp_bytes_received"
    static let peerAddress = "ztlp_peer_address"
    static let lastError = "ztlp_last_error"
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

    /// The resolved gateway address (for reconnects).
    private var resolvedGateway: String?

    /// The tunnel configuration (cached for reconnects).
    private var currentConfig: TunnelConfiguration?

    /// Current reconnect attempt counter.
    private var reconnectAttempt = 0

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

    /// The native VIP proxy (replaces tokio TcpListener).
    private var vipProxy: ZTLPVIPProxy?

    /// Standalone packet router handle (replaces ZtlpClient-based router).
    private var packetRouter: OpaquePointer?  // ZtlpPacketRouter*

    /// Keepalive timer.
    private var keepaliveTimer: DispatchSourceTimer?

    /// Periodic timer to flush outbound packets from the router.
    private var writePacketTimer: DispatchSourceTimer?

    /// ACK flush timer (10ms for low-latency ACKs).
    private var ackFlushTimer: DispatchSourceTimer?

    /// Action buffer for router write results (reusable, 256KB for large uploads).
    private var actionBuffer = [UInt8](repeating: 0, count: 262144)

    // MARK: - Mux Frame Constants
    private static let MUX_FRAME_DATA: UInt8 = 0x00
    private static let MUX_FRAME_OPEN: UInt8 = 0x06
    private static let MUX_FRAME_CLOSE: UInt8 = 0x05
    private static let MAX_MUX_PAYLOAD: Int = 1135  // 1140 - 5 byte mux header

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

    private var isDataActive: Bool {
        return Date().timeIntervalSince(lastDataActivity) < Self.activityGracePeriod
    }

    // MARK: - NEPacketTunnelProvider Overrides

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        updateConnectionState(.connecting)
        logger.info("═══════════════════════════════════════════", source: "Tunnel")
        logger.info("ZTLP NE v5C — SYNC ARCHITECTURE (no tokio)", source: "Tunnel")
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

                // Step 4: NS resolution
                let target = try self.resolveGateway(config: config, svcName: svcName)
                self.resolvedGateway = target

                // Step 5: Set client profile for CC selection
                // Detect interface type from NWPathMonitor (Network framework)
                let interfaceType: UInt8 = {
                    let monitor = NWPathMonitor()
                    let currentPath = monitor.currentPath
                    monitor.cancel()
                    if currentPath.usesInterfaceType(.cellular) {
                        return 1  // Cellular
                    } else if currentPath.usesInterfaceType(.wifi) {
                        return 2  // WiFi
                    } else if currentPath.usesInterfaceType(.wiredEthernet) {
                        return 3  // Wired
                    } else {
                        return 0  // Unknown
                    }
                }()

                var radioTech: UInt8 = 0  // Unknown
                let teleInfo = CTTelephonyNetworkInfo()
                if let radioAccess = teleInfo.serviceCurrentRadioAccessTechnology?.values.first {
                    switch radioAccess {
                    case CTRadioAccessTechnologyGPRS, CTRadioAccessTechnologyEdge:
                        radioTech = 1  // 2G
                    case CTRadioAccessTechnologyWCDMA, CTRadioAccessTechnologyHSDPA, CTRadioAccessTechnologyHSUPA:
                        radioTech = 2  // 3G
                    case CTRadioAccessTechnologyLTE:
                        radioTech = 3  // LTE
                    default:
                        if radioAccess.contains("NR") {
                            radioTech = 4  // 5G
                        }
                    }
                }

                let isConstrained: UInt8 = {
                    let monitor = NWPathMonitor()
                    let constrained = monitor.currentPath.isConstrained
                    monitor.cancel()
                    return constrained ? 1 : 0
                }()
                self.logger.info("Client profile: iface=\(interfaceType) radio=\(radioTech) constrained=\(isConstrained)", source: "Tunnel")
                ztlp_set_client_profile(interfaceType, radioTech, isConstrained)

                // Step 6: Sync connect (blocking, no tokio)
                self.logger.info("Connecting to \(target) via ztlp_connect_sync...", source: "Tunnel")

                let cryptoCtx = target.withCString { targetCStr -> OpaquePointer? in
                    return ztlp_connect_sync(identityPtr, cfgPtr, targetCStr, 20000)
                }

                guard let cryptoCtx = cryptoCtx else {
                    throw self.makeNSError("ztlp_connect_sync failed: \(self.lastError())")
                }

                self.logger.info("Connected to \(target)", source: "Tunnel")

                // Step 6: Create ZTLPTunnelConnection (NWConnection UDP)
                let conn = ZTLPTunnelConnection(
                    cryptoContext: cryptoCtx,
                    gatewayAddress: target,
                    queue: self.tunnelQueue
                )
                conn.delegate = self
                conn.start()
                self.tunnelConnection = conn

                // Step 7: Start standalone packet router
                let services: [(vip: String, name: String)] = [
                    ("10.122.0.2", svcName),
                    ("10.122.0.3", "http"),
                ]
                try self.startPacketRouter(services: services)

                // Step 8: Start VIP proxy (NWListener on 127.0.0.1)
                // Note: VIP proxy needs its own crypto context or shares the
                // tunnel connection for sending. We route through tunnelConnection.
                let proxy = ZTLPVIPProxy()
                proxy.addService(name: svcName, port: 8080)
                proxy.addService(name: svcName, port: 8443)
                try proxy.start(cryptoContext: cryptoCtx, sendHandler: { [weak self] data in
                    self?.tunnelConnection?.sendRaw(data)
                })
                self.vipProxy = proxy
                self.logger.info("VIP proxy started on 127.0.0.1:8080/8443", source: "Tunnel")

                // Step 9: Apply tunnel network settings
                let remoteAddr = config.relayAddress ?? target
                let tunSettings = self.createTunnelNetworkSettings(
                    tunnelRemoteAddress: remoteAddr,
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

                // Step 10: Start timers and finalize
                self.isTunnelActive = true
                self.connectedSince = Date()
                self.reconnectAttempt = 0
                self.consecutiveKeepaliveFailures = 0
                self.lastDataActivity = Date()
                self.startKeepaliveTimer()
                self.startWritePacketTimer()
                self.startAckFlushTimer()

                // Update shared state
                self.updateConnectionState(.connected)
                self.sharedDefaults?.set(
                    Date().timeIntervalSince1970,
                    forKey: SharedKey.connectedSince
                )
                self.sharedDefaults?.set(target, forKey: SharedKey.peerAddress)

                self.logger.info("═══════════════════════════════════════════", source: "Tunnel")
                self.logger.info("TUNNEL ACTIVE — v5C SYNC (no tokio)", source: "Tunnel")
                self.logger.info("TEXT seg: 1.65MB | Crypto: sync FFI", source: "Tunnel")
                self.logger.info("Router: standalone | VIP: NWListener", source: "Tunnel")
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

            // Stop VIP proxy
            self.vipProxy?.stop()
            self.vipProxy = nil
            self.logger.info("VIP proxy stopped", source: "Tunnel")

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
            self.resolvedGateway = nil
            self.currentConfig = nil
            self.sharedDefaults?.removeObject(forKey: SharedKey.connectedSince)
            self.sharedDefaults?.removeObject(forKey: SharedKey.peerAddress)
            self.sharedDefaults?.removeObject(forKey: SharedKey.lastError)
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

        // Start the utun packet I/O loop
        startPacketLoop()
    }

    private func startPacketLoop() {
        logger.info("Starting packet I/O loop", source: "Tunnel")
        readPacketLoop()
    }

    /// Recursive readPackets loop: utun → standalone router → ZTLP
    private func readPacketLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isTunnelActive, let router = self.packetRouter else { return }

            for (i, packet) in packets.enumerated() {
                let proto = protocols[i]
                if proto.intValue == AF_INET {
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
                        self.processRouterActions(
                            actionBuffer: self.actionBuffer,
                            actionLen: actionWritten
                        )
                    }
                }
            }

            if !packets.isEmpty {
                self.markDataActivity()
            }

            // Flush outbound response packets immediately
            self.flushOutboundPackets()

            // Continue reading
            self.readPacketLoop()
        }
    }

    /// Parse and dispatch serialized RouterActions from the standalone router.
    /// Format: [1B type][4B stream_id BE][2B data_len BE][data...]
    /// Type: 0=OpenStream, 1=SendData, 2=CloseStream
    ///
    /// Each action is re-framed as a ZTLP mux frame before sending to gateway:
    ///   OpenStream  -> [0x06 | stream_id(4 BE) | svc_name_len(1) | svc_name]
    ///   SendData    -> [0x00 | stream_id(4 BE) | chunk...] (chunked to 1135 bytes)
    ///   CloseStream -> [0x05 | stream_id(4 BE)]
    private func processRouterActions(actionBuffer: [UInt8], actionLen: Int) {
        var offset = 0
        while offset < actionLen {
            guard offset + 7 <= actionLen else { break }  // min: 1+4+2 = 7 bytes

            let actionType = actionBuffer[offset]
            offset += 1

            // Keep stream_id as raw bytes for mux framing
            let streamIdBytes: [UInt8] = [
                actionBuffer[offset],
                actionBuffer[offset+1],
                actionBuffer[offset+2],
                actionBuffer[offset+3]
            ]
            offset += 4

            let dataLen = Int(actionBuffer[offset]) << 8
                | Int(actionBuffer[offset+1])
            offset += 2

            guard offset + dataLen <= actionLen else { break }

            let actionData: Data? = dataLen > 0 ? Data(actionBuffer[offset..<(offset+dataLen)]) : nil
            offset += dataLen

            switch actionType {
            case 0: // OpenStream -> mux FRAME_OPEN
                // [0x06 | stream_id(4 BE) | svc_name_len(1) | svc_name]
                if let svcData = actionData {
                    var frame = Data(capacity: 6 + svcData.count)
                    frame.append(Self.MUX_FRAME_OPEN)
                    frame.append(contentsOf: streamIdBytes)
                    frame.append(UInt8(min(svcData.count, 255)))
                    frame.append(svcData)
                    tunnelConnection?.sendData(frame)
                }
            case 1: // SendData -> mux FRAME_DATA (chunked to MAX_MUX_PAYLOAD)
                // [0x00 | stream_id(4 BE) | chunk...]
                if let payload = actionData {
                    var chunkOffset = 0
                    while chunkOffset < payload.count {
                        let chunkEnd = min(chunkOffset + Self.MAX_MUX_PAYLOAD, payload.count)
                        let chunk = payload[chunkOffset..<chunkEnd]
                        var frame = Data(capacity: 5 + chunk.count)
                        frame.append(Self.MUX_FRAME_DATA)
                        frame.append(contentsOf: streamIdBytes)
                        frame.append(chunk)
                        tunnelConnection?.sendData(frame)
                        chunkOffset = chunkEnd
                    }
                }
            case 2: // CloseStream -> mux FRAME_CLOSE
                // [0x05 | stream_id(4 BE)]
                var frame = Data(capacity: 5)
                frame.append(Self.MUX_FRAME_CLOSE)
                frame.append(contentsOf: streamIdBytes)
                tunnelConnection?.sendData(frame)
            default:
                logger.warn("Unknown router action type: \(actionType)", source: "Tunnel")
            }
        }
    }

    /// Write response packets from the router back to the utun interface.
    private func flushOutboundPackets() {
        guard let router = packetRouter else { return }

        var packets: [Data] = []
        var protocols: [NSNumber] = []

        // Drain all available outbound packets
        while true {
            let bytesRead = ztlp_router_read_packet_sync(
                router,
                &readPacketBuffer,
                readPacketBuffer.count
            )
            if bytesRead <= 0 { break }

            packets.append(Data(readPacketBuffer[0..<Int(bytesRead)]))
            protocols.append(NSNumber(value: AF_INET))
        }

        if !packets.isEmpty {
            markDataActivity()
            packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    private func startWritePacketTimer() {
        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(5))
        timer.setEventHandler { [weak self] in
            guard let self = self, self.isTunnelActive else { return }
            self.flushOutboundPackets()
        }
        timer.resume()
        writePacketTimer = timer
    }

    private func stopWritePacketTimer() {
        writePacketTimer?.cancel()
        writePacketTimer = nil
    }

    /// Flush batched ACKs every 10ms for low latency without per-packet overhead.
    private func startAckFlushTimer() {
        ackFlushTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now() + .milliseconds(10), repeating: .milliseconds(10))
        timer.setEventHandler { [weak self] in
            self?.tunnelConnection?.flushPendingAcks()
        }
        timer.resume()
        ackFlushTimer = timer
    }

    // MARK: - NS Resolution (sync, no bridge)

    private func resolveGateway(config: TunnelConfiguration, svcName: String) throws -> String {
        // NOTE: ztlp_ns_resolve is tokio-gated and unavailable in ios-sync builds.
        // In sync mode, we use the targetNodeId directly (which contains the gateway
        // address from the app config, e.g., "34.219.64.205:23095").
        // TODO: Add ztlp_ns_resolve_sync or implement NS resolution in Swift.
        var target = ""

        let fallback = config.targetNodeId
        if fallback.contains(":") {
            target = fallback
            logger.info("Using gateway address: \(target)", source: "Tunnel")
        }

        guard !target.isEmpty else {
            throw makeNSError("Could not resolve gateway address. Ensure targetNodeId is set to host:port.")
        }

        return target
    }

    // MARK: - Reconnect

    private func scheduleReconnect() {
        guard isTunnelActive else { return }

        reconnectAttempt += 1

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

        logger.info("Reconnect attempt \(reconnectAttempt)/\(Self.maxReconnectAttempts) in \(String(format: "%.1f", finalDelay))s", source: "Tunnel")
        updateConnectionState(.reconnecting)

        tunnelQueue.asyncAfter(deadline: .now() + finalDelay) { [weak self] in
            guard let self = self, self.isTunnelActive else { return }
            self.attemptReconnect()
        }
    }

    private func attemptReconnect() {
        guard let identityPtr = identity else {
            logger.error("Identity lost during reconnect", source: "Tunnel")
            cancelTunnelWithError(makeNSError("Identity lost during reconnect"))
            return
        }

        // Stop old tunnel connection
        tunnelConnection?.stop()
        tunnelConnection = nil

        // Re-resolve gateway
        let config = currentConfig ?? (try? loadTunnelConfiguration())
        guard let config = config else {
            logger.error("Failed to load config for reconnect", source: "Tunnel")
            scheduleReconnect()
            return
        }

        let svcName = config.serviceName ?? "vault"
        var target = resolvedGateway ?? ""

        // NS resolution unavailable in sync build — use cached gateway address
        if target.isEmpty {
            let fallback = config.targetNodeId
            if fallback.contains(":") {
                target = fallback
            }
        }

        guard !target.isEmpty else {
            logger.warn("No gateway target for reconnect, will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        // Build config for reconnect
        let cfgPtr = ztlp_config_new()
        defer { if let c = cfgPtr { ztlp_config_free(c) } }

        if let cfgPtr = cfgPtr {
            if let relay = config.relayAddress, !relay.isEmpty {
                relay.withCString { ztlp_config_set_relay(cfgPtr, $0) }
            }
            ztlp_config_set_nat_assist(cfgPtr, true)
            ztlp_config_set_timeout_ms(cfgPtr, 15000)
            if !svcName.isEmpty {
                svcName.withCString { ztlp_config_set_service(cfgPtr, $0) }
            }
        }

        // Reconnect (blocking sync)
        let cryptoCtx = target.withCString { targetCStr -> OpaquePointer? in
            return ztlp_connect_sync(identityPtr, cfgPtr, targetCStr, 15000)
        }

        guard let cryptoCtx = cryptoCtx else {
            logger.warn("Reconnect failed: \(lastError()), will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        // Create new tunnel connection
        let conn = ZTLPTunnelConnection(
            cryptoContext: cryptoCtx,
            gatewayAddress: target,
            queue: tunnelQueue
        )
        conn.delegate = self
        conn.start()
        tunnelConnection = conn

        // Update VIP proxy send handler
        // (VIP proxy stays running — listeners are stable)

        // Success
        reconnectAttempt = 0
        consecutiveKeepaliveFailures = 0
        lastDataActivity = Date()
        logger.info("Reconnected successfully to \(target)", source: "Tunnel")
        updateConnectionState(.connected)
        sharedDefaults?.set(
            Date().timeIntervalSince1970,
            forKey: SharedKey.connectedSince
        )
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
                self.logger.debug(
                    "Keepalive send failed (\(self.consecutiveKeepaliveFailures)/\(Self.keepaliveFailureThreshold))",
                    source: "Tunnel"
                )

                if self.consecutiveKeepaliveFailures >= Self.keepaliveFailureThreshold
                    && !self.isDataActive
                    && self.isTunnelActive {
                    self.logger.warn(
                        "Connection appears dead — \(self.consecutiveKeepaliveFailures) keepalive failures, no data for \(String(format: "%.0f", Date().timeIntervalSince(self.lastDataActivity)))s",
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

        let dns = NEDNSSettings(servers: ["127.0.55.53"])
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

    private func logMemoryDiagnostics() {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        if result == KERN_SUCCESS {
            let residentMB = Double(info.resident_size) / 1_048_576.0
            let virtualMB = Double(info.virtual_size) / 1_048_576.0
            if residentMB > 10.0 {
                logger.warn(
                    "v5B-SYNC | Memory HIGH — resident=\(String(format: "%.1f", residentMB))MB virtual=\(String(format: "%.1f", virtualMB))MB (NE limit ~15MB)",
                    source: "Tunnel"
                )
            } else {
                logger.debug(
                    "v5B-SYNC | Memory resident=\(String(format: "%.1f", residentMB))MB virtual=\(String(format: "%.1f", virtualMB))MB",
                    source: "Tunnel"
                )
            }
        }

        if #available(iOS 13.0, *) {
            let available = os_proc_available_memory()
            let availableMB = Double(available) / 1_048_576.0
            if availableMB < 50.0 {
                logger.warn(
                    "v5B-SYNC | Low available memory: \(String(format: "%.1f", availableMB))MB",
                    source: "Tunnel"
                )
            }
        }
    }

    // MARK: - Helpers

    private func lastError() -> String {
        if let err = ztlp_last_error() {
            return String(cString: err)
        }
        return "unknown error"
    }

    private func makeNSError(_ message: String) -> NSError {
        NSError(
            domain: "com.ztlp.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

// MARK: - ZTLPTunnelConnectionDelegate

extension PacketTunnelProvider: ZTLPTunnelConnectionDelegate {

    func tunnelConnection(_ connection: ZTLPTunnelConnection, didReceiveData data: Data, sequence: UInt64) {
        guard isTunnelActive, let router = packetRouter else { return }

        markDataActivity()

        // The decrypted payload is a mux frame from the gateway.
        // Demux it and feed the inner data to the correct router stream.
        //
        // Mux frame formats (inner payload after tunnel FRAME_DATA stripped):
        //   FRAME_DATA:  [0x00 | stream_id(4 BE) | http_data...]
        //   FRAME_CLOSE: [0x05 | stream_id(4 BE)]
        //   FRAME_FIN:   [0x04 | stream_id(4 BE)]
        //
        // Legacy (non-mux) format: just raw http_data (no mux header)

        data.withUnsafeBytes { ptr in
            guard let baseAddr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            let len = ptr.count

            if len >= 5 {
                let frameType = baseAddr[0]

                if frameType == 0x00 {
                    // Mux FRAME_DATA: [0x00 | stream_id(4 BE) | payload...]
                    let streamId = UInt32(baseAddr[1]) << 24
                        | UInt32(baseAddr[2]) << 16
                        | UInt32(baseAddr[3]) << 8
                        | UInt32(baseAddr[4])

                    if streamId > 0 {
                        // Multiplexed data
                        let payloadPtr = baseAddr + 5
                        let payloadLen = len - 5
                        if payloadLen > 0 {
                            ztlp_router_gateway_data_sync(router, streamId, payloadPtr, payloadLen)
                        }
                    } else {
                        // stream_id 0 = legacy format, entire data is payload
                        ztlp_router_gateway_data_sync(router, 0, baseAddr, len)
                    }
                } else if frameType == 0x05 || frameType == 0x04 {
                    // Mux FRAME_CLOSE / FRAME_FIN: [type | stream_id(4 BE)]
                    let streamId = UInt32(baseAddr[1]) << 24
                        | UInt32(baseAddr[2]) << 16
                        | UInt32(baseAddr[3]) << 8
                        | UInt32(baseAddr[4])
                    ztlp_router_gateway_close_sync(router, streamId)
                } else {
                    // Unknown type or legacy — treat as raw data for stream 0
                    ztlp_router_gateway_data_sync(router, 0, baseAddr, len)
                }
            } else if len > 0 {
                // Short payload — legacy format, feed as stream 0
                ztlp_router_gateway_data_sync(router, 0, baseAddr, len)
            }
        }

        // Immediately flush any generated packets
        flushOutboundPackets()
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
    }
}