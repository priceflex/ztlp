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

/// App Group identifier shared between the main app and this extension.
private let appGroupId = "group.com.ztlp.shared"

/// UDP port used for relay communication.
private let defaultRelayPort: UInt16 = 4433

/// NS record type for RELAY records.
private let NS_RECORD_TYPE_RELAY: UInt8 = 3

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

    /// DNS responder for *.ztlp queries (answers directly on utun, no tokio).
    private var dnsResponder: ZTLPDNSResponder?

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
    private static let maxRouterActionsPerCycle: Int = 64
    private static let maxPacketsPerReadCycle: Int = 32
    private static let maxOutboundPacketsPerFlush: Int = 64

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

                try self.startPacketRouter(services: services)

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

            // Stop DNS responder
            self.dnsResponder = nil
            self.logger.info("DNS responder stopped", source: "Tunnel")

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

            if !packets.isEmpty && packets.count > 1 {
                self.logger.debug("readPacketLoop: received \(packets.count) packet(s)", source: "Tunnel")
            }

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
            self.flushOutboundPackets(maxPackets: Self.maxOutboundPacketsPerFlush)

            self.readPacketLoop()
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
                logger.debug("Router: OpenStream stream=\(streamId) service=\(String(data: serviceData, encoding: .utf8) ?? "?")", source: "Router")
                if tunnelConnection?.sendData(muxOpen) != true {
                    logger.warn("Router: OpenStream backpressured for stream \(streamId)", source: "Router")
                    return
                }

            case 1: // SendData
                guard let payload = actionData else { continue }
                var muxData = Data(capacity: 5 + payload.count)
                muxData.append(Self.MUX_FRAME_DATA)
                muxData.append(contentsOf: beStreamIdBytes(streamId))
                muxData.append(payload)
                logger.debug("Router: SendData stream=\(streamId) bytes=\(payload.count)", source: "Router")
                if tunnelConnection?.sendData(muxData) != true {
                    logger.warn("Router: SendData backpressured for stream \(streamId) bytes=\(payload.count)", source: "Router")
                    return
                }

            case 2: // CloseStream
                var muxClose = Data(capacity: 5)
                muxClose.append(Self.MUX_FRAME_CLOSE)
                muxClose.append(contentsOf: beStreamIdBytes(streamId))
                logger.debug("Router: CloseStream stream=\(streamId)", source: "Router")
                if tunnelConnection?.sendData(muxClose) != true {
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
            logger.debug("GW->NE mux DATA stream=\(streamId) bytes=\(payload.count)", source: "Tunnel")
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
            logger.debug("GW->NE mux CLOSE stream=\(streamId)", source: "Tunnel")
            ztlp_router_gateway_close_sync(router, streamId)

        default:
            logger.debug("GW->NE legacy payload bytes=\(data.count)", source: "Tunnel")
            data.withUnsafeBytes { ptr in
                guard let baseAddr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                ztlp_router_gateway_data_sync(router, 0, baseAddr, ptr.count)
            }
        }

        flushOutboundPackets()
    }

    private func beStreamIdBytes(_ streamId: UInt32) -> [UInt8] {
        withUnsafeBytes(of: streamId.bigEndian) { Array($0) }
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

            if shouldThrottleRouterWork() {
                break
            }
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

        // Re-query NS for fresh relay list if pool needs refresh
        // Check if we need NS refresh before selecting
        if let pool = relayPool, ztlp_relay_pool_needs_refresh(pool) {
            logger.info("Relay pool stale, re-querying NS for refresh", source: "Relay")
            discoverRelays(config: config)
        }

        // Select next best relay from pool
        let svcName = config.serviceName ?? "vault"
        guard let relayAddr = selectRelay(config: config) else {
            logger.error("No relay available for reconnect", source: "Relay")
            scheduleReconnect()
            return
        }

        logger.info("Reconnecting via relay \(relayAddr)...", source: "Relay")
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
        handshakeSemaphore.wait()

        if let handshakeError = handshakeError {
            conn.stop()
            // Report this relay as failed and retry
            if let pool = relayPool {
                relayAddr.withCString { ztlp_relay_pool_report_failure(pool, $0) }
            }
            logger.warn("Reconnect to \(relayAddr) failed: \(handshakeError.localizedDescription), will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        tunnelConnection = conn

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
        logger.info("Reconnected successfully via relay \(relayAddr)", source: "Tunnel")
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

    private func logMemoryDiagnostics() {
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
            sharedDefaults?.set(Int(residentMB.rounded()), forKey: SharedKey.neMemoryMB)
            sharedDefaults?.set(Int(virtualMB.rounded()), forKey: SharedKey.neVirtualMB)

            if residentMB > 18.0 {
                logger.warn(
                    "v5D-SYNC | Memory HIGH — resident=\(String(format: "%.1f", residentMB))MB virtual=\(String(format: "%.1f", virtualMB))MB",
                    source: "Tunnel"
                )
            } else {
                logger.debug(
                    "v5D-SYNC | Memory resident=\(String(format: "%.1f", residentMB))MB virtual=\(String(format: "%.1f", virtualMB))MB",
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
    }
}