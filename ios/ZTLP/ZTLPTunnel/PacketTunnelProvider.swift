// PacketTunnelProvider.swift
// ZTLPTunnel (Network Extension)
//
// This is the core of the ZTLP VPN on iOS. It runs as a separate process
// managed by NetworkExtension.framework. The main app communicates with
// this extension via NETunnelProviderSession.sendProviderMessage().
//
// Architecture:
//   The extension uses ZTLPBridge to establish the ZTLP connection, then
//   starts a packet router on the 10.122.0.0/16 VIP subnet. Each service
//   gets a virtual IP (e.g., 10.122.0.2 = vault, 10.122.0.3 = http).
//   The utun interface captures IPv4 packets destined for VIPs, and the
//   Rust packet router handles TCP state + ZTLP mux stream routing.
//
//   A legacy VIP TCP proxy on 127.0.0.1:8080 is also started for backward
//   compatibility with HTTP benchmarks and tools using port-based addressing.
//
// Lifecycle:
//   1. iOS calls startTunnel() when the user toggles the VPN on.
//   2. We load the identity from the shared app group container.
//   3. Initialize ZTLPBridge, NS-resolve the gateway, connect.
//   4. Start VIP proxy (TCP listeners on 127.0.0.1:8080/8443).
//   5. Apply minimal NEPacketTunnelNetworkSettings (split tunnel, no routes).
//   6. Start keepalive timer.
//   7. Call completionHandler(nil) on success.
//   8. iOS calls stopTunnel() when user disconnects or system reclaims.
//
// App Group: group.com.ztlp.shared
//   - Identity file: identity.json in shared container
//   - UserDefaults: connection state for the main app to observe
//   - Log file: ztlp.log for shared logging

import NetworkExtension
import Foundation

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

    /// The ZTLPBridge singleton (separate instance in extension process).
    private let bridge = ZTLPBridge.shared

    /// Keepalive timer — sends keepalive pings to maintain the connection.
    private var keepaliveTimer: DispatchSourceTimer?

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

    // MARK: - NEPacketTunnelProvider Overrides

    /// Called by iOS when the VPN should start.
    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        updateConnectionState(.connecting)
        logger.info("Starting tunnel...", source: "Tunnel")

        tunnelQueue.async { [weak self] in
            guard let self = self else {
                completionHandler(self?.makeNSError("Provider deallocated") ?? NSError(
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

                // Step 2: Initialize bridge + identity
                if !self.bridge.hasClient {
                    self.logger.info("Initializing bridge and identity...", source: "Tunnel")
                    try self.bridge.initialize()

                    let identity = try self.loadOrCreateIdentity(config: config)

                    guard identity.nodeId != nil else {
                        throw self.makeNSError("Failed to get node ID from identity")
                    }
                    self.logger.info("Node ID: \(identity.nodeId ?? "unknown")", source: "Tunnel")

                    try self.bridge.createClient(identity: identity)
                    self.logger.info("Client created", source: "Tunnel")
                }

                // Step 3: Build config handle
                let configHandle = ZTLPConfigHandle()

                if let relay = config.relayAddress, !relay.isEmpty {
                    try configHandle.setRelay(relay)
                    self.logger.debug("Config: relay=\(relay)", source: "Tunnel")
                }

                try configHandle.setNatAssist(true)
                try configHandle.setTimeoutMs(60000)

                let svcName = config.serviceName ?? "vault"
                if !svcName.isEmpty {
                    try configHandle.setService(svcName)
                    self.logger.debug("Config: service=\(svcName)", source: "Tunnel")
                }

                // Step 4: NS resolution — resolve gateway address
                let target = try self.resolveGateway(config: config, svcName: svcName)
                self.resolvedGateway = target

                // Step 5: Connect via bridge
                if let relay = config.relayAddress, !relay.isEmpty {
                    self.logger.info("Connecting to gateway \(target) via relay \(relay)...", source: "Tunnel")
                } else {
                    self.logger.info("Connecting directly to \(target)...", source: "Tunnel")
                }

                // Bridge async connect → sync via semaphore
                let connectSemaphore = DispatchSemaphore(value: 0)
                var connectError: Error?

                Task.detached(priority: .userInitiated) {
                    do {
                        try await self.bridge.connect(target: target, config: configHandle)
                    } catch {
                        connectError = error
                    }
                    connectSemaphore.signal()
                }

                let waitResult = connectSemaphore.wait(timeout: .now() + 20)
                if waitResult == .timedOut {
                    throw self.makeNSError("Connection timed out")
                }
                if let err = connectError {
                    throw err
                }

                self.logger.info("Connected to \(target)", source: "Tunnel")

                // Step 6: Start packet router (VIP IP routing on 10.122.0.0/16)
                // Register services: each gets its own virtual IP on the tunnel subnet.
                // Apps connect to the VIP using standard ports (80, 443).
                let services: [(vip: String, name: String)] = [
                    ("10.122.0.2", svcName),           // Primary service (vault/default)
                    ("10.122.0.3", "http"),             // HTTP echo/web service
                ]
                try self.startPacketRouter(services: services)

                // Also start VIP proxy on 127.0.0.1 for backward compatibility
                // (HTTP benchmarks and tools that use port-based addressing)
                try self.startVipProxy(serviceName: svcName)

                // Step 7: Apply tunnel network settings (with packet router routes)
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

                // Step 8: Start keepalive timer
                self.isTunnelActive = true
                self.connectedSince = Date()
                self.reconnectAttempt = 0
                self.startKeepaliveTimer()

                // Step 9: Update shared state
                self.updateConnectionState(.connected)
                self.sharedDefaults?.set(
                    Date().timeIntervalSince1970,
                    forKey: SharedKey.connectedSince
                )
                self.sharedDefaults?.set(target, forKey: SharedKey.peerAddress)

                self.logger.info("Tunnel active — packet router on 10.122.0.0/16 + VIP proxy on 127.0.0.1:8080/8443", source: "Tunnel")
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

    /// Called by iOS when the VPN should stop.
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

            // Stop keepalive timer
            self.keepaliveTimer?.cancel()
            self.keepaliveTimer = nil

            // Stop packet router, write timer, VIP proxy, and DNS
            self.stopWritePacketTimer()
            self.bridge.routerStop()
            self.logger.info("Packet router stopped", source: "Tunnel")

            self.bridge.vipStop()
            self.logger.info("VIP proxy stopped", source: "Tunnel")

            self.bridge.dnsStop()
            self.logger.info("DNS resolver stopped", source: "Tunnel")

            // Disconnect and destroy client
            self.bridge.disconnect()
            self.logger.info("Bridge disconnected", source: "Tunnel")

            // Shut down the library
            self.bridge.shutdown()

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

    /// Handle messages from the main app.
    ///
    /// Protocol:
    ///   - First byte is the message type (AppToTunnelMessage).
    ///   - Response is JSON-encoded.
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
                "bytesSent": bridge.bytesSent,
                "bytesReceived": bridge.bytesReceived
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))

        case .getStats:
            let stats: [String: Any] = [
                "bytesSent": bridge.bytesSent,
                "bytesReceived": bridge.bytesReceived,
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: stats))

        case .resetCounters:
            bridge.resetCounters()
            sharedDefaults?.set(0, forKey: SharedKey.bytesSent)
            sharedDefaults?.set(0, forKey: SharedKey.bytesReceived)
            completionHandler?(Data([1])) // ACK
        }
    }

    // MARK: - Identity

    /// Load existing identity or create a new one.
    private func loadOrCreateIdentity(config: TunnelConfiguration) throws -> ZTLPIdentityHandle {
        let identityPath = config.identityPath ?? defaultIdentityPath()

        if let path = identityPath, FileManager.default.fileExists(atPath: path) {
            let identity = try bridge.loadIdentity(from: path)
            logger.info("Loaded existing identity from \(path)", source: "Tunnel")
            return identity
        }

        // Try hardware identity first (Secure Enclave)
        do {
            let identity = try bridge.createHardwareIdentity(provider: 1)
            logger.info("Created Secure Enclave identity", source: "Tunnel")
            return identity
        } catch {
            logger.debug("Secure Enclave unavailable: \(error.localizedDescription)", source: "Tunnel")
        }

        // Fall back to software identity
        let identity = try bridge.generateIdentity()
        if let path = identityPath {
            try identity.save(to: path)
        }
        logger.info("Generated software identity", source: "Tunnel")
        return identity
    }

    // MARK: - VIP Proxy

    /// Start VIP proxy listeners and DNS resolver.
    private func startVipProxy(serviceName: String) throws {
        try bridge.vipAddService(name: serviceName, vip: "127.0.0.1", port: 8080)
        try bridge.vipAddService(name: serviceName, vip: "127.0.0.1", port: 8443)
        logger.info("VIP services registered: \(serviceName) → 127.0.0.1:8080/8443", source: "Tunnel")

        try bridge.vipStart()
        logger.info("VIP proxy listeners started", source: "Tunnel")

        // Start DNS resolver (optional — may fail in extension context)
        do {
            try bridge.dnsStart(listenAddr: "127.0.55.53:5354")
            logger.info("DNS resolver started on 127.0.55.53:5354", source: "Tunnel")
        } catch {
            logger.warn("DNS resolver failed (expected on iOS): \(error.localizedDescription)", source: "Tunnel")
        }
    }

    // MARK: - Packet Router

    /// Start the packet router for VIP IP routing on 10.122.0.0/16.
    /// This replaces the VIP proxy for services that should be accessed
    /// via virtual IP addresses instead of 127.0.0.1:port.
    private func startPacketRouter(services: [(vip: String, name: String)]) throws {
        // Initialize the router with the tunnel interface address
        try bridge.routerNew(tunnelAddr: "10.122.0.1")
        logger.info("Packet router initialized (tunnel=10.122.0.1)", source: "Tunnel")

        // Register all services
        for svc in services {
            try bridge.routerAddService(vip: svc.vip, serviceName: svc.name)
            logger.info("Router service: \(svc.vip) → \(svc.name)", source: "Tunnel")
        }

        // Start the packet read/write loop
        startPacketLoop()
    }

    /// Start the utun packet I/O loop.
    /// Reads IP packets from the tunnel interface, feeds them to the Rust
    /// packet router, and writes response packets back to the interface.
    private func startPacketLoop() {
        logger.info("Starting packet I/O loop", source: "Tunnel")

        // Read loop: utun → packet router → ZTLP
        readPacketLoop()

        // Write loop: poll outbound packets from router → utun
        // Runs on a background timer to avoid busy-waiting
        startWritePacketTimer()
    }

    /// Recursive readPackets loop. iOS calls the completion handler each
    /// time packets are available, and we call readPackets again to keep
    /// the loop going. This is the standard pattern for NEPacketTunnelProvider.
    private func readPacketLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isTunnelActive else { return }

            for (i, packet) in packets.enumerated() {
                // Only handle IPv4 (protocol family 2 = AF_INET)
                let proto = protocols[i]
                if proto.intValue == AF_INET {
                    do {
                        try self.bridge.routerWritePacket(packet)
                    } catch {
                        self.logger.warn("router write error: \(error)", source: "Tunnel")
                    }
                }
            }

            // Immediately flush any outbound response packets
            self.flushOutboundPackets()

            // Continue reading
            self.readPacketLoop()
        }
    }

    /// Write response packets from the router back to the utun interface.
    private func flushOutboundPackets() {
        var packets: [Data] = []
        var protocols: [NSNumber] = []

        // Drain all available outbound packets
        while let pkt = bridge.routerReadPacket() {
            packets.append(pkt)
            protocols.append(NSNumber(value: AF_INET)) // IPv4
        }

        if !packets.isEmpty {
            packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    /// Periodic timer to flush outbound packets from the router.
    /// This catches response packets that arrive asynchronously from the
    /// gateway (e.g., HTTP response data) outside of the readPackets cycle.
    private var writePacketTimer: DispatchSourceTimer?

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

    // MARK: - NS Resolution

    /// Resolve the gateway address via NS or fallback to targetNodeId.
    private func resolveGateway(config: TunnelConfiguration, svcName: String) throws -> String {
        var target = ""
        let nsServer = config.nsServer ?? config.targetNodeId

        if !svcName.isEmpty && !nsServer.isEmpty {
            let zoneName = config.zoneName ?? "techrockstars.ztlp"
            let nsName = svcName.contains(".") ? svcName : "\(svcName).\(zoneName)"
            logger.info("Resolving \(nsName) via NS \(nsServer)...", source: "Tunnel")

            do {
                let resolved = try bridge.nsResolve(
                    serviceName: nsName,
                    nsServer: nsServer,
                    timeoutMs: 5000
                )
                target = resolved
                logger.info("NS resolved: \(nsName) → \(resolved)", source: "Tunnel")
            } catch {
                logger.warn("NS resolution failed: \(error.localizedDescription)", source: "Tunnel")
            }
        }

        // Fallback: use targetNodeId if it looks like an address (contains :)
        if target.isEmpty {
            let fallback = config.targetNodeId
            if fallback.contains(":") {
                target = fallback
                logger.info("Using targetNodeId as gateway address: \(target)", source: "Tunnel")
            }
        }

        guard !target.isEmpty else {
            throw makeNSError("Could not resolve gateway address. Check NS server and service name.")
        }

        return target
    }

    // MARK: - Reconnect

    /// Schedule a reconnect attempt with exponential backoff.
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

    /// Perform a reconnect attempt.
    private func attemptReconnect() {
        guard bridge.hasClient else {
            logger.error("Client lost during reconnect", source: "Tunnel")
            cancelTunnelWithError(makeNSError("Client lost during reconnect"))
            return
        }

        // Disconnect transport but keep client alive (VIP listeners stay)
        bridge.disconnectTransport()

        // Re-resolve gateway
        let config = currentConfig ?? (try? loadTunnelConfiguration())
        guard let config = config else {
            logger.error("Failed to load config for reconnect", source: "Tunnel")
            scheduleReconnect()
            return
        }

        let svcName = config.serviceName ?? "vault"
        var target = resolvedGateway ?? ""
        let nsServer = config.nsServer ?? config.targetNodeId

        if !svcName.isEmpty && !nsServer.isEmpty {
            let zoneName = config.zoneName ?? "techrockstars.ztlp"
            let nsName = svcName.contains(".") ? svcName : "\(svcName).\(zoneName)"
            do {
                let resolved = try bridge.nsResolve(
                    serviceName: nsName,
                    nsServer: nsServer,
                    timeoutMs: 5000
                )
                target = resolved
                resolvedGateway = resolved
                logger.info("Reconnect NS resolved: \(nsName) → \(resolved)", source: "Tunnel")
            } catch {
                logger.warn("Reconnect NS resolution failed, using cached: \(target)", source: "Tunnel")
            }
        }

        guard !target.isEmpty else {
            logger.warn("No gateway target for reconnect, will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        // Reconnect via bridge (async → sync)
        let connectSemaphore = DispatchSemaphore(value: 0)
        var connectError: Error?

        Task.detached(priority: .userInitiated) {
            do {
                try await self.bridge.connect(target: target, config: nil)
            } catch {
                connectError = error
            }
            connectSemaphore.signal()
        }

        let waitResult = connectSemaphore.wait(timeout: .now() + 15)
        if waitResult == .timedOut || connectError != nil {
            let msg = connectError?.localizedDescription ?? "timed out"
            logger.warn("Reconnect failed: \(msg), will retry", source: "Tunnel")
            scheduleReconnect()
            return
        }

        // Success — reset counter and update state
        reconnectAttempt = 0
        logger.info("Reconnected successfully to \(target)", source: "Tunnel")
        updateConnectionState(.connected)
        sharedDefaults?.set(
            Date().timeIntervalSince1970,
            forKey: SharedKey.connectedSince
        )
    }

    // MARK: - Keepalive

    /// Start a 25-second keepalive timer to maintain the connection.
    private func startKeepaliveTimer() {
        keepaliveTimer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now() + 25, repeating: 25)
        timer.setEventHandler { [weak self] in
            guard let self = self, self.bridge.hasClient else { return }
            // Send a 1-byte keepalive
            let keepaliveData = Data([0])
            do {
                try self.bridge.send(data: keepaliveData)
            } catch {
                self.logger.debug("Keepalive send failed: \(error.localizedDescription)", source: "Tunnel")
                // Keepalive failure might mean disconnection — schedule reconnect
                if self.isTunnelActive {
                    self.scheduleReconnect()
                }
            }
        }
        timer.resume()
        keepaliveTimer = timer
    }

    // MARK: - Configuration

    /// Load tunnel configuration from the NETunnelProviderProtocol.
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

    /// Default identity file path in the shared app group container.
    private func defaultIdentityPath() -> String? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupId
        ) else { return nil }
        return containerURL.appendingPathComponent("identity.json").path
    }

    /// Create minimal NEPacketTunnelNetworkSettings.
    ///
    /// We don't use TUN packet I/O — the VIP proxy handles all traffic.
    /// These settings are required by iOS to consider the VPN "active",
    /// but we configure split-tunnel that captures nothing.
    private func createTunnelNetworkSettings(
        tunnelRemoteAddress: String,
        usePacketRouter: Bool = true
    ) -> NEPacketTunnelNetworkSettings {
        // NEPacketTunnelNetworkSettings requires a bare IP address (no port).
        // The address may contain a port (e.g., "34.219.64.205:23095"), so strip it.
        let remoteAddress = tunnelRemoteAddress.components(separatedBy: ":").first ?? tunnelRemoteAddress

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        if usePacketRouter {
            // Packet router mode: route 10.122.0.0/16 through the tunnel.
            // Apps connect to service VIPs (e.g., 10.122.0.1:443) using
            // standard ports. The utun interface captures these packets,
            // and PacketTunnelProvider feeds them through the Rust packet
            // router, which manages TCP state and ZTLP mux streams.
            let ipv4 = NEIPv4Settings(
                addresses: ["10.122.0.1"],           // Tunnel interface IP
                subnetMasks: ["255.255.0.0"]          // /16 subnet
            )
            // Route the entire VIP subnet through the tunnel
            let vipRoute = NEIPv4Route(
                destinationAddress: "10.122.0.0",
                subnetMask: "255.255.0.0"
            )
            ipv4.includedRoutes = [vipRoute]
            // Don't route anything else through the tunnel
            ipv4.excludedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = ipv4
        } else {
            // Legacy VIP proxy mode: no real traffic routes through the tunnel.
            // Traffic goes to 127.0.0.1:port VIP proxy listeners.
            let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
            ipv4.includedRoutes = []
            ipv4.excludedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = ipv4
        }

        // DNS: only intercept .ztlp domain queries
        let dns = NEDNSSettings(servers: ["127.0.55.53"])
        dns.matchDomains = ["ztlp"]
        settings.dnsSettings = dns

        // MTU
        settings.mtu = NSNumber(value: 1400)

        return settings
    }

    // MARK: - Shared State

    /// Update the connection state in shared UserDefaults.
    private func updateConnectionState(_ state: TunnelConnectionState) {
        sharedDefaults?.set(state.rawValue, forKey: SharedKey.connectionState)
        sharedDefaults?.synchronize()
    }

    // MARK: - Helpers

    private func makeNSError(_ message: String) -> NSError {
        NSError(
            domain: "com.ztlp.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
