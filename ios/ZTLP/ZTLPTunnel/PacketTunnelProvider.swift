// PacketTunnelProvider.swift
// ZTLPTunnel (Network Extension)
//
// This is the core of the ZTLP VPN on iOS. It runs as a separate process
// managed by NetworkExtension.framework. The main app communicates with
// this extension via NETunnelProviderSession.sendProviderMessage().
//
// Lifecycle:
//   1. iOS calls startTunnel() when the user toggles the VPN on.
//   2. We load the identity from the shared keychain (app group).
//   3. Initialize the ZTLP C library (ztlp_init).
//   4. Create client, connect to relay/peer.
//   5. Set up the TUN interface via NEPacketTunnelNetworkSettings.
//   6. Read packets from TUN → send via ZTLP FFI → encrypted UDP out.
//   7. Receive encrypted UDP → decrypt via ZTLP FFI → write to TUN.
//   8. iOS calls stopTunnel() when user disconnects or system reclaims.
//
// App Group: group.com.ztlp.shared
//   - Keychain: identity private key material
//   - UserDefaults: connection state for the main app to observe

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
    static let relayAddress = "ztlp_relay_address"
    static let targetNodeId = "ztlp_target_node_id"
    static let identityPath = "ztlp_identity_path"
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

    /// Handle to the ZTLP client (C FFI opaque pointer).
    private var ztlpClient: OpaquePointer?

    /// Handle to the current identity (only held until client takes ownership).
    private var ztlpIdentity: OpaquePointer?

    /// Keepalive timer — sends empty packets every 25s to maintain NAT mappings.
    private var keepaliveTimer: DispatchSourceTimer?

    /// Serial queue for ZTLP operations (FFI calls are thread-safe, but we
    /// serialize our own state mutations).
    private let tunnelQueue = DispatchQueue(label: "com.ztlp.tunnel.queue", qos: .userInitiated)

    /// Shared UserDefaults for communicating state to the main app.
    private lazy var sharedDefaults: UserDefaults? = {
        UserDefaults(suiteName: appGroupId)
    }()

    /// Traffic counters.
    private var bytesSent: UInt64 = 0
    private var bytesReceived: UInt64 = 0

    /// Connection start time (for duration display).
    private var connectedSince: Date?

    /// Whether we're currently in a tunnel session.
    private var isTunnelActive = false

    // MARK: - NEPacketTunnelProvider Overrides

    /// Called by iOS when the VPN should start.
    ///
    /// Flow:
    ///   1. Read configuration from protocolConfiguration.
    ///   2. Load identity from shared keychain/file.
    ///   3. Initialize ZTLP, create client, connect.
    ///   4. Configure TUN interface.
    ///   5. Start reading packets from TUN.
    ///   6. Call completionHandler(nil) on success.
    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        updateConnectionState(.connecting)

        tunnelQueue.async { [weak self] in
            guard let self = self else {
                completionHandler(NSError(
                    domain: "com.ztlp.tunnel",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Provider deallocated"]
                ))
                return
            }

            do {
                // Step 1: Read tunnel configuration from the NETunnelProviderProtocol
                let config = try self.loadTunnelConfiguration()

                // Step 2: Initialize the ZTLP library
                let initResult = ztlp_init()
                guard initResult == 0 else {
                    throw self.makeNSError("ztlp_init failed: \(self.lastCError())")
                }

                // Step 3: Load or generate identity
                let identity = try self.loadOrCreateIdentity(config: config)

                // Step 4: Create client (identity ownership transfers)
                guard let client = ztlp_client_new(identity) else {
                    throw self.makeNSError("ztlp_client_new failed: \(self.lastCError())")
                }
                self.ztlpClient = client
                self.ztlpIdentity = nil // ownership transferred

                // Step 5: Set up receive callback
                let selfPtr = Unmanaged.passUnretained(self).toOpaque()
                ztlp_set_recv_callback(client, { userData, dataPtr, dataLen, session in
                    guard let userData = userData else { return }
                    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(userData)
                        .takeUnretainedValue()
                    provider.handleReceivedData(dataPtr: dataPtr, length: dataLen)
                }, selfPtr)

                ztlp_set_disconnect_callback(client, { userData, session, reason in
                    guard let userData = userData else { return }
                    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(userData)
                        .takeUnretainedValue()
                    provider.handleDisconnect(reason: reason)
                }, selfPtr)

                // Step 6: Configure and connect
                let ztlpConfig = ztlp_config_new()!
                if let relay = config.relayAddress {
                    relay.withCString { cRelay in
                        _ = ztlp_config_set_relay(ztlpConfig, cRelay)
                    }
                }
                _ = ztlp_config_set_timeout_ms(ztlpConfig, 10000)
                _ = ztlp_config_set_nat_assist(ztlpConfig, true)

                // Step 7: Connect (async — we use a semaphore to bridge)
                let connectSemaphore = DispatchSemaphore(value: 0)
                var connectError: Error?

                let semPtr = Unmanaged.passRetained(
                    SemaphoreBox(semaphore: connectSemaphore, errorRef: &connectError)
                ).toOpaque()

                let target = config.targetNodeId
                let connectResult = target.withCString { cTarget in
                    ztlp_connect(client, cTarget, ztlpConfig, { userData, resultCode, peerAddr in
                        guard let userData = userData else { return }
                        let box_ = Unmanaged<SemaphoreBox>.fromOpaque(userData).takeRetainedValue()
                        if resultCode != 0 {
                            let msg = ztlp_last_error().map { String(cString: $0) } ?? "unknown"
                            box_.errorRef?.pointee = NSError(
                                domain: "com.ztlp.tunnel",
                                code: Int(resultCode),
                                userInfo: [NSLocalizedDescriptionKey: msg]
                            )
                        }
                        box_.semaphore.signal()
                    }, semPtr)
                }

                ztlp_config_free(ztlpConfig)

                if connectResult != 0 {
                    let _ = Unmanaged<SemaphoreBox>.fromOpaque(semPtr).takeRetainedValue()
                    throw self.makeNSError("ztlp_connect failed: \(self.lastCError())")
                }

                // Wait for connection (with timeout)
                let waitResult = connectSemaphore.wait(timeout: .now() + 15)
                if waitResult == .timedOut {
                    throw self.makeNSError("Connection timed out")
                }
                if let err = connectError {
                    throw err
                }

                // Step 8: Configure the TUN interface
                let tunSettings = self.createTunnelNetworkSettings(config: config)
                self.setTunnelNetworkSettings(tunSettings) { error in
                    if let error = error {
                        self.updateConnectionState(.disconnected)
                        completionHandler(error)
                        return
                    }

                    // Step 9: Start reading packets from TUN
                    self.isTunnelActive = true
                    self.connectedSince = Date()
                    self.startReadingPackets()
                    self.startKeepaliveTimer()
                    self.updateConnectionState(.connected)
                    self.sharedDefaults?.set(
                        Date().timeIntervalSince1970,
                        forKey: SharedKey.connectedSince
                    )
                    completionHandler(nil)
                }

            } catch {
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

            // Stop tunnel if active
            if let client = self.ztlpClient {
                ztlp_tunnel_stop(client)
            }

            // Free the client (drops connection, runtime, identity)
            if let client = self.ztlpClient {
                ztlp_client_free(client)
                self.ztlpClient = nil
            }

            // Shut down the library
            ztlp_shutdown()

            // Update shared state
            self.updateConnectionState(.disconnected)
            self.connectedSince = nil
            self.sharedDefaults?.removeObject(forKey: SharedKey.connectedSince)

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
                "bytesSent": bytesSent,
                "bytesReceived": bytesReceived
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))

        case .getStats:
            let stats: [String: Any] = [
                "bytesSent": bytesSent,
                "bytesReceived": bytesReceived,
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: stats))

        case .resetCounters:
            bytesSent = 0
            bytesReceived = 0
            sharedDefaults?.set(0, forKey: SharedKey.bytesSent)
            sharedDefaults?.set(0, forKey: SharedKey.bytesReceived)
            completionHandler?(Data([1])) // ACK
        }
    }

    // MARK: - Packet I/O

    /// Continuously read IP packets from the virtual TUN interface and send
    /// them through the ZTLP encrypted tunnel.
    ///
    /// NEPacketTunnelProvider.packetFlow provides the TUN read/write interface.
    /// Each packet is an IP packet (v4 or v6) that the OS routes through our VPN.
    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isTunnelActive else { return }

            for (index, packet) in packets.enumerated() {
                self.sendPacketToTunnel(packet, protocol: protocols[index])
            }

            // Continue reading (recursive, but on the system's callback queue)
            self.startReadingPackets()
        }
    }

    /// Encrypt and send a single IP packet through the ZTLP tunnel.
    private func sendPacketToTunnel(_ packet: Data, protocol proto: NSNumber) {
        guard let client = ztlpClient else { return }

        // Prepend a 2-byte protocol header so the other side knows the AF.
        // AF_INET = 2, AF_INET6 = 30 (on Darwin)
        var framedPacket = Data(capacity: 2 + packet.count)
        var protoValue = proto.uint16Value
        framedPacket.append(Data(bytes: &protoValue, count: 2))
        framedPacket.append(packet)

        let result = framedPacket.withUnsafeBytes { rawBuf -> Int32 in
            guard let baseAddress = rawBuf.baseAddress else { return -1 }
            return ztlp_send(client, baseAddress.assumingMemoryBound(to: UInt8.self), rawBuf.count)
        }

        if result == 0 {
            bytesSent += UInt64(packet.count)
            sharedDefaults?.set(bytesSent, forKey: SharedKey.bytesSent)
        }
    }

    /// Handle decrypted data received from the ZTLP tunnel.
    /// Called from the C recv callback (on the Rust tokio thread).
    ///
    /// The data has a 2-byte protocol header followed by the IP packet.
    private func handleReceivedData(dataPtr: UnsafePointer<UInt8>?, length: Int) {
        guard let dataPtr = dataPtr, length > 2 else { return }

        // First 2 bytes: protocol number (AF_INET or AF_INET6)
        let protoValue = UInt16(dataPtr[0]) | (UInt16(dataPtr[1]) << 8)
        let proto = NSNumber(value: protoValue)

        // Remaining bytes: the IP packet
        let packetData = Data(bytes: dataPtr.advanced(by: 2), count: length - 2)

        bytesReceived += UInt64(packetData.count)
        sharedDefaults?.set(bytesReceived, forKey: SharedKey.bytesReceived)

        // Write the decrypted packet into the TUN interface.
        // The OS will route it to the appropriate socket/app.
        packetFlow.writePackets([packetData], withProtocols: [proto])
    }

    /// Current reconnect attempt counter.
    private var reconnectAttempt = 0

    /// Maximum reconnect attempts before giving up.
    private static let maxReconnectAttempts = 10

    /// Base reconnect delay in seconds (exponential backoff).
    private static let baseReconnectDelay: TimeInterval = 1.0

    /// Maximum reconnect delay cap.
    private static let maxReconnectDelay: TimeInterval = 60.0

    /// Handle unexpected disconnection from the peer.
    private func handleDisconnect(reason: Int32) {
        guard isTunnelActive else { return }

        // Reason 100 = network change (intentional teardown for reconnect)
        // Other reasons = unexpected disconnect
        updateConnectionState(.reconnecting)

        scheduleReconnect()
    }

    /// Schedule a reconnect attempt with exponential backoff.
    private func scheduleReconnect() {
        guard isTunnelActive else { return }

        reconnectAttempt += 1

        if reconnectAttempt > Self.maxReconnectAttempts {
            // Give up — cancel the tunnel
            cancelTunnelWithError(
                makeError("Failed to reconnect after \(Self.maxReconnectAttempts) attempts")
            )
            return
        }

        let delay = min(
            Self.baseReconnectDelay * pow(2.0, Double(reconnectAttempt - 1)),
            Self.maxReconnectDelay
        )
        // Add jitter (±20%)
        let jitter = delay * Double.random(in: -0.2...0.2)
        let finalDelay = max(0.5, delay + jitter)

        tunnelQueue.asyncAfter(deadline: .now() + finalDelay) { [weak self] in
            guard let self = self, self.isTunnelActive else { return }
            self.attemptReconnect()
        }
    }

    /// Perform a reconnect attempt.
    private func attemptReconnect() {
        guard let client = ztlpClient else {
            cancelTunnelWithError(makeError("Client lost during reconnect"))
            return
        }

        // Disconnect transport but keep client alive
        ztlp_disconnect_transport(client)

        // Re-read configuration
        guard let config = try? loadTunnelConfiguration() else {
            cancelTunnelWithError(makeError("Failed to load config for reconnect"))
            return
        }

        // Reconnect
        let connectSemaphore = DispatchSemaphore(value: 0)
        var connectError: Error?

        let semPtr = Unmanaged.passRetained(
            SemaphoreBox(semaphore: connectSemaphore, errorRef: &connectError)
        ).toOpaque()

        let target = config.targetNodeId
        let connectResult = target.withCString { cTarget in
            ztlp_connect(client, cTarget, nil, { userData, resultCode, peerAddr in
                guard let userData = userData else { return }
                let box_ = Unmanaged<SemaphoreBox>.fromOpaque(userData).takeRetainedValue()
                if resultCode != 0 {
                    let msg = ztlp_last_error().map { String(cString: $0) } ?? "unknown"
                    box_.errorRef?.pointee = NSError(
                        domain: "com.ztlp.tunnel",
                        code: Int(resultCode),
                        userInfo: [NSLocalizedDescriptionKey: msg]
                    )
                }
                box_.semaphore.signal()
            }, semPtr)
        }

        if connectResult != 0 {
            let _ = Unmanaged<SemaphoreBox>.fromOpaque(semPtr).takeRetainedValue()
            scheduleReconnect()
            return
        }

        let waitResult = connectSemaphore.wait(timeout: .now() + 15)
        if waitResult == .timedOut || connectError != nil {
            scheduleReconnect()
            return
        }

        // Success — reset counter and update state
        reconnectAttempt = 0
        updateConnectionState(.connected)
        sharedDefaults?.set(
            Date().timeIntervalSince1970,
            forKey: SharedKey.connectedSince
        )
    }

    // MARK: - Keepalive

    /// Start a 25-second keepalive timer to maintain NAT port mappings.
    ///
    /// Mobile networks aggressively expire UDP NAT mappings (often 30-60s).
    /// We send a small keepalive packet every 25s to prevent this.
    private func startKeepaliveTimer() {
        keepaliveTimer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now() + 25, repeating: 25)
        timer.setEventHandler { [weak self] in
            guard let self = self, let client = self.ztlpClient else { return }
            // Send a 1-byte keepalive (the library recognizes this as a keepalive)
            var keepalive: UInt8 = 0
            _ = ztlp_send(client, &keepalive, 1)
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

        let providerConfig = proto.providerConfiguration ?? [:]

        guard let targetNodeId = providerConfig["targetNodeId"] as? String,
              !targetNodeId.isEmpty else {
            throw makeNSError("Missing targetNodeId in provider configuration")
        }

        return TunnelConfiguration(
            targetNodeId: targetNodeId,
            relayAddress: providerConfig["relayAddress"] as? String,
            stunServer: providerConfig["stunServer"] as? String ?? "stun.l.google.com:19302",
            tunnelAddress: providerConfig["tunnelAddress"] as? String ?? "10.0.0.2",
            tunnelNetmask: providerConfig["tunnelNetmask"] as? String ?? "255.255.255.0",
            dnsServers: providerConfig["dnsServers"] as? [String] ?? ["1.1.1.1", "8.8.8.8"],
            mtu: providerConfig["mtu"] as? Int ?? 1400,
            identityPath: providerConfig["identityPath"] as? String
        )
    }

    /// Load identity from the shared app group container or generate a new one.
    private func loadOrCreateIdentity(config: TunnelConfiguration) throws -> OpaquePointer {
        // Try loading from file in the shared container
        if let path = config.identityPath ?? defaultIdentityPath() {
            if FileManager.default.fileExists(atPath: path) {
                if let identity = path.withCString({ ztlp_identity_from_file($0) }) {
                    return identity
                }
                // File exists but is corrupt — fall through to generate
            }
        }

        // Try Secure Enclave identity
        if let identity = ztlp_identity_from_hardware(1) {
            return identity
        }

        // Fall back to software identity
        guard let identity = ztlp_identity_generate() else {
            throw makeNSError("Failed to generate identity: \(lastCError())")
        }

        // Save for next launch
        if let path = defaultIdentityPath() {
            path.withCString { cPath in
                _ = ztlp_identity_save(identity, cPath)
            }
        }

        return identity
    }

    /// Default identity file path in the shared app group container.
    private func defaultIdentityPath() -> String? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupId
        ) else { return nil }
        return containerURL.appendingPathComponent("identity.json").path
    }

    /// Create NEPacketTunnelNetworkSettings for the TUN interface.
    ///
    /// By default, uses split-tunnel mode: only `.ztlp` domain traffic goes
    /// through the tunnel. The rest of the user's traffic routes normally.
    /// Full-tunnel mode can be enabled via configuration.
    private func createTunnelNetworkSettings(
        config: TunnelConfiguration
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: config.relayAddress ?? config.targetNodeId
        )

        // IPv4 settings — split tunnel by default
        let ipv4 = NEIPv4Settings(
            addresses: [config.tunnelAddress],
            subnetMasks: [config.tunnelNetmask]
        )

        if config.fullTunnel {
            // Full tunnel: all traffic goes through VPN
            ipv4.includedRoutes = [NEIPv4Route.default()]
        } else {
            // Split tunnel: only route the VIP loopback range through the tunnel
            // 127.0.55.0/24 covers all ZTLP VIP addresses
            ipv4.includedRoutes = [
                NEIPv4Route(destinationAddress: "127.0.55.0", subnetMask: "255.255.255.0")
            ]
            // Exclude standard routes so normal traffic isn't captured
            ipv4.excludedRoutes = [NEIPv4Route.default()]
        }
        settings.ipv4Settings = ipv4

        // DNS — match only .ztlp domains in split tunnel mode
        let dns = NEDNSSettings(servers: config.dnsServers)
        if !config.fullTunnel {
            // Only intercept DNS queries for .ztlp domains
            dns.matchDomains = ["ztlp"]
        }
        settings.dnsSettings = dns

        // MTU (account for ZTLP encryption + UDP overhead)
        settings.mtu = NSNumber(value: config.mtu)

        return settings
    }

    // MARK: - Shared State

    /// Update the connection state in shared UserDefaults.
    private func updateConnectionState(_ state: TunnelConnectionState) {
        sharedDefaults?.set(state.rawValue, forKey: SharedKey.connectionState)
        sharedDefaults?.synchronize()
    }

    // MARK: - Helpers

    private func lastCError() -> String {
        ztlp_last_error().map { String(cString: $0) } ?? "unknown error"
    }

    private func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.ztlp.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    private func makeNSError(_ message: String) -> NSError {
        makeError(message)
    }
}

// MARK: - SemaphoreBox

/// Box for passing a DispatchSemaphore + error reference through a C void*.
private final class SemaphoreBox {
    let semaphore: DispatchSemaphore
    let errorRef: UnsafeMutablePointer<Error?>?

    init(semaphore: DispatchSemaphore, errorRef: UnsafeMutablePointer<Error?>?) {
        self.semaphore = semaphore
        self.errorRef = errorRef
    }
}
