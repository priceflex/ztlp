// PacketTunnelProvider.swift
// ZTLPSystemExtension (macOS System Extension)
//
// Core ZTLP VPN tunnel implementation for macOS.
// Runs as a System Extension process managed by NetworkExtension.framework.
// Adapted from the iOS PacketTunnelProvider — same FFI, different lifecycle.
//
// On macOS, System Extensions replace App Extensions for VPN:
//   - Installed via OSSystemExtensionManager (from the main app)
//   - Runs as a standalone process (not inside the app)
//   - Communicates via NETunnelProviderSession.sendProviderMessage()
//   - Uses shared UserDefaults for real-time state updates

import NetworkExtension
import Foundation

// MARK: - TunnelConfiguration (local copy for system extension target)

/// Configuration for the ZTLP packet tunnel.
/// Duplicated here because the system extension is a separate target.
private struct TunnelConfiguration {
    let targetNodeId: String
    let relayAddress: String?
    let stunServer: String
    let tunnelAddress: String
    let tunnelNetmask: String
    let dnsServers: [String]
    let mtu: Int
    let identityPath: String?
}

/// App Group identifier shared between the main app and this extension.
private let appGroupId = "group.com.ztlp.shared.macos"

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

    private var ztlpClient: OpaquePointer?
    private var ztlpIdentity: OpaquePointer?
    private var keepaliveTimer: DispatchSourceTimer?
    private let tunnelQueue = DispatchQueue(label: "com.ztlp.tunnel.queue", qos: .userInitiated)

    private lazy var sharedDefaults: UserDefaults? = {
        UserDefaults(suiteName: appGroupId)
    }()

    private var bytesSent: UInt64 = 0
    private var bytesReceived: UInt64 = 0
    private var connectedSince: Date?
    private var isTunnelActive = false

    // MARK: - NEPacketTunnelProvider Overrides

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        updateConnectionState(.connecting)

        tunnelQueue.async { [weak self] in
            guard let self = self else {
                completionHandler(self?.makeError("Provider deallocated"))
                return
            }

            do {
                let config = try self.loadTunnelConfiguration()

                let initResult = ztlp_init()
                guard initResult == 0 else {
                    throw self.makeError("ztlp_init failed: \(self.lastCError())")
                }

                let identity = try self.loadOrCreateIdentity(config: config)

                guard let client = ztlp_client_new(identity) else {
                    throw self.makeError("ztlp_client_new failed: \(self.lastCError())")
                }
                self.ztlpClient = client
                self.ztlpIdentity = nil

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

                let ztlpConfig = ztlp_config_new()!
                if let relay = config.relayAddress {
                    relay.withCString { cRelay in
                        _ = ztlp_config_set_relay(ztlpConfig, cRelay)
                    }
                }
                _ = ztlp_config_set_timeout_ms(ztlpConfig, 10000)
                _ = ztlp_config_set_nat_assist(ztlpConfig, true)

                let connectSemaphore = DispatchSemaphore(value: 0)
                var connectError: Error?

                let semBox = SemaphoreBox(semaphore: connectSemaphore, errorRef: &connectError)
                let semPtr = Unmanaged.passRetained(semBox).toOpaque()

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
                    throw self.makeError("ztlp_connect failed: \(self.lastCError())")
                }

                let waitResult = connectSemaphore.wait(timeout: .now() + 15)
                if waitResult == .timedOut {
                    throw self.makeError("Connection timed out")
                }
                if let err = connectError {
                    throw err
                }

                let tunSettings = self.createTunnelNetworkSettings(config: config)
                self.setTunnelNetworkSettings(tunSettings) { error in
                    if let error = error {
                        self.updateConnectionState(.disconnected)
                        completionHandler(error)
                        return
                    }

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

            self.keepaliveTimer?.cancel()
            self.keepaliveTimer = nil

            if let client = self.ztlpClient {
                ztlp_tunnel_stop(client)
                ztlp_client_free(client)
                self.ztlpClient = nil
            }

            ztlp_shutdown()

            self.updateConnectionState(.disconnected)
            self.connectedSince = nil
            self.sharedDefaults?.removeObject(forKey: SharedKey.connectedSince)

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
            completionHandler?(Data([1]))
        }
    }

    // MARK: - Packet I/O

    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isTunnelActive else { return }

            for (index, packet) in packets.enumerated() {
                self.sendPacketToTunnel(packet, protocol: protocols[index])
            }

            self.startReadingPackets()
        }
    }

    private func sendPacketToTunnel(_ packet: Data, protocol proto: NSNumber) {
        guard let client = ztlpClient else { return }

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

    private func handleReceivedData(dataPtr: UnsafePointer<UInt8>?, length: Int) {
        guard let dataPtr = dataPtr, length > 2 else { return }

        let protoValue = UInt16(dataPtr[0]) | (UInt16(dataPtr[1]) << 8)
        let proto = NSNumber(value: protoValue)
        let packetData = Data(bytes: dataPtr.advanced(by: 2), count: length - 2)

        bytesReceived += UInt64(packetData.count)
        sharedDefaults?.set(bytesReceived, forKey: SharedKey.bytesReceived)

        packetFlow.writePackets([packetData], withProtocols: [proto])
    }

    private func handleDisconnect(reason: Int32) {
        guard isTunnelActive else { return }

        updateConnectionState(.reconnecting)

        tunnelQueue.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            guard let self = self, self.isTunnelActive else { return }
            self.cancelTunnelWithError(
                self.makeError("Disconnected from peer (reason: \(reason))")
            )
        }
    }

    // MARK: - Keepalive

    private func startKeepaliveTimer() {
        keepaliveTimer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
        timer.schedule(deadline: .now() + 25, repeating: 25)
        timer.setEventHandler { [weak self] in
            guard let self = self, let client = self.ztlpClient else { return }
            var keepalive: UInt8 = 0
            _ = ztlp_send(client, &keepalive, 1)
        }
        timer.resume()
        keepaliveTimer = timer
    }

    // MARK: - Configuration

    private func loadTunnelConfiguration() throws -> TunnelConfiguration {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            throw makeError("Invalid protocol configuration")
        }

        let providerConfig = proto.providerConfiguration ?? [:]

        guard let targetNodeId = providerConfig["targetNodeId"] as? String,
              !targetNodeId.isEmpty else {
            throw makeError("Missing targetNodeId in provider configuration")
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

    private func loadOrCreateIdentity(config: TunnelConfiguration) throws -> OpaquePointer {
        if let path = config.identityPath ?? defaultIdentityPath() {
            if FileManager.default.fileExists(atPath: path) {
                if let identity = path.withCString({ ztlp_identity_from_file($0) }) {
                    return identity
                }
            }
        }

        guard let identity = ztlp_identity_generate() else {
            throw makeError("Failed to generate identity: \(lastCError())")
        }

        if let path = defaultIdentityPath() {
            path.withCString { cPath in
                _ = ztlp_identity_save(identity, cPath)
            }
        }

        return identity
    }

    private func defaultIdentityPath() -> String? {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first
        guard let dir = appSupport?.appendingPathComponent("ZTLP") else { return nil }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("identity.json").path
    }

    private func createTunnelNetworkSettings(
        config: TunnelConfiguration
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: config.relayAddress ?? config.targetNodeId
        )

        let ipv4 = NEIPv4Settings(
            addresses: [config.tunnelAddress],
            subnetMasks: [config.tunnelNetmask]
        )
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: config.dnsServers)
        settings.dnsSettings = dns

        settings.mtu = NSNumber(value: config.mtu)

        return settings
    }

    // MARK: - Shared State

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
}

// MARK: - SemaphoreBox

private final class SemaphoreBox {
    let semaphore: DispatchSemaphore
    let errorRef: UnsafeMutablePointer<Error?>?

    init(semaphore: DispatchSemaphore, errorRef: UnsafeMutablePointer<Error?>?) {
        self.semaphore = semaphore
        self.errorRef = errorRef
    }
}
