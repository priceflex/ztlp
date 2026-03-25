// TunnelViewModel.swift
// ZTLP macOS
//
// Manages the tunnel lifecycle with two connection modes:
//   1. VPN Tunnel (System Extension) — routes all system traffic, needs Apple entitlement
//   2. Direct Connect (userspace) — app-level encrypted session, no entitlement needed
//
// Automatically falls back to Direct Connect if VPN setup fails with permission error.

import Foundation
import AppKit
import NetworkExtension
import Combine
import SwiftUI

/// Connection mode used by the tunnel.
enum ConnectionMode: String, Equatable {
    case vpnTunnel = "VPN Tunnel"
    case directConnect = "Direct Connect"

    var icon: String {
        switch self {
        case .vpnTunnel: return "lock.shield"
        case .directConnect: return "bolt.shield"
        }
    }

    var description: String {
        switch self {
        case .vpnTunnel:
            return "Full VPN — all traffic routed through ZTLP"
        case .directConnect:
            return "App-level encrypted session (no VPN entitlement needed)"
        }
    }
}

/// ViewModel for the main connect/disconnect UI.
@MainActor
final class TunnelViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var status: ConnectionStatus = .disconnected
    @Published private(set) var stats = TrafficStats()
    @Published private(set) var zoneName: String = ""
    @Published private(set) var peerAddress: String = ""
    @Published private(set) var lastError: String?
    @Published private(set) var testResult: String?
    @Published private(set) var isVPNConfigInstalled: Bool = false
    @Published private(set) var connectionMode: ConnectionMode = .directConnect
    @Published var preferVPN: Bool = false
    @Published var autoReconnectEnabled: Bool = true
    @Published private(set) var reconnectAttempt: Int = 0

    // MARK: - Auto-Reconnect

    private var reconnectTask: Task<Void, Never>?
    private let maxReconnectDelay: TimeInterval = 30
    private let baseReconnectDelay: TimeInterval = 1

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let networkMonitor = NetworkMonitor.shared
    private let sysExtManager = SystemExtensionManager.shared
    private let bridge = ZTLPBridge.shared
    private var cancellables = Set<AnyCancellable>()
    private var tunnelManager: NETunnelProviderManager?
    private var statsTimer: Timer?
    private var directIdentity: ZTLPIdentityHandle?

    private let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared.macos")

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.zoneName = configuration.zoneName
        setupObservers()
        checkVPNAvailability()
    }

    // MARK: - Actions

    func toggleConnection() {
        switch status {
        case .disconnected:
            connect()
        case .connected, .reconnecting:
            disconnect()
        default:
            break
        }
    }

    func connect() {
        guard status.canConnect else { return }

        lastError = nil
        status = .connecting

        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        Task {
            if preferVPN {
                // Try VPN first, fall back to direct
                do {
                    try await connectVPN()
                    connectionMode = .vpnTunnel
                } catch {
                    let errMsg = error.localizedDescription
                    if errMsg.contains("permission") || errMsg.contains("entitlement")
                        || errMsg.contains("configuration is invalid") || errMsg.contains("NEVPNError") {
                        // VPN not available — fall back to direct connect
                        lastError = nil
                        await connectDirect()
                    } else {
                        status = .disconnected
                        lastError = errMsg
                        NSSound.beep()
                    }
                }
            } else {
                await connectDirect()
            }
        }
    }

    func disconnect() {
        guard status.canDisconnect else { return }

        // Cancel any pending auto-reconnect
        reconnectTask?.cancel()
        reconnectAttempt = 0

        status = .disconnecting
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        switch connectionMode {
        case .vpnTunnel:
            tunnelManager?.connection.stopVPNTunnel()
        case .directConnect:
            stopVipProxy()
            bridge.disconnect()
        }

        stopStatsPolling()
        status = .disconnected
        stats = TrafficStats()
        peerAddress = ""
    }

    // MARK: - Direct Connect (Userspace)

    private func connectDirect() async {
        connectionMode = .directConnect

        do {
            try bridge.initialize()

            // Load or create identity
            let identity: ZTLPIdentityHandle
            let identityPath = defaultIdentityPath()

            if let path = identityPath,
               FileManager.default.fileExists(atPath: path) {
                identity = try bridge.loadIdentity(from: path)
            } else {
                identity = try bridge.generateIdentity()
                if let path = identityPath {
                    try identity.save(to: path)
                }
            }

            self.directIdentity = identity

            guard identity.nodeId != nil else {
                status = .disconnected
                lastError = "Failed to get node ID from identity"
                return
            }

            // Create client
            try bridge.createClient(identity: identity)

            // Build config
            let config = ZTLPConfigHandle()
            let relay = configuration.relayAddress
            if !relay.isEmpty {
                try config.setRelay(relay)
            }
            try config.setNatAssist(configuration.natAssist)
            try config.setTimeoutMs(15000)

            // Set service name for gateway routing
            let svcName = configuration.serviceName
            if !svcName.isEmpty {
                try config.setService(svcName)
            }

            // Resolve gateway address via NS if we have a service name and NS server
            var target = relay
            let nsServer = configuration.targetNodeId  // NS server address
            if !svcName.isEmpty && !nsServer.isEmpty {
                let nsName = svcName.contains(".") ? svcName : "\(svcName).techrockstars.ztlp"
                do {
                    // Run blocking NS resolve off the main thread to avoid priority inversion
                    let bridgeRef = bridge
                    let resolved = try await Task.detached(priority: .userInitiated) {
                        try bridgeRef.nsResolve(
                            serviceName: nsName,
                            nsServer: nsServer,
                            timeoutMs: 5000
                        )
                    }.value
                    print("[ZTLP] NS resolved \(nsName) -> \(resolved)")
                    target = resolved
                } catch {
                    print("[ZTLP] NS resolution failed: \(error), falling back to relay/direct")
                    // Fall back to relay address or NS server
                    if target.isEmpty {
                        target = nsServer
                    }
                }
            }

            // Fall back to relay or NS address if NS resolution didn't set a target
            if target.isEmpty {
                target = nsServer
            }
            guard !target.isEmpty else {
                status = .disconnected
                lastError = "No relay or target address configured. Enroll first."
                return
            }

            try await bridge.connect(target: target, config: config)

            // Connected! Start VIP proxy + DNS
            status = .connected
            stats.connectedSince = Date()
            peerAddress = target
            startDirectStatsPolling()
            await startVipProxy()

            // Give gateway time to set up session before marking fully connected
            try? await Task.sleep(nanoseconds: 200_000_000) // 200ms

            NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)

        } catch {
            status = .disconnected
            lastError = error.localizedDescription
            NSSound.beep()
        }
    }

    // MARK: - VPN Tunnel (System Extension)

    private func connectVPN() async throws {
        let manager = try await loadOrCreateTunnelManager()
        self.tunnelManager = manager

        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.ztlp.app.macos.system-extension"
        proto.serverAddress = configuration.relayAddress.isEmpty
            ? configuration.targetNodeId
            : configuration.relayAddress

        var providerConfig: [String: Any] = [
            "targetNodeId": configuration.targetNodeId,
            "relayAddress": configuration.relayAddress,
            "stunServer": configuration.stunServer,
            "tunnelAddress": configuration.tunnelAddress,
            "mtu": configuration.mtu,
        ]
        providerConfig["dnsServers"] = configuration.dnsServers

        proto.providerConfiguration = providerConfig

        manager.protocolConfiguration = proto
        manager.localizedDescription = "ZTLP VPN"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        let session = manager.connection as! NETunnelProviderSession
        try session.startVPNTunnel()

        startStatsPolling()
    }

    // MARK: - VPN Availability

    private func checkVPNAvailability() {
        Task {
            do {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                if let existing = managers.first(where: {
                    guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                    return proto.providerBundleIdentifier == "com.ztlp.app.macos.system-extension"
                }) {
                    self.tunnelManager = existing
                    self.isVPNConfigInstalled = true
                    self.preferVPN = true
                    updateStatusFromConnection(existing.connection)
                }
            } catch {
                self.isVPNConfigInstalled = false
                self.preferVPN = false
            }
        }
    }

    func sendMessageToExtension(_ message: Data) async -> Data? {
        guard let session = tunnelManager?.connection as? NETunnelProviderSession else {
            return nil
        }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(message) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    // MARK: - Private

    private func loadOrCreateTunnelManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        if let existing = managers.first(where: {
            guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            return proto.providerBundleIdentifier == "com.ztlp.app.macos.system-extension"
        }) {
            return existing
        }

        return NETunnelProviderManager()
    }

    private func setupObservers() {
        // VPN status changes
        NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] notification in
                guard let self = self,
                      self.connectionMode == .vpnTunnel,
                      let connection = notification.object as? NEVPNConnection else { return }
                self.updateStatusFromConnection(connection)
            }
            .store(in: &cancellables)

        // Direct connect events
        bridge.eventSubject
            .receive(on: DispatchQueue.main)
            .sink { [weak self] event in
                guard let self = self, self.connectionMode == .directConnect else { return }
                switch event {
                case .connected(let addr):
                    self.peerAddress = addr
                    if self.status != .connected {
                        self.status = .connected
                        self.stats.connectedSince = Date()
                    }
                case .disconnected(let reason):
                    if reason == 100 && self.autoReconnectEnabled && self.status == .connected {
                        // Keepalive timeout — schedule auto-reconnect
                        // Don't clear stats/polling — reconnect will restore them
                        self.stopStatsPolling()
                        self.scheduleReconnect()
                    } else {
                        self.status = .disconnected
                        self.reconnectAttempt = 0
                        self.reconnectTask?.cancel()
                        self.stats = TrafficStats()
                        self.stopStatsPolling()
                    }
                case .error(let error):
                    self.lastError = error.localizedDescription
                default:
                    break
                }
            }
            .store(in: &cancellables)

        // Network changes
        networkMonitor.interfaceChangePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self, self.status == .connected else { return }
                self.status = .reconnecting
            }
            .store(in: &cancellables)

        // Zone name binding
        configuration.$zoneName
            .receive(on: DispatchQueue.main)
            .assign(to: &$zoneName)
    }

    private func updateStatusFromConnection(_ connection: NEVPNConnection) {
        switch connection.status {
        case .invalid, .disconnected:
            status = .disconnected
            stats.connectedSince = nil
            stopStatsPolling()
        case .connecting:
            status = .connecting
        case .connected:
            status = .connected
            stats.connectedSince = connection.connectedDate
            startStatsPolling()
            NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
        case .reasserting:
            status = .reconnecting
        case .disconnecting:
            status = .disconnecting
        @unknown default:
            break
        }
    }

    // MARK: - Stats Polling

    private func startStatsPolling() {
        stopStatsPolling()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshVPNStats()
            }
        }
    }

    private func startDirectStatsPolling() {
        stopStatsPolling()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshDirectStats()
            }
        }
    }

    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
    }

    private func refreshVPNStats() {
        guard let defaults = sharedDefaults else { return }
        stats.bytesSent = UInt64(defaults.integer(forKey: "ztlp_bytes_sent"))
        stats.bytesReceived = UInt64(defaults.integer(forKey: "ztlp_bytes_received"))
        if let since = defaults.object(forKey: "ztlp_connected_since") as? TimeInterval, since > 0 {
            stats.connectedSince = Date(timeIntervalSince1970: since)
        }
        peerAddress = defaults.string(forKey: "ztlp_peer_address") ?? ""
    }

    private func refreshDirectStats() {
        stats.bytesSent = bridge.bytesSent
        stats.bytesReceived = bridge.bytesReceived
    }


    // MARK: - Service Test

    /// Send an HTTP GET through the ZTLP tunnel and display the response.
    func testService() async {
        guard status == .connected else {
            testResult = "Not connected"
            return
        }
        testResult = "Testing..."
        
        let httpRequest = "GET / HTTP/1.1\r\nHost: beta.local\r\nConnection: close\r\n\r\n"
        guard let requestData = httpRequest.data(using: .utf8) else {
            testResult = "Failed to encode request"
            return
        }
        
        do {
            try bridge.send(data: requestData)
            await MainActor.run {
                testResult = "Sent \(requestData.count) bytes through tunnel. Check gateway logs for response."
            }
            // Wait a moment for response via recv callback
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            await MainActor.run {
                let rx = bridge.bytesReceived
                if rx > 0 {
                    testResult = "✅ Sent \(requestData.count)B, Received \(rx)B"
                } else {
                    testResult = "⚠️ Sent \(requestData.count)B, Received 0B (gateway may not be forwarding yet)"
                }
            }
        } catch {
            await MainActor.run {
                testResult = "Error: \(error.localizedDescription)"
            }
        }
    }


    // MARK: - VIP Proxy + DNS

    @Published private(set) var vipStatus: String?
    private var networkingConfigured = false

    private func startVipProxy() async {
        do {
            // Register services with VIP addresses (high ports — pf redirects 80->8080, 443->8443)
            try bridge.vipAddService(name: "beta", vip: "127.0.55.1", port: 8080)
            try bridge.vipAddService(name: "beta", vip: "127.0.55.1", port: 8443)

            // Set up loopback aliases + pf redirect + DNS resolver (prompts for admin password once)
            // Skip on reconnect — networking config persists across tunnel sessions
            if !networkingConfigured {
                try bridge.setupNetworking(vips: ["127.0.55.1", "127.0.55.53"])
                networkingConfigured = true
            }

            // Start TCP proxy listeners on high ports (pf handles 80/443 redirect)
            try bridge.vipStart()

            // Start DNS resolver (safe to call again — re-binds on new port)
            try bridge.dnsStart(listenAddr: "127.0.55.53:5354")

            await MainActor.run {
                vipStatus = "VIP proxy active \u{2014} browse to http://beta.techrockstars.ztlp:8080"
            }
        } catch {
            await MainActor.run {
                vipStatus = "VIP proxy failed: \(error.localizedDescription)"
            }
        }
    }

    private func stopVipProxy() {
        bridge.vipStop()
        bridge.dnsStop()
        bridge.teardownNetworking(vips: ["127.0.55.1", "127.0.55.53"])
        networkingConfigured = false
        vipStatus = nil
    }

    // MARK: - Auto-Reconnect

    private func scheduleReconnect() {
        reconnectTask?.cancel()
        reconnectTask = Task {
            let delay = min(baseReconnectDelay * pow(2, Double(reconnectAttempt)), maxReconnectDelay)
            reconnectAttempt += 1
            status = .reconnecting
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            if !Task.isCancelled {
                connect()
            }
        }
    }

    // MARK: - Identity Path

    private func defaultIdentityPath() -> String? {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first
        guard let dir = appSupport?.appendingPathComponent("ZTLP") else { return nil }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("identity.json").path
    }
}
