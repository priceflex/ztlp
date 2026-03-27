// TunnelViewModel.swift
// ZTLP
//
// Manages the tunnel lifecycle using Direct Connect (userspace).
// Connects via ZTLPBridge directly from the main app process,
// sets up VIP proxy on localhost for Safari access.
//
// No VPN/NetworkExtension dependency — accesses services via
// http://127.0.55.1:8080 (VIP proxy).

import Foundation
import UIKit
import Combine
import SwiftUI

/// ViewModel for the main connect/disconnect UI.
@MainActor
final class TunnelViewModel: ObservableObject {

    // MARK: - Published State

    /// Current connection status.
    @Published private(set) var status: ConnectionStatus = .disconnected

    /// Traffic statistics.
    @Published private(set) var stats = TrafficStats()

    /// The zone name (from enrollment or settings).
    @Published private(set) var zoneName: String = ""

    /// The peer address we're connected to.
    @Published private(set) var peerAddress: String = ""

    /// Last error message (cleared on next connect attempt).
    @Published private(set) var lastError: String?

    /// VIP proxy status (nil when not active).
    @Published private(set) var vipStatus: String?

    /// The service URL users can open in Safari (nil when not connected).
    @Published private(set) var serviceURL: String?

    /// Pretty service name for display (e.g., "vault.techrockstars.ztlp").
    @Published private(set) var serviceDisplayName: String?

    /// Whether the device is enrolled.
    var isEnrolled: Bool { configuration.isEnrolled }

    /// Current reconnect attempt number.
    @Published private(set) var reconnectAttempt: Int = 0

    /// Whether auto-reconnect is enabled.
    @Published var autoReconnectEnabled: Bool = true

    // MARK: - Auto-Reconnect

    private var reconnectTask: Task<Void, Never>?
    private let maxReconnectDelay: TimeInterval = 30
    private let baseReconnectDelay: TimeInterval = 1
    /// Set to true when intentionally tearing down for reconnect — suppresses the
    /// disconnect event handler from cancelling the pending reconnect.
    private var isReconnecting = false

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let networkMonitor = NetworkMonitor.shared
    private let bridge = ZTLPBridge.shared
    private let logger = TunnelLogger.shared
    private var cancellables = Set<AnyCancellable>()
    private var statsTimer: Timer?
    private var directIdentity: ZTLPIdentityHandle?

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.zoneName = configuration.zoneName

        setupObservers()
    }

    // MARK: - Actions

    /// Open the service URL in Safari.
    func openServiceInSafari() {
        guard let urlStr = serviceURL, let url = URL(string: urlStr) else { return }
        UIApplication.shared.open(url)
    }

    /// Toggle the connection.
    func toggleConnection() {
        switch status {
        case .disconnected:
            connect()
        case .connected, .reconnecting:
            disconnect()
        default:
            break // Transitioning — ignore
        }
    }

    /// Start the tunnel via Direct Connect.
    func connect() {
        guard status.canConnect else { return }

        lastError = nil
        status = .connecting
        logger.info("Connecting (Direct Connect)... target=\(configuration.targetNodeId), relay=\(configuration.relayAddress), ns=\(configuration.nsServer), service=\(configuration.serviceName)", source: "Direct")

        // Haptic feedback
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()

        Task {
            await connectDirect()
        }
    }

    /// Stop the tunnel.
    func disconnect() {
        guard status.canDisconnect else { return }

        // Cancel any pending auto-reconnect
        reconnectTask?.cancel()
        reconnectAttempt = 0
        isReconnecting = false

        status = .disconnecting
        logger.info("Disconnecting (Direct Connect)", source: "Direct")

        // Haptic feedback
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()

        // Stop VIP proxy and DNS
        stopVipProxy()

        // Disconnect the bridge
        bridge.disconnect()

        stopStatsPolling()
        status = .disconnected
        stats = TrafficStats()
        peerAddress = ""
        serviceURL = nil
        serviceDisplayName = nil
    }

    // MARK: - Direct Connect (Userspace)

    /// Connect using ZTLPBridge directly from the main app process.
    private func connectDirect() async {
        do {
            // Step 1: Initialize bridge + identity
            if !bridge.hasClient {
                logger.info("Initializing bridge and identity...", source: "Direct")
                try bridge.initialize()

                let identity: ZTLPIdentityHandle
                let identityPath = defaultIdentityPath()

                if let path = identityPath, FileManager.default.fileExists(atPath: path) {
                    identity = try bridge.loadIdentity(from: path)
                    logger.info("Loaded existing identity from \(path)", source: "Direct")
                } else if configuration.useSecureEnclave && SecureEnclaveService.shared.isAvailable {
                    do {
                        identity = try bridge.createHardwareIdentity(provider: 1)
                        logger.info("Created Secure Enclave identity", source: "Direct")
                    } catch {
                        identity = try bridge.generateIdentity()
                        if let path = identityPath {
                            try identity.save(to: path)
                        }
                        logger.info("Secure Enclave unavailable, generated software identity", source: "Direct")
                    }
                } else {
                    identity = try bridge.generateIdentity()
                    if let path = identityPath {
                        try identity.save(to: path)
                    }
                    logger.info("Generated software identity", source: "Direct")
                }

                self.directIdentity = identity

                guard identity.nodeId != nil else {
                    status = .disconnected
                    lastError = "Failed to get node ID from identity"
                    logger.error("Identity has no node ID", source: "Direct")
                    return
                }

                logger.info("Node ID: \(identity.nodeId ?? "unknown")", source: "Direct")
                try bridge.createClient(identity: identity)
                logger.info("Client created", source: "Direct")
            }

            // Step 2: Build config
            let config = ZTLPConfigHandle()

            let relay = configuration.relayAddress
            if !relay.isEmpty {
                try config.setRelay(relay)
                logger.debug("Config: relay=\(relay)", source: "Direct")
            }

            try config.setNatAssist(configuration.natAssist)
            try config.setTimeoutMs(15000)

            let svcName = configuration.serviceName
            if !svcName.isEmpty {
                try config.setService(svcName)
                logger.debug("Config: service=\(svcName)", source: "Direct")
            }

            // Step 3: NS resolution
            var target = relay
            let nsServer = configuration.nsServer.isEmpty ? configuration.targetNodeId : configuration.nsServer

            if !svcName.isEmpty && !nsServer.isEmpty {
                let nsName = svcName.contains(".") ? svcName : "\(svcName).techrockstars.ztlp"
                logger.info("Resolving \(nsName) via NS \(nsServer)...", source: "Direct")

                do {
                    let bridgeRef = bridge
                    let resolved = try await Task.detached(priority: .userInitiated) {
                        try bridgeRef.nsResolve(serviceName: nsName, nsServer: nsServer, timeoutMs: 5000)
                    }.value
                    target = resolved
                    logger.info("NS resolved: \(nsName) → \(resolved)", source: "Direct")
                } catch {
                    logger.warn("NS resolution failed: \(error.localizedDescription). Falling back to relay/NS address.", source: "Direct")
                    if target.isEmpty {
                        target = nsServer
                    }
                }
            }

            if target.isEmpty {
                target = nsServer
            }

            guard !target.isEmpty else {
                status = .disconnected
                lastError = "No target configured. Enroll first."
                logger.error("No target address available", source: "Direct")
                return
            }

            // Step 4: Connect
            logger.info("Connecting to \(target)...", source: "Direct")
            try await bridge.connect(target: target, config: config)

            // Step 5: Connected!
            status = .connected
            peerAddress = target
            reconnectAttempt = 0
            stats.connectedSince = Date()

            // Set service URL for Safari access
            let svc = configuration.serviceName
            if !svc.isEmpty {
                serviceURL = "http://127.0.55.1:8080"
                let zone = configuration.zoneName.isEmpty ? "techrockstars.ztlp" : configuration.zoneName
                serviceDisplayName = "\(svc).\(zone)"
            }

            logger.info("Connected to \(target)", source: "Direct")

            // Haptic feedback for success
            UINotificationFeedbackGenerator().notificationOccurred(.success)

            // Step 6: Start VIP proxy
            await startVipProxy()

            // Step 7: Start stats polling
            startDirectStatsPolling()

        } catch {
            status = .disconnected
            lastError = error.localizedDescription
            logger.error("Direct connect failed: \(error.localizedDescription)", source: "Direct")

            // Haptic feedback for error
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
    }

    // MARK: - VIP Proxy

    /// Start VIP proxy listeners and DNS resolver.
    private func startVipProxy() async {
        let svcName = configuration.serviceName.isEmpty ? "vault" : configuration.serviceName

        do {
            // Register services with VIP addresses
            // On iOS, Safari can reach 127.0.55.1:8080 directly without DNS
            try bridge.vipAddService(name: svcName, vip: "127.0.55.1", port: 8080)
            try bridge.vipAddService(name: svcName, vip: "127.0.55.1", port: 8443)
            logger.info("VIP services registered: \(svcName) → 127.0.55.1:8080/8443", source: "VIP")

            // Start TCP proxy listeners
            try bridge.vipStart()
            logger.info("VIP proxy listeners started", source: "VIP")

            // Start DNS resolver (for future use — iOS apps can't use this without VPN extension)
            do {
                try bridge.dnsStart(listenAddr: "127.0.55.53:5354")
                logger.info("DNS resolver started on 127.0.55.53:5354", source: "VIP")
            } catch {
                // DNS is optional on iOS — continue without it
                logger.warn("DNS resolver failed (expected on iOS): \(error.localizedDescription)", source: "VIP")
            }

            vipStatus = "VIP proxy active — \(svcName).techrockstars.ztlp"
            logger.info("VIP proxy active for \(svcName)", source: "VIP")

        } catch {
            vipStatus = "VIP proxy failed: \(error.localizedDescription)"
            logger.error("VIP proxy setup failed: \(error.localizedDescription)", source: "VIP")
        }
    }

    /// Stop VIP proxy listeners and DNS.
    private func stopVipProxy() {
        bridge.vipStop()
        bridge.dnsStop()
        vipStatus = nil
        logger.info("VIP proxy stopped", source: "VIP")
    }

    // MARK: - Auto-Reconnect

    private func scheduleReconnect() {
        reconnectTask?.cancel()
        reconnectTask = Task {
            let delay = min(baseReconnectDelay * pow(2, Double(reconnectAttempt)), maxReconnectDelay)
            reconnectAttempt += 1
            status = .reconnecting
            logger.info("Reconnecting in \(String(format: "%.1f", delay))s (attempt \(reconnectAttempt))...", source: "Direct")

            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            if !Task.isCancelled {
                isReconnecting = false
                connect()
            }
        }
    }

    // MARK: - Observers

    /// Set up observers for connection events and network changes.
    private func setupObservers() {
        // Observe bridge connection events
        bridge.eventSubject
            .receive(on: DispatchQueue.main)
            .sink { [weak self] event in
                guard let self = self else { return }
                switch event {
                case .connected(let addr):
                    self.peerAddress = addr
                    self.logger.info("Bridge event: connected to \(addr)", source: "Direct")

                case .disconnected(let reason):
                    self.logger.warn("Bridge event: disconnected (reason=\(reason))", source: "Direct")
                    // Auto-reconnect if we were connected and auto-reconnect is enabled
                    if self.autoReconnectEnabled && (self.status == .connected || self.isReconnecting) {
                        self.status = .reconnecting
                        self.stopStatsPolling()
                        self.isReconnecting = true
                        self.scheduleReconnect()
                    } else if !self.isReconnecting {
                        self.status = .disconnected
                        self.reconnectAttempt = 0
                        self.reconnectTask?.cancel()
                        self.stats = TrafficStats()
                        self.stopStatsPolling()
                    }

                case .error(let error):
                    self.lastError = error.localizedDescription
                    self.logger.error("Bridge event: error — \(error.localizedDescription)", source: "Direct")

                default:
                    break
                }
            }
            .store(in: &cancellables)

        // Observe network interface changes (WiFi ↔ Cellular)
        networkMonitor.interfaceChangePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newInterface in
                guard let self = self else { return }
                guard self.status == .connected || self.status == .reconnecting else { return }
                // Don't reconnect if network dropped entirely
                guard newInterface != .none else {
                    self.status = .reconnecting
                    self.logger.warn("Network lost, waiting for connectivity...", source: "Network")
                    return
                }
                self.logger.warn("Network interface changed to \(newInterface.rawValue), reconnecting...", source: "Network")
                self.status = .reconnecting
                self.isReconnecting = true
                self.stopStatsPolling()
                self.bridge.disconnectTransport()
                self.scheduleReconnect()
            }
            .store(in: &cancellables)

        // Observe configuration changes
        configuration.$zoneName
            .receive(on: DispatchQueue.main)
            .assign(to: &$zoneName)
    }

    // MARK: - Stats Polling

    /// Start polling traffic stats directly from the bridge.
    private func startDirectStatsPolling() {
        stopStatsPolling()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshDirectStats()
            }
        }
    }

    /// Stop the stats polling timer.
    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
    }

    /// Read latest stats directly from the bridge.
    private func refreshDirectStats() {
        stats.bytesSent = bridge.bytesSent
        stats.bytesReceived = bridge.bytesReceived
    }

    // MARK: - Identity Path

    /// Default identity file path in the shared app group container.
    private func defaultIdentityPath() -> String? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) else {
            // Fallback to Application Support
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory, in: .userDomainMask
            ).first
            guard let dir = appSupport?.appendingPathComponent("ZTLP") else { return nil }
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir.appendingPathComponent("identity.json").path
        }
        return containerURL.appendingPathComponent("identity.json").path
    }
}
