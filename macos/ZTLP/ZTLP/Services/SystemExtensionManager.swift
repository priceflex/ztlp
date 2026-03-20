// SystemExtensionManager.swift
// ZTLP macOS
//
// Manages the lifecycle of the ZTLP System Extension.
// On macOS, VPN packet tunnels require a System Extension (not an App Extension).
// This class handles activation, deactivation, and status tracking.

import Foundation
import SystemExtensions
import NetworkExtension
import Combine

/// State of the system extension.
enum SystemExtensionState: Equatable {
    case unknown
    case needsApproval
    case activating
    case activated
    case deactivating
    case failed(String)
}

/// Manages the ZTLP System Extension lifecycle.
final class SystemExtensionManager: NSObject, ObservableObject {

    static let shared = SystemExtensionManager()

    /// Bundle identifier of the system extension.
    private let extensionBundleId = "com.ztlp.app.macos.system-extension"

    /// Current state of the system extension.
    @Published private(set) var state: SystemExtensionState = .unknown

    /// Whether the VPN tunnel manager is configured.
    @Published private(set) var tunnelManagerConfigured: Bool = false

    /// The NETunnelProviderManager for our VPN.
    private(set) var tunnelManager: NETunnelProviderManager?

    private override init() {
        super.init()
    }

    // MARK: - Extension Lifecycle

    /// Request activation of the system extension.
    func activateExtension() {
        state = .activating
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Request deactivation of the system extension.
    func deactivateExtension() {
        state = .deactivating
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - VPN Manager

    /// Load or create the NETunnelProviderManager.
    func loadTunnelManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == extensionBundleId
        }) {
            self.tunnelManager = existing
            self.tunnelManagerConfigured = true
            return existing
        }

        let manager = NETunnelProviderManager()
        self.tunnelManager = manager
        return manager
    }

    /// Configure and save the tunnel manager with the given settings.
    func configureTunnel(with configuration: ZTLPConfiguration) async throws {
        let manager = try await loadTunnelManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extensionBundleId
        proto.serverAddress = configuration.relayAddress.isEmpty
            ? configuration.targetNodeId
            : configuration.relayAddress
        proto.providerConfiguration = [
            "targetNodeId": configuration.targetNodeId,
            "relayAddress": configuration.relayAddress,
            "stunServer": configuration.stunServer,
            "tunnelAddress": configuration.tunnelAddress,
            "dnsServers": configuration.dnsServers,
            "mtu": configuration.mtu,
        ]

        manager.protocolConfiguration = proto
        manager.localizedDescription = "ZTLP VPN"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        tunnelManagerConfigured = true
    }

    /// Remove the VPN configuration.
    func removeTunnelConfiguration() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        for manager in managers {
            try await manager.removeFromPreferences()
        }
        tunnelManager = nil
        tunnelManagerConfigured = false
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        DispatchQueue.main.async {
            self.state = .needsApproval
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        DispatchQueue.main.async {
            switch result {
            case .completed:
                self.state = .activated
            case .willCompleteAfterReboot:
                self.state = .needsApproval
            @unknown default:
                self.state = .failed("Unknown result")
            }
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        DispatchQueue.main.async {
            self.state = .failed(error.localizedDescription)
        }
    }
}
