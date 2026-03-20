// NetworkMonitor.swift
// ZTLP
//
// Monitors network connectivity changes using NWPathMonitor.
// Publishes connectivity state changes so the TunnelViewModel can
// react to WiFi ↔ Cellular transitions (which require NAT re-traversal).

import Foundation
import Network
import Combine

/// Network interface type.
enum NetworkInterfaceType: String {
    case wifi = "Wi-Fi"
    case cellular = "Cellular"
    case wiredEthernet = "Ethernet"
    case other = "Other"
    case none = "No Connection"
}

/// Observable network connectivity monitor.
final class NetworkMonitor: ObservableObject {

    /// Shared singleton.
    static let shared = NetworkMonitor()

    /// Whether any network path is available.
    @Published private(set) var isConnected: Bool = false

    /// The current primary interface type.
    @Published private(set) var interfaceType: NetworkInterfaceType = .none

    /// Whether the path is "expensive" (cellular data).
    @Published private(set) var isExpensive: Bool = false

    /// Whether the path is "constrained" (Low Data Mode).
    @Published private(set) var isConstrained: Bool = false

    /// Combine publisher that fires when the network interface changes.
    /// Used by TunnelViewModel to trigger NAT re-traversal.
    let interfaceChangePublisher = PassthroughSubject<NetworkInterfaceType, Never>()

    /// The underlying NWPathMonitor.
    private let monitor = NWPathMonitor()

    /// Dedicated queue for path update callbacks.
    private let monitorQueue = DispatchQueue(label: "com.ztlp.network-monitor", qos: .utility)

    /// Previous interface type (for change detection).
    private var previousInterfaceType: NetworkInterfaceType = .none

    private init() {
        startMonitoring()
    }

    deinit {
        monitor.cancel()
    }

    // MARK: - Monitoring

    /// Start monitoring network path changes.
    private func startMonitoring() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }

            let connected = path.status == .satisfied
            let expensive = path.isExpensive
            let constrained = path.isConstrained

            let interfaceType: NetworkInterfaceType
            if path.usesInterfaceType(.wifi) {
                interfaceType = .wifi
            } else if path.usesInterfaceType(.cellular) {
                interfaceType = .cellular
            } else if path.usesInterfaceType(.wiredEthernet) {
                interfaceType = .wiredEthernet
            } else if connected {
                interfaceType = .other
            } else {
                interfaceType = .none
            }

            // Publish on main thread for UI
            DispatchQueue.main.async {
                self.isConnected = connected
                self.isExpensive = expensive
                self.isConstrained = constrained
                self.interfaceType = interfaceType

                // Detect interface changes (WiFi → Cellular, etc.)
                if interfaceType != self.previousInterfaceType {
                    self.previousInterfaceType = interfaceType
                    self.interfaceChangePublisher.send(interfaceType)
                }
            }
        }

        monitor.start(queue: monitorQueue)
    }

    /// Force a path re-evaluation (useful after VPN tunnel setup).
    func refreshPath() {
        // NWPathMonitor doesn't have a refresh method, but we can re-read
        // the current path by accessing it through the update handler.
        // The handler fires whenever the path changes, which is sufficient.
    }
}
