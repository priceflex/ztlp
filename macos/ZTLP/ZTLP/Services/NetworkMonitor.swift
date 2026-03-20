// NetworkMonitor.swift
// ZTLP macOS
//
// Monitors network connectivity changes using NWPathMonitor.
// Adapted from iOS — adds wiredEthernet as a primary interface type on macOS.

import Foundation
import Network
import Combine

/// Network interface type.
enum NetworkInterfaceType: String {
    case wifi = "Wi-Fi"
    case wiredEthernet = "Ethernet"
    case other = "Other"
    case none = "No Connection"
}

/// Observable network connectivity monitor.
final class NetworkMonitor: ObservableObject {

    static let shared = NetworkMonitor()

    @Published private(set) var isConnected: Bool = false
    @Published private(set) var interfaceType: NetworkInterfaceType = .none
    @Published private(set) var isExpensive: Bool = false
    @Published private(set) var isConstrained: Bool = false

    let interfaceChangePublisher = PassthroughSubject<NetworkInterfaceType, Never>()

    private let monitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.ztlp.network-monitor", qos: .utility)
    private var previousInterfaceType: NetworkInterfaceType = .none

    private init() {
        startMonitoring()
    }

    deinit {
        monitor.cancel()
    }

    private func startMonitoring() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }

            let connected = path.status == .satisfied
            let expensive = path.isExpensive
            let constrained = path.isConstrained

            let interfaceType: NetworkInterfaceType
            if path.usesInterfaceType(.wiredEthernet) {
                interfaceType = .wiredEthernet
            } else if path.usesInterfaceType(.wifi) {
                interfaceType = .wifi
            } else if connected {
                interfaceType = .other
            } else {
                interfaceType = .none
            }

            DispatchQueue.main.async {
                self.isConnected = connected
                self.isExpensive = expensive
                self.isConstrained = constrained
                self.interfaceType = interfaceType

                if interfaceType != self.previousInterfaceType {
                    self.previousInterfaceType = interfaceType
                    self.interfaceChangePublisher.send(interfaceType)
                }
            }
        }

        monitor.start(queue: monitorQueue)
    }

    func refreshPath() {
        // NWPathMonitor fires automatically on changes
    }
}
