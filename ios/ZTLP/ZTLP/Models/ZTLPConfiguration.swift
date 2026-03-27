// ZTLPConfiguration.swift
// ZTLP
//
// Persisted app configuration. Stored in UserDefaults (app group shared)
// so both the main app and the Network Extension can read it.

import Foundation

/// App-level ZTLP configuration, persisted across launches.
final class ZTLPConfiguration: ObservableObject {

    // MARK: - Keys

    private enum Key {
        static let relayAddress = "config_relay_address"
        static let stunServer = "config_stun_server"
        static let targetNodeId = "config_target_node_id"
        static let zoneName = "config_zone_name"
        static let tunnelAddress = "config_tunnel_address"
        static let dnsServers = "config_dns_servers"
        static let mtu = "config_mtu"
        static let natAssist = "config_nat_assist"
        static let autoConnect = "config_auto_connect"
        static let useSecureEnclave = "config_use_secure_enclave"
        static let hasCompletedOnboarding = "config_onboarding_complete"
        static let isEnrolled = "config_is_enrolled"
        static let fullTunnel = "config_full_tunnel"
        static let nsServer = "config_ns_server"
        static let serviceName = "config_service_name"
    }

    // MARK: - Storage

    private let defaults: UserDefaults

    // MARK: - Published Properties

    /// Relay server address (e.g., "relay.ztlp.net:4433").
    @Published var relayAddress: String {
        didSet { defaults.set(relayAddress, forKey: Key.relayAddress) }
    }

    /// STUN server for NAT discovery.
    @Published var stunServer: String {
        didSet { defaults.set(stunServer, forKey: Key.stunServer) }
    }

    /// Target peer Node ID (hex string).
    @Published var targetNodeId: String {
        didSet { defaults.set(targetNodeId, forKey: Key.targetNodeId) }
    }

    /// Zone name this device is enrolled in.
    @Published var zoneName: String {
        didSet { defaults.set(zoneName, forKey: Key.zoneName) }
    }

    /// TUN interface address.
    @Published var tunnelAddress: String {
        didSet { defaults.set(tunnelAddress, forKey: Key.tunnelAddress) }
    }

    /// DNS servers while tunnel is active.
    @Published var dnsServers: [String] {
        didSet { defaults.set(dnsServers, forKey: Key.dnsServers) }
    }

    /// MTU for the TUN interface.
    @Published var mtu: Int {
        didSet { defaults.set(mtu, forKey: Key.mtu) }
    }

    /// Whether NAT traversal assistance is enabled.
    @Published var natAssist: Bool {
        didSet { defaults.set(natAssist, forKey: Key.natAssist) }
    }

    /// Auto-connect on app launch.
    @Published var autoConnect: Bool {
        didSet { defaults.set(autoConnect, forKey: Key.autoConnect) }
    }

    /// Use Secure Enclave for key storage (if available).
    @Published var useSecureEnclave: Bool {
        didSet { defaults.set(useSecureEnclave, forKey: Key.useSecureEnclave) }
    }

    /// Whether the user has completed the onboarding flow.
    @Published var hasCompletedOnboarding: Bool {
        didSet { defaults.set(hasCompletedOnboarding, forKey: Key.hasCompletedOnboarding) }
    }

    /// Whether the device is enrolled in a zone.
    @Published var isEnrolled: Bool {
        didSet { defaults.set(isEnrolled, forKey: Key.isEnrolled) }
    }

    /// Full tunnel mode (all traffic through VPN) vs split tunnel (.ztlp only).
    @Published var fullTunnel: Bool {
        didSet { defaults.set(fullTunnel, forKey: Key.fullTunnel) }
    }

    /// NS server address for ZTLP-NS resolution (e.g., "52.39.59.34:23096").
    @Published var nsServer: String {
        didSet { defaults.set(nsServer, forKey: Key.nsServer) }
    }

    /// Service name for NS resolution and VIP proxy (e.g., "vault").
    @Published var serviceName: String {
        didSet { defaults.set(serviceName, forKey: Key.serviceName) }
    }

    // MARK: - Init

    init(suiteName: String = "group.com.ztlp.shared") {
        let store = UserDefaults(suiteName: suiteName) ?? .standard
        self.defaults = store

        self.relayAddress = store.string(forKey: Key.relayAddress) ?? ""
        self.stunServer = store.string(forKey: Key.stunServer) ?? "stun.l.google.com:19302"
        self.targetNodeId = store.string(forKey: Key.targetNodeId) ?? ""
        self.zoneName = store.string(forKey: Key.zoneName) ?? ""
        self.tunnelAddress = store.string(forKey: Key.tunnelAddress) ?? "10.0.0.2"
        self.dnsServers = store.stringArray(forKey: Key.dnsServers) ?? ["1.1.1.1", "8.8.8.8"]
        self.mtu = store.integer(forKey: Key.mtu) == 0 ? 1400 : store.integer(forKey: Key.mtu)
        self.natAssist = store.object(forKey: Key.natAssist) == nil ? true : store.bool(forKey: Key.natAssist)
        self.autoConnect = store.bool(forKey: Key.autoConnect)
        self.useSecureEnclave = store.object(forKey: Key.useSecureEnclave) == nil ? true : store.bool(forKey: Key.useSecureEnclave)
        self.hasCompletedOnboarding = store.bool(forKey: Key.hasCompletedOnboarding)
        self.isEnrolled = store.bool(forKey: Key.isEnrolled)
        self.fullTunnel = store.bool(forKey: Key.fullTunnel)
        self.nsServer = store.string(forKey: Key.nsServer) ?? ""
        self.serviceName = store.string(forKey: Key.serviceName) ?? "vault"
    }

    /// Create a TunnelConfiguration from the current app settings.
    func toTunnelConfiguration() -> TunnelConfiguration {
        TunnelConfiguration(
            targetNodeId: targetNodeId,
            relayAddress: relayAddress.isEmpty ? nil : relayAddress,
            stunServer: stunServer,
            tunnelAddress: tunnelAddress,
            tunnelNetmask: "255.255.255.0",
            dnsServers: dnsServers,
            mtu: mtu,
            identityPath: nil,
            fullTunnel: fullTunnel,
            nsServer: nsServer.isEmpty ? nil : nsServer,
            serviceName: serviceName.isEmpty ? nil : serviceName,
            zoneName: zoneName.isEmpty ? nil : zoneName
        )
    }

    /// Reset all settings to defaults.
    func reset() {
        relayAddress = ""
        stunServer = "stun.l.google.com:19302"
        targetNodeId = ""
        zoneName = ""
        tunnelAddress = "10.0.0.2"
        dnsServers = ["1.1.1.1", "8.8.8.8"]
        mtu = 1400
        natAssist = true
        autoConnect = false
        useSecureEnclave = true
        hasCompletedOnboarding = false
        isEnrolled = false
        fullTunnel = false
        nsServer = ""
        serviceName = "vault"
    }

    /// Human-readable summary for debugging.
    var summary: String {
        """
        Zone: \(zoneName.isEmpty ? "(none)" : zoneName)
        Relay: \(relayAddress.isEmpty ? "(none)" : relayAddress)
        NS Server: \(nsServer.isEmpty ? "(none)" : nsServer)
        Service: \(serviceName.isEmpty ? "(none)" : serviceName)
        Target: \(targetNodeId.isEmpty ? "(none)" : targetNodeId)
        NAT Assist: \(natAssist)
        Enrolled: \(isEnrolled)
        """
    }
}
