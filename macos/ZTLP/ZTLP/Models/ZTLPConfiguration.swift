// ZTLPConfiguration.swift
// ZTLP macOS
//
// Persisted app configuration. Stored in UserDefaults (app group suite).
//
// Task 6c: TUN/VPN-only fields (tunnel address, DNS servers, MTU, STUN,
// NAT assist) removed with the System Extension. The daemon owns
// networking; the app keeps only enrollment facts + UI preferences.
// relayAddress/targetNodeId are informational (written by enrollment from
// the token) — the daemon reads its own agent.toml, not these.

import Foundation

/// App-level ZTLP configuration, persisted across launches.
final class ZTLPConfiguration: ObservableObject {

    // MARK: - Keys

    private enum Key {
        static let relayAddress = "config_relay_address"
        static let targetNodeId = "config_target_node_id"
        static let zoneName = "config_zone_name"
        static let autoConnect = "config_auto_connect"
        static let useSecureEnclave = "config_use_secure_enclave"
        static let hasCompletedOnboarding = "config_onboarding_complete"
        static let isEnrolled = "config_is_enrolled"
        static let serviceName = "config_service_name"
    }

    // MARK: - Storage

    private let defaults: UserDefaults

    // MARK: - Published Properties

    /// Relay server address (e.g., "relay.ztlp.net:4433").
    @Published var relayAddress: String {
        didSet { defaults.set(relayAddress, forKey: Key.relayAddress) }
    }

    /// Target peer Node ID (hex string).
    @Published var targetNodeId: String {
        didSet { defaults.set(targetNodeId, forKey: Key.targetNodeId) }
    }

    /// Zone name this device is enrolled in.
    @Published var zoneName: String {
        didSet { defaults.set(zoneName, forKey: Key.zoneName) }
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

    /// Target service name for gateway routing (e.g., "beta").
    @Published var serviceName: String {
        didSet { defaults.set(serviceName, forKey: Key.serviceName) }
    }

    // MARK: - Init

    init(suiteName: String = "group.com.ztlp.shared.macos") {
        let store = UserDefaults(suiteName: suiteName) ?? .standard
        self.defaults = store

        self.relayAddress = store.string(forKey: Key.relayAddress) ?? ""
        self.targetNodeId = store.string(forKey: Key.targetNodeId) ?? ""
        self.zoneName = store.string(forKey: Key.zoneName) ?? ""
        self.autoConnect = store.bool(forKey: Key.autoConnect)
        self.useSecureEnclave = store.object(forKey: Key.useSecureEnclave) == nil ? true : store.bool(forKey: Key.useSecureEnclave)
        self.hasCompletedOnboarding = store.bool(forKey: Key.hasCompletedOnboarding)
        self.isEnrolled = store.bool(forKey: Key.isEnrolled)
        self.serviceName = store.string(forKey: Key.serviceName) ?? "beta"
    }

    /// Reset all settings to defaults.
    func reset() {
        relayAddress = ""
        targetNodeId = ""
        zoneName = ""
        autoConnect = false
        useSecureEnclave = true
        hasCompletedOnboarding = false
        isEnrolled = false
        serviceName = "beta"
    }
}
