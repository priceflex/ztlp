// TunnelManager.swift
// Owns the one NETunnelProviderManager: saves the VPN configuration with an
// on-demand "always connect" rule, reports its state, and removes it.
//
// There is no user-facing connect or disconnect. iOS keeps the tunnel up
// through the on-demand rule.

import Foundation
import NetworkExtension

@MainActor
final class TunnelManager {
    private var manager: NETunnelProviderManager?

    /// Load the configuration unless one is already held and still valid.
    func loadIfNeeded() async {
        if let manager, manager.connection.status != .invalid { return }
        await load()
    }

    /// Load the saved configuration, if any.
    @discardableResult
    func load() async -> Bool {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = all.first { candidate in
                (candidate.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == SharedPaths.tunnelBundleID
            }
        } catch {
            manager = nil
        }
        return manager != nil
    }

    /// Create or repair the configuration, enable on-demand, and start it.
    /// The first save shows the iOS "Add VPN Configurations" prompt.
    func installAndStart() async throws {
        // Always look again: the user may have deleted the configuration in
        // Settings, which leaves the old object unusable.
        await load()
        let target = manager ?? NETunnelProviderManager()

        let proto = (target.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = SharedPaths.tunnelBundleID
        // Required by iOS and shown in Settings; there is no single server.
        proto.serverAddress = "ZTLP"
        target.protocolConfiguration = proto
        target.localizedDescription = "ZTLP"

        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        target.onDemandRules = [rule]
        target.isOnDemandEnabled = true
        target.isEnabled = true

        try await target.saveToPreferences()
        // A freshly saved manager must be reloaded before it can start.
        try await target.loadFromPreferences()
        manager = target

        switch target.connection.status {
        case .connected, .connecting, .reasserting:
            break
        default:
            try target.connection.startVPNTunnel()
        }
    }

    /// Turn off on-demand, stop the tunnel and delete the configuration.
    func remove() async {
        if manager == nil { await load() }
        guard let target = manager else { return }
        target.isOnDemandEnabled = false
        try? await target.saveToPreferences()
        target.connection.stopVPNTunnel()
        try? await target.removeFromPreferences()
        manager = nil
    }

    /// Current phase, including iOS's reason when the tunnel is down.
    func phase() async -> TunnelPhase {
        guard let manager else { return .notConfigured }
        switch manager.connection.status {
        case .connected:
            return .connected
        case .connecting, .reasserting:
            return .connecting
        case .invalid:
            return .notConfigured
        case .disconnecting, .disconnected:
            if !manager.isEnabled || !manager.isOnDemandEnabled {
                return .disconnected(reason: "ZTLP is turned off in Settings. Tap Fix to turn it back on.")
            }
            return .disconnected(reason: await lastDisconnectReason(manager.connection))
        @unknown default:
            return .unknown
        }
    }

    /// Ask the running extension for the agent's status JSON.
    func providerStatus() async -> AgentStatus? {
        guard let session = manager?.connection as? NETunnelProviderSession,
              session.status == .connected else { return nil }
        let data: Data? = await withCheckedContinuation { continuation in
            let once = ResumeOnce(continuation)
            do {
                try session.sendProviderMessage(Data("status".utf8)) { reply in
                    once.resume(reply)
                }
            } catch {
                once.resume(nil)
                return
            }
            // The reply handler is not guaranteed to run if the extension
            // goes away mid-request.
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                once.resume(nil)
            }
        }
        return data.flatMap(AgentStatus.decode)
    }

    private func lastDisconnectReason(_ connection: NEVPNConnection) async -> String? {
        await withCheckedContinuation { continuation in
            let once = ResumeOnce(continuation)
            connection.fetchLastDisconnectError { error in
                once.resume(error?.localizedDescription)
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                once.resume(nil)
            }
        }
    }
}

/// Resumes a continuation exactly once, whichever caller gets there first.
private final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T?, Never>?

    init(_ continuation: CheckedContinuation<T?, Never>) {
        self.continuation = continuation
    }

    func resume(_ value: T?) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}
