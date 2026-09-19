// TunnelViewModel.swift
// ZTLP macOS
//
// Task 6b (Option A, thin shell): the GUI no longer owns a data plane.
// The root `ztlp agent` LaunchDaemon (installed via SMAppService, see
// AgentServiceInstaller) does DNS, VIP allocation, TLS minting, CA trust and
// the QUIC tunnels. This view model only:
//
//   1. asks the daemon "are you there / what's your state" over its JSON
//      control socket (AgentControlClient -> 127.100.255.1:4433), mirroring
//      desktop/src-tauri/src/tunnel.rs (agent_is_reachable_at +
//      wait_for_agent_ready) on the Windows side, and
//   2. maps the Home "Connect"/"Disconnect" toggle onto the ONLY privileged
//      lever the non-root GUI has: SMAppService register()/unregister() of
//      the root daemon. Steven's call (session 6): Disconnect really stops
//      the service; Connect really starts it. No sudo, no Terminal.
//
// Because the daemon plist is KeepAlive=true, a control-socket "shutdown"
// would just be respawned by launchd — so unregister() is the correct
// "stop", not "shutdown".

import Foundation
import AppKit
import Combine
import SwiftUI

/// What the daemon last told us about itself (control "status" +
/// "setup_status" + "tunnels"). Nil until the first successful poll.
struct DaemonSnapshot: Equatable {
    var version: String = ""
    var dnsListen: String = ""
    var nsServer: String = ""
    var vipAllocated: Int = 0
    var uptimeSecs: Int = 0
    var zone: String = ""
    var identityEnrolled: Bool = false
    var caInstalled: Bool = false
    var dnsConfigured: Bool = false
    var activeTunnels: Int = 0
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0

    /// One-line human summary for the Home screen (6d: "one status line").
    var statusLine: String {
        if !identityEnrolled { return "Service running — not enrolled yet" }
        var parts: [String] = []
        parts.append(caInstalled ? "HTTPS trusted" : "HTTPS trust missing")
        parts.append(dnsConfigured ? "DNS routed" : "DNS not routed")
        if activeTunnels > 0 {
            parts.append("\(activeTunnels) active tunnel\(activeTunnels == 1 ? "" : "s")")
        }
        return parts.joined(separator: " · ")
    }
}

/// ViewModel for the main connect/disconnect UI.
@MainActor
final class TunnelViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var status: ConnectionStatus = .disconnected
    @Published private(set) var stats = TrafficStats()
    @Published private(set) var zoneName: String = ""
    @Published private(set) var lastError: String?
    @Published private(set) var testResult: String?
    @Published private(set) var daemon: DaemonSnapshot?
    /// Mirrors AgentServiceInstaller.state so Home can say "Needs approval"
    /// (System Settings > Login Items) instead of a generic "Disconnected".
    @Published private(set) var serviceState: AgentServiceState = .notRegistered

    // MARK: - Tunables (mirror desktop/src-tauri/src/tunnel.rs)

    /// Poll cadence while the app is open (Windows UI polls ~2s).
    static let pollInterval: TimeInterval = 2
    /// How long Connect waits for the freshly registered daemon to answer.
    static let readyTimeout: TimeInterval = 15
    /// How long Disconnect waits for the daemon to actually go away.
    static let stopTimeout: TimeInterval = 8
    static let readyPollInterval: TimeInterval = 0.25

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let installer = AgentServiceInstaller.shared
    private var cancellables = Set<AnyCancellable>()
    private var pollTask: Task<Void, Never>?
    /// Set while a user-initiated connect/disconnect is in flight so the
    /// background poller doesn't flip `status` under it.
    private var transitionInFlight = false

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.zoneName = configuration.zoneName
        setupObservers()
        startPolling()
    }

    deinit {
        pollTask?.cancel()
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

    /// Connect = make sure the root daemon is installed and answering.
    ///
    /// Mirrors `start_tunnel` on Windows: if the agent already answers its
    /// control socket, we're done; otherwise start it (here: SMAppService
    /// register, which is what launches the LaunchDaemon) and poll until it
    /// answers or we time out.
    func connect() {
        guard status.canConnect, !transitionInFlight else { return }
        lastError = nil
        status = .connecting
        transitionInFlight = true
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        Task {
            defer { transitionInFlight = false }

            if await Self.daemonReachable() {
                await refresh()
                status = .connected
                return
            }

            installer.register()
            serviceState = installer.state

            switch installer.state {
            case .requiresApproval:
                // macOS wants a human click in System Settings. That IS the
                // one system prompt Steven accepted (UAC equivalent); we
                // can't approve programmatically, so send them there.
                installer.openLoginItemsSettings()
                status = .disconnected
                lastError = "Approve “ZTLP” under System Settings › General › Login Items & Extensions, then press Connect again."
                return
            case .failed(let msg):
                status = .disconnected
                lastError = "Could not start the ZTLP service: \(msg)"
                NSSound.beep()
                return
            case .notFound:
                status = .disconnected
                lastError = "The ZTLP service is missing from this app bundle (org.ztlp.agent.plist). Reinstall ZTLP."
                NSSound.beep()
                return
            case .notRegistered:
                if let err = installer.lastError {
                    status = .disconnected
                    lastError = "Could not start the ZTLP service: \(err)"
                    NSSound.beep()
                    return
                }
            case .running:
                break
            }

            if await Self.waitForDaemon(reachable: true, timeout: Self.readyTimeout) {
                await refresh()
                status = .connected
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
            } else {
                status = .disconnected
                lastError = "The ZTLP service was installed but did not answer within \(Int(Self.readyTimeout))s."
                NSSound.beep()
            }
        }
    }

    /// Disconnect = stop the root daemon by unregistering it (KeepAlive
    /// means a plain "shutdown" would respawn — see header comment).
    func disconnect() {
        guard status.canDisconnect, !transitionInFlight else { return }
        lastError = nil
        status = .disconnecting
        transitionInFlight = true
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        Task {
            defer { transitionInFlight = false }

            installer.unregister()
            serviceState = installer.state
            if case .failed(let msg) = installer.state {
                lastError = "Could not stop the ZTLP service: \(msg)"
            } else if let err = installer.lastError {
                lastError = "Could not stop the ZTLP service: \(err)"
            }

            _ = await Self.waitForDaemon(reachable: false, timeout: Self.stopTimeout)
            let stillUp = await Self.daemonReachable()
            if stillUp {
                // launchd hasn't torn it down yet (or unregister failed).
                // Report honestly rather than showing a fake "Disconnected".
                status = .connected
                if lastError == nil {
                    lastError = "The ZTLP service is still running. Try again in a moment."
                }
            } else {
                status = .disconnected
                stats = TrafficStats()
                daemon = nil
            }
        }
    }

    // MARK: - Daemon polling (the "IPC" half of tunnel.rs)

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOnce()
                try? await Task.sleep(nanoseconds: UInt64(Self.pollInterval * 1_000_000_000))
            }
        }
    }

    private func pollOnce() async {
        serviceState = installer.state
        installer.refreshState()
        serviceState = installer.state

        guard !transitionInFlight else { return }

        if await Self.daemonReachable() {
            missedPolls = 0
            await refresh()
            if status != .connected {
                status = .connected
                if stats.connectedSince == nil { stats.connectedSince = Date() }
            }
        } else if status == .connected || status == .reconnecting {
            // We were up and the daemon vanished (crash, manual unload).
            // KeepAlive normally brings it straight back, so show
            // "Reconnecting" for a few polls before a hard Disconnected.
            missedPolls += 1
            if missedPolls >= Self.missedPollsBeforeDisconnected {
                status = .disconnected
                daemon = nil
                stats = TrafficStats()
                missedPolls = 0
            } else {
                status = .reconnecting
            }
        }
    }

    /// Consecutive failed polls while we believed we were connected.
    private var missedPolls = 0
    /// ~3 polls x 2s = 6s grace for launchd KeepAlive to respawn the daemon.
    static let missedPollsBeforeDisconnected = 3

    /// Pull status + setup_status + tunnels from the daemon and fold them
    /// into `daemon`, `zoneName`, `stats`.
    func refresh() async {
        var snap = daemon ?? DaemonSnapshot()

        if let st = try? await AgentControlClient.send(cmd: "status", timeout: 3),
           st.ok, case .object(let o)? = st.data {
            snap.version = o["version"]?.stringValue ?? snap.version
            snap.dnsListen = o["dns_listen"]?.stringValue ?? snap.dnsListen
            snap.nsServer = o["ns_server"]?.stringValue ?? snap.nsServer
            snap.vipAllocated = o["vip_allocated"]?.intValue ?? snap.vipAllocated
            snap.uptimeSecs = o["uptime_secs"]?.intValue ?? snap.uptimeSecs
        }

        if let ss = try? await AgentControlClient.send(cmd: "setup_status", timeout: 3),
           ss.ok, case .object(let o)? = ss.data {
            snap.zone = o["zone"]?.stringValue ?? ""
            snap.identityEnrolled = o["identity_enrolled"]?.boolValue ?? false
            snap.caInstalled = o["ca_installed_system_trust"]?.boolValue ?? false
            snap.dnsConfigured = o["dns_configured"]?.boolValue ?? false
        }

        if let tn = try? await AgentControlClient.send(cmd: "tunnels", timeout: 3),
           tn.ok, case .object(let o)? = tn.data {
            snap.activeTunnels = o["active"]?.intValue ?? 0
            var tx: UInt64 = 0
            var rx: UInt64 = 0
            if case .array(let list)? = o["tunnels"] {
                for case .object(let t) in list {
                    tx += UInt64(t["bytes_sent"]?.intValue ?? 0)
                    rx += UInt64(t["bytes_recv"]?.intValue ?? 0)
                }
            }
            snap.bytesSent = tx
            snap.bytesReceived = rx
        }

        daemon = snap

        // Zone: the daemon's own enrollment is the truth for what DNS/TLS
        // will serve; fall back to the app's stored zone before enrollment.
        let effectiveZone = snap.zone.isEmpty ? configuration.zoneName : snap.zone
        if effectiveZone != zoneName { zoneName = effectiveZone }

        // Stats: uptime-derived connectedSince keeps the duration counter
        // honest across app relaunches (the daemon may have been up for days).
        if snap.uptimeSecs > 0 {
            stats.connectedSince = Date(timeIntervalSinceNow: -TimeInterval(snap.uptimeSecs))
        } else if stats.connectedSince == nil {
            stats.connectedSince = Date()
        }
        if snap.bytesSent != stats.bytesSent || snap.bytesReceived != stats.bytesReceived {
            stats.lastActivity = Date()
        }
        stats.bytesSent = snap.bytesSent
        stats.bytesReceived = snap.bytesReceived
    }

    // MARK: - Reachability helpers (agent_is_reachable_at / wait_for_agent_ready)

    /// One "status" round trip on the control socket. Reachable = the
    /// daemon answered *anything* well-formed (an auth error still proves
    /// it's alive; the token problem surfaces via lastError elsewhere).
    static func daemonReachable() async -> Bool {
        do {
            _ = try await AgentControlClient.send(cmd: "status", timeout: 2)
            return true
        } catch AgentControlError.daemonError {
            return true
        } catch {
            return false
        }
    }

    /// Poll until `daemonReachable() == reachable` or timeout. Returns true
    /// if the desired state was reached.
    static func waitForDaemon(reachable want: Bool, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if await daemonReachable() == want { return true }
            if Date() >= deadline { return false }
            try? await Task.sleep(nanoseconds: UInt64(readyPollInterval * 1_000_000_000))
        }
    }

    // MARK: - Service Test

    /// The real user test from §0.1: fetch the zone service over HTTPS the
    /// way Safari would (system resolver -> /etc/resolver -> agent DNS ->
    /// VIP -> local TLS with the trusted ZTLP CA). No `-k`, no custom
    /// resolver — if this returns 200 the browser will too.
    func testService() async {
        guard status == .connected else {
            testResult = "Not connected"
            return
        }
        let zone = zoneName
        let svc = configuration.serviceName
        guard !zone.isEmpty, !svc.isEmpty else {
            testResult = "Set a service name and enroll first"
            return
        }
        let host = svc.contains(".") ? svc : "\(svc).\(zone)"
        guard let url = URL(string: "https://\(host)/") else {
            testResult = "Bad service host: \(host)"
            return
        }
        testResult = "Testing https://\(host)/ …"

        var req = URLRequest(url: url)
        req.timeoutInterval = 15
        req.cachePolicy = .reloadIgnoringLocalCacheData
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let body = String(data: data, encoding: .utf8) ?? ""
            let hmac = body.contains("hmac_verified\": true") || body.contains("hmac_verified\":true")
            if (200..<400).contains(code) {
                testResult = "✅ HTTPS \(code) from \(host) (\(data.count)B)\(hmac ? ", identity verified by gateway" : "")"
            } else {
                testResult = "⚠️ HTTPS \(code) from \(host)"
            }
        } catch {
            testResult = "Error: \(error.localizedDescription)"
        }
    }

    // MARK: - Observers

    private func setupObservers() {
        configuration.$zoneName
            .receive(on: DispatchQueue.main)
            .sink { [weak self] z in
                guard let self else { return }
                if self.daemon?.zone.isEmpty ?? true { self.zoneName = z }
            }
            .store(in: &cancellables)

        installer.$state
            .receive(on: DispatchQueue.main)
            .sink { [weak self] s in self?.serviceState = s }
            .store(in: &cancellables)

        // Re-poll immediately when the user comes back (e.g. after approving
        // the daemon in System Settings) instead of waiting a full tick.
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in Task { await self?.pollOnce() } }
            .store(in: &cancellables)
    }
}

// MARK: - JSONValue conveniences used above

extension JSONValue {
    var intValue: Int? {
        if case .number(let d) = self { return Int(d) }
        return nil
    }
    var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }
}
