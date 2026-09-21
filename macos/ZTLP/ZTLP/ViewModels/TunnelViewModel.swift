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
    /// The daemon has generated its device-local CA (ca/root.pem exists).
    var caInitialized: Bool = false
    /// Absolute path of the daemon's root.pem — what "Trust HTTPS" installs.
    var caRootPemPath: String = ""
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

// MARK: - Task 8: readiness checklist (single-page Home)

/// State of one row on the Home readiness checklist.
enum ReadinessState: Equatable {
    /// Green check — nothing to do.
    case ready(String)
    /// Grey/orange — something the user must do; `action` is the one button.
    case needsAction(String, action: ReadinessAction)
    /// Spinner — waiting on a previous row / the daemon.
    case waiting(String)
    /// Red — something failed; message is shown verbatim.
    case failed(String)

    var isReady: Bool {
        if case .ready = self { return true }
        return false
    }
}

/// The single action a checklist row can offer.
enum ReadinessAction: Equatable {
    case installService
    case openLoginItems
    case enroll
    /// Row 3: install the daemon's device-local root CA into the System
    /// keychain via the standard macOS admin prompt (Option B). The root
    /// LaunchDaemon is not allowed to write trust settings unattended.
    case trustHTTPS
    case none
}

/// One row of the checklist.
struct ReadinessRow: Equatable {
    let title: String
    let systemImage: String
    let state: ReadinessState
}

/// The whole Home page, derived purely from (service state, daemon
/// snapshot, daemon reachable). Pure so XCTest can pin every branch
/// without SMAppService or a live daemon.
///
/// Order of operations is enforced by the rows themselves — this is the
/// user-facing half of the B4 fix: you cannot enroll before the service is
/// Running, and the UI says so instead of timing out.
struct HomeReadiness: Equatable {
    let service: ReadinessRow
    let identity: ReadinessRow
    let network: ReadinessRow

    var rows: [ReadinessRow] { [service, identity, network] }
    var allReady: Bool { rows.allSatisfy { $0.state.isReady } }

    /// The one line of guidance under the checklist.
    func guidance(zone: String) -> String {
        if allReady {
            let z = zone.isEmpty ? "<zone>" : zone
            return "Open any https://<name>.\(z) site in your browser. ZTLP connects on demand — there is nothing to switch on."
        }
        if !service.state.isReady { return "Step 1: install the ZTLP background service." }
        if !identity.state.isReady { return "Step 2: enroll this Mac with the enrollment link from your administrator." }
        if case .needsAction(_, .trustHTTPS) = network.state {
            return "Step 3: press Trust HTTPS once so Safari trusts this Mac's ZTLP certificates for every .ztlp site. No password needed."
        }
        return "Almost there — the service is finishing HTTPS and DNS setup."
    }

    static func compute(
        serviceState: AgentServiceState,
        daemonReachable: Bool,
        daemon: DaemonSnapshot?
    ) -> HomeReadiness {
        // Row 1 — Service (SMAppService registration + daemon answering)
        let service: ReadinessRow
        switch serviceState {
        case .running:
            service = ReadinessRow(
                title: "Service",
                systemImage: "gearshape.2",
                state: daemonReachable
                    ? .ready("Running")
                    : .waiting("Starting…")
            )
        case .requiresApproval:
            service = ReadinessRow(
                title: "Service",
                systemImage: "gearshape.2",
                state: .needsAction("Needs your approval in System Settings", action: .openLoginItems)
            )
        case .notRegistered:
            service = ReadinessRow(
                title: "Service",
                systemImage: "gearshape.2",
                state: .needsAction("Not installed", action: .installService)
            )
        case .notFound:
            service = ReadinessRow(
                title: "Service",
                systemImage: "gearshape.2",
                state: .failed("Service missing from this app bundle — reinstall ZTLP")
            )
        case .failed(let msg):
            service = ReadinessRow(
                title: "Service",
                systemImage: "gearshape.2",
                state: .failed(msg)
            )
        }

        // Row 2 — Identity (the ROOT daemon's enrollment; that is what DNS/TLS use)
        let identity: ReadinessRow
        if !service.state.isReady {
            identity = ReadinessRow(
                title: "Identity",
                systemImage: "person.badge.key",
                state: .waiting("Waiting for service")
            )
        } else if let d = daemon, d.identityEnrolled {
            identity = ReadinessRow(
                title: "Identity",
                systemImage: "person.badge.key",
                state: .ready(d.zone.isEmpty ? "Enrolled" : "Enrolled in \(d.zone)")
            )
        } else {
            identity = ReadinessRow(
                title: "Identity",
                systemImage: "person.badge.key",
                state: .needsAction("Not enrolled", action: .enroll)
            )
        }

        // Row 3 — Network ready (HTTPS trusted + DNS routed, from the daemon)
        let network: ReadinessRow
        if !identity.state.isReady {
            network = ReadinessRow(
                title: "Network ready",
                systemImage: "network",
                state: .waiting(service.state.isReady ? "Waiting for enrollment" : "Waiting for service")
            )
        } else if let d = daemon {
            if d.caInstalled && d.dnsConfigured {
                network = ReadinessRow(
                    title: "Network ready",
                    systemImage: "network",
                    state: .ready("HTTPS trusted · DNS routed")
                )
            } else if d.caInitialized && !d.caInstalled {
                // The daemon made the CA; only the human trust step remains.
                network = ReadinessRow(
                    title: "Network ready",
                    systemImage: "network",
                    state: .needsAction(
                        d.dnsConfigured ? "HTTPS not trusted yet" : "HTTPS not trusted yet · DNS routing pending",
                        action: .trustHTTPS
                    )
                )
            } else {
                var missing: [String] = []
                if !d.caInitialized { missing.append("HTTPS certificate") }
                if !d.dnsConfigured { missing.append("DNS routing") }
                network = ReadinessRow(
                    title: "Network ready",
                    systemImage: "network",
                    state: .waiting("Setting up \(missing.joined(separator: " and "))…")
                )
            }
        } else {
            network = ReadinessRow(
                title: "Network ready",
                systemImage: "network",
                state: .waiting("Waiting for service")
            )
        }

        return HomeReadiness(service: service, identity: identity, network: network)
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
    static let readyTimeout: TimeInterval = 30
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
        // "Connect on Launch" (Settings > General). Mirrors the Windows
        // client's auto_connect: if the daemon isn't already up, start it.
        if configuration.autoConnect {
            Task { [weak self] in
                guard let self else { return }
                if await !Self.daemonReachable() { self.installService() }
            }
        }
    }

    deinit {
        pollTask?.cancel()
    }

    // MARK: - Actions (Task 8: no Connect button — identity network, not a VPN)

    /// Latest readiness checklist for the single-page Home. Recomputed on
    /// every poll from (service state, daemon reachable, daemon snapshot).
    @Published private(set) var readiness: HomeReadiness = HomeReadiness.compute(
        serviceState: .notRegistered, daemonReachable: false, daemon: nil
    )
    @Published private(set) var daemonIsReachable: Bool = false

    /// Legacy entry point kept for the menu bar toggle: with no session to
    /// toggle, "on" = make sure the service is installed; "off" = uninstall
    /// it (Settings > Service is the primary place for that).
    func toggleConnection() {
        if daemonIsReachable { disconnect() } else { installService() }
    }

    /// Row 1 action: install (SMAppService register) the root service.
    /// There is no "connect" — once the service is Running, DNS connects
    /// on demand when the user opens a zone hostname.
    func installService() {
        guard !transitionInFlight else { return }
        lastError = nil
        transitionInFlight = true
        status = .connecting
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        Task {
            defer { transitionInFlight = false }

            if await Self.daemonReachable() {
                await pollOnceUnlocked()
                return
            }

            installer.register()
            serviceState = installer.state

            switch installer.state {
            case .requiresApproval:
                // macOS wants a human click in System Settings — the one
                // system prompt Steven accepted (UAC equivalent).
                installer.openLoginItemsSettings()
                status = .disconnected
                lastError = "Approve “ZTLP” under System Settings › General › Login Items & Extensions. This page updates by itself."
                return
            case .failed(let msg):
                status = .disconnected
                lastError = "Could not install the ZTLP service: \(msg)"
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
                    lastError = "Could not install the ZTLP service: \(err)"
                    NSSound.beep()
                    return
                }
            case .running:
                break
            }

            // B4(c): retry with backoff instead of one 15s window. A fresh
            // daemon now comes up in unenrolled standby within ~1s, but a
            // slow first launchd spawn (notarization check, first run) can
            // take longer.
            if await Self.waitForDaemonWithBackoff(timeout: Self.readyTimeout) {
                await pollOnceUnlocked()
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
            } else {
                status = .disconnected
                lastError = "The ZTLP service was installed but did not answer within \(Int(Self.readyTimeout))s. It may still be starting — this page keeps checking."
                NSSound.beep()
            }
        }
    }

    /// Backwards-compatible name used by older callers.
    func connect() { installService() }

    /// Uninstall the root daemon (SMAppService unregister). Lives in
    /// Settings as "Uninstall Service"; KeepAlive means a plain "shutdown"
    /// would respawn — see header comment.
    func disconnect() {
        guard !transitionInFlight else { return }
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
                status = .connected
                if lastError == nil {
                    lastError = "The ZTLP service is still running. Try again in a moment."
                }
            } else {
                status = .disconnected
                daemonIsReachable = false
                stats = TrafficStats()
                daemon = nil
                recomputeReadiness()
            }
        }
    }

    /// Row 3 action (Option B): trust the daemon's device-local root CA for
    /// THIS USER. Probe on macOS 26.5 (2026-09-20, MACLLM4):
    ///   - `security add-trusted-cert -d ... System.keychain` via AppleScript
    ///     "with administrator privileges": REFUSED (SecTrustSettingsSetTrustSettings
    ///     "no user interaction was possible") — the helper has no Aqua session.
    ///   - `security add-trusted-cert -r trustRoot -k <login keychain>` as the
    ///     logged-in user, NO admin: TRUSTED. Safari runs as the same user.
    /// So: no password prompt at all. Per-user trust; another account on the
    /// Mac presses the same button once. The root.pem is world-readable and
    /// name-constrained to .ztlp, so this can never validate a public site.
    @Published private(set) var trustInFlight = false

    func trustHTTPS() {
        guard !trustInFlight, let pem = daemon?.caRootPemPath, !pem.isEmpty else { return }
        trustInFlight = true
        lastError = nil
        Task.detached { [weak self] in
            let result = Self.runTrustCommand(pemPath: pem)
            await MainActor.run {
                guard let self else { return }
                self.trustInFlight = false
                if let err = result {
                    self.lastError = err
                    NSSound.beep()
                }
                Task { await self.pollOnce() }
            }
        }
    }

    /// Pure builder, unit-tested: argv for the user-domain trust write.
    nonisolated static func trustCommandArgs(pemPath: String, loginKeychain: String) -> [String] {
        ["add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain, pemPath]
    }

    nonisolated static func loginKeychainPath() -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/Keychains/login.keychain-db")
    }

    /// Runs /usr/bin/security as the current user. nil on success.
    nonisolated private static func runTrustCommand(pemPath: String) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = trustCommandArgs(pemPath: pemPath, loginKeychain: loginKeychainPath())
        let errPipe = Pipe()
        p.standardError = errPipe
        p.standardOutput = Pipe()
        do { try p.run() } catch { return "Could not run the trust command: \(error.localizedDescription)" }
        p.waitUntilExit()
        if p.terminationStatus == 0 { return nil }
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return "Could not trust the ZTLP certificate (exit \(p.terminationStatus)): \(err)"
    }

    /// `security verify-cert -c <root.pem>` as the current user: succeeds
    /// only when the root is trusted in a domain this user's session sees
    /// (user, admin or system).
    nonisolated static func rootIsTrustedForThisUser(pemPath: String) -> Bool {
        guard !pemPath.isEmpty, FileManager.default.fileExists(atPath: pemPath) else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["verify-cert", "-c", pemPath]
        p.standardOutput = Pipe(); p.standardError = Pipe()
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    /// Row 2 action is handled by EnrollmentView (sheet). After the sheet
    /// closes we poll immediately so the Identity row flips without
    /// waiting for the 2s tick.
    func enrollmentDidFinish() {
        Task { await pollOnce() }
    }

    private func recomputeReadiness() {
        let r = HomeReadiness.compute(
            serviceState: serviceState,
            daemonReachable: daemonIsReachable,
            daemon: daemon
        )
        if r != readiness { readiness = r }
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
        guard !transitionInFlight else { return }
        await pollOnceUnlocked()
    }

    /// The poll body without the in-flight guard (used by installService
    /// right after the daemon answers).
    private func pollOnceUnlocked() async {
        installer.refreshState()
        serviceState = installer.state

        if await Self.daemonReachable() {
            missedPolls = 0
            daemonIsReachable = true
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
                daemonIsReachable = false
                daemon = nil
                stats = TrafficStats()
                missedPolls = 0
            } else {
                status = .reconnecting
            }
        } else {
            daemonIsReachable = false
        }
        recomputeReadiness()
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
            snap.caInitialized = o["ca_initialized"]?.boolValue ?? false
            snap.caRootPemPath = o["ca_root_pem_path"]?.stringValue ?? ""
            // Trust is evaluated HERE, in the user's session — the root daemon
            // cannot see user-domain trust settings (probe 2026-09-20: the
            // user-domain write is the one that works without admin).
            let daemonView = o["ca_installed_system_trust"]?.boolValue ?? false
            snap.caInstalled = daemonView || (snap.caInitialized && Self.rootIsTrustedForThisUser(pemPath: snap.caRootPemPath))
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

    /// B4(c): like `waitForDaemon(reachable: true)` but with exponential
    /// backoff (0.25s → 2s cap) so a slow first spawn isn't hammered and a
    /// fast one is caught quickly.
    static func waitForDaemonWithBackoff(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        var delay: TimeInterval = readyPollInterval
        while true {
            if await daemonReachable() { return true }
            if Date() >= deadline { return false }
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            delay = nextBackoffDelay(delay)
        }
    }

    /// Pure backoff step, unit-tested: doubles, capped at 2s.
    nonisolated static func nextBackoffDelay(_ current: TimeInterval) -> TimeInterval {
        min(current * 2, 2.0)
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
