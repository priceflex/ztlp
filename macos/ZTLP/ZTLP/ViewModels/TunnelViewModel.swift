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
    var relay: String = ""
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

/// Pure fold: daemon `dns_configured` flag + the live resolve probe result ->
/// the DNS row state. `probe` is nil (not probed / not enrolled yet), true
/// (`ztlp-health.ztlp` resolved to the ZTLP VIP), or false (resolved
/// elsewhere / error). The flag says the *config* exists; the probe says the
/// *resolver* is actually routing. Both must agree for green.
func dnsRowState(dnsConfigured: Bool, probe: Bool?) -> ReadinessState {
    switch (dnsConfigured, probe) {
    case (true, true):
        return .ready(".ztlp names resolve through ZTLP")
    case (true, false):
        return .failed("DNS routing not working")
    case (true, nil):
        return .waiting("Checking…")
    case (false, _):
        return .failed("DNS routing not set up")
    }
}

/// Pure fold: daemon `ca_installed`/`ca_initialized` flags + the live TLS
/// probe result -> the HTTPS row state. The flags are the source of truth for
/// the row (trust is a per-user keychain fact the daemon cannot see); the
/// probe is confirmatory.
func httpsRowState(caInstalled: Bool, caInitialized: Bool, probe: Bool?) -> ReadinessState {
    if caInstalled {
        return .ready("Browsers trust ZTLP certificates")
    }
    if caInitialized {
        return .needsAction("HTTPS not trusted yet", action: .trustHTTPS)
    }
    return .waiting("Setting up certificate…")
}

/// The whole Home page, derived purely from (service state, daemon
/// snapshot, daemon reachable, live DNS/HTTPS probe results). Pure so XCTest
/// can pin every branch without SMAppService or a live daemon.
///
/// **4 rows** (Windows parity): Agent / Identity / DNS / HTTPS — the combined
/// "Network ready" row is split so the user can see exactly which half of the
/// network path is not ready and which one button to press.
///
/// Order of operations is enforced by the rows themselves — this is the
/// user-facing half of the B4 fix: you cannot enroll before the agent is
/// Running, and the UI says so instead of timing out.
struct HomeReadiness: Equatable {
    let agent: ReadinessRow
    let identity: ReadinessRow
    let dns: ReadinessRow
    let https: ReadinessRow

    var rows: [ReadinessRow] { [agent, identity, dns, https] }
    var allReady: Bool { rows.allSatisfy { $0.state.isReady } }

    /// The one line of guidance under the checklist.
    func guidance(zone: String) -> String {
        if allReady {
            let z = zone.isEmpty ? "<zone>" : zone
            return "Open any https://<name>.\(z) site in your browser. ZTLP connects on demand — there is nothing to switch on."
        }
        if !agent.state.isReady { return "Step 1: install the ZTLP background service." }
        if !identity.state.isReady { return "Step 2: enroll this Mac with the enrollment link from your administrator." }
        if case .needsAction(_, .trustHTTPS) = https.state {
            return "Step 3: press Trust HTTPS once so Safari trusts this Mac's ZTLP certificates for every .ztlp site. No password needed."
        }
        if case .failed = dns.state {
            return "Step 3: DNS routing is not set up. Press Fix to add the .ztlp resolver (needs admin)."
        }
        return "Almost there — the service is finishing HTTPS and DNS setup."
    }

    static func compute(
        serviceState: AgentServiceState,
        daemonReachable: Bool,
        daemon: DaemonSnapshot?,
        dnsProbe: Bool? = nil,
        httpsProbe: Bool? = nil
    ) -> HomeReadiness {
        // Row 1 — Agent (SMAppService registration + daemon answering)
        let agent: ReadinessRow
        switch serviceState {
        case .running:
            agent = ReadinessRow(
                title: "Agent",
                systemImage: "gearshape.2",
                state: daemonReachable
                    ? .ready("Running")
                    : .waiting("Starting…")
            )
        case .requiresApproval:
            agent = ReadinessRow(
                title: "Agent",
                systemImage: "gearshape.2",
                state: .needsAction("Needs your approval in System Settings", action: .openLoginItems)
            )
        case .notRegistered:
            agent = ReadinessRow(
                title: "Agent",
                systemImage: "gearshape.2",
                state: .needsAction("Not installed", action: .installService)
            )
        case .notFound:
            agent = ReadinessRow(
                title: "Agent",
                systemImage: "gearshape.2",
                state: .failed("Agent missing from this app bundle — reinstall ZTLP")
            )
        case .failed(let msg):
            agent = ReadinessRow(
                title: "Agent",
                systemImage: "gearshape.2",
                state: .failed(msg)
            )
        }

        // Row 2 — Identity (the daemon's enrollment; that is what DNS/TLS use)
        let identity: ReadinessRow
        if !agent.state.isReady {
            identity = ReadinessRow(
                title: "Identity",
                systemImage: "person.badge.key",
                state: .waiting("Waiting for agent")
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

        // Row 3 — DNS (the .ztlp resolver is routed through the agent).
        // The daemon's `dns_configured` flag says the config exists; the live
        // `dnsProbe` (resolve ztlp-health.ztlp) says the resolver is actually
        // routing. Both must agree for green.
        let dns: ReadinessRow
        if !identity.state.isReady {
            dns = ReadinessRow(
                title: "DNS",
                systemImage: "network",
                state: .waiting("Waiting for enrollment")
            )
        } else if daemon == nil {
            dns = ReadinessRow(
                title: "DNS",
                systemImage: "network",
                state: .waiting("Waiting for agent")
            )
        } else {
            dns = ReadinessRow(
                title: "DNS",
                systemImage: "network",
                state: dnsRowState(dnsConfigured: daemon!.dnsConfigured, probe: dnsProbe)
            )
        }

        // Row 4 — HTTPS (browsers trust the daemon's CA). The flags are the
        // source of truth (trust is a per-user keychain fact the daemon cannot
        // see); the live `httpsProbe` (TLS to the health responder) is
        // confirmatory.
        let https: ReadinessRow
        if !identity.state.isReady {
            https = ReadinessRow(
                title: "HTTPS",
                systemImage: "lock",
                state: .waiting("Waiting for enrollment")
            )
        } else if daemon == nil {
            https = ReadinessRow(
                title: "HTTPS",
                systemImage: "lock",
                state: .waiting("Waiting for agent")
            )
        } else {
            https = ReadinessRow(
                title: "HTTPS",
                systemImage: "lock",
                state: httpsRowState(caInstalled: daemon!.caInstalled, caInitialized: daemon!.caInitialized, probe: httpsProbe)
            )
        }

        return HomeReadiness(agent: agent, identity: identity, dns: dns, https: https)
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
    /// Live probe results feeding the DNS/HTTPS rows (Task 5b). nil = not
    /// probed yet; refreshed on each poll while enrolled.
    private var dnsProbe: Bool? = nil
    private var httpsProbe: Bool? = nil

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

    /// Spawns + keeps the per-user agent alive (the data plane). Stopped on
    /// deinit so the agent never outlives the login session.
    private let agentSupervisor: AgentSupervisor
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
        // Per-user data plane (macOS analog of Windows peruser.rs): assign the
        // supervisor before any self method call; start it below. The app
        // spawns + supervises the per-user agent itself — the slim machine
        // daemon only does the machine bits and exits.
        self.agentSupervisor = AgentSupervisor()
        setupObservers()
        startPolling()
        // Task 4 (macOS parity): mirror Windows' session-lock freeze/thaw.
        // Start the freeze observer so a locked/sleeping Mac stops serving
        // ZTLP connections (NXDOMAIN) until it unlocks/wakes.
        SessionFreezeCoordinator.shared.start()
        // Start the per-user agent supervisor (control socket
        // 127.100.255.1:4433 is served by THIS agent process).
        self.agentSupervisor.start()
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
        // Stop the per-user agent supervisor (closes the stdin pipe -> the
        // agent's stdin watch fires -> it removes its pidfile and exits; no
        // orphan agent outliving the login session). deinit of a @MainActor
        // object runs on the main thread, so assumeIsolated is sound here.
        MainActor.assumeIsolated {
            self.agentSupervisor.stop()
        }
        // Stop the freeze observer (best-effort thaw on quit).
        SessionFreezeCoordinator.shared.stop()
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
    ///
    /// Field fixes 2026-10-13 (Steven, fresh Mac):
    ///  - "Install does nothing": the old guard silently returned while a
    ///    launch-time auto-start was still waiting (up to 30 s). Now the
    ///    button shows `installInFlight` progress and a second click is a
    ///    visible no-op, not a silent one.
    ///  - "Had to uninstall + reinstall": a stale SMAppService/BTM entry
    ///    (previous build or an approval granted after register) reports
    ///    .enabled but launchd never spawns the new binary. If the daemon
    ///    does not answer within `staleRegistrationTimeout`, we unregister +
    ///    register ONCE automatically — exactly what fixed it by hand.
    func installService() {
        guard !installInFlight else { return }
        lastError = nil
        installInFlight = true
        transitionInFlight = true
        status = .connecting
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        Task {
            defer { transitionInFlight = false; installInFlight = false }

            if await Self.daemonReachable() {
                await pollOnceUnlocked()
                return
            }

            await installer.registerAsync()
            serviceState = installer.state

            if await handleNonRunningState() { return }

            // Registered and approved. A fresh daemon answers in ~1 s.
            if await Self.waitForDaemonWithBackoff(timeout: Self.staleRegistrationTimeout) {
                await pollOnceUnlocked()
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
                return
            }

            // Stale registration: re-register once (the manual fix).
            await installer.unregisterAsync()
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await installer.registerAsync()
            serviceState = installer.state
            if await handleNonRunningState() { return }

            if await Self.waitForDaemonWithBackoff(timeout: Self.readyTimeout) {
                await pollOnceUnlocked()
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
            } else {
                status = .disconnected
                lastError = "The ZTLP service is installed but is not answering. Open Settings › Service and press Uninstall Service, then Install again. If that fails, restart the Mac."
                NSSound.beep()
            }
        }
    }

    /// Handles every installer state except a clean `.running`. Returns true
    /// when installService should stop here.
    private func handleNonRunningState() async -> Bool {
        switch installer.state {
        case .requiresApproval:
            // macOS wants a human click in System Settings. Open it and tell
            // the user EXACTLY which switch; the poll flips the row when done.
            installer.openLoginItemsSettings()
            status = .disconnected
            lastError = Self.loginItemsInstructions
            return true
        case .failed(let msg):
            status = .disconnected
            lastError = "Could not install the ZTLP service: \(msg)"
            NSSound.beep()
            return true
        case .notFound:
            status = .disconnected
            lastError = "The ZTLP service is missing from this app bundle (org.ztlp.agent.plist). Reinstall ZTLP."
            NSSound.beep()
            return true
        case .notRegistered:
            status = .disconnected
            lastError = "Could not install the ZTLP service: \(installer.lastError ?? "macOS did not register it")"
            NSSound.beep()
            return true
        case .running:
            return false
        }
    }

    /// Shown on Home and in Settings whenever macOS is waiting for approval.
    nonisolated static let loginItemsInstructions =
        "macOS needs your OK to run ZTLP in the background. In the System Settings window that just opened (General › Login Items & Extensions), find ZTLP under “Allow in the Background” and turn its switch ON. Enter your Mac password if asked, then come back here. This page updates by itself."

    /// How long a just-registered daemon may stay silent before we treat the
    /// registration as stale and re-register once.
    static let staleRegistrationTimeout: TimeInterval = 10

    /// Drives the Install button's spinner.
    @Published private(set) var installInFlight = false

    /// Re-entered when the user comes back from System Settings (approval
    /// granted): finish the install without another click.
    private var wasAwaitingApproval = false

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

            await installer.unregisterAsync()
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
        Task { [weak self] in
            let result = await Self.runTrustCommand(pemPath: pem)
            guard let self else { return }
            self.trustInFlight = false
            self.trustCache = nil   // re-evaluate on the next poll
            if let err = result {
                self.lastError = err
                NSSound.beep()
            }
            await self.pollOnce()
        }
    }

    /// Pure builder, unit-tested: argv for the user-domain trust write.
    nonisolated static func trustCommandArgs(pemPath: String, loginKeychain: String) -> [String] {
        ["add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain, pemPath]
    }

    nonisolated static func loginKeychainPath() -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/Keychains/login.keychain-db")
    }

    /// Runs /usr/bin/security as the current user, off the main thread.
    /// nil on success. The trust write may show the login-keychain prompt,
    /// so it gets a long watchdog (the user may be typing a password).
    nonisolated private static func runTrustCommand(pemPath: String) async -> String? {
        let r = await BackgroundProcess.run(
            "/usr/bin/security",
            trustCommandArgs(pemPath: pemPath, loginKeychain: loginKeychainPath()),
            timeout: 120
        )
        if r.ok { return nil }
        if r.timedOut { return "Trusting the ZTLP certificate timed out. Try again." }
        if r.status == -1 { return "Could not run the trust command: \(r.stderr)" }
        return "Could not trust the ZTLP certificate (exit \(r.status)): \(r.stderr)"
    }

    /// `security verify-cert -c <root.pem>` as the current user: succeeds
    /// only when the root is trusted in a domain this user's session sees
    /// (user, admin or system).
    ///
    /// v0.35.18 freeze fix: this used to run `Process` + `waitUntilExit()`
    /// synchronously from the @MainActor poll every 2 s, which beachballed
    /// the menu bar. Now it runs off-main via BackgroundProcess and the
    /// result is cached per PEM (path + mtime) for `trustCacheTTL`, the same
    /// idea as the agent's 5 s setup_status probe cache (ZT-11). trustHTTPS()
    /// clears the cache so the row flips right after the user grants trust.
    nonisolated static func rootIsTrustedForThisUser(pemPath: String) async -> Bool {
        guard !pemPath.isEmpty, FileManager.default.fileExists(atPath: pemPath) else { return false }
        return await BackgroundProcess.run("/usr/bin/security", ["verify-cert", "-c", pemPath], timeout: 10).ok
    }

    struct TrustCacheEntry: Equatable {
        let pemPath: String
        let pemModified: Date?
        let trusted: Bool
        let checkedAt: Date
    }
    nonisolated static let trustCacheTTL: TimeInterval = 30
    private var trustCache: TrustCacheEntry?

    /// Pure, unit-tested: may a cached answer be reused?
    nonisolated static func trustCacheIsFresh(_ entry: TrustCacheEntry?, pemPath: String, pemModified: Date?, now: Date) -> Bool {
        guard let e = entry else { return false }
        return e.pemPath == pemPath && e.pemModified == pemModified && now.timeIntervalSince(e.checkedAt) < trustCacheTTL
    }

    private func cachedRootTrust(pemPath: String) async -> Bool {
        let mtime = (try? FileManager.default.attributesOfItem(atPath: pemPath))?[.modificationDate] as? Date
        if Self.trustCacheIsFresh(trustCache, pemPath: pemPath, pemModified: mtime, now: Date()), let c = trustCache {
            return c.trusted
        }
        let trusted = await Self.rootIsTrustedForThisUser(pemPath: pemPath)
        trustCache = TrustCacheEntry(pemPath: pemPath, pemModified: mtime, trusted: trusted, checkedAt: Date())
        return trusted
    }

    /// Row 2 action is handled by EnrollmentView (sheet). After the sheet
    /// closes we poll immediately so the Identity row flips without
    /// waiting for the 2s tick.
    func enrollmentDidFinish() {
        Task { await pollOnce() }
    }

    // MARK: - Live DNS/HTTPS probes (Task 5b: rows reflect real network state)

    /// Reserved health name the daemon answers (mirrors peruser::HEALTH_NAME).
    static let healthName = "ztlp-health.ztlp"
    /// Fixed loopback address the health name must resolve to when the
    /// resolver is routing .ztlp through the agent (peruser::HEALTH_VIP).
    static let healthVIP = "127.100.255.2"
    /// Health responder port (peruser::HEALTH_PORT).
    static let healthPort: UInt16 = 443

    /// Live DNS probe: resolve `ztlp-health.ztlp` through the OS resolver and
    /// check it lands on the ZTLP VIP. `true` = resolves to the VIP, `false` =
    /// resolves elsewhere or errors, `nil` = skip (not enrolled yet).
    nonisolated static func probeDNS(enrolled: Bool) async -> Bool? {
        guard enrolled else { return nil }
        let host = Self.healthName
        return await withCheckedContinuation { cont in
            Task.detached(priority: .utility) {
                let resolved = host.withCString { h in
                    var addrs: UnsafeMutablePointer<addrinfo>?
                    var hints = addrinfo()
                    hints.ai_family = AF_INET
                    hints.ai_socktype = SOCK_STREAM
                    guard getaddrinfo(h, nil, &hints, &addrs) == 0, let root = addrs else {
                        return false
                    }
                    defer { freeaddrinfo(addrs) }
                    var p = root.pointee
                    var ok = false
                    while p.ai_addr != nil {
                        if p.ai_family == AF_INET, let sockPtr = p.ai_addr {
                            let inaddr = sockPtr.withMemoryRebound(to: in_addr.self, capacity: 1) { $0.pointee }
                            if "\(inet_ntoa(inaddr))" == Self.healthVIP { ok = true }
                        }
                        guard let next = p.ai_next else { break }
                        p = next.pointee
                    }
                    return ok
                }
                cont.resume(returning: resolved)
            }
        }
    }

    /// Live HTTPS probe: open TLS to `https://ztlp-health.ztlp:443/` the way
    /// Safari would — the OS resolver routes the name to the loopback VIP (the
    /// agent), SNI = the health name, and the system trust store validates the
    /// chain. `true` = 2xx + the health body, `false` = error, `nil` = skip.
    /// Mirrors the Rust `probe_https` (SNI = health name, roots = OS store).
    nonisolated static func probeHTTPS(enrolled: Bool, dnsOk: Bool) async -> Bool? {
        guard enrolled, dnsOk else { return nil }
        guard let url = URL(string: "https://\(Self.healthName):\(Self.healthPort)/") else { return false }
        var req = URLRequest(url: url)
        req.timeoutInterval = 10
        req.cachePolicy = .reloadIgnoringLocalCacheData
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let body = String(data: data, encoding: .utf8) ?? ""
            return (200..<400).contains(code) && body.contains("ztlp-health-ok")
        } catch {
            return false
        }
    }

    private func recomputeReadiness() {
        let r = HomeReadiness.compute(
            serviceState: serviceState,
            daemonReachable: daemonIsReachable,
            daemon: daemon,
            dnsProbe: dnsProbe,
            httpsProbe: httpsProbe
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

        // Approval just granted in System Settings: finish the install for
        // the user (wait for the daemon, re-register once if stale).
        if case .requiresApproval = installer.state {
            wasAwaitingApproval = true
            if lastError == nil { lastError = Self.loginItemsInstructions }
        } else if wasAwaitingApproval, case .running = installer.state {
            wasAwaitingApproval = false
            if lastError == Self.loginItemsInstructions { lastError = nil }
            if !installInFlight, await !Self.daemonReachable() {
                installService()
                return
            }
        }

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
        // Task 5b: while enrolled + the daemon is up, refresh the live
        // DNS/HTTPS probes so the rows reflect real network state, not just
        // the daemon's config flags. Skip the probes (nil) when not enrolled
        // or the daemon is down — the rows then show the waiting state.
        let enrolled = daemon?.identityEnrolled ?? false
        if daemonIsReachable && enrolled {
            dnsProbe = await Self.probeDNS(enrolled: enrolled)
            httpsProbe = await Self.probeHTTPS(enrolled: enrolled, dnsOk: dnsProbe == true)
        } else {
            dnsProbe = nil
            httpsProbe = nil
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
            snap.relay = o["relay"]?.stringValue ?? snap.relay
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
            if daemonView {
                snap.caInstalled = true
            } else if snap.caInitialized {
                snap.caInstalled = await cachedRootTrust(pemPath: snap.caRootPemPath)
            } else {
                snap.caInstalled = false
            }
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
