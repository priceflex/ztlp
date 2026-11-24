// AgentServiceInstaller.swift
// ZTLP macOS
//
// Task 5.5: GUI-driven install of the root `ztlp agent` LaunchDaemon.
//
// Session 4 (2026-09-19) proved the LaunchDaemon itself live on MACLLM4 via
// CLI (`sudo ztlp agent install` + `sudo launchctl bootstrap system ...`,
// survives reboot with zero further sudo — see ZTLP-MAC-PLAN-2026-09-19.md
// Task 5b). This file replaces those two manual `sudo` invocations with
// `SMAppService.daemon(plistName:)`, which shows macOS's own "Allow
// background item" system prompt (the UAC equivalent Steven asked for) the
// FIRST time `register()` is called, and needs no Terminal at all.
//
// Bundle layout (Xcode Copy Files phases, added session 5 via the
// xcodeproj gem; fixed session 6):
//   - Contents/Helpers/ztlp  — the `ztlp` CLI/agent binary (tracked at
//     macos/ZTLP/Libraries/ztlp). NOT Contents/MacOS/ztlp: on
//     case-insensitive APFS that is the same path as the app executable
//     Contents/MacOS/ZTLP and the CLI silently clobbered the GUI.
//   - Contents/Library/LaunchDaemons/org.ztlp.agent.plist — BundleProgram =
//     Contents/Helpers/ztlp (bundle-relative, macOS 13+), so the daemon
//     follows the .app wherever it is moved.

import Foundation
import ServiceManagement
import Combine

/// Install state of the root agent LaunchDaemon, as seen by the GUI.
enum AgentServiceState: Equatable {
    case notRegistered
    /// Registered, but macOS is still waiting on the user to approve it in
    /// System Settings > General > Login Items & Extensions.
    case requiresApproval
    case running
    case notFound
    case failed(String)
}

/// Drives the root `org.ztlp.agent` LaunchDaemon via `SMAppService`.
///
/// This is the GUI-native replacement for the two commands Steven ran by
/// hand in session 4 (`ztlp agent install`, `sudo launchctl bootstrap
/// system ...`). `SMAppService.daemon` needs a SIGNED app (satisfied —
/// MACLLM4 build uses "Apple Development: Steven Price", team 5527A7TH5P)
/// and the plist to already be inside the app bundle at
/// Contents/Library/LaunchDaemons/<label>.plist (satisfied once the Xcode
/// build-phase changes above land).
@MainActor
final class AgentServiceInstaller: ObservableObject {

    static let shared = AgentServiceInstaller()

    /// Must match Contents/Library/LaunchDaemons/<this>.plist exactly.
    /// Task 6: the app now installs the slim machine daemon (machine bits
    /// only — CA, resolver, lo0 aliases, kept idempotent at boot by
    /// `agent machine-setup --boot`), NOT the full root agent. The data plane
    /// is the per-user agent, started by the app.
    nonisolated static let plistName = "org.ztlp.machine.plist"

    /// The legacy full root agent daemon. Upgrades from 1.3.0 remove it (the
    /// per-user model replaces it); a fresh install has nothing to remove.
    nonisolated static let legacyAgentPlistName = "org.ztlp.agent.plist"

    @Published private(set) var state: AgentServiceState = .notRegistered
    @Published private(set) var lastError: String?

    private var service: SMAppService { .daemon(plistName: Self.plistName) }

    private init() {
        refreshState()
    }

    /// Re-read `SMAppService.status` — call after register/unregister and
    /// on app launch/foreground so a user who approved/revoked in System
    /// Settings sees it reflected without restarting the app.
    func refreshState() {
        switch service.status {
        case .notRegistered:
            state = .notRegistered
        case .enabled:
            state = .running
        case .requiresApproval:
            state = .requiresApproval
        case .notFound:
            state = .notFound
        @unknown default:
            state = .failed("unknown SMAppService.Status")
        }
    }

    /// Register the machine daemon. Triggers macOS's one-time "background
    /// item" system prompt on first call (Steven's "one macOS system prompt,
    /// like Windows UAC" requirement). No sudo, no Terminal. Also removes the
    /// legacy full root agent daemon (upgrades from 1.3.0).
    func register() {
        // Legacy removal strictly BEFORE the register (was a concurrent Task).
        let legacy = Self.legacyAgentPlistName
        let svc = service
        do {
            try Self.registrationSteps(
                unregisterLegacy: { try SMAppService.daemon(plistName: legacy).unregister() },
                register: { try svc.register() }
            )()
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        refreshState()
    }

    /// Unregister (uninstall). Does not delete the daemon's config dir
    /// (`/Library/Application Support/ZTLP`) — that is a separate, explicit
    /// "Erase configuration" action so an accidental Uninstall click can't
    /// silently drop the enrolled identity.
    func unregister() {
        do {
            try service.unregister()
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        refreshState()
    }

    /// Open System Settings > General > Login Items & Extensions so the
    /// user can approve a `.requiresApproval` registration. SMAppService
    /// has no programmatic "approve" — this is the documented Apple flow.
    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    // MARK: - Off-main variants (v0.35.18 freeze fix)
    //
    // `SMAppService.register()` / `.unregister()` are synchronous XPC calls
    // into launchd/BTM. The first register can take seconds (background-item
    // approval, notarization check), and they ran on the main actor from
    // button handlers and installService(), freezing the window. These hop
    // the blocking call to a global queue and publish state back on main.

    @Published private(set) var operationInFlight = false

    /// The register/unregister currently running. The task clears this (and
    /// publishes state) itself before it completes, so anyone awaiting its
    /// value resumes with it already cleared.
    private var inFlight: Task<String?, Never>?

    private func startOperation(_ op: @escaping @Sendable () throws -> Void) -> Task<String?, Never> {
        operationInFlight = true
        let task = Task { [weak self] () -> String? in
            let err = await Self.runOffMain(op)
            if let self {
                self.inFlight = nil
                self.operationInFlight = false
                self.lastError = err
                self.refreshState()
            }
            return err
        }
        inFlight = task
        return task
    }

    nonisolated private static func runOffMain(_ body: @escaping @Sendable () throws -> Void) async -> String? {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do { try body(); cont.resume(returning: nil) }
                catch { cont.resume(returning: error.localizedDescription) }
            }
        }
    }

    /// One registration operation: remove the legacy root agent (best
    /// effort — a fresh install has nothing to remove), THEN register the
    /// machine daemon. Run as a single guarded operation so a second click
    /// can't slip in between and the order is guaranteed.
    nonisolated static func registrationSteps(
        unregisterLegacy: @escaping @Sendable () throws -> Void,
        register: @escaping @Sendable () throws -> Void
    ) -> @Sendable () throws -> Void {
        {
            try? unregisterLegacy()
            try register()
        }
    }

    func registerAsync() async {
        guard inFlight == nil else { return }  // a second click while busy is a no-op
        // startOperation sets inFlight synchronously (no await before it), and
        // the legacy removal runs INSIDE it, before the register.
        let plist = Self.plistName
        let legacy = Self.legacyAgentPlistName
        _ = await startOperation(Self.registrationSteps(
            unregisterLegacy: { try SMAppService.daemon(plistName: legacy).unregister() },
            register: { try SMAppService.daemon(plistName: plist).register() }
        )).value
    }

    /// Stop + unregister the legacy full root agent daemon (`org.ztlp.agent`).
    /// The per-user model (Task 1-6) replaces it with the slim machine daemon
    /// + a per-user agent, so a 1.3.0 upgrade must remove the old root agent
    /// to avoid two data planes. Best-effort: a fresh install has nothing to
    /// remove and the call is a harmless no-op. Runs off-main (SMAppService
    /// unregister is a synchronous XPC call).
    @discardableResult
    func removeLegacyAgentDaemon() async -> Bool {
        let legacy = Self.legacyAgentPlistName
        return await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try SMAppService.daemon(plistName: legacy).unregister()
                    cont.resume(returning: true)
                } catch {
                    // .notFound / not registered is the expected fresh-install
                    // outcome — not an error worth surfacing.
                    cont.resume(returning: true)
                }
            }
        }
    }

    /// Waits for any register/unregister already running, then unregisters.
    /// Returns true when the daemon is not registered afterwards (including
    /// "was never registered"), so callers like factory reset can refuse to
    /// continue while the service is still installed.
    @discardableResult
    func unregisterAsync() async -> Bool {
        while let pending = inFlight { _ = await pending.value }
        let plist = Self.plistName
        let err = await startOperation { try SMAppService.daemon(plistName: plist).unregister() }.value
        let status = service.status
        return err == nil || status == .notRegistered || status == .notFound
    }
}
