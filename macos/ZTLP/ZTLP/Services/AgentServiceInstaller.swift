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
    static let plistName = "org.ztlp.agent.plist"

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

    /// Register the daemon. Triggers macOS's one-time "background item"
    /// system prompt on first call (Steven's "one macOS system prompt,
    /// like Windows UAC" requirement). No sudo, no Terminal.
    func register() {
        do {
            try service.register()
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
}
