// SessionFreeze.swift
//
// Task 4 (macOS parity): mirror Windows' session-lock freeze/thaw. The desktop
// app sends `freeze` when the Mac sleeps or the screen locks, and `thaw` when
// it wakes or unlocks. While frozen the agent (Rust side, already
// cross-platform) stops accepting new connections and the resolver answers
// NXDOMAIN for .ztlp names — so a locked Mac can't be ridden by whoever walks
// up to the shared kiosk or hands the Mac to someone.
//
// Split into two layers, mirroring the codebase's TDD convention:
//
//   1. `FreezeAction`, `SessionFreezeEvent`, and `action(for:)` — PURE. No
//      AppKit, no Foundation event objects, no I/O. Unit-testable in
//      isolation (see the standalone `SessionFreezePureCheck.swift` and the
//      ZTLPTests target once the test target's Info.plist is fixed).
//
//   2. `SessionFreezeObserver` — thin AppKit glue. Subscribes to the
//      SUPPORTED public notifications (NSWorkspace willSleep/didWake +
//      session resign/become active), maps each to a `FreezeAction` via the
//      pure function, and forwards to an injected `send` closure (tests pass
//      a recorder; the app passes `AgentControlClient.send`).
//
// Lock detection: macOS has no public NSWorkspace "screen locked"
// notification. We use `NSWorkspaceSessionDidResignActiveNotification`
// (fired on screen-lock and on session sleep) as the lock trigger, and
// `NSWorkspaceSessionDidBecomeActiveNotification` as the unlock trigger, with
// `CGSessionCopyCurrentDictionary()`'s `CGSSessionScreenIsLocked` as the
// source of truth for whether the session is actually locked when a resign
// fires. A wake after a lock is a thaw even if the lock screen is still up;
// the subsequent unlock sends a second (idempotent) thaw. Both directions are
// idempotent on the Rust side (`is_frozen()` is a flag), so over-sending is
// harmless. This is a deliberate, documented heuristic with the same
// tradeoff as the Windows side (a missed lock event costs at most a stale
// "still available" window until the next event).

import AppKit
import CoreGraphics
import Foundation

/// What the desktop app should do to the agent in response to a session event.
enum FreezeAction: Equatable {
    /// Session locked / Mac sleeping: send `freeze`.
    case freeze
    /// Session unlocked / Mac awake: send `thaw`.
    case thaw
    /// Event is irrelevant to freeze state (e.g. session resign with no lock —
    /// e.g. the user just switched Spaces). No command.
    case none
}

/// The observable session events, reduced to the facts the pure mapper needs.
/// Kept as an enum (not AppKit notification names) so the pure function is
/// testable without instantiating NSWorkspace objects.
enum SessionFreezeEvent: Equatable {
    /// System is about to sleep (NSWorkspace.willSleepNotification).
    case systemWillSleep
    /// System woke (NSWorkspace.didWakeNotification).
    case systemDidWake
    /// Session resigned (NSWorkspace.sessionDidResignActiveNotification) —
    /// fires on screen-lock, session sleep, and some space switches. The
    /// observer checks `sessionLocked()` to decide freeze vs none.
    case sessionResigned
    /// Session became active again (NSWorkspace.sessionDidBecomeActiveNotification).
    case sessionBecameActive
}

/// Map a session event to the agent command. PURE — no AppKit, no I/O.
///
/// `sessionResigned` is mapped to `.none` at the pure level (it needs the
/// `sessionLocked()` fact to become `.freeze`); the observer applies that
/// refinement before sending. Everything else maps directly.
func action(for event: SessionFreezeEvent) -> FreezeAction {
    switch event {
    case .systemWillSleep:
        return .freeze
    case .systemDidWake:
        return .thaw
    case .sessionResigned:
        return .none
    case .sessionBecameActive:
        return .thaw
    }
}

/// Source of truth for lock state: `CGSessionCopyCurrentDictionary()`'s
/// `CGSSessionScreenIsLocked` key (value 1/true when the screen is
/// locked). Verified present on macOS 26.5.
/// `action(for:)` refined with the lock fact. A Mac that locks on sleep
/// wakes with the lock screen up: stay frozen until the unlock
/// (`sessionBecameActive`) sends the thaw.
func finalFreezeAction(for event: SessionFreezeEvent, locked: Bool) -> FreezeAction {
    let a = action(for: event)
    if event == .sessionResigned && a == .none { return locked ? .freeze : .none }
    if event == .systemDidWake && locked { return .none }
    return a
}

func sessionLocked() -> Bool {
    guard let cf = CGSessionCopyCurrentDictionary() else { return false }
    let dict = cf as NSDictionary
    for (key, value) in dict {
        let k = "\(key)"
        if k.hasSuffix("ScreenIsLocked") {
            switch value {
            case let b as Bool: return b
            case let n as NSNumber: return n.boolValue
            default: break
            }
        }
    }
    return false
}

/// Thin AppKit glue: subscribe to the OS sleep/wake/session events and forward
/// the mapped action to the agent. Created once at app launch; `stop()`
/// unsubscribes.
final class SessionFreezeObserver {
    private var observers: [NSObjectProtocol] = []
    private let send: (FreezeAction) -> Void
    private let sessionLocked: () -> Bool

    /// `send` is injected so the observer is testable without a live agent
    /// (tests pass a closure that records the actions). `sessionLocked` is
    /// injected so the lock check is testable without a real CGSession.
    init(
        send: @escaping (FreezeAction) -> Void,
        sessionLocked: @escaping () -> Bool = defaultSessionLockedDetector
    ) {
        self.send = send
        self.sessionLocked = sessionLocked
    }

    deinit { stop() }

    func start() {
        guard observers.isEmpty else { return }
        let ws = NSWorkspace.shared.notificationCenter
        observers.append(ws.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.emit(.systemWillSleep) })
        observers.append(ws.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.emit(.systemDidWake) })
        observers.append(ws.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            // Session resigned: only freeze if the session is actually locked
            // (not just a Space switch). The pure mapper returns `.none` here;
            // the observer refines it with the lock fact.
            if self?.sessionLocked() == true {
                self?.emit(.sessionResigned)
            }
        })
        observers.append(ws.addObserver(
            forName: NSWorkspace.sessionDidBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.emit(.sessionBecameActive) })
    }

    func stop() {
        let ws = NSWorkspace.shared.notificationCenter
        for o in observers { ws.removeObserver(o) }
        observers.removeAll()
    }

    private func emit(_ event: SessionFreezeEvent) {
        let final = finalFreezeAction(for: event, locked: sessionLocked())
        if final != .none {
            send(final)
        }
    }
}

/// Source of truth for lock state: `CGSessionCopyCurrentDictionary()`'s
/// `CGSSessionScreenIsLocked` key (value 1/true when the screen is
/// locked). Verified present on macOS 26.5.
let defaultSessionLockedDetector: () -> Bool = {
    guard let cf = CGSessionCopyCurrentDictionary() else { return false }
    let dict = cf as NSDictionary
    for (key, value) in dict {
        let k = "\(key)"
        if k.hasSuffix("ScreenIsLocked") {
            switch value {
            case let b as Bool: return b
            case let n as NSNumber: return n.boolValue
            default: break
            }
        }
    }
    return false
}

/// App-owned coordinator: owns the `SessionFreezeObserver` and forwards
/// `freeze`/`thaw` to the agent via `AgentControlClient`. The desktop app
/// starts it once (e.g. from `TunnelViewModel.init`) and it lives for the
/// process lifetime. Best-effort: a failed send is logged, not surfaced —
/// a missed freeze costs at most a stale "still available" window until the
/// next event.
final class SessionFreezeCoordinator {
    static let shared = SessionFreezeCoordinator()

    private var observer: SessionFreezeObserver?
    private var running = false

    private init() {}

    /// Start observing sleep/wake/lock and freeze the agent on lock.
    /// Idempotent — safe to call from multiple init paths.
    func start() {
        guard !running else { return }
        running = true
        let obs = SessionFreezeObserver(
            send: { [weak self] action in
                Task { @MainActor in
                    guard self != nil else { return }
                    let cmd = (action == .freeze) ? "freeze" : "thaw"
                    if let r = try? await AgentControlClient.send(cmd: cmd, timeout: 3) {
                        if !r.ok {
                            NSLog("[ztlp] freeze/thaw \(cmd) rejected: \(r.error ?? "n/a")")
                        }
                    } else {
                        NSLog("[ztlp] freeze/thaw \(cmd) send failed (daemon may be down)")
                    }
                }
            }
        )
        obs.start()
        self.observer = obs
        NSLog("[ztlp] SessionFreezeObserver started")
    }

    /// Stop observing (app quit). Also send a best-effort `thaw` so the agent
    /// is never left frozen across an app restart (the freeze is only meant to
    /// be in force while the session is locked; a quit is not a lock).
    func stop() {
        guard running else { return }
        running = false
        observer?.stop()
        observer = nil
        // Best-effort thaw: unblock the agent in case it was frozen. A quit is
        // not a lock, so leaving it thawed is the safe default for the next
        // launch / login.
        Task { @MainActor in
            _ = try? await AgentControlClient.send(cmd: "thaw", timeout: 2)
        }
        NSLog("[ztlp] SessionFreezeObserver stopped")
    }
}
