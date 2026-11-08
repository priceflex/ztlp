//  AgentSupervisor.swift
//  ZTLP
//
//  The macOS per-user agent supervisor — the exact analog of the Windows
//  `peruser.rs::spawn_agent()`. The desktop app spawns the data-plane agent
//  ITSELF, as the logged-in user, and keeps it alive:
//
//      ztlp agent start --foreground --parent-pid <app-pid>
//
//  with ZTLP_PARENT_STDIN=1 and a piped stdin. Two independent "the app is
//  gone" signals make the agent exit when we die (so it never outlives the
//  login session):
//    1. stdin pipe closes  (the app exited/crashed -> OS closes the write end;
//       the agent's ztlp-parent-stdin watch reads EOF and exits, instantly)
//    2. --parent-pid       (belt-and-suspenders: the agent polls whether our
//       PID is still alive; if not, it exits)
//
//  If the agent dies for any other reason we restart it (with backoff). The
//  control socket the UI polls (127.100.255.1:4433) is served by THIS process
//  — the slim org.ztlp.machine daemon only does the machine bits
//  (CA/resolver/lo0) and exits, it does NOT run the agent.

import Foundation

// MARK: - Pure decision logic (unit-tested, no Process)

/// How the supervisor should behave given one observation of the agent's
/// exit + how long it has been up. Keeping this as a pure fold makes the
/// restart/backoff logic testable without a real child process.
enum SupervisorDecision: Equatable {
    /// Keep the agent running (it just started / is healthy).
    case keepRunning
    /// The agent exited and we should spawn a replacement.
    case respawn
    /// The agent exited and we should wait `backoff` seconds before respawning
    /// (it died quickly -> avoid a tight crash loop).
    case backoff(TimeInterval)
    /// Stop supervising entirely (we asked it to stop, or it exited with the
    /// "parent gone" code, meaning the app itself is shutting down).
    case stop
}

/// The agent's exit code when its parent (the app) went away. Matches
/// `peruser.rs::EXIT_PARENT_GONE`. When we see this we must NOT respawn —
/// the app is quitting.
nonisolated let kAgentParentGoneExitCode: Int32 = 3

/// How long a freshly spawned agent must stay up before a crash counts as a
/// "quick death" that triggers backoff instead of an immediate respawn.
nonisolated let kQuickDeathThreshold: TimeInterval = 2.0

/// Minimum seconds between restarts when the agent is crash-looping.
nonisolated let kBackoffInterval: TimeInterval = 3.0

/// Decide what to do after the agent process exits.
///
/// - `wantsRunning`: we have not been asked to stop (the app is still
///   supervising). `false` -> always `.stop`.
/// - `exitCode`: the child's termination status.
/// - `ranFor`: how long (seconds) the child lived before exiting.
nonisolated func supervisorDecision(
    wantsRunning: Bool,
    exitCode: Int32,
    ranFor: TimeInterval
) -> SupervisorDecision {
    guard wantsRunning else { return .stop }
    // The agent told us "your parent (the app) is gone" -> we are shutting
    // down; do not spawn a replacement.
    if exitCode == kAgentParentGoneExitCode { return .stop }
    // A clean exit (0) with wantsRunning is unexpected for a foreground agent;
    // respawn so a transient clean-exit doesn't wedge the data plane.
    if exitCode == 0 { return .respawn }
    // Crashed, or killed. If it lived longer than the threshold, respawn
    // immediately (a real crash of a long-running agent is worth retrying
    // fast). If it died quickly, back off to avoid a tight loop.
    if ranFor >= kQuickDeathThreshold {
        return .respawn
    }
    return .backoff(kBackoffInterval)
}

/// Build the argv for spawning the per-user agent. Pure -> unit-testable.
///
/// `parentPid` is our (the app's) PID. The agent's parent-watch uses it; the
/// stdin pipe is the primary, instant signal.
nonisolated func agentSpawnArgs(parentPid: Int32) -> [String] {
    ["agent", "start", "--foreground", "--parent-pid", String(parentPid)]
}

/// The environment the agent is spawned with. `ZTLP_PARENT_STDIN=1` tells the
/// agent to watch stdin for EOF (the instant "app is gone" signal). We remove
/// `ZTLP_HOME` so the agent resolves state to the user's `~/.ztlp` (not a
/// service-pinned HOME).
nonisolated func agentSpawnEnv() -> [String: String] {
    ["ZTLP_PARENT_STDIN": "1"]
}

// MARK: - The live supervisor (spawns + keeps the agent alive)

/// Spawns the per-user agent as the logged-in user and restarts it if it dies.
/// Tied to the app's lifetime: the stdin pipe + --parent-pid make the agent
/// exit when the app quits (no orphan agent).
@MainActor
final class AgentSupervisor: ObservableObject {

    @Published private(set) var isRunning = false

    private var process: Process?
    private var stdinPipe: Pipe?
    private var wantsRunning = false
    private var spawnStart = Date()
    private var restartTask: Task<Void, Never>?
    private var helperPath: String

    /// The bundle-relative path to the `ztlp` helper (Contents/Helpers/ztlp).
    /// Injectable for tests (a real path is resolved from Bundle.main in prod).
    init(helperPath: String? = nil) {
        if let helperPath {
            self.helperPath = helperPath
        } else {
            // Bundle.main.bundleURL/Contents/Helpers/ztlp
            let app = Bundle.main.bundleURL
            self.helperPath = app
                .appendingPathComponent("Contents")
                .appendingPathComponent("Helpers")
                .appendingPathComponent("ztlp")
                .path
        }
    }

    /// Start supervising. Idempotent (a second call while running is a no-op).
    func start() {
        guard !wantsRunning else { return }
        wantsRunning = true
        spawn()
    }

    /// Stop supervising: ask the agent to exit (close stdin -> agent's stdin
    /// watch fires -> it removes its pidfile and exits) and stop respawning.
    func stop() {
        wantsRunning = false
        restartTask?.cancel()
        restartTask = nil
        // Closing the write end of the stdin pipe makes the agent read EOF and
        // exit (the instant, reliable "app is gone" signal).
        if let p = process, p.isRunning {
            p.terminationHandler = nil
            p.terminate()
        }
        process = nil
        stdinPipe = nil
        isRunning = false
    }

    /// The path the agent writes its logs to (user-scoped).
    func agentLogPath() -> URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home
            .appendingPathComponent("Library/Logs/ZTLP")
            .appendingPathComponent("agent.log")
    }

    private func spawn() {
        guard wantsRunning else { return }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: helperPath)
        p.arguments = agentSpawnArgs(parentPid: ProcessInfo.processInfo.processIdentifier)
        p.environment = agentSpawnEnv()

        // Create the log file if it doesn't exist (FileHandle(forWritingTo:)
        // requires an existing file). Truncate when it passes 5 MB.
        let logURL = agentLogPath()
        try? FileManager.default.createDirectory(
            at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let attrs = try? FileManager.default.attributesOfItem(atPath: logURL.path)
        let size = attrs?[FileAttributeKey.size] as? Int ?? 0
        if size > 5 * 1024 * 1024 {
            try? FileManager.default.removeItem(at: logURL)
        }
        if !(FileManager.default.fileExists(atPath: logURL.path)) {
            try? Data().write(to: logURL)
        }

        // The stdin pipe is the parent signal: the agent reads EOF on it and
        // exits. We keep the write end (stdinPipe) for the lifetime of `p`.
        let stdin = Pipe()
        p.standardInput = stdin
        // Send one harmless byte so the agent knows the pipe is live (not a
        // null stdin that reads EOF immediately); it then blocks reading until
        // we close it.
        do {
            let out = try FileHandle(forWritingTo: logURL)
            p.standardOutput = out
            p.standardError = out
            try p.run()
            try? stdin.fileHandleForWriting.write(Data([0x00]))
        } catch {
            // Couldn't spawn (e.g. helper missing / not executable). Surface it
            // via the UI's lastError via a lightweight publish; back off so we
            // don't hot-loop a missing binary.
            restartTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(kBackoffInterval * 1_000_000_000))
                self?.spawn()
            }
            return
        }

        self.process = p
        self.stdinPipe = stdin
        self.spawnStart = Date()
        self.isRunning = true

        p.terminationHandler = { [weak self] proc in
            Task { @MainActor in
                self?.handleExit(code: proc.terminationStatus)
            }
        }
    }

    private func handleExit(code: Int32) {
        let lived = Date().timeIntervalSince(spawnStart)
        isRunning = false
        let decision = supervisorDecision(wantsRunning: wantsRunning, exitCode: code, ranFor: lived)
        switch decision {
        case .keepRunning:
            break
        case .stop:
            wantsRunning = false
            process = nil
            stdinPipe = nil
        case .respawn:
            process = nil
            stdinPipe = nil
            spawn()
        case .backoff(let secs):
            process = nil
            stdinPipe = nil
            restartTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(secs * 1_000_000_000))
                self?.spawn()
            }
        }
    }
}
