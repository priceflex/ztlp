// TunnelLogger.swift
// ZTLP
//
// Shared logging service that writes to the app group container.
// Both the main app and the Network Extension can write/read logs
// through the same file, enabling a unified log viewer.

import Foundation

// MARK: - LogLevel

/// Log severity levels.
enum LogLevel: String, CaseIterable, Codable, Comparable {
    case debug = "DEBUG"
    case info  = "INFO"
    case warn  = "WARN"
    case error = "ERROR"

    static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        let order: [LogLevel] = [.debug, .info, .warn, .error]
        return (order.firstIndex(of: lhs) ?? 0) < (order.firstIndex(of: rhs) ?? 0)
    }
}

// MARK: - LogEntry

/// A single parsed log entry.
struct LogEntry: Identifiable, Equatable {
    let id: UUID
    let timestamp: Date
    let level: LogLevel
    let source: String
    let message: String
}

// MARK: - TunnelLogger

/// Thread-safe singleton logger that writes to the shared app group container.
///
/// Log format per line:
///   `[2026-03-27T05:24:00Z] [INFO] [VPN] Connection established`
///
/// Both the main app and the Network Extension write to the same file.
/// The UI observes `TunnelLogger.didLog` to update in real time.
final class TunnelLogger {

    // MARK: - Singleton

    static let shared = TunnelLogger()

    // MARK: - Notifications

    /// Posted on the main thread whenever a new log entry is written.
    /// The `object` is the new `LogEntry`.
    static let didLog = Notification.Name("TunnelLoggerDidLog")

    // MARK: - Constants

    /// Maximum number of lines to keep in the log file.
    private static let maxLines = 5000
    /// Only trim the file periodically so hot-path logging stays append-only.
    private static let rotationCheckInterval: TimeInterval = 60

    // MARK: - Properties

    /// Serial queue for thread-safe file I/O.
    private let queue = DispatchQueue(label: "com.ztlp.logger", qos: .utility)

    /// Path to the shared log file.
    private let logFileURL: URL?

    /// Last time we ran an on-disk rotation pass.
    private var lastRotationCheck = Date.distantPast

    /// ISO 8601 formatter for timestamps.
    private let dateFormatter: ISO8601DateFormatter = {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fmt
    }()

    // MARK: - Init

    private init() {
        if let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) {
            self.logFileURL = container.appendingPathComponent("ztlp.log")
        } else {
            // Fallback for previews / tests
            self.logFileURL = nil
        }
    }

    // MARK: - Public API

    /// Write a log entry.
    ///
    /// - Parameters:
    ///   - message: The log message.
    ///   - level: Severity level.
    ///   - source: Origin identifier (e.g. "App", "Tunnel", "Enrollment", "VPN", "Network").
    func log(_ message: String, level: LogLevel = .info, source: String = "App") {
        let now = Date()
        let timestamp = dateFormatter.string(from: now)
        let line = "[\(timestamp)] [\(level.rawValue)] [\(source)] \(message)"

        let entry = LogEntry(
            id: UUID(),
            timestamp: now,
            level: level,
            source: source,
            message: message
        )

        queue.async { [weak self] in
            self?.appendLine(line)

            // Post notification on main thread so UI can update
            DispatchQueue.main.async {
                NotificationCenter.default.post(
                    name: TunnelLogger.didLog,
                    object: entry
                )
            }
        }
    }

    /// Convenience: log at debug level.
    func debug(_ message: String, source: String = "App") {
        log(message, level: .debug, source: source)
    }

    /// Convenience: log at info level.
    func info(_ message: String, source: String = "App") {
        log(message, level: .info, source: source)
    }

    /// Convenience: log at warn level.
    func warn(_ message: String, source: String = "App") {
        log(message, level: .warn, source: source)
    }

    /// Convenience: log at error level.
    func error(_ message: String, source: String = "App") {
        log(message, level: .error, source: source)
    }

    /// Read all log entries from the file.
    func readAll() -> [LogEntry] {
        var result: [LogEntry] = []
        queue.sync {
            guard let url = logFileURL,
                  let contents = try? String(contentsOf: url, encoding: .utf8) else {
                return
            }
            let lines = contents.components(separatedBy: "\n").filter { !$0.isEmpty }
            result = lines.compactMap { parseLine($0) }
        }
        return result
    }

    /// Clear the log file.
    func clear() {
        queue.async { [weak self] in
            guard let url = self?.logFileURL else { return }
            try? "".write(to: url, atomically: true, encoding: .utf8)
        }
    }

    /// Export the full log as UTF-8 data (for sharing).
    func exportData() -> Data {
        flush()
        var data = Data()
        queue.sync {
            guard let url = logFileURL,
                  let contents = try? Data(contentsOf: url) else {
                return
            }
            data = contents
        }
        return data
    }

    /// Block until all queued log writes have been persisted.
    func flush() {
        queue.sync { }
    }

    // MARK: - Private

    /// Append a line to the log file using append-only I/O.
    private func appendLine(_ line: String) {
        guard let url = logFileURL else { return }

        let data = Data((line + "\n").utf8)

        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }

        if let handle = try? FileHandle(forWritingTo: url) {
            do {
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
                try handle.close()
            } catch {
                try? handle.close()
                try? data.write(to: url, options: .atomic)
            }
        } else {
            try? data.write(to: url, options: .atomic)
        }

        rotateLogIfNeeded(now: Date(), url: url)
    }

    private func rotateLogIfNeeded(now: Date, url: URL) {
        guard now.timeIntervalSince(lastRotationCheck) >= Self.rotationCheckInterval else {
            return
        }
        lastRotationCheck = now

        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return
        }

        let lines = contents.split(separator: "\n", omittingEmptySubsequences: true)
        guard lines.count > Self.maxLines else { return }

        let trimmed = lines.suffix(Self.maxLines).joined(separator: "\n") + "\n"
        try? trimmed.write(to: url, atomically: false, encoding: .utf8)
    }

    /// Parse a log line into a LogEntry.
    ///
    /// Expected format: `[2026-03-27T05:24:00.000Z] [INFO] [VPN] message text`
    private func parseLine(_ line: String) -> LogEntry? {
        // Match: [timestamp] [LEVEL] [source] message
        let pattern = #"^\[(.+?)\] \[(\w+)\] \[(.+?)\] (.*)$"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(
                in: line,
                range: NSRange(line.startIndex..., in: line)
              ),
              match.numberOfRanges == 5 else {
            return nil
        }

        func group(_ i: Int) -> String? {
            guard let range = Range(match.range(at: i), in: line) else { return nil }
            return String(line[range])
        }

        guard let timestampStr = group(1),
              let levelStr = group(2),
              let source = group(3),
              let message = group(4),
              let level = LogLevel(rawValue: levelStr) else {
            return nil
        }

        let timestamp = dateFormatter.date(from: timestampStr) ?? Date()

        return LogEntry(
            id: UUID(),
            timestamp: timestamp,
            level: level,
            source: source,
            message: message
        )
    }
}
