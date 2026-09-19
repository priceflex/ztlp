// AgentControlClient.swift
// ZTLP macOS
//
// Task 6a: talk to the root `ztlp agent` daemon over its TCP loopback
// control socket (127.100.255.1:4433), the same JSON-line protocol the
// CLI itself uses (proto/src/agent/control.rs). This is the "thin shell"
// half of Option A — the GUI never touches DNS/VIP/TLS/enrollment state
// directly; it asks the daemon to do it and reads back a JSON result.
//
// Auth: the daemon's control socket is Bearer-token gated by
// `~/.ztlp/agent.token` (F7a in the plan). Because the daemon runs as
// root with HOME pinned to `/Library/Application Support/ZTLP`
// (macos_daemon.rs MACOS_SYSTEM_CONFIG_DIR), its token file lives at
// `/Library/Application Support/ZTLP/.ztlp/agent.token` — chgrp staff,
// 0640, so the non-root GUI user can read it (see Task 5a design note in
// ZTLP-MAC-PLAN-2026-09-19.md §3).

import Foundation

/// Errors talking to the root agent daemon's control socket.
enum AgentControlError: LocalizedError {
    case daemonUnreachable(String)
    case tokenUnreadable(String)
    case malformedResponse(String)
    case daemonError(String)

    var errorDescription: String? {
        switch self {
        case .daemonUnreachable(let msg):
            return "Cannot reach the ZTLP agent service: \(msg)"
        case .tokenUnreadable(let msg):
            return "Cannot read the agent's control token: \(msg)"
        case .malformedResponse(let msg):
            return "Unexpected response from the agent service: \(msg)"
        case .daemonError(let msg):
            return msg
        }
    }
}

/// Minimal JSON-line TCP client for the daemon's control socket.
///
/// One request per connection, mirroring `control::send_command` on the
/// Rust side exactly (proto/src/agent/control.rs) — connect, write one
/// JSON line, read one JSON line back, close.
enum AgentControlClient {

    /// Default control socket address (must match
    /// `control::default_ipc_address()`).
    static let defaultAddress = (host: "127.100.255.1", port: UInt16(4433))

    /// Where the root daemon's own bearer token lives (F7a: macOS daemon
    /// HOME is pinned to `/Library/Application Support/ZTLP`, so its
    /// `~/.ztlp` resolves under there — NOT the invoking user's home).
    static let daemonTokenPath =
        "/Library/Application Support/ZTLP/.ztlp/agent.token"

    /// Read the daemon's control-socket bearer token from disk.
    ///
    /// Returns `nil` (not an error) if the file doesn't exist yet — the
    /// daemon may be running in legacy/no-auth mode, or not installed at
    /// all. Callers send `token: nil` in that case; the daemon's own
    /// `expected_token` gate decides whether that's accepted.
    static func readDaemonToken() -> String? {
        guard let data = FileManager.default.contents(atPath: daemonTokenPath),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Send one control command and return the raw decoded response.
    ///
    /// - Parameters:
    ///   - cmd: command name, e.g. "status", "enroll".
    ///   - name: optional `name` field (device name for enroll, target for connect).
    ///   - enrollmentURI: optional `enrollment_uri` field (enroll only).
    ///   - relaySecret: optional `relay_secret` field (enroll only, plan §4a).
    ///   - timeout: socket read/write timeout in seconds.
    static func send(
        cmd: String,
        name: String? = nil,
        enrollmentURI: String? = nil,
        relaySecret: String? = nil,
        timeout: TimeInterval = 30
    ) async throws -> AgentControlResponse {
        var payload: [String: Any] = ["cmd": cmd]
        if let name { payload["name"] = name }
        if let enrollmentURI { payload["enrollment_uri"] = enrollmentURI }
        if let relaySecret { payload["relay_secret"] = relaySecret }
        if let token = readDaemonToken() { payload["token"] = token }

        let requestData = try JSONSerialization.data(withJSONObject: payload)

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let response = try sendSync(requestData: requestData, timeout: timeout)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Blocking POSIX-socket implementation, run off the main actor via
    /// the `DispatchQueue.global` hop in `send(...)` above. Kept
    /// synchronous + dependency-free (no Network.framework) to match the
    /// same one-shot connect/write/read/close shape as the Rust CLI's
    /// `send_command`.
    private static func sendSync(
        requestData: Data,
        timeout: TimeInterval
    ) throws -> AgentControlResponse {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw AgentControlError.daemonUnreachable("socket() failed (errno \(errno))")
        }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = defaultAddress.port.bigEndian
        guard inet_pton(AF_INET, defaultAddress.host, &addr.sin_addr) == 1 else {
            throw AgentControlError.daemonUnreachable("invalid control address")
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            throw AgentControlError.daemonUnreachable(
                "connect() failed (errno \(errno)) — is the ZTLP agent service running?"
            )
        }

        var outgoing = requestData
        outgoing.append(0x0A) // newline-delimited, matching the Rust framing
        let writeResult = outgoing.withUnsafeBytes { buf -> Int in
            write(fd, buf.baseAddress, buf.count)
        }
        guard writeResult == outgoing.count else {
            throw AgentControlError.daemonUnreachable("write() failed (errno \(errno))")
        }

        var received = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !received.contains(0x0A) {
            let n = buffer.withUnsafeMutableBytes { buf -> Int in
                read(fd, buf.baseAddress, buf.count)
            }
            if n < 0 {
                throw AgentControlError.daemonUnreachable("read() failed (errno \(errno))")
            }
            if n == 0 { break } // EOF
            received.append(contentsOf: buffer[0..<n])
        }

        guard let newlineIndex = received.firstIndex(of: 0x0A) else {
            throw AgentControlError.malformedResponse("no response line received")
        }
        let line = received[received.startIndex..<newlineIndex]

        guard let decoded = try? JSONDecoder().decode(AgentControlResponse.self, from: Data(line)) else {
            let raw = String(data: Data(line), encoding: .utf8) ?? "<binary>"
            throw AgentControlError.malformedResponse(raw)
        }
        return decoded
    }
}

/// Mirrors `control::ControlResponse` on the Rust side.
struct AgentControlResponse: Decodable {
    let ok: Bool
    let error: String?
    let data: JSONValue?
}

/// Minimal untyped-JSON box so `AgentControlResponse.data` can hold
/// whatever shape a given command returns (status/tunnels/enroll all
/// differ) without a bespoke Decodable type per command.
enum JSONValue: Decodable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let v = try? container.decode(String.self) { self = .string(v); return }
        if let v = try? container.decode(Double.self) { self = .number(v); return }
        if let v = try? container.decode(Bool.self) { self = .bool(v); return }
        if let v = try? container.decode([String: JSONValue].self) { self = .object(v); return }
        if let v = try? container.decode([JSONValue].self) { self = .array(v); return }
        self = .null
    }

    var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }
}
