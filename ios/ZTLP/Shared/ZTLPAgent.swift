// ZTLPAgent.swift
// Shared by the app and the packet tunnel extension.
//
// Thin Swift wrapper over the C contract in Libraries/ztlp_ios.h. Every
// wrapper is synchronous and blocking; call them off the main thread.
//
// `ztlp_ios_last_error` is per-thread, so each wrapper reads it immediately
// after the failing call, on the same thread, before returning.

import Foundation

/// Decoded `ztlp_ios_status_json`.
struct AgentStatus: Equatable, Sendable {
    var running = false
    var enrolled = false
    var nodeName = ""
    var zone = ""
    var vips = 0
    var tunnels = 0
    var caReady = false
    var lastError = ""

    /// Lenient decode: missing or mistyped fields keep their defaults, so a
    /// newer agent adding fields never breaks the app.
    static func decode(_ data: Data) -> AgentStatus? {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dict = object as? [String: Any] else { return nil }
        var status = AgentStatus()
        status.running = dict["running"] as? Bool ?? false
        status.enrolled = dict["enrolled"] as? Bool ?? false
        status.nodeName = dict["node_name"] as? String ?? ""
        status.zone = dict["zone"] as? String ?? ""
        status.vips = dict["vips"] as? Int ?? 0
        status.tunnels = dict["tunnels"] as? Int ?? 0
        status.caReady = dict["ca_ready"] as? Bool ?? false
        status.lastError = dict["last_error"] as? String ?? ""
        return status
    }
}

struct AgentError: Error, LocalizedError, Equatable {
    let code: Int32
    let message: String

    var errorDescription: String? { message }
}

enum ZTLPAgent {
    private static let initLock = NSLock()
    // Guarded by initLock.
    nonisolated(unsafe) private static var initialized = false

    /// `ztlp_ios_init`, at most once per process. A failed init is not
    /// remembered, so the caller may retry.
    static func initialize(home: URL) -> Result<Void, AgentError> {
        initLock.lock()
        defer { initLock.unlock() }
        if initialized { return .success(()) }
        let rc = home.path.withCString { ztlp_ios_init($0) }
        guard rc == 0 else { return .failure(failure(rc, doing: "start the ZTLP library")) }
        initialized = true
        return .success(())
    }

    static var isEnrolled: Bool { ztlp_ios_is_enrolled() == 1 }

    static func enroll(uri: String, deviceName: String) -> Result<Void, AgentError> {
        let rc = uri.withCString { uriPtr in
            deviceName.withCString { namePtr in ztlp_ios_enroll(uriPtr, namePtr) }
        }
        return rc == 0 ? .success(()) : .failure(failure(rc, doing: "enroll"))
    }

    static func ensureCA() -> Result<Void, AgentError> {
        let rc = ztlp_ios_ensure_ca()
        return rc == 0 ? .success(()) : .failure(failure(rc, doing: "create the certificate"))
    }

    static func caRootPEM() -> Result<String, AgentError> {
        readString(doing: "read the certificate") { ztlp_ios_ca_root_pem($0, $1) }
    }

    static func start(dnsIP: String, vipCIDR: String) -> Result<Void, AgentError> {
        let rc = dnsIP.withCString { dns in
            vipCIDR.withCString { cidr in ztlp_ios_agent_start(dns, cidr) }
        }
        return rc == 0 ? .success(()) : .failure(failure(rc, doing: "start the agent"))
    }

    @discardableResult
    static func stop() -> Int32 { ztlp_ios_agent_stop() }

    /// Tell the agent the device's network changed, so it stops using
    /// connections made on the old one.
    @discardableResult
    static func networkChanged() -> Int32 { ztlp_ios_network_changed() }

    /// Raw status JSON, as the extension returns it to the app.
    static func statusJSON() -> Data? {
        switch readString(doing: "read status", { ztlp_ios_status_json($0, $1) }) {
        case .success(let text): return Data(text.utf8)
        case .failure: return nil
        }
    }

    static func status() -> AgentStatus? {
        statusJSON().flatMap(AgentStatus.decode)
    }

    // MARK: - Helpers

    /// Call a "copy string into buffer" function, growing the buffer when the
    /// library answers -2 (buffer too small).
    private static func readString(
        doing what: String,
        _ call: (UnsafeMutablePointer<CChar>, UInt32) -> Int32
    ) -> Result<String, AgentError> {
        var capacity = 16 * 1024
        while capacity <= 1024 * 1024 {
            var buffer = [CChar](repeating: 0, count: capacity)
            let rc = buffer.withUnsafeMutableBufferPointer { ptr -> Int32 in
                guard let base = ptr.baseAddress else { return -1 }
                return call(base, UInt32(ptr.count))
            }
            if rc == -2 {
                capacity *= 4
                continue
            }
            guard rc >= 0, Int(rc) < capacity else {
                return .failure(failure(rc, doing: what))
            }
            let bytes = buffer.prefix(Int(rc)).map { UInt8(bitPattern: $0) }
            return .success(String(decoding: bytes, as: UTF8.self))
        }
        return .failure(AgentError(code: -2, message: "Could not \(what): reply too large."))
    }

    /// Build an error from the library's per-thread last-error text.
    private static func failure(_ code: Int32, doing what: String) -> AgentError {
        var text = ""
        if let ptr = ztlp_ios_last_error() {
            text = String(cString: ptr).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if text.isEmpty { text = "Could not \(what) (error \(code))." }
        return AgentError(code: code, message: text)
    }
}

/// Carries a value the compiler cannot prove Sendable (a system completion
/// handler, for example) into a dispatch closure. The call site is
/// responsible for using it from one place at a time.
struct UncheckedSendable<Value>: @unchecked Sendable {
    let value: Value
    init(_ value: Value) { self.value = value }
}
