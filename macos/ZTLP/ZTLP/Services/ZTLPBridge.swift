// ZTLPBridge.swift
// ZTLP macOS
//
// Swift wrapper around the ZTLP C FFI (ztlp.h) — IDENTITY ONLY.
//
// Task 6c (2026-09-19): the app used to drive a full userspace data plane
// through this bridge (ztlp_connect, VIP proxy, DNS resolver, pf redirects,
// AppleScript admin prompts, a hand-rolled com.ztlp.networking LaunchDaemon).
// All of that now lives in the root `ztlp agent` daemon (Option A) and the
// GUI talks to it over AgentControlClient. What remains here is the part
// the app still legitimately owns: generating/loading the app's OWN
// identity for the callback-verified enrollment flow (EnrollmentViewModel)
// and showing it in Settings.

import Foundation

// MARK: - Error Types

/// Errors originating from the ZTLP C library.
enum ZTLPError: LocalizedError {
    case notInitialized
    case invalidArgument(String)
    case identityError(String)
    case handshakeError(String)
    case connectionError(String)
    case timeout(String)
    case sessionNotFound(String)
    case encryptionError(String)
    case natError(String)
    case alreadyConnected
    case notConnected
    case internalError(String)
    case unknownError(Int32, String)

    var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "ZTLP library not initialized"
        case .invalidArgument(let msg):
            return "Invalid argument: \(msg)"
        case .identityError(let msg):
            return "Identity error: \(msg)"
        case .handshakeError(let msg):
            return "Handshake failed: \(msg)"
        case .connectionError(let msg):
            return "Connection error: \(msg)"
        case .timeout(let msg):
            return "Timeout: \(msg)"
        case .sessionNotFound(let msg):
            return "Session not found: \(msg)"
        case .encryptionError(let msg):
            return "Encryption error: \(msg)"
        case .natError(let msg):
            return "NAT traversal error: \(msg)"
        case .alreadyConnected:
            return "Already connected to a peer"
        case .notConnected:
            return "Not connected — call connect first"
        case .internalError(let msg):
            return "Internal error: \(msg)"
        case .unknownError(let code, let msg):
            return "Unknown error (\(code)): \(msg)"
        }
    }

    /// Map a C result code to a Swift error (returns nil for ZTLP_OK).
    static func from(code: Int32) -> ZTLPError? {
        guard code != 0 else { return nil }
        let message = lastError() ?? "no details"
        switch code {
        case -1:  return .invalidArgument(message)
        case -2:  return .identityError(message)
        case -3:  return .handshakeError(message)
        case -4:  return .connectionError(message)
        case -5:  return .timeout(message)
        case -6:  return .sessionNotFound(message)
        case -7:  return .encryptionError(message)
        case -8:  return .natError(message)
        case -9:  return .alreadyConnected
        case -10: return .notConnected
        case -11: return .connectionError("access rejected: \(message)")
        case -99: return .internalError(message)
        default:  return .unknownError(code, message)
        }
    }

    private static func lastError() -> String? {
        guard let ptr = ztlp_last_error() else { return nil }
        return String(cString: ptr)
    }
}

// MARK: - Handle Wrappers

/// RAII wrapper for ZtlpIdentity*.
final class ZTLPIdentityHandle {
    private(set) var pointer: OpaquePointer?
    private var ownsPointer: Bool

    init(_ pointer: OpaquePointer) {
        self.pointer = pointer
        self.ownsPointer = true
    }

    func transferOwnership() -> OpaquePointer? {
        ownsPointer = false
        return pointer
    }

    var nodeId: String? {
        guard let ptr = pointer, let cStr = ztlp_identity_node_id(ptr) else { return nil }
        return String(cString: cStr)
    }

    var publicKey: String? {
        guard let ptr = pointer, let cStr = ztlp_identity_public_key(ptr) else { return nil }
        return String(cString: cStr)
    }

    func save(to path: String) throws {
        guard let ptr = pointer else { throw ZTLPError.notInitialized }
        let result = path.withCString { cPath in
            ztlp_identity_save(ptr, cPath)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    deinit {
        if ownsPointer, let ptr = pointer {
            ztlp_identity_free(ptr)
        }
    }
}

// MARK: - Bridge

/// Singleton bridge between Swift and the ZTLP C FFI (identity + version).
final class ZTLPBridge {

    static let shared = ZTLPBridge()

    private var isInitialized = false

    private init() {}

    // MARK: - Lifecycle

    func initialize() throws {
        guard !isInitialized else { return }

        // Library log to ~/Library/Logs/ZTLP/ (persistent, visible in Console.app)
        let logsDir = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Logs/ZTLP")
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)
        let logPath = logsDir.appendingPathComponent("app.log").path
        setenv("ZTLP_LOG_FILE", logPath, 0) // Don't override if already set
        setenv("ZTLP_LOG_LEVEL", "info", 0)

        let result = ztlp_init()
        if let error = ZTLPError.from(code: result) { throw error }
        isInitialized = true
    }

    func shutdown() {
        if isInitialized {
            ztlp_shutdown()
            isInitialized = false
        }
    }

    var version: String {
        guard let ptr = ztlp_version() else { return "unknown" }
        return String(cString: ptr)
    }

    // MARK: - Identity

    func generateIdentity() throws -> ZTLPIdentityHandle {
        try ensureInitialized()
        guard let ptr = ztlp_identity_generate() else {
            throw lastErrorAsZTLPError(fallback: .identityError("generation failed"))
        }
        return ZTLPIdentityHandle(ptr)
    }

    func loadIdentity(from path: String) throws -> ZTLPIdentityHandle {
        try ensureInitialized()
        let ptr = path.withCString { cPath -> OpaquePointer? in
            return ztlp_identity_from_file(cPath)
        }
        guard let identity = ptr else {
            throw lastErrorAsZTLPError(fallback: .identityError("failed to load from \(path)"))
        }
        return ZTLPIdentityHandle(identity)
    }

    /// Create a hardware-backed identity.
    /// On macOS, provider 0 (software) is the typical choice.
    func createHardwareIdentity(provider: Int32 = 0) throws -> ZTLPIdentityHandle {
        try ensureInitialized()
        guard let ptr = ztlp_identity_from_hardware(provider) else {
            throw lastErrorAsZTLPError(fallback: .identityError("hardware provider \(provider) unavailable"))
        }
        return ZTLPIdentityHandle(ptr)
    }

    // MARK: - Helpers

    private func ensureInitialized() throws {
        guard isInitialized else { throw ZTLPError.notInitialized }
    }

    private func lastErrorAsZTLPError(fallback: ZTLPError) -> ZTLPError {
        if let ptr = ztlp_last_error() {
            let msg = String(cString: ptr)
            return .internalError(msg)
        }
        return fallback
    }
}
