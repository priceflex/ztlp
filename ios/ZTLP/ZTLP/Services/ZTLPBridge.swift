// ZTLPBridge.swift
// ZTLP
//
// Swift wrapper around the ZTLP C FFI (ztlp.h).
//
// This is the central bridge between Swift and the Rust static library.
// All C function calls are routed through this singleton to ensure proper
// lifecycle management and thread safety.
//
// Memory ownership rules:
//   - ZtlpIdentity*: Caller owns until passed to ztlp_client_new() (which takes ownership).
//   - ZtlpClient*: Caller owns. Free with ztlp_client_free().
//   - ZtlpConfig*: Caller owns. Free with ztlp_config_free().
//   - ZtlpSession*: Library owns. Only valid during callback invocation.
//   - Strings from accessors (node_id, public_key): Library owns. Do NOT free.
//   - Strings marked "caller must free": Use ztlp_string_free().
//
// Threading:
//   All C callbacks fire on the Rust tokio runtime thread. We dispatch to
//   MainActor or a serial queue before touching any Swift state.

import Foundation
import Combine
import Network

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
        guard code != 0 else { return nil } // ZTLP_OK
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
        case -99: return .internalError(message)
        default:  return .unknownError(code, message)
        }
    }

    /// Read the thread-local error message from the C library.
    private static func lastError() -> String? {
        guard let ptr = ztlp_last_error() else { return nil }
        return String(cString: ptr)
    }
}

// MARK: - Handle Wrappers

/// RAII wrapper for ZtlpIdentity*.
/// Automatically frees the handle on deinit unless ownership was transferred.
final class ZTLPIdentityHandle {
    private(set) var pointer: OpaquePointer?
    private var ownsPointer: Bool

    init(_ pointer: OpaquePointer) {
        self.pointer = pointer
        self.ownsPointer = true
    }

    /// Transfer ownership to ztlp_client_new. After this, we no longer free.
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

/// RAII wrapper for ZtlpConfig*.
final class ZTLPConfigHandle {
    let pointer: OpaquePointer

    init() {
        self.pointer = ztlp_config_new()
    }

    func setRelay(_ address: String) throws {
        let result = address.withCString { cAddr in
            ztlp_config_set_relay(pointer, cAddr)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    func setStunServer(_ address: String) throws {
        let result = address.withCString { cAddr in
            ztlp_config_set_stun_server(pointer, cAddr)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    func setNatAssist(_ enabled: Bool) throws {
        let result = ztlp_config_set_nat_assist(pointer, enabled)
        if let error = ZTLPError.from(code: result) { throw error }
    }

    func setTimeoutMs(_ ms: UInt64) throws {
        let result = ztlp_config_set_timeout_ms(pointer, ms)
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Set the service name for gateway routing.
    func setService(_ name: String) throws {
        let result = name.withCString { cName in
            ztlp_config_set_service(pointer, cName)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    deinit {
        ztlp_config_free(pointer)
    }
}

// MARK: - Connection Event

/// Events emitted by the bridge via Combine publishers.
enum ZTLPConnectionEvent {
    case connected(peerAddress: String)
    case disconnected(reason: Int32)
    case dataReceived(Data)
    case stateChanged(Int32)
    case error(ZTLPError)
}

// MARK: - Bridge

/// Singleton bridge between Swift and the ZTLP C FFI.
///
/// Thread safety:
///   - The C library is thread-safe (Arc<Mutex<>> internally).
///   - C callbacks fire on the Rust tokio thread.
///   - We dispatch all callback results to `eventSubject` (Combine),
///     which callers observe on their preferred scheduler.
///   - The `clientLock` serializes client lifecycle operations.
final class ZTLPBridge {

    // MARK: Singleton

    static let shared = ZTLPBridge()

    // MARK: Properties

    /// Combine subject for connection events.
    let eventSubject = PassthroughSubject<ZTLPConnectionEvent, Never>()

    /// Current client handle (nil when not connected).
    private var client: OpaquePointer?

    /// Current identity handle (only set before client creation).
    private var currentIdentity: ZTLPIdentityHandle?

    /// Serial queue protecting client lifecycle mutations.
    private let clientLock = DispatchQueue(label: "com.ztlp.bridge.client", qos: .userInitiated)

    /// Whether ztlp_init() has been called.
    private var isInitialized = false

    /// Traffic counters (updated atomically from callbacks).
    private(set) var bytesSent: UInt64 = 0
    private(set) var bytesReceived: UInt64 = 0

    /// Dedicated NWConnection for ACK sending, bypassing the Rust-owned socket.
    private var ackConnection: NWConnection?
    private let ackQueue = DispatchQueue(label: "com.ztlp.ack-sender", qos: .userInteractive)

    // MARK: Init

    private init() {}

    // MARK: - Lifecycle

    /// Initialize the ZTLP library. Safe to call multiple times.
    func initialize() throws {
        guard !isInitialized else { return }
        let result = ztlp_init()
        if let error = ZTLPError.from(code: result) { throw error }
        isInitialized = true
    }

    /// Shut down the ZTLP library. Call on app termination.
    func shutdown() {
        clientLock.sync {
            if let c = client {
                ztlp_client_free(c)
                client = nil
            }
            currentIdentity = nil
        }
        if isInitialized {
            ztlp_shutdown()
            isInitialized = false
        }
    }

    /// The library version string.
    var version: String {
        guard let ptr = ztlp_version() else { return "unknown" }
        return String(cString: ptr)
    }

    // MARK: - Identity

    /// Generate a new software identity.
    func generateIdentity() throws -> ZTLPIdentityHandle {
        try ensureInitialized()
        guard let ptr = ztlp_identity_generate() else {
            throw lastErrorAsZTLPError(fallback: .identityError("generation failed"))
        }
        return ZTLPIdentityHandle(ptr)
    }

    /// Load an identity from a JSON file.
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

    /// Create a hardware-backed identity (Secure Enclave on iOS).
    ///
    /// Provider constants:
    ///   - 0: Software (file-based)
    ///   - 1: iOS Secure Enclave
    ///   - 2: Android Keystore
    ///   - 3: Hardware token (reserved)
    func createHardwareIdentity(provider: Int32 = 1) throws -> ZTLPIdentityHandle {
        try ensureInitialized()
        guard let ptr = ztlp_identity_from_hardware(provider) else {
            throw lastErrorAsZTLPError(fallback: .identityError("hardware provider \(provider) unavailable"))
        }
        return ZTLPIdentityHandle(ptr)
    }

    // MARK: - Client

    /// Create the ZTLP client from the given identity.
    ///
    /// The identity's ownership transfers to the client. Do not use the
    /// identity handle after this call.
    func createClient(identity: ZTLPIdentityHandle) throws {
        try ensureInitialized()
        guard let idPtr = identity.transferOwnership() else {
            throw ZTLPError.invalidArgument("identity handle is nil")
        }
        let newClient = ztlp_client_new(idPtr)
        guard let c = newClient else {
            throw lastErrorAsZTLPError(fallback: .internalError("client creation failed"))
        }
        clientLock.sync {
            // Free any existing client first
            if let old = self.client {
                ztlp_client_free(old)
            }
            self.client = c
        }
        // Set up callbacks
        try setupCallbacks()
    }

    /// Whether a client handle currently exists.
    var hasClient: Bool {
        clientLock.sync { self.client != nil }
    }

    /// Free the current client. Safe to call if no client exists.
    func destroyClient() {
        clientLock.sync {
            if let c = self.client {
                ztlp_client_free(c)
                self.client = nil
            }
            self.ackConnection?.cancel()
            self.ackConnection = nil
            self.bytesSent = 0
            self.bytesReceived = 0
        }
    }

    /// Disconnect the transport session but keep the client and runtime alive.
    /// On reconnect, call connect() again — the existing client + VIP proxy
    /// listeners remain intact.
    func disconnectTransport() {
        clientLock.sync {
            if let c = self.client {
                ztlp_disconnect_transport(c)
            }
        }
    }

    /// Set the service name on the client (legacy path — prefer ZTLPConfigHandle.setService).
    func setService(_ name: String) throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = name.withCString { cName in
            ztlp_config_set_service(c, cName)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    // MARK: - NS Resolution

    /// Resolve a service name via ZTLP-NS.
    ///
    /// This is a static call — no client required. Contacts the NS server directly.
    ///
    /// - Parameters:
    ///   - serviceName: The ZTLP-NS name (e.g., "vault.techrockstars.ztlp")
    ///   - nsServer: The NS server address (e.g., "52.39.59.34:23096")
    ///   - timeoutMs: Query timeout in ms (0 = default 5000ms)
    /// - Returns: Resolved address string (e.g., "10.42.42.112:23098")
    func nsResolve(serviceName: String, nsServer: String, timeoutMs: UInt32 = 5000) throws -> String {
        let result = serviceName.withCString { cName in
            nsServer.withCString { cServer in
                ztlp_ns_resolve(cName, cServer, timeoutMs)
            }
        }
        guard let cStr = result else {
            let errMsg = String(cString: ztlp_last_error())
            throw ZTLPError.connectionError("NS resolution failed: \(errMsg)")
        }
        let resolved = String(cString: cStr)
        ztlp_string_free(cStr)
        return resolved
    }

    // MARK: - VIP Proxy & DNS

    /// Register a service with a VIP address for local proxy.
    func vipAddService(name: String, vip: String, port: UInt16) throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = name.withCString { cName in
            vip.withCString { cVip in
                ztlp_vip_add_service(c, cName, cVip, port)
            }
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Start VIP TCP proxy listeners on all registered VIP:port combos.
    func vipStart() throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = ztlp_vip_start(c)
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Stop all VIP proxy listeners.
    func vipStop() {
        guard let c = clientLock.sync(execute: { self.client }) else { return }
        ztlp_vip_stop(c)
    }

    // MARK: - Packet Router (10.122.0.0/16 VIP Routing)

    /// Initialize the packet router with the tunnel interface address.
    /// Call after `connect()` succeeds. The router handles raw IPv4 packets
    /// from the utun interface and maps destination IPs to ZTLP services.
    func routerNew(tunnelAddr: String) throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = tunnelAddr.withCString { cAddr in
            ztlp_router_new(c, cAddr)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Register a VIP service with the packet router.
    /// Maps a VIP address (e.g., "10.122.0.1") to a ZTLP service name.
    func routerAddService(vip: String, serviceName: String) throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = vip.withCString { cVip in
            serviceName.withCString { cName in
                ztlp_router_add_service(c, cVip, cName)
            }
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Write a raw IPv4 packet into the packet router (from utun → ZTLP).
    /// Call this from the readPackets loop.
    func routerWritePacket(_ data: Data) throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = data.withUnsafeBytes { ptr in
            ztlp_router_write_packet(c, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Read the next outbound IPv4 packet from the router (ZTLP → utun).
    /// Returns nil when no packets are available.
    func routerReadPacket() -> Data? {
        guard let c = clientLock.sync(execute: { self.client }) else { return nil }
        // Max IPv4 packet size with 1400 MTU
        var buf = [UInt8](repeating: 0, count: 1500)
        let result = ztlp_router_read_packet(c, &buf, buf.count)
        if result > 0 {
            return Data(buf[..<Int(result)])
        }
        return nil
    }

    /// Stop the packet router.
    func routerStop() {
        guard let c = clientLock.sync(execute: { self.client }) else { return }
        ztlp_router_stop(c)
    }

    /// Start local DNS resolver for *.ztlp domains.
    func dnsStart(listenAddr: String = "127.0.55.53:5354") throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = listenAddr.withCString { cAddr in
            ztlp_dns_start(c, cAddr)
        }
        if let error = ZTLPError.from(code: result) { throw error }
    }

    /// Stop DNS resolver.
    func dnsStop() {
        guard let c = clientLock.sync(execute: { self.client }) else { return }
        ztlp_dns_stop(c)
    }

    // MARK: - Connection

    /// Connect to a peer asynchronously.
    ///
    /// Returns when the connection succeeds or fails.
    func connect(target: String, config: ZTLPConfigHandle? = nil) async throws {
        try ensureInitialized()
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }

        return try await withCheckedThrowingContinuation { continuation in
            // We use an Unmanaged pointer to pass the continuation to the C callback.
            // The callback is invoked exactly once, so we use passRetained/takeRetainedValue.
            let context = Unmanaged.passRetained(
                ContinuationBox(continuation: continuation)
            ).toOpaque()

            let result = target.withCString { cTarget in
                ztlp_connect(c, cTarget, config?.pointer, connectCallback, context)
            }

            if let error = ZTLPError.from(code: result) {
                // Immediate failure — clean up the retained context
                let _ = Unmanaged<ContinuationBox>.fromOpaque(context).takeRetainedValue()
                continuation.resume(throwing: error)
            }
        }
    }

    /// Disconnect and free the current client.
    func disconnect() {
        destroyClient()
        eventSubject.send(.disconnected(reason: 0))
    }

    // MARK: - Data Transfer

    /// Send data through the active session.
    func send(data: Data) throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = data.withUnsafeBytes { rawBuf -> Int32 in
            guard let baseAddress = rawBuf.baseAddress else { return -1 }
            return ztlp_send(c, baseAddress.assumingMemoryBound(to: UInt8.self), rawBuf.count)
        }
        if let error = ZTLPError.from(code: result) { throw error }
        bytesSent += UInt64(data.count)
    }

    // MARK: - Tunnel

    /// Start a TCP tunnel (local port forwarding over ZTLP).
    func startTunnel(localPort: UInt16, remoteHost: String, remotePort: UInt16) async throws {
        try ensureInitialized()
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }

        return try await withCheckedThrowingContinuation { continuation in
            let context = Unmanaged.passRetained(
                ContinuationBox(continuation: continuation)
            ).toOpaque()

            let result = remoteHost.withCString { cHost in
                ztlp_tunnel_start(c, localPort, cHost, remotePort, connectCallback, context)
            }

            if let error = ZTLPError.from(code: result) {
                let _ = Unmanaged<ContinuationBox>.fromOpaque(context).takeRetainedValue()
                continuation.resume(throwing: error)
            }
        }
    }

    /// Stop the active TCP tunnel.
    func stopTunnel() throws {
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }
        let result = ztlp_tunnel_stop(c)
        if let error = ZTLPError.from(code: result) { throw error }
    }

    // MARK: - Callbacks

    /// Set up the receive and disconnect callbacks on the current client.
    private func setupCallbacks() throws {
        guard let c = clientLock.sync(execute: { self.client }) else { return }

        // Store a pointer to `self` as user_data.
        // ZTLPBridge.shared is a singleton that outlives all callbacks, so
        // using Unmanaged.passUnretained is safe (no extra retain cycle).
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()

        let recvResult = ztlp_set_recv_callback(c, recvCallback, selfPtr)
        if let error = ZTLPError.from(code: recvResult) { throw error }

        let disconnectResult = ztlp_set_disconnect_callback(c, disconnectCallbackFn, selfPtr)
        if let error = ZTLPError.from(code: disconnectResult) { throw error }

        let ackResult = ztlp_set_ack_send_callback(c, ackSendCallback, selfPtr)
        if let error = ZTLPError.from(code: ackResult) { throw error }
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

    /// Reset traffic counters.
    func resetCounters() {
        bytesSent = 0
        bytesReceived = 0
    }

    /// Increment bytes received counter (called from C callback context).
    func addBytesReceived(_ count: UInt64) {
        bytesReceived += count
    }
}

// MARK: - Continuation Box

/// Box for passing a Swift checked continuation through a C void* callback.
private final class ContinuationBox {
    let continuation: CheckedContinuation<Void, Error>
    init(continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }
}

// MARK: - C Callback Trampolines

/// Connect callback — invoked once from Rust tokio thread.
///
/// user_data contains a retained `ContinuationBox`.
private func connectCallback(userData: UnsafeMutableRawPointer?,
                              resultCode: Int32,
                              peerAddr: UnsafePointer<CChar>?) {
    guard let userData = userData else { return }
    let box_ = Unmanaged<ContinuationBox>.fromOpaque(userData).takeRetainedValue()

    if resultCode == 0 {
        // Notify the event subject about successful connection
        let addr = peerAddr.map { String(cString: $0) } ?? "unknown"
        ZTLPBridge.shared.eventSubject.send(.connected(peerAddress: addr))
        box_.continuation.resume()
    } else {
        let error = ZTLPError.from(code: resultCode) ?? .unknownError(resultCode, "connection failed")
        box_.continuation.resume(throwing: error)
    }
}

/// Receive callback — invoked for every incoming packet from Rust tokio thread.
///
/// user_data is an unretained pointer to ZTLPBridge.shared.
private func recvCallback(userData: UnsafeMutableRawPointer?,
                           dataPtr: UnsafePointer<UInt8>?,
                           dataLen: Int,
                           session: OpaquePointer?) {
    guard let dataPtr = dataPtr, dataLen > 0 else { return }
    // Copy data immediately — the pointer is only valid during this callback.
    let data = Data(bytes: dataPtr, count: dataLen)
    ZTLPBridge.shared.addBytesReceived(UInt64(dataLen))
    ZTLPBridge.shared.eventSubject.send(.dataReceived(data))
}

/// Disconnect callback — invoked from Rust tokio thread when session drops.
///
/// user_data is an unretained pointer to ZTLPBridge.shared.
private func disconnectCallbackFn(userData: UnsafeMutableRawPointer?,
                                   session: OpaquePointer?,
                                   reason: Int32) {
    ZTLPBridge.shared.eventSubject.send(.disconnected(reason: reason))
}

/// ACK send callback — invoked from Rust with pre-encrypted ZTLP packet bytes.
///
/// Creates or reuses an NWConnection (UDP) to send the bytes on a dedicated
/// dispatch queue, completely separate from Rust's tokio socket.
private func ackSendCallback(userData: UnsafeMutableRawPointer?,
                              dataPtr: UnsafePointer<UInt8>?,
                              dataLen: Int,
                              destAddr: UnsafePointer<CChar>?) {
    guard let dataPtr = dataPtr, dataLen > 0, let destAddr = destAddr else { return }
    let data = Data(bytes: dataPtr, count: dataLen)
    let addrStr = String(cString: destAddr)
    
    let bridge = ZTLPBridge.shared
    bridge.ackQueue.async {
        // Parse address
        let parts = addrStr.split(separator: ":")
        guard parts.count == 2,
              let port = NWEndpoint.Port(rawValue: UInt16(parts[1]) ?? 0) else { return }
        let host = NWEndpoint.Host(String(parts[0]))
        
        // Create connection on first use
        if bridge.ackConnection == nil || bridge.ackConnection?.state == .cancelled {
            let params = NWParameters.udp
            let conn = NWConnection(host: host, port: port, using: params)
            conn.stateUpdateHandler = { state in
                if case .failed(let err) = state {
                    print("[ZTLP-ACK] NWConnection failed: \(err)")
                    bridge.ackConnection = nil
                }
            }
            conn.start(queue: bridge.ackQueue)
            bridge.ackConnection = conn
        }
        
        // Send the pre-encrypted bytes — fire and forget
        bridge.ackConnection?.send(content: data, completion: .idempotent)
    }
}
