// ZTLPBridge.swift
// ZTLP macOS
//
// Swift wrapper around the ZTLP C FFI (ztlp.h).
// Adapted from iOS version — removes iOS-specific bits (UIKit).

import Foundation
import Combine

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
final class ZTLPBridge {

    static let shared = ZTLPBridge()

    let eventSubject = PassthroughSubject<ZTLPConnectionEvent, Never>()

    private var client: OpaquePointer?
    private var currentIdentity: ZTLPIdentityHandle?
    private let clientLock = DispatchQueue(label: "com.ztlp.bridge.client", qos: .userInitiated)
    private var isInitialized = false

    private(set) var bytesSent: UInt64 = 0
    private(set) var bytesReceived: UInt64 = 0

    private init() {}

    // MARK: - Lifecycle

    func initialize() throws {
        guard !isInitialized else { return }
        let result = ztlp_init()
        if let error = ZTLPError.from(code: result) { throw error }
        isInitialized = true
    }

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

    // MARK: - Client

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
            if let old = self.client {
                ztlp_client_free(old)
            }
            self.client = c
        }
        try setupCallbacks()
    }

    func destroyClient() {
        clientLock.sync {
            if let c = self.client {
                ztlp_client_free(c)
                self.client = nil
            }
            self.bytesSent = 0
            self.bytesReceived = 0
        }
    }

    // MARK: - Connection

    func connect(target: String, config: ZTLPConfigHandle? = nil) async throws {
        try ensureInitialized()
        guard let c = clientLock.sync(execute: { self.client }) else {
            throw ZTLPError.notConnected
        }

        return try await withCheckedThrowingContinuation { continuation in
            let context = Unmanaged.passRetained(
                ContinuationBox(continuation: continuation)
            ).toOpaque()

            let result = target.withCString { cTarget in
                ztlp_connect(c, cTarget, config?.pointer, connectCallback, context)
            }

            if let error = ZTLPError.from(code: result) {
                let _ = Unmanaged<ContinuationBox>.fromOpaque(context).takeRetainedValue()
                continuation.resume(throwing: error)
            }
        }
    }

    func disconnect() {
        destroyClient()
        eventSubject.send(.disconnected(reason: 0))
    }

    // MARK: - Data Transfer

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

    // MARK: - NS Resolution

    /// Resolve a ZTLP service name via NS, returning the gateway endpoint address.
    /// - Parameters:
    ///   - serviceName: The ZTLP-NS name (e.g., "beta.techrockstars.ztlp")
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

    /// Start local DNS resolver for *.ztlp domains.
    func dnsStart(listenAddr: String = "127.0.55.53:53") throws {
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

    /// Check if networking (loopback aliases, pf, DNS resolver) is already configured.
    func isNetworkingConfigured(vips: [String]) -> Bool {
        // Check DNS resolver file
        guard FileManager.default.fileExists(atPath: "/etc/resolver/ztlp") else { return false }
        // Check pf anchor file
        guard FileManager.default.fileExists(atPath: "/etc/pf.anchors/ztlp") else { return false }
        // Check loopback aliases — run ifconfig and look for our VIPs
        guard let ifconfigOutput = runShell("/sbin/ifconfig lo0") else { return false }
        for vip in vips {
            if !ifconfigOutput.contains(vip) { return false }
        }
        return true
    }

    /// Run a shell command and return stdout, or nil on failure.
    private func runShell(_ command: String) -> String? {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", command]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }

    /// Set up loopback aliases + pf redirect + DNS resolver.
    /// Skips the admin password prompt if everything is already configured.
    func setupNetworking(vips: [String]) throws {
        // Skip if already set up (survives across app restarts until reboot)
        if isNetworkingConfigured(vips: vips) {
            return
        }

        // Write a temp shell script to avoid AppleScript escaping hell
        let tmpScript = "/tmp/ztlp_setup.sh"
        var script = "#!/bin/bash\nset -e\n"

        // Add loopback aliases
        for vip in vips {
            script += "ifconfig lo0 alias \(vip) up\n"
        }

        // pf rules: redirect port 80/443 on VIPs to high ports
        let serviceVips = vips.filter { $0 != "127.0.55.53" }
        script += "cat > /etc/pf.anchors/ztlp << 'PFEOF'\n"
        for vip in serviceVips {
            script += "rdr pass on lo0 proto tcp from any to \(vip) port 80 -> \(vip) port 8080\n"
            script += "rdr pass on lo0 proto tcp from any to \(vip) port 443 -> \(vip) port 8443\n"
        }
        script += "PFEOF\n"

        // Load pf anchor — insert BEFORE dummynet/filter anchors (pf requires rdr before filter)
        script += "if ! grep -q 'rdr-anchor \"ztlp\"' /etc/pf.conf; then\n"
        script += "  sed -i '' '/^dummynet-anchor/i\\\n"
        script += "rdr-anchor \"ztlp\"\\\n"
        script += "load anchor \"ztlp\" from \"/etc/pf.anchors/ztlp\"\n"
        script += "' /etc/pf.conf\n"
        script += "  # Fallback: if no dummynet-anchor line, insert before anchor \"com.apple\"\n"
        script += "  if ! grep -q 'rdr-anchor \"ztlp\"' /etc/pf.conf; then\n"
        script += "    sed -i '' '/^anchor/i\\\n"
        script += "rdr-anchor \"ztlp\"\\\n"
        script += "load anchor \"ztlp\" from \"/etc/pf.anchors/ztlp\"\n"
        script += "' /etc/pf.conf\n"
        script += "  fi\n"
        script += "fi\n"
        script += "pfctl -f /etc/pf.conf 2>/dev/null || true\n"
        script += "pfctl -e 2>/dev/null || true\n"

        // DNS resolver
        script += "mkdir -p /etc/resolver\n"
        script += "cat > /etc/resolver/ztlp << 'DNSEOF'\n"
        script += "nameserver 127.0.55.53\n"
        script += "port 5354\n"
        script += "DNSEOF\n"

        // Install LaunchDaemon so setup persists across reboots (one-time)
        script += installLaunchDaemonScript(vips: vips)

        // Write the script and make executable
        try script.write(toFile: tmpScript, atomically: true, encoding: .utf8)

        // Run with admin privileges via AppleScript
        let asSource = "do shell script \"/bin/bash \(tmpScript)\" with administrator privileges"
        let appleScript = NSAppleScript(source: asSource)
        var asError: NSDictionary?
        appleScript?.executeAndReturnError(&asError)

        // Clean up temp script
        try? FileManager.default.removeItem(atPath: tmpScript)

        if let asError = asError {
            throw ZTLPError.connectionError("Failed to setup networking: \(asError)")
        }
    }

    /// Generate shell commands to install a LaunchDaemon that re-applies networking on boot.
    private func installLaunchDaemonScript(vips: [String]) -> String {
        let serviceVips = vips.filter { $0 != "127.0.55.53" }
        let daemonId = "com.ztlp.networking"
        let scriptPath = "/usr/local/bin/ztlp-networking-setup.sh"
        let plistPath = "/Library/LaunchDaemons/\(daemonId).plist"

        // Only install if not already present
        var s = "if [ ! -f \(plistPath) ]; then\n"

        // Write the boot script
        s += "cat > \(scriptPath) << 'BOOTEOF'\n"
        s += "#!/bin/bash\n"
        s += "# ZTLP networking setup — runs at boot via LaunchDaemon\n"
        for vip in vips {
            s += "/sbin/ifconfig lo0 alias \(vip) up\n"
        }
        s += "cat > /etc/pf.anchors/ztlp << 'PF'\n"
        for vip in serviceVips {
            s += "rdr pass on lo0 proto tcp from any to \(vip) port 80 -> \(vip) port 8080\n"
            s += "rdr pass on lo0 proto tcp from any to \(vip) port 443 -> \(vip) port 8443\n"
        }
        s += "PF\n"
        // Ensure anchor is in pf.conf before dummynet/filter rules
        s += "if ! grep -q 'rdr-anchor \"ztlp\"' /etc/pf.conf; then\n"
        s += "  sed -i '' '/^dummynet-anchor/i\\\\\n"
        s += "rdr-anchor \"ztlp\"\\\\\n"
        s += "load anchor \"ztlp\" from \"/etc/pf.anchors/ztlp\"\n"
        s += "' /etc/pf.conf\n"
        s += "fi\n"
        s += "/sbin/pfctl -f /etc/pf.conf 2>/dev/null || true\n"
        s += "/sbin/pfctl -e 2>/dev/null || true\n"
        s += "mkdir -p /etc/resolver\n"
        s += "cat > /etc/resolver/ztlp << 'DNS'\n"
        s += "nameserver 127.0.55.53\n"
        s += "port 5354\n"
        s += "DNS\n"
        s += "BOOTEOF\n"
        s += "chmod 755 \(scriptPath)\n"

        // Write the LaunchDaemon plist
        s += "cat > \(plistPath) << 'PLISTEOF'\n"
        s += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        s += "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        s += "<plist version=\"1.0\">\n"
        s += "<dict>\n"
        s += "  <key>Label</key>\n"
        s += "  <string>\(daemonId)</string>\n"
        s += "  <key>ProgramArguments</key>\n"
        s += "  <array>\n"
        s += "    <string>/bin/bash</string>\n"
        s += "    <string>\(scriptPath)</string>\n"
        s += "  </array>\n"
        s += "  <key>RunAtLoad</key>\n"
        s += "  <true/>\n"
        s += "</dict>\n"
        s += "</plist>\n"
        s += "PLISTEOF\n"
        s += "chmod 644 \(plistPath)\n"
        s += "launchctl load \(plistPath) 2>/dev/null || true\n"
        s += "fi\n"

        return s
    }

    /// Remove loopback aliases + pf rules + DNS resolver + LaunchDaemon.
    func teardownNetworking(vips: [String]) {
        let tmpScript = "/tmp/ztlp_teardown.sh"
        var script = "#!/bin/bash\n"
        for vip in vips {
            script += "ifconfig lo0 -alias \(vip) 2>/dev/null || true\n"
        }
        script += "rm -f /etc/pf.anchors/ztlp /etc/resolver/ztlp\n"
        script += "sed -i \'\' \'/ztlp/d\' /etc/pf.conf 2>/dev/null || true\n"
        script += "pfctl -f /etc/pf.conf 2>/dev/null || true\n"
        // Remove LaunchDaemon
        script += "launchctl unload /Library/LaunchDaemons/com.ztlp.networking.plist 2>/dev/null || true\n"
        script += "rm -f /Library/LaunchDaemons/com.ztlp.networking.plist /usr/local/bin/ztlp-networking-setup.sh\n"

        try? script.write(toFile: tmpScript, atomically: true, encoding: .utf8)
        let asSource = "do shell script \"/bin/bash \(tmpScript)\" with administrator privileges"
        let appleScript = NSAppleScript(source: asSource)
        var asError: NSDictionary?
        appleScript?.executeAndReturnError(&asError)
        try? FileManager.default.removeItem(atPath: tmpScript)
    }

        // MARK: - Callbacks

    private func setupCallbacks() throws {
        guard let c = clientLock.sync(execute: { self.client }) else { return }

        let selfPtr = Unmanaged.passUnretained(self).toOpaque()

        let recvResult = ztlp_set_recv_callback(c, recvCallback, selfPtr)
        if let error = ZTLPError.from(code: recvResult) { throw error }

        let disconnectResult = ztlp_set_disconnect_callback(c, disconnectCallbackFn, selfPtr)
        if let error = ZTLPError.from(code: disconnectResult) { throw error }
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

    func resetCounters() {
        bytesSent = 0
        bytesReceived = 0
    }

    func addBytesReceived(_ count: UInt64) {
        bytesReceived += count
    }
}

// MARK: - Continuation Box

private final class ContinuationBox {
    let continuation: CheckedContinuation<Void, Error>
    init(continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }
}

// MARK: - C Callback Trampolines

private func connectCallback(userData: UnsafeMutableRawPointer?,
                              resultCode: Int32,
                              peerAddr: UnsafePointer<CChar>?) {
    guard let userData = userData else { return }
    let box_ = Unmanaged<ContinuationBox>.fromOpaque(userData).takeRetainedValue()

    if resultCode == 0 {
        let addr = peerAddr.map { String(cString: $0) } ?? "unknown"
        ZTLPBridge.shared.eventSubject.send(.connected(peerAddress: addr))
        box_.continuation.resume()
    } else {
        let error = ZTLPError.from(code: resultCode) ?? .unknownError(resultCode, "connection failed")
        box_.continuation.resume(throwing: error)
    }
}

private func recvCallback(userData: UnsafeMutableRawPointer?,
                           dataPtr: UnsafePointer<UInt8>?,
                           dataLen: Int,
                           session: OpaquePointer?) {
    guard let dataPtr = dataPtr, dataLen > 0 else { return }
    let data = Data(bytes: dataPtr, count: dataLen)
    ZTLPBridge.shared.addBytesReceived(UInt64(dataLen))
    ZTLPBridge.shared.eventSubject.send(.dataReceived(data))
}

private func disconnectCallbackFn(userData: UnsafeMutableRawPointer?,
                                   session: OpaquePointer?,
                                   reason: Int32) {
    ZTLPBridge.shared.eventSubject.send(.disconnected(reason: reason))
}
