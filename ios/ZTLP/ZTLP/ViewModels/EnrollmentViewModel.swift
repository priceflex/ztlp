// EnrollmentViewModel.swift
// ZTLP
//
// Manages the enrollment flow: QR code scanning → token parsing →
// enrollment request → identity provisioning.
//
// Enrollment URI format: ztlp://enroll/<base64url-encoded-token>
// Query-param format: ztlp://enroll/?zone=foo&ns=1.2.3.4:23096&token=abcd&expires=...

import Foundation
import Combine
import AVFoundation

/// State of the enrollment flow.
enum EnrollmentState: Equatable {
    case idle
    case scanning
    case tokenParsed(EnrollmentTokenInfo)
    case enrolling
    case success(zoneName: String)
    case error(String)
}

/// Parsed enrollment token information for display.
struct EnrollmentTokenInfo: Equatable {
    let zone: String
    let nsAddress: String
    let relayAddresses: [String]
    let gatewayAddress: String?
    let expiresAt: Date
    let maxUses: Int
    let rawURI: String

    /// Whether the token has expired.
    var isExpired: Bool {
        expiresAt < Date()
    }

    /// Human-readable expiry string.
    var expiryDescription: String {
        if isExpired { return "Expired" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return "Expires \(formatter.localizedString(for: expiresAt, relativeTo: Date()))"
    }
}

/// ViewModel for the enrollment/QR scanning flow.
@MainActor
final class EnrollmentViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var state: EnrollmentState = .idle

    /// Whether the camera is authorized for QR scanning.
    @Published private(set) var cameraAuthorized: Bool = false

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let bridge = ZTLPBridge.shared

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        checkCameraPermission()
    }

    // MARK: - Camera Permission

    /// Check and request camera permission for QR scanning.
    func checkCameraPermission() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            cameraAuthorized = true
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                Task { @MainActor in
                    self?.cameraAuthorized = granted
                }
            }
        case .denied, .restricted:
            cameraAuthorized = false
        @unknown default:
            cameraAuthorized = false
        }
    }

    // MARK: - Scanning

    /// Start the QR scanning mode.
    func startScanning() {
        state = .scanning
    }

    /// Cancel scanning and return to idle.
    func cancelScanning() {
        state = .idle
    }

    /// Handle a scanned QR code string.
    ///
    /// Parses the enrollment URI and transitions to the token-parsed state.
    func handleScannedCode(_ code: String) {
        guard let tokenInfo = parseEnrollmentURI(code) else {
            state = .error("Invalid enrollment code. Expected ztlp://enroll/... URI.")
            return
        }

        if tokenInfo.isExpired {
            state = .error("This enrollment token has expired.")
            return
        }

        state = .tokenParsed(tokenInfo)
    }

    /// Handle manual entry of an enrollment URI.
    func handleManualEntry(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        handleScannedCode(trimmed)
    }

    // MARK: - Enrollment

    /// Execute the enrollment with the parsed token.
    func enroll() {
        guard case .tokenParsed(let tokenInfo) = state else { return }

        state = .enrolling

        Task {
            do {
                // Step 1: Initialize the ZTLP bridge if needed
                try bridge.initialize()

                // Step 2: Generate or load identity
                let identity: ZTLPIdentityHandle
                if configuration.useSecureEnclave && SecureEnclaveService.shared.isAvailable {
                    identity = try bridge.createHardwareIdentity(provider: 1)
                } else {
                    identity = try bridge.generateIdentity()
                }

                guard let nodeId = identity.nodeId else {
                    state = .error("Failed to get node ID from identity")
                    return
                }

                // Step 3: Save identity to keychain
                // The identity JSON is saved to the shared app group container
                // so the Network Extension can load it.
                let identityPath = defaultIdentityPath()
                if let path = identityPath {
                    try identity.save(to: path)
                }

                // Step 4: Update configuration with enrollment info
                configuration.zoneName = tokenInfo.zone
                configuration.targetNodeId = tokenInfo.nsAddress // NS is the first target
                if let relay = tokenInfo.relayAddresses.first {
                    configuration.relayAddress = relay
                }
                configuration.isEnrolled = true
                configuration.hasCompletedOnboarding = true

                // Step 5: Create client and enroll with NS
                // In a full implementation, this would:
                //   1. Connect to the NS at tokenInfo.nsAddress
                //   2. Present the enrollment token + our public key
                //   3. NS validates the token and registers our node
                //   4. NS returns our zone assignment + peer addresses

                // For now, we store the config and succeed
                state = .success(zoneName: tokenInfo.zone)

                // Haptic feedback
                UINotificationFeedbackGenerator().notificationOccurred(.success)

            } catch {
                state = .error("Enrollment failed: \(error.localizedDescription)")
                UINotificationFeedbackGenerator().notificationOccurred(.error)
            }
        }
    }

    /// Reset state to allow re-scanning.
    func reset() {
        state = .idle
    }

    // MARK: - Token Parsing

    /// Parse a ztlp://enroll/ URI into an EnrollmentTokenInfo.
    ///
    /// Supports two formats:
    ///   1. Binary: ztlp://enroll/<base64url>
    ///   2. Query-param: ztlp://enroll/?zone=foo&ns=1.2.3.4:23096&relay=...
    private func parseEnrollmentURI(_ uri: String) -> EnrollmentTokenInfo? {
        guard uri.hasPrefix("ztlp://enroll/") else { return nil }

        let payload = String(uri.dropFirst("ztlp://enroll/".count))

        // Query-param format
        if payload.contains("?") && payload.contains("zone=") {
            return parseQueryParamEnrollment(payload, rawURI: uri)
        }

        // Binary format (base64url)
        return parseBinaryEnrollment(payload, rawURI: uri)
    }

    /// Parse query-param enrollment URI.
    private func parseQueryParamEnrollment(_ payload: String, rawURI: String) -> EnrollmentTokenInfo? {
        guard let queryStart = payload.firstIndex(of: "?") else { return nil }
        let queryString = String(payload[payload.index(after: queryStart)...])

        var params: [String: String] = [:]
        for pair in queryString.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            params[String(parts[0])] = String(parts[1])
                .removingPercentEncoding ?? String(parts[1])
        }

        guard let zone = params["zone"],
              let ns = params["ns"] else { return nil }

        let expires: Date
        if let expiresStr = params["expires"], let ts = TimeInterval(expiresStr) {
            expires = Date(timeIntervalSince1970: ts)
        } else {
            expires = Date.distantFuture
        }

        var relays: [String] = []
        if let relay = params["relay"] {
            relays = relay.split(separator: ",").map(String.init)
        }

        return EnrollmentTokenInfo(
            zone: zone,
            nsAddress: ns,
            relayAddresses: relays,
            gatewayAddress: params["gateway"],
            expiresAt: expires,
            maxUses: Int(params["max_uses"] ?? "0") ?? 0,
            rawURI: rawURI
        )
    }

    /// Parse binary (base64url) enrollment token.
    private func parseBinaryEnrollment(_ b64: String, rawURI: String) -> EnrollmentTokenInfo? {
        // Decode base64url
        var base64 = b64
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let padLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: padLength)

        guard let data = Data(base64Encoded: base64), data.count > 48 else {
            return nil
        }

        // Parse the binary wire format (see enrollment.rs for the spec)
        var pos = 0

        // Version (1 byte)
        guard data.count > pos else { return nil }
        let version = data[pos]
        pos += 1
        guard version == 0x01 else { return nil }

        // Flags (1 byte)
        guard data.count > pos else { return nil }
        let flags = data[pos]
        pos += 1

        // Zone (length-prefixed string)
        guard let zone = readLenPrefixedString(data, &pos) else { return nil }

        // NS address (length-prefixed string)
        guard let nsAddr = readLenPrefixedString(data, &pos) else { return nil }

        // Relay addresses
        guard data.count > pos else { return nil }
        let relayCount = Int(data[pos])
        pos += 1

        var relays: [String] = []
        for _ in 0..<relayCount {
            guard let relay = readLenPrefixedString(data, &pos) else { return nil }
            relays.append(relay)
        }

        // Gateway (optional)
        var gateway: String?
        if flags & 0x01 != 0 {
            gateway = readLenPrefixedString(data, &pos)
        }

        // Max uses (2 bytes, big-endian)
        guard data.count >= pos + 2 else { return nil }
        let maxUses = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1]))
        pos += 2

        // Expires at (8 bytes, big-endian)
        guard data.count >= pos + 8 else { return nil }
        var expiresRaw: UInt64 = 0
        for i in 0..<8 {
            expiresRaw = (expiresRaw << 8) | UInt64(data[pos + i])
        }
        pos += 8

        return EnrollmentTokenInfo(
            zone: zone,
            nsAddress: nsAddr,
            relayAddresses: relays,
            gatewayAddress: gateway,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(expiresRaw)),
            maxUses: maxUses,
            rawURI: rawURI
        )
    }

    /// Read a length-prefixed string (2-byte big-endian length + UTF-8 data).
    private func readLenPrefixedString(_ data: Data, _ pos: inout Int) -> String? {
        guard data.count >= pos + 2 else { return nil }
        let len = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1]))
        pos += 2
        guard data.count >= pos + len else { return nil }
        let str = String(data: data[pos..<(pos + len)], encoding: .utf8)
        pos += len
        return str
    }

    /// Default identity file path in the shared app group container.
    private func defaultIdentityPath() -> String? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) else { return nil }
        return containerURL.appendingPathComponent("identity.json").path
    }
}
