// EnrollmentViewModel.swift
// ZTLP
//
// Manages the enrollment flow: QR code scanning → token parsing →
// enrollment request → identity provisioning.
//
// Enrollment URI format: ztlp://enroll/<base64url-encoded-token>
// Query-param format: ztlp://enroll/?zone=foo&ns=1.2.3.4:23096&token=***

import Foundation
import UIKit
import Combine
import AVFoundation

/// Simplified state for the enrollment flow (used by EnrollmentView).
enum EnrollmentState: Equatable {
    case idle
    case tokenParsed
    case enrolling
    case success
    case error

    // Legacy compat — scanning maps to idle, success/tokenParsed carry data via VM properties
    static func == (lhs: EnrollmentState, rhs: EnrollmentState) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle),
             (.tokenParsed, .tokenParsed),
             (.enrolling, .enrolling),
             (.success, .success),
             (.error, .error):
            return true
        default:
            return false
        }
    }
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
    @Published private(set) var hasCameraPermission: Bool = false

    /// Error message (set when state == .error).
    @Published private(set) var errorMessage: String?

    /// Parsed token fields for display in the review card.
    @Published private(set) var parsedZone: String?
    @Published private(set) var parsedRelay: String?
    @Published private(set) var parsedGateway: String?
    @Published private(set) var parsedNS: String?

    // MARK: - Internal

    private var currentToken: EnrollmentTokenInfo?

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let logger = TunnelLogger.shared

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        checkCameraPermission()
    }

    // MARK: - Camera Permission

    /// Request camera permission for QR scanning.
    func requestCameraPermission() {
        checkCameraPermission()
    }

    private func checkCameraPermission() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            hasCameraPermission = true
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                Task { @MainActor in
                    self?.hasCameraPermission = granted
                }
            }
        case .denied, .restricted:
            hasCameraPermission = false
        @unknown default:
            hasCameraPermission = false
        }
    }

    // MARK: - Token Parsing

    /// Parse a scanned QR code or manually entered URI.
    func parseToken(from code: String) {
        guard let tokenInfo = parseEnrollmentURI(code) else {
            errorMessage = "Invalid enrollment code. Expected ztlp://enroll/... URI."
            state = .error
            return
        }

        if tokenInfo.isExpired {
            logger.warn("Enrollment token expired", source: "Enrollment")
            errorMessage = "This enrollment token has expired."
            state = .error
            return
        }

        currentToken = tokenInfo
        parsedZone = tokenInfo.zone
        parsedNS = tokenInfo.nsAddress
        parsedRelay = tokenInfo.relayAddresses.first
        parsedGateway = tokenInfo.gatewayAddress

        logger.info("Parsed enrollment token for zone: \(tokenInfo.zone), NS: \(tokenInfo.nsAddress)", source: "Enrollment")
        state = .tokenParsed
    }

    // MARK: - Enrollment

    /// Execute the enrollment with the parsed token.
    func enroll() {
        guard let tokenInfo = currentToken else { return }

        state = .enrolling
        errorMessage = nil
        logger.info("Starting enrollment for zone: \(tokenInfo.zone)", source: "Enrollment")

        Task {
            do {
                // Nebula pivot (S1.5): in-process identity generation via
                // ZTLPBridge is gone. Enrollment currently only persists
                // the token-side config (zone / NS / relay / gateway) and
                // fetches the CA root. Identity provisioning now happens
                // on first NE tunnel start. Rewire end-to-end in a
                // follow-up.

                // Step 1: Update configuration with enrollment info
                configuration.zoneName = tokenInfo.zone
                configuration.nsServer = tokenInfo.nsAddress
                configuration.targetNodeId = tokenInfo.gatewayAddress ?? tokenInfo.nsAddress
                configuration.serviceName = "vault"

                if let relay = tokenInfo.relayAddresses.first {
                    configuration.relayAddress = relay
                    logger.info("Relay address: \(relay)", source: "Enrollment")
                }

                configuration.isEnrolled = true
                configuration.hasCompletedOnboarding = true

                logger.info(
                    "Enrollment config saved — Zone: \(tokenInfo.zone), NS: \(tokenInfo.nsAddress), Relay: \(tokenInfo.relayAddresses.first ?? "none"), Service: vault",
                    source: "Enrollment"
                )

                // Step 2: NS registration stub
                logger.warn("Enrollment stub: NS registration not yet implemented. Config saved locally only.", source: "Enrollment")

                // Step 3: Fetch and store the ZTLP CA root certificate
                logger.info("Fetching ZTLP CA root certificate from NS...", source: "Enrollment")
                let certService = CertificateService.shared
                let certFetched = await certService.fetchCARootCert(
                    nsServer: tokenInfo.nsAddress,
                    timeoutMs: 15000
                )
                if certFetched {
                    logger.info("CA root certificate fetched and stored", source: "Enrollment")
                } else {
                    logger.warn("Could not fetch CA cert during enrollment — can be done later from Settings", source: "Enrollment")
                }

                // Success!
                logger.info("Enrollment complete for zone: \(tokenInfo.zone)", source: "Enrollment")
                state = .success

                UINotificationFeedbackGenerator().notificationOccurred(.success)

            } catch {
                logger.error("Enrollment failed: \(error.localizedDescription)", source: "Enrollment")
                errorMessage = error.localizedDescription
                state = .error
                UINotificationFeedbackGenerator().notificationOccurred(.error)
            }
        }
    }

    /// Reset state to allow re-scanning.
    func reset() {
        state = .idle
        errorMessage = nil
        currentToken = nil
        parsedZone = nil
        parsedRelay = nil
        parsedGateway = nil
        parsedNS = nil
    }

    // MARK: - Token Parsing (Private)

    /// Parse a ztlp://enroll/ URI into an EnrollmentTokenInfo.
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
            gatewayAddress: params["gw"] ?? params["gateway"],
            expiresAt: expires,
            maxUses: Int(params["max_uses"] ?? "0") ?? 0,
            rawURI: rawURI
        )
    }

    /// Parse binary (base64url) enrollment token.
    private func parseBinaryEnrollment(_ b64: String, rawURI: String) -> EnrollmentTokenInfo? {
        var base64 = b64
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let padLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: padLength)

        guard let data = Data(base64Encoded: base64), data.count > 48 else {
            return nil
        }

        var pos = 0

        guard data.count > pos else { return nil }
        let version = data[pos]
        pos += 1
        guard version == 0x01 else { return nil }

        guard data.count > pos else { return nil }
        let flags = data[pos]
        pos += 1

        guard let zone = readLenPrefixedString(data, &pos) else { return nil }
        guard let nsAddr = readLenPrefixedString(data, &pos) else { return nil }

        guard data.count > pos else { return nil }
        let relayCount = Int(data[pos])
        pos += 1

        var relays: [String] = []
        for _ in 0..<relayCount {
            guard let relay = readLenPrefixedString(data, &pos) else { return nil }
            relays.append(relay)
        }

        var gateway: String?
        if flags & 0x01 != 0 {
            gateway = readLenPrefixedString(data, &pos)
        }

        guard data.count >= pos + 2 else { return nil }
        let maxUses = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1]))
        pos += 2

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
