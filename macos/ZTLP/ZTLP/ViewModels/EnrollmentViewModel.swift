// EnrollmentViewModel.swift
// ZTLP macOS
//
// Manages the enrollment flow: token paste → parsing → enrollment request →
// identity provisioning.
// Adapted from iOS — no camera/QR scanning, paste-only on macOS.
//
// Enrollment URI format: ztlp://enroll/<base64url-encoded-token>
// Query-param format: ztlp://enroll/?zone=foo&ns=1.2.3.4:23096&token=abcd&expires=...

import Foundation
import AppKit
import Combine

/// State of the enrollment flow.
enum EnrollmentState: Equatable {
    case idle
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

    var isExpired: Bool {
        expiresAt < Date()
    }

    var expiryDescription: String {
        if isExpired { return "Expired" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return "Expires \(formatter.localizedString(for: expiresAt, relativeTo: Date()))"
    }
}

/// ViewModel for the enrollment flow (macOS: paste-only, no camera).
@MainActor
final class EnrollmentViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var state: EnrollmentState = .idle

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let bridge = ZTLPBridge.shared

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Entry

    /// Handle manual entry of an enrollment URI.
    func handleManualEntry(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let tokenInfo = parseEnrollmentURI(trimmed) else {
            state = .error("Invalid enrollment code. Expected ztlp://enroll/... URI.")
            return
        }

        if tokenInfo.isExpired {
            state = .error("This enrollment token has expired.")
            return
        }

        state = .tokenParsed(tokenInfo)
    }

    /// Paste from the macOS clipboard.
    func pasteFromClipboard() {
        guard let text = NSPasteboard.general.string(forType: .string) else {
            state = .error("No text found on clipboard.")
            return
        }
        handleManualEntry(text)
    }

    // MARK: - Enrollment

    func enroll() {
        guard case .tokenParsed(let tokenInfo) = state else { return }

        state = .enrolling

        Task {
            do {
                try bridge.initialize()

                // Try hardware identity first, fall back to software.
                // Hardware keys (Secure Enclave) can't be exported to file,
                // so if we need file-based persistence we use software keys.
                var identity: ZTLPIdentityHandle
                var isHardwareKey = false

                if configuration.useSecureEnclave {
                    do {
                        identity = try bridge.createHardwareIdentity(provider: 1)
                        isHardwareKey = true
                    } catch {
                        // Secure Enclave not available or failed — use software key
                        identity = try bridge.generateIdentity()
                    }
                } else {
                    identity = try bridge.generateIdentity()
                }

                guard identity.nodeId != nil else {
                    state = .error("Failed to get node ID from identity")
                    return
                }

                // Save identity to file (only for software keys —
                // hardware keys stay in Secure Enclave and are loaded via handle).
                if !isHardwareKey, let path = defaultIdentityPath() {
                    try identity.save(to: path)
                }

                configuration.zoneName = tokenInfo.zone
                configuration.targetNodeId = tokenInfo.nsAddress
                if let relay = tokenInfo.relayAddresses.first {
                    configuration.relayAddress = relay
                }
                configuration.isEnrolled = true
                configuration.hasCompletedOnboarding = true

                state = .success(zoneName: tokenInfo.zone)
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)

            } catch {
                state = .error("Enrollment failed: \(error.localizedDescription)")
                NSSound.beep()
            }
        }
    }

    func reset() {
        state = .idle
    }

    // MARK: - Token Parsing

    private func parseEnrollmentURI(_ uri: String) -> EnrollmentTokenInfo? {
        guard uri.hasPrefix("ztlp://enroll/") else { return nil }

        let payload = String(uri.dropFirst("ztlp://enroll/".count))

        if payload.contains("?") && payload.contains("zone=") {
            return parseQueryParamEnrollment(payload, rawURI: uri)
        }

        return parseBinaryEnrollment(payload, rawURI: uri)
    }

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

    private func readLenPrefixedString(_ data: Data, _ pos: inout Int) -> String? {
        guard data.count >= pos + 2 else { return nil }
        let len = Int(UInt16(data[pos]) << 8 | UInt16(data[pos + 1]))
        pos += 2
        guard data.count >= pos + len else { return nil }
        let str = String(data: data[pos..<(pos + len)], encoding: .utf8)
        pos += len
        return str
    }

    private func defaultIdentityPath() -> String? {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first
        guard let dir = appSupport?.appendingPathComponent("ZTLP") else { return nil }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("identity.json").path
    }
}
