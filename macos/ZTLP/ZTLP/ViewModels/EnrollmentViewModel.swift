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
    /// The opaque token identifier from the enrollment URI.
    let tokenId: String?
    /// The server callback URL for enrollment confirmation.
    let callbackURL: String?

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

    /// Task 6a / plan §4a: optional relay CLIENT_ROUTE HMAC secret ("group
    /// password" the prod relay checks). Option B (fallback, zero protocol
    /// change) — a second field the user pastes from their admin, sent to
    /// the daemon's "enroll" control command and written into the
    /// daemon's own agent.toml exactly as `ztlp setup --relay-secret`
    /// would. NOT part of the enrollment token itself (see §4a option A,
    /// not implemented — Task 5.9 was cancelled by Steven 2026-09-19).
    @Published var relaySecret: String = ""

    /// Non-fatal warning after a successful daemon enrollment (e.g. the
    /// daemon could not create its HTTPS certificate). `nil` = no warning.
    @Published private(set) var daemonEnrollWarning: String?

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration

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
            // ONE enrollment, ONE identity (2026-09-20). Demo/Launch tokens are
            // single-use (max_uses=1). The previous flow enrolled the app's
            // OWN user-level identity first (consuming the token via the
            // server callback) and then asked the root daemon to enroll with
            // the same token — NS answered 0x08 0x02 "token has been used
            // up". The daemon IS the device identity (DNS/VIP/TLS all hang
            // off it, and Home reads everything from it), so the token goes
            // straight to the daemon. Server-side verification (the
            // [CWE-287] callback confirm) is done by the daemon's `ztlp
            // setup`, which refuses to persist without a real 2xx.
            guard tokenInfo.callbackURL != nil else {
                state = .error(
                    "This enrollment URI has no server callback — it cannot be verified and was rejected."
                )
                return
            }
            guard tokenInfo.tokenId != nil else {
                state = .error("Enrollment token is missing its identifier — rejected.")
                return
            }

            let result = await enrollDaemon(tokenInfo)
            switch result {
            case .failure(let message):
                state = .error(message)
                NSSound.beep()
            case .success:
                // Mirror the zone into app config so the menu bar / header can
                // label it before the first daemon poll lands.
                configuration.zoneName = tokenInfo.zone
                configuration.targetNodeId = tokenInfo.nsAddress
                if let relay = tokenInfo.relayAddresses.first {
                    configuration.relayAddress = relay
                }
                configuration.isEnrolled = true
                configuration.hasCompletedOnboarding = true
                state = .success(zoneName: tokenInfo.zone)
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
            }
        }
    }

    func reset() {
        state = .idle
        daemonEnrollWarning = nil
    }

    enum DaemonEnrollResult { case success, failure(String) }

    /// Ask the root daemon to enroll ITSELF via its "enroll" control command
    /// (proto/src/agent/control.rs cmd_enroll), which re-execs the daemon's
    /// binary through `ztlp setup --token ... --yes` so identity.json /
    /// config.toml / agent.toml land under the daemon's HOME. This is THE
    /// enrollment (see enroll()).
    private func enrollDaemon(_ tokenInfo: EnrollmentTokenInfo) async -> DaemonEnrollResult {
        do {
            let response = try await AgentControlClient.send(
                cmd: "enroll",
                name: hostNameForEnrollment(),
                enrollmentURI: tokenInfo.rawURI,
                relaySecret: relaySecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? nil
                    : relaySecret.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            if !response.ok {
                return .failure(Self.userFacingEnrollError(response.error ?? "unknown error"))
            }
            if case .object(let o)? = response.data,
               case .bool(false)? = o["tls_provisioned"] {
                // The daemon enrolled but could not make its CA. Home row 3
                // shows the state; this is a warning, not a failure.
                let why = o["tls_warning"]?.stringValue ?? "unknown"
                daemonEnrollWarning = "Enrolled, but the HTTPS certificate could not be created automatically (\(why)). " +
                    "The Home checklist will keep showing Network as not ready."
            }
            return .success
        } catch {
            // B4: the daemon waits in unenrolled standby, so this only happens
            // if the service really isn't installed/approved — which the Home
            // checklist gates before Enroll is offered.
            return .failure("Could not reach the ZTLP service to enroll (\(error.localizedDescription)). " +
                "Check the Service row on the Home page, then press Enroll again.")
        }
    }

    /// The daemon returns "<reason>\n\n--- full output ---\n<wizard transcript>".
    /// Show the reason; keep the transcript out of the alert.
    nonisolated static func userFacingEnrollError(_ raw: String) -> String {
        let reason = raw.components(separatedBy: "\n\n--- full output ---").first ?? raw
        var r = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        if r.hasPrefix("enrollment failed (exit") , let colon = r.range(of: "): ") {
            r = String(r[colon.upperBound...])
        }
        if r.lowercased().contains("used up") || r.lowercased().contains("max uses") {
            r += " — ask your administrator for a new enrollment link."
        }
        return r
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

    /// Parse query-param enrollment URI.
    ///
    /// Security requirements (CTF finding ero-sirt):
    ///   - `token` is mandatory — prevents crafting ad-hoc URIs
    ///   - `expires` is mandatory — no implicit "never expires" fallback
    ///   - `expires` must be within a sane range (not in the past,
    ///     not more than 30 days out) to reject tampered timestamps.
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

        // Require token parameter — prevents ad-hoc URI construction
        guard let tokenId = params["token"], !tokenId.isEmpty else { return nil }

        // Validate token format: hex string, 8–64 chars
        guard tokenId.allSatisfy({ $0.isHexDigit }),
              (8...64).contains(tokenId.count) else { return nil }

        // Require expires parameter — no implicit "never expires"
        guard let expiresStr = params["expires"],
              let ts = TimeInterval(expiresStr) else { return nil }

        let expires: Date = Date(timeIntervalSince1970: ts)

        // Reject obviously invalid expiry: in the past or > 30 days out
        let maxAge: TimeInterval = 30 * 24 * 3600  // 30 days
        guard ts > 0,
              expires > Date().addingTimeInterval(-60),    // within 60 s of now
              expires < Date().addingTimeInterval(maxAge) else { return nil }

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
            rawURI: rawURI,
            tokenId: tokenId,
            callbackURL: params["callback"]
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
            rawURI: rawURI,
            tokenId: nil,
            callbackURL: nil
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

    /// Device name sent to the daemon's `enroll` command (JSON, so no form
    /// encoding needed). `ztlp setup` registers `<name>.<zone>` in NS, so keep
    /// it a DNS-friendly label: lowercase, [a-z0-9-], no apostrophes/spaces.
    /// "Steven's MacBook Pro (2)" -> "stevens-macbook-pro-2".
    private func hostNameForEnrollment() -> String {
        Self.dnsLabel(from: Host.current().localizedName ?? ProcessInfo.processInfo.hostName)
    }

    nonisolated static func dnsLabel(from raw: String) -> String {
        let folded = raw.folding(options: [.diacriticInsensitive, .caseInsensitive], locale: .current).lowercased()
        var out = ""
        var lastDash = false
        for ch in folded.unicodeScalars {
            if CharacterSet.alphanumerics.contains(ch) && ch.isASCII {
                out.unicodeScalars.append(ch); lastDash = false
            } else if ch == "'" || ch == "\u{2019}" {
                continue // "Steven's" -> "stevens"
            } else if !lastDash && !out.isEmpty {
                out += "-"; lastDash = true
            }
        }
        while out.hasSuffix("-") { out.removeLast() }
        if out.count > 63 { out = String(out.prefix(63)) }
        return out.isEmpty ? "mac" : out
    }
}
