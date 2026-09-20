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

    /// Task 6a: non-fatal warning surfaced when the app's own (server-
    /// confirmed) enrollment succeeds but the root daemon's enrollment
    /// fails or the daemon isn't reachable at all. `nil` = no warning.
    @Published private(set) var daemonEnrollWarning: String?

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

                // [CWE-287 hlv-ulgo] Before this fix, the GUI enrollment flow
                // treated the URI's zone/ns/relay fields as trusted the moment
                // local FORMAT validation passed (ero-sirt's hex-format +
                // expiry-window checks) — it never actually confirmed the
                // token with the issuing server. An attacker-crafted URI with
                // a syntactically-valid-looking token and attacker-controlled
                // ns/relay addresses would enroll successfully with NO server
                // ever having issued that token, silently redirecting all
                // future tunnel traffic through attacker infrastructure.
                //
                // The CLI's confirm_enrollment() (proto/src/bin/ztlp-cli.rs)
                // already does this correctly: POST token_id+node_id+pubkey
                // to the URI's callback endpoint and require a real 2xx HTTP
                // response before treating enrollment as legitimate. Mirror
                // that here — if the URI carries a callbackURL, it MUST
                // confirm before we persist isEnrolled=true. If the URI has
                // NO callback at all, we conservatively refuse to enroll
                // rather than silently trusting an unconfirmable token
                // (better to fail the enrollment than to accept one this
                // client can't verify).
                guard let callbackURLString = tokenInfo.callbackURL,
                      let callbackURL = URL(string: callbackURLString) else {
                    state = .error(
                        "This enrollment URI has no server callback — it cannot be verified and was rejected."
                    )
                    return
                }

                let nodeIdHex = identity.nodeId ?? ""
                let pubkeyHex = identity.publicKey ?? ""

                guard let tokenId = tokenInfo.tokenId else {
                    state = .error("Enrollment token is missing its identifier — rejected.")
                    return
                }

                var confirmRequest = URLRequest(url: callbackURL)
                confirmRequest.httpMethod = "POST"
                confirmRequest.setValue(
                    "application/x-www-form-urlencoded",
                    forHTTPHeaderField: "Content-Type"
                )
                let bodyString = "token_id=\(tokenId)&node_id=\(nodeIdHex)&name=\(hostNameForEnrollment())&pubkey_hex=\(pubkeyHex)"
                confirmRequest.httpBody = bodyString.data(using: .utf8)
                confirmRequest.timeoutInterval = 60

                let (_, response) = try await URLSession.shared.data(for: confirmRequest)

                guard let httpResponse = response as? HTTPURLResponse,
                      (200..<300).contains(httpResponse.statusCode) else {
                    let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                    state = .error(
                        "Server rejected enrollment confirmation (HTTP \(code)). Enrollment was not completed."
                    )
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

                // Task 6a: the app's own identity above is separate from the
                // root daemon's identity (F2/session-2) — the daemon is what
                // actually does DNS/VIP/TLS, so it needs its OWN enrollment
                // too. Best-effort: a daemon enroll failure does not fail
                // the (already server-confirmed) app enrollment above — the
                // user sees a distinct warning instead, and Settings > Service
                // still shows the daemon as not enrolled so it's discoverable.
                await enrollDaemon(tokenInfo)

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
        daemonEnrollWarning = nil
    }

    /// Task 6a: ask the root daemon to enroll ITSELF via its "enroll"
    /// control command (proto/src/agent/control.rs cmd_enroll), which
    /// re-execs the daemon's own binary through the exact
    /// `ztlp setup --token ... --yes` path already live-proven on
    /// MACLLM4 (plan §5.7) — so identity.json/config.toml/agent.toml land
    /// under the daemon's own HOME, not this app's.
    ///
    /// Best-effort: failures here are surfaced as a warning, not a fatal
    /// enrollment error — the app's own identity (verified via the
    /// server callback above) is still valid either way.
    private func enrollDaemon(_ tokenInfo: EnrollmentTokenInfo) async {
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
                daemonEnrollWarning = "Root service enrollment failed: \(response.error ?? "unknown error"). " +
                    "The app is enrolled, but DNS/HTTPS routing needs the service enrolled too — " +
                    "the Home checklist will show Identity as not enrolled; press Enroll again."
            } else if case .object(let o)? = response.data,
                      case .bool(false)? = o["tls_provisioned"] {
                // B4(b): the daemon enrolled but could not finish ca-init /
                // CA trust. HTTPS will warn in Safari until this is fixed.
                let why = o["tls_warning"]?.stringValue ?? "unknown"
                daemonEnrollWarning = "Enrolled, but HTTPS trust could not be set up automatically (\(why)). " +
                    "The Home checklist will keep showing Network as not ready."
            }
        } catch {
            // B4: the daemon now waits in unenrolled standby, so this should
            // only happen if the service really isn't installed/approved —
            // which the Home checklist gates before Enroll is offered.
            daemonEnrollWarning = "Could not reach the root service to finish DNS/HTTPS setup " +
                "(\(error.localizedDescription)). Check the Service row on the Home page, then press Enroll again."
        }
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

    private func defaultIdentityPath() -> String? {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first
        guard let dir = appSupport?.appendingPathComponent("ZTLP") else { return nil }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("identity.json").path
    }

    /// Percent-encode a value for use in an x-www-form-urlencoded POST body.
    /// [CWE-287 hlv-ulgo] The confirm-enrollment callback body is built via
    /// string interpolation — a hostname containing `&`/`=` would corrupt
    /// the encoded form body's field boundaries. NOTE: `.urlQueryAllowed`
    /// is NOT sufficient here — it explicitly PERMITS `&`, `=`, `+`, `;`
    /// (they're structurally legal in a URL query per RFC 3986), which
    /// would leave exactly the characters we need to escape untouched.
    /// Use a narrow allowed-set that excludes every x-www-form-urlencoded
    /// delimiter/reserved character instead.
    private func hostNameForEnrollment() -> String {
        let raw = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return raw.addingPercentEncoding(withAllowedCharacters: allowed) ?? "device"
    }
}
