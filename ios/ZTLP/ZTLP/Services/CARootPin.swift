// CARootPin.swift
// ZTLP (main app target)
//
// Trust-On-First-Use (TOFU) fingerprint pinning for the ZTLP CA root
// certificate, addressing SAST finding sjy-yrjl: fetchCARootCert
// previously accepted ANY non-empty DER bytes returned by
// ztlp_ns_fetch_ca_root and persisted them as the trust root with zero
// validation — a MITM-controlled NS server could hand the client its
// own CA and have it trusted for every future TLS certificate
// validation within the ZTLP network.
//
// Same design as GatewayKeyPin (rhf-phvo) for the gateway's static
// Noise key, but this lives in the main app target (not the Network
// Extension), so it can use the existing KeychainService.shared
// directly instead of needing its own self-contained Keychain helper.

import Foundation

enum CARootPin {
    /// Verify the fetched CA root's SHA-256 fingerprint against a
    /// pinned value for this NS server, or pin it if this is the
    /// first-ever successful fetch from that server.
    ///
    /// - Returns: `nil` if the fetch should be accepted (first fetch,
    ///   now pinned; or fingerprint matches the existing pin). A
    ///   human-readable error string if the fingerprint does NOT
    ///   match the pinned value — the fetched CA MUST be rejected in
    ///   that case.
    static func verifyOrPin(nsServer: String, fingerprintHex: String) -> String? {
        let key = pinKey(for: nsServer)

        if let pinnedHex = try? KeychainService.shared.load(forKey: key),
           let pinnedString = String(data: pinnedHex, encoding: .utf8) {
            if pinnedString.lowercased() == fingerprintHex.lowercased() {
                return nil
            }
            return "CA root fingerprint for \(nsServer) does not match the pinned value. " +
                "This may indicate a man-in-the-middle attack, or the NS server's CA was " +
                "legitimately rotated (in which case the pin must be reset by the user in Settings)."
        }

        // First successful fetch from this NS server — pin it now.
        if let data = fingerprintHex.data(using: .utf8) {
            try? KeychainService.shared.save(data: data, forKey: key)
        }
        return nil
    }

    /// Explicitly clear a pin (e.g. exposed via a "Reset CA Pin" Settings
    /// action for legitimate CA rotation scenarios).
    static func resetPin(nsServer: String) {
        try? KeychainService.shared.delete(forKey: pinKey(for: nsServer))
    }

    private static func pinKey(for nsServer: String) -> String {
        "ca_root_pin_\(nsServer)"
    }
}
