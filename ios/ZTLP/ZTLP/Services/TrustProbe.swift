// TrustProbe.swift
// Decides whether this device trusts the agent's HTTPS certificates.

import Foundation

enum TrustProbe {
    /// The agent's health name. The Rust agent answers HTTPS on port 8443
    /// for this name with a leaf from the device-local CA. Change it here
    /// only.
    static func healthURL() -> URL? {
        URL(string: "https://ztlp-health.ztlp:8443/")
    }

    /// One HTTPS request with the system's normal trust evaluation. Any HTTP
    /// answer means the TLS handshake validated, so the CA is trusted.
    static func run() async -> TrustState {
        guard let url = healthURL() else { return .unreachable }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 6
        config.timeoutIntervalForResource = 8
        config.waitsForConnectivity = false
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        do {
            _ = try await session.data(from: url)
            note("trust probe: trusted")
            return .trusted
        } catch {
            let ns = error as NSError
            note("trust probe: \(classify(error)) [\(ns.domain) \(ns.code)] \(ns.localizedDescription)")
            return classify(error)
        }
    }

    /// Record the outcome in the diagnostics log, once per change.
    private static let lastNote = NoteBox()
    private static func note(_ text: String) {
        guard lastNote.replace(with: text) else { return }
        SharedPaths.appendDiag([text], who: "app")
    }

    private final class NoteBox: @unchecked Sendable {
        private let lock = NSLock()
        private var last = ""
        /// True if the text differs from the previous one.
        func replace(with text: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard text != last else { return false }
            last = text
            return true
        }
    }

    /// Certificate errors mean "reached the agent, not trusted yet". Anything
    /// else (no DNS answer, refused, timed out) says nothing about trust.
    static func classify(_ error: Error) -> TrustState {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain else { return .unreachable }
        switch nsError.code {
        case NSURLErrorServerCertificateUntrusted,
             NSURLErrorServerCertificateHasUnknownRoot,
             NSURLErrorServerCertificateHasBadDate,
             NSURLErrorServerCertificateNotYetValid,
             NSURLErrorClientCertificateRejected,
             NSURLErrorClientCertificateRequired:
            return .notTrusted
        default:
            return .unreachable
        }
    }
}
