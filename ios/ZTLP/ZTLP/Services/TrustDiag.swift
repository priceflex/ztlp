// TrustDiag.swift
// Asks iOS, in detail, whether it trusts the certificates the agent issues.
//
// A browser only says "not trusted". This evaluates the agent's own chains
// twice: once the way a browser does (the system's trust settings), and once
// with the device root pinned as the anchor. Trusted-when-pinned but not by
// the system means the root is not fully trusted on this device; failing even
// when pinned means iOS objects to the certificates themselves.

import Foundation
import Security

enum TrustDiag {
    /// One line per check, for the diagnostics log. Blocking; call off the
    /// main thread.
    static func report(container: URL) -> [String] {
        let state = SharedPaths.stateDirectory(in: container)
        let caDir = state.appendingPathComponent("ca", isDirectory: true)
        let certDir = state.appendingPathComponent("certs", isDirectory: true)

        guard let rootPEM = try? String(contentsOf: caDir.appendingPathComponent("root.pem"), encoding: .utf8),
              let root = certificates(inPEM: rootPEM).first else {
            return ["trust: no device root certificate found"]
        }
        var lines = ["trust: device root \"\(summary(root))\" sha256 \(fingerprint(root).prefix(16))…"]

        let files = ((try? FileManager.default.contentsOfDirectory(atPath: certDir.path)) ?? [])
            .filter { $0.hasSuffix(".pem") }.sorted().prefix(4)
        if files.isEmpty { lines.append("trust: no site certificates issued yet") }
        for file in files {
            guard let pem = try? String(contentsOf: certDir.appendingPathComponent(file), encoding: .utf8) else { continue }
            let chain = certificates(inPEM: pem)
            guard let leaf = chain.first else { continue }
            let name = summary(leaf)
            lines.append("trust \(name) (chain of \(chain.count)): system=\(evaluate(chain, host: name, anchor: nil)) | root pinned=\(evaluate(chain, host: name, anchor: root))")
        }
        return lines
    }

    /// Whether iOS, under its own trust settings (what every browser
    /// applies), accepts a site certificate issued by this device's CA. Nil
    /// when the agent has not issued any site certificate yet. No network.
    static func systemTrust(container: URL) -> Bool? {
        let certDir = SharedPaths.stateDirectory(in: container).appendingPathComponent("certs", isDirectory: true)
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: certDir.path)) ?? [])
            .filter { $0.hasSuffix(".pem") }.sorted()
        for file in files {
            guard let pem = try? String(contentsOf: certDir.appendingPathComponent(file), encoding: .utf8) else { continue }
            let chain = certificates(inPEM: pem)
            guard let leaf = chain.first else { continue }
            return evaluate(chain, host: summary(leaf), anchor: nil) == "trusted"
        }
        return nil
    }

    /// "trusted", or iOS's own reason for refusing.
    static func evaluate(_ chain: [SecCertificate], host: String, anchor: SecCertificate?) -> String {
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, host as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess, let trust else {
            return "could not build a trust object"
        }
        if let anchor {
            SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
        }
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) { return "trusted" }
        guard let error else { return "refused (no reason given)" }
        let ns = error as Error as NSError
        return "refused: \(ns.localizedDescription) [\(ns.domain) \(ns.code)]"
    }

    /// Every certificate in a PEM string, in order.
    static func certificates(inPEM pem: String) -> [SecCertificate] {
        let end = "-----END CERTIFICATE-----"
        var out: [SecCertificate] = []
        var rest = Substring(pem)
        while let endRange = rest.range(of: end) {
            let block = String(rest[rest.startIndex..<endRange.upperBound])
            if let der = CertificateEncoding.derFromPEM(block),
               let cert = SecCertificateCreateWithData(nil, der as CFData) {
                out.append(cert)
            }
            rest = rest[endRange.upperBound...]
        }
        return out
    }

    private static func summary(_ cert: SecCertificate) -> String {
        (SecCertificateCopySubjectSummary(cert) as String?) ?? "?"
    }

    private static func fingerprint(_ cert: SecCertificate) -> String {
        let der = SecCertificateCopyData(cert) as Data
        return CertificateEncoding.sha256Hex(der)
    }
}
