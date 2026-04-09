// CertificateManager.swift
// ZTLP macOS
//
// Manages local CA trust for ZTLP service certificates.
//
// When ZTLP services use HTTPS (e.g., https://vault.techrockstars.ztlp),
// the VIP proxy terminates TLS locally using certs signed by a local CA.
// For browsers to trust these certs, the CA must be in the macOS Keychain.
//
// This class handles:
//   1. Detecting whether the CA is already trusted
//   2. Installing the CA via the native macOS admin password dialog
//   3. Generating service certs for registered VIP services

import Foundation
import AppKit

/// Status of the local certificate authority.
enum CATrustStatus: Equatable {
    case trusted
    case notTrusted
    case noCertificate
    case checking
    case installing
    case error(String)

    var label: String {
        switch self {
        case .trusted:       return "Trusted"
        case .notTrusted:    return "Not Trusted"
        case .noCertificate: return "No Certificate"
        case .checking:      return "Checking…"
        case .installing:    return "Installing…"
        case .error(let msg): return "Error: \(msg)"
        }
    }

    var isTrusted: Bool {
        self == .trusted
    }
}

/// Manages certificate trust for local TLS.
@MainActor
final class CertificateManager: ObservableObject {

    // MARK: - Published State

    @Published private(set) var trustStatus: CATrustStatus = .checking
    @Published private(set) var certCount: Int = 0

    // MARK: - Paths

    /// mkcert CA root certificate.
    private var caRootPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Application Support/mkcert/rootCA.pem"
    }

    /// ZTLP certs directory (per-service certs live here).
    private var certsDir: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.ztlp/certs"
    }

    // MARK: - Init

    init() {
        checkTrust()
    }

    // MARK: - Check Trust

    /// Check if the local CA is installed in the macOS System Keychain.
    func checkTrust() {
        trustStatus = .checking

        // First check if the CA cert file even exists
        guard FileManager.default.fileExists(atPath: caRootPath) else {
            trustStatus = .noCertificate
            countCerts()
            return
        }

        // Check if it's trusted by looking for it in the keychain
        DispatchQueue.global(qos: .userInitiated).async { [caRootPath] in
            let trusted = Self.isCATrustedInKeychain(caPath: caRootPath)
            DispatchQueue.main.async { [weak self] in
                self?.trustStatus = trusted ? .trusted : .notTrusted
                self?.countCerts()
            }
        }
    }

    // MARK: - Install CA

    /// Install the CA certificate into the macOS System Keychain.
    ///
    /// This triggers the native macOS admin password dialog via AppleScript.
    /// The user sees the standard lock icon prompt — no terminal needed.
    func installCA() {
        guard FileManager.default.fileExists(atPath: caRootPath) else {
            trustStatus = .noCertificate
            return
        }

        trustStatus = .installing

        let certPath = caRootPath

        DispatchQueue.global(qos: .userInitiated).async {
            let result = Self.installCAWithPrivileges(certPath: certPath)

            DispatchQueue.main.async { [weak self] in
                switch result {
                case .success:
                    self?.trustStatus = .trusted
                    NSHapticFeedbackManager.defaultPerformer.perform(
                        .levelChange, performanceTime: .default
                    )
                case .failure(let error):
                    if error.localizedDescription.contains("canceled") ||
                       error.localizedDescription.contains("-128") {
                        // User cancelled the password dialog
                        self?.trustStatus = .notTrusted
                    } else {
                        self?.trustStatus = .error(error.localizedDescription)
                    }
                }
            }
        }
    }

    // MARK: - Generate CA + Certs

    /// Generate the local CA and service certificates using mkcert.
    /// Called when no CA exists yet.
    func generateCA() {
        trustStatus = .installing

        DispatchQueue.global(qos: .userInitiated).async { [weak self, certsDir] in
            let mkcert = Self.findMkcert()
            guard let mkcertPath = mkcert else {
                DispatchQueue.main.async {
                    self?.trustStatus = .error("mkcert not found. Install with: brew install mkcert")
                }
                return
            }

            // Create certs directory
            try? FileManager.default.createDirectory(
                atPath: certsDir,
                withIntermediateDirectories: true
            )

            // Generate CA (non-privileged — just creates key files)
            let caResult = Self.runProcess(mkcertPath, args: ["-install"])
            // mkcert -install will fail on the trust part (needs admin), but
            // creates the CA files. We handle trust separately.

            DispatchQueue.main.async {
                self?.checkTrust()
            }
        }
    }

    /// Generate a TLS certificate for a service hostname.
    func generateServiceCert(hostname: String) {
        DispatchQueue.global(qos: .userInitiated).async { [certsDir] in
            guard let mkcertPath = Self.findMkcert() else { return }

            try? FileManager.default.createDirectory(
                atPath: certsDir,
                withIntermediateDirectories: true
            )

            let certFile = "\(certsDir)/\(hostname).pem"
            let keyFile = "\(certsDir)/\(hostname).key"

            // Skip if cert already exists
            guard !FileManager.default.fileExists(atPath: certFile) else { return }

            _ = Self.runProcess(mkcertPath, args: [
                "-cert-file", certFile,
                "-key-file", keyFile,
                hostname,
            ])

            DispatchQueue.main.async { [weak self] in
                self?.countCerts()
            }
        }
    }

    // MARK: - Private

    private func countCerts() {
        let dir = certsDir
        DispatchQueue.global(qos: .utility).async {
            let count = (try? FileManager.default.contentsOfDirectory(atPath: dir))?
                .filter { $0.hasSuffix(".pem") }
                .count ?? 0
            DispatchQueue.main.async { [weak self] in
                self?.certCount = count
            }
        }
    }

    /// Check if the CA cert is trusted in the System Keychain.
    private static func isCATrustedInKeychain(caPath: String) -> Bool {
        // Use `security verify-cert` to check if a cert signed by our CA is valid.
        // Simpler: check if the CA's subject ("mkcert ...") is in the keychain.
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = [
            "find-certificate", "-c", "mkcert", "-a",
            "/Library/Keychains/System.keychain",
        ]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("mkcert")
        } catch {
            return false
        }
    }

    /// Install the CA cert using osascript with administrator privileges.
    ///
    /// This shows the native macOS password dialog — the standard lock icon
    /// that users expect for admin operations. No terminal involved.
    private static func installCAWithPrivileges(certPath: String) -> Result<Void, Error> {
        let escapedPath = certPath.replacingOccurrences(of: "'", with: "'\\''")
        let shellCommand = "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '\(escapedPath)'"

        let appleScript = """
        do shell script "\(shellCommand)" with administrator privileges
        """

        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", appleScript]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus == 0 {
                return .success(())
            } else {
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                let errorStr = String(data: errorData, encoding: .utf8) ?? "Unknown error"
                return .failure(NSError(
                    domain: "CertificateManager",
                    code: Int(process.terminationStatus),
                    userInfo: [NSLocalizedDescriptionKey: errorStr]
                ))
            }
        } catch {
            return .failure(error)
        }
    }

    /// Find mkcert binary.
    private static func findMkcert() -> String? {
        let candidates = [
            "/opt/homebrew/bin/mkcert",
            "/usr/local/bin/mkcert",
        ]
        return candidates.first { FileManager.default.fileExists(atPath: $0) }
    }

    /// Run a process and return stdout.
    @discardableResult
    private static func runProcess(_ path: String, args: [String]) -> String {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }
}
