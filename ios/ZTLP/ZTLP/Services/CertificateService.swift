// CertificateService.swift
// ZTLP
//
// Manages ZTLP CA root certificate fetching, storage, and installation.
//
// During enrollment, the app fetches the CA root cert from the ZTLP-NS
// server and offers to install it as a configuration profile so that
// Safari and other apps trust TLS certificates signed by the ZTLP CA.
//
// Installation flow:
//   1. Fetch DER cert from NS via FFI (ztlp_ns_fetch_ca_root)
//   2. Generate a .mobileconfig XML profile with the cert embedded
//   3. Serve the profile via a local HTTP server on localhost
//   4. Open Safari to http://localhost:<port>/ca.mobileconfig
//   5. iOS prompts user to install the profile in Settings
//   6. User goes to Settings → Profile Downloaded → Install → enable full trust

import Foundation
import UIKit

/// Manages ZTLP CA certificate distribution and trust.
@MainActor
final class CertificateService: ObservableObject {
    
    static let shared = CertificateService()
    
    // MARK: - Published State
    
    @Published private(set) var caRootDER: Data?
    @Published private(set) var caRootPEM: String?
    @Published private(set) var isInstalled: Bool = false
    @Published private(set) var isFetching: Bool = false
    @Published private(set) var errorMessage: String?
    
    // MARK: - Private
    
    private let logger = TunnelLogger.shared
    private var httpServer: CertHTTPServer?
    
    private init() {
        // Check if we've previously stored the CA cert
        if let stored = loadStoredCACert() {
            caRootDER = stored
            caRootPEM = derToPEM(stored, label: "CERTIFICATE")
            isInstalled = UserDefaults.standard.bool(forKey: "ztlp_ca_installed")
        }
    }
    
    // MARK: - Fetch CA Root from NS
    
    /// Fetch the CA root certificate from the ZTLP-NS server.
    ///
    /// This calls `ztlp_ns_fetch_ca_root()` via FFI which sends a UDP
    /// query (0x14 0x01) to the NS server.
    func fetchCARootCert(nsServer: String, timeoutMs: UInt32 = 10000) async -> Bool {
        isFetching = true
        errorMessage = nil
        
        logger.info("Fetching CA root cert from NS: \(nsServer)", source: "CertService")
        
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                var dataPtr: UnsafeMutablePointer<UInt8>?
                var dataLen: UInt32 = 0
                
                let result = nsServer.withCString { serverPtr in
                    ztlp_ns_fetch_ca_root(serverPtr, timeoutMs, &dataPtr, &dataLen)
                }
                
                Task { @MainActor [weak self] in
                    guard let self else {
                        continuation.resume(returning: false)
                        return
                    }
                    
                    self.isFetching = false
                    
                    if result == 0, let ptr = dataPtr, dataLen > 0 {
                        let data = Data(bytes: ptr, count: Int(dataLen))
                        ztlp_bytes_free(ptr, dataLen)
                        
                        self.caRootDER = data
                        self.caRootPEM = self.derToPEM(data, label: "CERTIFICATE")
                        self.storeCACert(data)
                        
                        self.logger.info("CA root cert fetched (\(dataLen) bytes)", source: "CertService")
                        continuation.resume(returning: true)
                    } else {
                        let errMsg: String
                        if let errPtr = ztlp_last_error() {
                            errMsg = String(cString: errPtr)
                        } else {
                            errMsg = "Unknown error (code \(result))"
                        }
                        self.errorMessage = errMsg
                        self.logger.error("Failed to fetch CA root: \(errMsg)", source: "CertService")
                        continuation.resume(returning: false)
                    }
                }
            }
        }
    }
    
    // MARK: - Install via Configuration Profile
    
    /// Generate a .mobileconfig profile and open it for installation.
    ///
    /// iOS requires configuration profiles to be "downloaded" — they can't
    /// be installed programmatically. We start a temporary local HTTP server
    /// and open Safari to download the profile.
    func installCACert() {
        guard let der = caRootDER else {
            errorMessage = "No CA certificate available. Fetch it first."
            return
        }
        
        logger.info("Starting CA cert installation flow", source: "CertService")
        
        // Generate the .mobileconfig XML
        let profileData = generateMobileConfig(certDER: der)
        
        // Start local HTTP server to serve the profile
        httpServer = CertHTTPServer(profileData: profileData)
        guard let port = httpServer?.start() else {
            errorMessage = "Failed to start local server for cert installation"
            logger.error("Failed to start cert HTTP server", source: "CertService")
            return
        }
        
        logger.info("Cert server started on port \(port)", source: "CertService")
        
        // Open Safari to download the profile
        let url = URL(string: "http://localhost:\(port)/ca.mobileconfig")!
        UIApplication.shared.open(url) { [weak self] success in
            if success {
                self?.logger.info("Opened Safari for cert installation", source: "CertService")
                // Mark as "installation attempted" — user still needs to complete in Settings
                UserDefaults.standard.set(true, forKey: "ztlp_ca_install_attempted")
            } else {
                self?.logger.error("Failed to open Safari", source: "CertService")
                self?.errorMessage = "Could not open Safari to install the certificate"
            }
            
            // Stop the server after a delay (give Safari time to download)
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
                self?.httpServer?.stop()
                self?.httpServer = nil
            }
        }
    }
    
    /// Mark the CA cert as installed (called after user confirms installation).
    func markAsInstalled() {
        isInstalled = true
        UserDefaults.standard.set(true, forKey: "ztlp_ca_installed")
        logger.info("CA cert marked as installed", source: "CertService")
    }
    
    /// Reset installation state (for re-enrollment or troubleshooting).
    func reset() {
        caRootDER = nil
        caRootPEM = nil
        isInstalled = false
        errorMessage = nil
        UserDefaults.standard.removeObject(forKey: "ztlp_ca_installed")
        UserDefaults.standard.removeObject(forKey: "ztlp_ca_install_attempted")
        removeCACert()
    }
    
    // MARK: - Mobile Config Generation
    
    /// Generate a .mobileconfig XML plist with the CA root certificate.
    ///
    /// This creates a Configuration Profile that installs the ZTLP CA
    /// as a trusted root certificate on the device.
    private func generateMobileConfig(certDER: Data) -> Data {
        let certBase64 = certDER.base64EncodedString(options: .lineLength76Characters)
        let uuid1 = UUID().uuidString
        let uuid2 = UUID().uuidString
        
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadCertificateFileName</key>
                    <string>ztlp-ca-root.cer</string>
                    <key>PayloadContent</key>
                    <data>
        \(certBase64)
                    </data>
                    <key>PayloadDescription</key>
                    <string>Installs the ZTLP Certificate Authority root certificate for secure service access.</string>
                    <key>PayloadDisplayName</key>
                    <string>ZTLP Root CA</string>
                    <key>PayloadIdentifier</key>
                    <string>com.ztlp.cert.root.\(uuid2)</string>
                    <key>PayloadType</key>
                    <string>com.apple.security.root</string>
                    <key>PayloadUUID</key>
                    <string>\(uuid2)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>Installs the ZTLP Certificate Authority root certificate so your device trusts ZTLP-secured services like Vaultwarden, internal apps, and other services on your ZTLP network.</string>
            <key>PayloadDisplayName</key>
            <string>ZTLP Network Trust</string>
            <key>PayloadIdentifier</key>
            <string>com.ztlp.profile.ca.\(uuid1)</string>
            <key>PayloadOrganization</key>
            <string>ZTLP</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuid1)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
        
        return xml.data(using: .utf8) ?? Data()
    }
    
    // MARK: - Storage
    
    /// Store the CA cert in the shared app group container.
    private func storeCACert(_ der: Data) {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) else {
            // Fallback to UserDefaults
            UserDefaults.standard.set(der, forKey: "ztlp_ca_root_der")
            return
        }
        
        let certURL = containerURL.appendingPathComponent("ca-root.der")
        try? der.write(to: certURL)
    }
    
    /// Load the stored CA cert from the shared app group container.
    private func loadStoredCACert() -> Data? {
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) {
            let certURL = containerURL.appendingPathComponent("ca-root.der")
            return try? Data(contentsOf: certURL)
        }
        return UserDefaults.standard.data(forKey: "ztlp_ca_root_der")
    }
    
    /// Remove the stored CA cert.
    private func removeCACert() {
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) {
            let certURL = containerURL.appendingPathComponent("ca-root.der")
            try? FileManager.default.removeItem(at: certURL)
        }
        UserDefaults.standard.removeObject(forKey: "ztlp_ca_root_der")
    }
    
    // MARK: - Helpers
    
    /// Convert DER data to PEM string.
    private func derToPEM(_ der: Data, label: String) -> String {
        let base64 = der.base64EncodedString(options: .lineLength64Characters)
        return "-----BEGIN \(label)-----\n\(base64)\n-----END \(label)-----"
    }
}

// MARK: - Local HTTP Server for Profile Download

/// Minimal HTTP server that serves a .mobileconfig file on localhost.
///
/// iOS requires configuration profiles to be "downloaded" from a URL.
/// This server runs briefly on localhost to serve the profile to Safari.
private class CertHTTPServer {
    
    private let profileData: Data
    private var listener: CFSocket?
    private var serverSocket: Int32 = -1
    private var port: UInt16 = 0
    private var isRunning = false
    private var acceptSource: DispatchSourceRead?
    
    init(profileData: Data) {
        self.profileData = profileData
    }
    
    /// Start the server on a random available port.
    /// Returns the port number, or nil on failure.
    func start() -> UInt16? {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0)
        guard serverSocket >= 0 else { return nil }
        
        var yes: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0  // Let OS assign port
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(serverSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(serverSocket)
            return nil
        }
        
        guard Darwin.listen(serverSocket, 5) == 0 else {
            close(serverSocket)
            return nil
        }
        
        // Get assigned port
        var boundAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                getsockname(serverSocket, sockPtr, &addrLen)
            }
        }
        port = UInt16(bigEndian: boundAddr.sin_port)
        
        isRunning = true
        
        // Accept connections on a background queue
        let source = DispatchSource.makeReadSource(fileDescriptor: serverSocket, queue: .global(qos: .userInitiated))
        source.setEventHandler { [weak self] in
            self?.acceptConnection()
        }
        source.setCancelHandler { [weak self] in
            if let fd = self?.serverSocket, fd >= 0 {
                close(fd)
            }
        }
        acceptSource = source
        source.resume()
        
        return port
    }
    
    func stop() {
        isRunning = false
        acceptSource?.cancel()
        acceptSource = nil
    }
    
    private func acceptConnection() {
        var clientAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        
        let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                accept(serverSocket, sockPtr, &addrLen)
            }
        }
        guard clientSocket >= 0 else { return }
        
        // Read the HTTP request (we don't really parse it, just serve the profile)
        var buf = [UInt8](repeating: 0, count: 4096)
        _ = recv(clientSocket, &buf, buf.count, 0)
        
        // Build HTTP response
        let headers = """
        HTTP/1.1 200 OK\r
        Content-Type: application/x-apple-aspen-config\r
        Content-Disposition: attachment; filename="ztlp-ca.mobileconfig"\r
        Content-Length: \(profileData.count)\r
        Connection: close\r
        \r
        
        """
        
        let headerData = headers.data(using: .ascii) ?? Data()
        headerData.withUnsafeBytes { ptr in
            _ = send(clientSocket, ptr.baseAddress!, headerData.count, 0)
        }
        profileData.withUnsafeBytes { ptr in
            _ = send(clientSocket, ptr.baseAddress!, profileData.count, 0)
        }
        
        close(clientSocket)
    }
}
