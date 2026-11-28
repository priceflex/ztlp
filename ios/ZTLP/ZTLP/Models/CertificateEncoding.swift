// CertificateEncoding.swift
// Pure helpers for the certificate install flow. No I/O, unit tested.

import CryptoKit
import Foundation

enum CertificateEncoding {
    /// DER bytes of the first certificate in a PEM string, or nil.
    static func derFromPEM(_ pem: String) -> Data? {
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        guard let beginRange = pem.range(of: begin),
              let endRange = pem.range(of: end, range: beginRange.upperBound..<pem.endIndex) else {
            return nil
        }
        let body = pem[beginRange.upperBound..<endRange.lowerBound]
            .filter { !$0.isWhitespace }
        guard !body.isEmpty, let der = Data(base64Encoded: String(body)) else { return nil }
        // Every DER certificate is an ASN.1 SEQUENCE.
        guard der.first == 0x30 else { return nil }
        return der
    }

    /// Lower-case hex SHA-256 of some bytes (a certificate fingerprint).
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static let contentType = "application/x-x509-ca-cert"

    /// Complete HTTP/1.1 response carrying the certificate. The content type
    /// is what makes Safari offer to install it as a profile.
    static func httpResponse(der: Data) -> Data {
        var response = Data(
            ("HTTP/1.1 200 OK\r\n"
             + "Content-Type: \(contentType)\r\n"
             + "Content-Length: \(der.count)\r\n"
             + "Cache-Control: no-store\r\n"
             + "Connection: close\r\n\r\n").utf8
        )
        response.append(der)
        return response
    }
}

enum LogTail {
    /// Last `maxLines` lines of a log chunk. A chunk read from the middle of
    /// a file may start mid-line; `dropPartialFirstLine` discards that piece.
    static func lastLines(of data: Data, maxLines: Int, dropPartialFirstLine: Bool) -> [String] {
        guard maxLines > 0 else { return [] }
        let text = String(decoding: data, as: UTF8.self)
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if dropPartialFirstLine, lines.count > 1 { lines.removeFirst() }
        if lines.last?.isEmpty == true { lines.removeLast() }
        return Array(lines.suffix(maxLines))
    }

    /// Read the tail of a file without loading all of it.
    static func read(url: URL, maxLines: Int = 200, maxBytes: UInt64 = 96 * 1024) -> [String] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        guard let size = try? handle.seekToEnd() else { return [] }
        let start = size > maxBytes ? size - maxBytes : 0
        guard (try? handle.seek(toOffset: start)) != nil,
              let data = try? handle.readToEnd() else { return [] }
        return lastLines(of: data, maxLines: maxLines, dropPartialFirstLine: start > 0)
    }
}
