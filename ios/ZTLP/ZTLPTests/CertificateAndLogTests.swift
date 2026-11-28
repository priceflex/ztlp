import XCTest
@testable import ZTLP

final class CertificateEncodingTests: XCTestCase {

    // Not a real certificate: any DER SEQUENCE is enough for these helpers.
    private let der = Data([0x30, 0x03, 0x02, 0x01, 0x05])

    private var pem: String {
        "-----BEGIN CERTIFICATE-----\n\(der.base64EncodedString())\n-----END CERTIFICATE-----\n"
    }

    func testPEMToDER() {
        XCTAssertEqual(CertificateEncoding.derFromPEM(pem), der)
    }

    func testPEMWithWrappedLinesCRLFAndSurroundingText() {
        let long = Data([0x30, 0x82, 0x01, 0x00] + [UInt8](repeating: 0xAB, count: 256))
        let b64 = long.base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn, .endLineWithLineFeed])
        let text = "subject=ZTLP\r\n-----BEGIN CERTIFICATE-----\r\n\(b64)\r\n-----END CERTIFICATE-----\r\ntrailing"
        XCTAssertEqual(CertificateEncoding.derFromPEM(text), long)
    }

    func testOnlyTheFirstCertificateIsUsed() {
        let second = Data([0x30, 0x03, 0x02, 0x01, 0x09])
        let two = pem + "-----BEGIN CERTIFICATE-----\n\(second.base64EncodedString())\n-----END CERTIFICATE-----\n"
        XCTAssertEqual(CertificateEncoding.derFromPEM(two), der)
    }

    func testRejectsBadPEM() {
        XCTAssertNil(CertificateEncoding.derFromPEM(""))
        XCTAssertNil(CertificateEncoding.derFromPEM("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"))
        XCTAssertNil(CertificateEncoding.derFromPEM("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"))
        XCTAssertNil(CertificateEncoding.derFromPEM("-----BEGIN CERTIFICATE-----\nAAAA"))
        // Valid base64 that is not a DER SEQUENCE.
        XCTAssertNil(CertificateEncoding.derFromPEM("-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----"))
    }

    func testHTTPResponse() throws {
        let response = CertificateEncoding.httpResponse(der: der)
        let separator = Data("\r\n\r\n".utf8)
        let split = try XCTUnwrap(response.range(of: separator))
        let head = String(decoding: response[..<split.lowerBound], as: UTF8.self)
        XCTAssertTrue(head.hasPrefix("HTTP/1.1 200 OK\r\n"))
        XCTAssertTrue(head.contains("Content-Type: application/x-x509-ca-cert"))
        XCTAssertTrue(head.contains("Content-Length: \(der.count)"))
        XCTAssertEqual(response[split.upperBound...], der)
    }
}

final class TrustProbeTests: XCTestCase {

    private func urlError(_ code: Int) -> Error {
        NSError(domain: NSURLErrorDomain, code: code)
    }

    func testCertificateErrorsMeanNotTrusted() {
        for code in [NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
                     NSURLErrorServerCertificateHasBadDate, NSURLErrorServerCertificateNotYetValid] {
            XCTAssertEqual(TrustProbe.classify(urlError(code)), .notTrusted)
        }
    }

    func testOtherErrorsSayNothingAboutTrust() {
        for code in [NSURLErrorCannotFindHost, NSURLErrorTimedOut, NSURLErrorCannotConnectToHost,
                     NSURLErrorNotConnectedToInternet, NSURLErrorSecureConnectionFailed] {
            XCTAssertEqual(TrustProbe.classify(urlError(code)), .unreachable)
        }
        XCTAssertEqual(TrustProbe.classify(NSError(domain: "other", code: NSURLErrorServerCertificateUntrusted)), .unreachable)
    }

    func testHealthURLIsHTTPSOnAZTLPName() throws {
        let url = try XCTUnwrap(TrustProbe.healthURL())
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "ztlp-health.ztlp")
        XCTAssertEqual(url.port, 8443)
    }
}

final class FingerprintTests: XCTestCase {
    func testSHA256HexOfKnownInput() {
        XCTAssertEqual(
            CertificateEncoding.sha256Hex(Data("abc".utf8)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testPEMWithNoCertificatesGivesNone() {
        XCTAssertTrue(TrustDiag.certificates(inPEM: "").isEmpty)
        XCTAssertTrue(TrustDiag.certificates(inPEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").isEmpty)
    }
}

final class LogTailTests: XCTestCase {

    func testLastLines() {
        let data = Data((1...10).map { "line \($0)" }.joined(separator: "\n").appending("\n").utf8)
        XCTAssertEqual(LogTail.lastLines(of: data, maxLines: 3, dropPartialFirstLine: false),
                       ["line 8", "line 9", "line 10"])
        XCTAssertEqual(LogTail.lastLines(of: data, maxLines: 200, dropPartialFirstLine: false).count, 10)
        XCTAssertEqual(LogTail.lastLines(of: data, maxLines: 0, dropPartialFirstLine: false), [])
    }

    func testDropsPartialFirstLine() {
        let data = Data("rtial\nwhole 1\nwhole 2".utf8)
        XCTAssertEqual(LogTail.lastLines(of: data, maxLines: 10, dropPartialFirstLine: true),
                       ["whole 1", "whole 2"])
    }

    func testEmptyAndMissingFile() {
        XCTAssertEqual(LogTail.lastLines(of: Data(), maxLines: 5, dropPartialFirstLine: false), [])
        let missing = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        XCTAssertEqual(LogTail.read(url: missing), [])
    }

    func testReadTailOfLargeFile() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let text = (1...5000).map { "entry \($0)" }.joined(separator: "\n") + "\n"
        try Data(text.utf8).write(to: url)
        let lines = LogTail.read(url: url, maxLines: 200, maxBytes: 8 * 1024)
        XCTAssertEqual(lines.count, 200)
        XCTAssertEqual(lines.last, "entry 5000")
        XCTAssertEqual(lines.first, "entry 4801")
    }
}
