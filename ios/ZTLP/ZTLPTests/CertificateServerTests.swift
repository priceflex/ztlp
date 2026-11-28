import Network
import XCTest
@testable import ZTLP

/// Exercises the real loopback listener with a raw TCP client (the same
/// bytes Safari would send), so no App Transport Security rules apply.
final class CertificateServerTests: XCTestCase {

    private let der = Data([0x30, 0x82, 0x01, 0x00] + [UInt8](repeating: 0x5A, count: 256))

    func testServesCertificateOnLoopback() async throws {
        let server = CertificateServer()
        defer { server.stop() }

        let url = try await server.start(der: der)
        XCTAssertEqual(url.scheme, "http")
        XCTAssertEqual(url.host, "127.0.0.1")
        XCTAssertEqual(url.path, "/ztlp-ca.cer")
        let port = try XCTUnwrap(url.port)
        XCTAssertGreaterThan(port, 0)

        let reply = try await fetch(port: port, request: "GET /ztlp-ca.cer HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n")
        XCTAssertEqual(reply, CertificateEncoding.httpResponse(der: der))
    }

    func testRestartMovesToAFreshListenerAndServesTheNewCertificate() async throws {
        let server = CertificateServer()
        defer { server.stop() }

        _ = try await server.start(der: der)
        let other = Data([0x30, 0x03, 0x02, 0x01, 0x07])
        let second = try await server.start(der: other)
        let port = try XCTUnwrap(second.port)
        let reply = try await fetch(port: port, request: "GET / HTTP/1.1\r\n\r\n")
        XCTAssertEqual(reply, CertificateEncoding.httpResponse(der: other))
    }

    /// Send `request`, read until the server closes the connection.
    private func fetch(port: Int, request: String) async throws -> Data {
        let nwPort = try XCTUnwrap(NWEndpoint.Port(rawValue: UInt16(port)))
        let connection = NWConnection(host: .ipv4(.loopback), port: nwPort, using: .tcp)
        let queue = DispatchQueue(label: "test.certclient")
        let collector = Collector()

        return try await withCheckedThrowingContinuation { continuation in
            collector.continuation = continuation

            @Sendable func read() {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                    if let data { collector.data.append(data) }
                    if isComplete || error != nil {
                        connection.cancel()
                        collector.finish(error: collector.data.isEmpty ? error : nil)
                    } else {
                        read()
                    }
                }
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: Data(request.utf8), completion: .contentProcessed { _ in })
                    read()
                case .failed(let error):
                    collector.finish(error: error)
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 10) {
                connection.cancel()
                collector.finish(error: NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "timed out"]))
            }
        }
    }
}

/// Confined to the client queue.
private final class Collector: @unchecked Sendable {
    var data = Data()
    var continuation: CheckedContinuation<Data, Error>?

    func finish(error: Error?) {
        guard let continuation else { return }
        self.continuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume(returning: data)
        }
    }
}
