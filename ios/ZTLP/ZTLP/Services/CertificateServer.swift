// CertificateServer.swift
// Serves the device's root certificate to Safari from 127.0.0.1 so iOS
// offers to install it as a profile. Runs only while the user is in the
// install flow.

import Foundation
import Network

final class CertificateServer: @unchecked Sendable {
    enum ServerError: LocalizedError {
        case couldNotStart(String)

        var errorDescription: String? {
            switch self {
            case .couldNotStart(let why): return "Could not offer the certificate: \(why)"
            }
        }
    }

    /// How long the listener stays up after it starts.
    static let lifetime: TimeInterval = 300

    private let queue = DispatchQueue(label: "com.ztlp.app.certserver")
    // Touched on `queue` only.
    private var listener: NWListener?
    private var generation = 0

    /// Start listening on a random loopback port and return the URL to open.
    func start(der: Data) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                listener?.cancel()
                listener = nil
                generation += 1
                let myGeneration = generation

                let parameters = NWParameters.tcp
                parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
                parameters.allowLocalEndpointReuse = true

                let newListener: NWListener
                do {
                    newListener = try NWListener(using: parameters)
                } catch {
                    continuation.resume(throwing: ServerError.couldNotStart(error.localizedDescription))
                    return
                }

                let response = CertificateEncoding.httpResponse(der: der)
                let pending = PendingStart(continuation)
                newListener.stateUpdateHandler = { [weak newListener] state in
                    // Runs on `queue`.
                    switch state {
                    case .ready:
                        if let port = newListener?.port,
                           let url = URL(string: "http://127.0.0.1:\(port.rawValue)/ztlp-ca.cer") {
                            pending.finish(.success(url))
                        } else {
                            pending.finish(.failure(ServerError.couldNotStart("no port")))
                        }
                    case .failed(let error):
                        newListener?.cancel()
                        pending.finish(.failure(ServerError.couldNotStart(error.localizedDescription)))
                    case .cancelled:
                        pending.finish(.failure(ServerError.couldNotStart("cancelled")))
                    default:
                        break
                    }
                }
                newListener.newConnectionHandler = { [queue] connection in
                    CertificateRequest(connection, response: response, queue: queue).start()
                }
                listener = newListener
                newListener.start(queue: queue)

                queue.asyncAfter(deadline: .now() + Self.lifetime) { [self] in
                    guard generation == myGeneration else { return }
                    listener?.cancel()
                    listener = nil
                }
            }
        }
    }

    func stop() {
        queue.async { [self] in
            generation += 1
            listener?.cancel()
            listener = nil
        }
    }
}

/// Resumes the start continuation once. Used on the server queue only.
private final class PendingStart: @unchecked Sendable {
    private var continuation: CheckedContinuation<URL, Error>?

    init(_ continuation: CheckedContinuation<URL, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<URL, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(with: result)
    }
}

/// One HTTP exchange: read the request head (its content does not matter,
/// every path gets the certificate), send the response, close. All state is
/// touched on the server queue only.
private final class CertificateRequest: @unchecked Sendable {
    private let connection: NWConnection
    private let response: Data
    private let queue: DispatchQueue
    private var received = Data()

    init(_ connection: NWConnection, response: Data, queue: DispatchQueue) {
        self.connection = connection
        self.response = response
        self.queue = queue
    }

    func start() {
        connection.start(queue: queue)
        readMore()
        // A client that never sends a request must not hold the connection.
        queue.asyncAfter(deadline: .now() + 15) { [self] in
            if connection.state != .cancelled { connection.cancel() }
        }
    }

    private func readMore() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [self] data, _, isComplete, error in
            if let data { received.append(data) }
            let headDone = received.range(of: Data("\r\n\r\n".utf8)) != nil
            if headDone, error == nil {
                connection.send(content: response, completion: .contentProcessed { [connection] _ in
                    connection.cancel()
                })
            } else if isComplete || error != nil || received.count > 16 * 1024 {
                connection.cancel()
            } else {
                readMore()
            }
        }
    }
}
