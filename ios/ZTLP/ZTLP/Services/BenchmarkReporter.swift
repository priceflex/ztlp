// BenchmarkReporter.swift
// ZTLP (Main App)
//
// Sends benchmark results to the bootstrap server after benchmark runs.
// POST /api/benchmarks with JSON payload. Authenticated via network enrollment secret.

import Foundation

struct BenchmarkResult: Codable {
    let name: String
    let passed: Bool
    let latency_ms: Double?
    let throughput_kbps: Double?
    let p99_latency_ms: Double?
    let packet_loss_pct: Double?
    let error: String?
}

struct BenchmarkReport: Codable {
    let device_id: String?
    let node_id: String?
    let app_version: String
    let build_tag: String
    let device_model: String
    let ios_version: String
    let ne_memory_mb: Int?
    let ne_virtual_mb: Int?
    let ne_memory_pass: Bool
    let benchmarks_passed: Int
    let benchmarks_total: Int
    let individual_results: [BenchmarkResult]?
    let relay_address: String?
    let gateway_address: String?
    let ns_address: String?
    let latency_ms: Int?
    let throughput_kbps: Int?
    let p99_latency_ms: Int?
    let packet_loss_pct: Int?
    let errors: String?
}

class BenchmarkReporter {
    static let shared = BenchmarkReporter()

    private let bootstrapURL: String?
    private let apiToken: String?

    init(bootstrapURL: URL? = nil, apiToken: String? = nil) {
        // Default to the bootstrap server configured in your network
        self.bootstrapURL = bootstrapURL?.absoluteString ?? "http://10.69.95.12:3000"
        self.apiToken = apiToken
    }

    /// Send a benchmark report to the bootstrap server.
    /// Call this after the benchmark suite finishes.
    func submit(_ report: BenchmarkReport, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let authToken = apiToken else {
            completion(.failure(ReporterError.noAuthToken))
            return
        }

        var components = URLComponents(string: "\(bootstrapURL)/api/benchmarks")!
        guard let url = components.url else {
            completion(.failure(ReporterError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(authToken)", forHTTPHeaderField: "Authorization")

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        do {
            request.httpBody = try encoder.encode(report)
        } catch {
            completion(.failure(error))
            return
        }

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            if let httpResponse = response as? HTTPURLResponse {
                if (200...299).contains(httpResponse.statusCode) {
                    completion(.success(()))
                } else {
                    let msg = String(data: data ?? Data(), encoding: .utf8) ?? "HTTP \(httpResponse.statusCode)"
                    completion(.failure(ReporterError.serverError(msg)))
                }
            }
        }
        task.resume()
    }

    /// Quick helper: submit from benchmark params.
    func submit(
        deviceID: String? = nil,
        nodeID: String? = nil,
        appVersion: String = ProcessInfo.processInfo.operatingSystemVersionString,
        buildTag: String = "v5D-SYNC",
        neMemoryMB: Int?,
        neVirtualMB: Int?,
        passedCount: Int,
        totalCount: Int,
        individualResults: [BenchmarkResult]? = nil,
        relayAddress: String? = nil,
        gatewayAddress: String? = nil,
        nsAddress: String? = nil,
        avgLatencyMs: Int? = nil,
        throughputKbps: Int? = nil,
        p99LatencyMs: Int? = nil,
        packetLossPct: Int? = nil,
        errors: String? = nil
    ) {
        let report = BenchmarkReport(
            device_id: deviceID,
            node_id: nodeID,
            app_version: appVersion,
            build_tag: buildTag,
            device_model: UIDevice.current.model,
            ios_version: UIDevice.current.systemVersion,
            ne_memory_mb: neMemoryMB,
            ne_virtual_mb: neVirtualMB,
            ne_memory_pass: (neMemoryMB ?? 999) <= 15,
            benchmarks_passed: passedCount,
            benchmarks_total: totalCount,
            individual_results: individualResults,
            relay_address: relayAddress,
            gateway_address: gatewayAddress,
            ns_address: nsAddress,
            latency_ms: avgLatencyMs,
            throughput_kbps: throughputKbps,
            p99_latency_ms: p99LatencyMs,
            packet_loss_pct: packetLossPct,
            errors: errors
        )

        submit(report) { result in
            switch result {
            case .success:
                print("[BenchmarkReporter] Submitted to bootstrap server")
            case .failure(let error):
                print("[BenchmarkReporter] Failed to submit: \(error)")
            }
        }
    }

    enum ReporterError: Error, LocalizedError {
        case noAuthToken
        case invalidURL
        case serverError(String)

        var errorDescription: String? {
            switch self {
            case .noAuthToken: return "No API token configured"
            case .invalidURL: return "Invalid bootstrap URL"
            case .serverError(let msg): return "Server error: \(msg)"
            }
        }
    }
}
