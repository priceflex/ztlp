// BenchmarkReporter.swift
// ZTLP (Main App)
//
// Sends benchmark results to the bootstrap server after benchmark runs.
// POST /api/benchmarks with JSON payload. Authenticated via network enrollment secret.

import Foundation
import UIKit

struct BenchmarkUploadResult: Codable {
    let name: String
    let passed: Bool
    let latency_ms: Double?
    let throughput_kbps: Double?
    let p99_latency_ms: Double?
    let packet_loss_pct: Double?
    let error: String?
}

struct BenchmarkUploadReport: Codable {
    var summaryScore: String { "\(benchmarks_passed)/\(benchmarks_total)" }

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
    let individual_results: [BenchmarkUploadResult]?
    let relay_address: String?
    let gateway_address: String?
    let ns_address: String?
    let latency_ms: Int?
    let throughput_kbps: Int?
    let p99_latency_ms: Int?
    let packet_loss_pct: Int?
    let errors: String?
    let device_logs: String?
}

/// Read ztlp.log from the shared App Group container
func readDeviceLogs() -> String? {
    guard let containerURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared") else {
        return nil
    }
    let logURL = containerURL.appendingPathComponent("ztlp.log")
    return try? String(contentsOf: logURL, encoding: .utf8)
}

private func deviceLogStats(_ logs: String?) -> (lineCount: Int, byteCount: Int) {
    guard let logs, !logs.isEmpty else { return (0, 0) }
    return (
        logs.split(whereSeparator: \.isNewline).count,
        logs.lengthOfBytes(using: .utf8)
    )
}


enum bootstrapDefaults {
    static let url = "http://10.69.95.12:3000"
}

class BenchmarkReporter {
    private let logger = TunnelLogger.shared

    static let shared = BenchmarkReporter()

    private let bootstrapURL: String?
    private let apiToken: String?

    init(bootstrapURL: URL? = nil, apiToken: String? = nil) {
        self.bootstrapURL = bootstrapURL?.absoluteString
            ?? UserDefaults.standard.string(forKey: "ztlp_bootstrap_url")
            ?? bootstrapDefaults.url

        let defaultToken="***"
        self.apiToken=***

        if UserDefaults.standard.string(forKey: "ztlp_enrollment_secret") != nil {
            TunnelLogger.shared.warn(
                "Ignoring UserDefaults ztlp_enrollment_secret for benchmark upload; using embedded live token",
                source: "BenchUpload"
            )
        }
    }

    /// Send a benchmark report to the bootstrap server.
    /// Call this after the benchmark suite finishes.
    func submit(_ report: BenchmarkUploadReport, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let authToken = apiToken, !authToken.isEmpty else {
            logger.error("Benchmark upload skipped: missing bootstrap auth token", source: "BenchUpload")
            completion(.failure(ReporterError.noAuthToken))
            return
        }

        guard let bootstrapURL, !bootstrapURL.isEmpty,
              let url = URL(string: "\(bootstrapURL)/api/benchmarks") else {
            logger.error("Benchmark upload skipped: invalid bootstrap URL", source: "BenchUpload")
            completion(.failure(ReporterError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(authToken)", forHTTPHeaderField: "Authorization")

        let logStats = deviceLogStats(report.device_logs)
        logger.info(
            "Submitting benchmark report score=\(report.summaryScore) results=\(report.individual_results?.count ?? 0) log_lines=\(logStats.lineCount) log_bytes=\(logStats.byteCount) to \(url.host ?? bootstrapURL)",
            source: "BenchUpload"
        )

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        do {
            request.httpBody = try encoder.encode(report)
            logger.debug("Encoded benchmark payload bytes=\(request.httpBody?.count ?? 0)", source: "BenchUpload")
        } catch {
            logger.error("Benchmark upload encode failed: \(error.localizedDescription)", source: "BenchUpload")
            completion(.failure(error))
            return
        }

        let task = URLSession.shared.dataTask(with: request) { [logger] data, response, error in
            if let error = error {
                logger.error("Benchmark upload failed: \(error.localizedDescription)", source: "BenchUpload")
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                logger.error("Benchmark upload failed: missing HTTP response", source: "BenchUpload")
                completion(.failure(ReporterError.serverError("Missing HTTP response")))
                return
            }

            let responseBody = String(data: data ?? Data(), encoding: .utf8) ?? ""
            if (200...299).contains(httpResponse.statusCode) {
                logger.info(
                    "Benchmark upload complete: HTTP \(httpResponse.statusCode) score=\(report.summaryScore) response=\(responseBody.isEmpty ? "<empty>" : responseBody)",
                    source: "BenchUpload"
                )
                completion(.success(()))
            } else {
                let msg = responseBody.isEmpty ? "HTTP \(httpResponse.statusCode)" : responseBody
                logger.error("Benchmark upload rejected: HTTP \(httpResponse.statusCode) body=\(msg)", source: "BenchUpload")
                completion(.failure(ReporterError.serverError(msg)))
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
        individualResults: [BenchmarkUploadResult]? = nil,
        relayAddress: String? = nil,
        gatewayAddress: String? = nil,
        nsAddress: String? = nil,
        avgLatencyMs: Int? = nil,
        throughputKbps: Int? = nil,
        p99LatencyMs: Int? = nil,
        packetLossPct: Int? = nil,
        errors: String? = nil
    ) {
        let report = BenchmarkUploadReport(
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
            errors: errors,
            device_logs: readDeviceLogs()
        )

        submit(report) { [logger] result in
            switch result {
            case .success:
                logger.info("Benchmark report stored on bootstrap server", source: "BenchUpload")
                print("[BenchmarkReporter] Submitted to bootstrap server")
            case .failure(let error):
                logger.error("Benchmark report submission failed: \(error.localizedDescription)", source: "BenchUpload")
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
