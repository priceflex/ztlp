// HTTPBenchmark.swift
// ZTLP
//
// HTTP benchmarks that send real web traffic through the ZTLP tunnel.
//
// Flow:
//   1. Connect to relay (Noise_XX handshake)
//   2. Start VIP proxy (maps local IP:port → remote HTTP service through tunnel)
//   3. Make URLSession HTTP requests through the local VIP proxy
//   4. Measure latency, throughput, time-to-first-byte
//
// Benchmarks:
//   - HTTP ping (/ping endpoint, measures full HTTP RTT through tunnel)
//   - Small payload GET (1KB, 10KB, 100KB)
//   - Large download (1MB, 5MB) — measures sustained HTTP throughput
//   - Upload POST (1KB, 100KB, 1MB)
//   - Echo round-trip (POST body → get it back)
//   - Concurrent requests (5 parallel GETs)
//   - Time-to-first-byte (download start latency)
//
// Results logged via TunnelLogger (source: "HTTPBench") for Logs tab capture.

import Foundation
import Combine

@MainActor
final class HTTPBenchmark: ObservableObject {

    static let shared = HTTPBenchmark()

    // MARK: Published State

    @Published var isRunning = false
    @Published var currentBenchmark = ""
    @Published var progress: Double = 0
    @Published var results: [BenchmarkResult] = []
    @Published var connectionStatus = "Idle"

    // MARK: Properties

    private let logger = TunnelLogger.shared

    /// VIP proxy address for HTTP echo benchmark traffic.
    /// Uses 127.0.0.1:9080 — different port from the VPN extension's
    /// VIP proxy (which uses 127.0.0.1:8080 for vault).
    /// iOS only allows binding to 127.0.0.1 (not 127.0.0.2+).
    private let vipAddress = "127.0.0.1"
    private let vipPort: UInt16 = 9080
    private var baseURL: String { "http://\(vipAddress):\(vipPort)" }

    /// Track whether we created our own connection (so we can clean up).
    private var ownedConnection = false

    /// URLSession configured to not cache and use short timeouts.
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 120
        config.timeoutIntervalForResource = 300
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: config)
    }()

    private init() {}

    // MARK: - Server Configuration

    private var relayAddress: String {
        UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_relay_server")
            ?? "34.219.64.205:23095"
    }

    private var nsServer: String {
        UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_ns_server")
            ?? "34.217.62.46:23096"
    }

    private var gatewayTarget: String {
        // The target for ztlp_connect is the relay address (IP:port).
        // The node ID (ztlp_target_node_id) is for the VPN extension's
        // tunnel configuration, not for direct in-process connections.
        relayAddress
    }

    // MARK: - Run All

    func runAll() async {
        guard !isRunning else { return }
        isRunning = true
        results = []
        progress = 0

        logger.info("═══════════════════════════════════════════", source: "HTTPBench")
        logger.info("ZTLP HTTP Benchmark Suite", source: "HTTPBench")
        logger.info("Device: \(deviceInfo())", source: "HTTPBench")
        logger.info("Date: \(ISO8601DateFormatter().string(from: Date()))", source: "HTTPBench")
        logger.info("Library: \(ZTLPBridge.shared.version)", source: "HTTPBench")
        logger.info("Relay: \(relayAddress)", source: "HTTPBench")
        logger.info("HTTP VIP: \(baseURL) (in-process, separate from VPN extension)", source: "HTTPBench")
        logger.info("═══════════════════════════════════════════", source: "HTTPBench")

        // Step 1: Establish ZTLP tunnel + VIP proxy
        connectionStatus = "Connecting to relay..."
        guard await setupTunnel() else {
            logger.error("Failed to set up tunnel — aborting HTTP benchmarks", source: "HTTPBench")
            connectionStatus = "Connection failed"
            isRunning = false
            return
        }

        // Step 2: Verify HTTP echo server is reachable
        connectionStatus = "Verifying HTTP endpoint..."
        guard await verifyEndpoint() else {
            logger.error("HTTP echo server not reachable through tunnel — aborting", source: "HTTPBench")
            connectionStatus = "HTTP endpoint unreachable"
            isRunning = false
            return
        }

        // Step 3: Run benchmarks
        let benchmarks: [(String, () async -> BenchmarkResult?)] = [
            ("HTTP Ping", benchPing),
            ("GET 1KB", { await self.benchGet(size: 1024, label: "1KB") }),
            ("GET 10KB", { await self.benchGet(size: 10_240, label: "10KB") }),
            ("GET 100KB", { await self.benchGet(size: 102_400, label: "100KB") }),
            ("GET 1MB", { await self.benchGet(size: 1_048_576, label: "1MB") }),
            ("Download 5MB", benchDownload5MB),
            ("POST Echo 1KB", { await self.benchPostEcho(size: 1024, label: "1KB") }),
            ("POST Echo 100KB", { await self.benchPostEcho(size: 102_400, label: "100KB") }),
            ("Upload 1MB", benchUpload1MB),
            ("Concurrent 5x GET", benchConcurrent),
            ("Time-to-First-Byte", benchTTFB),
        ]

        let total = Double(benchmarks.count)

        for (index, (name, bench)) in benchmarks.enumerated() {
            currentBenchmark = name
            progress = Double(index) / total
            connectionStatus = "Running: \(name)"
            logger.info("--- \(name) ---", source: "HTTPBench")

            if let result = await bench() {
                results.append(result)
                logger.info(result.summary, source: "HTTPBench")
            } else {
                logger.warn("\(name): SKIPPED or FAILED", source: "HTTPBench")
            }

            // Brief pause between benchmarks
            try? await Task.sleep(nanoseconds: 300_000_000)
        }

        // Cleanup
        connectionStatus = "Complete"
        progress = 1.0
        currentBenchmark = "Done"

        // Summary
        logger.info("═══════════════════════════════════════════", source: "HTTPBench")
        logger.info("HTTP BENCHMARK RESULTS", source: "HTTPBench")
        logger.info("═══════════════════════════════════════════", source: "HTTPBench")
        for result in results {
            logger.info(result.summary, source: "HTTPBench")
        }
        logger.info("Benchmarks complete: \(results.count)/\(benchmarks.count)", source: "HTTPBench")
        logger.info("═══════════════════════════════════════════", source: "HTTPBench")

        isRunning = false
    }

    // MARK: - Tunnel Setup

    private func setupTunnel() async -> Bool {
        // IMPORTANT: The VPN tunnel runs in the Network Extension process,
        // NOT in the main app process. ZTLPBridge.shared.hasClient may return
        // true from stale state, but we can't add VIP services to a tunnel
        // we don't own. Always create a fresh in-process connection.
        //
        // This is independent from the VPN toggle on the Home tab.

        // Clean up any stale state first
        ZTLPBridge.shared.destroyClient()

        do {
            let identity = try ZTLPBridge.shared.generateIdentity()
            try ZTLPBridge.shared.createClient(identity: identity)

            let config = ZTLPConfigHandle()
            try config.setRelay(relayAddress)
            try config.setTimeoutMs(60000)
            try config.setService("http")

            connectionStatus = "Handshaking with relay..."
            logger.info("Connecting to \(relayAddress) for 'http' service...", source: "HTTPBench")
            try await ZTLPBridge.shared.connect(target: gatewayTarget, config: config)
            ownedConnection = true
            connectionStatus = "Connected"
            logger.info("Noise_XX handshake complete", source: "HTTPBench")
        } catch {
            logger.error("Connection failed: \(error.localizedDescription)", source: "HTTPBench")
            return false
        }

        // Register VIP for "http" service on 127.0.0.2:8080
        do {
            try ZTLPBridge.shared.vipAddService(name: "http", vip: vipAddress, port: vipPort)
            try ZTLPBridge.shared.vipStart()
            connectionStatus = "VIP proxy active (\(baseURL))"
            logger.info("HTTP VIP proxy: \(baseURL) → 'http' service through tunnel", source: "HTTPBench")
            // Give VIP proxy a moment to bind
            try? await Task.sleep(nanoseconds: 500_000_000)
            return true
        } catch {
            logger.error("VIP proxy setup failed: \(error.localizedDescription)", source: "HTTPBench")
            connectionStatus = "VIP setup failed"
            return false
        }
    }

    private func verifyEndpoint() async -> Bool {
        guard let url = URL(string: "\(baseURL)/health") else { return false }

        for attempt in 1...3 {
            do {
                let (_, response) = try await session.data(from: url)
                if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                    logger.info("HTTP endpoint verified (attempt \(attempt))", source: "HTTPBench")
                    return true
                }
            } catch {
                logger.warn("Health check attempt \(attempt) failed: \(error.localizedDescription)", source: "HTTPBench")
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
        return false
    }

    // MARK: - HTTP Ping

    private func benchPing() async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/ping") else { return nil }
        var timings: [Double] = []
        let iterations = 30

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            do {
                let (data, response) = try await session.data(from: url)
                let end = CFAbsoluteTimeGetCurrent()
                if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                    timings.append((end - start) * 1000.0)

                    // Parse server timestamp for one-way calculation
                    if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let serverTs = json["ts"] as? Int64 {
                        let clientTs = Int64(Date().timeIntervalSince1970 * 1000)
                        let clockDiff = abs(clientTs - serverTs)
                        if timings.count == 1 {
                            logger.info("Clock diff client-server: ~\(clockDiff)ms", source: "HTTPBench")
                        }
                    }
                }
            } catch {
                // Skip failed pings
            }
        }

        guard !timings.isEmpty else { return nil }
        return buildResult(name: "HTTP Ping", timings: timings, iterations: timings.count,
                          extraInfo: "\(timings.count)/\(iterations) successful")
    }

    // MARK: - GET (various sizes)

    private func benchGet(size: Int, label: String) async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/echo?size=\(size)") else { return nil }
        var timings: [Double] = []
        let iterations = 20

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            do {
                let (data, response) = try await session.data(from: url)
                let end = CFAbsoluteTimeGetCurrent()
                if let http = response as? HTTPURLResponse, http.statusCode == 200, data.count == size {
                    timings.append((end - start) * 1000.0)
                }
            } catch {
                // Skip
            }
        }

        guard !timings.isEmpty else { return nil }
        let totalBytes = Double(size * timings.count)
        let totalTime = timings.reduce(0, +) / 1000.0
        let throughputMBps = totalTime > 0 ? totalBytes / totalTime / 1_048_576.0 : 0

        return buildResult(name: "GET \(label)", timings: timings, iterations: timings.count,
                          throughputMBps: throughputMBps,
                          extraInfo: "\(String(format: "%.1f", throughputMBps)) MB/s")
    }

    // MARK: - Large Download

    private func benchDownload5MB() async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/download/5") else { return nil }
        var timings: [Double] = []
        let iterations = 5
        let expectedSize = 5 * 1_048_576

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            do {
                let (data, response) = try await session.data(from: url)
                let end = CFAbsoluteTimeGetCurrent()
                if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                    timings.append((end - start) * 1000.0)
                    logger.info("Download: \(data.count) bytes in \(String(format: "%.1f", (end - start) * 1000))ms", source: "HTTPBench")
                }
            } catch {
                logger.warn("Download failed: \(error.localizedDescription)", source: "HTTPBench")
            }
        }

        guard !timings.isEmpty else { return nil }
        let totalBytes = Double(expectedSize * timings.count)
        let totalTime = timings.reduce(0, +) / 1000.0
        let throughputMBps = totalTime > 0 ? totalBytes / totalTime / 1_048_576.0 : 0

        return buildResult(name: "Download 5MB", timings: timings, iterations: timings.count,
                          throughputMBps: throughputMBps,
                          extraInfo: "\(String(format: "%.1f", throughputMBps)) MB/s")
    }

    // MARK: - POST Echo

    private func benchPostEcho(size: Int, label: String) async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/echo") else { return nil }
        let payload = Data(repeating: 0xBE, count: size)
        var timings: [Double] = []
        let iterations = 20

        for _ in 0..<iterations {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = payload
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            request.setValue("\(size)", forHTTPHeaderField: "Content-Length")

            let start = CFAbsoluteTimeGetCurrent()
            do {
                let (data, response) = try await session.data(for: request)
                let end = CFAbsoluteTimeGetCurrent()
                if let http = response as? HTTPURLResponse, http.statusCode == 200, data.count == size {
                    timings.append((end - start) * 1000.0)
                }
            } catch {
                // Skip
            }
        }

        guard !timings.isEmpty else { return nil }
        // Round-trip: sent + received = 2x size
        let totalBytes = Double(size * 2 * timings.count)
        let totalTime = timings.reduce(0, +) / 1000.0
        let throughputMBps = totalTime > 0 ? totalBytes / totalTime / 1_048_576.0 : 0

        return buildResult(name: "POST Echo \(label)", timings: timings, iterations: timings.count,
                          throughputMBps: throughputMBps,
                          extraInfo: "round-trip \(String(format: "%.1f", throughputMBps)) MB/s")
    }

    // MARK: - Upload

    private func benchUpload1MB() async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/upload") else { return nil }
        let payload = Data(repeating: 0xEF, count: 1_048_576)
        var timings: [Double] = []
        let iterations = 5

        for _ in 0..<iterations {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = payload
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            request.setValue("1048576", forHTTPHeaderField: "Content-Length")

            let start = CFAbsoluteTimeGetCurrent()
            do {
                let (data, response) = try await session.data(for: request)
                let end = CFAbsoluteTimeGetCurrent()
                if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                    timings.append((end - start) * 1000.0)

                    // Parse server-side timing
                    if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let serverMs = json["ms"] as? Double,
                       let serverTp = json["throughput_mbps"] as? Double {
                        logger.info("Upload server-side: \(String(format: "%.1f", serverMs))ms, \(String(format: "%.1f", serverTp)) Mbps", source: "HTTPBench")
                    }
                }
            } catch {
                logger.warn("Upload failed: \(error.localizedDescription)", source: "HTTPBench")
            }
        }

        guard !timings.isEmpty else { return nil }
        let totalBytes = Double(1_048_576 * timings.count)
        let totalTime = timings.reduce(0, +) / 1000.0
        let throughputMBps = totalTime > 0 ? totalBytes / totalTime / 1_048_576.0 : 0

        return buildResult(name: "Upload 1MB", timings: timings, iterations: timings.count,
                          throughputMBps: throughputMBps,
                          extraInfo: "\(String(format: "%.1f", throughputMBps)) MB/s upload")
    }

    // MARK: - Concurrent Requests

    private func benchConcurrent() async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/echo?size=10240") else { return nil }
        let concurrency = 5
        let iterations = 3
        var timings: [Double] = []

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()

            // Fire concurrent requests
            await withTaskGroup(of: Bool.self) { group in
                for _ in 0..<concurrency {
                    group.addTask {
                        do {
                            let (data, response) = try await self.session.data(from: url)
                            if let http = response as? HTTPURLResponse,
                               http.statusCode == 200, data.count == 10240 {
                                return true
                            }
                        } catch {}
                        return false
                    }
                }

                var successes = 0
                for await result in group {
                    if result { successes += 1 }
                }

                let end = CFAbsoluteTimeGetCurrent()
                if successes == concurrency {
                    timings.append((end - start) * 1000.0)
                }
                logger.info("Concurrent: \(successes)/\(concurrency) succeeded in \(String(format: "%.1f", (end - start) * 1000))ms", source: "HTTPBench")
            }
        }

        guard !timings.isEmpty else { return nil }
        return buildResult(name: "Concurrent 5x GET", timings: timings, iterations: timings.count,
                          extraInfo: "\(concurrency) parallel 10KB GETs")
    }

    // MARK: - Time-to-First-Byte

    private func benchTTFB() async -> BenchmarkResult? {
        guard let url = URL(string: "\(baseURL)/download/1") else { return nil }
        var timings: [Double] = []
        let iterations = 10

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()

            // Use a delegate-based approach to measure TTFB
            do {
                let request = URLRequest(url: url)

                // Use bytes async sequence to get first byte time
                let (bytes, response) = try await session.bytes(from: url)
                if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                    // Read first chunk
                    var iterator = bytes.makeAsyncIterator()
                    if let _ = try await iterator.next() {
                        let ttfb = CFAbsoluteTimeGetCurrent()
                        timings.append((ttfb - start) * 1000.0)

                        // Drain the rest to not leave connections hanging
                        while let _ = try await iterator.next() {}
                    }
                }
            } catch {
                // Skip
            }
        }

        guard !timings.isEmpty else { return nil }
        return buildResult(name: "Time-to-First-Byte", timings: timings, iterations: timings.count,
                          extraInfo: "1MB download, TTFB only")
    }

    // MARK: - Helpers

    private func buildResult(
        name: String,
        timings: [Double],
        iterations: Int,
        throughputMBps: Double? = nil,
        extraInfo: String? = nil
    ) -> BenchmarkResult {
        let sorted = timings.sorted()
        let totalMs = timings.reduce(0, +)

        // Trim outliers (top/bottom 10%)
        let trimCount = max(0, timings.count / 10)
        let trimmed = Array(sorted.dropFirst(trimCount).dropLast(trimCount))
        let avgTimings = trimmed.isEmpty ? sorted : trimmed
        let avg = avgTimings.reduce(0, +) / Double(avgTimings.count)

        return BenchmarkResult(
            name: name,
            iterations: iterations,
            totalMs: totalMs,
            avgMs: avg,
            minMs: sorted.first ?? 0,
            maxMs: sorted.last ?? 0,
            opsPerSec: totalMs > 0 ? Double(iterations) / (totalMs / 1000.0) : 0,
            throughputMBps: throughputMBps,
            extraInfo: extraInfo
        )
    }

    private func deviceInfo() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machine = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        return "\(machine) | \(osVersion)"
    }
}
