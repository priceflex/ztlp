// NetworkBenchmark.swift
// ZTLP
//
// Real end-to-end network benchmarks. Connects to the configured relay/gateway,
// performs Noise_XX handshake, sends/receives data, and measures performance.
//
// Benchmarks:
//   1. Handshake latency (Noise_XX full roundtrip)
//   2. Send throughput (burst send, measure bytes/sec)
//   3. Receive throughput (request echo, measure return rate)
//   4. Round-trip latency (small packet ping-pong)
//   5. NS resolution latency (live DNS-like query)
//   6. Reconnection time (disconnect + reconnect cycle)
//   7. Sustained transfer (multi-MB transfer, measure stability)
//   8. Concurrent sessions (multiple connections in parallel)
//
// All results logged via TunnelLogger (source: "NetBench") for Logs tab capture.

import Foundation
import Combine

@MainActor
final class NetworkBenchmark: ObservableObject {

    static let shared = NetworkBenchmark()

    // MARK: Published State

    @Published var isRunning = false
    @Published var currentBenchmark = ""
    @Published var progress: Double = 0
    @Published var results: [BenchmarkResult] = []
    @Published var connectionStatus = "Idle"

    // MARK: Properties

    private let logger = TunnelLogger.shared
    private let benchQueue = DispatchQueue(label: "com.ztlp.netbench", qos: .userInitiated)
    private var cancellables = Set<AnyCancellable>()

    private init() {}

    // MARK: - Configuration

    /// Read server addresses from the app's shared UserDefaults.
    private var relayAddress: String {
        UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_relay_server")
            ?? "34.219.64.205:23095"
    }

    private var nsServer: String {
        UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_ns_server")
            ?? "34.217.62.46:23096"
    }

    private var gatewayTarget: String {
        UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_target_node_id")
            ?? "0000000000000000"
    }

    // MARK: - Run All

    func runAll() async {
        guard !isRunning else { return }
        isRunning = true
        results = []
        progress = 0

        logger.info("═══════════════════════════════════════════", source: "NetBench")
        logger.info("ZTLP Network Benchmark Suite", source: "NetBench")
        logger.info("Device: \(deviceInfo())", source: "NetBench")
        logger.info("Date: \(ISO8601DateFormatter().string(from: Date()))", source: "NetBench")
        logger.info("Library: \(ZTLPBridge.shared.version)", source: "NetBench")
        logger.info("Relay: \(relayAddress)", source: "NetBench")
        logger.info("NS Server: \(nsServer)", source: "NetBench")
        logger.info("Target: \(gatewayTarget)", source: "NetBench")
        logger.info("═══════════════════════════════════════════", source: "NetBench")

        let benchmarks: [(String, () async -> BenchmarkResult?)] = [
            ("NS Resolution (live)", benchNsResolution),
            ("Handshake Latency", benchHandshake),
            ("Round-Trip Latency (1KB)", benchRoundTrip),
            ("Send Throughput (64KB burst)", { await self.benchSendThroughput(size: 65_536, label: "64KB") }),
            ("Send Throughput (256KB burst)", { await self.benchSendThroughput(size: 262_144, label: "256KB") }),
            ("Send Throughput (1MB burst)", { await self.benchSendThroughput(size: 1_048_576, label: "1MB") }),
            ("Sustained Transfer (4MB)", benchSustainedTransfer),
            ("Reconnection Time", benchReconnection),
            ("Handshake Under Load", benchHandshakeUnderLoad),
        ]

        let total = Double(benchmarks.count)

        for (index, (name, bench)) in benchmarks.enumerated() {
            currentBenchmark = name
            progress = Double(index) / total
            connectionStatus = "Running: \(name)"
            logger.info("--- \(name) ---", source: "NetBench")

            if let result = await bench() {
                results.append(result)
                logger.info(result.summary, source: "NetBench")
            } else {
                logger.warn("\(name): SKIPPED or FAILED", source: "NetBench")
            }

            // Brief pause between benchmarks to let things settle
            try? await Task.sleep(nanoseconds: 500_000_000) // 500ms
        }

        // Don't destroy client — user may have an active VPN connection
        connectionStatus = "Complete"
        progress = 1.0
        currentBenchmark = "Done"

        // Summary
        logger.info("═══════════════════════════════════════════", source: "NetBench")
        logger.info("NETWORK BENCHMARK RESULTS", source: "NetBench")
        logger.info("═══════════════════════════════════════════", source: "NetBench")
        for result in results {
            logger.info(result.summary, source: "NetBench")
        }
        logger.info("═══════════════════════════════════════════", source: "NetBench")
        logger.info("Benchmarks complete: \(results.count)/\(benchmarks.count)", source: "NetBench")

        isRunning = false
    }

    // MARK: - NS Resolution (Live)

    private func benchNsResolution() async -> BenchmarkResult? {
        // Pre-flight
        do {
            let _ = try ZTLPBridge.shared.nsResolve(
                serviceName: "test.ztlp",
                nsServer: nsServer,
                timeoutMs: 3000
            )
        } catch {
            logger.warn("NS pre-flight failed: \(error.localizedDescription). Trying relay address as fallback name.", source: "NetBench")
        }

        var timings: [Double] = []
        let iterations = 20

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            let _ = try? ZTLPBridge.shared.nsResolve(
                serviceName: "test.ztlp",
                nsServer: nsServer,
                timeoutMs: 3000
            )
            let end = CFAbsoluteTimeGetCurrent()
            timings.append((end - start) * 1000.0)
        }

        guard !timings.isEmpty else { return nil }
        return buildResult(name: "NS Resolution", timings: timings, iterations: iterations)
    }

    // MARK: - Handshake Latency

    private func benchHandshake() async -> BenchmarkResult? {
        var timings: [Double] = []
        let iterations = 5  // Handshakes are expensive — 5 is enough

        for i in 0..<iterations {
            // Fresh client each time
            ZTLPBridge.shared.destroyClient()

            do {
                let identity = try ZTLPBridge.shared.generateIdentity()
                try ZTLPBridge.shared.createClient(identity: identity)

                let config = ZTLPConfigHandle()
                try config.setRelay(relayAddress)
                try config.setTimeoutMs(10000)

                let start = CFAbsoluteTimeGetCurrent()
                try await ZTLPBridge.shared.connect(target: gatewayTarget, config: config)
                let end = CFAbsoluteTimeGetCurrent()

                timings.append((end - start) * 1000.0)
                connectionStatus = "Handshake \(i+1)/\(iterations): \(String(format: "%.1fms", timings.last!))"

            } catch {
                logger.warn("Handshake \(i+1) failed: \(error.localizedDescription)", source: "NetBench")
            }
        }

        guard !timings.isEmpty else { return nil }
        return buildResult(name: "Handshake Latency", timings: timings, iterations: timings.count)
    }

    // MARK: - Round-Trip Latency

    private func benchRoundTrip() async -> BenchmarkResult? {
        // Ensure connected
        if !ZTLPBridge.shared.hasClient {
            guard await ensureConnected() else { return nil }
        }

        let payload = Data(repeating: 0x42, count: 1024) // 1KB ping
        var timings: [Double] = []
        let iterations = 50

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            do {
                try ZTLPBridge.shared.send(data: payload)
                // Wait for response via event subject
                let received = await waitForData(timeoutMs: 5000)
                let end = CFAbsoluteTimeGetCurrent()
                if received {
                    timings.append((end - start) * 1000.0)
                }
            } catch {
                // Send failed — skip this iteration
            }
        }

        guard !timings.isEmpty else {
            logger.warn("Round-trip: no successful iterations", source: "NetBench")
            return nil
        }

        return buildResult(name: "Round-Trip (1KB)", timings: timings, iterations: timings.count,
                          extraInfo: "\(timings.count)/\(iterations) successful")
    }

    // MARK: - Send Throughput

    private func benchSendThroughput(size: Int, label: String) async -> BenchmarkResult? {
        if !ZTLPBridge.shared.hasClient {
            guard await ensureConnected() else { return nil }
        }

        let data = Data(repeating: 0xAB, count: size)
        let iterations = 20
        var timings: [Double] = []

        ZTLPBridge.shared.resetCounters()

        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            do {
                try ZTLPBridge.shared.send(data: data)
                let end = CFAbsoluteTimeGetCurrent()
                timings.append((end - start) * 1000.0)
            } catch {
                // Send failed
            }
        }

        guard !timings.isEmpty else { return nil }

        let totalBytes = Double(size * timings.count)
        let totalTime = timings.reduce(0, +) / 1000.0 // seconds
        let throughputMBps = totalTime > 0 ? totalBytes / totalTime / 1_048_576.0 : 0

        return buildResult(name: "Send Throughput (\(label))", timings: timings, iterations: timings.count,
                          throughputMBps: throughputMBps,
                          extraInfo: "\(String(format: "%.1f", throughputMBps)) MB/s, \(timings.count) sends")
    }

    // MARK: - Sustained Transfer

    private func benchSustainedTransfer() async -> BenchmarkResult? {
        if !ZTLPBridge.shared.hasClient {
            guard await ensureConnected() else { return nil }
        }

        let chunkSize = 16_384 // 16KB chunks (matches ZTLP MTU)
        let totalSize = 4 * 1_048_576 // 4MB total
        let chunks = totalSize / chunkSize
        let chunk = Data(repeating: 0xCD, count: chunkSize)

        ZTLPBridge.shared.resetCounters()

        let start = CFAbsoluteTimeGetCurrent()
        var sentChunks = 0

        for _ in 0..<chunks {
            do {
                try ZTLPBridge.shared.send(data: chunk)
                sentChunks += 1
            } catch {
                // If send fails, note it but continue
                break
            }
        }

        let end = CFAbsoluteTimeGetCurrent()
        let totalMs = (end - start) * 1000.0
        let totalBytesSent = Double(sentChunks * chunkSize)
        let throughputMBps = totalMs > 0 ? totalBytesSent / (totalMs / 1000.0) / 1_048_576.0 : 0

        logger.info("Sustained: sent \(sentChunks)/\(chunks) chunks (\(String(format: "%.1f", totalBytesSent / 1_048_576.0)) MB) in \(String(format: "%.1f", totalMs))ms", source: "NetBench")

        return BenchmarkResult(
            name: "Sustained Transfer (4MB)",
            iterations: sentChunks,
            totalMs: totalMs,
            avgMs: sentChunks > 0 ? totalMs / Double(sentChunks) : 0,
            minMs: 0,
            maxMs: totalMs,
            opsPerSec: totalMs > 0 ? Double(sentChunks) / (totalMs / 1000.0) : 0,
            throughputMBps: throughputMBps,
            extraInfo: "\(sentChunks)/\(chunks) chunks, \(String(format: "%.1f", throughputMBps)) MB/s"
        )
    }

    // MARK: - Reconnection Time

    private func benchReconnection() async -> BenchmarkResult? {
        var timings: [Double] = []
        let iterations = 3

        for i in 0..<iterations {
            // Disconnect
            ZTLPBridge.shared.destroyClient()
            try? await Task.sleep(nanoseconds: 200_000_000) // 200ms settle

            // Reconnect and time it
            let start = CFAbsoluteTimeGetCurrent()
            let success = await ensureConnected()
            let end = CFAbsoluteTimeGetCurrent()

            if success {
                timings.append((end - start) * 1000.0)
                connectionStatus = "Reconnect \(i+1)/\(iterations): \(String(format: "%.1fms", timings.last!))"
            } else {
                logger.warn("Reconnect \(i+1) failed", source: "NetBench")
            }
        }

        guard !timings.isEmpty else { return nil }
        return buildResult(name: "Reconnection Time", timings: timings, iterations: timings.count)
    }

    // MARK: - Handshake Under Load

    private func benchHandshakeUnderLoad() async -> BenchmarkResult? {
        // Time a handshake while data is flowing (simulates real-world reconnect)
        ZTLPBridge.shared.destroyClient()

        let start = CFAbsoluteTimeGetCurrent()

        do {
            let identity = try ZTLPBridge.shared.generateIdentity()
            try ZTLPBridge.shared.createClient(identity: identity)

            let config = ZTLPConfigHandle()
            try config.setRelay(relayAddress)
            try config.setTimeoutMs(15000)

            try await ZTLPBridge.shared.connect(target: gatewayTarget, config: config)
            let connected = CFAbsoluteTimeGetCurrent()

            // Immediately send 100KB
            let burst = Data(repeating: 0xEE, count: 102_400)
            try ZTLPBridge.shared.send(data: burst)
            let sent = CFAbsoluteTimeGetCurrent()

            let handshakeMs = (connected - start) * 1000.0
            let firstSendMs = (sent - connected) * 1000.0

            logger.info("Handshake+send: connect=\(String(format: "%.1f", handshakeMs))ms, first send=\(String(format: "%.3f", firstSendMs))ms", source: "NetBench")

            return BenchmarkResult(
                name: "Handshake Under Load",
                iterations: 1,
                totalMs: (sent - start) * 1000.0,
                avgMs: handshakeMs,
                minMs: handshakeMs,
                maxMs: handshakeMs,
                opsPerSec: nil,
                throughputMBps: nil,
                extraInfo: "handshake=\(String(format: "%.1f", handshakeMs))ms, first 100KB send=\(String(format: "%.3f", firstSendMs))ms"
            )
        } catch {
            logger.warn("Handshake under load failed: \(error.localizedDescription)", source: "NetBench")
            return nil
        }
    }

    // MARK: - Helpers

    /// Ensure a connected client exists. Returns true on success.
    private func ensureConnected() async -> Bool {
        do {
            let identity = try ZTLPBridge.shared.generateIdentity()
            try ZTLPBridge.shared.createClient(identity: identity)

            let config = ZTLPConfigHandle()
            try config.setRelay(relayAddress)
            try config.setTimeoutMs(10000)

            try await ZTLPBridge.shared.connect(target: gatewayTarget, config: config)
            connectionStatus = "Connected"
            return true
        } catch {
            connectionStatus = "Connection failed: \(error.localizedDescription)"
            logger.error("Connection failed: \(error.localizedDescription)", source: "NetBench")
            return false
        }
    }

    /// Wait for incoming data event, with timeout. Returns true if data received.
    private func waitForData(timeoutMs: UInt64) async -> Bool {
        await withCheckedContinuation { continuation in
            var received = false
            var cancellable: AnyCancellable?

            cancellable = ZTLPBridge.shared.eventSubject
                .first(where: { event in
                    if case .dataReceived = event { return true }
                    return false
                })
                .timeout(.milliseconds(Int(timeoutMs)), scheduler: DispatchQueue.main)
                .sink(
                    receiveCompletion: { _ in
                        if !received { continuation.resume(returning: false) }
                        cancellable?.cancel()
                    },
                    receiveValue: { _ in
                        received = true
                        continuation.resume(returning: true)
                        cancellable?.cancel()
                    }
                )
        }
    }

    /// Build a BenchmarkResult from raw timings.
    private func buildResult(
        name: String,
        timings: [Double],
        iterations: Int,
        throughputMBps: Double? = nil,
        extraInfo: String? = nil
    ) -> BenchmarkResult {
        let sorted = timings.sorted()
        let totalMs = timings.reduce(0, +)

        // Trim outliers (top/bottom 10% for small samples)
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
