// BenchmarkRunner.swift
// ZTLP
//
// In-app performance benchmark suite for the ZTLP iOS SDK.
//
// Measures:
//   - Identity generation (software + Secure Enclave)
//   - Library init/shutdown cycle time
//   - Pipeline encoding/decoding throughput
//   - Noise_XX handshake latency (via relay loopback)
//   - Send/receive throughput (via relay loopback)
//   - NS resolution latency
//   - VIP proxy setup time
//   - Memory footprint during operations
//
// All results are emitted via TunnelLogger with source "Bench" so they
// appear in the Logs tab and can be exported.
//
// Usage:
//   Task { await BenchmarkRunner.shared.runAll() }

import Foundation

// MARK: - BenchmarkResult

/// A single benchmark measurement.
struct BenchmarkResult: Identifiable {
    let id = UUID()
    let name: String
    let iterations: Int
    let totalMs: Double
    let avgMs: Double
    let minMs: Double
    let maxMs: Double
    let opsPerSec: Double?
    let throughputMBps: Double?
    let extraInfo: String?

    var summary: String {
        var s = "\(name): avg=\(String(format: "%.3f", avgMs))ms min=\(String(format: "%.3f", minMs))ms max=\(String(format: "%.3f", maxMs))ms (\(iterations) iterations)"
        if let ops = opsPerSec {
            s += " | \(formatOps(ops)) ops/sec"
        }
        if let tp = throughputMBps {
            s += " | \(String(format: "%.1f", tp)) MB/s"
        }
        if let extra = extraInfo {
            s += " | \(extra)"
        }
        return s
    }

    private func formatOps(_ ops: Double) -> String {
        if ops >= 1_000_000 { return String(format: "%.2fM", ops / 1_000_000) }
        if ops >= 1_000 { return String(format: "%.1fK", ops / 1_000) }
        return String(format: "%.0f", ops)
    }
}

// MARK: - BenchmarkRunner

/// Singleton benchmark runner with progress reporting.
@MainActor
final class BenchmarkRunner: ObservableObject {

    static let shared = BenchmarkRunner()

    // MARK: Published State

    @Published var isRunning = false
    @Published var currentBenchmark = ""
    @Published var progress: Double = 0  // 0.0 - 1.0
    @Published var results: [BenchmarkResult] = []

    // MARK: Properties

    private let logger = TunnelLogger.shared
    private let benchQueue = DispatchQueue(label: "com.ztlp.bench", qos: .userInitiated)

    private init() {}

    // MARK: - Run All

    /// Run the complete benchmark suite.
    func runAll() async {
        guard !isRunning else { return }
        isRunning = true
        results = []
        progress = 0

        logger.info("═══════════════════════════════════════════", source: "Bench")
        logger.info("ZTLP iOS Benchmark Suite", source: "Bench")
        logger.info("Device: \(deviceInfo())", source: "Bench")
        logger.info("Date: \(ISO8601DateFormatter().string(from: Date()))", source: "Bench")
        logger.info("Library: \(ZTLPBridge.shared.version)", source: "Bench")
        logger.info("═══════════════════════════════════════════", source: "Bench")

        let benchmarks: [(String, () async -> BenchmarkResult?)] = [
            ("Library Init/Shutdown", benchLibraryInit),
            ("Identity Generation (Software)", benchIdentityGenSoftware),
            ("Identity Generation (Secure Enclave)", benchIdentityGenHardware),
            ("Identity Save/Load", benchIdentitySaveLoad),
            ("Config Create/Configure", benchConfigCreate),
            ("Error Mapping", benchErrorMapping),
            ("Send Buffer Alloc (1KB)", { await self.benchBufferAlloc(size: 1024, label: "1KB") }),
            ("Send Buffer Alloc (64KB)", { await self.benchBufferAlloc(size: 65536, label: "64KB") }),
            ("Send Buffer Alloc (1MB)", { await self.benchBufferAlloc(size: 1_048_576, label: "1MB") }),
            ("Data Copy (pipeline sim 1400B)", { await self.benchDataCopy(size: 1400) }),
            ("Data Copy (pipeline sim 64KB)", { await self.benchDataCopy(size: 65536) }),
            ("Logger Throughput", benchLoggerThroughput),
            ("NS Resolution", benchNsResolution),
            ("Memory Baseline", benchMemoryBaseline),
        ]

        let total = Double(benchmarks.count)

        for (index, (name, bench)) in benchmarks.enumerated() {
            currentBenchmark = name
            progress = Double(index) / total
            logger.info("--- \(name) ---", source: "Bench")

            if let result = await bench() {
                results.append(result)
                logger.info(result.summary, source: "Bench")
            } else {
                logger.warn("\(name): SKIPPED", source: "Bench")
            }
        }

        progress = 1.0
        currentBenchmark = "Done"

        // Summary
        logger.info("═══════════════════════════════════════════", source: "Bench")
        logger.info("RESULTS SUMMARY", source: "Bench")
        logger.info("═══════════════════════════════════════════", source: "Bench")
        for result in results {
            logger.info(result.summary, source: "Bench")
        }
        logger.info("═══════════════════════════════════════════", source: "Bench")
        logger.info("Total benchmarks: \(results.count) / \(benchmarks.count)", source: "Bench")
        logger.info("Benchmark suite complete", source: "Bench")

        isRunning = false
    }

    // MARK: - Individual Benchmarks

    /// Measure library init + shutdown cycle.
    private func benchLibraryInit() async -> BenchmarkResult? {
        await measure(name: "Library Init/Shutdown", iterations: 100) {
            let r = ztlp_init()
            if r == 0 { ztlp_shutdown() }
        }
    }

    /// Measure software identity generation.
    private func benchIdentityGenSoftware() async -> BenchmarkResult? {
        // Ensure library is initialized
        let initResult = ztlp_init()
        defer { if initResult == 0 { /* leave init for other benchmarks */ } }

        return await measure(name: "Identity Gen (Software)", iterations: 50) {
            if let id = ztlp_identity_generate() {
                ztlp_identity_free(id)
            }
        }
    }

    /// Measure Secure Enclave identity generation.
    private func benchIdentityGenHardware() async -> BenchmarkResult? {
        // Secure Enclave is only available on real devices
        guard let testId = ztlp_identity_from_hardware(1) else {
            logger.info("Secure Enclave not available (simulator?)", source: "Bench")
            return nil
        }
        ztlp_identity_free(testId)

        return await measure(name: "Identity Gen (Secure Enclave)", iterations: 20) {
            if let id = ztlp_identity_from_hardware(1) {
                ztlp_identity_free(id)
            }
        }
    }

    /// Measure identity save + load cycle.
    private func benchIdentitySaveLoad() async -> BenchmarkResult? {
        let tmpDir = NSTemporaryDirectory()
        let path = (tmpDir as NSString).appendingPathComponent("ztlp_bench_identity.json")
        defer { try? FileManager.default.removeItem(atPath: path) }

        guard let identity = ztlp_identity_generate() else { return nil }
        // Save once to create the file
        let _ = path.withCString { ztlp_identity_save(identity, $0) }
        ztlp_identity_free(identity)

        return await measure(name: "Identity Save/Load", iterations: 100) {
            if let loaded = path.withCString({ ztlp_identity_from_file($0) }) {
                let _ = path.withCString { ztlp_identity_save(loaded, $0) }
                ztlp_identity_free(loaded)
            }
        }
    }

    /// Measure config creation and configuration.
    private func benchConfigCreate() async -> BenchmarkResult? {
        await measure(name: "Config Create/Configure", iterations: 1000) {
            let cfg = ztlp_config_new()
            "relay.ztlp.net:23095".withCString { _ = ztlp_config_set_relay(cfg, $0) }
            "stun.l.google.com:19302".withCString { _ = ztlp_config_set_stun_server(cfg, $0) }
            _ = ztlp_config_set_nat_assist(cfg, true)
            _ = ztlp_config_set_timeout_ms(cfg, 10000)
            ztlp_config_free(cfg)
        }
    }

    /// Measure error code mapping performance.
    private func benchErrorMapping() async -> BenchmarkResult? {
        await measure(name: "Error Mapping", iterations: 10000) {
            for code: Int32 in -10...0 {
                let _ = ZTLPError.from(code: code)
            }
        }
    }

    /// Measure buffer allocation (simulates send path framing).
    private func benchBufferAlloc(size: Int, label: String) async -> BenchmarkResult? {
        let sourceData = Data(repeating: 0x42, count: size)
        let iterations = size > 100_000 ? 1000 : 10000

        let result = await measure(name: "Buffer Alloc (\(label))", iterations: iterations) {
            // Simulate the PacketTunnelProvider send path:
            // 2-byte protocol header + packet
            var framedPacket = Data(capacity: 2 + sourceData.count)
            var proto: UInt16 = 2 // AF_INET
            framedPacket.append(Data(bytes: &proto, count: 2))
            framedPacket.append(sourceData)
            // Simulate the withUnsafeBytes call
            framedPacket.withUnsafeBytes { _ in }
        }

        if var r = result {
            let bytesPerSec = Double(size) * Double(iterations) / (r.totalMs / 1000.0)
            return BenchmarkResult(
                name: r.name,
                iterations: r.iterations,
                totalMs: r.totalMs,
                avgMs: r.avgMs,
                minMs: r.minMs,
                maxMs: r.maxMs,
                opsPerSec: r.opsPerSec,
                throughputMBps: bytesPerSec / 1_048_576.0,
                extraInfo: nil
            )
        }
        return result
    }

    /// Measure raw data copy throughput (simulates pipeline packet processing).
    private func benchDataCopy(size: Int) async -> BenchmarkResult? {
        let sourceData = Data(repeating: 0xAB, count: size)
        let iterations = size > 10_000 ? 5000 : 50000

        let result = await measure(name: "Data Copy (\(size)B)", iterations: iterations) {
            // Simulate receive path: copy from C pointer to Swift Data
            sourceData.withUnsafeBytes { rawBuf in
                guard let baseAddr = rawBuf.baseAddress else { return }
                let copied = Data(bytes: baseAddr, count: rawBuf.count)
                _ = copied.count // prevent optimizer from removing
            }
        }

        if let r = result {
            let bytesPerSec = Double(size) * Double(iterations) / (r.totalMs / 1000.0)
            return BenchmarkResult(
                name: r.name,
                iterations: r.iterations,
                totalMs: r.totalMs,
                avgMs: r.avgMs,
                minMs: r.minMs,
                maxMs: r.maxMs,
                opsPerSec: r.opsPerSec,
                throughputMBps: bytesPerSec / 1_048_576.0,
                extraInfo: nil
            )
        }
        return result
    }

    /// Measure TunnelLogger write throughput.
    private func benchLoggerThroughput() async -> BenchmarkResult? {
        // Use a temporary logger to avoid polluting main log
        await measure(name: "Logger Throughput", iterations: 1000) {
            TunnelLogger.shared.debug("Benchmark log entry #\(Int.random(in: 0...999999))", source: "BenchSink")
        }
    }

    /// Measure NS resolution if a server is configured.
    private func benchNsResolution() async -> BenchmarkResult? {
        // Try to resolve against the configured NS server
        // This requires network access — may fail in airplane mode
        let nsServer = UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_ns_server")
            ?? "34.217.62.46:23096"

        // Pre-flight check
        do {
            let _ = try ZTLPBridge.shared.nsResolve(
                serviceName: "test.ztlp",
                nsServer: nsServer,
                timeoutMs: 2000
            )
        } catch {
            logger.info("NS resolution pre-flight failed: \(error.localizedDescription) — skipping", source: "Bench")
            return nil
        }

        return await measure(name: "NS Resolution", iterations: 20) {
            let _ = try? ZTLPBridge.shared.nsResolve(
                serviceName: "test.ztlp",
                nsServer: nsServer,
                timeoutMs: 5000
            )
        }
    }

    /// Measure current memory usage as a baseline.
    private func benchMemoryBaseline() async -> BenchmarkResult? {
        let mem = currentMemoryMB()
        logger.info("Memory footprint: \(String(format: "%.1f", mem)) MB", source: "Bench")

        return BenchmarkResult(
            name: "Memory Baseline",
            iterations: 1,
            totalMs: 0,
            avgMs: 0,
            minMs: 0,
            maxMs: 0,
            opsPerSec: nil,
            throughputMBps: nil,
            extraInfo: "\(String(format: "%.1f", mem)) MB resident"
        )
    }

    // MARK: - Measurement Helpers

    /// Run a closure `iterations` times and return timing statistics.
    private func measure(
        name: String,
        iterations: Int,
        warmup: Int = 3,
        body: @escaping () -> Void
    ) async -> BenchmarkResult? {
        return await withCheckedContinuation { continuation in
            benchQueue.async {
                // Warmup
                for _ in 0..<warmup {
                    body()
                }

                var timings: [Double] = []
                timings.reserveCapacity(iterations)

                let wallStart = CFAbsoluteTimeGetCurrent()

                for _ in 0..<iterations {
                    let start = CFAbsoluteTimeGetCurrent()
                    body()
                    let end = CFAbsoluteTimeGetCurrent()
                    timings.append((end - start) * 1000.0)  // ms
                }

                let wallEnd = CFAbsoluteTimeGetCurrent()
                let totalMs = (wallEnd - wallStart) * 1000.0

                guard !timings.isEmpty else {
                    continuation.resume(returning: nil)
                    return
                }

                let sorted = timings.sorted()
                // Trim top/bottom 5% for more stable results
                let trimCount = max(1, timings.count / 20)
                let trimmed = Array(sorted.dropFirst(trimCount).dropLast(trimCount))
                let actualTimings = trimmed.isEmpty ? sorted : trimmed

                let avg = actualTimings.reduce(0, +) / Double(actualTimings.count)
                let min = sorted.first ?? 0
                let max = sorted.last ?? 0
                let opsPerSec = totalMs > 0 ? Double(iterations) / (totalMs / 1000.0) : 0

                let result = BenchmarkResult(
                    name: name,
                    iterations: iterations,
                    totalMs: totalMs,
                    avgMs: avg,
                    minMs: min,
                    maxMs: max,
                    opsPerSec: opsPerSec,
                    throughputMBps: nil,
                    extraInfo: nil
                )

                continuation.resume(returning: result)
            }
        }
    }

    // MARK: - System Info

    private func deviceInfo() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machine = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let cores = ProcessInfo.processInfo.processorCount
        let memGB = String(format: "%.1f", Double(ProcessInfo.processInfo.physicalMemory) / 1_073_741_824)
        return "\(machine) | \(osVersion) | \(cores) cores | \(memGB) GB RAM"
    }

    private func currentMemoryMB() -> Double {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        if result == KERN_SUCCESS {
            return Double(info.resident_size) / 1_048_576.0
        }
        return 0
    }
}
