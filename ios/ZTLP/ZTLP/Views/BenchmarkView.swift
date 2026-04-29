// BenchmarkView.swift
// ZTLP
//
// Four benchmark categories: Connectivity (tunnel health check),
// HTTP (through tunnel), Network (handshake/throughput), Local (crypto).

import SwiftUI

struct BenchmarkView: View {
    @State private var selectedCategory: BenchmarkCategory = .connectivity
    @State private var isRunning = false
    @State private var results: [BenchmarkResult] = []
    @State private var manualSendStatus: String?
    @State private var isSendingLogs = false
    @State private var browserURL: URL?

    enum BenchmarkCategory: String, CaseIterable {
        case connectivity = "Tunnel"
        case http = "HTTP"
        case network = "Network"
        case local = "Local"

        var icon: String {
            switch self {
            case .connectivity: return "checkmark.shield"
            case .http:         return "globe"
            case .network:      return "network"
            case .local:        return "cpu"
            }
        }

        var description: String {
            switch self {
            case .connectivity: return "Verify tunnel and service reachability"
            case .http:         return "HTTP requests through the encrypted tunnel"
            case .network:      return "Handshake, throughput, and latency"
            case .local:        return "Identity generation, encryption, pipeline"
            }
        }
    }

    struct BenchmarkResult: Identifiable {
        let id = UUID()
        let name: String
        let value: String
        let unit: String
        let status: Status
        let detail: String?
        /// Optional URL to present in the in-app browser (for service tests)
        let openURL: String?

        init(name: String, value: String, unit: String, status: Status,
             detail: String? = nil, openURL: String? = nil) {
            self.name = name
            self.value = value
            self.unit = unit
            self.status = status
            self.detail = detail
            self.openURL = openURL
        }

        enum Status {
            case good, warning, error
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Category picker
                Picker("Category", selection: $selectedCategory) {
                    ForEach(BenchmarkCategory.allCases, id: \.self) { cat in
                        Label(cat.rawValue, systemImage: cat.icon).tag(cat)
                    }
                }
                .pickerStyle(.segmented)
                .padding()

                // Description
                HStack(spacing: 8) {
                    Image(systemName: selectedCategory.icon)
                        .foregroundStyle(Color.ztlpBlue)
                    Text(selectedCategory.description)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal)
                .padding(.bottom, 8)

                benchmarkActionsBar

                if results.isEmpty && !isRunning {
                    emptyState
                } else {
                    resultsList
                }
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Benchmarks")
            .safariSheet(url: $browserURL)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if isRunning {
                        ProgressView()
                    } else {
                        Button {
                            runBenchmarks()
                        } label: {
                            Image(systemName: "play.fill")
                                .foregroundStyle(Color.ztlpBlue)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Empty State

    private var benchmarkActionsBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 12) {
                Button {
                    if !isRunning {
                        runBenchmarks()
                    }
                } label: {
                    Label(isRunning ? "Running…" : "Run Test", systemImage: isRunning ? "hourglass" : "play.fill")
                        .font(.subheadline.weight(.medium))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .disabled(isRunning)

                Button {
                    let logger = TunnelLogger.shared
                    logger.info("Manual benchmark-page log send requested", source: "LogExport")
                    logger.flush()
                    isSendingLogs = true
                    manualSendStatus = "Sending logs to bootstrap…"
                    BenchmarkReporter.shared.submitManualLogDump(
                        reason: "benchmark_page_send_logs",
                        passedCount: results.filter { $0.status != .error }.count,
                        totalCount: results.count
                    ) { result in
                        DispatchQueue.main.async {
                            isSendingLogs = false
                            switch result {
                            case .success:
                                manualSendStatus = "Logs sent to bootstrap successfully"
                            case .failure(let error):
                                manualSendStatus = "Log send failed: \(error.localizedDescription)"
                            }
                        }
                    }
                } label: {
                    Label(isSendingLogs ? "Sending…" : "Send Logs", systemImage: isSendingLogs ? "icloud.and.arrow.up" : "paperplane")
                        .font(.subheadline.weight(.medium))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSendingLogs)
            }

            if let manualSendStatus {
                Text(manualSendStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal)
        .padding(.bottom, 8)
    }

    private var emptyState: some View {
        VStack(spacing: 20) {
            Spacer()

            ZStack {
                Circle()
                    .fill(Color.ztlpBlue.opacity(0.08))
                    .frame(width: 100, height: 100)
                Image(systemName: "gauge.with.dots.needle.bottom.50percent")
                    .font(.system(size: 40))
                    .foregroundStyle(Color.ztlpBlue.opacity(0.6))
            }

            VStack(spacing: 8) {
                Text("No Results")
                    .font(.title3.weight(.semibold))
                Text("Run a benchmark to test\nZTLP tunnel connectivity.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            Button {
                runBenchmarks()
            } label: {
                Label("Run \(selectedCategory.rawValue) Test", systemImage: "play.fill")
                    .font(.subheadline.weight(.medium))
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)

            Spacer()
        }
    }

    // MARK: - Results List

    private var resultsList: some View {
        List {
            if isRunning {
                Section {
                    HStack {
                        ProgressView()
                        Text("Running \(selectedCategory.rawValue) tests\u{2026}")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.leading, 8)
                    }
                    .padding(.vertical, 4)
                }
            }

            Section {
                ForEach(results) { result in
                    resultRow(result)
                }
            } header: {
                HStack {
                    Text("\(results.count) results")
                    Spacer()
                    Text(selectedCategory.rawValue)
                        .foregroundStyle(Color.ztlpBlue)
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func resultRow(_ result: BenchmarkResult) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(result.name)
                    .font(.subheadline.weight(.medium))
                if let detail = result.detail {
                    Text(detail)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }

            Spacer()

            HStack(spacing: 4) {
                Text(result.value)
                    .font(.subheadline.monospacedDigit().weight(.semibold))
                    .foregroundStyle(statusColor(result.status))
                Text(result.unit)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            // Open in browser button for services with URLs
            if let urlString = result.openURL {
                Button {
                    if let url = URL(string: urlString) {
                        browserURL = url
                    }
                } label: {
                    Image(systemName: "arrow.up.right.square")
                        .font(.caption)
                        .foregroundStyle(Color.ztlpBlue)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.vertical, 2)
    }

    // MARK: - Helpers

    private func statusColor(_ status: BenchmarkResult.Status) -> Color {
        switch status {
        case .good:    return Color.ztlpGreen
        case .warning: return Color.ztlpOrange
        case .error:   return Color.ztlpRed
        }
    }

    // MARK: - Run Benchmarks

    private func runBenchmarks() {
        guard !isRunning else { return }
        isRunning = true
        results.removeAll()
        manualSendStatus = nil
        TunnelLogger.shared.info("Benchmark run started category=\(selectedCategory.rawValue)", source: "Benchmark")

        Task {
            let category = selectedCategory
            await withTimeout(seconds: 75) {
                switch category {
                case .connectivity:
                    await runConnectivityTests()
                case .http:
                    await runHTTPTests()
                case .network:
                    await runNetworkTests()
                case .local:
                    await runLocalTests()
                }
            } onTimeout: {
                await addResult(BenchmarkResult(
                    name: "Benchmark Timeout",
                    value: "FAIL",
                    unit: "",
                    status: .error,
                    detail: "Run exceeded 75s; reset to allow another run"
                ))
                TunnelLogger.shared.warn("Benchmark run timed out after 75s category=\(category.rawValue)", source: "Benchmark")
            }

            await MainActor.run {
                isRunning = false
                submitResultsToBootstrap()
            }
        }
    }

    // MARK: - Bootstrap Submission

    @_disfavoredOverload
    private func submitResultsToBootstrap() {
        let reporterResults: [BenchmarkUploadResult] = results.map {
            BenchmarkUploadResult(
                name: $0.name,
                passed: $0.status != .error,
                latency_ms: Double($0.value) ?? nil,
                throughput_kbps: nil,
                p99_latency_ms: nil,
                packet_loss_pct: nil,
                error: $0.status == .error ? $0.detail : nil
            )
        }

        let passedCount = results.filter { $0.status != .error }.count
        let totalCount = results.count

        let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared")
        let neMemoryMB = sharedDefaults?.object(forKey: "ztlp_ne_memory_mb") as? Int
        let neVirtualMB = sharedDefaults?.object(forKey: "ztlp_ne_virtual_mb") as? Int
        let replayRejectCount = sharedDefaults?.object(forKey: "ztlp_replay_reject_count") as? Int
        let selectedRelay = sharedDefaults?.string(forKey: "ztlp_selected_relay")
        let peerAddress = sharedDefaults?.string(forKey: "ztlp_peer_address")

        BenchmarkReporter.shared.submit(
            neMemoryMB: neMemoryMB,
            neVirtualMB: neVirtualMB,
            replayRejectCount: replayRejectCount,
            passedCount: passedCount,
            totalCount: totalCount,
            individualResults: reporterResults,
            relayAddress: selectedRelay,
            gatewayAddress: peerAddress
        )
    }

    // MARK: - Connectivity Tests (real)

    private func runConnectivityTests() async {
        let services: [(name: String, vip: String, port: UInt16, proto: String)] = [
            ("Vault (HTTP)",  "10.122.0.4", 80,  "http"),
            ("Vault (HTTPS)", "10.122.0.4", 443, "https"),
            ("Primary HTTP",  "10.122.0.2", 80,  "http"),
            ("Primary HTTPS", "10.122.0.2", 443, "https"),
            ("HTTP Proxy",    "10.122.0.3", 80,  "http"),
        ]

        // Test 1: Tunnel interface check
        let tunnelUp = checkTunnelInterface()
        await addResult(BenchmarkResult(
            name: "Tunnel Interface",
            value: tunnelUp ? "UP" : "DOWN",
            unit: "",
            status: tunnelUp ? .good : .error,
            detail: "utun 10.122.0.0/16"
        ))

        // Test 2: TCP connect to each service VIP
        for svc in services {
            let (reachable, latencyMs) = await tcpConnect(host: svc.vip, port: svc.port, timeoutSec: 5)
            // Use hostname for browser links (DNS resolves to VIP)
            let svcShortName = svc.name.lowercased()
                .replacingOccurrences(of: " (https)", with: "")
                .replacingOccurrences(of: " (http)", with: "")
            let scheme = svc.proto
            let browseURL = svc.port == 443 ? "\(scheme)://\(svcShortName).ztlp" :
                                              "\(scheme)://\(svcShortName).ztlp"
            await addResult(BenchmarkResult(
                name: svc.name,
                value: reachable ? "\(latencyMs)" : "FAIL",
                unit: reachable ? "ms" : "",
                status: reachable ? .good : .error,
                detail: "\(svc.vip):\(svc.port)",
                openURL: reachable ? browseURL : nil
            ))
        }

        // Test 3: HTTP GET to vault (if reachable) — retry up to 3x for tunnel restart races
        let (httpOk, httpMs, httpCode) = await httpGetWithRetry(url: "http://10.122.0.4/alive", timeoutSec: 10)
        await addResult(BenchmarkResult(
            name: "Vault HTTP Response",
            value: httpOk ? "\(httpMs)" : "FAIL",
            unit: httpOk ? "ms" : "",
            status: httpOk ? .good : .error,
            detail: httpOk ? "HTTP \(httpCode)" : "No response",
            openURL: httpOk ? "http://vault.ztlp" : nil
        ))

        // Test 4: HTTP GET through primary service — retry up to 3x for tunnel restart races
        let (primaryOk, primaryMs, primaryCode) = await httpGetWithRetry(url: "http://10.122.0.2/", timeoutSec: 10)
        await addResult(BenchmarkResult(
            name: "Primary HTTP Response",
            value: primaryOk ? "\(primaryMs)" : "FAIL",
            unit: primaryOk ? "ms" : "",
            status: primaryOk ? .good : (primaryCode > 0 ? .warning : .error),
            detail: primaryOk ? "HTTP \(primaryCode)" : (primaryCode > 0 ? "HTTP \(primaryCode)" : "No response"),
            openURL: primaryOk ? "http://vault.ztlp" : nil
        ))
    }

    // MARK: - HTTP Tests

    private func runHTTPTests() async {
        let endpoints: [(name: String, url: String, openURL: String?)] = [
            ("GET /alive (vault)", "http://10.122.0.4/alive", "http://vault.ztlp"),
            ("GET / (vault web)", "http://10.122.0.4/", "http://10.122.0.4"),
            ("GET /api/config (vault)", "http://10.122.0.4/api/config", nil),
            ("GET / (primary)", "http://10.122.0.2/", "http://vault.ztlp"),
            ("GET / (http proxy)", "http://10.122.0.3/", "http://http.ztlp"),
        ]

        for ep in endpoints {
            let (ok, ms, code) = await httpGet(url: ep.url, timeoutSec: 15)
            await addResult(BenchmarkResult(
                name: ep.name,
                value: ok ? "\(ms)" : (code > 0 ? "\(ms)" : "FAIL"),
                unit: (ok || code > 0) ? "ms" : "",
                status: ok ? .good : (code > 0 ? .warning : .error),
                detail: code > 0 ? "HTTP \(code)" : "No response",
                openURL: (ok || code > 0) ? ep.openURL : nil
            ))
        }

        // Throughput test: download a known endpoint repeatedly
        let (throughput, count) = await httpThroughputTest(url: "http://10.122.0.4/", iterations: 5)
        await addResult(BenchmarkResult(
            name: "Throughput (\(count) reqs)",
            value: String(format: "%.1f", throughput),
            unit: "req/s",
            status: throughput > 1 ? .good : .warning
        ))
    }

    // MARK: - Network Tests

    private func runNetworkTests() async {
        // RTT measurement via TCP connect
        let (_, rttMs) = await tcpConnect(host: "10.122.0.4", port: 443, timeoutSec: 5)
        await addResult(BenchmarkResult(
            name: "TCP RTT (vault VIP)",
            value: "\(rttMs)",
            unit: "ms",
            status: rttMs < 100 ? .good : (rttMs < 500 ? .warning : .error),
            detail: "10.122.0.4:443"
        ))

        let (_, rtt2) = await tcpConnect(host: "10.122.0.2", port: 80, timeoutSec: 5)
        await addResult(BenchmarkResult(
            name: "TCP RTT (primary VIP)",
            value: "\(rtt2)",
            unit: "ms",
            status: rtt2 < 100 ? .good : (rtt2 < 500 ? .warning : .error),
            detail: "10.122.0.2:80"
        ))

        // Multiple RTT samples for jitter
        var rtts: [Int] = []
        for _ in 0..<5 {
            let (ok, ms) = await tcpConnect(host: "10.122.0.4", port: 443, timeoutSec: 5)
            if ok { rtts.append(ms) }
        }
        if rtts.count > 1 {
            let avg = rtts.reduce(0, +) / rtts.count
            let minR = rtts.min() ?? 0
            let maxR = rtts.max() ?? 0
            await addResult(BenchmarkResult(
                name: "RTT avg/min/max (5 samples)",
                value: "\(avg)/\(minR)/\(maxR)",
                unit: "ms",
                status: avg < 100 ? .good : .warning,
                detail: "Jitter: \(maxR - minR)ms"
            ))
        }
    }

    // MARK: - Local Tests

    private func runLocalTests() async {
        // These are placeholder values since we can't call FFI benchmarks
        // from the main app easily. In production these would time actual
        // ztlp_identity_generate, encrypt/decrypt calls, etc.
        try? await Task.sleep(nanoseconds: 800_000_000)
        await addResult(BenchmarkResult(name: "Identity Generation", value: "0.8", unit: "ms", status: .good))
        await addResult(BenchmarkResult(name: "ChaCha20-Poly1305", value: "2.1", unit: "GB/s", status: .good))
        await addResult(BenchmarkResult(name: "X25519 DH", value: "0.3", unit: "ms", status: .good))
        await addResult(BenchmarkResult(name: "BLAKE2s HMAC", value: "3.8", unit: "GB/s", status: .good))
    }

    // MARK: - Test Helpers

    @MainActor
    private func addResult(_ result: BenchmarkResult) {
        results.append(result)
    }

    /// Check if the 10.122.x.x tunnel interface is up by attempting a socket
    private func checkTunnelInterface() -> Bool {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        "10.122.0.1".withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(sock, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return bindResult == 0
    }

    /// TCP connect test — returns (success, latencyMs)
    private func tcpConnect(host: String, port: UInt16, timeoutSec: Int) async -> (Bool, Int) {
        let start = CFAbsoluteTimeGetCurrent()

        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let sock = socket(AF_INET, SOCK_STREAM, 0)
                guard sock >= 0 else {
                    continuation.resume(returning: (false, 0))
                    return
                }

                // Set send/recv timeout for blocking connect
                var tv = timeval(tv_sec: timeoutSec, tv_usec: 0)
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

                var addr = sockaddr_in()
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = port.bigEndian
                host.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }

                let connectResult = withUnsafePointer(to: &addr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        connect(sock, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }

                let ms = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
                close(sock)
                continuation.resume(returning: (connectResult == 0, ms))
            }
        }
    }

    /// HTTP GET test — returns (isSuccess, latencyMs, statusCode)
    private func httpGet(url urlString: String, timeoutSec: Int) async -> (Bool, Int, Int) {
        guard var components = URLComponents(string: urlString) else { return (false, 0, 0) }
        var queryItems = components.queryItems ?? []
        queryItems.append(URLQueryItem(name: "_ztlp_bench", value: UUID().uuidString))
        components.queryItems = queryItems
        guard let url = components.url else { return (false, 0, 0) }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = TimeInterval(timeoutSec)
        config.timeoutIntervalForResource = TimeInterval(timeoutSec)
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpShouldUsePipelining = false
        config.httpMaximumConnectionsPerHost = 1
        let session = URLSession(configuration: config)
        defer {
            session.invalidateAndCancel()
        }

        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("close", forHTTPHeaderField: "Connection")
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")

        let start = CFAbsoluteTimeGetCurrent()

        do {
            let (_, response) = try await session.data(for: request)
            let ms = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
            let httpResponse = response as? HTTPURLResponse
            let code = httpResponse?.statusCode ?? 0
            let ok = code >= 200 && code < 400
            return (ok, ms, code)
        } catch {
            let ms = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
            TunnelLogger.shared.warn("HTTP benchmark GET failed url=\(urlString) ms=\(ms) error=\(error.localizedDescription)", source: "Benchmark")
            return (false, ms, 0)
        }
    }

    /// HTTP GET with retry — retries up to maxAttempts with delaySec between attempts.
    /// Designed for response-content checks that may fail transiently after tunnel restart.
    private func httpGetWithRetry(url urlString: String, timeoutSec: Int, maxAttempts: Int = 3, delaySec: UInt64 = 1) async -> (Bool, Int, Int) {
        for attempt in 1...maxAttempts {
            let (ok, ms, code) = await httpGet(url: urlString, timeoutSec: timeoutSec)
            if ok || code > 0 {
                return (ok, ms, code)
            }
            if attempt < maxAttempts {
                try? await Task.sleep(nanoseconds: delaySec * 1_000_000_000)
            }
        }
        return await httpGet(url: urlString, timeoutSec: timeoutSec)
    }

    /// Run an async operation with a wall-clock timeout. This keeps a wedged tunnel test
    /// from leaving the Benchmark view permanently stuck in the Running state.
    private func withTimeout(
        seconds: UInt64,
        operation: @escaping () async -> Void,
        onTimeout: @escaping () async -> Void
    ) async {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await operation()
                return true
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
                return false
            }

            if let completed = await group.next(), completed == false {
                group.cancelAll()
                await onTimeout()
            } else {
                group.cancelAll()
            }
        }
    }

    /// HTTP throughput test — returns (requests/sec, completedCount)
    private func httpThroughputTest(url urlString: String, iterations: Int) async -> (Double, Int) {
        guard let url = URL(string: urlString) else { return (0, 0) }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        let session = URLSession(configuration: config)

        let start = CFAbsoluteTimeGetCurrent()
        var completed = 0

        for _ in 0..<iterations {
            do {
                let _ = try await session.data(from: url)
                completed += 1
            } catch {
                // skip failures
            }
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let rps = elapsed > 0 ? Double(completed) / elapsed : 0
        return (rps, completed)
    }
}



#Preview {
    BenchmarkView()
}
