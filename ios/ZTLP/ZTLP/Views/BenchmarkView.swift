// BenchmarkView.swift
// ZTLP
//
// In-app benchmark UI with two sections:
//   1. Local benchmarks (identity, crypto, pipeline — no network needed)
//   2. Network benchmarks (handshake, throughput, latency — connects to relay)
//
// Results are also written to the Logs tab via TunnelLogger.

import SwiftUI

struct BenchmarkView: View {

    @StateObject private var localRunner = BenchmarkRunner.shared
    @StateObject private var netRunner = NetworkBenchmark.shared

    var body: some View {
        NavigationView {
            List {
                // Network Benchmarks
                Section {
                    if netRunner.isRunning {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle())
                                VStack(alignment: .leading) {
                                    Text(netRunner.currentBenchmark)
                                        .font(.subheadline)
                                    Text(netRunner.connectionStatus)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                            ProgressView(value: netRunner.progress)
                                .progressViewStyle(LinearProgressViewStyle())
                        }
                        .padding(.vertical, 4)
                    } else {
                        Button {
                            Task { await netRunner.runAll() }
                        } label: {
                            HStack {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                    .font(.title2)
                                    .foregroundColor(.blue)
                                VStack(alignment: .leading) {
                                    Text("Run Network Benchmarks")
                                        .font(.headline)
                                    Text("Handshake, throughput, latency, reconnect")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .disabled(localRunner.isRunning)
                    }
                } header: {
                    Text("🌐 Network (Live Server)")
                } footer: {
                    Text("Connects to relay at \(netRunner.isRunning ? "..." : UserDefaults(suiteName: "group.com.ztlp.shared")?.string(forKey: "ztlp_relay_server") ?? "34.219.64.205:23095"). Requires network access.")
                }

                // Network Results
                if !netRunner.results.isEmpty {
                    Section("Network Results") {
                        ForEach(netRunner.results) { result in
                            BenchmarkResultRow(result: result)
                        }
                    }
                }

                // Local Benchmarks
                Section {
                    if localRunner.isRunning {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle())
                                Text(localRunner.currentBenchmark)
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            }
                            ProgressView(value: localRunner.progress)
                                .progressViewStyle(LinearProgressViewStyle())
                        }
                        .padding(.vertical, 4)
                    } else {
                        Button {
                            Task { await localRunner.runAll() }
                        } label: {
                            HStack {
                                Image(systemName: "cpu")
                                    .font(.title2)
                                    .foregroundColor(.green)
                                VStack(alignment: .leading) {
                                    Text("Run Local Benchmarks")
                                        .font(.headline)
                                    Text("Identity, crypto, pipeline, memory")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .disabled(netRunner.isRunning)
                    }
                } header: {
                    Text("📱 Local (On-Device)")
                } footer: {
                    Text("Measures FFI performance, identity generation, and memory. No network required.")
                }

                // Local Results
                if !localRunner.results.isEmpty {
                    Section("Local Results") {
                        ForEach(localRunner.results) { result in
                            BenchmarkResultRow(result: result)
                        }
                    }
                }

                // Combined Summary
                if !netRunner.results.isEmpty || !localRunner.results.isEmpty {
                    Section("Summary") {
                        let allResults = netRunner.results + localRunner.results
                        let totalTime = allResults.reduce(0) { $0 + $1.totalMs }
                        LabeledContent("Total Time", value: formatMs(totalTime))
                        LabeledContent("Benchmarks Run", value: "\(allResults.count)")

                        if let fastest = allResults.filter({ $0.avgMs > 0 }).min(by: { $0.avgMs < $1.avgMs }) {
                            LabeledContent("Fastest", value: "\(fastest.name) (\(formatMs(fastest.avgMs)))")
                        }
                        if let slowest = allResults.filter({ $0.avgMs > 0 }).max(by: { $0.avgMs < $1.avgMs }) {
                            LabeledContent("Slowest", value: "\(slowest.name) (\(formatMs(slowest.avgMs)))")
                        }

                        // Network-specific summary
                        if let handshake = netRunner.results.first(where: { $0.name.contains("Handshake Latency") }) {
                            LabeledContent("Handshake (avg)", value: formatMs(handshake.avgMs))
                        }
                        if let sustained = netRunner.results.first(where: { $0.name.contains("Sustained") }),
                           let tp = sustained.throughputMBps {
                            LabeledContent("Sustained Throughput", value: String(format: "%.1f MB/s", tp))
                        }
                    }
                }
            }
            .navigationTitle("Benchmarks")
            .toolbar {
                if (!netRunner.results.isEmpty || !localRunner.results.isEmpty) &&
                    !netRunner.isRunning && !localRunner.isRunning {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        ShareLink(item: exportAllResults()) {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
            }
        }
    }

    private func formatMs(_ ms: Double) -> String {
        if ms < 1 { return String(format: "%.3fms", ms) }
        if ms < 1000 { return String(format: "%.1fms", ms) }
        return String(format: "%.2fs", ms / 1000)
    }

    private func exportAllResults() -> String {
        var text = "ZTLP iOS Benchmark Results\n"
        text += "Date: \(ISO8601DateFormatter().string(from: Date()))\n"
        text += "Library: \(ZTLPBridge.shared.version)\n"
        text += String(repeating: "=", count: 60) + "\n\n"

        if !netRunner.results.isEmpty {
            text += "--- NETWORK BENCHMARKS ---\n"
            for result in netRunner.results {
                text += result.summary + "\n"
            }
            text += "\n"
        }

        if !localRunner.results.isEmpty {
            text += "--- LOCAL BENCHMARKS ---\n"
            for result in localRunner.results {
                text += result.summary + "\n"
            }
        }

        return text
    }
}

// MARK: - Result Row

struct BenchmarkResultRow: View {
    let result: BenchmarkResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(result.name)
                .font(.subheadline.weight(.medium))

            HStack {
                StatBadge(label: "avg", value: formatMs(result.avgMs), color: .blue)
                StatBadge(label: "min", value: formatMs(result.minMs), color: .green)
                StatBadge(label: "max", value: formatMs(result.maxMs), color: .orange)
            }

            HStack {
                if let ops = result.opsPerSec, ops > 0 {
                    Text(formatOps(ops) + " ops/sec")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                if let tp = result.throughputMBps {
                    Text(String(format: "%.1f MB/s", tp))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                if let extra = result.extraInfo {
                    Text(extra)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Text("\(result.iterations) iter")
                    .font(.caption2)
                    .foregroundColor(.secondary.opacity(0.7))
            }
        }
        .padding(.vertical, 2)
    }

    private func formatMs(_ ms: Double) -> String {
        if ms == 0 { return "—" }
        if ms < 0.001 { return String(format: "%.0fns", ms * 1_000_000) }
        if ms < 1 { return String(format: "%.1fµs", ms * 1000) }
        if ms < 1000 { return String(format: "%.2fms", ms) }
        return String(format: "%.2fs", ms / 1000)
    }

    private func formatOps(_ ops: Double) -> String {
        if ops >= 1_000_000 { return String(format: "%.2fM", ops / 1_000_000) }
        if ops >= 1_000 { return String(format: "%.1fK", ops / 1_000) }
        return String(format: "%.0f", ops)
    }
}

// MARK: - Stat Badge

struct StatBadge: View {
    let label: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 1) {
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundColor(color.opacity(0.8))
            Text(value)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundColor(color)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.1))
        .cornerRadius(6)
    }
}
