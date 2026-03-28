// BenchmarkView.swift
// ZTLP
//
// In-app benchmark UI. Displays real-time progress and results.
// Results are also written to the Logs tab via TunnelLogger.

import SwiftUI

struct BenchmarkView: View {

    @StateObject private var runner = BenchmarkRunner.shared

    var body: some View {
        NavigationView {
            List {
                // Header / Controls
                Section {
                    if runner.isRunning {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle())
                                Text(runner.currentBenchmark)
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            }
                            ProgressView(value: runner.progress)
                                .progressViewStyle(LinearProgressViewStyle())
                        }
                        .padding(.vertical, 4)
                    } else {
                        Button {
                            Task { await runner.runAll() }
                        } label: {
                            HStack {
                                Image(systemName: "gauge.with.dots.needle.bottom.50percent")
                                    .font(.title2)
                                VStack(alignment: .leading) {
                                    Text("Run Benchmark Suite")
                                        .font(.headline)
                                    Text("Tests identity, crypto, pipeline, network")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                } header: {
                    Text("Performance Benchmarks")
                } footer: {
                    Text("Results are logged to the Logs tab for export.")
                }

                // Results
                if !runner.results.isEmpty {
                    Section("Results") {
                        ForEach(runner.results) { result in
                            BenchmarkResultRow(result: result)
                        }
                    }

                    // Summary Stats
                    Section("Summary") {
                        let totalTime = runner.results.reduce(0) { $0 + $1.totalMs }
                        LabeledContent("Total Time", value: formatMs(totalTime))
                        LabeledContent("Benchmarks Run", value: "\(runner.results.count)")

                        if let fastest = runner.results.filter({ $0.avgMs > 0 }).min(by: { $0.avgMs < $1.avgMs }) {
                            LabeledContent("Fastest", value: "\(fastest.name) (\(formatMs(fastest.avgMs)))")
                        }
                        if let slowest = runner.results.filter({ $0.avgMs > 0 }).max(by: { $0.avgMs < $1.avgMs }) {
                            LabeledContent("Slowest", value: "\(slowest.name) (\(formatMs(slowest.avgMs)))")
                        }
                    }
                }
            }
            .navigationTitle("Benchmarks")
            .toolbar {
                if !runner.results.isEmpty && !runner.isRunning {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        ShareLink(item: exportText()) {
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

    private func exportText() -> String {
        var text = "ZTLP iOS Benchmark Results\n"
        text += "Date: \(ISO8601DateFormatter().string(from: Date()))\n"
        text += "Library: \(ZTLPBridge.shared.version)\n"
        text += String(repeating: "=", count: 60) + "\n\n"
        for result in runner.results {
            text += result.summary + "\n"
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
                if let ops = result.opsPerSec {
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
                    .foregroundColor(.tertiary)
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
