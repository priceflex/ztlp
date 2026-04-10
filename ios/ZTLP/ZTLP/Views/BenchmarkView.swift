// BenchmarkView.swift
// ZTLP
//
// Three benchmark categories: HTTP (through tunnel), Network (handshake/throughput),
// Local (identity/crypto). Professional layout with results and export.

import SwiftUI

struct BenchmarkView: View {
    @State private var selectedCategory: BenchmarkCategory = .http
    @State private var isRunning = false
    @State private var results: [BenchmarkResult] = []
    @State private var showExport = false

    enum BenchmarkCategory: String, CaseIterable {
        case http = "HTTP"
        case network = "Network"
        case local = "Local"

        var icon: String {
            switch self {
            case .http:    return "globe"
            case .network: return "network"
            case .local:   return "cpu"
            }
        }

        var description: String {
            switch self {
            case .http:    return "HTTP requests through the encrypted tunnel"
            case .network: return "Handshake, throughput, and latency"
            case .local:   return "Identity generation, encryption, pipeline"
            }
        }
    }

    struct BenchmarkResult: Identifiable {
        let id = UUID()
        let name: String
        let value: String
        let unit: String
        let status: Status

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

                if results.isEmpty && !isRunning {
                    emptyState
                } else {
                    resultsList
                }
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Benchmarks")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if isRunning {
                        ProgressView()
                    } else {
                        Menu {
                            Button {
                                runBenchmarks()
                            } label: {
                                Label("Run \(selectedCategory.rawValue)", systemImage: "play.fill")
                            }

                            if !results.isEmpty {
                                Button {
                                    showExport = true
                                } label: {
                                    Label("Export Results", systemImage: "square.and.arrow.up")
                                }

                                Button(role: .destructive) {
                                    results.removeAll()
                                } label: {
                                    Label("Clear Results", systemImage: "trash")
                                }
                            }
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
                Text("Run a benchmark to measure\nZTLP tunnel performance.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            Button {
                runBenchmarks()
            } label: {
                Label("Run \(selectedCategory.rawValue) Benchmark", systemImage: "play.fill")
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
                        Text("Running \(selectedCategory.rawValue) benchmarks\u{2026}")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.leading, 8)
                    }
                    .padding(.vertical, 4)
                }
            }

            Section {
                ForEach(results) { result in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(result.name)
                                .font(.subheadline.weight(.medium))
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
                    }
                    .padding(.vertical, 2)
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

    // MARK: - Helpers

    private func statusColor(_ status: BenchmarkResult.Status) -> Color {
        switch status {
        case .good:    return Color.ztlpGreen
        case .warning: return Color.ztlpOrange
        case .error:   return Color.ztlpRed
        }
    }

    private func runBenchmarks() {
        isRunning = true
        results.removeAll()

        // Simulated benchmark results — in production these would
        // actually run HTTP requests, measure handshake times, etc.
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)

            await MainActor.run {
                switch selectedCategory {
                case .http:
                    results = [
                        BenchmarkResult(name: "GET /health", value: "42", unit: "ms", status: .good),
                        BenchmarkResult(name: "GET /api/sync", value: "156", unit: "ms", status: .good),
                        BenchmarkResult(name: "POST /api/ciphers", value: "89", unit: "ms", status: .good),
                        BenchmarkResult(name: "Throughput", value: "12.4", unit: "MB/s", status: .good),
                    ]
                case .network:
                    results = [
                        BenchmarkResult(name: "Noise_XX Handshake", value: "34", unit: "ms", status: .good),
                        BenchmarkResult(name: "RTT (tunnel)", value: "18", unit: "ms", status: .good),
                        BenchmarkResult(name: "Download", value: "45.2", unit: "MB/s", status: .good),
                        BenchmarkResult(name: "Upload", value: "22.1", unit: "MB/s", status: .good),
                    ]
                case .local:
                    results = [
                        BenchmarkResult(name: "Identity Generation", value: "0.8", unit: "ms", status: .good),
                        BenchmarkResult(name: "ChaCha20-Poly1305", value: "2.1", unit: "GB/s", status: .good),
                        BenchmarkResult(name: "X25519 DH", value: "0.3", unit: "ms", status: .good),
                        BenchmarkResult(name: "BLAKE2s HMAC", value: "3.8", unit: "GB/s", status: .good),
                    ]
                }
                isRunning = false
            }
        }
    }
}

#Preview {
    BenchmarkView()
}
