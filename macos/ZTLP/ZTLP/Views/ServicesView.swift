// ServicesView.swift
// ZTLP macOS
//
// Service discovery list with reachability indicators.
// Adapted from iOS — macOS table style, no swipe actions, uses context menus.

import SwiftUI

struct ServicesView: View {
    @ObservedObject var viewModel: ServicesViewModel

    var body: some View {
        Group {
            if viewModel.services.isEmpty && !viewModel.isRefreshing {
                emptyState
            } else {
                serviceList
            }
        }
        .searchable(text: $viewModel.searchText, prompt: "Search services")
        .toolbar {
            ToolbarItem {
                if viewModel.isRefreshing {
                    ProgressView()
                        .scaleEffect(0.6)
                } else {
                    Button {
                        Task { await viewModel.refresh() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .help("Refresh services")
                }
            }
        }
        .task {
            await viewModel.refresh()
        }
    }

    // MARK: - Subviews

    private var serviceList: some View {
        List {
            Section {
                ForEach(viewModel.filteredServices) { service in
                    ServiceRow(service: service)
                        .contextMenu {
                            Button("Copy Endpoint") {
                                viewModel.copyHostname(service)
                            }
                            Button("Check Reachability") {
                                Task { await viewModel.checkReachability(for: service) }
                            }
                        }
                }
            } header: {
                HStack {
                    Text("\(viewModel.filteredServices.count) services")
                    Spacer()
                    Text("\(viewModel.reachableCount) reachable")
                        .foregroundStyle(Color.ztlpGreen)
                }
            }

            if let error = viewModel.lastError {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(Color.ztlpRed)
                        .font(.caption)
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "server.rack")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("No Services")
                .font(.title3.weight(.semibold))
            Text("Services in your ZTLP zone will appear here.\nConnect to the tunnel and refresh.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Refresh") {
                Task { await viewModel.refresh() }
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Service Row

private struct ServiceRow: View {
    let service: ZTLPService

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(service.isReachable ? Color.ztlpGreen : Color.ztlpRed)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(service.name)
                    .font(.body.weight(.medium))

                HStack(spacing: 6) {
                    Text(service.endpoint)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)

                    Text(service.protocolType.uppercased())
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Color.ztlpBlue.opacity(0.12), in: Capsule())
                        .foregroundStyle(Color.ztlpBlue)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Image(systemName: iconForProtocol(service.protocolType))
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let lastChecked = service.lastChecked {
                    Text(lastChecked, style: .relative)
                        .font(.caption2)
                        .foregroundStyle(.quaternary)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func iconForProtocol(_ proto: String) -> String {
        switch proto.lowercased() {
        case "https", "tls":  return "lock.fill"
        case "http":          return "globe"
        case "ssh":           return "terminal"
        case "tcp":           return "arrow.left.arrow.right"
        case "udp":           return "waveform"
        default:              return "network"
        }
    }
}
