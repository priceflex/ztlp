// ServicesView.swift
// ZTLP
//
// Service discovery list with reachability indicators and pull-to-refresh.
// Shows ZTLP-NS registered services in the current zone.

import SwiftUI

struct ServicesView: View {
    @ObservedObject var viewModel: ServicesViewModel

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.services.isEmpty && !viewModel.isRefreshing {
                    emptyState
                } else {
                    serviceList
                }
            }
            .navigationTitle("Services")
            .searchable(text: $viewModel.searchText, prompt: "Search services")
            .refreshable {
                await viewModel.refresh()
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if viewModel.isRefreshing {
                        ProgressView()
                    } else {
                        Button {
                            Task { await viewModel.refresh() }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .accessibilityLabel("Refresh services")
                    }
                }
            }
            .task {
                await viewModel.refresh()
            }
        }
    }

    // MARK: - Subviews

    /// List of discovered services.
    private var serviceList: some View {
        List {
            Section {
                ForEach(viewModel.filteredServices) { service in
                    ServiceRow(service: service)
                        .swipeActions(edge: .trailing) {
                            Button {
                                viewModel.copyHostname(service)
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                            }
                            .tint(.ztlpBlue)
                        }
                        .swipeActions(edge: .leading) {
                            Button {
                                Task { await viewModel.checkReachability(for: service) }
                            } label: {
                                Label("Ping", systemImage: "antenna.radiowaves.left.and.right")
                            }
                            .tint(.ztlpGreen)
                        }
                }
            } header: {
                HStack {
                    Text("\(viewModel.filteredServices.count) services")
                    Spacer()
                    Text("\(viewModel.reachableCount) reachable")
                        .foregroundStyle(.ztlpGreen)
                }
            }

            if let error = viewModel.lastError {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.ztlpRed)
                        .font(.caption)
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    /// Empty state when no services are discovered.
    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Services", systemImage: "server.rack")
        } description: {
            Text("Services in your ZTLP zone will appear here. Connect to the tunnel and pull to refresh.")
        } actions: {
            Button("Refresh") {
                Task { await viewModel.refresh() }
            }
            .buttonStyle(.borderedProminent)
            .tint(.ztlpBlue)
        }
    }
}

// MARK: - Service Row

/// A single service row in the list.
private struct ServiceRow: View {
    let service: ZTLPService

    var body: some View {
        HStack(spacing: 12) {
            // Reachability dot
            Circle()
                .fill(service.isReachable ? Color.ztlpGreen : Color.ztlpRed)
                .frame(width: 10, height: 10)
                .accessibilityLabel(service.isReachable ? "Reachable" : "Unreachable")

            // Service info
            VStack(alignment: .leading, spacing: 4) {
                Text(service.name)
                    .font(.body.weight(.medium))

                HStack(spacing: 8) {
                    Text(service.endpoint)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)

                    Text(service.protocolType.uppercased())
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.ztlpBlue.opacity(0.12), in: Capsule())
                        .foregroundStyle(.ztlpBlue)
                }

                if let description = service.description, !description.isEmpty {
                    Text(description)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }

            Spacer()

            // Host node badge
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
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(service.name), \(service.endpoint), \(service.isReachable ? "reachable" : "unreachable")")
    }

    /// Map protocol type to an SF Symbol.
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

// MARK: - Tags View

/// Horizontal tag row for service categorization.
private struct TagsView: View {
    let tags: [String]

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(tags, id: \.self) { tag in
                    Text(tag)
                        .font(.caption2)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.secondary.opacity(0.12), in: Capsule())
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - Previews

#Preview("With Services") {
    ServicesView(viewModel: {
        let vm = ServicesViewModel(configuration: ZTLPConfiguration())
        return vm
    }())
}

#Preview("Empty") {
    ServicesView(viewModel: ServicesViewModel(configuration: ZTLPConfiguration()))
}
