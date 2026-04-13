// ServicesView.swift
// ZTLP
//
// Service discovery list with reachability indicators, pull-to-refresh,
// and tappable rows that open HTTP/HTTPS services in the browser.

import SwiftUI

struct ServicesView: View {
    @ObservedObject var viewModel: ServicesViewModel
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @State private var browserURL: URL?

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
            .safariSheet(url: $browserURL)
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
                    ServiceRow(service: service) { url in
                        browserURL = url
                    }
                        .swipeActions(edge: .trailing) {
                            Button {
                                viewModel.copyHostname(service)
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                            }
                            .tint(Color.ztlpBlue)
                        }
                        .swipeActions(edge: .leading) {
                            Button {
                                Task { await viewModel.checkReachability(for: service) }
                            } label: {
                                Label("Ping", systemImage: "antenna.radiowaves.left.and.right")
                            }
                            .tint(Color.ztlpGreen)
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
        .listStyle(.insetGrouped)
    }

    /// Empty state when no services are discovered.
    private var emptyState: some View {
        VStack(spacing: 20) {
            Spacer()

            ZStack {
                Circle()
                    .fill(Color.ztlpBlue.opacity(0.08))
                    .frame(width: 100, height: 100)
                Image(systemName: "server.rack")
                    .font(.system(size: 40))
                    .foregroundStyle(Color.ztlpBlue.opacity(0.6))
            }

            VStack(spacing: 8) {
                Text("No Services")
                    .font(.title3.weight(.semibold))
                Text("Services in your ZTLP zone will appear here.\nConnect to the tunnel and pull to refresh.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Button {
                Task { await viewModel.refresh() }
            } label: {
                Text("Refresh")
                    .font(.subheadline.weight(.medium))
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)

            Spacer()
        }
    }
}

// MARK: - Service Row

private struct ServiceRow: View {
    let service: ZTLPService
    let openURL: (URL) -> Void

    /// Whether this service can be opened in a browser
    private var isBrowsable: Bool {
        let proto = service.protocolType.lowercased()
        return proto == "http" || proto == "https" || proto == "tls"
    }

    /// Build a URL for browsable services
    private var browseURL: URL? {
        guard isBrowsable else { return nil }
        let scheme = service.protocolType.lowercased() == "https" || service.protocolType.lowercased() == "tls" ? "https" : "http"
        return URL(string: "\(scheme)://\(service.hostname):\(service.port)")
    }

    var body: some View {
        Button {
            if let url = browseURL {
                openURL(url)
            }
        } label: {
            HStack(spacing: 12) {
                // Reachability indicator
                Circle()
                    .fill(service.isReachable ? Color.ztlpGreen : Color.ztlpRed)
                    .frame(width: 10, height: 10)
                    .accessibilityLabel(service.isReachable ? "Reachable" : "Unreachable")

                // Service info
                VStack(alignment: .leading, spacing: 4) {
                    Text(service.name)
                        .font(.body.weight(.medium))
                        .foregroundStyle(.primary)

                    HStack(spacing: 8) {
                        Text(service.endpoint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)

                        Text(service.protocolType.uppercased())
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.ztlpBlue.opacity(0.12), in: Capsule())
                            .foregroundStyle(Color.ztlpBlue)
                    }

                    if let description = service.description, !description.isEmpty {
                        Text(description)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                Spacer()

                // Open in browser indicator
                VStack(alignment: .trailing, spacing: 2) {
                    if isBrowsable {
                        Image(systemName: "arrow.up.right.square")
                            .font(.caption)
                            .foregroundStyle(Color.ztlpBlue)
                    } else {
                        Image(systemName: iconForProtocol(service.protocolType))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if let lastChecked = service.lastChecked {
                        Text(lastChecked, style: .relative)
                            .font(.caption2)
                            .foregroundStyle(.quaternary)
                    }
                }
            }
            .padding(.vertical, 4)
        }
        .buttonStyle(.plain)
        .disabled(!isBrowsable)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(service.name), \(service.endpoint), \(service.isReachable ? "reachable" : "unreachable")")
    }

    /// Map protocol type to SF Symbol.
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
    let config = ZTLPConfiguration()
    ServicesView(
        viewModel: ServicesViewModel(configuration: config),
        tunnelViewModel: TunnelViewModel(configuration: config)
    )
}

#Preview("Empty") {
    let config = ZTLPConfiguration()
    ServicesView(
        viewModel: ServicesViewModel(configuration: config),
        tunnelViewModel: TunnelViewModel(configuration: config)
    )
}
