// ServicesViewModel.swift
// ZTLP
//
// Manages service discovery — querying the ZTLP Name Service (NS)
// for available services in the current zone and their reachability.

import Foundation
import UIKit
import Combine

/// ViewModel for the Services discovery list.
@MainActor
final class ServicesViewModel: ObservableObject {

    // MARK: - Published State

    /// Discovered services.
    @Published private(set) var services: [ZTLPService] = []

    /// Whether a refresh is in progress.
    @Published private(set) var isRefreshing: Bool = false

    /// Last error during refresh.
    @Published private(set) var lastError: String?

    /// Search text for filtering services.
    @Published var searchText: String = ""

    /// Filtered services based on search text.
    var filteredServices: [ZTLPService] {
        if searchText.isEmpty { return services }
        let query = searchText.lowercased()
        return services.filter {
            $0.name.lowercased().contains(query) ||
            $0.hostname.lowercased().contains(query) ||
            $0.tags.contains(where: { $0.lowercased().contains(query) })
        }
    }

    /// Count of reachable services.
    var reachableCount: Int {
        services.filter(\.isReachable).count
    }

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Actions

    /// Refresh the service list from the ZTLP Name Service.
    func refresh() async {
        guard !isRefreshing else { return }

        isRefreshing = true
        lastError = nil

        do {
            // In a full implementation, this would:
            //   1. Send a service discovery query via the ZTLP tunnel
            //   2. The NS responds with registered services for our zone
            //   3. We parse the response and update the service list
            //
            // The query protocol would use ztlp_send() to send a service
            // discovery request message and ztlp_set_recv_callback() to
            // handle the response.

            // For now, simulate the discovery with a network delay
            try await Task.sleep(nanoseconds: 500_000_000) // 0.5s

            // In production, this would be populated from the NS response.
            // The services list would be parsed from a protobuf/msgpack response.
            // Placeholder: keep current services or show empty if not connected.

            isRefreshing = false

        } catch {
            isRefreshing = false
            lastError = error.localizedDescription
        }
    }

    /// Check reachability of a specific service.
    func checkReachability(for service: ZTLPService) async {
        guard let index = services.firstIndex(where: { $0.id == service.id }) else { return }

        // In production, this would send a ping/probe through the ZTLP tunnel
        // to check if the service endpoint is responding.

        // Simulate a reachability check
        try? await Task.sleep(nanoseconds: 200_000_000) // 0.2s

        services[index].lastChecked = Date()
    }

    /// Copy a service's hostname to the clipboard.
    func copyHostname(_ service: ZTLPService) {
        UIPasteboard.general.string = service.endpoint
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }
}
