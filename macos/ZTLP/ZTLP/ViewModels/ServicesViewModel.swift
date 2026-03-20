// ServicesViewModel.swift
// ZTLP macOS
//
// Manages service discovery — querying the ZTLP Name Service (NS)
// for available services in the current zone and their reachability.
// Adapted from iOS — uses NSPasteboard instead of UIPasteboard.

import Foundation
import AppKit
import Combine

/// ViewModel for the Services discovery list.
@MainActor
final class ServicesViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var services: [ZTLPService] = []
    @Published private(set) var isRefreshing: Bool = false
    @Published private(set) var lastError: String?
    @Published var searchText: String = ""

    var filteredServices: [ZTLPService] {
        if searchText.isEmpty { return services }
        let query = searchText.lowercased()
        return services.filter {
            $0.name.lowercased().contains(query) ||
            $0.hostname.lowercased().contains(query) ||
            $0.tags.contains(where: { $0.lowercased().contains(query) })
        }
    }

    var reachableCount: Int {
        services.filter(\.isReachable).count
    }

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let bridge = ZTLPBridge.shared
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Actions

    func refresh() async {
        guard !isRefreshing else { return }

        isRefreshing = true
        lastError = nil

        do {
            // In production, this queries the ZTLP-NS for services in the zone.
            try await Task.sleep(nanoseconds: 500_000_000)
            isRefreshing = false
        } catch {
            isRefreshing = false
            lastError = error.localizedDescription
        }
    }

    func checkReachability(for service: ZTLPService) async {
        guard let index = services.firstIndex(where: { $0.id == service.id }) else { return }
        try? await Task.sleep(nanoseconds: 200_000_000)
        services[index].lastChecked = Date()
    }

    /// Copy a service's hostname to the macOS clipboard.
    func copyHostname(_ service: ZTLPService) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(service.endpoint, forType: .string)
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)
    }
}
