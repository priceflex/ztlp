// ZTLPApp.swift
// ZTLP macOS
//
// @main entry point for the ZTLP macOS app.
// Provides a MenuBarExtra (dropdown) and an optional main window.

import SwiftUI

@main
struct ZTLPApp: App {

    @StateObject private var configuration = ZTLPConfiguration()
    @StateObject private var networkMonitor = NetworkMonitor.shared

    /// Shared tunnel view model — created eagerly so the menu bar icon
    /// observes status changes immediately.
    @StateObject private var tunnelVM: TunnelViewModel

    @State private var servicesViewModel: ServicesViewModel?
    @State private var settingsViewModel: SettingsViewModel?
    @State private var enrollmentViewModel: EnrollmentViewModel?
    @StateObject private var certManager = CertificateManager()

    init() {
        let config = ZTLPConfiguration()
        _configuration = StateObject(wrappedValue: config)
        _networkMonitor = StateObject(wrappedValue: NetworkMonitor.shared)
        _tunnelVM = StateObject(wrappedValue: TunnelViewModel(configuration: config))
    }

    var body: some Scene {
        // Menu bar dropdown — icon changes based on connection state
        MenuBarExtra {
            MenuBarView(
                tunnelViewModel: tunnelVM,
                configuration: configuration
            )
        } label: {
            // macOS renders menu bar images as template (monochrome).
            // Use distinct SF Symbols so users can tell connected vs disconnected at a glance.
            Image(systemName: menuBarIconName)
        }
        .menuBarExtraStyle(.window)

        // Main window (opened from menu bar or Dock)
        Window("ZTLP", id: "main") {
            MainWindow(
                tunnelViewModel: tunnelVM,
                servicesViewModel: servicesVM,
                settingsViewModel: settingsVM,
                enrollmentViewModel: enrollmentVM,
                configuration: configuration,
                certManager: certManager
            )
            .environmentObject(configuration)
            .environmentObject(networkMonitor)
        }
        .defaultSize(width: 720, height: 560)

        // Settings window (Cmd+,)
        Settings {
            SettingsView(
                viewModel: settingsVM,
                enrollmentViewModel: enrollmentVM,
                configuration: configuration,
                certManager: certManager
            )
        }
    }

    // MARK: - Computed Properties

    private var servicesVM: ServicesViewModel {
        if let vm = servicesViewModel { return vm }
        let vm = ServicesViewModel(configuration: configuration)
        DispatchQueue.main.async { servicesViewModel = vm }
        return vm
    }

    private var settingsVM: SettingsViewModel {
        if let vm = settingsViewModel { return vm }
        let vm = SettingsViewModel(configuration: configuration)
        DispatchQueue.main.async { settingsViewModel = vm }
        return vm
    }

    private var enrollmentVM: EnrollmentViewModel {
        if let vm = enrollmentViewModel { return vm }
        let vm = EnrollmentViewModel(configuration: configuration)
        DispatchQueue.main.async { enrollmentViewModel = vm }
        return vm
    }

    /// SF Symbol name for the menu bar icon.
    /// Connected: filled shield (solid). Disconnected: slashed shield.
    /// Transitioning: half-filled shield.
    private var menuBarIconName: String {
        switch tunnelVM.status {
        case .connected:
            return "shield.checkered"
        case .connecting, .reconnecting:
            return "shield.lefthalf.filled"
        case .disconnecting:
            return "shield.lefthalf.filled"
        case .disconnected:
            return "shield.slash"
        }
    }
}
