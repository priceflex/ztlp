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

    @State private var tunnelViewModel: TunnelViewModel?
    @State private var servicesViewModel: ServicesViewModel?
    @State private var settingsViewModel: SettingsViewModel?
    @State private var enrollmentViewModel: EnrollmentViewModel?

    var body: some Scene {
        // Menu bar dropdown
        MenuBarExtra {
            MenuBarView(
                tunnelViewModel: tunnelVM,
                configuration: configuration
            )
        } label: {
            Image(systemName: menuBarIcon)
                .symbolRenderingMode(.hierarchical)
        }
        .menuBarExtraStyle(.window)

        // Main window (opened from menu bar or Dock)
        Window("ZTLP", id: "main") {
            MainWindow(
                tunnelViewModel: tunnelVM,
                servicesViewModel: servicesVM,
                settingsViewModel: settingsVM,
                enrollmentViewModel: enrollmentVM,
                configuration: configuration
            )
            .environmentObject(configuration)
            .environmentObject(networkMonitor)
        }
        .defaultSize(width: 720, height: 560)

        // Settings window (Cmd+,)
        Settings {
            SettingsView(
                viewModel: settingsVM,
                configuration: configuration
            )
        }
    }

    // MARK: - Computed Properties

    private var tunnelVM: TunnelViewModel {
        if let vm = tunnelViewModel { return vm }
        let vm = TunnelViewModel(configuration: configuration)
        DispatchQueue.main.async { tunnelViewModel = vm }
        return vm
    }

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

    /// Menu bar icon changes based on connection status.
    private var menuBarIcon: String {
        switch tunnelViewModel?.status ?? .disconnected {
        case .connected:    return "shield.checkered"
        case .connecting, .reconnecting, .disconnecting: return "shield.lefthalf.filled"
        case .disconnected: return "shield.slash"
        }
    }
}
