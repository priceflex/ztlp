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
            // ZTLP shield-lock logo as a template image (macOS tints it for
            // light/dark menu bars). Full strength = all readiness rows green;
            // dimmed = not ready yet; pulsing dim while a transition runs.
            Image("MenuBarIcon")
                .renderingMode(.template)
                .opacity(menuBarIconOpacity)
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
                enrollmentViewModel: enrollmentVM,
                configuration: configuration
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

    /// Menu bar logo strength. Ready (all three rows green): full.
    /// Transitioning: 0.7. Not ready: 0.45, the same "dimmed" convention
    /// macOS uses for inactive status items.
    private var menuBarIconOpacity: Double {
        if tunnelVM.readiness.allReady { return 1.0 }
        switch tunnelVM.status {
        case .connecting, .reconnecting, .disconnecting:
            return 0.7
        default:
            return 0.45
        }
    }
}
