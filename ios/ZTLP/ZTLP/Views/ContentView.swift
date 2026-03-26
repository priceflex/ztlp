// ContentView.swift
// ZTLP
//
// Root tab navigation — 3 tabs: Home, Services, Settings.
// Clean layout matching the macOS app structure.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration

    @State private var selectedTab: Tab = .home

    /// We initialize view models lazily on first appearance,
    /// since @EnvironmentObject isn't available in init().
    @State private var tunnelVM: TunnelViewModel?
    @State private var servicesVM: ServicesViewModel?
    @State private var settingsVM: SettingsViewModel?
    @State private var enrollmentVM: EnrollmentViewModel?

    enum Tab: String {
        case home
        case services
        case settings
    }

    var body: some View {
        Group {
            if let tunnelVM, let servicesVM, let settingsVM, let enrollmentVM {
                TabView(selection: $selectedTab) {
                    HomeView(viewModel: tunnelVM)
                        .tabItem {
                            Label("Home", systemImage: "shield.checkered")
                        }
                        .tag(Tab.home)

                    ServicesView(
                        viewModel: servicesVM,
                        tunnelViewModel: tunnelVM
                    )
                        .tabItem {
                            Label("Services", systemImage: "server.rack")
                        }
                        .tag(Tab.services)

                    SettingsView(
                        viewModel: settingsVM,
                        enrollmentViewModel: enrollmentVM,
                        configuration: configuration
                    )
                        .tabItem {
                            Label("Settings", systemImage: "gear")
                        }
                        .tag(Tab.settings)
                }
                .tint(Color.ztlpBlue)
            } else {
                ProgressView("Loading…")
                    .onAppear { initializeViewModels() }
            }
        }
    }

    private func initializeViewModels() {
        tunnelVM = TunnelViewModel(configuration: configuration)
        servicesVM = ServicesViewModel(configuration: configuration)
        settingsVM = SettingsViewModel(configuration: configuration)
        enrollmentVM = EnrollmentViewModel(configuration: configuration)
    }
}

#Preview {
    ContentView()
        .environmentObject(ZTLPConfiguration())
        .environmentObject(NetworkMonitor.shared)
}
