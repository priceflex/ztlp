// ContentView.swift
// ZTLP
//
// Root tab navigation — 5 tabs: Home, Services, Logs, Bench, Settings.
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
        case logs
        case bench
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

                    LogsView()
                        .tabItem {
                            Label("Logs", systemImage: "doc.text.magnifyingglass")
                        }
                        .tag(Tab.logs)

                    BenchmarkView()
                        .tabItem {
                            Label("Bench", systemImage: "gauge.with.dots.needle.bottom.50percent")
                        }
                        .tag(Tab.bench)

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
