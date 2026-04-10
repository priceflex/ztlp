// ContentView.swift
// ZTLP
//
// Root tab navigation — 5 tabs: Home, Services, Logs, Bench, Settings.
// Professional layout with connection-aware badge on Home tab.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration
    @EnvironmentObject var networkMonitor: NetworkMonitor

    @State private var selectedTab: Tab = .home

    /// View models initialized lazily (requires @EnvironmentObject).
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
                    HomeView(viewModel: tunnelVM, configuration: configuration)
                        .tabItem {
                            Label("Home", systemImage: "shield.checkered")
                        }
                        .tag(Tab.home)
                        .badge(tunnelVM.status.isActive ? "●" : nil)

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
                ProgressView("Loading\u{2026}")
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
