// ContentView.swift
// ZTLP
//
// Root tab navigation for the main app experience.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration

    /// Tab selection state.
    @State private var selectedTab: Tab = .home

    enum Tab: String {
        case home
        case services
        case identity
        case settings
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            HomeView(
                viewModel: TunnelViewModel(configuration: configuration)
            )
            .tabItem {
                Label("Connect", systemImage: "shield.checkered")
            }
            .tag(Tab.home)

            ServicesView(
                viewModel: ServicesViewModel(configuration: configuration)
            )
            .tabItem {
                Label("Services", systemImage: "server.rack")
            }
            .tag(Tab.services)

            IdentityView()
            .tabItem {
                Label("Identity", systemImage: "person.badge.key")
            }
            .tag(Tab.identity)

            SettingsView(
                viewModel: SettingsViewModel(configuration: configuration)
            )
            .tabItem {
                Label("Settings", systemImage: "gear")
            }
            .tag(Tab.settings)
        }
        .tint(Color.ztlpBlue)
    }
}

#Preview {
    ContentView()
        .environmentObject(ZTLPConfiguration())
        .environmentObject(NetworkMonitor.shared)
}
