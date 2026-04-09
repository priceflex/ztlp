// MainWindow.swift
// ZTLP macOS
//
// Main window with simplified 3-tab sidebar: Home, Services, Settings.

import SwiftUI

struct MainWindow: View {
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @ObservedObject var servicesViewModel: ServicesViewModel
    @ObservedObject var settingsViewModel: SettingsViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel
    @ObservedObject var configuration: ZTLPConfiguration
    @ObservedObject var certManager: CertificateManager

    @State private var selectedTab: SidebarTab = .home

    enum SidebarTab: String, CaseIterable, Identifiable {
        case home = "Home"
        case services = "Services"
        case settings = "Settings"

        var id: String { rawValue }

        var systemImage: String {
            switch self {
            case .home:     return "shield.checkered"
            case .services: return "server.rack"
            case .settings: return "gearshape"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(SidebarTab.allCases, selection: $selectedTab) { tab in
                Label(tab.rawValue, systemImage: tab.systemImage)
                    .tag(tab)
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 140, ideal: 160)
        } detail: {
            switch selectedTab {
            case .home:
                HomeView(viewModel: tunnelViewModel)
            case .services:
                ServicesView(
                    viewModel: servicesViewModel,
                    tunnelViewModel: tunnelViewModel
                )
            case .settings:
                SettingsView(
                    viewModel: settingsViewModel,
                    enrollmentViewModel: enrollmentViewModel,
                    configuration: configuration,
                    certManager: certManager
                )
            }
        }
        .navigationTitle("ZTLP")
        .frame(minWidth: 580, minHeight: 420)
    }
}
