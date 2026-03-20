// MainWindow.swift
// ZTLP macOS
//
// Main settings/status window with sidebar navigation.
// Opened from the menu bar dropdown or via Cmd+O.

import SwiftUI

struct MainWindow: View {
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @ObservedObject var servicesViewModel: ServicesViewModel
    @ObservedObject var settingsViewModel: SettingsViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @State private var selectedTab: SidebarTab = .home

    enum SidebarTab: String, CaseIterable, Identifiable {
        case home = "Home"
        case services = "Services"
        case identity = "Identity"
        case enrollment = "Enrollment"
        case settings = "Settings"

        var id: String { rawValue }

        var systemImage: String {
            switch self {
            case .home:       return "shield.checkered"
            case .services:   return "server.rack"
            case .identity:   return "person.badge.key"
            case .enrollment: return "ticket"
            case .settings:   return "gearshape"
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
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
        } detail: {
            switch selectedTab {
            case .home:
                HomeView(viewModel: tunnelViewModel)
            case .services:
                ServicesView(viewModel: servicesViewModel)
            case .identity:
                IdentityView(settingsViewModel: settingsViewModel, configuration: configuration)
            case .enrollment:
                EnrollmentView(viewModel: enrollmentViewModel)
            case .settings:
                SettingsView(viewModel: settingsViewModel, configuration: configuration)
            }
        }
        .navigationTitle("ZTLP")
        .frame(minWidth: 600, minHeight: 400)
    }
}
