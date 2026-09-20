// MainWindow.swift
// ZTLP macOS
//
// Task 8 (HANDOFF-2026-09-20, Steven's direction): ONE page.
//
//   "I want just one page. Move identity, service, and enrollment all onto
//    the Home page so the user knows what is required before connecting.
//    And it should just connect — this is not a VPN, this is an identity
//    network. There is no connection required until the user goes to a
//    website and DNS triggers the connection."
//
// So: no sidebar, no tabs. Home IS the window. Settings (Factory Reset,
// Uninstall Service, identity details, licenses) is reachable only through
// the gear button in the toolbar / Cmd+, — advanced and rare, not primary.

import SwiftUI

struct MainWindow: View {
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @ObservedObject var servicesViewModel: ServicesViewModel
    @ObservedObject var settingsViewModel: SettingsViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @State private var showSettings = false

    var body: some View {
        HomeView(
            viewModel: tunnelViewModel,
            enrollmentViewModel: enrollmentViewModel
        )
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
                .help("Advanced settings (service, identity, reset)")
                .keyboardShortcut(",", modifiers: .command)
            }
        }
        .sheet(isPresented: $showSettings) {
            VStack(spacing: 0) {
                HStack {
                    Text("Advanced")
                        .font(.headline)
                    Spacer()
                    Button("Done") { showSettings = false }
                        .keyboardShortcut(.defaultAction)
                }
                .padding(12)
                Divider()
                SettingsView(
                    viewModel: settingsViewModel,
                    enrollmentViewModel: enrollmentViewModel,
                    configuration: configuration
                )
            }
            .frame(minWidth: 520, minHeight: 480)
        }
        .navigationTitle("ZTLP")
        .frame(minWidth: 520, minHeight: 420)
    }
}
