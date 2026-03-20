// SettingsView.swift
// ZTLP
//
// Settings screen: relay address config, STUN server, auto-reconnect,
// identity management, and about section.

import SwiftUI

struct SettingsView: View {
    @ObservedObject var viewModel: SettingsViewModel

    /// Confirmation alert for destructive actions.
    @State private var showRegenConfirm = false
    @State private var showResetConfirm = false

    var body: some View {
        NavigationStack {
            Form {
                connectionSection
                tunnelSection
                securitySection
                identitySection
                aboutSection
                dangerZoneSection
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .status) {
                    if let msg = viewModel.statusMessage {
                        Text(msg)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .transition(.opacity)
                    }
                }
            }
            .animation(.easeInOut, value: viewModel.statusMessage)
        }
    }

    // MARK: - Sections

    /// Relay and peer connection settings.
    private var connectionSection: some View {
        Section("Connection") {
            HStack {
                Label("Relay Server", systemImage: "antenna.radiowaves.left.and.right")
                Spacer()
                TextField("relay.ztlp.net:4433", text: $viewModel.configuration.relayAddress)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }
            .accessibilityElement(children: .combine)

            HStack {
                Label("STUN Server", systemImage: "network")
                Spacer()
                TextField("stun.l.google.com:19302", text: $viewModel.configuration.stunServer)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }
            .accessibilityElement(children: .combine)

            HStack {
                Label("Target Node ID", systemImage: "point.3.filled.connected.trianglepath.dotted")
                Spacer()
                TextField("Peer node ID (hex)", text: $viewModel.configuration.targetNodeId)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            .accessibilityElement(children: .combine)

            Toggle(isOn: $viewModel.configuration.natAssist) {
                Label("NAT Traversal Assist", systemImage: "arrow.triangle.branch")
            }

            Toggle(isOn: $viewModel.configuration.autoConnect) {
                Label("Auto-Connect on Launch", systemImage: "bolt.fill")
            }
        }
    }

    /// Tunnel-specific settings.
    private var tunnelSection: some View {
        Section("Tunnel") {
            HStack {
                Label("Tunnel Address", systemImage: "network.badge.shield.half.filled")
                Spacer()
                TextField("10.0.0.2", text: $viewModel.configuration.tunnelAddress)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .keyboardType(.numbersAndPunctuation)
            }

            HStack {
                Label("DNS Servers", systemImage: "server.rack")
                Spacer()
                TextField("1.1.1.1, 8.8.8.8", text: Binding(
                    get: { viewModel.configuration.dnsServers.joined(separator: ", ") },
                    set: { newValue in
                        viewModel.configuration.dnsServers = newValue
                            .split(separator: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                    }
                ))
                .multilineTextAlignment(.trailing)
                .font(.callout.monospaced())
                .textInputAutocapitalization(.never)
                .keyboardType(.numbersAndPunctuation)
            }

            Stepper(value: $viewModel.configuration.mtu, in: 1200...1500, step: 50) {
                Label("MTU: \(viewModel.configuration.mtu)", systemImage: "arrow.left.and.right")
            }
        }
    }

    /// Security settings.
    private var securitySection: some View {
        Section("Security") {
            Toggle(isOn: $viewModel.configuration.useSecureEnclave) {
                Label("Use Secure Enclave", systemImage: "cpu")
            }
            .disabled(!viewModel.secureEnclaveAvailable)

            if !viewModel.secureEnclaveAvailable {
                Text("Secure Enclave is not available on this device.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Identity display.
    private var identitySection: some View {
        Section("Identity") {
            if let identity = viewModel.identity {
                HStack {
                    Label("Node ID", systemImage: "number")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(identity.shortNodeId)
                        .font(.caption.monospaced())
                }

                HStack {
                    Label("Provider", systemImage: "shield.checkered")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(identity.providerType.replacingOccurrences(of: "_", with: " ").capitalized)
                        .font(.caption)
                }

                Button {
                    showRegenConfirm = true
                } label: {
                    Label("Regenerate Identity", systemImage: "arrow.triangle.2.circlepath")
                }
                .confirmationDialog(
                    "Regenerate Identity?",
                    isPresented: $showRegenConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Regenerate", role: .destructive) {
                        Task { await viewModel.regenerateIdentity() }
                    }
                } message: {
                    Text("This will create a new Node ID. Your existing enrollment and connections will be lost.")
                }
            } else {
                Button {
                    Task { await viewModel.regenerateIdentity() }
                } label: {
                    Label("Generate Identity", systemImage: "plus.circle")
                }
            }
        }
    }

    /// About section with version info.
    private var aboutSection: some View {
        Section("About") {
            HStack {
                Label("ZTLP Library", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
                Spacer()
                Text("v\(viewModel.libraryVersion)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            HStack {
                Label("App Version", systemImage: "app")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(appVersion)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            HStack {
                Label("iOS", systemImage: "iphone")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(UIDevice.current.systemVersion)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Destructive actions.
    private var dangerZoneSection: some View {
        Section {
            Button(role: .destructive) {
                Task { await viewModel.removeVPNConfiguration() }
            } label: {
                Label("Remove VPN Configuration", systemImage: "xmark.shield")
            }

            Button(role: .destructive) {
                showResetConfirm = true
            } label: {
                Label("Factory Reset", systemImage: "trash")
            }
            .confirmationDialog(
                "Factory Reset?",
                isPresented: $showResetConfirm,
                titleVisibility: .visible
            ) {
                Button("Reset Everything", role: .destructive) {
                    Task { await viewModel.factoryReset() }
                }
            } message: {
                Text("This will delete your identity, enrollment, VPN configuration, and all settings. This cannot be undone.")
            }
        } header: {
            Text("Danger Zone")
        }
    }

    // MARK: - Helpers

    /// App version string from Info.plist.
    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(version) (\(build))"
    }
}

// MARK: - Previews

#Preview {
    SettingsView(viewModel: SettingsViewModel(configuration: ZTLPConfiguration()))
}
