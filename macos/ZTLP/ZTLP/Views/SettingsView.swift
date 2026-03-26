// SettingsView.swift
// ZTLP macOS
//
// Unified settings: General, Identity, Enrollment, Advanced (collapsed), About, Danger Zone.
// Clean, professional layout. Advanced fields hidden by default.

import SwiftUI

struct SettingsView: View {
    @ObservedObject var viewModel: SettingsViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @State private var showAdvanced = false
    @State private var showRegenConfirm = false
    @State private var showResetConfirm = false
    @State private var showEnrollmentSheet = false
    @State private var copiedField: String?

    var body: some View {
        Form {
            generalSection
            identitySection
            enrollmentSection

            if showAdvanced {
                connectionSection
                tunnelSection
            }

            advancedToggle
            aboutSection
            dangerZoneSection
        }
        .formStyle(.grouped)
        .sheet(isPresented: $showEnrollmentSheet) {
            EnrollmentView(viewModel: enrollmentViewModel)
                .frame(width: 500, height: 450)
        }
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
        .overlay(alignment: .bottom) {
            if let field = copiedField {
                copiedToast(field)
            }
        }
        .animation(.easeInOut(duration: 0.25), value: showAdvanced)
        .animation(.easeInOut, value: viewModel.statusMessage)
    }

    // MARK: - General

    private var generalSection: some View {
        Section("General") {
            Toggle(isOn: $configuration.autoConnect) {
                Label("Connect on Launch", systemImage: "bolt.fill")
            }

            Toggle(isOn: $configuration.natAssist) {
                Label("NAT Traversal Assist", systemImage: "arrow.triangle.branch")
            }
        }
    }

    // MARK: - Identity

    private var identitySection: some View {
        Section("Identity") {
            if let identity = viewModel.identity {
                HStack {
                    Label("Node ID", systemImage: "number")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(identity.shortNodeId)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    copyButton(identity.nodeId, field: "Node ID")
                }

                HStack {
                    Label("Public Key", systemImage: "key")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(identity.shortPublicKey)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    copyButton(identity.publicKey, field: "Public Key")
                }

                HStack {
                    Label("Provider", systemImage: identity.isHardwareBacked ? "cpu" : "doc.text")
                        .foregroundStyle(.secondary)
                    Spacer()
                    HStack(spacing: 4) {
                        if identity.isHardwareBacked {
                            Image(systemName: "checkmark.shield.fill")
                                .font(.caption2)
                                .foregroundStyle(Color.ztlpGreen)
                        }
                        Text(identity.providerType.replacingOccurrences(of: "_", with: " ").capitalized)
                            .font(.caption)
                    }
                }

                Button {
                    showRegenConfirm = true
                } label: {
                    Label("Regenerate Identity", systemImage: "arrow.triangle.2.circlepath")
                        .font(.callout)
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
                VStack(spacing: 8) {
                    Text("No identity generated")
                        .font(.callout)
                        .foregroundStyle(.secondary)

                    Button("Generate Identity") {
                        Task { await viewModel.regenerateIdentity() }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Color.ztlpBlue)
                    .controlSize(.small)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
        }
    }

    // MARK: - Enrollment

    private var enrollmentSection: some View {
        Section("Enrollment") {
            HStack {
                Label("Status", systemImage: "checkmark.seal")
                    .foregroundStyle(.secondary)
                Spacer()
                if configuration.isEnrolled {
                    Label("Enrolled", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(Color.ztlpGreen)
                        .font(.callout)
                } else {
                    Label("Not Enrolled", systemImage: "xmark.circle")
                        .foregroundStyle(Color.ztlpOrange)
                        .font(.callout)
                }
            }

            if !configuration.zoneName.isEmpty {
                HStack {
                    Label("Zone", systemImage: "globe")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(configuration.zoneName)
                        .font(.callout.monospaced())
                }
            }

            Button {
                showEnrollmentSheet = true
            } label: {
                Label(
                    configuration.isEnrolled ? "Re-enroll Device" : "Enroll Device",
                    systemImage: "ticket"
                )
                .font(.callout)
            }
        }
    }

    // MARK: - Advanced Toggle

    private var advancedToggle: some View {
        Section {
            Button {
                showAdvanced.toggle()
            } label: {
                HStack {
                    Label("Advanced Settings", systemImage: "slider.horizontal.3")
                    Spacer()
                    Image(systemName: showAdvanced ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Connection (Advanced)

    private var connectionSection: some View {
        Section("Connection") {
            HStack {
                Label("Relay Server", systemImage: "antenna.radiowaves.left.and.right")
                Spacer()
                TextField("relay.ztlp.net:4433", text: $configuration.relayAddress)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textFieldStyle(.plain)
                    .frame(maxWidth: 250)
            }

            HStack {
                Label("STUN Server", systemImage: "network")
                Spacer()
                TextField("stun.l.google.com:19302", text: $configuration.stunServer)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textFieldStyle(.plain)
                    .frame(maxWidth: 250)
            }

            HStack {
                Label("Target Node ID", systemImage: "point.3.filled.connected.trianglepath.dotted")
                Spacer()
                TextField("Peer node ID (hex)", text: $configuration.targetNodeId)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textFieldStyle(.plain)
                    .frame(maxWidth: 250)
            }
        }
    }

    // MARK: - Tunnel (Advanced)

    private var tunnelSection: some View {
        Section("Tunnel") {
            HStack {
                Label("Tunnel Address", systemImage: "network.badge.shield.half.filled")
                Spacer()
                TextField("10.0.0.2", text: $configuration.tunnelAddress)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textFieldStyle(.plain)
                    .frame(maxWidth: 250)
            }

            HStack {
                Label("DNS Servers", systemImage: "server.rack")
                Spacer()
                TextField("1.1.1.1, 8.8.8.8", text: Binding(
                    get: { configuration.dnsServers.joined(separator: ", ") },
                    set: { newValue in
                        configuration.dnsServers = newValue
                            .split(separator: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                    }
                ))
                .multilineTextAlignment(.trailing)
                .font(.callout.monospaced())
                .textFieldStyle(.plain)
                .frame(maxWidth: 250)
            }

            Stepper(value: $configuration.mtu, in: 1200...1500, step: 50) {
                Label("MTU: \(configuration.mtu)", systemImage: "arrow.left.and.right")
            }
        }
    }

    // MARK: - About

    private var aboutSection: some View {
        Section("About") {
            infoRow(icon: "info.circle", label: "ZTLP Library", value: "v\(viewModel.libraryVersion)")
            infoRow(icon: "app", label: "App Version", value: appVersion)
            infoRow(icon: "desktopcomputer", label: "macOS", value: ProcessInfo.processInfo.operatingSystemVersionString)
        }
    }

    // MARK: - Danger Zone

    private var dangerZoneSection: some View {
        Section {
            Button(role: .destructive) {
                Task { await viewModel.removeVPNConfiguration() }
            } label: {
                Label("Remove VPN Configuration", systemImage: "xmark.shield")
                    .font(.callout)
            }

            Button(role: .destructive) {
                showResetConfirm = true
            } label: {
                Label("Factory Reset", systemImage: "trash")
                    .font(.callout)
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

    private func infoRow(icon: String, label: String, value: String) -> some View {
        HStack {
            Label(label, systemImage: icon)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(.tertiary)
        }
    }

    private func copyButton(_ text: String, field: String) -> some View {
        Button {
            viewModel.copyToClipboard(text)
            withAnimation(.easeInOut(duration: 0.2)) {
                copiedField = field
            }
            Task {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                withAnimation { copiedField = nil }
            }
        } label: {
            Image(systemName: "doc.on.doc")
                .font(.caption)
        }
        .buttonStyle(.borderless)
        .help("Copy \(field)")
    }

    private func copiedToast(_ field: String) -> some View {
        Text("\(field) copied")
            .font(.caption.weight(.medium))
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(.ultraThinMaterial, in: Capsule())
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .padding(.bottom, 12)
    }

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(version) (\(build))"
    }
}
