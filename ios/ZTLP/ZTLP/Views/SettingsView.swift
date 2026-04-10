// SettingsView.swift
// ZTLP
//
// Comprehensive settings with grouped form layout.
// Sections: General, Identity, Enrollment, Certificate Trust,
// Connection, About, Danger Zone.

import SwiftUI

struct SettingsView: View {
    @ObservedObject var viewModel: SettingsViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @State private var showEnrollment = false
    @State private var showResetConfirmation = false
    @State private var showRemoveVPNConfirmation = false
    @State private var showAdvanced = false
    @State private var showCertTrust = false
    @State private var showLicenses = false

    var body: some View {
        NavigationStack {
            Form {
                generalSection
                identitySection
                enrollmentSection
                certificateSection

                if showAdvanced {
                    connectionSection
                    tunnelSection
                }

                advancedToggleSection
                aboutSection
                dangerZoneSection
            }
            
            .navigationTitle("Settings")
            .sheet(isPresented: $showEnrollment) {
                EnrollmentView(
                    viewModel: enrollmentViewModel,
                    onComplete: nil
                )
            }
            .sheet(isPresented: $showCertTrust) {
                CertificateTrustGuide()
            }
            .sheet(isPresented: $showLicenses) {
                licensesSheet
            }
        }
    }

    // MARK: - General

    private var generalSection: some View {
        Section {
            Toggle(isOn: $configuration.autoConnect) {
                Label("Auto-Connect on Launch", systemImage: "bolt.fill")
            }
            .tint(Color.ztlpBlue)

            Toggle(isOn: $configuration.natAssist) {
                Label("NAT Traversal Assist", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .tint(Color.ztlpBlue)

            Toggle(isOn: $configuration.useSecureEnclave) {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Secure Enclave Keys")
                        if !viewModel.secureEnclaveAvailable {
                            Text("Not available on this device")
                                .font(.caption2)
                                .foregroundStyle(Color.ztlpOrange)
                        }
                    }
                } icon: {
                    Image(systemName: "cpu")
                }
            }
            .tint(Color.ztlpBlue)
            .disabled(!viewModel.secureEnclaveAvailable)
        } header: {
            Text("General")
                .ztlpSectionHeader()
        }
    }

    // MARK: - Identity

    private var identitySection: some View {
        Section {
            if let identity = viewModel.identity {
                HStack {
                    Label("Node ID", systemImage: "person.badge.key")
                    Spacer()
                    Text(identity.shortNodeId)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    CopyButton(text: identity.nodeId)
                }

                HStack {
                    Label("Public Key", systemImage: "key.fill")
                    Spacer()
                    Text(identity.shortPublicKey)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    CopyButton(text: identity.publicKey)
                }

                HStack {
                    Label("Provider", systemImage: identity.isHardwareBacked ? "cpu" : "doc.fill")
                    Spacer()
                    Text(identity.providerType.replacingOccurrences(of: "_", with: " ").capitalized)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                HStack {
                    Label("No Identity", systemImage: "person.badge.key")
                    Spacer()
                    Text("Not generated")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        } header: {
            Text("Identity")
                .ztlpSectionHeader()
        }
    }

    // MARK: - Enrollment

    private var enrollmentSection: some View {
        Section {
            HStack {
                Label("Status", systemImage: "ticket")
                Spacer()
                if configuration.isEnrolled {
                    Label("Enrolled", systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(Color.ztlpGreen)
                } else {
                    Text("Not Enrolled")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if !configuration.zoneName.isEmpty {
                HStack {
                    Label("Zone", systemImage: "globe.americas")
                    Spacer()
                    Text(configuration.zoneName)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            if !configuration.isEnrolled {
                Button {
                    showEnrollment = true
                } label: {
                    Label("Enroll Device", systemImage: "qrcode.viewfinder")
                }
            } else {
                Button {
                    showEnrollment = true
                } label: {
                    Label("Re-enroll Device", systemImage: "arrow.clockwise")
                }
            }
        } header: {
            Text("Enrollment")
                .ztlpSectionHeader()
        }
    }

    // MARK: - Certificate Trust

    private var certificateSection: some View {
        Section {
            Button {
                showCertTrust = true
            } label: {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Install HTTPS Certificate")
                        Text("Required for HTTPS access to services")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "checkmark.shield")
                }
            }
        } header: {
            Text("Certificate Trust")
                .ztlpSectionHeader()
        } footer: {
            Text("The tunnel is already end-to-end encrypted. This certificate enables browser HTTPS trust for web vault access.")
        }
    }

    // MARK: - Connection (Advanced)

    private var connectionSection: some View {
        Section {
            HStack {
                Label("Relay Server", systemImage: "point.3.connected.trianglepath.dotted")
                Spacer()
                TextField("relay.ztlp.net:4433", text: $configuration.relayAddress)
                    .font(.caption.monospaced())
                    .multilineTextAlignment(.trailing)
            }

            HStack {
                Label("Gateway", systemImage: "server.rack")
                Spacer()
                TextField("host:port", text: $configuration.targetNodeId)
                    .font(.caption.monospaced())
                    .multilineTextAlignment(.trailing)
            }

            HStack {
                Label("NS Server", systemImage: "network")
                Spacer()
                TextField("ns.ztlp.net:23096", text: $configuration.nsServer)
                    .font(.caption.monospaced())
                    .multilineTextAlignment(.trailing)
            }

            HStack {
                Label("Service Name", systemImage: "tag")
                Spacer()
                TextField("vault", text: $configuration.serviceName)
                    .font(.caption.monospaced())
                    .multilineTextAlignment(.trailing)
            }

            HStack {
                Label("STUN Server", systemImage: "antenna.radiowaves.left.and.right")
                Spacer()
                TextField("stun.l.google.com:19302", text: $configuration.stunServer)
                    .font(.caption.monospaced())
                    .multilineTextAlignment(.trailing)
            }
        } header: {
            Text("Connection")
                .ztlpSectionHeader()
        }
    }

    // MARK: - Tunnel (Advanced)

    private var tunnelSection: some View {
        Section {
            HStack {
                Label("Tunnel Address", systemImage: "network.badge.shield.half.filled")
                Spacer()
                TextField("10.0.0.2", text: $configuration.tunnelAddress)
                    .font(.caption.monospaced())
                    .multilineTextAlignment(.trailing)
            }

            Picker(selection: $configuration.mtu) {
                Text("1280").tag(1280)
                Text("1400 (recommended)").tag(1400)
                Text("1500").tag(1500)
            } label: {
                Label("MTU", systemImage: "ruler")
            }

            Toggle(isOn: $configuration.fullTunnel) {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Full Tunnel Mode")
                        Text("Route all traffic through ZTLP")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "arrow.triangle.branch")
                }
            }
            .tint(Color.ztlpBlue)
        } header: {
            Text("Tunnel")
                .ztlpSectionHeader()
        }
    }

    // MARK: - Advanced Toggle

    private var advancedToggleSection: some View {
        Section {
            Button {
                withAnimation { showAdvanced.toggle() }
            } label: {
                Label(
                    showAdvanced ? "Hide Advanced Settings" : "Show Advanced Settings",
                    systemImage: showAdvanced ? "chevron.up" : "chevron.down"
                )
            }
        }
    }

    // MARK: - About

    private var aboutSection: some View {
        Section {
            HStack {
                Label("App Version", systemImage: "info.circle")
                Spacer()
                Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Label("Library Version", systemImage: "gearshape.2")
                Spacer()
                Text(viewModel.libraryVersion)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            HStack {
                Label("Author", systemImage: "person")
                Spacer()
                Text("Steven Price / Tech Rockstars")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Link(destination: URL(string: "https://ztlp.org")!) {
                Label("Website", systemImage: "globe")
            }

            Link(destination: URL(string: "https://github.com/priceflex/ztlp")!) {
                Label("Source Code", systemImage: "chevron.left.forwardslash.chevron.right")
            }

            Button {
                showLicenses = true
            } label: {
                Label("Open Source Licenses", systemImage: "doc.text")
            }
        } header: {
            Text("About")
                .ztlpSectionHeader()
        }
    }

    // MARK: - Danger Zone

    private var dangerZoneSection: some View {
        Section {
            Button(role: .destructive) {
                showRemoveVPNConfirmation = true
            } label: {
                Label("Remove VPN Configuration", systemImage: "trash")
            }
            .confirmationDialog(
                "Remove VPN Configuration?",
                isPresented: $showRemoveVPNConfirmation,
                titleVisibility: .visible
            ) {
                Button("Remove", role: .destructive) {
                    Task { await viewModel.removeVPNConfiguration() }
                }
            } message: {
                Text("This will remove the ZTLP VPN profile from this device. You can re-add it by connecting again.")
            }

            Button(role: .destructive) {
                showResetConfirmation = true
            } label: {
                Label("Factory Reset", systemImage: "exclamationmark.triangle")
            }
            .confirmationDialog(
                "Factory Reset?",
                isPresented: $showResetConfirmation,
                titleVisibility: .visible
            ) {
                Button("Reset Everything", role: .destructive) {
                    Task {
                        await viewModel.factoryReset()
                        await MainActor.run { configuration.reset() }
                    }
                }
            } message: {
                Text("This will delete your identity, enrollment, and all settings. This cannot be undone.")
            }
        } header: {
            Text("Danger Zone")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Color.ztlpRed)
                .textCase(.uppercase)
                .tracking(0.5)
        }
    }

    // MARK: - Licenses Sheet

    private var licensesSheet: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Group {
                        LicenseEntry(
                            name: "ZTLP Protocol Library",
                            license: "Proprietary \u{2014} Tech Rockstars LLC",
                            url: "https://github.com/priceflex/ztlp"
                        )
                        LicenseEntry(
                            name: "snow (Noise Protocol)",
                            license: "Apache-2.0",
                            url: "https://github.com/mcginty/snow"
                        )
                        LicenseEntry(
                            name: "x25519-dalek",
                            license: "BSD-3-Clause",
                            url: "https://github.com/dalek-cryptography/x25519-dalek"
                        )
                        LicenseEntry(
                            name: "blake2",
                            license: "MIT OR Apache-2.0",
                            url: "https://github.com/RustCrypto/hashes"
                        )
                        LicenseEntry(
                            name: "chacha20poly1305",
                            license: "MIT OR Apache-2.0",
                            url: "https://github.com/RustCrypto/AEADs"
                        )
                    }
                }
                .padding()
            }
            .navigationTitle("Open Source Licenses")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { showLicenses = false }
                }
            }
        }
    }
}

// MARK: - Copy Button

private struct CopyButton: View {
    let text: String
    @State private var copied = false

    var body: some View {
        Button {
            UIPasteboard.general.string = text
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                copied = false
            }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .font(.caption2)
                .foregroundStyle(copied ? Color.ztlpGreen : Color.ztlpBlue)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - License Entry

private struct LicenseEntry: View {
    let name: String
    let license: String
    let url: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(name)
                .font(.subheadline.weight(.semibold))
            Text(license)
                .font(.caption)
                .foregroundStyle(.secondary)
            if let link = URL(string: url) {
                Link(url, destination: link)
                    .font(.caption2)
                    .foregroundStyle(Color.ztlpBlue)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Previews

#Preview {
    let config = ZTLPConfiguration()
    SettingsView(
        viewModel: SettingsViewModel(configuration: config),
        enrollmentViewModel: EnrollmentViewModel(configuration: config),
        configuration: config
    )
}
