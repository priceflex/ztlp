// SettingsView.swift
// ZTLP
//
// Unified settings: General, Identity, Enrollment, Advanced (collapsed), About, Danger Zone.
// Mirrors the macOS SettingsView structure with iOS-appropriate controls.

import SwiftUI

struct SettingsView: View {
    @ObservedObject var viewModel: SettingsViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @State private var showAdvanced = false
    @State private var showRegenConfirm = false
    @State private var showResetConfirm = false
    @State private var showEnrollmentSheet = false
    @State private var showLicenses = false

    var body: some View {
        NavigationStack {
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
            .navigationTitle("Settings")
            .sheet(isPresented: $showEnrollmentSheet) {
                NavigationStack {
                    EnrollmentView(viewModel: enrollmentViewModel)
                        .navigationTitle("Enroll Device")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Done") { showEnrollmentSheet = false }
                            }
                        }
                }
            }
            .animation(.easeInOut(duration: 0.25), value: showAdvanced)
            .animation(.easeInOut(duration: 0.25), value: showLicenses)
        }
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

            Toggle(isOn: $configuration.useSecureEnclave) {
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
                }

                HStack {
                    Label("Public Key", systemImage: "key")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(identity.shortPublicKey)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
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
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }

            HStack {
                Label("NS Server", systemImage: "globe.americas")
                Spacer()
                TextField("52.39.59.34:23096", text: $configuration.nsServer)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }

            HStack {
                Label("Service Name", systemImage: "server.rack")
                Spacer()
                TextField("vault", text: $configuration.serviceName)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }

            HStack {
                Label("STUN Server", systemImage: "network")
                Spacer()
                TextField("stun.l.google.com:19302", text: $configuration.stunServer)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }

            HStack {
                Label("Target Node ID", systemImage: "point.3.filled.connected.trianglepath.dotted")
                Spacer()
                TextField("Peer node ID (hex)", text: $configuration.targetNodeId)
                    .multilineTextAlignment(.trailing)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
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
                    .textInputAutocapitalization(.never)
                    .keyboardType(.numbersAndPunctuation)
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
                .textInputAutocapitalization(.never)
                .keyboardType(.numbersAndPunctuation)
            }

            Stepper(value: $configuration.mtu, in: 1200...1500, step: 50) {
                Label("MTU: \(configuration.mtu)", systemImage: "arrow.left.and.right")
            }

            Toggle(isOn: $configuration.fullTunnel) {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Full Tunnel", systemImage: "shield.fill")
                    Text("Route all traffic through VPN (default: .ztlp domains only)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: - About

    private var aboutSection: some View {
        Section("About") {
            // App info
            VStack(spacing: 12) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 36))
                    .foregroundStyle(Color.ztlpBlue)

                Text("ZTLP")
                    .font(.title2.weight(.bold))

                Text("Zero Trust Layer Protocol")
                    .font(.callout)
                    .foregroundStyle(.secondary)

                Text("v\(viewModel.libraryVersion)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)

            // Author
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Label("Author", systemImage: "person.fill")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("Steven Price")
                        .font(.callout)
                }
                HStack {
                    Label("Organization", systemImage: "building.2")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("Tech Rockstar Academy")
                        .font(.callout)
                }
            }

            // Links
            HStack {
                Label("Website", systemImage: "globe")
                    .foregroundStyle(.secondary)
                Spacer()
                Link("ztlp.org", destination: URL(string: "https://ztlp.org")!)
                    .font(.callout)
            }

            HStack {
                Label("Source", systemImage: "chevron.left.forwardslash.chevron.right")
                    .foregroundStyle(.secondary)
                Spacer()
                Link("GitHub", destination: URL(string: "https://github.com/priceflex/ztlp")!)
                    .font(.callout)
            }

            HStack {
                Label("License", systemImage: "doc.text")
                    .foregroundStyle(.secondary)
                Spacer()
                Text("Apache 2.0")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            // Version info
            infoRow(icon: "app", label: "App Version", value: appVersion)
            infoRow(icon: "iphone", label: "iOS", value: UIDevice.current.systemVersion)

            // Open Source
            Button {
                showLicenses.toggle()
            } label: {
                HStack {
                    Label("Open Source Licenses", systemImage: "heart.fill")
                        .foregroundStyle(Color.ztlpBlue)
                    Spacer()
                    Image(systemName: showLicenses ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .buttonStyle(.plain)

            if showLicenses {
                openSourceCredits
            }
        }
    }

    // MARK: - Open Source Credits

    private var openSourceCredits: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("ZTLP is built with these outstanding open source projects:")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.bottom, 4)

            // Cryptography
            licenseSectionHeader("Cryptography")
            licenseRow("snow", desc: "Noise Protocol Framework", license: "Apache-2.0", url: "https://github.com/mcginty/snow")
            licenseRow("chacha20poly1305", desc: "AEAD cipher", license: "Apache-2.0/MIT", url: "https://github.com/RustCrypto/AEADs")
            licenseRow("ed25519-dalek", desc: "Ed25519 signatures", license: "BSD-3-Clause", url: "https://github.com/dalek-cryptography/ed25519-dalek")
            licenseRow("curve25519-dalek", desc: "Elliptic curve operations", license: "BSD-3-Clause", url: "https://github.com/dalek-cryptography/curve25519-dalek")
            licenseRow("blake2", desc: "BLAKE2 hash function", license: "Apache-2.0/MIT", url: "https://github.com/RustCrypto/hashes")
            licenseRow("subtle", desc: "Constant-time operations", license: "BSD-3-Clause", url: "https://github.com/dalek-cryptography/subtle")

            // Runtime & Async
            licenseSectionHeader("Runtime")
            licenseRow("tokio", desc: "Async runtime for Rust", license: "MIT", url: "https://github.com/tokio-rs/tokio")
            licenseRow("tokio-rustls", desc: "TLS for async I/O", license: "Apache-2.0/MIT", url: "https://github.com/rustls/tokio-rustls")
            licenseRow("tracing", desc: "Structured logging", license: "MIT", url: "https://github.com/tokio-rs/tracing")

            // Serialization
            licenseSectionHeader("Serialization & CLI")
            licenseRow("serde", desc: "Serialization framework", license: "Apache-2.0/MIT", url: "https://github.com/serde-rs/serde")
            licenseRow("clap", desc: "Command-line argument parser", license: "Apache-2.0/MIT", url: "https://github.com/clap-rs/clap")
            licenseRow("toml", desc: "TOML parser", license: "Apache-2.0/MIT", url: "https://github.com/toml-rs/toml")
            licenseRow("base64", desc: "Base64 encoding", license: "Apache-2.0/MIT", url: "https://github.com/marshallpierce/rust-base64")
            licenseRow("hex", desc: "Hex encoding", license: "Apache-2.0/MIT", url: "https://github.com/KokaKiwi/rust-hex")

            // Utilities
            licenseSectionHeader("Utilities")
            licenseRow("rand", desc: "Random number generation", license: "Apache-2.0/MIT", url: "https://github.com/rust-random/rand")
            licenseRow("thiserror", desc: "Error derive macros", license: "Apache-2.0/MIT", url: "https://github.com/dtolnay/thiserror")
            licenseRow("dialoguer", desc: "Terminal prompts", license: "MIT", url: "https://github.com/console-rs/dialoguer")
            licenseRow("indicatif", desc: "Progress bars", license: "MIT", url: "https://github.com/console-rs/indicatif")
            licenseRow("colored", desc: "Terminal colors", license: "MPL-2.0", url: "https://github.com/mackwic/colored")
            licenseRow("qr2term", desc: "QR codes in terminal", license: "MIT", url: "https://github.com/nickel-org/qr2term")
            licenseRow("dirs", desc: "Platform directories", license: "Apache-2.0/MIT", url: "https://github.com/dirs-dev/dirs-rs")
            licenseRow("hostname", desc: "System hostname", license: "MIT", url: "https://github.com/svartalf/hostname")
            licenseRow("libc", desc: "C library bindings", license: "Apache-2.0/MIT", url: "https://github.com/rust-lang/libc")

            // Elixir / OTP
            licenseSectionHeader("Server (Elixir/OTP)")
            licenseRow("Elixir", desc: "Dynamic, functional language", license: "Apache-2.0", url: "https://github.com/elixir-lang/elixir")
            licenseRow("Erlang/OTP", desc: "Concurrent runtime system", license: "Apache-2.0", url: "https://github.com/erlang/otp")
        }
        .padding(.vertical, 4)
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

    private func licenseSectionHeader(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.tertiary)
            .padding(.top, 4)
    }

    private func licenseRow(_ name: String, desc: String, license: String, url: String) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Link(name, destination: URL(string: url)!)
                    .font(.caption.weight(.medium))
                Text(desc)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(license)
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
        }
    }

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(version) (\(build))"
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
