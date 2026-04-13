// HomeView.swift
// ZTLP
//
// Main connection screen with hero status ring, service cards,
// traffic stats, and quick-access vault button.

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: TunnelViewModel
    @ObservedObject var configuration: ZTLPConfiguration
    @EnvironmentObject var networkMonitor: NetworkMonitor

    @State private var ringRotation: Double = 0
    @State private var pulseScale: CGFloat = 1.0
    @State private var showVaultSheet = false
    @State private var browserURL: URL?

    /// Zone-qualified domain suffix (e.g., "techrockstars.ztlp")
    private var zoneSuffix: String {
        let bare = configuration.zoneName.replacingOccurrences(of: ".ztlp", with: "")
        return bare.isEmpty ? "ztlp" : "\(bare).ztlp"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    // Hero connection ring
                    heroSection

                    // Quick actions
                    if viewModel.status.isActive {
                        quickActionsSection
                    }

                    // Service status cards
                    if viewModel.status.isActive {
                        serviceCardsSection
                    }

                    // Traffic stats
                    if viewModel.status.isActive || viewModel.stats.bytesSent > 0 {
                        trafficStatsSection
                    }

                    // Network info
                    networkInfoSection
                }
                .padding(.horizontal)
                .padding(.bottom, 32)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("ZTLP")
            .safariSheet(url: $browserURL)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    connectionBadge
                }
            }
        }
    }

    // MARK: - Hero Section

    private var heroSection: some View {
        VStack(spacing: 20) {
            ZStack {
                // Outer glow ring
                Circle()
                    .stroke(
                        viewModel.status.gradient,
                        lineWidth: 4
                    )
                    .frame(width: 180, height: 180)
                    .scaleEffect(pulseScale)
                    .opacity(viewModel.status.isActive ? 0.3 : 0)

                // Main ring
                Circle()
                    .stroke(
                        viewModel.status.gradient,
                        lineWidth: 6
                    )
                    .frame(width: 160, height: 160)

                // Rotating accent (when connecting)
                if viewModel.status.isTransitioning {
                    Circle()
                        .trim(from: 0, to: 0.3)
                        .stroke(
                            Color.ztlpOrange,
                            style: StrokeStyle(lineWidth: 4, lineCap: .round)
                        )
                        .frame(width: 160, height: 160)
                        .rotationEffect(.degrees(ringRotation))
                }

                // Center content
                VStack(spacing: 8) {
                    Image(systemName: viewModel.status.systemImage)
                        .font(.system(size: 40, weight: .medium))
                        .foregroundStyle(viewModel.status.color)

                    Text(viewModel.status.label)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)

                    if viewModel.status.isActive {
                        Text(viewModel.stats.formattedDuration)
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .onAppear {
                withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) {
                    ringRotation = 360
                }
                withAnimation(.easeInOut(duration: 2).repeatForever(autoreverses: true)) {
                    pulseScale = 1.08
                }
            }

            // Connect / Disconnect button
            Button {
                if viewModel.status.canConnect {
                    viewModel.connect()
                } else if viewModel.status.canDisconnect {
                    viewModel.disconnect()
                }
            } label: {
                HStack(spacing: 8) {
                    if viewModel.status.isTransitioning {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            .scaleEffect(0.8)
                    }
                    Text(connectButtonLabel)
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(connectButtonGradient, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .foregroundColor(.white)
            }
            .disabled(!viewModel.status.canConnect && !viewModel.status.canDisconnect)
            .padding(.horizontal, 40)

            // Error banner
            if let error = viewModel.lastError {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(Color.ztlpOrange)
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(12)
                .background(Color.ztlpOrange.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .padding(.horizontal)
            }
        }
        .padding(.top, 12)
    }

    // MARK: - Quick Actions

    private var quickActionsSection: some View {
        HStack(spacing: 12) {
            QuickActionButton(
                icon: "lock.shield",
                title: "Open Vault",
                subtitle: "vault.\(zoneSuffix)",
                color: .ztlpBlue
            ) {
                if let url = URL(string: "http://vault.\(zoneSuffix)") {
                    browserURL = url
                } else {
                    showVaultSheet = true
                }
            }
            .sheet(isPresented: $showVaultSheet) {
                VaultAccessSheet(zoneSuffix: zoneSuffix, openURL: { url in
                    browserURL = url
                })
            }

            QuickActionButton(
                icon: "doc.text.magnifyingglass",
                title: "View Logs",
                subtitle: "Live tunnel",
                color: .ztlpGreen
            ) {
                // Navigate to logs tab
            }
        }
    }

    // MARK: - Service Cards

    private var serviceCardsSection: some View {
        let svcName = configuration.serviceName.isEmpty ? "vault" : configuration.serviceName

        return VStack(alignment: .leading, spacing: 12) {
            Text("ACTIVE SERVICES")
                .ztlpSectionHeader()

            VStack(spacing: 8) {
                ActiveServiceCard(
                    icon: "lock.shield.fill",
                    name: "Vaultwarden",
                    hostname: "vault.\(zoneSuffix)",
                    vip: "10.122.0.4",
                    port: 443,
                    proto: "https",
                    isActive: true,
                    openURL: { url in browserURL = url }
                )

                ActiveServiceCard(
                    icon: "globe",
                    name: svcName.capitalized,
                    hostname: "\(svcName).\(zoneSuffix)",
                    vip: "10.122.0.2",
                    port: 80,
                    proto: "http",
                    isActive: true,
                    openURL: { url in browserURL = url }
                )

                ActiveServiceCard(
                    icon: "lock.fill",
                    name: "\(svcName.capitalized) (HTTPS)",
                    hostname: "\(svcName).\(zoneSuffix)",
                    vip: "10.122.0.2",
                    port: 443,
                    proto: "https",
                    isActive: true,
                    openURL: { url in browserURL = url }
                )

                ActiveServiceCard(
                    icon: "network",
                    name: "HTTP Proxy",
                    hostname: "http.\(zoneSuffix)",
                    vip: "10.122.0.3",
                    port: 80,
                    proto: "http",
                    isActive: true,
                    openURL: { url in browserURL = url }
                )
            }
        }
    }

    // MARK: - Traffic Stats

    private var trafficStatsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("TRAFFIC")
                .ztlpSectionHeader()

            HStack(spacing: 16) {
                StatCard(
                    icon: "arrow.up.circle.fill",
                    label: "Sent",
                    value: viewModel.stats.formattedBytesSent,
                    color: .ztlpBlue
                )

                StatCard(
                    icon: "arrow.down.circle.fill",
                    label: "Received",
                    value: viewModel.stats.formattedBytesReceived,
                    color: .ztlpGreen
                )
            }
        }
    }

    // MARK: - Network Info

    private var networkInfoSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("NETWORK")
                .ztlpSectionHeader()

            HStack(spacing: 12) {
                Label {
                    Text(String(describing: networkMonitor.interfaceType))
                        .font(.subheadline)
                } icon: {
                    Image(systemName: networkMonitor.isConnected ? "wifi" : "wifi.slash")
                        .foregroundStyle(networkMonitor.isConnected ? Color.ztlpGreen : Color.ztlpRed)
                }

                Spacer()

                if !configuration.zoneName.isEmpty {
                    Label {
                        Text(configuration.zoneName)
                            .font(.caption.monospaced())
                    } icon: {
                        Image(systemName: "globe.americas")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .ztlpCard()
        }
    }

    // MARK: - Helpers

    private var connectionBadge: some View {
        Circle()
            .fill(viewModel.status.color)
            .frame(width: 10, height: 10)
            .overlay(
                Circle()
                    .stroke(Color(.systemBackground), lineWidth: 2)
            )
    }

    private var connectButtonLabel: String {
        switch viewModel.status {
        case .disconnected:  return "Connect"
        case .connecting:    return "Connecting\u{2026}"
        case .connected:     return "Disconnect"
        case .reconnecting:  return "Reconnecting\u{2026}"
        case .disconnecting: return "Disconnecting\u{2026}"
        }
    }

    private var connectButtonGradient: LinearGradient {
        if viewModel.status.canConnect {
            return .ztlpConnected
        } else if viewModel.status.canDisconnect {
            return LinearGradient(colors: [Color.ztlpRed, Color.ztlpRed.opacity(0.8)], startPoint: .leading, endPoint: .trailing)
        } else {
            return .ztlpDisconnected
        }
    }
}

// MARK: - Quick Action Button

private struct QuickActionButton: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(color)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .ztlpCard()
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Active Service Card (tappable — opens in-app browser)

private struct ActiveServiceCard: View {
    let icon: String
    let name: String
    let hostname: String
    let vip: String
    let port: UInt16
    let proto: String  // "http" or "https"
    let isActive: Bool
    let openURL: (URL) -> Void

    /// Build the URL to present in the in-app browser using DNS-resolved hostnames.
    private var serviceURL: String {
        if port == 80 || port == 443 {
            return "\(proto)://\(hostname)"
        }
        return "\(proto)://\(hostname):\(port)"
    }

    var body: some View {
        Button {
            if let url = URL(string: serviceURL) {
                openURL(url)
            }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundStyle(isActive ? Color.ztlpGreen : .secondary)
                    .frame(width: 32)

                VStack(alignment: .leading, spacing: 2) {
                    Text(name)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.primary)
                    Text(hostname)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }

                Spacer()

                VStack(alignment: .trailing, spacing: 2) {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(isActive ? Color.ztlpGreen : Color.ztlpRed)
                            .frame(width: 8, height: 8)
                        Image(systemName: "arrow.up.right.square")
                            .font(.caption2)
                            .foregroundStyle(Color.ztlpBlue)
                    }
                    Text(vip)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }
            .ztlpCard(padding: 12)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Stat Card

private struct StatCard: View {
    let icon: String
    let label: String
    let value: String
    let color: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(color)

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.subheadline.weight(.semibold).monospacedDigit())
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .ztlpCard(padding: 12)
    }
}

// MARK: - Vault Access Sheet

private struct VaultAccessSheet: View {
    let zoneSuffix: String
    let openURL: (URL) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var showCertInfo = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                // Vault icon
                ZStack {
                    Circle()
                        .fill(LinearGradient.ztlpShield)
                        .frame(width: 80, height: 80)
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 36))
                        .foregroundStyle(.white)
                }
                .padding(.top, 20)

                VStack(spacing: 8) {
                    Text("Vaultwarden")
                        .font(.title2.weight(.bold))
                    Text("vault.\(zoneSuffix)")
                        .font(.caption.monospaced())
                        .foregroundStyle(Color.ztlpBlue)
                    Text("Your password vault is accessible through\nthe encrypted ZTLP tunnel.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                VStack(spacing: 12) {
                    VaultLinkRow(
                        title: "Web Vault",
                        url: "https://vault.\(zoneSuffix)",
                        icon: "lock.fill",
                        note: "vault.\(zoneSuffix)",
                        openURL: openURL
                    )

                    VaultLinkRow(
                        title: "Web Vault (HTTP)",
                        url: "http://vault.\(zoneSuffix)",
                        icon: "globe",
                        note: "No certificate required",
                        openURL: openURL
                    )

                    VaultLinkRow(
                        title: "Bitwarden Sync URL",
                        url: "http://vault.\(zoneSuffix)",
                        icon: "arrow.triangle.2.circlepath",
                        note: "Set this in Bitwarden app settings",
                        openURL: openURL
                    )
                }
                .padding(.horizontal)

                Button {
                    showCertInfo = true
                } label: {
                    Label("Set up HTTPS Certificate", systemImage: "checkmark.shield")
                        .font(.subheadline)
                }
                .sheet(isPresented: $showCertInfo) {
                    CertificateTrustGuide()
                }

                Spacer()
            }
            .navigationTitle("Vault Access")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

private struct VaultLinkRow: View {
    let title: String
    let url: String
    let icon: String
    let note: String
    let openURL: (URL) -> Void

    var body: some View {
        Button {
            if let url = URL(string: url) {
                openURL(url)
            }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundStyle(Color.ztlpBlue)
                    .frame(width: 32)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.primary)
                    Text(note)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Image(systemName: "arrow.up.right.square")
                    .font(.caption)
                    .foregroundStyle(Color.ztlpBlue)
            }
            .ztlpCard(padding: 12)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Certificate Trust Guide

struct CertificateTrustGuide: View {
    @Environment(\.dismiss) private var dismiss
    @State private var isInstallingCert = false
    @State private var certError: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
                    VStack(spacing: 8) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 48))
                            .foregroundStyle(Color.ztlpGreen)

                        Text("HTTPS Certificate Trust")
                            .font(.title3.weight(.bold))

                        Text("Install the ZTLP CA certificate to access services over HTTPS without browser warnings.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.top, 12)

                    // Steps
                    VStack(alignment: .leading, spacing: 16) {
                        StepRow(number: 1, text: "Tap \"Install Certificate\" below to download the CA profile")
                        StepRow(number: 2, text: "Open Settings \u{2192} General \u{2192} VPN & Device Management")
                        StepRow(number: 3, text: "Tap the ZTLP CA profile and tap Install")
                        StepRow(number: 4, text: "Go to Settings \u{2192} General \u{2192} About \u{2192} Certificate Trust Settings")
                        StepRow(number: 5, text: "Enable full trust for the ZTLP CA certificate")
                    }
                    .padding()
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))

                    // Install button
                    Button {
                        installCertificate()
                    } label: {
                        HStack {
                            if isInstallingCert {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            }
                            Text("Install Certificate")
                                .font(.headline)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color.ztlpBlue, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .foregroundColor(.white)
                    }
                    .disabled(isInstallingCert)

                    if let error = certError {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(Color.ztlpRed)
                    }

                    // Note
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundStyle(Color.ztlpBlue)
                        Text("The tunnel itself is already encrypted with Noise_XX. HTTPS adds browser-level trust for web vault access. This step is optional.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding()
                    .background(Color.ztlpBlue.opacity(0.05))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
                .padding()
            }
            .navigationTitle("Certificate Setup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func installCertificate() {
        isInstallingCert = true
        certError = nil

        // installCACert handles everything: generates .mobileconfig,
        // starts local HTTP server, and opens Safari
        CertificateService.shared.installCACert()

        // Give it a moment then reset state
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            isInstallingCert = false
        }
    }
}

private struct StepRow: View {
    let number: Int
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.caption.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 24, height: 24)
                .background(Color.ztlpBlue, in: Circle())

            Text(text)
                .font(.subheadline)
                .foregroundStyle(.primary)
        }
    }
}

// MARK: - Previews

#Preview("Connected") {
    let config = ZTLPConfiguration()
    HomeView(
        viewModel: TunnelViewModel(configuration: config),
        configuration: config
    )
    .environmentObject(NetworkMonitor.shared)
}

#Preview("Disconnected") {
    let config = ZTLPConfiguration()
    HomeView(
        viewModel: TunnelViewModel(configuration: config),
        configuration: config
    )
    .environmentObject(NetworkMonitor.shared)
}
