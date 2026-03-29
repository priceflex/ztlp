// HomeView.swift
// ZTLP
//
// Main connect/disconnect screen with status indicator,
// connection timer, traffic stats, and VIP proxy access.
//
// When connected via Direct Connect, shows the VIP proxy URL
// (http://127.0.0.1:8080) with a tap-to-open button for Safari.

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: TunnelViewModel
    @ObservedObject var configuration: ZTLPConfiguration
    @StateObject private var certService = CertificateService.shared
    @EnvironmentObject var networkMonitor: NetworkMonitor

    /// Animation state for the pulsing status ring.
    @State private var isPulsing = false

    /// Timer for updating the duration display.
    @State private var durationTimer = Timer.publish(every: 1, on: .main, in: .common)
        .autoconnect()
    @State private var currentDuration: String = "--:--:--"

    /// VIP proxy URL for Safari access.
    private let vipURL = "http://127.0.0.1:8080"

    var body: some View {
        NavigationStack {
            ZStack {
                // Background gradient
                backgroundGradient
                    .ignoresSafeArea()

                VStack(spacing: 32) {
                    Spacer()

                    // Zone name
                    if !viewModel.zoneName.isEmpty {
                        Text(viewModel.zoneName)
                            .font(.headline)
                            .foregroundStyle(.secondary)
                    }

                    // Status indicator + connect button
                    statusButton

                    // Status label
                    Text(viewModel.status.label)
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(viewModel.status.color)
                        .animation(.easeInOut, value: viewModel.status)

                    // CA Trust card (shown after enrollment, before cert is installed)
                    if configuration.isEnrolled && !certService.isInstalled {
                        caTrustCard
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }

                    // Connection duration
                    if viewModel.status == .connected {
                        Text(currentDuration)
                            .font(.system(.title3, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .onReceive(durationTimer) { _ in
                                currentDuration = viewModel.stats.formattedDuration
                            }
                    }

                    // VIP proxy access card (when connected)
                    if viewModel.status == .connected {
                        vipAccessCard
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }

                    Spacer()

                    // Traffic stats
                    if viewModel.status.isActive {
                        trafficStatsView
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }

                    // Network indicator
                    networkIndicator

                    // Error message
                    if let error = viewModel.lastError {
                        errorBanner(error)
                    }
                }
                .padding()
            }
            .navigationTitle("ZTLP")
            .navigationBarTitleDisplayMode(.inline)
            .animation(.spring(response: 0.4), value: viewModel.status)
        }
    }

    // MARK: - Subviews

    /// The main connect/disconnect button with animated status ring.
    private var statusButton: some View {
        Button {
            viewModel.toggleConnection()
        } label: {
            ZStack {
                // Outer pulsing ring (when connected)
                if viewModel.status == .connected {
                    Circle()
                        .stroke(viewModel.status.color.opacity(0.3), lineWidth: 4)
                        .frame(width: 180, height: 180)
                        .scaleEffect(isPulsing ? 1.15 : 1.0)
                        .opacity(isPulsing ? 0.0 : 0.6)
                        .animation(
                            .easeInOut(duration: 2.0).repeatForever(autoreverses: false),
                            value: isPulsing
                        )
                }

                // Status ring
                Circle()
                    .stroke(viewModel.status.color, lineWidth: 6)
                    .frame(width: 160, height: 160)

                // Spinning ring (when transitioning)
                if viewModel.status.isTransitioning {
                    Circle()
                        .trim(from: 0, to: 0.3)
                        .stroke(viewModel.status.color, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                        .frame(width: 160, height: 160)
                        .rotationEffect(.degrees(isPulsing ? 360 : 0))
                        .animation(
                            .linear(duration: 1.0).repeatForever(autoreverses: false),
                            value: isPulsing
                        )
                }

                // Center icon
                VStack(spacing: 8) {
                    Image(systemName: viewModel.status.systemImage)
                        .font(.system(size: 48))
                        .foregroundStyle(viewModel.status.color)

                    Text(viewModel.status.canConnect ? "Connect" : "Disconnect")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(!viewModel.status.canConnect && !viewModel.status.canDisconnect)
        .accessibilityLabel(viewModel.status.canConnect ? "Connect" : "Disconnect")
        .accessibilityHint(viewModel.status.label)
        .onAppear { isPulsing = true }
    }

    /// CA trust card — prompts user to install the ZTLP CA certificate.
    private var caTrustCard: some View {
        VStack(spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "lock.shield.fill")
                    .font(.title2)
                    .foregroundStyle(Color.ztlpOrange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Install ZTLP Certificate")
                        .font(.callout.weight(.semibold))
                    Text("Required for HTTPS access to ZTLP services")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            if certService.caRootDER != nil {
                // Cert is fetched, ready to install
                Button {
                    certService.installCACert()
                } label: {
                    HStack {
                        Image(systemName: "square.and.arrow.down.fill")
                        Text("Install Certificate")
                            .font(.callout.weight(.semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color.ztlpBlue, in: RoundedRectangle(cornerRadius: 10))
                    .foregroundStyle(.white)
                }

                // After Safari opens, show confirm button
                if UserDefaults.standard.bool(forKey: "ztlp_ca_install_attempted") {
                    Button {
                        certService.markAsInstalled()
                    } label: {
                        HStack {
                            Image(systemName: "checkmark.circle")
                            Text("Done — I've installed it")
                                .font(.caption)
                        }
                        .foregroundStyle(Color.ztlpGreen)
                    }
                    .padding(.top, 4)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("After downloading in Safari:")
                            .font(.caption2.weight(.medium))
                        Text("Settings → General → VPN & Device Mgmt → Install")
                            .font(.caption2)
                        Text("Settings → General → About → Certificate Trust → Enable")
                            .font(.caption2)
                    }
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                // Need to fetch first
                Button {
                    Task {
                        let ns = configuration.nsServer.isEmpty ? "34.217.62.46:23096" : configuration.nsServer
                        await certService.fetchCARootCert(nsServer: ns)
                    }
                } label: {
                    HStack {
                        if certService.isFetching {
                            ProgressView()
                                .controlSize(.small)
                                .tint(.white)
                        } else {
                            Image(systemName: "arrow.down.circle.fill")
                        }
                        Text(certService.isFetching ? "Fetching..." : "Download Certificate")
                            .font(.callout.weight(.semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color.ztlpOrange, in: RoundedRectangle(cornerRadius: 10))
                    .foregroundStyle(.white)
                }
                .disabled(certService.isFetching)
            }

            if let error = certService.errorMessage {
                Text(error)
                    .font(.caption2)
                    .foregroundStyle(.red)
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    /// VIP proxy access card — shows URL and tap-to-open button.
    private var vipAccessCard: some View {
        VStack(spacing: 12) {
            // VIP status
            if let vipStatus = viewModel.vipStatus {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                    Text(vipStatus)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            // Access URL button
            Button {
                if let url = URL(string: vipURL) {
                    UIApplication.shared.open(url)
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "safari")
                        .font(.title3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Open in Safari")
                            .font(.callout.weight(.semibold))
                        Text(vipURL)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "arrow.up.right.square")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .background(Color.ztlpBlue.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Open service in Safari at \(vipURL)")

            // Peer address
            if !viewModel.peerAddress.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "point.3.filled.connected.trianglepath.dotted")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    Text("Peer: \(viewModel.peerAddress)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    /// Traffic statistics (upload/download).
    private var trafficStatsView: some View {
        HStack(spacing: 40) {
            // Upload
            VStack(spacing: 4) {
                Image(systemName: "arrow.up")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(viewModel.stats.formattedBytesSent)
                    .font(.system(.body, design: .monospaced))
                Text("Sent")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Sent \(viewModel.stats.formattedBytesSent)")

            // Divider
            Rectangle()
                .fill(.quaternary)
                .frame(width: 1, height: 40)

            // Download
            VStack(spacing: 4) {
                Image(systemName: "arrow.down")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(viewModel.stats.formattedBytesReceived)
                    .font(.system(.body, design: .monospaced))
                Text("Received")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Received \(viewModel.stats.formattedBytesReceived)")
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    /// Network connectivity indicator.
    private var networkIndicator: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(networkMonitor.isConnected ? .green : .red)
                .frame(width: 8, height: 8)
            Text(networkMonitor.interfaceType.rawValue)
                .font(.caption)
                .foregroundStyle(.secondary)
            if networkMonitor.isExpensive {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.bottom, 8)
    }

    /// Error banner.
    private func errorBanner(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    /// Background gradient that shifts based on connection state.
    private var backgroundGradient: some View {
        LinearGradient(
            colors: [
                viewModel.status == .connected
                    ? Color.ztlpBlue.opacity(0.08)
                    : Color.clear,
                Color(.systemBackground)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}

#Preview("Disconnected") {
    let config = ZTLPConfiguration()
    HomeView(viewModel: TunnelViewModel(configuration: config), configuration: config)
        .environmentObject(NetworkMonitor.shared)
}
