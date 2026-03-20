// HomeView.swift
// ZTLP
//
// Main connect/disconnect screen with status indicator,
// connection timer, and traffic stats.

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: TunnelViewModel
    @EnvironmentObject var networkMonitor: NetworkMonitor

    /// Animation state for the pulsing status ring.
    @State private var isPulsing = false

    /// Timer for updating the duration display.
    @State private var durationTimer = Timer.publish(every: 1, on: .main, in: .common)
        .autoconnect()
    @State private var currentDuration: String = "--:--:--"

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

                    // Connection duration
                    if viewModel.status == .connected {
                        Text(currentDuration)
                            .font(.system(.title3, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .onReceive(durationTimer) { _ in
                                currentDuration = viewModel.stats.formattedDuration
                            }
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
                        .contentTransition(.symbolEffect(.replace))

                    Text(viewModel.status.canConnect ? "Connect" : "Disconnect")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(!viewModel.status.canConnect && !viewModel.status.canDisconnect)
        .accessibilityLabel(viewModel.status.canConnect ? "Connect to VPN" : "Disconnect from VPN")
        .accessibilityHint(viewModel.status.label)
        .onAppear { isPulsing = true }
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
    HomeView(viewModel: TunnelViewModel(configuration: ZTLPConfiguration()))
        .environmentObject(NetworkMonitor.shared)
}
