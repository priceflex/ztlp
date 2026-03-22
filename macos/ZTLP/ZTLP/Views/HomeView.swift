// HomeView.swift
// ZTLP macOS
//
// Main connection status and toggle view.
// Adapted from iOS — macOS layout, no UIKit.

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: TunnelViewModel

    @State private var isPulsing = false
    @State private var durationTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    @State private var currentDuration: String = "--:--:--"

    var body: some View {
        VStack(spacing: 24) {
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

            // Connection mode indicator
            if viewModel.status.isActive || viewModel.status.isTransitioning {
                HStack(spacing: 6) {
                    Image(systemName: viewModel.connectionMode.icon)
                        .font(.caption)
                    Text(viewModel.connectionMode.rawValue)
                        .font(.caption.weight(.medium))
                }
                .foregroundStyle(.secondary)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(.ultraThinMaterial, in: Capsule())
            }

            // Error message
            if let error = viewModel.lastError {
                errorBanner(error)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(backgroundGradient)
        .animation(.spring(response: 0.4), value: viewModel.status)
    }

    // MARK: - Subviews

    private var statusButton: some View {
        Button {
            viewModel.toggleConnection()
        } label: {
            ZStack {
                // Outer pulsing ring (when connected)
                if viewModel.status == .connected {
                    Circle()
                        .stroke(viewModel.status.color.opacity(0.3), lineWidth: 3)
                        .frame(width: 150, height: 150)
                        .scaleEffect(isPulsing ? 1.15 : 1.0)
                        .opacity(isPulsing ? 0.0 : 0.6)
                        .animation(
                            .easeInOut(duration: 2.0).repeatForever(autoreverses: false),
                            value: isPulsing
                        )
                }

                // Status ring
                Circle()
                    .stroke(viewModel.status.color, lineWidth: 5)
                    .frame(width: 130, height: 130)

                // Spinning ring (when transitioning)
                if viewModel.status.isTransitioning {
                    Circle()
                        .trim(from: 0, to: 0.3)
                        .stroke(viewModel.status.color, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                        .frame(width: 130, height: 130)
                        .rotationEffect(.degrees(isPulsing ? 360 : 0))
                        .animation(
                            .linear(duration: 1.0).repeatForever(autoreverses: false),
                            value: isPulsing
                        )
                }

                // Center icon
                VStack(spacing: 8) {
                    Image(systemName: viewModel.status.systemImage)
                        .font(.system(size: 40))
                        .foregroundStyle(viewModel.status.color)

                    Text(viewModel.status.canConnect ? "Connect" : "Disconnect")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(!viewModel.status.canConnect && !viewModel.status.canDisconnect)
        .onAppear { isPulsing = true }
    }

    private var trafficStatsView: some View {
        HStack(spacing: 32) {
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

            Rectangle()
                .fill(.quaternary)
                .frame(width: 1, height: 36)

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
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private var networkIndicator: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(NetworkMonitor.shared.isConnected ? .green : .red)
                .frame(width: 8, height: 8)
            Text(NetworkMonitor.shared.interfaceType.rawValue)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.bottom, 8)
    }

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
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    private var backgroundGradient: some View {
        LinearGradient(
            colors: [
                viewModel.status == .connected
                    ? Color.ztlpBlue.opacity(0.06)
                    : Color.clear,
                Color(nsColor: .windowBackgroundColor)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}
