// HomeView.swift
// ZTLP macOS
//
// Clean connection screen. Big connect button as the hero CTA.
// When disconnected: inviting call to action.
// When connected: status ring + traffic stats.

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: TunnelViewModel

    @State private var isPulsing = false
    @State private var durationTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    @State private var currentDuration: String = "--:--:--"

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Zone badge
            if !viewModel.zoneName.isEmpty {
                Text(viewModel.zoneName)
                    .font(.system(.subheadline, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .padding(.bottom, 16)
            }

            // Hero connect button
            connectButton
                .padding(.bottom, 20)

            // Status label
            Text(statusText)
                .font(.title3.weight(.medium))
                .foregroundStyle(viewModel.status.color)
                .animation(.easeInOut(duration: 0.3), value: viewModel.status)

            // Duration
            if viewModel.status == .connected {
                Text(currentDuration)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.quaternary)
                    .padding(.top, 4)
                    .onReceive(durationTimer) { _ in
                        currentDuration = viewModel.stats.formattedDuration
                    }
            }

            // Connection mode (subtle)
            if viewModel.status.isActive {
                HStack(spacing: 5) {
                    Image(systemName: viewModel.connectionMode.icon)
                        .font(.caption2)
                    Text(viewModel.connectionMode.rawValue)
                        .font(.caption2.weight(.medium))
                }
                .foregroundStyle(.quaternary)
                .padding(.top, 8)
            }

            Spacer()

            // Traffic stats (connected only)
            if viewModel.status.isActive {
                trafficBar
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .padding(.bottom, 20)
            }

            // Error
            if let error = viewModel.lastError {
                errorBanner(error)
                    .padding(.bottom, 16)
            }
        }
        .padding(.horizontal, 32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(backgroundGradient)
        .animation(.spring(response: 0.4), value: viewModel.status)
    }

    // MARK: - Status Text

    private var statusText: String {
        switch viewModel.status {
        case .disconnected:
            return "Tap to connect"
        default:
            return viewModel.status.label
        }
    }

    // MARK: - Connect Button

    private var connectButton: some View {
        Button {
            viewModel.toggleConnection()
        } label: {
            ZStack {
                // Pulsing outer ring (connected)
                if viewModel.status == .connected {
                    Circle()
                        .stroke(Color.ztlpGreen.opacity(0.25), lineWidth: 2.5)
                        .frame(width: 140, height: 140)
                        .scaleEffect(isPulsing ? 1.2 : 1.0)
                        .opacity(isPulsing ? 0.0 : 0.5)
                        .animation(
                            .easeOut(duration: 2.5).repeatForever(autoreverses: false),
                            value: isPulsing
                        )
                }

                // Main ring
                Circle()
                    .stroke(
                        viewModel.status == .disconnected
                            ? Color.ztlpBlue.opacity(0.4)
                            : viewModel.status.color,
                        lineWidth: 4
                    )
                    .frame(width: 120, height: 120)

                // Spinning arc (transitions)
                if viewModel.status.isTransitioning {
                    Circle()
                        .trim(from: 0, to: 0.25)
                        .stroke(
                            viewModel.status.color,
                            style: StrokeStyle(lineWidth: 4, lineCap: .round)
                        )
                        .frame(width: 120, height: 120)
                        .rotationEffect(.degrees(isPulsing ? 360 : 0))
                        .animation(
                            .linear(duration: 1.0).repeatForever(autoreverses: false),
                            value: isPulsing
                        )
                }

                // Center content
                VStack(spacing: 6) {
                    Image(systemName: viewModel.status.systemImage)
                        .font(.system(size: 32, weight: .light))
                        .foregroundStyle(
                            viewModel.status == .disconnected
                                ? Color.ztlpBlue
                                : viewModel.status.color
                        )
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(!viewModel.status.canConnect && !viewModel.status.canDisconnect)
        .onAppear { isPulsing = true }
        .contentShape(Circle().size(width: 140, height: 140))
    }

    // MARK: - Traffic Bar

    private var trafficBar: some View {
        HStack(spacing: 28) {
            HStack(spacing: 6) {
                Image(systemName: "arrow.up")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text(viewModel.stats.formattedBytesSent)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Rectangle()
                .fill(.quaternary)
                .frame(width: 1, height: 16)

            HStack(spacing: 6) {
                Image(systemName: "arrow.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text(viewModel.stats.formattedBytesReceived)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Error Banner

    private func errorBanner(_ message: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.yellow)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: 400)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    // MARK: - Background

    private var backgroundGradient: some View {
        LinearGradient(
            colors: [
                viewModel.status == .connected
                    ? Color.ztlpGreen.opacity(0.04)
                    : viewModel.status == .disconnected
                        ? Color.ztlpBlue.opacity(0.02)
                        : Color.clear,
                Color(nsColor: .windowBackgroundColor)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}
