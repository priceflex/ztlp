// MenuBarView.swift
// ZTLP macOS
//
// The dropdown panel shown when clicking the menu bar icon.
// Lightweight — shows status, toggle, and shortcuts.

import SwiftUI

struct MenuBarView: View {
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(spacing: 8) {
                HStack(spacing: 10) {
                    // Status dot
                    Circle()
                        .fill(tunnelViewModel.status.color)
                        .frame(width: 10, height: 10)

                    Text(tunnelViewModel.status.label)
                        .font(.headline)

                    Spacer()

                    // Connect/Disconnect toggle
                    Toggle("", isOn: Binding(
                        get: { tunnelViewModel.status == .connected },
                        set: { _ in tunnelViewModel.toggleConnection() }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .disabled(!tunnelViewModel.status.canConnect && !tunnelViewModel.status.canDisconnect)
                    .controlSize(.small)
                }

                // Relay / zone info
                if !configuration.relayAddress.isEmpty || !configuration.zoneName.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        if !configuration.zoneName.isEmpty {
                            HStack(spacing: 4) {
                                Image(systemName: "globe")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                Text(configuration.zoneName)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        if !configuration.relayAddress.isEmpty {
                            HStack(spacing: 4) {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                Text(configuration.relayAddress)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                // Traffic stats when connected
                if tunnelViewModel.status.isActive {
                    HStack(spacing: 16) {
                        Label(tunnelViewModel.stats.formattedBytesSent, systemImage: "arrow.up")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Label(tunnelViewModel.stats.formattedBytesReceived, systemImage: "arrow.down")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                // Error
                if let error = tunnelViewModel.lastError {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.yellow)
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(12)

            Divider()

            // Actions
            VStack(spacing: 0) {
                Button {
                    openWindow(id: "main")
                    // Bring the app to the foreground
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    HStack {
                        Image(systemName: "macwindow")
                        Text("Open ZTLP…")
                        Spacer()
                        Text("⌘O")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                Divider()

                Button {
                    NSApp.terminate(nil)
                } label: {
                    HStack {
                        Image(systemName: "power")
                        Text("Quit ZTLP")
                        Spacer()
                        Text("⌘Q")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .frame(width: 300)
    }
}
