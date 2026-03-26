// MenuBarView.swift
// ZTLP macOS
//
// Menu bar dropdown. Lightweight: status, toggle, zone info, and window launcher.

import SwiftUI

struct MenuBarView: View {
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 0) {
            // Status header
            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    Circle()
                        .fill(tunnelViewModel.status.color)
                        .frame(width: 10, height: 10)

                    Text(tunnelViewModel.status.label)
                        .font(.headline)

                    Spacer()

                    Toggle("", isOn: Binding(
                        get: { tunnelViewModel.status == .connected },
                        set: { _ in tunnelViewModel.toggleConnection() }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .disabled(!tunnelViewModel.status.canConnect && !tunnelViewModel.status.canDisconnect)
                    .controlSize(.small)
                }

                // Zone info
                if !configuration.zoneName.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "globe")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        Text(configuration.zoneName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                }

                // Traffic when connected
                if tunnelViewModel.status.isActive {
                    HStack(spacing: 16) {
                        Label(tunnelViewModel.stats.formattedBytesSent, systemImage: "arrow.up")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Label(tunnelViewModel.stats.formattedBytesReceived, systemImage: "arrow.down")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
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
                menuButton(icon: "macwindow", title: "Open ZTLP…", shortcut: "⌘O") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }

                Divider()

                menuButton(icon: "power", title: "Quit ZTLP", shortcut: "⌘Q") {
                    NSApp.terminate(nil)
                }
            }
        }
        .frame(width: 280)
    }

    // MARK: - Helpers

    private func menuButton(icon: String, title: String, shortcut: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                Text(title)
                Spacer()
                Text(shortcut)
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
