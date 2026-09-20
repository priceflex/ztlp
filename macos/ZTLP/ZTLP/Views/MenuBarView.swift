// MenuBarView.swift
// ZTLP macOS
//
// Menu bar dropdown. Task 8: no on/off switch (there is no session to
// switch), just the three readiness rows in miniature + window launcher.

import SwiftUI

struct MenuBarView: View {
    @ObservedObject var tunnelViewModel: TunnelViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: tunnelViewModel.readiness.allReady ? "shield.checkered" : "shield")
                        .foregroundStyle(tunnelViewModel.readiness.allReady ? Color.ztlpGreen : Color.ztlpBlue)
                    Text(tunnelViewModel.readiness.allReady ? "Ready" : "Setup needed")
                        .font(.headline)
                    Spacer()
                }

                ForEach(Array(tunnelViewModel.readiness.rows.enumerated()), id: \.offset) { _, row in
                    HStack(spacing: 6) {
                        miniBadge(row.state)
                        Text(row.title)
                            .font(.caption)
                        Spacer()
                        Text(detail(row.state))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }

                if !tunnelViewModel.zoneName.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "globe")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        Text(tunnelViewModel.zoneName)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                }

                if let error = tunnelViewModel.lastError {
                    HStack(alignment: .top, spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.yellow)
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(3)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(12)

            Divider()

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
        .frame(width: 300)
    }

    // MARK: - Helpers

    @ViewBuilder
    private func miniBadge(_ state: ReadinessState) -> some View {
        switch state {
        case .ready:
            Image(systemName: "checkmark.circle.fill").font(.caption).foregroundStyle(Color.ztlpGreen)
        case .needsAction:
            Image(systemName: "circle").font(.caption).foregroundStyle(Color.ztlpOrange)
        case .waiting:
            Image(systemName: "ellipsis.circle").font(.caption).foregroundStyle(.secondary)
        case .failed:
            Image(systemName: "xmark.circle.fill").font(.caption).foregroundStyle(.red)
        }
    }

    private func detail(_ state: ReadinessState) -> String {
        switch state {
        case .ready(let s), .waiting(let s), .failed(let s): return s
        case .needsAction(let s, _): return s
        }
    }

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
