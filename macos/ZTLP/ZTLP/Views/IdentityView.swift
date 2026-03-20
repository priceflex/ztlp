// IdentityView.swift
// ZTLP macOS
//
// Displays the device's ZTLP identity: Node ID, public key,
// zone enrollment status, and provider type.
// Adapted from iOS — uses NSPasteboard instead of UIPasteboard.

import SwiftUI

struct IdentityView: View {
    @ObservedObject var settingsViewModel: SettingsViewModel
    @ObservedObject var configuration: ZTLPConfiguration

    @State private var copiedField: String?

    var body: some View {
        Form {
            if let identity = settingsViewModel.identity {
                identitySection(identity)
                enrollmentSection
                providerSection(identity)
                actionsSection(identity)
            } else {
                noIdentitySection
            }
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItem {
                Button {
                    settingsViewModel.loadState()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh identity")
            }
        }
        .overlay(alignment: .bottom) {
            if let field = copiedField {
                copiedToast(field)
            }
        }
    }

    // MARK: - Sections

    private func identitySection(_ identity: ZTLPIdentityInfo) -> some View {
        Section("Node Identity") {
            HStack {
                Label("Node ID", systemImage: "number")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(identity.shortNodeId)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                Button {
                    copyToClipboard(identity.nodeId, field: "Node ID")
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
                .help("Copy Node ID")
            }

            HStack {
                Label("Public Key", systemImage: "key")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(identity.shortPublicKey)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                Button {
                    copyToClipboard(identity.publicKey, field: "Public Key")
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
                .help("Copy Public Key")
            }
        }
    }

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
        }
    }

    private func providerSection(_ identity: ZTLPIdentityInfo) -> some View {
        Section("Provider") {
            HStack {
                Label("Type", systemImage: identity.isHardwareBacked ? "cpu" : "doc.text")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(identity.providerType.replacingOccurrences(of: "_", with: " ").capitalized)
                    .font(.callout)
            }

            HStack {
                Label("Hardware Backed", systemImage: "shield.checkered")
                    .foregroundStyle(.secondary)
                Spacer()
                Image(systemName: identity.isHardwareBacked ? "checkmark.circle.fill" : "xmark.circle")
                    .foregroundStyle(identity.isHardwareBacked ? Color.ztlpGreen : Color.secondary)
            }
        }
    }

    private func actionsSection(_ identity: ZTLPIdentityInfo) -> some View {
        Section {
            Button {
                if let text = settingsViewModel.exportIdentityString() {
                    copyToClipboard(text, field: "Identity")
                }
            } label: {
                Label("Copy Full Identity", systemImage: "square.and.arrow.up")
            }

            Button {
                Task { await settingsViewModel.regenerateIdentity() }
            } label: {
                Label("Regenerate Identity", systemImage: "arrow.triangle.2.circlepath")
            }
        }
    }

    private var noIdentitySection: some View {
        Section {
            VStack(spacing: 12) {
                Image(systemName: "person.badge.key")
                    .font(.system(size: 36))
                    .foregroundStyle(.secondary)
                Text("No Identity")
                    .font(.headline)
                Text("Generate or enroll an identity to see your node information.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("Generate Identity") {
                    Task { await settingsViewModel.regenerateIdentity() }
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 20)
        }
    }

    // MARK: - Helpers

    private func copyToClipboard(_ text: String, field: String) {
        settingsViewModel.copyToClipboard(text)
        withAnimation(.easeInOut(duration: 0.2)) {
            copiedField = field
        }
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            withAnimation { copiedField = nil }
        }
    }

    private func copiedToast(_ field: String) -> some View {
        Text("\(field) copied")
            .font(.caption.weight(.medium))
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(.ultraThinMaterial, in: Capsule())
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .padding(.bottom, 12)
    }
}
