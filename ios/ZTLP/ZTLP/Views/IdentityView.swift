// IdentityView.swift
// ZTLP
//
// Displays the device's ZTLP identity: Node ID, public key,
// zone enrollment status, and provider type.

import SwiftUI

struct IdentityView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration

    /// Identity info loaded from the bridge.
    @State private var identity: ZTLPIdentityInfo?

    /// Whether the identity is being loaded/refreshed.
    @State private var isLoading = false

    /// Copy-feedback message.
    @State private var copiedField: String?

    var body: some View {
        NavigationStack {
            List {
                if let identity = identity {
                    identitySection(identity)
                    enrollmentSection
                    providerSection(identity)
                    actionsSection(identity)
                } else if isLoading {
                    loadingSection
                } else {
                    noIdentitySection
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Identity")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        loadIdentity()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .accessibilityLabel("Refresh identity")
                }
            }
            .onAppear { loadIdentity() }
            .overlay(alignment: .bottom) {
                if let field = copiedField {
                    copiedToast(field)
                }
            }
        }
    }

    // MARK: - Sections

    /// Node ID and public key.
    private func identitySection(_ identity: ZTLPIdentityInfo) -> some View {
        Section("Node Identity") {
            // Node ID
            identityRow(
                label: "Node ID",
                value: identity.nodeId,
                shortValue: identity.shortNodeId,
                systemImage: "number"
            )

            // Public Key
            identityRow(
                label: "Public Key",
                value: identity.publicKey,
                shortValue: identity.shortPublicKey,
                systemImage: "key"
            )

            // Created
            HStack {
                Label("Created", systemImage: "calendar")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(identity.createdAt, style: .date)
                    .font(.caption.monospaced())
            }
        }
    }

    /// Zone enrollment status.
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

    /// Identity provider details.
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

            HStack {
                Label("Secure Enclave", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(SecureEnclaveService.shared.isAvailable ? "Available" : "Unavailable")
                    .font(.callout)
                    .foregroundStyle(SecureEnclaveService.shared.isAvailable ? Color.ztlpGreen : Color.secondary)
            }
        }
    }

    /// Export / copy actions.
    private func actionsSection(_ identity: ZTLPIdentityInfo) -> some View {
        Section {
            Button {
                copyToClipboard(identity.nodeId, field: "Node ID")
            } label: {
                Label("Copy Node ID", systemImage: "doc.on.doc")
            }

            Button {
                copyToClipboard(identity.publicKey, field: "Public Key")
            } label: {
                Label("Copy Public Key", systemImage: "doc.on.doc")
            }

            Button {
                let text = """
                ZTLP Identity
                Node ID: \(identity.nodeId)
                Public Key: \(identity.publicKey)
                Provider: \(identity.providerType)
                Zone: \(configuration.zoneName.isEmpty ? "not enrolled" : configuration.zoneName)
                """
                copyToClipboard(text, field: "Identity")
            } label: {
                Label("Copy Full Identity", systemImage: "square.and.arrow.up")
            }
        }
    }

    /// Loading placeholder.
    private var loadingSection: some View {
        Section {
            HStack {
                ProgressView()
                    .padding(.trailing, 8)
                Text("Loading identity…")
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// No identity found.
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
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 20)
        }
    }

    // MARK: - Components

    /// An identity field row with copy-on-tap.
    private func identityRow(
        label: String,
        value: String,
        shortValue: String,
        systemImage: String
    ) -> some View {
        Button {
            copyToClipboard(value, field: label)
        } label: {
            HStack {
                Label(label, systemImage: systemImage)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(shortValue)
                    .font(.caption.monospaced())
                    .foregroundStyle(.primary)
                Image(systemName: "doc.on.doc")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(label): \(shortValue). Tap to copy.")
    }

    /// Copied toast overlay.
    private func copiedToast(_ field: String) -> some View {
        Text("\(field) copied")
            .font(.caption.weight(.medium))
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(.ultraThinMaterial, in: Capsule())
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .padding(.bottom, 16)
    }

    // MARK: - Actions

    /// Load identity from the ZTLP bridge.
    private func loadIdentity() {
        // Nebula pivot (S1.5): ZTLPBridge was deleted. Identity loading
        // in the main-app target has no backing FFI at the moment —
        // rewire through the Network Extension in a follow-up.
        isLoading = false
        identity = nil
    }

    /// Copy text to the clipboard with haptic and visual feedback.
    private func copyToClipboard(_ text: String, field: String) {
        UIPasteboard.general.string = text
        UIImpactFeedbackGenerator(style: .light).impactOccurred()

        withAnimation(.easeInOut(duration: 0.2)) {
            copiedField = field
        }
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            withAnimation { copiedField = nil }
        }
    }
}

// MARK: - Previews

#Preview {
    IdentityView()
        .environmentObject(ZTLPConfiguration())
}
