// CertificateTrustView.swift
// ZTLP macOS
//
// Certificate trust UI — shown in Settings.
//
// Explains what the CA is for and provides a one-click install
// that triggers the native macOS admin password dialog.

import SwiftUI

struct CertificateTrustView: View {
    @ObservedObject var certManager: CertificateManager

    var body: some View {
        Section("HTTPS Certificates") {

            // Trust status row
            HStack {
                Label("Local CA", systemImage: statusIcon)
                    .foregroundStyle(.secondary)
                Spacer()
                statusBadge
            }

            // Service cert count
            if certManager.certCount > 0 {
                HStack {
                    Label("Service Certs", systemImage: "doc.badge.gearshape")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(certManager.certCount) installed")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }

            // Explanation + action
            switch certManager.trustStatus {
            case .trusted:
                trustedView

            case .notTrusted:
                notTrustedView

            case .noCertificate:
                noCertificateView

            case .installing, .checking:
                HStack {
                    Spacer()
                    ProgressView()
                        .scaleEffect(0.8)
                    Text(certManager.trustStatus.label)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(.vertical, 4)

            case .error(let msg):
                errorView(msg)
            }
        }
    }

    // MARK: - Status

    private var statusIcon: String {
        switch certManager.trustStatus {
        case .trusted:       return "checkmark.shield.fill"
        case .notTrusted:    return "shield.slash"
        case .noCertificate: return "shield.slash"
        case .checking:      return "shield"
        case .installing:    return "shield"
        case .error:         return "exclamationmark.shield"
        }
    }

    private var statusBadge: some View {
        Group {
            switch certManager.trustStatus {
            case .trusted:
                Label("Trusted", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(Color.ztlpGreen)
                    .font(.callout)
            case .notTrusted:
                Label("Not Trusted", systemImage: "xmark.circle")
                    .foregroundStyle(Color.ztlpOrange)
                    .font(.callout)
            case .noCertificate:
                Label("Not Set Up", systemImage: "minus.circle")
                    .foregroundStyle(.tertiary)
                    .font(.callout)
            case .checking, .installing:
                ProgressView()
                    .scaleEffect(0.7)
            case .error:
                Label("Error", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
            }
        }
    }

    // MARK: - State Views

    private var trustedView: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("HTTPS is ready. Services like **vault.techrockstars.ztlp** are trusted by your browser — no certificate warnings.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    private var notTrustedView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ZTLP uses a local certificate authority to encrypt connections to services like Vaultwarden. Your browser needs to trust this CA to avoid \"Not Secure\" warnings.")
                .font(.caption)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 4) {
                Label("Encrypts the browser ↔ ZTLP agent hop", systemImage: "lock.fill")
                Label("Certificates never leave your machine", systemImage: "desktopcomputer")
                Label("One-time setup — works for all services", systemImage: "checkmark.seal")
            }
            .font(.caption)
            .foregroundStyle(.tertiary)

            Button {
                certManager.installCA()
            } label: {
                Label("Trust Certificate Authority", systemImage: "lock.shield")
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.regular)
        }
    }

    private var noCertificateView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("No local CA found. Generate one to enable HTTPS for ZTLP services. This creates a private certificate authority on your Mac — certificates never leave your machine.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                certManager.generateCA()
            } label: {
                Label("Set Up HTTPS", systemImage: "lock.shield")
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.regular)
        }
    }

    private func errorView(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(message)
                .font(.caption)
                .foregroundStyle(.red)

            Button {
                certManager.checkTrust()
            } label: {
                Label("Retry", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
    }
}
