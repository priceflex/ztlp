// EnrollmentView.swift
// ZTLP macOS
//
// Enrollment flow — paste-only on macOS (no camera/QR).
// User pastes a ztlp://enroll/... URI to enroll the device.

import SwiftUI

struct EnrollmentView: View {
    @ObservedObject var viewModel: EnrollmentViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var manualEntryText = ""

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Group {
                switch viewModel.state {
                case .idle:
                    idleView
                case .tokenParsed(let tokenInfo):
                    tokenReviewView(tokenInfo)
                case .enrolling:
                    enrollingView
                case .success(let zoneName):
                    successView(zoneName)
                case .error(let message):
                    errorView(message)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(24)

            // Close button (top-right X)
            Button {
                viewModel.reset()
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .padding(12)
            .help("Close")
        }
    }

    // MARK: - State Views

    private var idleView: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "ticket")
                .font(.system(size: 56))
                .foregroundStyle(Color.ztlpBlue)

            Text("Enroll Device")
                .font(.title2.weight(.semibold))

            Text("Paste an enrollment URI provided by your administrator to join a ZTLP zone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)

            VStack(spacing: 12) {
                TextEditor(text: $manualEntryText)
                    .font(.callout.monospaced())
                    .frame(height: 80)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(.quaternary, lineWidth: 1)
                    )
                    .frame(maxWidth: 450)

                HStack(spacing: 12) {
                    Button {
                        viewModel.pasteFromClipboard()
                    } label: {
                        Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                    }
                    .buttonStyle(.bordered)

                    Button {
                        viewModel.handleManualEntry(manualEntryText)
                    } label: {
                        Text("Submit")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Color.ztlpBlue)
                    .disabled(manualEntryText.isEmpty)
                }
            }

            Spacer()
        }
    }

    private func tokenReviewView(_ tokenInfo: EnrollmentTokenInfo) -> some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "checkmark.seal")
                .font(.system(size: 48))
                .foregroundStyle(Color.ztlpBlue)

            Text("Enrollment Token Found")
                .font(.title2.weight(.semibold))

            VStack(alignment: .leading, spacing: 10) {
                tokenRow(label: "Zone", value: tokenInfo.zone, systemImage: "globe")
                tokenRow(label: "Name Service", value: tokenInfo.nsAddress, systemImage: "server.rack")
                if !tokenInfo.relayAddresses.isEmpty {
                    tokenRow(
                        label: "Relays",
                        value: tokenInfo.relayAddresses.joined(separator: ", "),
                        systemImage: "antenna.radiowaves.left.and.right"
                    )
                }
                if let gateway = tokenInfo.gatewayAddress {
                    tokenRow(label: "Gateway", value: gateway, systemImage: "door.left.hand.open")
                }
                tokenRow(label: "Expires", value: tokenInfo.expiryDescription, systemImage: "clock")
            }
            .padding()
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
            .frame(maxWidth: 450)

            Spacer()

            HStack(spacing: 12) {
                Button("Cancel") {
                    viewModel.reset()
                }
                .buttonStyle(.bordered)

                Button {
                    viewModel.enroll()
                } label: {
                    Label("Enroll Device", systemImage: "checkmark.circle")
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
            }
        }
    }

    private var enrollingView: some View {
        VStack(spacing: 20) {
            Spacer()
            ProgressView()
                .scaleEffect(1.2)
            Text("Enrolling\u{2026}")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("Generating identity and registering with the zone.")
                .font(.callout)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 350)
            Spacer()
        }
    }

    private func successView(_ zoneName: String) -> some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 64))
                .foregroundStyle(Color.ztlpGreen)

            Text("Enrolled!")
                .font(.title.weight(.bold))

            Text("Your device is now enrolled in zone **\(zoneName)**.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 350)

            Spacer()

            Button("Done") {
                viewModel.reset()
                manualEntryText = ""
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
        }
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(Color.ztlpOrange)

            Text("Enrollment Failed")
                .font(.title2.weight(.semibold))

            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)

            Spacer()

            HStack(spacing: 12) {
                Button("Close") {
                    viewModel.reset()
                    dismiss()
                }
                .buttonStyle(.bordered)

                Button {
                    viewModel.reset()
                    manualEntryText = ""
                } label: {
                    Label("Try Again", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
            }
        }
    }

    // MARK: - Components

    private func tokenRow(label: String, value: String, systemImage: String) -> some View {
        HStack {
            Label(label, systemImage: systemImage)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 120, alignment: .leading)
            Text(value)
                .font(.callout.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }
}
