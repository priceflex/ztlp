// CertificateGuideView.swift
// The steps for trusting this device's ZTLP certificate. iOS does not let an
// app do this for the user: the app hands the certificate to Safari, and the
// user installs it and then turns on full trust, in two different places in
// Settings. The second place is the one people miss, so it gets its own step
// and the page says plainly when it is still off.

import SwiftUI

struct CertificateGuideView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var working = false

    static let certificateName = "ZTLP Root CA (this device)"

    var body: some View {
        NavigationStack {
            List {
                Section {
                    statusRow
                }

                Section("Step 1: Download") {
                    Text("Safari opens and asks to download a configuration profile. Tap Allow.")
                        .font(.callout)
                    Button {
                        working = true
                        Task {
                            await model.installCertificate()
                            working = false
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if working {
                                ProgressView()
                            } else {
                                Text("Download certificate").fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(working)
                }

                Section("Step 2: Install") {
                    path(["Settings", "General", "VPN & Device Management"])
                    Text("Tap \(Self.certificateName), then Install.")
                        .font(.callout)
                }

                Section {
                    path(["Settings", "General", "About", "Certificate Trust Settings"])
                    Text("It is at the very bottom of About. Turn on the switch for \(Self.certificateName).")
                        .font(.callout)
                } header: {
                    Text("Step 3: Turn on full trust")
                } footer: {
                    Text("This is a separate switch from installing. Until it is on, browsers still refuse .ztlp sites.")
                }

                if let error = model.actionError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Color.ztlpRed)
                            .font(.footnote)
                    }
                }

                Section {
                } footer: {
                    Text("The certificate is made on this device and only works for .ztlp names. Use Safari for step 1; other browsers cannot install it.")
                }
            }
            .navigationTitle("Trust HTTPS")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    @ViewBuilder
    private var statusRow: some View {
        switch model.trust {
        case .trusted:
            Label("HTTPS is trusted. You are done.", systemImage: "checkmark.circle.fill")
                .foregroundStyle(Color.ztlpGreen)
        case .unknown:
            HStack(spacing: 10) {
                ProgressView()
                Text("Checking…").foregroundStyle(.secondary)
            }
        case .notTrusted, .unreachable:
            VStack(alignment: .leading, spacing: 4) {
                Label("Not trusted yet", systemImage: "circle")
                    .foregroundStyle(Color.ztlpBlue)
                Text("This page checks by itself and turns green when all three steps are done.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// A Settings path shown as "Settings › General › About".
    private func path(_ parts: [String]) -> some View {
        Text(parts.joined(separator: " › "))
            .font(.callout.weight(.semibold))
            .fixedSize(horizontal: false, vertical: true)
    }
}
