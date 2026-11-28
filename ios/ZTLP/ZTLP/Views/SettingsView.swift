// SettingsView.swift
// Identity, log tail, certificate, and "Remove this device".

import SwiftUI
import UIKit

struct SettingsView: View {
    @ObservedObject var model: AppModel
    /// Called when the user asks for the certificate steps; the presenter
    /// shows them after this sheet has closed.
    let onInstallCertificate: () -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var logKind: AppModel.LogKind = .agent
    @State private var logLines: [String] = []
    @State private var confirmRemove = false
    @State private var removing = false

    var body: some View {
        NavigationStack {
            List {
                Section("This device") {
                    LabeledContent("Device name", value: model.nodeName.isEmpty ? "Not enrolled" : model.nodeName)
                    LabeledContent("Zone", value: model.zone.isEmpty ? "None" : model.zone)
                    if let status = model.agentStatus, status.running {
                        LabeledContent("Open tunnels", value: "\(status.tunnels)")
                    }
                }

                if model.isEnrolled {
                    Section {
                        Button("Install certificate") {
                            onInstallCertificate()
                            dismiss()
                        }
                    } footer: {
                        Text("Needed once so Safari trusts https:// on .ztlp sites.")
                    }
                }

                Section {
                    Picker("Log", selection: $logKind) {
                        ForEach(AppModel.LogKind.allCases) { kind in
                            Text(kind.rawValue).tag(kind)
                        }
                    }
                    .pickerStyle(.segmented)

                    if logLines.isEmpty {
                        Text("No log yet.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        ScrollView(.horizontal, showsIndicators: false) {
                            Text(logLines.joined(separator: "\n"))
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        Button("Copy log") {
                            UIPasteboard.general.string = logLines.joined(separator: "\n")
                        }
                    }
                } header: {
                    Text("Log (last 200 lines)")
                }

                if model.isEnrolled {
                    Section {
                        Button(role: .destructive) {
                            confirmRemove = true
                        } label: {
                            if removing {
                                ProgressView()
                            } else {
                                Text("Remove this device")
                            }
                        }
                        .disabled(removing)
                    } footer: {
                        Text("Stops ZTLP, deletes its configuration from iOS and erases this device's identity. You need a new code to enroll again.")
                    }
                }

                Section {
                    LabeledContent("Version", value: Self.versionText)
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog(
                "Remove this device from ZTLP?",
                isPresented: $confirmRemove,
                titleVisibility: .visible
            ) {
                Button("Remove this device", role: .destructive) {
                    removing = true
                    Task {
                        await model.removeDevice()
                        removing = false
                        dismiss()
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(".ztlp sites stop working on this device until you enroll again.")
            }
            .task(id: logKind) {
                // Reload the tail every few seconds while Settings is open.
                while !Task.isCancelled {
                    logLines = await model.logTail(logKind)
                    try? await Task.sleep(for: .seconds(3))
                }
            }
        }
    }

    private static var versionText: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }
}
