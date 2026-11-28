// HomeView.swift
// The single page: logo, a three-row readiness checklist, one line of
// guidance. A checklist, not a connect screen.

import SwiftUI

struct HomeView: View {
    @ObservedObject var model: AppModel
    @State private var showSettings = false
    @State private var enrollmentStartsWithScanner = false
    @State private var certificateGuideAfterSettings = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header

                    if let fatal = model.fatalError {
                        banner(fatal)
                    }

                    VStack(spacing: 10) {
                        ForEach(model.readiness.rows) { row in
                            ReadinessRowView(row: row) { rowActions(for: row) }
                        }
                    }

                    Text(Readiness.guidance(zone: model.zone))
                        .font(.callout)
                        .foregroundStyle(model.readiness.allReady ? Color.primary : Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("home.guidance")

                    if let error = model.actionError {
                        banner(error)
                    }
                }
                .padding(20)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity)
                .animation(.easeInOut(duration: 0.25), value: model.readiness)
            }
            .navigationTitle("ZTLP")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityLabel("Settings")
                }
            }
            .sheet(isPresented: $showSettings, onDismiss: {
                if certificateGuideAfterSettings {
                    certificateGuideAfterSettings = false
                    model.showCertificateGuide = true
                }
            }) {
                SettingsView(model: model) {
                    certificateGuideAfterSettings = true
                }
            }
            .sheet(isPresented: $model.showEnrollment) {
                EnrollmentView(model: model, startWithScanner: enrollmentStartsWithScanner)
            }
            .sheet(isPresented: $model.showCertificateGuide) {
                CertificateGuideView(model: model)
            }
            .task {
                await model.runPolling()
            }
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image("Logo")
                .resizable()
                .scaledToFit()
                .frame(width: 56, height: 56)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.readiness.allReady ? "Ready" : "Set up ZTLP")
                    .font(.title2.weight(.semibold))
                if !model.zone.isEmpty {
                    Text(model.zone)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private func rowActions(for row: ReadinessRow) -> some View {
        switch row.action {
        case .enroll:
            VStack(spacing: 8) {
                Button {
                    enrollmentStartsWithScanner = true
                    model.enrollmentError = nil
                    model.showEnrollment = true
                } label: {
                    Label("Scan QR code", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                Button {
                    enrollmentStartsWithScanner = false
                    model.enrollmentError = nil
                    model.showEnrollment = true
                } label: {
                    Label("Paste code", systemImage: "doc.on.clipboard")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
            .disabled(model.fatalError != nil)
        case .setUpTunnel:
            Button(row.status == "Needs permission" ? "Allow" : "Fix") {
                Task { await model.setUpTunnel() }
            }
            .buttonStyle(.borderedProminent)
        case .installCertificate:
            Button("Show steps") {
                model.showCertificateGuide = true
            }
            .buttonStyle(.borderedProminent)
        case .none:
            EmptyView()
        }
    }

    private func banner(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Color.ztlpOrange)
            Text(text)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.ztlpOrange.opacity(0.12))
        )
    }
}

/// One checklist row: state badge, title, short status, and (when not green)
/// a hint and at most one action.
struct ReadinessRowView<Actions: View>: View {
    let row: ReadinessRow
    @ViewBuilder let actions: () -> Actions

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                badge
                    .frame(width: 26, height: 26)
                Text(row.title)
                    .font(.body.weight(.medium))
                Spacer(minLength: 8)
                Text(row.status)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if !row.isReady {
                if let hint = row.hint {
                    Text(hint)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.leading, 38)
                }
                if row.action != nil {
                    actions()
                        .padding(.leading, 38)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color(.secondarySystemBackground))
        )
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("home.row.\(row.id)")
    }

    @ViewBuilder
    private var badge: some View {
        switch row.kind {
        case .ready:
            Image(systemName: "checkmark.circle.fill")
                .font(.title3)
                .foregroundStyle(Color.ztlpGreen)
        case .waiting:
            ProgressView()
        case .needsAction:
            Image(systemName: "circle")
                .font(.title3)
                .foregroundStyle(Color.ztlpBlue)
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.title3)
                .foregroundStyle(Color.ztlpRed)
        }
    }
}
