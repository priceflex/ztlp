// HomeView.swift
// ZTLP macOS
//
// Task 8 (HANDOFF-2026-09-20): the single page. A READINESS CHECKLIST, not
// a connect screen. Three rows, each with a state badge and at most one
// action, then one line of guidance. No Connect button, no traffic bar, no
// duration timer — there is no "session". ZTLP is an identity network: the
// daemon connects on demand when DNS sees a zone hostname.

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: TunnelViewModel
    @ObservedObject var enrollmentViewModel: EnrollmentViewModel

    @State private var showEnrollment = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.bottom, 20)

            VStack(spacing: 10) {
                ForEach(Array(viewModel.readiness.rows.enumerated()), id: \.offset) { idx, row in
                    checklistRow(number: idx + 1, row: row)
                }
            }

            Text(viewModel.readiness.guidance(zone: viewModel.zoneName))
                .font(.callout)
                .foregroundStyle(viewModel.readiness.allReady ? Color.primary : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 18)
                .accessibilityIdentifier("home.guidance")

            if viewModel.readiness.allReady, let d = viewModel.daemon, d.activeTunnels > 0 {
                Text("\(d.activeTunnels) active tunnel\(d.activeTunnels == 1 ? "" : "s") right now")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .padding(.top, 4)
            }

            if let error = viewModel.lastError {
                errorBanner(error)
                    .padding(.top, 14)
            }

            Spacer(minLength: 0)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
        .animation(.easeInOut(duration: 0.25), value: viewModel.readiness)
        .sheet(isPresented: $showEnrollment, onDismiss: { viewModel.enrollmentDidFinish() }) {
            EnrollmentView(viewModel: enrollmentViewModel)
                .frame(minWidth: 520, minHeight: 440)
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: viewModel.readiness.allReady ? "shield.checkered" : "shield")
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(viewModel.readiness.allReady ? Color.ztlpGreen : Color.ztlpBlue)
            VStack(alignment: .leading, spacing: 2) {
                Text(viewModel.readiness.allReady ? "Ready" : "Set up ZTLP")
                    .font(.title2.weight(.semibold))
                if !viewModel.zoneName.isEmpty {
                    Text(viewModel.zoneName)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
    }

    // MARK: - Rows

    private func checklistRow(number: Int, row: ReadinessRow) -> some View {
        HStack(spacing: 14) {
            badge(row.state)
                .frame(width: 22, height: 22)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("\(number).")
                        .foregroundStyle(.tertiary)
                    Text(row.title)
                        .fontWeight(.medium)
                }
                .font(.body)
                Text(detail(row.state))
                    .font(.caption)
                    .foregroundStyle(detailColor(row.state))
                    .lineLimit(2)
            }

            Spacer()

            actionButton(row.state)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("home.row.\(row.title.lowercased().replacingOccurrences(of: " ", with: "-"))")
    }

    @ViewBuilder
    private func badge(_ state: ReadinessState) -> some View {
        switch state {
        case .ready:
            Image(systemName: "checkmark.circle.fill")
                .font(.title3)
                .foregroundStyle(Color.ztlpGreen)
        case .needsAction:
            Image(systemName: "circle")
                .font(.title3)
                .foregroundStyle(Color.ztlpOrange)
        case .waiting:
            ProgressView()
                .controlSize(.small)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .font(.title3)
                .foregroundStyle(.red)
        }
    }

    private func detail(_ state: ReadinessState) -> String {
        switch state {
        case .ready(let s), .waiting(let s), .failed(let s): return s
        case .needsAction(let s, _): return s
        }
    }

    private func detailColor(_ state: ReadinessState) -> Color {
        switch state {
        case .ready: return .secondary
        case .needsAction: return Color.ztlpOrange
        case .waiting: return .secondary
        case .failed: return .red
        }
    }

    @ViewBuilder
    private func actionButton(_ state: ReadinessState) -> some View {
        if case .needsAction(_, let action) = state {
            switch action {
            case .installService:
                Button("Install") { viewModel.installService() }
                    .buttonStyle(.borderedProminent)
                    .tint(Color.ztlpBlue)
                    .accessibilityIdentifier("home.action.install")
            case .openLoginItems:
                Button("Open Login Items") { AgentServiceInstaller.shared.openLoginItemsSettings() }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("home.action.login-items")
            case .enroll:
                Button("Enroll") { showEnrollment = true }
                    .buttonStyle(.borderedProminent)
                    .tint(Color.ztlpBlue)
                    .accessibilityIdentifier("home.action.enroll")
            case .trustHTTPS:
                Button {
                    viewModel.trustHTTPS()
                } label: {
                    if viewModel.trustInFlight {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Trust HTTPS")
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .disabled(viewModel.trustInFlight)
                .help("Trusts this Mac's ZTLP certificate authority (limited to .ztlp names) for your account. No password needed.")
                .accessibilityIdentifier("home.action.trust-https")
            case .none:
                EmptyView()
            }
        }
    }

    // MARK: - Error Banner

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.yellow)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}
