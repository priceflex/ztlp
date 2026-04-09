// OnboardingView.swift
// ZTLP macOS
//
// First-run onboarding: welcome → enroll → done.
// Clean, focused. No camera — enrollment is paste-based on macOS.

import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration

    @State private var currentStep = 0
    @State private var showEnrollment = false

    var body: some View {
        VStack {
            switch currentStep {
            case 0:
                welcomeStep
            case 1:
                enrollStep
            default:
                completeStep
            }
        }
        .frame(width: 520, height: 480)
        .sheet(isPresented: $showEnrollment) {
            EnrollmentView(viewModel: EnrollmentViewModel(configuration: configuration))
                .frame(width: 500, height: 450)
        }
        .onChange(of: configuration.isEnrolled) { enrolled in
            if enrolled {
                showEnrollment = false
                withAnimation { currentStep = 2 }
            }
        }
        .onAppear {
            // Skip to complete if already enrolled
            if configuration.isEnrolled {
                currentStep = 2
            }
        }
    }

    // MARK: - Welcome

    private var welcomeStep: some View {
        VStack(spacing: 24) {
            Spacer()

            ZStack {
                Circle()
                    .fill(Color.ztlpBlue.opacity(0.08))
                    .frame(width: 110, height: 110)

                Image(systemName: "shield.checkered")
                    .font(.system(size: 46, weight: .light))
                    .foregroundStyle(Color.ztlpBlue)
            }

            VStack(spacing: 6) {
                Text("Welcome to ZTLP")
                    .font(.largeTitle.weight(.bold))
                Text("Zero Trust Layer Protocol")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 14) {
                featureRow(
                    icon: "lock.shield",
                    title: "End-to-End Encryption",
                    description: "All traffic encrypted with Noise_XX"
                )
                featureRow(
                    icon: "point.3.filled.connected.trianglepath.dotted",
                    title: "Peer-to-Peer Mesh",
                    description: "Direct connections with relay fallback"
                )
                featureRow(
                    icon: "desktopcomputer",
                    title: "Menu Bar Integration",
                    description: "Quick access from the macOS menu bar"
                )
            }
            .padding(.horizontal, 40)

            Spacer()

            Button {
                withAnimation { currentStep = 1 }
            } label: {
                Text("Get Started")
                    .frame(width: 200)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.large)
            .padding(.bottom, 32)
        }
    }

    // MARK: - Enroll

    private var enrollStep: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "ticket")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(Color.ztlpBlue)

            VStack(spacing: 8) {
                Text("Enroll Your Device")
                    .font(.title.weight(.bold))

                Text("Paste the enrollment URI from your administrator to join a ZTLP zone.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }

            Spacer()

            VStack(spacing: 12) {
                Button {
                    showEnrollment = true
                } label: {
                    Label("Enter Enrollment Code", systemImage: "text.badge.plus")
                        .frame(width: 250)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .controlSize(.large)

                Button {
                    withAnimation { currentStep = 2 }
                } label: {
                    Text("Set Up Later")
                        .font(.callout)
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.tertiary)
            }
            .padding(.bottom, 32)
        }
    }

    // MARK: - Complete

    private var completeStep: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 56))
                .foregroundStyle(Color.ztlpGreen)

            VStack(spacing: 8) {
                Text("You're All Set")
                    .font(.title.weight(.bold))

                Group {
                    if configuration.isEnrolled {
                        Text("Enrolled in zone **\(configuration.zoneName)**. You can now connect to the ZTLP network.")
                    } else {
                        Text("You can configure your connection in Settings, or enroll later.")
                    }
                }
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
            }

            Spacer()

            Button {
                configuration.hasCompletedOnboarding = true
            } label: {
                Text("Start Using ZTLP")
                    .frame(width: 200)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.large)
            .padding(.bottom, 32)
        }
    }

    // MARK: - Components

    private func featureRow(icon: String, title: String, description: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(Color.ztlpBlue)
                .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                Text(description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
