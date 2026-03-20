// OnboardingView.swift
// ZTLP
//
// First-run onboarding experience. Three pages:
//   1. Welcome — what ZTLP does
//   2. Scan — enrollment QR code
//   3. Done — ready to connect

import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration

    /// Current onboarding page.
    @State private var currentPage = 0

    /// Whether to show the enrollment scanner.
    @State private var showEnrollment = false

    var body: some View {
        TabView(selection: $currentPage) {
            welcomePage
                .tag(0)

            enrollPage
                .tag(1)

            completePage
                .tag(2)
        }
        .tabViewStyle(.page(indexDisplayMode: .always))
        .indexViewStyle(.page(backgroundDisplayMode: .always))
        .sheet(isPresented: $showEnrollment) {
            EnrollmentView(
                viewModel: EnrollmentViewModel(configuration: configuration)
            )
        }
        .onChange(of: configuration.isEnrolled) { enrolled in
            if enrolled {
                withAnimation { currentPage = 2 }
            }
        }
    }

    // MARK: - Pages

    /// Page 1: Welcome.
    private var welcomePage: some View {
        VStack(spacing: 32) {
            Spacer()

            // App icon / hero
            ZStack {
                Circle()
                    .fill(Color.ztlpBlue.opacity(0.1))
                    .frame(width: 160, height: 160)

                Image(systemName: "shield.checkered")
                    .font(.system(size: 70))
                    .foregroundStyle(Color.ztlpBlue)
            }
            .accessibilityHidden(true)

            VStack(spacing: 12) {
                Text("Welcome to ZTLP")
                    .font(.largeTitle.weight(.bold))

                Text("Zero Trust Layer Protocol")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 20) {
                featureRow(
                    icon: "lock.shield",
                    title: "End-to-End Encryption",
                    description: "All traffic is encrypted with Noise_XX protocol"
                )
                featureRow(
                    icon: "point.3.filled.connected.trianglepath.dotted",
                    title: "Peer-to-Peer",
                    description: "Direct connections with NAT traversal"
                )
                featureRow(
                    icon: "cpu",
                    title: "Hardware Security",
                    description: "Keys protected by Secure Enclave"
                )
            }
            .padding(.horizontal, 32)

            Spacer()

            Button {
                withAnimation { currentPage = 1 }
            } label: {
                Text("Get Started")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
    }

    /// Page 2: Enroll.
    private var enrollPage: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 80))
                .foregroundStyle(Color.ztlpBlue)
                .accessibilityHidden(true)

            VStack(spacing: 12) {
                Text("Enroll Your Device")
                    .font(.title.weight(.bold))

                Text("Scan the enrollment QR code provided by your administrator to join a ZTLP zone.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Spacer()

            VStack(spacing: 12) {
                Button {
                    showEnrollment = true
                } label: {
                    Label("Scan QR Code", systemImage: "camera")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .controlSize(.large)

                Button {
                    // Skip enrollment for manual setup
                    withAnimation { currentPage = 2 }
                } label: {
                    Text("Set Up Manually Later")
                        .font(.callout)
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
    }

    /// Page 3: Complete.
    private var completePage: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 80))
                .foregroundStyle(Color.ztlpGreen)
                .accessibilityHidden(true)

            VStack(spacing: 12) {
                Text("You're All Set!")
                    .font(.title.weight(.bold))

                if configuration.isEnrolled {
                    Text("Your device is enrolled in zone **\(configuration.zoneName)**. You can now connect to the ZTLP network.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                } else {
                    Text("You can configure your connection manually in Settings, or enroll later.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
            }

            Spacer()

            Button {
                configuration.hasCompletedOnboarding = true
            } label: {
                Text("Start Using ZTLP")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
    }

    // MARK: - Components

    /// Feature description row for the welcome page.
    private func featureRow(icon: String, title: String, description: String) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(Color.ztlpBlue)
                .frame(width: 36, height: 36)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                Text(description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Previews

#Preview {
    OnboardingView()
        .environmentObject(ZTLPConfiguration())
}
