// OnboardingView.swift
// ZTLP
//
// Three-page onboarding: Welcome, Enroll, Ready.
// Professional first impression with ZTLP branding and smooth transitions.

import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration
    @State private var currentPage = 0
    @State private var showEnrollment = false

    var body: some View {
        ZStack {
            // Background gradient
            LinearGradient(
                colors: [
                    Color(.systemBackground),
                    Color.ztlpBlue.opacity(0.05)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                TabView(selection: $currentPage) {
                    welcomePage.tag(0)
                    featuresPage.tag(1)
                    enrollPage.tag(2)
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
                .animation(.easeInOut(duration: 0.3), value: currentPage)

                // Page indicator + action button
                VStack(spacing: 20) {
                    // Custom page dots
                    HStack(spacing: 8) {
                        ForEach(0..<3) { index in
                            Capsule()
                                .fill(index == currentPage ? Color.ztlpBlue : Color.ztlpBlue.opacity(0.2))
                                .frame(width: index == currentPage ? 24 : 8, height: 8)
                                .animation(.spring(response: 0.3), value: currentPage)
                        }
                    }

                    // Action button
                    Button {
                        if currentPage < 2 {
                            withAnimation { currentPage += 1 }
                        } else {
                            showEnrollment = true
                        }
                    } label: {
                        Text(currentPage < 2 ? "Continue" : "Get Started")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 16)
                            .background(
                                LinearGradient.ztlpShield,
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                            )
                            .foregroundColor(.white)
                    }
                    .padding(.horizontal, 24)

                    // Skip button (on first two pages)
                    if currentPage < 2 {
                        Button("Skip") {
                            showEnrollment = true
                        }
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    }
                }
                .padding(.bottom, 40)
            }
        }
        .sheet(isPresented: $showEnrollment) {
            EnrollmentView(
                viewModel: EnrollmentViewModel(configuration: configuration),
                onComplete: {
                    configuration.hasCompletedOnboarding = true
                }
            )
        }
    }

    // MARK: - Welcome Page

    private var welcomePage: some View {
        VStack(spacing: 24) {
            Spacer()

            // Logo / Shield
            ZStack {
                Circle()
                    .fill(LinearGradient.ztlpShield.opacity(0.15))
                    .frame(width: 140, height: 140)

                Circle()
                    .fill(LinearGradient.ztlpShield.opacity(0.08))
                    .frame(width: 180, height: 180)

                Image(systemName: "shield.checkered")
                    .font(.system(size: 64, weight: .medium))
                    .foregroundStyle(LinearGradient.ztlpShield)
            }

            VStack(spacing: 12) {
                Text("ZTLP")
                    .font(.largeTitle.weight(.bold))

                Text("Zero Trust Lattice Protocol")
                    .font(.title3)
                    .foregroundStyle(.secondary)

                Text("Military-grade encrypted networking\nfor your devices and services.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 4)
            }

            Spacer()
            Spacer()
        }
        .padding(.horizontal, 32)
    }

    // MARK: - Features Page

    private var featuresPage: some View {
        VStack(spacing: 32) {
            Spacer()

            Text("Built for Security")
                .font(.title2.weight(.bold))

            VStack(spacing: 20) {
                FeatureRow(
                    icon: "lock.shield.fill",
                    title: "Noise_XX Handshake",
                    description: "Mutual authentication with forward secrecy. No certificates required."
                )

                FeatureRow(
                    icon: "bolt.horizontal.fill",
                    title: "Zero Configuration",
                    description: "Scan a QR code to enroll. NAT traversal handles the rest."
                )

                FeatureRow(
                    icon: "cpu",
                    title: "Secure Enclave Keys",
                    description: "Hardware-backed identity stored in the device's secure element."
                )

                FeatureRow(
                    icon: "network.badge.shield.half.filled",
                    title: "Service Access",
                    description: "Reach your Vaultwarden, servers, and services through encrypted tunnels."
                )
            }
            .padding(.horizontal, 24)

            Spacer()
            Spacer()
        }
    }

    // MARK: - Enroll Page

    private var enrollPage: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 64))
                .foregroundStyle(Color.ztlpBlue)

            VStack(spacing: 12) {
                Text("Ready to Enroll")
                    .font(.title2.weight(.bold))

                Text("Scan a ZTLP enrollment QR code or paste an enrollment URI to join your zone.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            // Example of what a QR code contains
            VStack(spacing: 4) {
                Text("Enrollment URI format:")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Text("ztlp://enroll?zone=...&relay=...&gw=...")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
            }
            .padding(12)
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            Spacer()
            Spacer()
        }
    }
}

// MARK: - Feature Row

private struct FeatureRow: View {
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(Color.ztlpBlue)
                .frame(width: 36, alignment: .center)

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

#Preview {
    OnboardingView()
        .environmentObject(ZTLPConfiguration())
}
