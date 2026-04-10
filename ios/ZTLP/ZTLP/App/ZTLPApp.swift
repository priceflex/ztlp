// ZTLPApp.swift
// ZTLP
//
// Main entry point for the ZTLP iOS app.
// Uses SwiftUI App lifecycle with a UIKit AppDelegate adapter
// for handling background tasks and push notifications.

import SwiftUI

@main
struct ZTLPApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    /// Shared app configuration (stored in app group UserDefaults).
    @StateObject private var configuration = ZTLPConfiguration()

    /// Network connectivity monitor.
    @StateObject private var networkMonitor = NetworkMonitor.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(configuration)
                .environmentObject(networkMonitor)
        }
    }
}

/// Root view that shows a launch screen while initializing, then switches
/// between onboarding and the main tab view.
struct RootView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration
    @State private var isReady = false
    @State private var showShield = true

    var body: some View {
        if isReady {
            if configuration.hasCompletedOnboarding {
                ContentView()
            } else {
                OnboardingView()
            }
        } else {
            // Professional launch screen
            ZStack {
                // Background
                LinearGradient(
                    colors: [
                        Color(.systemBackground),
                        Color.ztlpBlue.opacity(0.03)
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .ignoresSafeArea()

                VStack(spacing: 20) {
                    // Animated shield
                    ZStack {
                        Circle()
                            .fill(Color.ztlpBlue.opacity(0.08))
                            .frame(width: 120, height: 120)
                            .scaleEffect(showShield ? 1 : 0.8)

                        Image(systemName: "shield.checkered")
                            .font(.system(size: 56, weight: .medium))
                            .foregroundStyle(LinearGradient.ztlpShield)
                            .scaleEffect(showShield ? 1 : 0.5)
                            .opacity(showShield ? 1 : 0)
                    }
                    .animation(.spring(response: 0.6, dampingFraction: 0.7), value: showShield)

                    VStack(spacing: 6) {
                        Text("ZTLP")
                            .font(.title.weight(.bold))
                            .tracking(2)

                        Text("Zero Trust Lattice Protocol")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .tracking(0.5)
                    }

                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .tint(Color.ztlpBlue)
                        .padding(.top, 8)
                }
            }
            .task {
                // Initialize
                do {
                    try ZTLPBridge.shared.initialize()
                } catch {
                    print("[ZTLP] Library initialization failed: \(error)")
                }
                // Brief delay for polish
                try? await Task.sleep(nanoseconds: 400_000_000)
                withAnimation(.easeOut(duration: 0.3)) {
                    isReady = true
                }
            }
            .onAppear {
                withAnimation(.easeOut(duration: 0.5).delay(0.1)) {
                    showShield = true
                }
            }
        }
    }
}
