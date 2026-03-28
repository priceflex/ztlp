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

    var body: some View {
        if isReady {
            if configuration.hasCompletedOnboarding {
                ContentView()
            } else {
                OnboardingView()
            }
        } else {
            // Launch screen — shown while ZTLP library initializes
            ZStack {
                Color(.systemBackground)
                    .ignoresSafeArea()
                VStack(spacing: 16) {
                    Image(systemName: "shield.checkered")
                        .font(.system(size: 64))
                        .foregroundColor(.accentColor)
                    Text("ZTLP")
                        .font(.title.bold())
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                    Text("Initializing...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .task {
                // Move initialization off the immediate SwiftUI render path
                do {
                    try ZTLPBridge.shared.initialize()
                } catch {
                    print("[ZTLP] Library initialization failed: \(error)")
                }
                // Brief delay so the launch screen is visible (avoids flicker)
                try? await Task.sleep(nanoseconds: 200_000_000)
                isReady = true
            }
        }
    }
}
