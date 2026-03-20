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
                .onAppear {
                    initializeZTLP()
                }
        }
    }

    /// Initialize the ZTLP C library on first launch.
    private func initializeZTLP() {
        do {
            try ZTLPBridge.shared.initialize()
        } catch {
            // Non-fatal — the user can still browse settings.
            // Connection attempts will fail with a clear error.
            print("[ZTLP] Library initialization failed: \(error)")
        }
    }
}

/// Root view that switches between onboarding and the main tab view.
struct RootView: View {
    @EnvironmentObject var configuration: ZTLPConfiguration

    var body: some View {
        if configuration.hasCompletedOnboarding {
            ContentView()
        } else {
            OnboardingView()
        }
    }
}
