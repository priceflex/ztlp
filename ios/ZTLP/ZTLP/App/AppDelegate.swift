// AppDelegate.swift
// ZTLP
//
// UIKit AppDelegate adapter for handling system events that SwiftUI's
// App lifecycle doesn't cover: background task registration, push
// notification handling, and app termination cleanup.

import UIKit

class AppDelegate: NSObject, UIApplicationDelegate {

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // Initialize the ZTLP library early
        do {
            try ZTLPBridge.shared.initialize()
        } catch {
            print("[ZTLP] Failed to initialize library: \(error)")
        }
        return true
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Shut down the ZTLP library cleanly.
        // Note: The Network Extension continues running independently.
        ZTLPBridge.shared.shutdown()
    }

    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let config = UISceneConfiguration(
            name: "Default Configuration",
            sessionRole: connectingSceneSession.role
        )
        return config
    }
}
