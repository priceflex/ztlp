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
        // Nebula pivot (S1.5): the main app no longer initializes a ZTLP
        // library in-process. All tunnel I/O runs inside the Network
        // Extension. Nothing to do here on launch.
        return true
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Nebula pivot (S1.5): no in-process ZTLP library to shut down.
        // The Network Extension continues running independently.
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
