// ZTLPApp.swift
// ZTLP for iOS: one page, no Connect button. ZTLP is an identity network;
// the tunnel is kept up by iOS on demand.

import SwiftUI
import UIKit

@main
struct ZTLPApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            HomeView(model: model)
                .tint(.ztlpBlue)
                .onOpenURL { url in
                    model.handleIncomingURL(url)
                }
                .onReceive(
                    NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)
                ) { _ in
                    Task { await model.didBecomeActive() }
                }
        }
    }
}
