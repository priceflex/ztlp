import Foundation
import UIKit

struct LogExportPayload {
    let fileURL: URL
    let summary: String
}

enum LogExportService {
    static func createExportPayload(reason: String) -> LogExportPayload? {
        let logger = TunnelLogger.shared
        logger.info("Preparing log export: \(reason)", source: "LogExport")
        logger.flush()

        let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared")
        let snapshot = makeSnapshot(reason: reason, defaults: sharedDefaults)
        let logs = String(data: logger.exportData(), encoding: .utf8) ?? ""
        let combined = snapshot + "\n\n===== ztlp.log =====\n" + logs

        let tmpDir = FileManager.default.temporaryDirectory
        let filename = "ztlp-debug-\(Int(Date().timeIntervalSince1970)).txt"
        let url = tmpDir.appendingPathComponent(filename)

        do {
            try combined.data(using: .utf8)?.write(to: url)
            logger.info("Log export ready: \(url.lastPathComponent)", source: "LogExport")
            logger.flush()
            return LogExportPayload(fileURL: url, summary: snapshot)
        } catch {
            logger.error("Failed to write log export: \(error.localizedDescription)", source: "LogExport")
            return nil
        }
    }

    private static func makeSnapshot(reason: String, defaults: UserDefaults?) -> String {
        let date = ISO8601DateFormatter().string(from: Date())
        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
        let model = UIDevice.current.model
        let iosVersion = UIDevice.current.systemVersion
        let neMemoryMB = defaults?.object(forKey: "ztlp_ne_memory_mb") as? Int
        let neVirtualMB = defaults?.object(forKey: "ztlp_ne_virtual_mb") as? Int
        let replayRejectCount = defaults?.object(forKey: "ztlp_replay_reject_count") as? Int
        let selectedRelay = defaults?.string(forKey: "ztlp_selected_relay") ?? "<none>"
        let peerAddress = defaults?.string(forKey: "ztlp_peer_address") ?? "<none>"
        let connectionState = defaults?.string(forKey: "ztlp_connection_state") ?? "<unknown>"

        return """
        ===== ZTLP Debug Snapshot =====
        reason: \(reason)
        timestamp: \(date)
        app_version: \(appVersion)
        build: \(build)
        device_model: \(model)
        ios_version: \(iosVersion)
        connection_state: \(connectionState)
        selected_relay: \(selectedRelay)
        peer_address: \(peerAddress)
        ne_memory_mb: \(neMemoryMB.map(String.init) ?? "<nil>")
        ne_virtual_mb: \(neVirtualMB.map(String.init) ?? "<nil>")
        replay_reject_count: \(replayRejectCount.map(String.init) ?? "<nil>")
        """
    }
}
