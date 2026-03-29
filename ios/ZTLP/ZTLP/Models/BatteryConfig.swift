import Foundation
import UIKit

/// Battery optimization configuration
struct BatteryConfig: Codable {
    var lowBatteryDisconnect: Bool = false
    var lowBatteryThreshold: Int = 20  // percent
    var reducedModeOnBattery: Bool = true
    var keepaliveInterval: KeepAliveInterval = .normal
    var suspendOnBackground: Bool = false
    var backgroundTimeout: TimeInterval = 300  // 5 minutes
    var cellularOptimize: Bool = true  // Reduce keepalive on cellular

    enum KeepAliveInterval: String, Codable, CaseIterable {
        case aggressive = "Aggressive (15s)"
        case normal = "Normal (30s)"
        case conservative = "Conservative (60s)"
        case minimal = "Minimal (120s)"

        var seconds: TimeInterval {
            switch self {
            case .aggressive: return 15
            case .normal: return 30
            case .conservative: return 60
            case .minimal: return 120
            }
        }
    }

    /// Get effective keepalive interval based on current conditions
    func effectiveKeepalive(batteryLevel: Float, isCharging: Bool, isCellular: Bool) -> TimeInterval {
        var interval = keepaliveInterval.seconds

        // Double interval on battery + low power
        if !isCharging && batteryLevel < Float(lowBatteryThreshold) / 100.0 {
            interval *= 2
        }

        // 1.5x on cellular to save data
        if cellularOptimize && isCellular {
            interval *= 1.5
        }

        return min(interval, 300)  // cap at 5 minutes
    }

    /// Should VPN disconnect due to low battery?
    func shouldDisconnect(batteryLevel: Float, isCharging: Bool) -> Bool {
        guard lowBatteryDisconnect, !isCharging else { return false }
        return batteryLevel * 100 < Float(lowBatteryThreshold)
    }
}

/// Battery monitoring service
class BatteryMonitor: ObservableObject {
    @Published var batteryLevel: Float = 1.0
    @Published var isCharging: Bool = false
    @Published var batteryState: UIDevice.BatteryState = .unknown

    private var timer: Timer?

    init() {
        UIDevice.current.isBatteryMonitoringEnabled = true
        updateBatteryInfo()
    }

    func startMonitoring(interval: TimeInterval = 60) {
        updateBatteryInfo()
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            self?.updateBatteryInfo()
        }

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(batteryStateChanged),
            name: UIDevice.batteryStateDidChangeNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(batteryLevelChanged),
            name: UIDevice.batteryLevelDidChangeNotification,
            object: nil
        )
    }

    func stopMonitoring() {
        timer?.invalidate()
        timer = nil
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func batteryStateChanged() {
        updateBatteryInfo()
    }

    @objc private func batteryLevelChanged() {
        updateBatteryInfo()
    }

    private func updateBatteryInfo() {
        DispatchQueue.main.async { [self] in
            batteryLevel = UIDevice.current.batteryLevel
            batteryState = UIDevice.current.batteryState
            isCharging = batteryState == .charging || batteryState == .full
        }
    }

    deinit {
        stopMonitoring()
    }
}

class BatteryConfigManager: ObservableObject {
    @Published var config: BatteryConfig

    private let storageKey = "ztlp_battery_config"

    init() {
        if let data = UserDefaults(suiteName: "group.com.ztlp.shared")?.data(forKey: storageKey),
           let saved = try? JSONDecoder().decode(BatteryConfig.self, from: data) {
            config = saved
        } else {
            config = BatteryConfig()
        }
    }

    func save() {
        if let data = try? JSONEncoder().encode(config) {
            UserDefaults(suiteName: "group.com.ztlp.shared")?.set(data, forKey: storageKey)
        }
    }
}
