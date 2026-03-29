import SwiftUI

struct BatterySettingsView: View {
    @StateObject private var configManager = BatteryConfigManager()
    @StateObject private var monitor = BatteryMonitor()

    var body: some View {
        Form {
            Section("Current Status") {
                HStack {
                    Image(systemName: batteryIcon)
                        .foregroundColor(batteryColor)
                    Text("\(Int(monitor.batteryLevel * 100))%")
                        .font(.headline)
                    if monitor.isCharging {
                        Image(systemName: "bolt.fill")
                            .foregroundColor(.yellow)
                        Text("Charging")
                            .foregroundColor(.secondary)
                    }
                }
            }

            Section("Power Saving") {
                Toggle("Disconnect on Low Battery", isOn: $configManager.config.lowBatteryDisconnect)

                if configManager.config.lowBatteryDisconnect {
                    Stepper(
                        "Threshold: \(configManager.config.lowBatteryThreshold)%",
                        value: $configManager.config.lowBatteryThreshold,
                        in: 5...50,
                        step: 5
                    )
                }

                Toggle("Reduced Mode on Battery", isOn: $configManager.config.reducedModeOnBattery)

                Toggle("Optimize for Cellular", isOn: $configManager.config.cellularOptimize)
            }

            Section("Keepalive") {
                Picker("Interval", selection: $configManager.config.keepaliveInterval) {
                    ForEach(BatteryConfig.KeepAliveInterval.allCases, id: \.self) { interval in
                        Text(interval.rawValue).tag(interval)
                    }
                }

                let effective = configManager.config.effectiveKeepalive(
                    batteryLevel: monitor.batteryLevel,
                    isCharging: monitor.isCharging,
                    isCellular: false
                )
                Text("Effective: \(Int(effective))s")
                    .foregroundColor(.secondary)
            }

            Section("Background") {
                Toggle("Suspend on Background", isOn: $configManager.config.suspendOnBackground)

                if configManager.config.suspendOnBackground {
                    Stepper(
                        "Timeout: \(Int(configManager.config.backgroundTimeout))s",
                        value: $configManager.config.backgroundTimeout,
                        in: 60...900,
                        step: 60
                    )
                }
            }
        }
        .navigationTitle("Battery & Power")
        .onAppear { monitor.startMonitoring() }
        .onDisappear {
            monitor.stopMonitoring()
            configManager.save()
        }
        .onChange(of: configManager.config.lowBatteryDisconnect) { _ in configManager.save() }
        .onChange(of: configManager.config.reducedModeOnBattery) { _ in configManager.save() }
        .onChange(of: configManager.config.cellularOptimize) { _ in configManager.save() }
        .onChange(of: configManager.config.keepaliveInterval) { _ in configManager.save() }
        .onChange(of: configManager.config.suspendOnBackground) { _ in configManager.save() }
    }

    private var batteryIcon: String {
        let level = monitor.batteryLevel
        if monitor.isCharging { return "battery.100.bolt" }
        if level > 0.75 { return "battery.100" }
        if level > 0.50 { return "battery.75" }
        if level > 0.25 { return "battery.50" }
        return "battery.25"
    }

    private var batteryColor: Color {
        let level = monitor.batteryLevel
        if level > 0.5 { return .green }
        if level > 0.2 { return .yellow }
        return .red
    }
}
