import Foundation
import NetworkExtension

/// On-demand VPN rule configuration
/// Controls when the VPN automatically connects or disconnects
struct OnDemandRule: Identifiable, Codable {
    let id: UUID
    var action: OnDemandAction
    var ssidMatch: [String]       // WiFi SSIDs to match
    var interfaceType: InterfaceType
    var probeURL: String?         // URL to test connectivity
    var isEnabled: Bool

    init(
        id: UUID = UUID(),
        action: OnDemandAction = .connect,
        ssidMatch: [String] = [],
        interfaceType: InterfaceType = .any,
        probeURL: String? = nil,
        isEnabled: Bool = true
    ) {
        self.id = id
        self.action = action
        self.ssidMatch = ssidMatch
        self.interfaceType = interfaceType
        self.probeURL = probeURL
        self.isEnabled = isEnabled
    }
}

enum OnDemandAction: String, Codable, CaseIterable {
    case connect = "Connect"
    case disconnect = "Disconnect"
    case evaluateConnection = "Evaluate"
    case ignore = "Ignore"

    var description: String {
        switch self {
        case .connect: return "Always connect VPN"
        case .disconnect: return "Disconnect VPN"
        case .evaluateConnection: return "Evaluate and decide"
        case .ignore: return "Do nothing"
        }
    }

    var neAction: NEOnDemandRuleAction {
        switch self {
        case .connect: return .connect
        case .disconnect: return .disconnect
        case .evaluateConnection: return .evaluateConnection
        case .ignore: return .ignore
        }
    }
}

enum InterfaceType: String, Codable, CaseIterable {
    case any = "Any"
    case wifi = "WiFi"
    case cellular = "Cellular"
    case ethernet = "Ethernet"

    var neType: NEOnDemandRuleInterfaceType? {
        switch self {
        case .any: return nil
        case .wifi: return .wiFi
        case .cellular: return .cellular
        case .ethernet: return .ethernet
        }
    }
}

/// Manages on-demand VPN rules
class OnDemandRulesManager: ObservableObject {
    @Published var rules: [OnDemandRule] = []

    private let storageKey = "ztlp_on_demand_rules"

    init() {
        loadRules()
    }

    func addRule(_ rule: OnDemandRule) {
        rules.append(rule)
        saveRules()
    }

    func removeRule(at offsets: IndexSet) {
        rules.remove(atOffsets: offsets)
        saveRules()
    }

    func moveRule(from source: IndexSet, to destination: Int) {
        rules.move(fromOffsets: source, toOffset: destination)
        saveRules()
    }

    func updateRule(_ rule: OnDemandRule) {
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index] = rule
            saveRules()
        }
    }

    /// Convert to NEOnDemandRule array for NEVPNManager
    func toNEOnDemandRules() -> [NEOnDemandRule] {
        rules.filter(\.isEnabled).map { rule in
            let neRule: NEOnDemandRule
            switch rule.action {
            case .connect:
                neRule = NEOnDemandRuleConnect()
            case .disconnect:
                neRule = NEOnDemandRuleDisconnect()
            case .evaluateConnection:
                let evalRule = NEOnDemandRuleEvaluateConnection()
                if let url = rule.probeURL {
                    evalRule.connectionRules = [
                        NEEvaluateConnectionRule(matchDomains: ["*"], andAction: .connectIfNeeded)
                    ]
                    _ = url // probe URL stored for reference
                }
                neRule = evalRule
            case .ignore:
                neRule = NEOnDemandRuleIgnore()
            }

            if !rule.ssidMatch.isEmpty {
                neRule.ssidMatch = rule.ssidMatch
            }
            if let neType = rule.interfaceType.neType {
                neRule.interfaceTypeMatch = neType
            }
            if let url = rule.probeURL, let probeUrl = URL(string: url) {
                neRule.probeURL = probeUrl
            }

            return neRule
        }
    }

    /// Convenience: create standard rules for "trusted WiFi" pattern
    static func trustedWiFiRules(trustedSSIDs: [String]) -> [OnDemandRule] {
        var rules: [OnDemandRule] = []

        // Disconnect on trusted WiFi
        if !trustedSSIDs.isEmpty {
            rules.append(OnDemandRule(
                action: .disconnect,
                ssidMatch: trustedSSIDs,
                interfaceType: .wifi
            ))
        }

        // Connect on all other WiFi
        rules.append(OnDemandRule(
            action: .connect,
            interfaceType: .wifi
        ))

        // Connect on cellular
        rules.append(OnDemandRule(
            action: .connect,
            interfaceType: .cellular
        ))

        return rules
    }

    private func saveRules() {
        if let data = try? JSONEncoder().encode(rules) {
            UserDefaults(suiteName: "group.com.ztlp.shared")?.set(data, forKey: storageKey)
        }
    }

    private func loadRules() {
        guard let data = UserDefaults(suiteName: "group.com.ztlp.shared")?.data(forKey: storageKey),
              let saved = try? JSONDecoder().decode([OnDemandRule].self, from: data) else { return }
        rules = saved
    }
}
