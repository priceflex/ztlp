import SwiftUI

struct OnDemandRulesView: View {
    @StateObject private var manager = OnDemandRulesManager()
    @State private var showAddRule = false
    @State private var editingRule: OnDemandRule?

    var body: some View {
        List {
            Section {
                ForEach(manager.rules) { rule in
                    OnDemandRuleRow(rule: rule) {
                        editingRule = rule
                    }
                }
                .onDelete(perform: manager.removeRule)
                .onMove(perform: manager.moveRule)
            } header: {
                Text("Rules (evaluated top to bottom)")
            } footer: {
                Text("First matching rule wins. Drag to reorder.")
            }

            Section {
                Button("Add Rule") {
                    showAddRule = true
                }

                Button("Use Trusted WiFi Template") {
                    manager.rules = OnDemandRulesManager.trustedWiFiRules(trustedSSIDs: [])
                }
                .foregroundColor(.secondary)
            }
        }
        .navigationTitle("On-Demand Rules")
        .toolbar { EditButton() }
        .sheet(isPresented: $showAddRule) {
            OnDemandRuleEditor(manager: manager, rule: nil)
        }
        .sheet(item: $editingRule) { rule in
            OnDemandRuleEditor(manager: manager, rule: rule)
        }
    }
}

struct OnDemandRuleRow: View {
    let rule: OnDemandRule
    let onTap: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Image(systemName: rule.action == .connect ? "checkmark.shield" : "xmark.shield")
                        .foregroundColor(rule.action == .connect ? .green : .red)
                    Text(rule.action.rawValue)
                        .font(.headline)
                }

                HStack(spacing: 8) {
                    if rule.interfaceType != .any {
                        Label(rule.interfaceType.rawValue, systemImage: iconForInterface(rule.interfaceType))
                            .font(.caption)
                    }
                    if !rule.ssidMatch.isEmpty {
                        Text(rule.ssidMatch.joined(separator: ", "))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }

            Spacer()

            Toggle("", isOn: Binding(
                get: { rule.isEnabled },
                set: { enabled in
                    var updated = rule
                    updated.isEnabled = enabled
                    // Would need manager reference to save
                }
            ))
            .labelsHidden()
        }
        .contentShape(Rectangle())
        .onTapGesture(perform: onTap)
    }

    private func iconForInterface(_ type: InterfaceType) -> String {
        switch type {
        case .any: return "network"
        case .wifi: return "wifi"
        case .cellular: return "antenna.radiowaves.left.and.right"
        case .ethernet: return "cable.connector"
        }
    }
}

struct OnDemandRuleEditor: View {
    @ObservedObject var manager: OnDemandRulesManager
    @Environment(\.dismiss) private var dismiss

    let isNew: Bool
    @State var action: OnDemandAction
    @State var interfaceType: InterfaceType
    @State var ssidText: String
    @State var probeURL: String
    @State var isEnabled: Bool

    private var ruleId: UUID

    init(manager: OnDemandRulesManager, rule: OnDemandRule?) {
        self.manager = manager
        self.isNew = rule == nil
        self.ruleId = rule?.id ?? UUID()
        _action = State(initialValue: rule?.action ?? .connect)
        _interfaceType = State(initialValue: rule?.interfaceType ?? .any)
        _ssidText = State(initialValue: rule?.ssidMatch.joined(separator: ", ") ?? "")
        _probeURL = State(initialValue: rule?.probeURL ?? "")
        _isEnabled = State(initialValue: rule?.isEnabled ?? true)
    }

    var body: some View {
        NavigationView {
            Form {
                Section("Action") {
                    Picker("When matched", selection: $action) {
                        ForEach(OnDemandAction.allCases, id: \.self) { action in
                            Text(action.rawValue).tag(action)
                        }
                    }
                }

                Section("Network Conditions") {
                    Picker("Interface", selection: $interfaceType) {
                        ForEach(InterfaceType.allCases, id: \.self) { type in
                            Text(type.rawValue).tag(type)
                        }
                    }

                    TextField("WiFi SSIDs (comma-separated)", text: $ssidText)
                        .textInputAutocapitalization(.never)
                }

                Section("Advanced") {
                    TextField("Probe URL (optional)", text: $probeURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)

                    Toggle("Enabled", isOn: $isEnabled)
                }
            }
            .navigationTitle(isNew ? "New Rule" : "Edit Rule")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                }
            }
        }
    }

    private func save() {
        let ssids = ssidText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let rule = OnDemandRule(
            id: ruleId,
            action: action,
            ssidMatch: ssids,
            interfaceType: interfaceType,
            probeURL: probeURL.isEmpty ? nil : probeURL,
            isEnabled: isEnabled
        )

        if isNew {
            manager.addRule(rule)
        } else {
            manager.updateRule(rule)
        }
        dismiss()
    }
}
