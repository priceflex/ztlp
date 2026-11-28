// Readiness.swift
// The home page checklist as pure data. Modelled on the Mac app's
// HomeReadiness: three rows, each green or carrying one short hint and at
// most one action. No I/O, unit tested.

import Foundation

/// What the app knows about the VPN configuration and its connection.
enum TunnelPhase: Equatable, Sendable {
    /// Not looked up yet.
    case unknown
    /// No VPN configuration saved (first run, or the user removed it).
    case notConfigured
    case connecting
    case connected
    /// Configured but not up. `reason` is iOS's last disconnect error, if any.
    case disconnected(reason: String?)
}

/// Result of the HTTPS trust probe.
enum TrustState: Equatable, Sendable {
    /// Not probed yet.
    case unknown
    case trusted
    /// TLS answered but the certificate is not trusted on this device.
    case notTrusted
    /// The probe could not reach the agent at all.
    case unreachable
}

enum ReadinessAction: Equatable, Sendable {
    case enroll
    case setUpTunnel
    case installCertificate
}

struct ReadinessRow: Equatable, Identifiable, Sendable {
    enum Kind: Equatable, Sendable { case ready, waiting, needsAction, failed }

    let id: String
    let title: String
    let kind: Kind
    /// Short status next to the title ("Enrolled", "Starting").
    let status: String
    /// One line shown under a row that is not green.
    let hint: String?
    let action: ReadinessAction?

    var isReady: Bool { kind == .ready }
}

struct Readiness: Equatable, Sendable {
    let enrolled: ReadinessRow
    let tunnel: ReadinessRow
    let https: ReadinessRow

    var rows: [ReadinessRow] { [enrolled, tunnel, https] }
    var allReady: Bool { rows.allSatisfy(\.isReady) }

    /// The line that tells the user what to do with a working setup.
    static func guidance(zone: String) -> String {
        let z = zone.isEmpty ? "zone.ztlp" : zone
        return "Open any https://name.\(z) in Safari. There is nothing to switch on."
    }

    static func compute(
        enrolled isEnrolled: Bool,
        zone: String,
        tunnel phase: TunnelPhase,
        agent: AgentStatus?,
        trust: TrustState
    ) -> Readiness {
        // Row 1: Enrolled
        let enrolledRow: ReadinessRow
        if isEnrolled {
            enrolledRow = ReadinessRow(
                id: "enrolled", title: "Enrolled", kind: .ready,
                status: zone.isEmpty ? "Enrolled" : zone,
                hint: nil, action: nil
            )
        } else {
            enrolledRow = ReadinessRow(
                id: "enrolled", title: "Enrolled", kind: .needsAction,
                status: "Not enrolled",
                hint: "Scan the QR code from your administrator, or paste the code.",
                action: .enroll
            )
        }

        // Row 2: Tunnel running
        let tunnelRow: ReadinessRow
        if !isEnrolled {
            tunnelRow = ReadinessRow(
                id: "tunnel", title: "Tunnel running", kind: .waiting,
                status: "Waiting", hint: "Starts by itself after you enroll.", action: nil
            )
        } else {
            switch phase {
            case .unknown:
                tunnelRow = ReadinessRow(
                    id: "tunnel", title: "Tunnel running", kind: .waiting,
                    status: "Checking", hint: "Checking the ZTLP configuration.", action: nil
                )
            case .notConfigured:
                tunnelRow = ReadinessRow(
                    id: "tunnel", title: "Tunnel running", kind: .needsAction,
                    status: "Needs permission",
                    hint: "Tap Allow, then choose Allow when iOS asks to add the ZTLP configuration.",
                    action: .setUpTunnel
                )
            case .connecting:
                tunnelRow = ReadinessRow(
                    id: "tunnel", title: "Tunnel running", kind: .waiting,
                    status: "Starting", hint: "Starting. This takes a few seconds.", action: nil
                )
            case .connected:
                if let agent, agent.running {
                    tunnelRow = ReadinessRow(
                        id: "tunnel", title: "Tunnel running", kind: .ready,
                        status: "Running", hint: nil, action: nil
                    )
                } else if let agent, !agent.lastError.isEmpty {
                    tunnelRow = ReadinessRow(
                        id: "tunnel", title: "Tunnel running", kind: .failed,
                        status: "Problem", hint: agent.lastError, action: .setUpTunnel
                    )
                } else {
                    tunnelRow = ReadinessRow(
                        id: "tunnel", title: "Tunnel running", kind: .waiting,
                        status: "Starting", hint: "Starting. This takes a few seconds.", action: nil
                    )
                }
            case .disconnected(let reason):
                if let reason, !reason.isEmpty {
                    tunnelRow = ReadinessRow(
                        id: "tunnel", title: "Tunnel running", kind: .failed,
                        status: "Stopped", hint: reason, action: .setUpTunnel
                    )
                } else {
                    tunnelRow = ReadinessRow(
                        id: "tunnel", title: "Tunnel running", kind: .needsAction,
                        status: "Stopped",
                        hint: "iOS starts it on its own. If it stays stopped, tap Fix.",
                        action: .setUpTunnel
                    )
                }
            }
        }

        // Row 3: HTTPS trusted
        let httpsRow: ReadinessRow
        if !tunnelRow.isReady {
            httpsRow = ReadinessRow(
                id: "https", title: "HTTPS trusted", kind: .waiting,
                status: "Waiting", hint: "Checked once the tunnel is running.", action: nil
            )
        } else {
            switch trust {
            case .trusted:
                httpsRow = ReadinessRow(
                    id: "https", title: "HTTPS trusted", kind: .ready,
                    status: "Trusted", hint: nil, action: nil
                )
            case .unknown:
                httpsRow = ReadinessRow(
                    id: "https", title: "HTTPS trusted", kind: .waiting,
                    status: "Checking", hint: "Checking the certificate.", action: nil
                )
            case .notTrusted:
                httpsRow = ReadinessRow(
                    id: "https", title: "HTTPS trusted", kind: .needsAction,
                    status: "Not trusted yet",
                    hint: "Two steps in Settings: install the ZTLP certificate, then turn on full trust for it.",
                    action: .installCertificate
                )
            case .unreachable:
                httpsRow = ReadinessRow(
                    id: "https", title: "HTTPS trusted", kind: .needsAction,
                    status: "Not set up",
                    hint: "Two steps in Settings: install the ZTLP certificate, then turn on full trust for it.",
                    action: .installCertificate
                )
            }
        }

        return Readiness(enrolled: enrolledRow, tunnel: tunnelRow, https: httpsRow)
    }
}
