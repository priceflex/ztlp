// ZTLPService.swift
// ZTLP macOS
//
// Model for ZTLP-NS service discovery results.
// Services are resources (hosts, ports, applications) registered in a
// ZTLP zone that this node can reach through the encrypted tunnel.

import Foundation

/// A service discovered via ZTLP Name Service (NS).
struct ZTLPService: Identifiable, Equatable, Hashable, Codable {
    /// Unique service identifier (zone-scoped).
    let id: String

    /// Human-readable service name (e.g., "Web Server", "Database").
    let name: String

    /// Hostname or IP address within the ZTLP zone.
    let hostname: String

    /// TCP/UDP port the service listens on.
    let port: UInt16

    /// Protocol type (e.g., "tcp", "udp", "https").
    let protocolType: String

    /// Node ID of the host running this service.
    let hostNodeId: String

    /// Whether the service is currently reachable.
    var isReachable: Bool

    /// Last time reachability was checked.
    var lastChecked: Date?

    /// Optional description of the service.
    var serviceDescription: String?

    /// Optional tags for categorization.
    var tags: [String]

    /// Display string for the service endpoint.
    var endpoint: String {
        "\(hostname):\(port)"
    }

    /// Abbreviated host Node ID.
    var shortHostNodeId: String {
        guard hostNodeId.count >= 12 else { return hostNodeId }
        let prefix = hostNodeId.prefix(8)
        let suffix = hostNodeId.suffix(4)
        return "\(prefix)…\(suffix)"
    }
}

extension ZTLPService {
    /// Example services for SwiftUI previews.
    static let previews: [ZTLPService] = [
        ZTLPService(
            id: "svc-001",
            name: "Web Server",
            hostname: "web.internal.ztlp",
            port: 443,
            protocolType: "https",
            hostNodeId: "a1b2c3d4e5f60718",
            isReachable: true,
            lastChecked: Date(),
            serviceDescription: "Main web application",
            tags: ["web", "production"]
        ),
        ZTLPService(
            id: "svc-002",
            name: "Database",
            hostname: "db.internal.ztlp",
            port: 5432,
            protocolType: "tcp",
            hostNodeId: "f8e7d6c5b4a39201",
            isReachable: true,
            lastChecked: Date(),
            serviceDescription: "PostgreSQL primary",
            tags: ["database", "production"]
        ),
        ZTLPService(
            id: "svc-003",
            name: "SSH Gateway",
            hostname: "ssh.internal.ztlp",
            port: 22,
            protocolType: "tcp",
            hostNodeId: "1122334455667788",
            isReachable: false,
            lastChecked: Date().addingTimeInterval(-300),
            serviceDescription: "Jump host",
            tags: ["ssh", "admin"]
        ),
    ]
}
