// AddressPlan.swift
// Shared by the app and the packet tunnel extension.
//
// The one place the tunnel address plan lives (see
// docs/plans/2026-11-27-ios-native-agent.md): the agent listens on loopback,
// and the tunnel exists only to bring `.ztlp` DNS queries to the extension.

import Foundation

enum AddressPlan {
    /// DNS server address given to iOS for `.ztlp` names. It is ROUTED into
    /// the tunnel (not owned by the interface), so queries arrive as packets
    /// and the extension answers them.
    static let dnsAddress = "100.64.77.1"

    /// The tunnel interface's one own address.
    static let interfaceAddress = "100.64.77.2"

    /// Where the agent listens inside the extension. Measured on a device:
    /// iOS sends traffic for the tunnel's own addresses into the tunnel as
    /// packets, even from the extension itself, so kernel sockets bound there
    /// are unreachable. Loopback is delivered from other apps to the
    /// extension's sockets.
    static let agentAddress = "127.0.0.1"

    /// What the agent is told to serve sites on: the single loopback address
    /// (a /32 tells the agent to route by name instead of by address).
    static let agentCIDR = "127.0.0.1/32"

    /// Only names under this suffix are sent to the agent's resolver.
    static let matchDomain = "ztlp"

    /// Placeholder for `NEPacketTunnelNetworkSettings.tunnelRemoteAddress`.
    /// There is no single remote endpoint; the agent dials gateways itself.
    static let tunnelRemotePlaceholder = "127.0.0.1"

    /// Mask for every local tunnel address (each is its own /32).
    static let hostMask = "255.255.255.255"

    /// Usable host addresses of an IPv4 CIDR block (network and broadcast
    /// addresses excluded). Returns [] for anything that is not a /8.../30.
    static func usableHosts(cidr: String) -> [String] {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefix = Int(parts[1]), (8...30).contains(prefix),
              let base = ipv4ToUInt32(String(parts[0])) else { return [] }
        let hostBits = UInt32(32 - prefix)
        let size = UInt32(1) << hostBits
        let network = base & ~(size - 1)
        return (1..<(size - 1)).map { uint32ToIPv4(network + $0) }
    }

    /// Every address the tunnel interface owns.
    static var tunnelAddresses: [String] { [interfaceAddress] }

    static func ipv4ToUInt32(_ text: String) -> UInt32? {
        let octets = text.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var value: UInt32 = 0
        for octet in octets {
            guard !octet.isEmpty, octet.count <= 3,
                  octet.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let n = UInt32(octet), n <= 255 else { return nil }
            value = (value << 8) | n
        }
        return value
    }

    static func uint32ToIPv4(_ value: UInt32) -> String {
        "\((value >> 24) & 0xff).\((value >> 16) & 0xff).\((value >> 8) & 0xff).\(value & 0xff)"
    }
}

/// Identifiers and file locations both targets agree on.
enum SharedPaths {
    static let appGroup = "group.com.ztlp.shared"
    static let tunnelBundleID = "com.ztlp.app.tunnel"

    /// App Group container. This is the `home_dir` given to the Rust agent.
    static var container: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    /// `<container>/.ztlp`, where the agent keeps identity, config and logs.
    static func stateDirectory(in container: URL) -> URL {
        container.appendingPathComponent(".ztlp", isDirectory: true)
    }

    /// Log written by the Rust agent.
    static func agentLog(in container: URL) -> URL {
        stateDirectory(in: container).appendingPathComponent("agent.log")
    }

    /// Small log written by the extension's Swift shell (start/stop, memory).
    /// Kept outside `.ztlp` so the Rust side owns that directory alone.
    static func extensionLog(in container: URL) -> URL {
        container.appendingPathComponent("extension.log")
    }
}
