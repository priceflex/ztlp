// TunnelConfiguration.swift
// ZTLPTunnel
//
// Configuration model passed from the main app to the Network Extension
// via NETunnelProviderProtocol.providerConfiguration.
//
// The main app serializes this to a [String: Any] dictionary and stores it
// in the provider protocol. The extension deserializes it in startTunnel().

import Foundation

/// Configuration for the ZTLP packet tunnel.
struct TunnelConfiguration {

    /// The ZTLP Node ID of the target peer (hex string, 32 chars).
    let targetNodeId: String

    /// Optional relay server address (e.g., "relay.ztlp.net:4433").
    /// If nil, the client attempts direct peer-to-peer connection.
    let relayAddress: String?

    /// STUN server for NAT discovery (default: "stun.l.google.com:19302").
    let stunServer: String

    /// TUN interface IP address (default: "10.0.0.2").
    let tunnelAddress: String

    /// TUN interface subnet mask (default: "255.255.255.0").
    let tunnelNetmask: String

    /// DNS servers to use while tunnel is active.
    let dnsServers: [String]

    /// Maximum Transmission Unit for the TUN interface.
    /// 1400 accounts for ZTLP encryption + UDP overhead.
    let mtu: Int

    /// Optional path to the identity JSON file in the shared container.
    /// If nil, the extension uses the default path in the app group container.
    let identityPath: String?

    /// Whether to route all traffic through the tunnel (full VPN).
    /// Default is false (split-tunnel: only .ztlp domains).
    let fullTunnel: Bool

    // MARK: - Serialization

    /// Serialize to a dictionary suitable for NETunnelProviderProtocol.providerConfiguration.
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "targetNodeId": targetNodeId,
            "stunServer": stunServer,
            "tunnelAddress": tunnelAddress,
            "tunnelNetmask": tunnelNetmask,
            "dnsServers": dnsServers,
            "mtu": mtu,
        ]
        if let relay = relayAddress {
            dict["relayAddress"] = relay
        }
        if let path = identityPath {
            dict["identityPath"] = path
        }
        dict["fullTunnel"] = fullTunnel
        return dict
    }

    /// Deserialize from a provider configuration dictionary.
    static func from(dictionary dict: [String: Any]) -> TunnelConfiguration? {
        guard let targetNodeId = dict["targetNodeId"] as? String else {
            return nil
        }
        return TunnelConfiguration(
            targetNodeId: targetNodeId,
            relayAddress: dict["relayAddress"] as? String,
            stunServer: dict["stunServer"] as? String ?? "stun.l.google.com:19302",
            tunnelAddress: dict["tunnelAddress"] as? String ?? "10.0.0.2",
            tunnelNetmask: dict["tunnelNetmask"] as? String ?? "255.255.255.0",
            dnsServers: dict["dnsServers"] as? [String] ?? ["1.1.1.1", "8.8.8.8"],
            mtu: dict["mtu"] as? Int ?? 1400,
            identityPath: dict["identityPath"] as? String,
            fullTunnel: dict["fullTunnel"] as? Bool ?? false
        )
    }
}
