// ZTLPTests.swift
// ZTLP macOS Tests

import XCTest
@testable import ZTLP

final class ZTLPTests: XCTestCase {

    // MARK: - ConnectionStatus Tests

    func testConnectionStatusLabels() {
        XCTAssertEqual(ConnectionStatus.disconnected.label, "Disconnected")
        XCTAssertEqual(ConnectionStatus.connecting.label, "Connecting…")
        XCTAssertEqual(ConnectionStatus.connected.label, "Connected")
        XCTAssertEqual(ConnectionStatus.reconnecting.label, "Reconnecting…")
        XCTAssertEqual(ConnectionStatus.disconnecting.label, "Disconnecting…")
    }

    func testConnectionStatusCanConnect() {
        XCTAssertTrue(ConnectionStatus.disconnected.canConnect)
        XCTAssertFalse(ConnectionStatus.connecting.canConnect)
        XCTAssertFalse(ConnectionStatus.connected.canConnect)
    }

    func testConnectionStatusCanDisconnect() {
        XCTAssertFalse(ConnectionStatus.disconnected.canDisconnect)
        XCTAssertTrue(ConnectionStatus.connected.canDisconnect)
        XCTAssertTrue(ConnectionStatus.reconnecting.canDisconnect)
    }

    // MARK: - TrafficStats Tests

    func testTrafficStatsFormatting() {
        var stats = TrafficStats()
        stats.bytesSent = 1024
        XCTAssertEqual(stats.formattedBytesSent, "1 KB")

        stats.bytesReceived = 1_048_576
        XCTAssertEqual(stats.formattedBytesReceived, "1 MB")
    }

    func testTrafficStatsDuration() {
        var stats = TrafficStats()
        XCTAssertEqual(stats.formattedDuration, "--:--:--")

        stats.connectedSince = Date().addingTimeInterval(-3661) // 1h 1m 1s
        XCTAssertEqual(stats.formattedDuration, "01:01:01")
    }

    // MARK: - ZTLPConfiguration Tests

    func testConfigurationDefaults() {
        let config = ZTLPConfiguration(suiteName: "test.ztlp.\(UUID().uuidString)")
        XCTAssertEqual(config.stunServer, "stun.l.google.com:19302")
        XCTAssertEqual(config.tunnelAddress, "10.0.0.2")
        XCTAssertEqual(config.mtu, 1400)
        XCTAssertTrue(config.natAssist)
        XCTAssertFalse(config.autoConnect)
    }

    func testConfigurationReset() {
        let suiteName = "test.ztlp.\(UUID().uuidString)"
        let config = ZTLPConfiguration(suiteName: suiteName)
        config.relayAddress = "test.relay:4433"
        config.mtu = 1500
        config.autoConnect = true

        config.reset()

        XCTAssertEqual(config.relayAddress, "")
        XCTAssertEqual(config.mtu, 1400)
        XCTAssertFalse(config.autoConnect)
    }

    func testConfigurationToTunnelConfiguration() {
        let suiteName = "test.ztlp.\(UUID().uuidString)"
        let config = ZTLPConfiguration(suiteName: suiteName)
        config.targetNodeId = "abcd1234"
        config.relayAddress = "relay.test:4433"

        let tunnel = config.toTunnelConfiguration()
        XCTAssertEqual(tunnel.targetNodeId, "abcd1234")
        XCTAssertEqual(tunnel.relayAddress, "relay.test:4433")
    }

    // MARK: - TunnelConfiguration Tests

    func testTunnelConfigSerialization() {
        let config = TunnelConfiguration(
            targetNodeId: "abc123",
            relayAddress: "relay:4433",
            stunServer: "stun:19302",
            tunnelAddress: "10.0.0.2",
            tunnelNetmask: "255.255.255.0",
            dnsServers: ["1.1.1.1"],
            mtu: 1400,
            identityPath: nil
        )

        let dict = config.toDictionary()
        XCTAssertEqual(dict["targetNodeId"] as? String, "abc123")
        XCTAssertEqual(dict["relayAddress"] as? String, "relay:4433")

        let restored = TunnelConfiguration.from(dictionary: dict)
        XCTAssertNotNil(restored)
        XCTAssertEqual(restored?.targetNodeId, "abc123")
    }

    // MARK: - ZTLPIdentityInfo Tests

    func testIdentityShortIds() {
        let identity = ZTLPIdentityInfo(
            nodeId: "a1b2c3d4e5f60718",
            publicKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            providerType: "software",
            createdAt: Date()
        )
        XCTAssertEqual(identity.shortNodeId, "a1b2c3d4…0718")
        XCTAssertFalse(identity.isHardwareBacked)
    }

    func testIdentityHardwareBacked() {
        let identity = ZTLPIdentityInfo(
            nodeId: "test",
            publicKey: "test",
            providerType: "secure_enclave",
            createdAt: Date()
        )
        XCTAssertTrue(identity.isHardwareBacked)
    }

    // MARK: - ZTLPService Tests

    func testServiceEndpoint() {
        let service = ZTLPService(
            id: "test",
            name: "Test",
            hostname: "host.ztlp",
            port: 443,
            protocolType: "https",
            hostNodeId: "abc",
            isReachable: true,
            lastChecked: nil,
            serviceDescription: nil,
            tags: []
        )
        XCTAssertEqual(service.endpoint, "host.ztlp:443")
    }
}
