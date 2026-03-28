// TunnelConfigurationTests.swift
// ZTLPTests
//
// Tests for TunnelConfiguration model — serialization, defaults, and edge cases.

import XCTest
@testable import ZTLP

final class TunnelConfigurationTests: XCTestCase {

    // MARK: - Default Values

    func testDefaultValues() {
        let dict: [String: Any] = ["targetNodeId": "abcdef1234567890"]
        let config = TunnelConfiguration.from(dictionary: dict)

        XCTAssertNotNil(config)
        XCTAssertEqual(config?.targetNodeId, "abcdef1234567890")
        XCTAssertNil(config?.relayAddress)
        XCTAssertEqual(config?.stunServer, "stun.l.google.com:19302")
        XCTAssertEqual(config?.tunnelAddress, "10.0.0.2")
        XCTAssertEqual(config?.tunnelNetmask, "255.255.255.0")
        XCTAssertEqual(config?.dnsServers, ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(config?.mtu, 1400)
        XCTAssertNil(config?.identityPath)
        XCTAssertFalse(config?.fullTunnel ?? true)
    }

    // MARK: - Full Configuration

    func testFullConfiguration() {
        let dict: [String: Any] = [
            "targetNodeId": "deadbeef",
            "relayAddress": "34.219.64.205:23095",
            "stunServer": "stun.custom.com:3478",
            "tunnelAddress": "10.0.1.1",
            "tunnelNetmask": "255.255.0.0",
            "dnsServers": ["9.9.9.9"],
            "mtu": 1300,
            "identityPath": "/tmp/identity.json",
            "fullTunnel": true,
        ]
        let config = TunnelConfiguration.from(dictionary: dict)

        XCTAssertNotNil(config)
        XCTAssertEqual(config?.targetNodeId, "deadbeef")
        XCTAssertEqual(config?.relayAddress, "34.219.64.205:23095")
        XCTAssertEqual(config?.stunServer, "stun.custom.com:3478")
        XCTAssertEqual(config?.tunnelAddress, "10.0.1.1")
        XCTAssertEqual(config?.tunnelNetmask, "255.255.0.0")
        XCTAssertEqual(config?.dnsServers, ["9.9.9.9"])
        XCTAssertEqual(config?.mtu, 1300)
        XCTAssertEqual(config?.identityPath, "/tmp/identity.json")
        XCTAssertTrue(config?.fullTunnel ?? false)
    }

    // MARK: - Missing targetNodeId

    func testMissingTargetNodeIdReturnsNil() {
        let dict: [String: Any] = ["relayAddress": "1.2.3.4:5555"]
        let config = TunnelConfiguration.from(dictionary: dict)
        XCTAssertNil(config)
    }

    func testEmptyDictionaryReturnsNil() {
        let config = TunnelConfiguration.from(dictionary: [:])
        XCTAssertNil(config)
    }

    // MARK: - Serialization Roundtrip

    func testSerializationRoundtrip() {
        let original = TunnelConfiguration(
            targetNodeId: "abcdef",
            relayAddress: "10.0.0.1:23095",
            stunServer: "stun.l.google.com:19302",
            tunnelAddress: "10.0.0.2",
            tunnelNetmask: "255.255.255.0",
            dnsServers: ["1.1.1.1", "8.8.8.8"],
            mtu: 1400,
            identityPath: "/path/to/id.json",
            fullTunnel: false,
            nsServer: "34.217.62.46:23096",
            serviceName: "vault",
            zoneName: "techrockstars.ztlp"
        )

        let dict = original.toDictionary()
        let restored = TunnelConfiguration.from(dictionary: dict)

        XCTAssertNotNil(restored)
        XCTAssertEqual(restored?.targetNodeId, original.targetNodeId)
        XCTAssertEqual(restored?.relayAddress, original.relayAddress)
        XCTAssertEqual(restored?.stunServer, original.stunServer)
        XCTAssertEqual(restored?.tunnelAddress, original.tunnelAddress)
        XCTAssertEqual(restored?.tunnelNetmask, original.tunnelNetmask)
        XCTAssertEqual(restored?.dnsServers, original.dnsServers)
        XCTAssertEqual(restored?.mtu, original.mtu)
        XCTAssertEqual(restored?.identityPath, original.identityPath)
        XCTAssertEqual(restored?.fullTunnel, original.fullTunnel)
        XCTAssertEqual(restored?.nsServer, original.nsServer)
        XCTAssertEqual(restored?.serviceName, original.serviceName)
        XCTAssertEqual(restored?.zoneName, original.zoneName)
    }

    func testSerializationRoundtripWithoutOptionals() {
        let original = TunnelConfiguration(
            targetNodeId: "abcdef",
            relayAddress: nil,
            stunServer: "stun.l.google.com:19302",
            tunnelAddress: "10.0.0.2",
            tunnelNetmask: "255.255.255.0",
            dnsServers: ["1.1.1.1"],
            mtu: 1400,
            identityPath: nil,
            fullTunnel: true,
            nsServer: nil,
            serviceName: nil,
            zoneName: nil
        )

        let dict = original.toDictionary()
        let restored = TunnelConfiguration.from(dictionary: dict)

        XCTAssertNotNil(restored)
        XCTAssertNil(restored?.relayAddress)
        XCTAssertNil(restored?.identityPath)
        XCTAssertTrue(restored?.fullTunnel ?? false)
    }

    // MARK: - Dictionary Keys

    func testToDictionaryContainsExpectedKeys() {
        let config = TunnelConfiguration(
            targetNodeId: "test",
            relayAddress: "1.2.3.4:5",
            stunServer: "stun",
            tunnelAddress: "10.0.0.2",
            tunnelNetmask: "255.255.255.0",
            dnsServers: [],
            mtu: 1400,
            identityPath: "/path",
            fullTunnel: false,
            nsServer: "1.2.3.4:23096",
            serviceName: "web",
            zoneName: "test.ztlp"
        )

        let dict = config.toDictionary()

        XCTAssertNotNil(dict["targetNodeId"])
        XCTAssertNotNil(dict["relayAddress"])
        XCTAssertNotNil(dict["stunServer"])
        XCTAssertNotNil(dict["tunnelAddress"])
        XCTAssertNotNil(dict["tunnelNetmask"])
        XCTAssertNotNil(dict["dnsServers"])
        XCTAssertNotNil(dict["mtu"])
        XCTAssertNotNil(dict["identityPath"])
        XCTAssertNotNil(dict["fullTunnel"])
    }

    func testToDictionaryOmitsNilRelay() {
        let config = TunnelConfiguration(
            targetNodeId: "test",
            relayAddress: nil,
            stunServer: "stun",
            tunnelAddress: "10.0.0.2",
            tunnelNetmask: "255.255.255.0",
            dnsServers: [],
            mtu: 1400,
            identityPath: nil,
            fullTunnel: false,
            nsServer: nil,
            serviceName: nil,
            zoneName: nil
        )

        let dict = config.toDictionary()
        XCTAssertNil(dict["relayAddress"])
        XCTAssertNil(dict["identityPath"])
    }
}
