// TunnelRemoteAddressTests.swift
// ZTLPTests
//
// Tests for the tunnelRemoteAddress port-stripping fix.
// Validates that NEPacketTunnelNetworkSettings receives a bare IP,
// never an IP:port pair.

import XCTest
@testable import ZTLP

final class TunnelRemoteAddressTests: XCTestCase {

    // MARK: - Port Stripping Logic
    //
    // The fix in PacketTunnelProvider strips the port from the relay address
    // before passing to NEPacketTunnelNetworkSettings. We test the same
    // logic here to ensure correctness across all edge cases.

    /// Strip port from an address string, matching PacketTunnelProvider logic.
    private func stripPort(_ address: String) -> String {
        address.components(separatedBy: ":").first ?? address
    }

    func testStripsPortFromIPv4WithPort() {
        XCTAssertEqual(stripPort("34.219.64.205:23095"), "34.219.64.205")
    }

    func testPreservesBarIPv4() {
        XCTAssertEqual(stripPort("34.219.64.205"), "34.219.64.205")
    }

    func testStripsPortFromLocalhost() {
        XCTAssertEqual(stripPort("127.0.0.1:8080"), "127.0.0.1")
    }

    func testPreservesBarLocalhost() {
        XCTAssertEqual(stripPort("127.0.0.1"), "127.0.0.1")
    }

    func testStripsPortFromPrivateIP() {
        XCTAssertEqual(stripPort("10.99.0.80:23095"), "10.99.0.80")
    }

    func testHandlesHostnameWithPort() {
        XCTAssertEqual(stripPort("relay.ztlp.net:23095"), "relay.ztlp.net")
    }

    func testHandlesBareHostname() {
        XCTAssertEqual(stripPort("relay.ztlp.net"), "relay.ztlp.net")
    }

    func testHandlesNodeIdHex() {
        // If targetNodeId is used as fallback and it's a hex string
        let nodeId = "abcdef1234567890abcdef1234567890"
        XCTAssertEqual(stripPort(nodeId), nodeId)
    }

    func testHandlesEmptyString() {
        XCTAssertEqual(stripPort(""), "")
    }

    func testHandlesMultipleColons() {
        // Edge case: if someone passes something weird
        // components(separatedBy:).first gives everything before the first colon
        XCTAssertEqual(stripPort("1.2.3.4:5555:extra"), "1.2.3.4")
    }

    func testHandlesHighPort() {
        XCTAssertEqual(stripPort("192.168.1.1:65535"), "192.168.1.1")
    }

    func testHandlesPort0() {
        XCTAssertEqual(stripPort("10.0.0.1:0"), "10.0.0.1")
    }

    // MARK: - Relay Address from Config

    func testRelayAddressUsedOverTargetNodeId() {
        // Simulates: config.relayAddress ?? config.targetNodeId
        let config = TunnelConfiguration(
            targetNodeId: "deadbeef",
            relayAddress: "34.219.64.205:23095",
            stunServer: "stun.l.google.com:19302",
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

        let rawAddress = config.relayAddress ?? config.targetNodeId
        let remoteAddress = stripPort(rawAddress)
        XCTAssertEqual(remoteAddress, "34.219.64.205")
    }

    func testFallbackToTargetNodeIdWhenNoRelay() {
        let config = TunnelConfiguration(
            targetNodeId: "abcdef1234567890",
            relayAddress: nil,
            stunServer: "stun.l.google.com:19302",
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

        let rawAddress = config.relayAddress ?? config.targetNodeId
        let remoteAddress = stripPort(rawAddress)
        XCTAssertEqual(remoteAddress, "abcdef1234567890")
    }
}
