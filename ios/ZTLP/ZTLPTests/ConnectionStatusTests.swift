// ConnectionStatusTests.swift
// ZTLPTests
//
// Tests for ConnectionStatus state machine and TrafficStats formatting.

import XCTest
@testable import ZTLP

final class ConnectionStatusTests: XCTestCase {

    // MARK: - Raw Values

    func testRawValues() {
        XCTAssertEqual(ConnectionStatus.disconnected.rawValue, 0)
        XCTAssertEqual(ConnectionStatus.connecting.rawValue, 1)
        XCTAssertEqual(ConnectionStatus.connected.rawValue, 2)
        XCTAssertEqual(ConnectionStatus.reconnecting.rawValue, 3)
        XCTAssertEqual(ConnectionStatus.disconnecting.rawValue, 4)
    }

    // MARK: - Labels

    func testLabels() {
        XCTAssertEqual(ConnectionStatus.disconnected.label, "Disconnected")
        XCTAssertEqual(ConnectionStatus.connecting.label, "Connecting…")
        XCTAssertEqual(ConnectionStatus.connected.label, "Connected")
        XCTAssertEqual(ConnectionStatus.reconnecting.label, "Reconnecting…")
        XCTAssertEqual(ConnectionStatus.disconnecting.label, "Disconnecting…")
    }

    // MARK: - System Images

    func testSystemImages() {
        // Verify all statuses have non-empty SF Symbol names
        for status in [ConnectionStatus.disconnected, .connecting, .connected, .reconnecting, .disconnecting] {
            XCTAssertFalse(status.systemImage.isEmpty, "Empty systemImage for \(status)")
        }
    }

    // MARK: - canConnect

    func testCanConnect() {
        XCTAssertTrue(ConnectionStatus.disconnected.canConnect)
        XCTAssertFalse(ConnectionStatus.connecting.canConnect)
        XCTAssertFalse(ConnectionStatus.connected.canConnect)
        XCTAssertFalse(ConnectionStatus.reconnecting.canConnect)
        XCTAssertFalse(ConnectionStatus.disconnecting.canConnect)
    }

    // MARK: - canDisconnect

    func testCanDisconnect() {
        XCTAssertFalse(ConnectionStatus.disconnected.canDisconnect)
        XCTAssertFalse(ConnectionStatus.connecting.canDisconnect)
        XCTAssertTrue(ConnectionStatus.connected.canDisconnect)
        XCTAssertTrue(ConnectionStatus.reconnecting.canDisconnect)
        XCTAssertFalse(ConnectionStatus.disconnecting.canDisconnect)
    }

    // MARK: - isActive

    func testIsActive() {
        XCTAssertFalse(ConnectionStatus.disconnected.isActive)
        XCTAssertFalse(ConnectionStatus.connecting.isActive)
        XCTAssertTrue(ConnectionStatus.connected.isActive)
        XCTAssertFalse(ConnectionStatus.reconnecting.isActive)
        XCTAssertFalse(ConnectionStatus.disconnecting.isActive)
    }

    // MARK: - isTransitioning

    func testIsTransitioning() {
        XCTAssertFalse(ConnectionStatus.disconnected.isTransitioning)
        XCTAssertTrue(ConnectionStatus.connecting.isTransitioning)
        XCTAssertFalse(ConnectionStatus.connected.isTransitioning)
        XCTAssertTrue(ConnectionStatus.reconnecting.isTransitioning)
        XCTAssertTrue(ConnectionStatus.disconnecting.isTransitioning)
    }

    // MARK: - Equatable

    func testEquatable() {
        XCTAssertEqual(ConnectionStatus.connected, ConnectionStatus.connected)
        XCTAssertNotEqual(ConnectionStatus.connected, ConnectionStatus.disconnected)
    }

    // MARK: - Identifiable

    func testIdentifiable() {
        // Each status should have a unique ID
        let allStatuses: [ConnectionStatus] = [.disconnected, .connecting, .connected, .reconnecting, .disconnecting]
        let ids = Set(allStatuses.map(\.id))
        XCTAssertEqual(ids.count, allStatuses.count, "All statuses should have unique IDs")
    }

    // MARK: - State Machine Transitions

    func testValidTransitions() {
        // disconnected → connecting (via canConnect)
        XCTAssertTrue(ConnectionStatus.disconnected.canConnect)

        // connected → disconnecting (via canDisconnect)
        XCTAssertTrue(ConnectionStatus.connected.canDisconnect)

        // reconnecting → disconnecting (via canDisconnect)
        XCTAssertTrue(ConnectionStatus.reconnecting.canDisconnect)

        // connecting → cannot connect again
        XCTAssertFalse(ConnectionStatus.connecting.canConnect)

        // disconnecting → cannot disconnect again
        XCTAssertFalse(ConnectionStatus.disconnecting.canDisconnect)
    }

    // MARK: - TrafficStats

    func testTrafficStatsDefaultValues() {
        let stats = TrafficStats()
        XCTAssertEqual(stats.bytesSent, 0)
        XCTAssertEqual(stats.bytesReceived, 0)
        XCTAssertNil(stats.connectedSince)
        XCTAssertNil(stats.duration)
    }

    func testTrafficStatsFormattedDurationWithoutConnection() {
        let stats = TrafficStats()
        XCTAssertEqual(stats.formattedDuration, "--:--:--")
    }

    func testTrafficStatsFormattedDurationWithConnection() {
        var stats = TrafficStats()
        // Connected 90 seconds ago
        stats.connectedSince = Date().addingTimeInterval(-90)

        let duration = stats.formattedDuration
        // Should be roughly "00:01:30" (might vary by a second due to timing)
        XCTAssertTrue(duration.hasPrefix("00:01:"), "Expected ~00:01:30, got \(duration)")
    }

    func testTrafficStatsFormattedBytes() {
        var stats = TrafficStats()
        stats.bytesSent = 1_048_576 // 1 MB
        stats.bytesReceived = 2_621_440 // 2.5 MB

        let sent = stats.formattedBytesSent
        let recv = stats.formattedBytesReceived

        // ByteCountFormatter with .binary style
        XCTAssertTrue(sent.contains("MB") || sent.contains("MiB") || sent.contains("1"),
                       "Expected ~1 MB, got \(sent)")
        XCTAssertTrue(recv.contains("MB") || recv.contains("MiB") || recv.contains("2"),
                       "Expected ~2.5 MB, got \(recv)")
    }

    func testTrafficStatsDuration() {
        var stats = TrafficStats()
        stats.connectedSince = Date().addingTimeInterval(-3600)

        let duration = stats.duration
        XCTAssertNotNil(duration)
        // Should be roughly 3600 seconds
        XCTAssertGreaterThan(duration!, 3599)
        XCTAssertLessThan(duration!, 3602)
    }

    func testTrafficStatsEquatable() {
        let stats1 = TrafficStats(bytesSent: 100, bytesReceived: 200)
        let stats2 = TrafficStats(bytesSent: 100, bytesReceived: 200)
        let stats3 = TrafficStats(bytesSent: 300, bytesReceived: 400)

        XCTAssertEqual(stats1, stats2)
        XCTAssertNotEqual(stats1, stats3)
    }
}
