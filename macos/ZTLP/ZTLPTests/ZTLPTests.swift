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
        XCTAssertEqual(config.serviceName, "beta")
        XCTAssertFalse(config.autoConnect)
        XCTAssertFalse(config.isEnrolled)
        XCTAssertTrue(config.useSecureEnclave)
    }

    func testConfigurationReset() {
        let suiteName = "test.ztlp.\(UUID().uuidString)"
        let config = ZTLPConfiguration(suiteName: suiteName)
        config.relayAddress = "test.relay:4433"
        config.zoneName = "corp.ztlp"
        config.isEnrolled = true
        config.autoConnect = true

        config.reset()

        XCTAssertEqual(config.relayAddress, "")
        XCTAssertEqual(config.zoneName, "")
        XCTAssertFalse(config.isEnrolled)
        XCTAssertFalse(config.autoConnect)
    }

    // MARK: - DaemonSnapshot (Task 6b/6d Home status line)

    func testDaemonSnapshotStatusLineNotEnrolled() {
        var snap = DaemonSnapshot()
        snap.identityEnrolled = false
        snap.caInstalled = true
        snap.dnsConfigured = true
        XCTAssertEqual(snap.statusLine, "Service running — not enrolled yet")
    }

    func testDaemonSnapshotStatusLineHealthy() {
        var snap = DaemonSnapshot()
        snap.identityEnrolled = true
        snap.caInstalled = true
        snap.dnsConfigured = true
        snap.activeTunnels = 0
        XCTAssertEqual(snap.statusLine, "HTTPS trusted · DNS routed")
    }

    func testDaemonSnapshotStatusLineDegradedAndTunnels() {
        var snap = DaemonSnapshot()
        snap.identityEnrolled = true
        snap.caInstalled = false
        snap.dnsConfigured = true
        snap.activeTunnels = 1
        XCTAssertEqual(snap.statusLine, "HTTPS trust missing · DNS routed · 1 active tunnel")
        snap.activeTunnels = 3
        snap.dnsConfigured = false
        XCTAssertEqual(snap.statusLine, "HTTPS trust missing · DNS not routed · 3 active tunnels")
    }

    // MARK: - JSONValue (control-socket response decoding)

    // MARK: - HomeReadiness (Task 8 single-page checklist) — pure, every branch

    private func snap(enrolled: Bool, ca: Bool, dns: Bool, zone: String = "defcon.ztlp", caInit: Bool? = nil) -> DaemonSnapshot {
        var s = DaemonSnapshot()
        s.identityEnrolled = enrolled
        s.caInstalled = ca
        // Default: CA is initialized whenever it is installed (legacy tests).
        s.caInitialized = caInit ?? ca
        s.caRootPemPath = "/Library/Application Support/ZTLP/.ztlp/ca/root.pem"
        s.dnsConfigured = dns
        s.zone = zone
        return s
    }

    func testReadinessFreshMacServiceNotInstalledGatesEverything() {
        let r = HomeReadiness.compute(serviceState: .notRegistered, daemonReachable: false, daemon: nil)
        XCTAssertEqual(r.service.state, .needsAction("Not installed", action: .installService))
        XCTAssertEqual(r.identity.state, .waiting("Waiting for service"))
        XCTAssertEqual(r.network.state, .waiting("Waiting for service"))
        XCTAssertFalse(r.allReady)
        XCTAssertTrue(r.guidance(zone: "").hasPrefix("Step 1"))
    }

    func testReadinessRequiresApprovalOffersLoginItems() {
        let r = HomeReadiness.compute(serviceState: .requiresApproval, daemonReachable: false, daemon: nil)
        XCTAssertEqual(r.service.state, .needsAction("Needs your approval in System Settings", action: .openLoginItems))
        XCTAssertEqual(r.identity.state, .waiting("Waiting for service"))
    }

    func testReadinessRegisteredButNotAnsweringIsWaitingNotEnroll() {
        // B4 user-facing half: the daemon is registered but has not answered
        // yet -> Identity must NOT offer Enroll (that was the old timeout path).
        let r = HomeReadiness.compute(serviceState: .running, daemonReachable: false, daemon: nil)
        XCTAssertEqual(r.service.state, .waiting("Starting…"))
        XCTAssertEqual(r.identity.state, .waiting("Waiting for service"))
        XCTAssertFalse(r.allReady)
    }

    func testReadinessStandbyDaemonOffersEnroll() {
        // Daemon up in unenrolled standby: Service green, Identity = Enroll.
        let r = HomeReadiness.compute(
            serviceState: .running, daemonReachable: true,
            daemon: snap(enrolled: false, ca: false, dns: false, zone: "")
        )
        XCTAssertEqual(r.service.state, .ready("Running"))
        XCTAssertEqual(r.identity.state, .needsAction("Not enrolled", action: .enroll))
        XCTAssertEqual(r.network.state, .waiting("Waiting for enrollment"))
        XCTAssertTrue(r.guidance(zone: "").hasPrefix("Step 2"))
    }

    func testReadinessEnrolledButTlsPendingIsWaiting() {
        let r = HomeReadiness.compute(
            serviceState: .running, daemonReachable: true,
            daemon: snap(enrolled: true, ca: false, dns: true)
        )
        XCTAssertEqual(r.identity.state, .ready("Enrolled in defcon.ztlp"))
        XCTAssertEqual(r.network.state, .waiting("Setting up HTTPS certificate…"))
        XCTAssertFalse(r.allReady)
        XCTAssertTrue(r.guidance(zone: "defcon.ztlp").hasPrefix("Almost there"))
    }

    // Option B (2026-09-20): the daemon makes the CA; the GUI does the ONE
    // human trust step with the standard admin prompt.
    func testReadinessCaMadeButUntrustedOffersTrustHTTPS() {
        let r = HomeReadiness.compute(
            serviceState: .running, daemonReachable: true,
            daemon: snap(enrolled: true, ca: false, dns: true, caInit: true)
        )
        XCTAssertEqual(r.network.state, .needsAction("HTTPS not trusted yet", action: .trustHTTPS))
        XCTAssertTrue(r.guidance(zone: "defcon.ztlp").hasPrefix("Step 3"), r.guidance(zone: "defcon.ztlp"))
        XCTAssertFalse(r.allReady)
    }

    func testReadinessTrustStepNotOfferedBeforeEnrollment() {
        // Never ask for a password before there is anything to trust for.
        let r = HomeReadiness.compute(
            serviceState: .running, daemonReachable: true,
            daemon: snap(enrolled: false, ca: false, dns: false, zone: "", caInit: true)
        )
        XCTAssertEqual(r.identity.state, .needsAction("Not enrolled", action: .enroll))
        XCTAssertEqual(r.network.state, .waiting("Waiting for enrollment"))
    }

    func testTrustShellCommandTargetsSystemKeychainAndQuotesPath() {
        let cmd = TunnelViewModel.trustShellCommand(pemPath: "/Library/Application Support/ZTLP/.ztlp/ca/root.pem")
        XCTAssertEqual(
            cmd,
            "/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '/Library/Application Support/ZTLP/.ztlp/ca/root.pem'"
        )
        // A hostile path cannot break out of the single quotes.
        let evil = TunnelViewModel.trustShellCommand(pemPath: "/tmp/x'; rm -rf / #")
        XCTAssertTrue(evil.hasSuffix("'/tmp/x'\\''; rm -rf / #'"), evil)
    }

    func testReadinessAllGreenGuidanceHasNoConnectVerb() {
        let r = HomeReadiness.compute(
            serviceState: .running, daemonReachable: true,
            daemon: snap(enrolled: true, ca: true, dns: true)
        )
        XCTAssertTrue(r.allReady)
        XCTAssertEqual(r.network.state, .ready("HTTPS trusted · DNS routed"))
        let g = r.guidance(zone: "defcon.ztlp")
        XCTAssertTrue(g.contains("https://<name>.defcon.ztlp"), g)
        XCTAssertTrue(g.contains("on demand"), g)
        // Steven: "There is no connection required until the user goes to a
        // website" — the UI must never ask the user to press Connect.
        XCTAssertFalse(g.lowercased().contains("press connect"), g)
    }

    func testReadinessServiceFailedIsRed() {
        let r = HomeReadiness.compute(serviceState: .failed("boom"), daemonReachable: false, daemon: nil)
        XCTAssertEqual(r.service.state, .failed("boom"))
        let r2 = HomeReadiness.compute(serviceState: .notFound, daemonReachable: false, daemon: nil)
        if case .failed(let m) = r2.service.state { XCTAssertTrue(m.contains("reinstall")) } else { XCTFail("\(r2.service.state)") }
    }

    func testBackoffDoublesAndCapsAtTwoSeconds() {
        XCTAssertEqual(TunnelViewModel.nextBackoffDelay(0.25), 0.5)
        XCTAssertEqual(TunnelViewModel.nextBackoffDelay(0.5), 1.0)
        XCTAssertEqual(TunnelViewModel.nextBackoffDelay(1.0), 2.0)
        XCTAssertEqual(TunnelViewModel.nextBackoffDelay(2.0), 2.0)
        XCTAssertEqual(TunnelViewModel.nextBackoffDelay(5.0), 2.0)
    }

    func testJSONValueDecodesStandbyStatusShape() throws {
        // What the B4 unenrolled-standby daemon answers to "status".
        let json = #"{"ok":true,"data":{"standby":true,"enrolled":false,"identity_enrolled":false,"daemon_running":true,"version":"0.35.11","pid":42}}"#
        let resp = try JSONDecoder().decode(AgentControlResponse.self, from: Data(json.utf8))
        XCTAssertTrue(resp.ok)
        guard case .object(let o)? = resp.data else { return XCTFail("no object") }
        XCTAssertEqual(o["standby"]?.boolValue, true)
        XCTAssertEqual(o["identity_enrolled"]?.boolValue, false)
    }

    func testJSONValueDecodesDaemonStatusShape() throws {
        // Real shape from a live 0.35.10 daemon on MACLLM4 (2026-09-19).
        let raw = #"{"ok":true,"data":{"dns_listen":"127.0.0.55:15353","domain_mappings":0,"ns_server":"44.240.16.59:23096","pid":12940,"uptime_secs":779,"version":"0.35.10","vip_allocated":1,"vip_capacity":65534}}"#
        let resp = try JSONDecoder().decode(AgentControlResponse.self, from: Data(raw.utf8))
        XCTAssertTrue(resp.ok)
        guard case .object(let o)? = resp.data else { return XCTFail("data not an object") }
        XCTAssertEqual(o["version"]?.stringValue, "0.35.10")
        XCTAssertEqual(o["uptime_secs"]?.intValue, 779)
        XCTAssertEqual(o["vip_allocated"]?.intValue, 1)
    }

    func testJSONValueDecodesSetupStatusBools() throws {
        let raw = #"{"ok":true,"data":{"ca_installed_system_trust":true,"dns_configured":false,"identity_enrolled":true,"zone":"defcon.ztlp"}}"#
        let resp = try JSONDecoder().decode(AgentControlResponse.self, from: Data(raw.utf8))
        guard case .object(let o)? = resp.data else { return XCTFail("data not an object") }
        XCTAssertEqual(o["ca_installed_system_trust"]?.boolValue, true)
        XCTAssertEqual(o["dns_configured"]?.boolValue, false)
        XCTAssertEqual(o["zone"]?.stringValue, "defcon.ztlp")
    }

    func testJSONValueDecodesDaemonError() throws {
        let raw = #"{"ok":false,"error":"unauthorized"}"#
        let resp = try JSONDecoder().decode(AgentControlResponse.self, from: Data(raw.utf8))
        XCTAssertFalse(resp.ok)
        XCTAssertEqual(resp.error, "unauthorized")
        XCTAssertNil(resp.data)
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
