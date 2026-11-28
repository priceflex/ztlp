import XCTest
@testable import ZTLP

final class ReadinessTests: XCTestCase {

    private func running(_ lastError: String = "") -> AgentStatus {
        var status = AgentStatus()
        status.running = true
        status.enrolled = true
        status.lastError = lastError
        return status
    }

    func testNotEnrolled() {
        let r = Readiness.compute(enrolled: false, zone: "", tunnel: .unknown, agent: nil, trust: .unknown)
        XCTAssertEqual(r.enrolled.kind, .needsAction)
        XCTAssertEqual(r.enrolled.action, .enroll)
        XCTAssertEqual(r.tunnel.kind, .waiting)
        XCTAssertNil(r.tunnel.action)
        XCTAssertEqual(r.https.kind, .waiting)
        XCTAssertFalse(r.allReady)
    }

    func testNotEnrolledIgnoresStaleTunnelState() {
        let r = Readiness.compute(enrolled: false, zone: "", tunnel: .connected, agent: running(), trust: .trusted)
        XCTAssertFalse(r.tunnel.isReady)
        XCTAssertFalse(r.https.isReady)
    }

    func testEnrolledNeedsVPNPermission() {
        let r = Readiness.compute(enrolled: true, zone: "example.ztlp", tunnel: .notConfigured, agent: nil, trust: .unknown)
        XCTAssertTrue(r.enrolled.isReady)
        XCTAssertEqual(r.enrolled.status, "example.ztlp")
        XCTAssertEqual(r.tunnel.kind, .needsAction)
        XCTAssertEqual(r.tunnel.action, .setUpTunnel)
        XCTAssertEqual(r.https.kind, .waiting)
    }

    func testConnectingAndConnectedWithoutAgentAreWaiting() {
        for (phase, agent) in [(TunnelPhase.connecting, nil), (.connected, nil), (.connected, AgentStatus())]
            as [(TunnelPhase, AgentStatus?)] {
            let r = Readiness.compute(enrolled: true, zone: "", tunnel: phase, agent: agent, trust: .trusted)
            XCTAssertEqual(r.tunnel.kind, .waiting)
            XCTAssertFalse(r.https.isReady, "HTTPS cannot be green before the tunnel is")
        }
    }

    func testConnectedButAgentReportsError() {
        var status = AgentStatus()
        status.lastError = "port 53 is in use"
        let r = Readiness.compute(enrolled: true, zone: "", tunnel: .connected, agent: status, trust: .unknown)
        XCTAssertEqual(r.tunnel.kind, .failed)
        XCTAssertEqual(r.tunnel.hint, "port 53 is in use")
    }

    func testDisconnectedWithAndWithoutReason() {
        let withReason = Readiness.compute(
            enrolled: true, zone: "", tunnel: .disconnected(reason: "This device is not enrolled."),
            agent: nil, trust: .unknown
        )
        XCTAssertEqual(withReason.tunnel.kind, .failed)
        XCTAssertEqual(withReason.tunnel.hint, "This device is not enrolled.")
        XCTAssertEqual(withReason.tunnel.action, .setUpTunnel)

        let without = Readiness.compute(
            enrolled: true, zone: "", tunnel: .disconnected(reason: nil), agent: nil, trust: .unknown
        )
        XCTAssertEqual(without.tunnel.kind, .needsAction)
        XCTAssertEqual(without.tunnel.action, .setUpTunnel)
    }

    func testTrustStates() {
        func https(_ trust: TrustState) -> ReadinessRow {
            Readiness.compute(enrolled: true, zone: "example.ztlp", tunnel: .connected, agent: running(), trust: trust).https
        }
        XCTAssertEqual(https(.unknown).kind, .waiting)
        XCTAssertEqual(https(.notTrusted).kind, .needsAction)
        XCTAssertEqual(https(.notTrusted).action, .installCertificate)
        XCTAssertEqual(https(.unreachable).action, .installCertificate)
        XCTAssertEqual(https(.trusted).kind, .ready)
    }

    func testAllReady() {
        let r = Readiness.compute(enrolled: true, zone: "example.ztlp", tunnel: .connected, agent: running(), trust: .trusted)
        XCTAssertTrue(r.allReady)
        XCTAssertEqual(r.rows.map(\.title), ["Enrolled", "Tunnel running", "HTTPS trusted"])
        XCTAssertTrue(r.rows.allSatisfy { $0.hint == nil && $0.action == nil })
    }

    func testEveryRowThatIsNotGreenHasAHint() {
        let phases: [TunnelPhase] = [.unknown, .notConfigured, .connecting, .connected,
                                     .disconnected(reason: nil), .disconnected(reason: "x")]
        let trusts: [TrustState] = [.unknown, .trusted, .notTrusted, .unreachable]
        for enrolled in [false, true] {
            for phase in phases {
                for agent in [nil, AgentStatus(), running()] as [AgentStatus?] {
                    for trust in trusts {
                        let r = Readiness.compute(enrolled: enrolled, zone: "", tunnel: phase, agent: agent, trust: trust)
                        for row in r.rows where !row.isReady {
                            XCTAssertFalse((row.hint ?? "").isEmpty, "\(row.id) \(phase) \(trust)")
                        }
                    }
                }
            }
        }
    }

    func testGuidance() {
        XCTAssertEqual(
            Readiness.guidance(zone: "example.ztlp"),
            "Open any https://name.example.ztlp in Safari. There is nothing to switch on."
        )
        XCTAssertTrue(Readiness.guidance(zone: "").contains("https://name.zone.ztlp"))
    }
}

final class AgentStatusTests: XCTestCase {

    func testDecodesContractJSON() throws {
        let json = #"{"running":true,"enrolled":true,"node_name":"phone","zone":"example.ztlp","vips":3,"tunnels":2,"ca_ready":true,"last_error":""}"#
        let status = try XCTUnwrap(AgentStatus.decode(Data(json.utf8)))
        XCTAssertTrue(status.running)
        XCTAssertTrue(status.enrolled)
        XCTAssertEqual(status.nodeName, "phone")
        XCTAssertEqual(status.zone, "example.ztlp")
        XCTAssertEqual(status.vips, 3)
        XCTAssertEqual(status.tunnels, 2)
        XCTAssertTrue(status.caReady)
        XCTAssertEqual(status.lastError, "")
    }

    func testMissingAndExtraFieldsAreTolerated() throws {
        let status = try XCTUnwrap(AgentStatus.decode(Data(#"{"running":true,"future_field":[1,2]}"#.utf8)))
        XCTAssertTrue(status.running)
        XCTAssertFalse(status.enrolled)
        XCTAssertEqual(status.zone, "")
    }

    func testGarbageIsNil() {
        XCTAssertNil(AgentStatus.decode(Data()))
        XCTAssertNil(AgentStatus.decode(Data("not json".utf8)))
        XCTAssertNil(AgentStatus.decode(Data("[1,2,3]".utf8)))
    }
}
