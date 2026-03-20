// EnrollmentViewModelTests.swift
// ZTLPTests
//
// Tests for the enrollment URI parsing and state machine.

import XCTest
@testable import ZTLP

@MainActor
final class EnrollmentViewModelTests: XCTestCase {

    private var configuration: ZTLPConfiguration!
    private var viewModel: EnrollmentViewModel!

    override func setUp() {
        super.setUp()
        configuration = ZTLPConfiguration(suiteName: "group.com.ztlp.test.\(UUID().uuidString)")
        viewModel = EnrollmentViewModel(configuration: configuration)
    }

    override func tearDown() {
        viewModel = nil
        configuration = nil
        super.tearDown()
    }

    // MARK: - Initial State

    func testInitialStateIsIdle() {
        XCTAssertEqual(viewModel.state, .idle)
    }

    // MARK: - Scanning State

    func testStartScanningTransitionsToScanning() {
        viewModel.startScanning()
        XCTAssertEqual(viewModel.state, .scanning)
    }

    func testCancelScanningTransitionsToIdle() {
        viewModel.startScanning()
        viewModel.cancelScanning()
        XCTAssertEqual(viewModel.state, .idle)
    }

    // MARK: - Query-Param URI Parsing

    func testParseQueryParamURI() {
        let uri = "ztlp://enroll/?zone=testzone&ns=10.0.0.1:23096&relay=relay.ztlp.net:4433&expires=\(Int(Date().timeIntervalSince1970 + 3600))"

        viewModel.handleScannedCode(uri)

        if case .tokenParsed(let info) = viewModel.state {
            XCTAssertEqual(info.zone, "testzone")
            XCTAssertEqual(info.nsAddress, "10.0.0.1:23096")
            XCTAssertEqual(info.relayAddresses, ["relay.ztlp.net:4433"])
            XCTAssertFalse(info.isExpired)
        } else {
            XCTFail("Expected .tokenParsed, got \(viewModel.state)")
        }
    }

    func testParseQueryParamURIWithMultipleRelays() {
        let uri = "ztlp://enroll/?zone=multizone&ns=10.0.0.1:23096&relay=relay1.ztlp.net:4433,relay2.ztlp.net:4433"

        viewModel.handleScannedCode(uri)

        if case .tokenParsed(let info) = viewModel.state {
            XCTAssertEqual(info.zone, "multizone")
            XCTAssertEqual(info.relayAddresses.count, 2)
            XCTAssertEqual(info.relayAddresses[0], "relay1.ztlp.net:4433")
            XCTAssertEqual(info.relayAddresses[1], "relay2.ztlp.net:4433")
        } else {
            XCTFail("Expected .tokenParsed, got \(viewModel.state)")
        }
    }

    func testParseQueryParamURIWithGateway() {
        let uri = "ztlp://enroll/?zone=gwzone&ns=10.0.0.1:23096&gateway=gw.ztlp.net:443"

        viewModel.handleScannedCode(uri)

        if case .tokenParsed(let info) = viewModel.state {
            XCTAssertEqual(info.gatewayAddress, "gw.ztlp.net:443")
        } else {
            XCTFail("Expected .tokenParsed, got \(viewModel.state)")
        }
    }

    func testParseQueryParamURIWithMaxUses() {
        let uri = "ztlp://enroll/?zone=limited&ns=10.0.0.1:23096&max_uses=5"

        viewModel.handleScannedCode(uri)

        if case .tokenParsed(let info) = viewModel.state {
            XCTAssertEqual(info.maxUses, 5)
        } else {
            XCTFail("Expected .tokenParsed, got \(viewModel.state)")
        }
    }

    // MARK: - Expired Tokens

    func testExpiredTokenIsRejected() {
        let pastTimestamp = Int(Date().timeIntervalSince1970 - 3600)
        let uri = "ztlp://enroll/?zone=expired&ns=10.0.0.1:23096&expires=\(pastTimestamp)"

        viewModel.handleScannedCode(uri)

        if case .error(let msg) = viewModel.state {
            XCTAssertTrue(msg.lowercased().contains("expired"), "Error should mention expiry: \(msg)")
        } else {
            XCTFail("Expected .error for expired token, got \(viewModel.state)")
        }
    }

    // MARK: - Invalid URIs

    func testInvalidSchemeIsRejected() {
        viewModel.handleScannedCode("https://example.com/enroll/")

        if case .error = viewModel.state {
            // expected
        } else {
            XCTFail("Expected .error for invalid scheme, got \(viewModel.state)")
        }
    }

    func testEmptyStringIsRejected() {
        viewModel.handleScannedCode("")

        if case .error = viewModel.state {
            // expected
        } else {
            XCTFail("Expected .error for empty string, got \(viewModel.state)")
        }
    }

    func testMissingZoneIsRejected() {
        viewModel.handleScannedCode("ztlp://enroll/?ns=10.0.0.1:23096")

        if case .error = viewModel.state {
            // expected
        } else {
            XCTFail("Expected .error for missing zone, got \(viewModel.state)")
        }
    }

    func testMissingNsIsRejected() {
        viewModel.handleScannedCode("ztlp://enroll/?zone=test")

        if case .error = viewModel.state {
            // expected
        } else {
            XCTFail("Expected .error for missing ns, got \(viewModel.state)")
        }
    }

    // MARK: - Manual Entry

    func testManualEntryTrimsWhitespace() {
        let uri = "  ztlp://enroll/?zone=manual&ns=10.0.0.1:23096  \n"

        viewModel.handleManualEntry(uri)

        if case .tokenParsed(let info) = viewModel.state {
            XCTAssertEqual(info.zone, "manual")
        } else {
            XCTFail("Expected .tokenParsed, got \(viewModel.state)")
        }
    }

    // MARK: - Reset

    func testResetReturnsToIdle() {
        viewModel.handleScannedCode("ztlp://enroll/?zone=test&ns=10.0.0.1:23096")
        XCTAssertNotEqual(viewModel.state, .idle)

        viewModel.reset()
        XCTAssertEqual(viewModel.state, .idle)
    }

    // MARK: - Token Info Properties

    func testTokenInfoExpiryDescription() {
        let future = Date().addingTimeInterval(3600)
        let info = EnrollmentTokenInfo(
            zone: "test",
            nsAddress: "10.0.0.1:23096",
            relayAddresses: [],
            gatewayAddress: nil,
            expiresAt: future,
            maxUses: 0,
            rawURI: "ztlp://enroll/test"
        )

        XCTAssertFalse(info.isExpired)
        XCTAssertTrue(info.expiryDescription.contains("Expires"))
    }

    func testExpiredTokenInfoExpiryDescription() {
        let past = Date().addingTimeInterval(-3600)
        let info = EnrollmentTokenInfo(
            zone: "test",
            nsAddress: "10.0.0.1:23096",
            relayAddresses: [],
            gatewayAddress: nil,
            expiresAt: past,
            maxUses: 0,
            rawURI: "ztlp://enroll/test"
        )

        XCTAssertTrue(info.isExpired)
        XCTAssertEqual(info.expiryDescription, "Expired")
    }
}
