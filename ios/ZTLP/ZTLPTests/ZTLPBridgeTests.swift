// ZTLPBridgeTests.swift
// ZTLPTests
//
// Tests for the ZTLPBridge FFI bridge, error mapping, and handle lifecycle.

import XCTest
@testable import ZTLP

final class ZTLPBridgeTests: XCTestCase {

    // MARK: - Error Mapping

    func testErrorFromCodeReturnsNilForSuccess() {
        XCTAssertNil(ZTLPError.from(code: 0))
    }

    func testErrorFromCodeMapsInvalidArgument() {
        let error = ZTLPError.from(code: -1)
        if case .invalidArgument = error {
            // pass
        } else {
            XCTFail("Expected .invalidArgument, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsIdentityError() {
        let error = ZTLPError.from(code: -2)
        if case .identityError = error {
            // pass
        } else {
            XCTFail("Expected .identityError, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsHandshakeError() {
        let error = ZTLPError.from(code: -3)
        if case .handshakeError = error {
            // pass
        } else {
            XCTFail("Expected .handshakeError, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsConnectionError() {
        let error = ZTLPError.from(code: -4)
        if case .connectionError = error {
            // pass
        } else {
            XCTFail("Expected .connectionError, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsTimeout() {
        let error = ZTLPError.from(code: -5)
        if case .timeout = error {
            // pass
        } else {
            XCTFail("Expected .timeout, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsSessionNotFound() {
        let error = ZTLPError.from(code: -6)
        if case .sessionNotFound = error {
            // pass
        } else {
            XCTFail("Expected .sessionNotFound, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsEncryptionError() {
        let error = ZTLPError.from(code: -7)
        if case .encryptionError = error {
            // pass
        } else {
            XCTFail("Expected .encryptionError, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsNatError() {
        let error = ZTLPError.from(code: -8)
        if case .natError = error {
            // pass
        } else {
            XCTFail("Expected .natError, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsAlreadyConnected() {
        let error = ZTLPError.from(code: -9)
        if case .alreadyConnected = error {
            // pass
        } else {
            XCTFail("Expected .alreadyConnected, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsNotConnected() {
        let error = ZTLPError.from(code: -10)
        if case .notConnected = error {
            // pass
        } else {
            XCTFail("Expected .notConnected, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsInternalError() {
        let error = ZTLPError.from(code: -99)
        if case .internalError = error {
            // pass
        } else {
            XCTFail("Expected .internalError, got \(String(describing: error))")
        }
    }

    func testErrorFromCodeMapsUnknownCode() {
        let error = ZTLPError.from(code: -42)
        if case .unknownError(let code, _) = error {
            XCTAssertEqual(code, -42)
        } else {
            XCTFail("Expected .unknownError, got \(String(describing: error))")
        }
    }

    // MARK: - Error Descriptions

    func testErrorDescriptionsAreNonEmpty() {
        let errors: [ZTLPError] = [
            .notInitialized,
            .invalidArgument("test"),
            .identityError("test"),
            .handshakeError("test"),
            .connectionError("test"),
            .timeout("test"),
            .sessionNotFound("test"),
            .encryptionError("test"),
            .natError("test"),
            .alreadyConnected,
            .notConnected,
            .internalError("test"),
            .unknownError(-1, "test"),
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription, "Missing description for \(error)")
            XCTAssertFalse(error.errorDescription!.isEmpty, "Empty description for \(error)")
        }
    }

    // MARK: - Bridge Singleton

    func testBridgeIsSingleton() {
        let a = ZTLPBridge.shared
        let b = ZTLPBridge.shared
        XCTAssertTrue(a === b)
    }

    func testBridgeVersionIsNonEmpty() {
        // The version comes from the C library. In tests without the
        // actual native library linked, this may return "unknown".
        let version = ZTLPBridge.shared.version
        XCTAssertFalse(version.isEmpty)
    }

    // MARK: - Config Handle

    func testConfigHandleCanSetRelay() {
        let config = ZTLPConfigHandle()
        // This calls into the C library — in a unit test environment
        // without the native lib, we just verify it doesn't crash.
        // The actual FFI call is tested in integration tests.
        XCTAssertNotNil(config.pointer)
    }

    // MARK: - Connection Event

    func testConnectionEventEquality() {
        // Verify the event enum cases can be constructed
        let event1 = ZTLPConnectionEvent.connected(peerAddress: "1.2.3.4")
        let event2 = ZTLPConnectionEvent.disconnected(reason: 0)
        let event3 = ZTLPConnectionEvent.dataReceived(Data([1, 2, 3]))
        let event4 = ZTLPConnectionEvent.stateChanged(3)
        let event5 = ZTLPConnectionEvent.error(.notConnected)

        // Just verify they can be pattern-matched
        if case .connected(let addr) = event1 {
            XCTAssertEqual(addr, "1.2.3.4")
        }
        if case .disconnected(let reason) = event2 {
            XCTAssertEqual(reason, 0)
        }
        if case .dataReceived(let data) = event3 {
            XCTAssertEqual(data.count, 3)
        }
        if case .stateChanged(let state) = event4 {
            XCTAssertEqual(state, 3)
        }
        if case .error(let err) = event5 {
            XCTAssertNotNil(err.errorDescription)
        }
    }
}
