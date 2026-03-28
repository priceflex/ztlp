// TunnelLoggerTests.swift
// ZTLPTests
//
// Tests for TunnelLogger: format, severity, parsing, rotation.

import XCTest
@testable import ZTLP

final class TunnelLoggerTests: XCTestCase {

    // MARK: - LogLevel

    func testLogLevelOrdering() {
        XCTAssertTrue(LogLevel.debug < LogLevel.info)
        XCTAssertTrue(LogLevel.info < LogLevel.warn)
        XCTAssertTrue(LogLevel.warn < LogLevel.error)
        XCTAssertFalse(LogLevel.error < LogLevel.debug)
    }

    func testLogLevelRawValues() {
        XCTAssertEqual(LogLevel.debug.rawValue, "DEBUG")
        XCTAssertEqual(LogLevel.info.rawValue, "INFO")
        XCTAssertEqual(LogLevel.warn.rawValue, "WARN")
        XCTAssertEqual(LogLevel.error.rawValue, "ERROR")
    }

    func testLogLevelCaseIterable() {
        XCTAssertEqual(LogLevel.allCases.count, 4)
    }

    func testLogLevelCodable() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for level in LogLevel.allCases {
            let data = try encoder.encode(level)
            let decoded = try decoder.decode(LogLevel.self, from: data)
            XCTAssertEqual(decoded, level)
        }
    }

    func testLogLevelComparable() {
        let levels: [LogLevel] = [.error, .debug, .warn, .info]
        let sorted = levels.sorted()
        XCTAssertEqual(sorted, [.debug, .info, .warn, .error])
    }

    // MARK: - LogEntry

    func testLogEntryIdentifiable() {
        let entry1 = LogEntry(id: UUID(), timestamp: Date(), level: .info, source: "App", message: "test1")
        let entry2 = LogEntry(id: UUID(), timestamp: Date(), level: .info, source: "App", message: "test2")
        XCTAssertNotEqual(entry1.id, entry2.id)
    }

    func testLogEntryEquatable() {
        let id = UUID()
        let date = Date()
        let entry1 = LogEntry(id: id, timestamp: date, level: .info, source: "App", message: "test")
        let entry2 = LogEntry(id: id, timestamp: date, level: .info, source: "App", message: "test")
        XCTAssertEqual(entry1, entry2)
    }

    func testLogEntryNotEqualDifferentLevel() {
        let id = UUID()
        let date = Date()
        let entry1 = LogEntry(id: id, timestamp: date, level: .info, source: "App", message: "test")
        let entry2 = LogEntry(id: id, timestamp: date, level: .error, source: "App", message: "test")
        XCTAssertNotEqual(entry1, entry2)
    }

    // MARK: - Logger Singleton

    func testLoggerIsSingleton() {
        let a = TunnelLogger.shared
        let b = TunnelLogger.shared
        XCTAssertTrue(a === b)
    }

    // MARK: - Logger Operations (No-Crash Tests)

    func testLogAtAllLevels() {
        // These should not crash, even in a test environment without an app group
        TunnelLogger.shared.debug("test debug", source: "Test")
        TunnelLogger.shared.info("test info", source: "Test")
        TunnelLogger.shared.warn("test warn", source: "Test")
        TunnelLogger.shared.error("test error", source: "Test")
    }

    func testLogWithDefaultSource() {
        // Default source is "App"
        TunnelLogger.shared.log("test message")
    }

    func testClearDoesNotCrash() {
        TunnelLogger.shared.clear()
    }

    func testReadAllReturnsArray() {
        let entries = TunnelLogger.shared.readAll()
        // In test environment, may return empty array (no app group)
        XCTAssertNotNil(entries)
    }

    func testExportDataReturnsData() {
        let data = TunnelLogger.shared.exportData()
        XCTAssertNotNil(data)
    }

    // MARK: - Logger Notification

    func testLogPostsNotification() {
        let expectation = expectation(forNotification: TunnelLogger.didLog, object: nil)
        expectation.assertForOverFulfill = false

        TunnelLogger.shared.info("notification test", source: "Test")

        waitForExpectations(timeout: 2)
    }

    func testLogNotificationContainsEntry() {
        let expectation = expectation(forNotification: TunnelLogger.didLog, object: nil) { notification in
            if let entry = notification.object as? LogEntry {
                return entry.message == "entry test" && entry.source == "Test"
            }
            return false
        }

        TunnelLogger.shared.info("entry test", source: "Test")

        waitForExpectations(timeout: 2)
    }
}
