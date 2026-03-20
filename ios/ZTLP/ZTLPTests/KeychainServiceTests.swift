// KeychainServiceTests.swift
// ZTLPTests
//
// Tests for KeychainService CRUD operations.
// These tests use a unique access group to avoid polluting the real keychain.

import XCTest
@testable import ZTLP

final class KeychainServiceTests: XCTestCase {

    /// Use a test-specific access group to isolate tests.
    private var keychainService: KeychainService!

    override func setUp() {
        super.setUp()
        keychainService = KeychainService(accessGroup: "group.com.ztlp.test")
        // Clean up any stale test data
        try? keychainService.deleteIdentity()
        try? keychainService.delete(forKey: "test-key")
    }

    override func tearDown() {
        try? keychainService.deleteIdentity()
        try? keychainService.delete(forKey: "test-key")
        keychainService = nil
        super.tearDown()
    }

    // MARK: - Identity CRUD

    func testSaveAndLoadIdentity() throws {
        let testData = Data("test-identity-json-data".utf8)
        try keychainService.saveIdentity(testData, label: "Test Identity")

        let loaded = try keychainService.loadIdentity()
        XCTAssertEqual(loaded, testData)
    }

    func testHasIdentityReturnsTrueAfterSave() throws {
        let testData = Data("test-identity".utf8)
        try keychainService.saveIdentity(testData)

        XCTAssertTrue(keychainService.hasIdentity())
    }

    func testHasIdentityReturnsFalseInitially() {
        XCTAssertFalse(keychainService.hasIdentity())
    }

    func testDeleteIdentity() throws {
        let testData = Data("test-identity".utf8)
        try keychainService.saveIdentity(testData)
        XCTAssertTrue(keychainService.hasIdentity())

        try keychainService.deleteIdentity()
        XCTAssertFalse(keychainService.hasIdentity())
    }

    func testLoadIdentityThrowsNotFoundWhenEmpty() {
        XCTAssertThrowsError(try keychainService.loadIdentity()) { error in
            if case KeychainError.notFound = error {
                // expected
            } else {
                XCTFail("Expected KeychainError.notFound, got \(error)")
            }
        }
    }

    func testSaveOverwritesExisting() throws {
        let data1 = Data("first-identity".utf8)
        let data2 = Data("second-identity".utf8)

        try keychainService.saveIdentity(data1)
        try keychainService.saveIdentity(data2)

        let loaded = try keychainService.loadIdentity()
        XCTAssertEqual(loaded, data2)
    }

    // MARK: - Generic Key-Value CRUD

    func testSaveAndLoadForKey() throws {
        let testData = Data("test-value-data".utf8)
        try keychainService.save(data: testData, forKey: "test-key")

        let loaded = try keychainService.load(forKey: "test-key")
        XCTAssertEqual(loaded, testData)
    }

    func testDeleteForKey() throws {
        let testData = Data("test-value".utf8)
        try keychainService.save(data: testData, forKey: "test-key")

        try keychainService.delete(forKey: "test-key")

        XCTAssertThrowsError(try keychainService.load(forKey: "test-key")) { error in
            if case KeychainError.notFound = error {
                // expected
            } else {
                XCTFail("Expected KeychainError.notFound, got \(error)")
            }
        }
    }

    func testLoadForKeyThrowsNotFoundWhenMissing() {
        XCTAssertThrowsError(try keychainService.load(forKey: "nonexistent")) { error in
            if case KeychainError.notFound = error {
                // expected
            } else {
                XCTFail("Expected KeychainError.notFound, got \(error)")
            }
        }
    }

    func testDeleteForKeyDoesNotThrowWhenMissing() {
        XCTAssertNoThrow(try keychainService.delete(forKey: "nonexistent"))
    }

    func testDeleteIdentityDoesNotThrowWhenMissing() {
        XCTAssertNoThrow(try keychainService.deleteIdentity())
    }

    // MARK: - Error Descriptions

    func testKeychainErrorDescriptions() {
        let errors: [KeychainError] = [
            .saveFailed(errSecDuplicateItem),
            .readFailed(errSecItemNotFound),
            .deleteFailed(errSecAuthFailed),
            .notFound,
            .unexpectedData,
            .accessControlCreationFailed,
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription, "Missing description for \(error)")
            XCTAssertFalse(error.errorDescription!.isEmpty, "Empty description for \(error)")
        }
    }

    // MARK: - Large Data

    func testSaveAndLoadLargeData() throws {
        // Simulate a large identity JSON (~10KB)
        let largeData = Data(repeating: 0xAB, count: 10240)
        try keychainService.save(data: largeData, forKey: "test-key")

        let loaded = try keychainService.load(forKey: "test-key")
        XCTAssertEqual(loaded, largeData)
    }

    // MARK: - Empty Data

    func testSaveAndLoadEmptyData() throws {
        let emptyData = Data()
        try keychainService.save(data: emptyData, forKey: "test-key")

        let loaded = try keychainService.load(forKey: "test-key")
        XCTAssertEqual(loaded, emptyData)
    }
}
