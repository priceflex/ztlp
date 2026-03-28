// BenchmarkResultTests.swift
// ZTLPTests
//
// Tests for BenchmarkResult formatting and summary generation.

import XCTest
@testable import ZTLP

final class BenchmarkResultTests: XCTestCase {

    // MARK: - Summary Formatting

    func testBasicSummary() {
        let result = BenchmarkResult(
            name: "Test Bench",
            iterations: 100,
            totalMs: 500,
            avgMs: 5.0,
            minMs: 3.0,
            maxMs: 8.0,
            opsPerSec: nil,
            throughputMBps: nil,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("Test Bench"))
        XCTAssertTrue(summary.contains("avg=5.000ms"))
        XCTAssertTrue(summary.contains("min=3.000ms"))
        XCTAssertTrue(summary.contains("max=8.000ms"))
        XCTAssertTrue(summary.contains("100 iterations"))
    }

    func testSummaryWithOpsPerSec() {
        let result = BenchmarkResult(
            name: "Fast Op",
            iterations: 10000,
            totalMs: 100,
            avgMs: 0.01,
            minMs: 0.005,
            maxMs: 0.02,
            opsPerSec: 100_000,
            throughputMBps: nil,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("100.0K ops/sec"))
    }

    func testSummaryWithMillionOps() {
        let result = BenchmarkResult(
            name: "Very Fast",
            iterations: 1000000,
            totalMs: 1000,
            avgMs: 0.001,
            minMs: 0.0005,
            maxMs: 0.002,
            opsPerSec: 1_500_000,
            throughputMBps: nil,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("1.50M ops/sec"))
    }

    func testSummaryWithThroughput() {
        let result = BenchmarkResult(
            name: "Data Copy",
            iterations: 5000,
            totalMs: 250,
            avgMs: 0.05,
            minMs: 0.03,
            maxMs: 0.1,
            opsPerSec: 20000,
            throughputMBps: 953.7,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("MB/s"))
    }

    func testSummaryWithExtraInfo() {
        let result = BenchmarkResult(
            name: "Memory",
            iterations: 1,
            totalMs: 0,
            avgMs: 0,
            minMs: 0,
            maxMs: 0,
            opsPerSec: nil,
            throughputMBps: nil,
            extraInfo: "42.5 MB resident"
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("42.5 MB resident"))
    }

    func testSummaryWithAllFields() {
        let result = BenchmarkResult(
            name: "Full Test",
            iterations: 500,
            totalMs: 1000,
            avgMs: 2.0,
            minMs: 1.5,
            maxMs: 3.0,
            opsPerSec: 500,
            throughputMBps: 12.5,
            extraInfo: "with encryption"
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("Full Test"))
        XCTAssertTrue(summary.contains("ops/sec"))
        XCTAssertTrue(summary.contains("MB/s"))
        XCTAssertTrue(summary.contains("with encryption"))
    }

    // MARK: - Identifiable

    func testResultsHaveUniqueIds() {
        let r1 = BenchmarkResult(name: "A", iterations: 1, totalMs: 1, avgMs: 1, minMs: 1, maxMs: 1, opsPerSec: nil, throughputMBps: nil, extraInfo: nil)
        let r2 = BenchmarkResult(name: "A", iterations: 1, totalMs: 1, avgMs: 1, minMs: 1, maxMs: 1, opsPerSec: nil, throughputMBps: nil, extraInfo: nil)
        XCTAssertNotEqual(r1.id, r2.id)
    }

    // MARK: - Edge Cases

    func testZeroIterations() {
        let result = BenchmarkResult(
            name: "Empty",
            iterations: 0,
            totalMs: 0,
            avgMs: 0,
            minMs: 0,
            maxMs: 0,
            opsPerSec: nil,
            throughputMBps: nil,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("0 iterations"))
    }

    func testSubMicrosecondTiming() {
        let result = BenchmarkResult(
            name: "Nanosecond Op",
            iterations: 1000000,
            totalMs: 10,
            avgMs: 0.00001,
            minMs: 0.000005,
            maxMs: 0.00002,
            opsPerSec: 100_000_000,
            throughputMBps: nil,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertFalse(summary.isEmpty)
    }

    func testLowOpsFormatting() {
        let result = BenchmarkResult(
            name: "Slow Op",
            iterations: 5,
            totalMs: 50000,
            avgMs: 10000,
            minMs: 8000,
            maxMs: 12000,
            opsPerSec: 0.1,
            throughputMBps: nil,
            extraInfo: nil
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("ops/sec"))
    }
}
