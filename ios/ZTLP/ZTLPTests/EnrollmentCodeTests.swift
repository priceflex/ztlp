import XCTest
@testable import ZTLP

final class EnrollmentCodeTests: XCTestCase {

    private let token = "ztlp://enroll/AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
    private let query = "ztlp://enroll/?zone=example.ztlp&ns=192.0.2.1:23096&relay=192.0.2.2:23095&token=abcd1234&expires=9999999999"

    func testAcceptsBothCodeForms() {
        XCTAssertEqual(EnrollmentCode.normalize(token), .success(token))
        XCTAssertEqual(EnrollmentCode.normalize(query), .success(query))
    }

    func testStripsWhitespaceAndLineWraps() {
        let wrapped = "  ztlp://enroll/AQIDBAUGBwgJCgsM\n   DQ4PEBESExQVFhcYGRobHB0eHyA \r\n"
        XCTAssertEqual(EnrollmentCode.normalize(wrapped), .success(token))
    }

    func testSchemeIsCaseInsensitiveButPayloadIsKept() {
        XCTAssertEqual(
            EnrollmentCode.normalize("ZTLP://Enroll/AbCdEfGh1234"),
            .success("ztlp://enroll/AbCdEfGh1234")
        )
    }

    func testRejectsEmpty() {
        XCTAssertEqual(EnrollmentCode.normalize(""), .failure(.empty))
        XCTAssertEqual(EnrollmentCode.normalize(" \n\t "), .failure(.empty))
    }

    func testRejectsOtherText() {
        for bad in ["https://example.com/", "hello", "ztlp://connect/abcdefgh",
                    "ztlp:/enroll/abcdefgh", "xztlp://enroll/abcdefgh"] {
            XCTAssertEqual(EnrollmentCode.normalize(bad), .failure(.notAZTLPCode), bad)
        }
    }

    func testRejectsIncompleteCodes() {
        XCTAssertEqual(EnrollmentCode.normalize("ztlp://enroll/"), .failure(.incomplete))
        XCTAssertEqual(EnrollmentCode.normalize("ztlp://enroll/abc"), .failure(.incomplete))
        XCTAssertEqual(EnrollmentCode.normalize("ztlp://enroll/?zone=example.ztlp"), .failure(.incomplete))
    }

    func testEveryProblemHasAMessage() {
        for problem in [EnrollmentCode.Problem.empty, .notAZTLPCode, .incomplete] {
            XCTAssertFalse(problem.message.isEmpty)
        }
    }

    func testIncomingURL() throws {
        let url = try XCTUnwrap(URL(string: token))
        XCTAssertEqual(EnrollmentCode.fromIncomingURL(url), token)
        let queryURL = try XCTUnwrap(URL(string: query))
        XCTAssertEqual(EnrollmentCode.fromIncomingURL(queryURL), query)
        let other = try XCTUnwrap(URL(string: "https://example.com/ztlp://enroll/abcdefgh"))
        XCTAssertNil(EnrollmentCode.fromIncomingURL(other))
        let wrongHost = try XCTUnwrap(URL(string: "ztlp://open/abcdefgh"))
        XCTAssertNil(EnrollmentCode.fromIncomingURL(wrongHost))
    }
}

final class DeviceNameTests: XCTestCase {

    func testTypicalNames() {
        XCTAssertEqual(DeviceName.clean("Steven\u{2019}s iPhone 17 Pro"), "stevens-iphone-17-pro")
        XCTAssertEqual(DeviceName.clean("Steven's iPhone"), "stevens-iphone")
        XCTAssertEqual(DeviceName.clean("iPhone"), "iphone")
        XCTAssertEqual(DeviceName.clean("iPad (2)"), "ipad-2")
    }

    func testCollapsesAndTrimsSeparators() {
        XCTAssertEqual(DeviceName.clean("  --My__Phone!!  "), "my-phone")
        XCTAssertEqual(DeviceName.clean("a...b"), "a-b")
    }

    func testFoldsAccentsAndDropsOtherScripts() {
        XCTAssertEqual(DeviceName.clean("Zoë\u{2019}s Téléphone"), "zoes-telephone")
        XCTAssertEqual(DeviceName.clean("电话"), DeviceName.fallback)
        XCTAssertEqual(DeviceName.clean("📱"), DeviceName.fallback)
    }

    func testEmptyFallsBack() {
        XCTAssertEqual(DeviceName.clean(""), "iphone")
        XCTAssertEqual(DeviceName.clean("---"), "iphone")
    }

    func testLengthLimitAndNoTrailingHyphen() {
        let long = String(repeating: "abcdefghi ", count: 10)
        let cleaned = DeviceName.clean(long)
        XCTAssertLessThanOrEqual(cleaned.count, DeviceName.maxLength)
        XCTAssertFalse(cleaned.hasSuffix("-"))
        XCTAssertFalse(cleaned.hasPrefix("-"))
    }

    func testCleanIsIdempotentAndLabelSafe() {
        for raw in ["Steven\u{2019}s iPhone 17 Pro", "  A  B  ", "x_y.z", "Ünï cödé 9"] {
            let once = DeviceName.clean(raw)
            XCTAssertEqual(DeviceName.clean(once), once)
            XCTAssertTrue(once.unicodeScalars.allSatisfy {
                ($0.value >= 97 && $0.value <= 122) || ($0.value >= 48 && $0.value <= 57) || $0 == "-"
            }, once)
        }
    }
}
