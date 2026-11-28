import XCTest
@testable import ZTLP

final class AddressPlanTests: XCTestCase {

    func testTunnelOwnsOneAddressAndTheDNSServerIsRoutedNotOwned() {
        XCTAssertEqual(AddressPlan.tunnelAddresses, ["100.64.77.2"])
        XCTAssertFalse(AddressPlan.tunnelAddresses.contains(AddressPlan.dnsAddress))
        XCTAssertEqual(AddressPlan.agentAddress, "127.0.0.1")
    }

    func testPlanConstantsMatchTheContract() {
        XCTAssertEqual(AddressPlan.dnsAddress, "100.64.77.1")
        XCTAssertEqual(AddressPlan.agentCIDR, "127.0.0.1/32")
        XCTAssertEqual(AddressPlan.matchDomain, "ztlp")
        XCTAssertEqual(AddressPlan.hostMask, "255.255.255.255")
    }

    func testUsableHostsOtherBlocks() {
        XCTAssertEqual(AddressPlan.usableHosts(cidr: "10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(AddressPlan.usableHosts(cidr: "192.168.1.77/29").first, "192.168.1.73")
        XCTAssertEqual(AddressPlan.usableHosts(cidr: "192.168.1.77/29").count, 6)
        XCTAssertEqual(AddressPlan.usableHosts(cidr: "10.1.2.0/24").count, 254)
    }

    func testUsableHostsRejectsBadInput() {
        for bad in ["", "100.64.77.32", "100.64.77.32/", "100.64.77.32/31", "100.64.77.32/32",
                    "100.64.77.32/7", "100.64.77/27", "100.64.77.256/27", "a.b.c.d/27",
                    "100.64.77.32/27/1", "100.64.77.+3/27", "100.64..32/27"] {
            XCTAssertEqual(AddressPlan.usableHosts(cidr: bad), [], "should reject \(bad)")
        }
    }

    func testIPv4RoundTrip() {
        XCTAssertEqual(AddressPlan.ipv4ToUInt32("100.64.77.1"), 0x6440_4D01)
        XCTAssertEqual(AddressPlan.uint32ToIPv4(0x6440_4D01), "100.64.77.1")
        XCTAssertNil(AddressPlan.ipv4ToUInt32("1.2.3"))
        XCTAssertNil(AddressPlan.ipv4ToUInt32("1.2.3.4.5"))
    }
}
