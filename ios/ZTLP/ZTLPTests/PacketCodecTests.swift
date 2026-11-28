import XCTest
@testable import ZTLP

final class PacketCodecTests: XCTestCase {
    private let sample = UDPDatagram(
        source: 0x0A00_0001, destination: 0x6440_4D01,
        sourcePort: 50_000, destinationPort: 53,
        payload: Data(NetDiag.dnsQuery("name.example.ztlp"))
    )

    func testBuildThenParseRoundTrips() throws {
        let packet = try XCTUnwrap(PacketCodec.buildIPv4UDP(sample))
        XCTAssertEqual(packet.count, 28 + sample.payload.count)
        XCTAssertEqual(PacketCodec.parseIPv4UDP(packet), sample)
    }

    func testBuiltHeaderChecksumVerifies() throws {
        let packet = try XCTUnwrap(PacketCodec.buildIPv4UDP(sample))
        // Summing a header that includes its own checksum gives zero.
        XCTAssertEqual(PacketCodec.headerChecksum([UInt8](packet.prefix(20))[0..<20]), 0)
    }

    func testParseWorksOnADataSlice() throws {
        let packet = try XCTUnwrap(PacketCodec.buildIPv4UDP(sample))
        var padded = Data([0xff, 0xff, 0xff])
        padded.append(packet)
        XCTAssertEqual(PacketCodec.parseIPv4UDP(padded.dropFirst(3)), sample)
    }

    func testParseRejectsNonUDPTruncatedAndFragments() throws {
        var packet = try XCTUnwrap(PacketCodec.buildIPv4UDP(sample))
        XCTAssertNil(PacketCodec.parseIPv4UDP(packet.prefix(27)))
        XCTAssertNil(PacketCodec.parseIPv4UDP(Data()))
        var tcp = packet; tcp[9] = 6
        XCTAssertNil(PacketCodec.parseIPv4UDP(tcp))
        var v6 = packet; v6[0] = 0x60
        XCTAssertNil(PacketCodec.parseIPv4UDP(v6))
        packet[6] = 0x20 // more fragments
        XCTAssertNil(PacketCodec.parseIPv4UDP(packet))
    }

    func testParseRejectsLengthsBeyondThePacket() throws {
        var packet = try XCTUnwrap(PacketCodec.buildIPv4UDP(sample))
        packet[24] = 0xff; packet[25] = 0xff // UDP length
        XCTAssertNil(PacketCodec.parseIPv4UDP(packet))
    }

    func testDescribe() throws {
        let packet = try XCTUnwrap(PacketCodec.buildIPv4UDP(sample))
        XCTAssertEqual(PacketCodec.describe(packet), "udp 10.0.0.1:50000 > 100.64.77.1:53 len=\(packet.count)")
        XCTAssertEqual(PacketCodec.describe(Data()), "empty")
        XCTAssertEqual(PacketCodec.describe(Data([0x60, 0, 0, 0])), "ipv6 len=4")
    }

    func testDNSQueryShape() {
        let q = NetDiag.dnsQuery("a.bc")
        XCTAssertEqual(q.count, 12 + 1 + 1 + 1 + 2 + 1 + 4)
        XCTAssertEqual(Array(q[12...]), [1, 0x61, 2, 0x62, 0x63, 0, 0, 1, 0, 1])
    }

    func testNamesUnderTheSuffixAreInside() {
        for name in ["app.example.ztlp", "App.Example.ZTLP", "a.ztlp"] {
            XCTAssertEqual(DNSAnswer.classify(query: Data(NetDiag.dnsQuery(name))), .inside, name)
        }
        var aaaa = NetDiag.dnsQuery("app.example.ztlp")
        aaaa[aaaa.count - 3] = 28
        XCTAssertEqual(DNSAnswer.classify(query: Data(aaaa)), .inside)
    }

    func testNamesOutsideTheSuffixGetNoSuchName() {
        for outside in ["example.com", "ztlp.example.com", "_dns.resolver.arpa"] {
            let query = NetDiag.dnsQuery(outside, id: 0x1234)
            guard case .outside(let data) = DNSAnswer.classify(query: Data(query)) else {
                return XCTFail("\(outside) should be outside")
            }
            let answer = [UInt8](data)
            XCTAssertEqual(answer.count, query.count, outside)
            XCTAssertEqual(Array(answer[0..<2]), [0x12, 0x34])
            XCTAssertEqual(answer[2], 0x85, "response, authoritative, recursion-desired copied")
            XCTAssertEqual(answer[3], 0x83, "recursion available, no such name")
            XCTAssertEqual(Array(answer[4..<12]), [0, 1, 0, 0, 0, 0, 0, 0])
            XCTAssertEqual(Array(answer[12...]), Array(query[12...]), "question echoed")
        }
    }

    func testMalformedQueries() {
        XCTAssertEqual(DNSAnswer.classify(query: Data()), .malformed)
        var response = NetDiag.dnsQuery("a.ztlp"); response[2] |= 0x80
        XCTAssertEqual(DNSAnswer.classify(query: Data(response)), .malformed)
        var truncated = NetDiag.dnsQuery("a.ztlp"); truncated.removeLast(3)
        XCTAssertEqual(DNSAnswer.classify(query: Data(truncated)), .malformed)
        var pointer = NetDiag.dnsQuery("a.ztlp"); pointer[12] = 0xc0
        XCTAssertEqual(DNSAnswer.classify(query: Data(pointer)), .malformed)
        var twoQuestions = NetDiag.dnsQuery("a.ztlp"); twoQuestions[5] = 2
        XCTAssertEqual(DNSAnswer.classify(query: Data(twoQuestions)), .malformed)
    }
}
