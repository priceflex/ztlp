// PacketCodec.swift
// Shared by the app and the packet tunnel extension.
//
// Just enough IPv4/UDP to (a) describe a packet that turned up on the tunnel
// interface and (b) answer a DNS query that iOS delivered as a packet instead
// of to the agent's socket. No allocation beyond the packet itself.

import Foundation

struct UDPDatagram: Equatable {
    var source: UInt32
    var destination: UInt32
    var sourcePort: UInt16
    var destinationPort: UInt16
    var payload: Data
}

enum PacketCodec {
    static let protocolTCP: UInt8 = 6
    static let protocolUDP: UInt8 = 17

    /// An unfragmented IPv4 UDP packet, or nil for anything else.
    static func parseIPv4UDP(_ packet: Data) -> UDPDatagram? {
        let p = [UInt8](packet.prefix(60 + 8))
        guard p.count >= 28, p[0] >> 4 == 4 else { return nil }
        let headerLength = Int(p[0] & 0x0f) * 4
        guard headerLength >= 20, p.count >= headerLength + 8, p[9] == protocolUDP else { return nil }
        // More-fragments flag or a fragment offset: not handled.
        guard (UInt16(p[6]) << 8 | UInt16(p[7])) & 0x3fff == 0 else { return nil }
        let totalLength = Int(p[2]) << 8 | Int(p[3])
        guard totalLength >= headerLength + 8, totalLength <= packet.count else { return nil }
        let udpLength = Int(p[headerLength + 4]) << 8 | Int(p[headerLength + 5])
        guard udpLength >= 8, headerLength + udpLength <= totalLength else { return nil }
        let start = packet.startIndex + headerLength + 8
        let end = packet.startIndex + headerLength + udpLength
        return UDPDatagram(
            source: word(p, 12),
            destination: word(p, 16),
            sourcePort: UInt16(p[headerLength]) << 8 | UInt16(p[headerLength + 1]),
            destinationPort: UInt16(p[headerLength + 2]) << 8 | UInt16(p[headerLength + 3]),
            payload: packet.subdata(in: start..<end)
        )
    }

    /// An IPv4 UDP packet. The UDP checksum is left at zero, which IPv4
    /// allows. Returns nil if the payload does not fit one packet.
    static func buildIPv4UDP(_ d: UDPDatagram) -> Data? {
        let total = 20 + 8 + d.payload.count
        guard total <= 65_535 else { return nil }
        var h = [UInt8](repeating: 0, count: 28)
        h[0] = 0x45
        h[2] = UInt8(total >> 8); h[3] = UInt8(total & 0xff)
        h[8] = 64
        h[9] = protocolUDP
        put(&h, 12, d.source)
        put(&h, 16, d.destination)
        let sum = headerChecksum(h[0..<20])
        h[10] = UInt8(sum >> 8); h[11] = UInt8(sum & 0xff)
        h[20] = UInt8(d.sourcePort >> 8); h[21] = UInt8(d.sourcePort & 0xff)
        h[22] = UInt8(d.destinationPort >> 8); h[23] = UInt8(d.destinationPort & 0xff)
        let udpLength = 8 + d.payload.count
        h[24] = UInt8(udpLength >> 8); h[25] = UInt8(udpLength & 0xff)
        var out = Data(h)
        out.append(d.payload)
        return out
    }

    /// One short line for the log: "udp 10.0.0.1:5000 > 10.0.0.2:53 len=60".
    static func describe(_ packet: Data) -> String {
        let p = [UInt8](packet.prefix(60 + 20))
        guard let first = p.first else { return "empty" }
        guard first >> 4 == 4 else { return "ipv\(first >> 4) len=\(packet.count)" }
        guard p.count >= 20 else { return "ipv4 short len=\(packet.count)" }
        let headerLength = Int(first & 0x0f) * 4
        let src = AddressPlan.uint32ToIPv4(word(p, 12))
        let dst = AddressPlan.uint32ToIPv4(word(p, 16))
        let proto = p[9]
        guard proto == protocolTCP || proto == protocolUDP, p.count >= headerLength + 4 else {
            return "proto=\(proto) \(src) > \(dst) len=\(packet.count)"
        }
        let sport = Int(p[headerLength]) << 8 | Int(p[headerLength + 1])
        let dport = Int(p[headerLength + 2]) << 8 | Int(p[headerLength + 3])
        var flags = ""
        if proto == protocolTCP, p.count > headerLength + 13 {
            let f = p[headerLength + 13]
            flags = " flags=" + (f & 0x02 != 0 ? "S" : "") + (f & 0x10 != 0 ? "A" : "")
                + (f & 0x01 != 0 ? "F" : "") + (f & 0x04 != 0 ? "R" : "")
        }
        return "\(proto == protocolTCP ? "tcp" : "udp") \(src):\(sport) > \(dst):\(dport) len=\(packet.count)\(flags)"
    }

    static func headerChecksum(_ header: ArraySlice<UInt8>) -> UInt16 {
        var sum: UInt32 = 0
        var i = header.startIndex
        while i + 1 < header.endIndex {
            sum += UInt32(header[i]) << 8 | UInt32(header[i + 1])
            i += 2
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    private static func word(_ p: [UInt8], _ at: Int) -> UInt32 {
        UInt32(p[at]) << 24 | UInt32(p[at + 1]) << 16 | UInt32(p[at + 2]) << 8 | UInt32(p[at + 3])
    }

    private static func put(_ p: inout [UInt8], _ at: Int, _ v: UInt32) {
        p[at] = UInt8(v >> 24); p[at + 1] = UInt8((v >> 16) & 0xff)
        p[at + 2] = UInt8((v >> 8) & 0xff); p[at + 3] = UInt8(v & 0xff)
    }
}

/// First look at a DNS query that iOS delivered as a packet.
enum DNSAnswer {
    enum Verdict: Equatable {
        /// A well-formed one-question query for a name under the suffix.
        case inside
        /// A well-formed query for any other name, with the complete "no
        /// such name" response to send back.
        case outside(Data)
        case malformed
    }

    static func classify(query: Data, suffix: String = AddressPlan.matchDomain) -> Verdict {
        let q = [UInt8](query.prefix(512))
        guard q.count >= 17, q[2] & 0x80 == 0, q[4] == 0, q[5] == 1 else { return .malformed }
        var at = 12
        var lastLabel: [UInt8] = []
        while true {
            guard at < q.count else { return .malformed }
            let length = Int(q[at])
            if length == 0 { at += 1; break }
            guard length <= 63, at + 1 + length <= q.count else { return .malformed } // also rejects compression
            lastLabel = Array(q[(at + 1)..<(at + 1 + length)])
            at += 1 + length
        }
        guard at + 4 <= q.count else { return .malformed }
        if String(decoding: lastLabel, as: UTF8.self).lowercased() == suffix { return .inside }
        // Response, authoritative, recursion flags, rcode 3; question echoed.
        var r: [UInt8] = [q[0], q[1], 0x84 | (q[2] & 0x01), 0x83, 0, 1, 0, 0, 0, 0, 0, 0]
        r.append(contentsOf: q[12..<(at + 4)])
        return .outside(Data(r))
    }
}
