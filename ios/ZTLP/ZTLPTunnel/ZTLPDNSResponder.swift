// ZTLPDNSResponder.swift
// ZTLPTunnel (Network Extension)
//
// Lightweight DNS responder for the ZTLP tunnel.
// Intercepts DNS A-record queries for *.ztlp names arriving on the utun
// interface and synthesizes responses mapping hostnames to VIP addresses.
//
// Does NOT use tokio, Foundation networking, or any heavy frameworks.
// Operates purely on raw UDP/IP packet bytes.
//
// DNS wire format (RFC 1035):
//   Header: 12 bytes (ID, flags, counts)
//   Question: QNAME + QTYPE(2) + QCLASS(2)
//   Answer: NAME(ptr) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4 for A)

import Foundation

/// A lightweight DNS responder for *.ztlp domain queries.
/// Thread-safe: all state is set at init time and read-only thereafter.
final class ZTLPDNSResponder {

    /// Service name -> VIP address mapping.
    private var serviceMap: [String: String] = [:]

    /// The zone suffix (e.g., "techrockstars" so "vault.techrockstars.ztlp" resolves).
    private var zoneName: String = ""

    /// The DNS server address we intercept (the utun IP).
    let dnsServerIP: String = "10.122.0.1"

    /// TTL for DNS responses (seconds).
    private let responseTTL: UInt32 = 300

    /// Initialize with service-to-VIP mappings and zone name.
    /// - Parameters:
    ///   - services: Array of (serviceName, vipAddress) pairs
    ///   - zoneName: The zone name (e.g., "techrockstars")
    init(services: [(name: String, vip: String)], zoneName: String) {
        self.zoneName = zoneName.lowercased()
        for svc in services {
            // Register with zone: "vault.techrockstars.ztlp" -> VIP
            let fqdn: String
            if self.zoneName.isEmpty {
                fqdn = "\(svc.name.lowercased()).ztlp"
            } else {
                fqdn = "\(svc.name.lowercased()).\(self.zoneName).ztlp"
            }
            serviceMap[fqdn] = svc.vip

            // Also register short form: "vault.ztlp" -> VIP (fallback)
            serviceMap["\(svc.name.lowercased()).ztlp"] = svc.vip
        }
    }

    /// Check if a raw IPv4 packet is a DNS query we should handle.
    /// Returns true if it's a UDP packet to our DNS server IP on port 53.
    func isDNSQuery(_ packet: Data) -> Bool {
        guard packet.count >= 28 else { return false }  // min: 20 IP + 8 UDP

        return packet.withUnsafeBytes { ptr in
            let bytes = ptr.bindMemory(to: UInt8.self)

            // Check IPv4
            let version = bytes[0] >> 4
            guard version == 4 else { return false }

            // Check protocol = UDP (17)
            guard bytes[9] == 17 else { return false }

            // IP header length
            let ihl = Int(bytes[0] & 0x0F) * 4
            guard packet.count >= ihl + 8 else { return false }

            // Check destination port = 53
            let dstPort = UInt16(bytes[ihl + 2]) << 8 | UInt16(bytes[ihl + 3])
            guard dstPort == 53 else { return false }

            // Check destination IP = our DNS server
            let dstIP = "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])"
            return dstIP == dnsServerIP
        }
    }

    /// Try to handle a DNS query packet. Returns a response packet if we can
    /// answer it, or nil if it's not a *.ztlp query (pass through to real DNS).
    func handleQuery(_ packet: Data) -> Data? {
        guard packet.count >= 28 else { return nil }

        return packet.withUnsafeBytes { ptr -> Data? in
            let bytes = ptr.bindMemory(to: UInt8.self)
            let ihl = Int(bytes[0] & 0x0F) * 4
            let udpOffset = ihl
            let dnsOffset = udpOffset + 8  // UDP header is 8 bytes

            guard packet.count >= dnsOffset + 12 else { return nil }

            // Parse DNS header
            let txnID = UInt16(bytes[dnsOffset]) << 8 | UInt16(bytes[dnsOffset + 1])
            let flags = UInt16(bytes[dnsOffset + 2]) << 8 | UInt16(bytes[dnsOffset + 3])
            let qdCount = UInt16(bytes[dnsOffset + 4]) << 8 | UInt16(bytes[dnsOffset + 5])

            // Must be a standard query (QR=0, Opcode=0), with exactly 1 question
            guard flags & 0x8000 == 0 else { return nil }  // QR bit must be 0 (query)
            guard qdCount == 1 else { return nil }

            // Parse the question name
            var nameOffset = dnsOffset + 12
            var nameParts: [String] = []
            // Debug: track parsing for logging
            var debugNameParts: [String] = []

            while nameOffset < packet.count {
                let labelLen = Int(bytes[nameOffset])
                if labelLen == 0 {
                    nameOffset += 1
                    break
                }
                guard nameOffset + 1 + labelLen <= packet.count else { return nil }

                var label = ""
                for i in 0..<labelLen {
                    label.append(Character(UnicodeScalar(bytes[nameOffset + 1 + i])))
                }
                nameParts.append(label.lowercased())
                nameOffset += 1 + labelLen
            }

            // Check QTYPE and QCLASS
            guard nameOffset + 4 <= packet.count else { return nil }
            let qtype = UInt16(bytes[nameOffset]) << 8 | UInt16(bytes[nameOffset + 1])
            let qclass = UInt16(bytes[nameOffset + 2]) << 8 | UInt16(bytes[nameOffset + 3])

            // Build the FQDN first (need it for .ztlp check)
            let fqdn = nameParts.joined(separator: ".")

            // Log the query details
            TunnelLogger.shared.debug("DNS: qname=\(fqdn) qtype=\(qtype) qclass=\(qclass)", source: "DNS")

            // Must end in .ztlp — pass through non-.ztlp queries to real DNS
            guard fqdn.hasSuffix(".ztlp") else {
                TunnelLogger.shared.debug("DNS: pass-through — not .ztlp suffix", source: "DNS")
                return nil
            }

            // For AAAA (type 28) queries on .ztlp domains, return NXDOMAIN
            // immediately so iOS doesn't wait/retry for IPv6 addresses
            guard qtype == 1 && qclass == 1 else {
                TunnelLogger.shared.debug("DNS: NXDOMAIN for non-A query type=\(qtype)", source: "DNS")
                return buildNXDomainResponse(
                    originalPacket: packet,
                    ihl: ihl,
                    txnID: txnID,
                    questionEnd: nameOffset + 4
                )
            }

            // Look up the VIP for A record queries
            guard let vip = serviceMap[fqdn] else {
                TunnelLogger.shared.debug("DNS: NXDOMAIN for \(fqdn) (not in map: \(Array(serviceMap.keys)))", source: "DNS")
                // Unknown .ztlp name — return NXDOMAIN
                return buildNXDomainResponse(
                    originalPacket: packet,
                    ihl: ihl,
                    txnID: txnID,
                    questionEnd: nameOffset + 4
                )
            }

            // Build A record response
            return buildARecordResponse(
                originalPacket: packet,
                ihl: ihl,
                txnID: txnID,
                questionEnd: nameOffset + 4,
                vip: vip
            )
        }
    }

    // MARK: - Response Builders

    /// Build a DNS A record response packet (full IPv4/UDP/DNS).
    private func buildARecordResponse(
        originalPacket: Data,
        ihl: Int,
        txnID: UInt16,
        questionEnd: Int,
        vip: String
    ) -> Data {
        // Parse the VIP into 4 bytes
        let vipParts = vip.split(separator: ".").compactMap { UInt8($0) }
        guard vipParts.count == 4 else { return Data() }

        return originalPacket.withUnsafeBytes { ptr -> Data in
            let bytes = ptr.bindMemory(to: UInt8.self)
            let udpOffset = ihl
            let dnsOffset = udpOffset + 8

            // DNS question section (copy from original)
            let questionSection = Data(bytes: UnsafeRawPointer(bytes.baseAddress! + dnsOffset + 12),
                                       count: questionEnd - (dnsOffset + 12))

            // Build DNS response
            var dns = Data(capacity: 64)

            // Header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
            dns.append(UInt8(txnID >> 8))
            dns.append(UInt8(txnID & 0xFF))
            // Flags: QR=1, AA=1, RD=1, RA=1 = 0x8580
            dns.append(0x85)
            dns.append(0x80)
            // QDCOUNT = 1
            dns.append(0x00); dns.append(0x01)
            // ANCOUNT = 1
            dns.append(0x00); dns.append(0x01)
            // NSCOUNT = 0
            dns.append(0x00); dns.append(0x00)
            // ARCOUNT = 0
            dns.append(0x00); dns.append(0x00)

            // Question section (copied from query)
            dns.append(questionSection)

            // Answer section: name pointer + A record
            // Name: pointer to offset 12 in DNS message (0xC00C)
            dns.append(0xC0); dns.append(0x0C)
            // TYPE A = 1
            dns.append(0x00); dns.append(0x01)
            // CLASS IN = 1
            dns.append(0x00); dns.append(0x01)
            // TTL
            dns.append(UInt8(responseTTL >> 24 & 0xFF))
            dns.append(UInt8(responseTTL >> 16 & 0xFF))
            dns.append(UInt8(responseTTL >> 8 & 0xFF))
            dns.append(UInt8(responseTTL & 0xFF))
            // RDLENGTH = 4
            dns.append(0x00); dns.append(0x04)
            // RDATA = VIP address
            dns.append(vipParts[0])
            dns.append(vipParts[1])
            dns.append(vipParts[2])
            dns.append(vipParts[3])

            // Now wrap in UDP and IP
            return buildIPv4UDPPacket(
                originalPacket: originalPacket,
                ihl: ihl,
                dnsPayload: dns
            )
        }
    }

    /// Build an NXDOMAIN response for unknown .ztlp names.
    private func buildNXDomainResponse(
        originalPacket: Data,
        ihl: Int,
        txnID: UInt16,
        questionEnd: Int
    ) -> Data {
        return originalPacket.withUnsafeBytes { ptr -> Data in
            let bytes = ptr.bindMemory(to: UInt8.self)
            let dnsOffset = ihl + 8

            let questionSection = Data(bytes: UnsafeRawPointer(bytes.baseAddress! + dnsOffset + 12),
                                       count: questionEnd - (dnsOffset + 12))

            var dns = Data(capacity: 32)
            dns.append(UInt8(txnID >> 8))
            dns.append(UInt8(txnID & 0xFF))
            // Flags: QR=1, AA=1, RCODE=3 (NXDOMAIN) = 0x8583
            dns.append(0x85)
            dns.append(0x83)
            dns.append(0x00); dns.append(0x01)  // QDCOUNT
            dns.append(0x00); dns.append(0x00)  // ANCOUNT
            dns.append(0x00); dns.append(0x00)  // NSCOUNT
            dns.append(0x00); dns.append(0x00)  // ARCOUNT
            dns.append(questionSection)

            return buildIPv4UDPPacket(
                originalPacket: originalPacket,
                ihl: ihl,
                dnsPayload: dns
            )
        }
    }

    /// Build a complete IPv4/UDP packet with the DNS payload.
    /// Swaps src/dst IP and ports from the original query.
    private func buildIPv4UDPPacket(
        originalPacket: Data,
        ihl: Int,
        dnsPayload: Data
    ) -> Data {
        return originalPacket.withUnsafeBytes { ptr -> Data in
            let bytes = ptr.bindMemory(to: UInt8.self)

            let udpLen = 8 + dnsPayload.count
            let totalLen = ihl + udpLen

            var packet = Data(capacity: totalLen)

            // IPv4 header (copy from original, modify)
            var ipHeader = Data(bytes: UnsafeRawPointer(bytes.baseAddress!), count: ihl)

            // Total length
            ipHeader[2] = UInt8(totalLen >> 8)
            ipHeader[3] = UInt8(totalLen & 0xFF)

            // Protocol = UDP
            ipHeader[9] = 17

            // Swap src/dst IP
            let origSrcIP = Data(bytes: UnsafeRawPointer(bytes.baseAddress! + 12), count: 4)
            let origDstIP = Data(bytes: UnsafeRawPointer(bytes.baseAddress! + 16), count: 4)
            ipHeader.replaceSubrange(12..<16, with: origDstIP)  // new src = old dst
            ipHeader.replaceSubrange(16..<20, with: origSrcIP)  // new dst = old src

            // Recompute IP checksum
            ipHeader[10] = 0
            ipHeader[11] = 0
            let checksum = ipChecksum(ipHeader)
            ipHeader[10] = UInt8(checksum >> 8)
            ipHeader[11] = UInt8(checksum & 0xFF)

            packet.append(ipHeader)

            // UDP header
            let origSrcPort = UInt16(bytes[ihl]) << 8 | UInt16(bytes[ihl + 1])
            let origDstPort = UInt16(bytes[ihl + 2]) << 8 | UInt16(bytes[ihl + 3])

            // Swap ports
            packet.append(UInt8(origDstPort >> 8))   // src port = old dst port (53)
            packet.append(UInt8(origDstPort & 0xFF))
            packet.append(UInt8(origSrcPort >> 8))   // dst port = old src port
            packet.append(UInt8(origSrcPort & 0xFF))
            // UDP length
            packet.append(UInt8(udpLen >> 8))
            packet.append(UInt8(udpLen & 0xFF))
            // UDP checksum = 0 (optional for IPv4)
            packet.append(0x00)
            packet.append(0x00)

            // DNS payload
            packet.append(dnsPayload)

            return packet
        }
    }

    /// Compute IPv4 header checksum (ones' complement sum of 16-bit words).
    private func ipChecksum(_ header: Data) -> UInt16 {
        var sum: UInt32 = 0
        header.withUnsafeBytes { ptr in
            let bytes = ptr.bindMemory(to: UInt8.self)
            for i in stride(from: 0, to: header.count - 1, by: 2) {
                sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            }
            if header.count % 2 != 0 {
                sum += UInt32(bytes[header.count - 1]) << 8
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }
}
