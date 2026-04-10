// ZTLPNSClient.swift
// ZTLPTunnel (Network Extension)
//
// Sync ZTLP Name Service client for the Network Extension.
// Queries the NS server via UDP for service records (SVC type).
// Pure BSD sockets — no tokio, no Foundation networking.
//
// Wire format (ZTLP-NS protocol):
//   Query:  [opcode=0x01] [name_len: u16 BE] [name: bytes] [type: u8]
//   Response opcode 0x02 = FOUND, 0x03 = NOT_FOUND
//   Record: [type: u8] [name_len: u16 BE] [name] [data_len: u32 BE] [data: CBOR]
//   CBOR data for SVC (type 0x02): map with "address" key = "ip:port"
//   CBOR data for KEY (type 0x01): map with "node_id" key = hex string

import Foundation

/// Result of an NS service resolution.
struct NSServiceRecord {
    let name: String        // e.g., "vault.techrockstars.ztlp"
    let address: String     // e.g., "44.246.33.34:8200"
    let nodeId: String?     // Optional peer node ID (hex)
}

/// Sync ZTLP-NS client using BSD sockets.
final class ZTLPNSClient {

    /// Query timeout in seconds.
    private let timeoutSec: Int

    init(timeoutSec: Int = 3) {
        self.timeoutSec = timeoutSec
    }

    /// Resolve a service name via the NS server.
    /// - Parameters:
    ///   - name: The service name (e.g., "vault.techrockstars.ztlp")
    ///   - nsServer: The NS server address ("ip:port")
    /// - Returns: NSServiceRecord on success, nil on failure.
    func resolve(name: String, nsServer: String) -> NSServiceRecord? {
        guard let (host, port) = parseHostPort(nsServer) else { return nil }

        // First query: SVC record (type 0x02) for the address
        let svcQuery = buildQuery(name: name, recordType: 0x02)
        guard let svcResponse = sendUDP(data: svcQuery, host: host, port: port) else {
            return nil
        }
        guard let address = parseResponse(svcResponse, expectedType: 0x02, key: "address") else {
            return nil
        }

        // Optional second query: KEY record (type 0x01) for the node_id
        let keyQuery = buildQuery(name: name, recordType: 0x01)
        var nodeId: String? = nil
        if let keyResponse = sendUDP(data: keyQuery, host: host, port: port) {
            nodeId = parseResponse(keyResponse, expectedType: 0x01, key: "node_id")
        }

        return NSServiceRecord(name: name, address: address, nodeId: nodeId)
    }

    /// Discover all known services for a zone by querying common service names.
    /// - Parameters:
    ///   - zoneName: The zone (e.g., "techrockstars")
    ///   - nsServer: The NS server address
    ///   - serviceNames: Names to try (defaults to common services)
    /// - Returns: Array of resolved service records.
    func discoverServices(
        zoneName: String,
        nsServer: String,
        serviceNames: [String] = ["vault", "http", "web", "ssh", "rdp"]
    ) -> [NSServiceRecord] {
        var results: [NSServiceRecord] = []

        for svc in serviceNames {
            // Try zone-qualified name first
            let fqdn = zoneName.isEmpty ? "\(svc).ztlp" : "\(svc).\(zoneName).ztlp"
            if let record = resolve(name: fqdn, nsServer: nsServer) {
                results.append(record)
                continue
            }

            // Try short name
            if let record = resolve(name: "\(svc).ztlp", nsServer: nsServer) {
                results.append(record)
            }
        }

        return results
    }

    // MARK: - Query Builder

    /// Build an NS query packet.
    /// Format: [0x01] [name_len: u16 BE] [name: bytes] [type: u8]
    private func buildQuery(name: String, recordType: UInt8) -> Data {
        let nameBytes = Array(name.utf8)
        let nameLen = UInt16(nameBytes.count)

        var data = Data(capacity: 1 + 2 + nameBytes.count + 1)
        data.append(0x01)  // opcode: query by name
        data.append(UInt8(nameLen >> 8))
        data.append(UInt8(nameLen & 0xFF))
        data.append(contentsOf: nameBytes)
        data.append(recordType)

        return data
    }

    // MARK: - Response Parser

    /// Parse an NS response and extract a string value from the CBOR data.
    /// - Parameters:
    ///   - data: Raw response bytes
    ///   - expectedType: Expected record type (0x01 KEY, 0x02 SVC)
    ///   - key: CBOR map key to extract ("address" or "node_id")
    /// - Returns: The extracted string value, or nil.
    private func parseResponse(_ data: Data, expectedType: UInt8, key: String) -> String? {
        guard data.count >= 2 else { return nil }

        return data.withUnsafeBytes { ptr -> String? in
            let bytes = ptr.bindMemory(to: UInt8.self)
            var offset = 0

            // Response opcode
            let opcode = bytes[offset]
            offset += 1

            guard opcode == 0x02 else { return nil }  // 0x02 = FOUND

            // Optional truncation flag
            if offset < data.count && bytes[offset] == 0x01 {
                offset += 1
            }

            // Record type
            guard offset < data.count else { return nil }
            let recordType = bytes[offset]
            offset += 1
            guard recordType == expectedType else { return nil }

            // Name (length-prefixed)
            guard offset + 2 <= data.count else { return nil }
            let nameLen = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
            offset += 2
            guard offset + nameLen <= data.count else { return nil }
            offset += nameLen  // skip the name

            // Data length (4 bytes BE)
            guard offset + 4 <= data.count else { return nil }
            let dataLen = Int(bytes[offset]) << 24
                | Int(bytes[offset + 1]) << 16
                | Int(bytes[offset + 2]) << 8
                | Int(bytes[offset + 3])
            offset += 4

            guard offset + dataLen <= data.count else { return nil }

            // Parse CBOR map to find the key
            let cborData = Data(bytes: UnsafeRawPointer(bytes.baseAddress! + offset),
                                count: dataLen)
            return extractCBORString(from: cborData, key: key)
        }
    }

    // MARK: - CBOR Parser (minimal)

    /// Extract a string value from a CBOR map by key name.
    /// Handles: major type 5 (map), major type 3 (text string).
    private func extractCBORString(from data: Data, key: String) -> String? {
        guard !data.isEmpty else { return nil }

        return data.withUnsafeBytes { ptr -> String? in
            let bytes = ptr.bindMemory(to: UInt8.self)
            var offset = 0

            // Must start with a map (major type 5)
            let majorType = bytes[offset] >> 5
            guard majorType == 5 else { return nil }

            let mapCount = cborReadCount(bytes: bytes.baseAddress!, offset: &offset, count: data.count)
            guard mapCount > 0 else { return nil }

            for _ in 0..<mapCount {
                // Read key (text string, major type 3)
                guard offset < data.count else { return nil }
                let keyMajor = bytes[offset] >> 5
                guard keyMajor == 3 else {
                    // Skip unknown key type
                    cborSkipValue(bytes: bytes.baseAddress!, offset: &offset, count: data.count)
                    cborSkipValue(bytes: bytes.baseAddress!, offset: &offset, count: data.count)
                    continue
                }

                let keyLen = cborReadCount(bytes: bytes.baseAddress!, offset: &offset, count: data.count)
                guard offset + keyLen <= data.count else { return nil }

                let mapKey = String(bytes: Array(UnsafeBufferPointer(
                    start: bytes.baseAddress! + offset,
                    count: keyLen
                )), encoding: .utf8) ?? ""
                offset += keyLen

                // Read value
                if mapKey == key {
                    // Expect text string value (major type 3)
                    guard offset < data.count else { return nil }
                    let valMajor = bytes[offset] >> 5
                    guard valMajor == 3 else { return nil }

                    let valLen = cborReadCount(bytes: bytes.baseAddress!, offset: &offset, count: data.count)
                    guard offset + valLen <= data.count else { return nil }

                    let value = String(bytes: Array(UnsafeBufferPointer(
                        start: bytes.baseAddress! + offset,
                        count: valLen
                    )), encoding: .utf8)
                    return value
                } else {
                    // Skip this value
                    cborSkipValue(bytes: bytes.baseAddress!, offset: &offset, count: data.count)
                }
            }
            return nil
        }
    }

    /// Read the count/length from a CBOR item's initial byte(s) and advance offset.
    private func cborReadCount(bytes: UnsafePointer<UInt8>, offset: inout Int, count: Int) -> Int {
        guard offset < count else { return 0 }
        let additional = Int(bytes[offset] & 0x1F)
        offset += 1

        if additional < 24 {
            return additional
        } else if additional == 24 {
            guard offset < count else { return 0 }
            let val = Int(bytes[offset])
            offset += 1
            return val
        } else if additional == 25 {
            guard offset + 2 <= count else { return 0 }
            let val = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
            offset += 2
            return val
        } else if additional == 26 {
            guard offset + 4 <= count else { return 0 }
            let val = Int(bytes[offset]) << 24 | Int(bytes[offset + 1]) << 16
                | Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            offset += 4
            return val
        }
        return 0
    }

    /// Skip a CBOR value (used when we don't care about a map entry).
    private func cborSkipValue(bytes: UnsafePointer<UInt8>, offset: inout Int, count: Int) {
        guard offset < count else { return }
        let major = bytes[offset] >> 5
        let len = cborReadCount(bytes: bytes, offset: &offset, count: count)

        switch major {
        case 0, 1: break  // unsigned/negative int, count is the value
        case 2, 3: offset += len  // byte string / text string
        case 4:  // array
            for _ in 0..<len { cborSkipValue(bytes: bytes, offset: &offset, count: count) }
        case 5:  // map
            for _ in 0..<len {
                cborSkipValue(bytes: bytes, offset: &offset, count: count)
                cborSkipValue(bytes: bytes, offset: &offset, count: count)
            }
        default: break
        }
    }

    // MARK: - UDP Transport

    /// Send a UDP datagram and receive the response (blocking, with timeout).
    private func sendUDP(data: Data, host: String, port: UInt16) -> Data? {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else { return nil }
        defer { close(sock) }

        // Set timeout
        var tv = timeval(tv_sec: timeoutSec, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Build destination address
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        host.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }

        // Send
        let sendResult = data.withUnsafeBytes { ptr -> Int in
            withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(sock,
                           ptr.baseAddress,
                           data.count,
                           0,
                           sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sendResult > 0 else { return nil }

        // Receive
        var buf = [UInt8](repeating: 0, count: 4096)
        let recvLen = recv(sock, &buf, buf.count, 0)
        guard recvLen > 0 else { return nil }

        return Data(buf[0..<recvLen])
    }

    // MARK: - Helpers

    private func parseHostPort(_ address: String) -> (String, UInt16)? {
        let parts = address.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else { return nil }
        return (String(parts[0]), port)
    }
}
