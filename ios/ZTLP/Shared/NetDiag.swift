// NetDiag.swift
// Shared by the app and the packet tunnel extension.
//
// Small blocking network probes used to find out, on a real device, which
// paths iOS allows between an app and the agent inside the extension. Every
// probe returns one short line of text. Call them off the main thread.

import Foundation
import Network

enum NetDiag {
    /// Name used for lookups. Any reply at all (even "no such name") proves
    /// the resolver was reached.
    static let probeName = "ztlp-health.ztlp"
    /// UDP echo port the extension opens on loopback for the cross-process test.
    static let loopbackEchoPort: UInt16 = 15_355

    /// IPv4 addresses on loopback and tunnel interfaces.
    static func interfaces() -> String {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return "getifaddrs failed errno=\(errno)" }
        defer { freeifaddrs(head) }
        var byName: [String: [String]] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let name = String(cString: ifa.pointee.ifa_name)
            guard name.hasPrefix("utun") || name.hasPrefix("lo") || name.hasPrefix("ipsec") else { continue }
            let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            byName[name, default: []].append(AddressPlan.uint32ToIPv4(UInt32(bigEndian: addr)))
        }
        if byName.isEmpty { return "no loopback or tunnel addresses" }
        return byName.keys.sorted().map { name in
            let list = byName[name] ?? []
            let shown = list.count > 4 ? list.prefix(3).joined(separator: ",") + ",… (\(list.count) total)" : list.joined(separator: ",")
            return "\(name)=[\(shown)]"
        }.joined(separator: " ")
    }

    /// Send one DNS A query over UDP and wait for any reply.
    static func dnsProbe(server: String, port: UInt16 = 53, name: String = probeName, timeout: Int32 = 3000) -> String {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return "socket errno=\(errno)" }
        defer { close(fd) }
        guard var to = address(server, port) else { return "bad address" }
        let query = dnsQuery(name)
        let sent = query.withUnsafeBytes { raw in
            withUnsafePointer(to: &to) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, raw.baseAddress, raw.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == query.count else { return "send errno=\(errno) (\(String(cString: strerror(errno))))" }
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, timeout) > 0 else { return "no reply in \(timeout) ms" }
        var buf = [UInt8](repeating: 0, count: 512)
        let n = recv(fd, &buf, buf.count, 0)
        guard n >= 12 else { return "recv=\(n) errno=\(errno)" }
        let rcode = buf[3] & 0x0f
        let answers = Int(buf[6]) << 8 | Int(buf[7])
        var text = "reply \(n) bytes rcode=\(rcode) answers=\(answers)"
        if answers > 0, n >= 4 { text += " last4=\(buf[n - 4]).\(buf[n - 3]).\(buf[n - 2]).\(buf[n - 1])" }
        return text
    }

    /// TCP connect with a timeout.
    static func tcpProbe(host: String, port: UInt16, timeout: Int32 = 3000) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return "socket errno=\(errno)" }
        defer { close(fd) }
        guard var to = address(host, port) else { return "bad address" }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        let rc = withUnsafePointer(to: &to) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc == 0 { return "connected" }
        guard errno == EINPROGRESS else { return "connect errno=\(errno) (\(String(cString: strerror(errno))))" }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, timeout) > 0 else { return "no answer in \(timeout) ms" }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
        return err == 0 ? "connected" : "connect errno=\(err) (\(String(cString: strerror(err))))"
    }

    /// What the system resolver returns for a name (this is what Safari uses).
    static func resolveProbe(name: String = probeName) -> String {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        let started = Date()
        let rc = getaddrinfo(name, nil, &hints, &result)
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        guard rc == 0, let first = result else { return "failed rc=\(rc) (\(String(cString: gai_strerror(rc)))) after \(ms) ms" }
        defer { freeaddrinfo(result) }
        var out: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let ai = cursor, out.count < 4 {
            if let sa = ai.pointee.ai_addr {
                let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
                out.append(AddressPlan.uint32ToIPv4(UInt32(bigEndian: addr)))
            }
            cursor = ai.pointee.ai_next
        }
        return out.joined(separator: ",") + " after \(ms) ms"
    }

    /// Send one datagram and expect it back (the extension's loopback echo).
    static func echoProbe(host: String, port: UInt16, timeout: Int32 = 2000) -> String {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return "socket errno=\(errno)" }
        defer { close(fd) }
        guard var to = address(host, port) else { return "bad address" }
        let payload: [UInt8] = Array("ztlp-echo".utf8)
        let sent = withUnsafePointer(to: &to) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, payload, payload.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard sent == payload.count else { return "send errno=\(errno) (\(String(cString: strerror(errno))))" }
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, timeout) > 0 else { return "no reply in \(timeout) ms" }
        var buf = [UInt8](repeating: 0, count: 32)
        let n = recv(fd, &buf, buf.count, 0)
        return n == payload.count ? "echoed" : "recv=\(n) errno=\(errno)"
    }

    /// Connect by NAME with Network.framework (the path browsers use, unlike
    /// the raw-socket probes), send one HTTP request, report the first line.
    static func nameConnectProbe(name: String = probeName, port: UInt16 = 80, timeout: TimeInterval = 6) -> String {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return "bad port" }
        let connection = NWConnection(host: NWEndpoint.Host(name), port: nwPort, using: .tcp)
        let done = DispatchSemaphore(value: 0)
        let result = ResultBox()
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let via = connection.currentPath?.availableInterfaces.first?.name ?? "?"
                let remote = connection.currentPath?.remoteEndpoint.map { "\($0)" } ?? "?"
                let request = Data("GET / HTTP/1.1\r\nHost: \(name)\r\nConnection: close\r\n\r\n".utf8)
                connection.send(content: request, completion: .contentProcessed { _ in })
                connection.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, error in
                    let first = data.flatMap { String(data: $0, encoding: .utf8) }?
                        .split(separator: "\r\n").first.map(String.init) ?? "no data"
                    result.set("ready via \(via) to \(remote): \(error.map { "\($0)" } ?? first)")
                    done.signal()
                }
            case .waiting(let error):
                result.set("waiting: \(error)")
            case .failed(let error):
                result.set("failed: \(error)")
                done.signal()
            default:
                break
            }
        }
        connection.start(queue: DispatchQueue.global(qos: .utility))
        let timedOut = done.wait(timeout: .now() + timeout) == .timedOut
        connection.cancel()
        let text = result.get()
        return timedOut ? "timed out after \(Int(timeout)) s (\(text.isEmpty ? "no state" : text))" : text
    }

    private final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var text = ""
        func set(_ value: String) { lock.lock(); text = value; lock.unlock() }
        func get() -> String { lock.lock(); defer { lock.unlock() }; return text }
    }

    /// A DNS query for one A record, recursion desired.
    static func dnsQuery(_ name: String, id: UInt16 = 0x5a54) -> [UInt8] {
        var q: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            q.append(UInt8(bytes.count))
            q.append(contentsOf: bytes)
        }
        q.append(contentsOf: [0, 0, 1, 0, 1])
        return q
    }

    static func address(_ host: String, _ port: UInt16) -> sockaddr_in? {
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &sa.sin_addr) == 1 else { return nil }
        return sa
    }
}

extension SharedPaths {
    /// Results of the on-device path probes (app and extension both append).
    static func diagLog(in container: URL) -> URL {
        container.appendingPathComponent("diag.log")
    }

    static func appendDiag(_ lines: [String], who: String) {
        guard let container, !lines.isEmpty else { return }
        let url = diagLog(in: container)
        let stamp = ISO8601DateFormatter().string(from: Date())
        let text = lines.map { "\(stamp) [\(who)] \($0)\n" }.joined()
        let fm = FileManager.default
        let size = (try? fm.attributesOfItem(atPath: url.path)[.size] as? UInt64) ?? 0
        if size > 128 * 1024 || !fm.fileExists(atPath: url.path) {
            try? Data(text.utf8).write(to: url, options: .atomic)
            return
        }
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(text.utf8))
    }
}
