// PacketTunnelProvider.swift
// ZTLPTunnel
//
// Hosts the Rust ZTLP agent inside the packet tunnel extension.
//
// Measured on a device: iOS sends traffic for the tunnel's own addresses into
// the tunnel as packets, so the agent cannot listen there. Loopback is
// delivered from other apps to this extension's sockets. So:
//   - the agent listens on 127.0.0.1 (resolver 53, web 80/443, health 8443)
//     and tells sites apart by name (TLS server name / Host header);
//   - iOS is given one routed DNS server address for `.ztlp`; those queries
//     arrive here as packets and are passed to the agent's resolver, which
//     answers every site with 127.0.0.1;
//   - nothing else is routed here: this is not a VPN for general traffic.
//
// iOS kills this process above 50 MiB, so keep it lean: nothing here buffers
// data, and the footprint is logged every 30 s.

import Foundation
import Network
import NetworkExtension
import os

// @unchecked Sendable: the only mutable state is `memoryTimer`, which is
// touched on `agentQueue` alone.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    private let log = ExtensionLog()
    /// Serial queue for every blocking call into the Rust library.
    private let agentQueue = DispatchQueue(label: "com.ztlp.tunnel.agent")
    private var memoryTimer: DispatchSourceTimer?
    /// Work that blocks on a socket (DNS relay, probes).
    private let packetQueue = DispatchQueue(label: "com.ztlp.tunnel.packets", attributes: .concurrent)
    /// At most this many DNS relays in flight; more are dropped (the client retries).
    private let dnsSlots = DispatchSemaphore(value: 8)
    private let stats = PacketStats()
    /// Watches the device's real network (Wi-Fi, cellular) so the agent can
    /// be told the moment it changes. Touched on `agentQueue` only.
    private var pathMonitor: NWPathMonitor?
    private var lastPath = ""
    private let dnsAddress = AddressPlan.ipv4ToUInt32(AddressPlan.dnsAddress) ?? 0

    // MARK: - Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let container = SharedPaths.container else {
            completionHandler(TunnelError("Shared storage is not available. Reinstall ZTLP."))
            return
        }
        log.open(SharedPaths.extensionLog(in: container))
        log.write("startTunnel")
        let done = UncheckedSendable(completionHandler)

        agentQueue.async { [self] in
            if case .failure(let error) = ZTLPAgent.initialize(home: container) {
                log.write("init failed: \(error.message)")
                done.value(TunnelError(error.message))
                return
            }
            guard ZTLPAgent.isEnrolled else {
                log.write("not enrolled")
                done.value(TunnelError("This device is not enrolled. Open ZTLP and scan your enrollment code."))
                return
            }

            setTunnelNetworkSettings(Self.makeSettings()) { [self] error in
                if let error {
                    log.write("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                    done.value(error)
                    return
                }
                agentQueue.async { [self] in
                    startAgent(done)
                }
            }
        }
    }

    /// Runs on `agentQueue` once the tunnel addresses exist.
    private func startAgent(_ done: UncheckedSendable<(Error?) -> Void>) {
        // HTTP still works without the CA, so a CA failure is logged and
        // shown by the app's HTTPS row; it does not stop the tunnel.
        if case .failure(let error) = ZTLPAgent.ensureCA() {
            log.write("ensure_ca failed: \(error.message)")
        }
        switch ZTLPAgent.start(dnsIP: AddressPlan.agentAddress, vipCIDR: AddressPlan.agentCIDR) {
        case .success:
            log.write("agent started on \(AddressPlan.agentAddress)")
            startMemoryLog()
            readPackets()
            startLoopbackEcho()
            startPathMonitor()
            done.value(nil)
            runSelfTest()
        case .failure(let error):
            log.write("agent_start failed: \(error.message)")
            done.value(TunnelError(error.message))
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.write("stopTunnel reason=\(reason.rawValue)")
        let done = UncheckedSendable(completionHandler)
        agentQueue.async { [self] in
            memoryTimer?.cancel()
            memoryTimer = nil
            pathMonitor?.cancel()
            pathMonitor = nil
            stats.closeEcho()
            let rc = ZTLPAgent.stop()
            log.write("agent stopped rc=\(rc) footprint=\(Self.footprintText())")
            done.value()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        log.write("device sleeping")
        completionHandler()
    }

    /// Connections made before the device slept are usually dead.
    override func wake() {
        agentQueue.async { [self] in
            log.write("device woke: telling the agent (rc=\(ZTLPAgent.networkChanged()))")
        }
    }

    // MARK: - Network changes

    /// Runs on `agentQueue`. The first report is the starting state; every
    /// later report that differs is a network change.
    private func startPathMonitor() {
        pathMonitor?.cancel()
        lastPath = ""
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let now = Self.describe(path)
            // Already on agentQueue (the monitor's queue).
            if self.lastPath.isEmpty {
                self.lastPath = now
                self.log.write("network: \(now)")
            } else if now != self.lastPath {
                let before = self.lastPath
                self.lastPath = now
                self.log.write("network changed: \(before) -> \(now) (rc=\(ZTLPAgent.networkChanged()))")
            }
        }
        monitor.start(queue: agentQueue)
        pathMonitor = monitor
    }

    /// The interface the device is actually using: the first real one iOS
    /// lists (it lists them in order of preference), ignoring this tunnel's
    /// own. Only a change of THIS is a network change: telling the agent
    /// cuts transfers in progress, so a second interface merely becoming
    /// available (cellular coming up while on Wi-Fi) must not count.
    static func describe(_ path: Network.NWPath) -> String {
        guard path.status == .satisfied else { return "offline" }
        for iface in path.availableInterfaces {
            switch iface.type {
            case .wifi: return "wifi(\(iface.name))"
            case .cellular: return "cellular(\(iface.name))"
            case .wiredEthernet: return "wired(\(iface.name))"
            default: continue
            }
        }
        return "other"
    }

    /// Any message from the app is answered with the agent's status JSON.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else { return }
        let done = UncheckedSendable(completionHandler)
        // Not on agentQueue: status must answer even while a start is blocked.
        DispatchQueue.global(qos: .userInitiated).async {
            done.value(ZTLPAgent.statusJSON())
        }
    }

    // MARK: - Network settings

    static func makeSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: AddressPlan.tunnelRemotePlaceholder
        )

        let addresses = AddressPlan.tunnelAddresses
        let ipv4 = NEIPv4Settings(
            addresses: addresses,
            subnetMasks: Array(repeating: AddressPlan.hostMask, count: addresses.count)
        )
        // The only route is the DNS server address, so `.ztlp` lookups reach
        // this extension as packets. Nothing else is routed here.
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: AddressPlan.dnsAddress, subnetMask: AddressPlan.hostMask)
        ]
        ipv4.excludedRoutes = []
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [AddressPlan.dnsAddress])
        dns.matchDomains = [AddressPlan.matchDomain]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns

        // MTU is left at the system default.
        return settings
    }

    // MARK: - Packet flow

    /// The data path is meant to be kernel sockets, not packets. Whatever
    /// iOS still delivers as packets is counted, the first few are logged,
    /// and DNS queries for the agent are answered through its socket.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            for packet in packets { self.handle(packet) }
            self.readPackets()
        }
    }

    private func handle(_ packet: Data) {
        let seen = stats.countPacket()
        if seen <= 40 { log.write("packet #\(seen): \(PacketCodec.describe(packet))") }
        guard let query = PacketCodec.parseIPv4UDP(packet),
              query.destinationPort == 53, query.destination == dnsAddress else { return }
        // Our own relay socket's packet came back as a packet: relaying it
        // again would loop forever.
        if stats.isRelayPort(query.sourcePort) {
            if stats.countLoop() <= 3 { log.write("dns relay looped back into the tunnel; dropped") }
            return
        }
        // Names outside `.ztlp` (for example iOS's own resolver-discovery
        // query) are refused here at once; the agent is only asked about ours.
        switch DNSAnswer.classify(query: query.payload) {
        case .malformed:
            return
        case .outside(let refusal):
            if let reply = PacketCodec.buildIPv4UDP(UDPDatagram(
                source: query.destination, destination: query.source,
                sourcePort: 53, destinationPort: query.sourcePort, payload: refusal
            )) {
                packetFlow.writePackets([reply], withProtocols: [NSNumber(value: AF_INET)])
            }
            return
        case .inside:
            break
        }
        guard dnsSlots.wait(timeout: .now()) == .success else { return }
        packetQueue.async { [self] in
            defer { dnsSlots.signal() }
            let outcome = relayDNS(query.payload)
            let relayed = stats.countRelay()
            guard case .success(let answer) = outcome else {
                if relayed <= 10, case .failure(let why) = outcome { log.write("dns relay #\(relayed) failed: \(why.message)") }
                return
            }
            guard let reply = PacketCodec.buildIPv4UDP(UDPDatagram(
                source: query.destination, destination: query.source,
                sourcePort: 53, destinationPort: query.sourcePort, payload: answer
            )) else { return }
            packetFlow.writePackets([reply], withProtocols: [NSNumber(value: AF_INET)])
            if relayed <= 10 { log.write("dns relay #\(relayed): answered \(answer.count) bytes") }
        }
    }

    /// One query to the agent's resolver socket, one answer back.
    private func relayDNS(_ payload: Data) -> Result<Data, TunnelError> {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return .failure(TunnelError("socket errno=\(errno)")) }
        defer { close(fd) }
        var local = sockaddr_in()
        local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        local.sin_family = sa_family_t(AF_INET)
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &local) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, len) == 0 && getsockname(fd, $0, &len) == 0
            }
        }
        guard bound else { return .failure(TunnelError("bind errno=\(errno)")) }
        let port = UInt16(bigEndian: local.sin_port)
        stats.addRelayPort(port)
        defer { stats.removeRelayPort(port) }

        guard var to = NetDiag.address(AddressPlan.agentAddress, 53) else { return .failure(TunnelError("bad address")) }
        let sent = payload.withUnsafeBytes { raw in
            withUnsafePointer(to: &to) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, raw.baseAddress, raw.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == payload.count else { return .failure(TunnelError("send errno=\(errno)")) }
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, 8000) > 0 else { return .failure(TunnelError("no answer from the agent in 8 s")) }
        var buf = [UInt8](repeating: 0, count: 1500)
        let n = recv(fd, &buf, buf.count, 0)
        guard n > 0 else { return .failure(TunnelError("recv errno=\(errno)")) }
        return .success(Data(buf[0..<n]))
    }

    // MARK: - Path probes

    /// UDP echo on loopback, so the app can test whether loopback crosses
    /// from an app into this extension.
    private func startLoopbackEcho() {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0, var me = NetDiag.address("127.0.0.1", NetDiag.loopbackEchoPort) else { return }
        let rc = withUnsafePointer(to: &me) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            log.write("loopback echo bind failed errno=\(errno)")
            close(fd)
            return
        }
        stats.setEcho(fd)
        packetQueue.async {
            var buf = [UInt8](repeating: 0, count: 64)
            while true {
                var from = sockaddr_in()
                var len = socklen_t(MemoryLayout<sockaddr_in>.size)
                let n = withUnsafeMutablePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(fd, &buf, buf.count, 0, $0, &len)
                    }
                }
                guard n > 0 else { return }
                _ = withUnsafePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, buf, n, 0, $0, len)
                    }
                }
            }
        }
    }

    /// What this process itself can reach, written to the diagnostics log.
    private func runSelfTest() {
        packetQueue.asyncAfter(deadline: .now() + 1) { [log] in
            let lines = [
                "interfaces: \(NetDiag.interfaces())",
                "agent dns \(AddressPlan.agentAddress):53: \(NetDiag.dnsProbe(server: AddressPlan.agentAddress))",
                "agent health tcp \(AddressPlan.agentAddress):8443: \(NetDiag.tcpProbe(host: AddressPlan.agentAddress, port: 8443))",
            ]
            SharedPaths.appendDiag(lines, who: "ext")
            for line in lines { log.write("selftest \(line)") }
        }
    }

    // MARK: - Memory log

    /// Runs on `agentQueue`.
    private func startMemoryLog() {
        memoryTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: 30, leeway: .seconds(5))
        timer.setEventHandler { [log, stats] in
            log.write("memory footprint=\(Self.footprintText()) packets=\(stats.packets) dnsRelayed=\(stats.relays)")
        }
        timer.resume()
        memoryTimer = timer
    }

    /// Physical footprint of this process, the number iOS compares with the
    /// 50 MiB extension limit.
    static func physFootprintBytes() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size
        )
        let kr = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.phys_footprint : nil
    }

    static func footprintText() -> String {
        guard let bytes = physFootprintBytes() else { return "unknown" }
        return String(format: "%.1fMiB", Double(bytes) / 1_048_576.0)
    }
}

/// Counters and the small shared state of the packet path.
final class PacketStats: @unchecked Sendable {
    private let lock = NSLock()
    private var packetCount = 0
    private var relayCount = 0
    private var loopCount = 0
    private var relayPorts: Set<UInt16> = []
    private var echoFD: Int32 = -1

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    var packets: Int { locked { packetCount } }
    var relays: Int { locked { relayCount } }
    func countPacket() -> Int { locked { packetCount += 1; return packetCount } }
    func countRelay() -> Int { locked { relayCount += 1; return relayCount } }
    func countLoop() -> Int { locked { loopCount += 1; return loopCount } }
    func addRelayPort(_ port: UInt16) { locked { _ = relayPorts.insert(port) } }
    func removeRelayPort(_ port: UInt16) { locked { _ = relayPorts.remove(port) } }
    func isRelayPort(_ port: UInt16) -> Bool { locked { relayPorts.contains(port) } }
    func setEcho(_ fd: Int32) { locked { echoFD = fd } }
    func closeEcho() {
        let fd: Int32 = locked { let f = echoFD; echoFD = -1; return f }
        if fd >= 0 { close(fd) }
    }
}

/// Error whose text iOS shows the app through `NEVPNConnection`'s last
/// disconnect error.
struct TunnelError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// Tiny append-only log in the App Group container, readable from the app's
/// Settings page. Also mirrored to the unified log. Never holds more than
/// one line in memory and restarts the file at 256 KiB.
final class ExtensionLog: @unchecked Sendable {
    private static let maxBytes: UInt64 = 256 * 1024
    private let queue = DispatchQueue(label: "com.ztlp.tunnel.log")
    private let oslog = Logger(subsystem: "com.ztlp.app.tunnel", category: "tunnel")
    private var url: URL?
    private let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    func open(_ url: URL) {
        queue.sync { self.url = url }
    }

    func write(_ message: String) {
        oslog.info("\(message, privacy: .public)")
        queue.async { [self] in
            guard let url else { return }
            let line = Data("\(formatter.string(from: Date())) \(message)\n".utf8)
            let fm = FileManager.default
            let size = (try? fm.attributesOfItem(atPath: url.path)[.size] as? UInt64) ?? 0
            if size > Self.maxBytes || !fm.fileExists(atPath: url.path) {
                try? line.write(to: url, options: .atomic)
                return
            }
            guard let handle = try? FileHandle(forWritingTo: url) else { return }
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: line)
        }
    }
}
