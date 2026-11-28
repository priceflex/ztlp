// AppModel.swift
// The app's single view model: enrollment, VPN configuration, the readiness
// checklist and the certificate install flow.

import Foundation
import SwiftUI
import UIKit

@MainActor
final class AppModel: ObservableObject {

    // MARK: - Published state

    @Published private(set) var isEnrolled = false
    @Published private(set) var nodeName = ""
    @Published private(set) var zone = ""
    @Published private(set) var tunnelPhase: TunnelPhase = .unknown
    @Published private(set) var agentStatus: AgentStatus?
    @Published private(set) var trust: TrustState = .unknown
    /// Problem that stops the app from working at all (no shared storage).
    @Published private(set) var fatalError: String?
    /// Last error from a user action (tunnel setup, certificate, removal).
    @Published var actionError: String?

    @Published private(set) var isEnrolling = false
    @Published var enrollmentError: String?
    /// Code delivered by a ztlp:// link, waiting for the enrollment form.
    @Published var incomingCode: String?
    @Published var showEnrollment = false
    @Published var showCertificateGuide = false

    var readiness: Readiness {
        Readiness.compute(
            enrolled: isEnrolled, zone: zone, tunnel: tunnelPhase,
            agent: agentStatus, trust: trust
        )
    }

    // MARK: - Private

    private let tunnel = TunnelManager()
    private let certificateServer = CertificateServer()
    /// Serial queue for blocking calls into the Rust library.
    private let agentQueue = DispatchQueue(label: "com.ztlp.app.agent", qos: .userInitiated)
    private var libraryReady = false
    private var lastTrustProbe = Date.distantPast
    private var refreshing = false
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    static let pollInterval: Duration = .seconds(2)

    // MARK: - Lifecycle

    /// Poll until the calling task is cancelled (the home view goes away).
    /// Run the path probes once each time the app comes to the foreground.
    private var diagPending = true

    /// What an ordinary app can reach of the agent: written to diag.log.
    nonisolated static func runPathProbes() {
        DispatchQueue.global(qos: .utility).async {
            let agent = AddressPlan.agentAddress
            let lines = [
                "interfaces: \(NetDiag.interfaces())",
                "system resolver \(NetDiag.probeName): \(NetDiag.resolveProbe())",
                "tcp \(agent):80: \(NetDiag.tcpProbe(host: agent, port: 80))",
                "connect by name \(NetDiag.probeName):80: \(NetDiag.nameConnectProbe())",
                "tcp \(agent):8443 (agent health): \(NetDiag.tcpProbe(host: agent, port: 8443))",
                "agent dns \(agent):53: \(NetDiag.dnsProbe(server: agent))",
                "loopback echo \(agent):\(NetDiag.loopbackEchoPort): \(NetDiag.echoProbe(host: agent, port: NetDiag.loopbackEchoPort))",
            ]
            let trust = SharedPaths.container.map { TrustDiag.report(container: $0) } ?? []
            SharedPaths.appendDiag(lines + trust, who: "app")
        }
    }

    func runPolling() async {
        while !Task.isCancelled {
            await refresh()
            try? await Task.sleep(for: Self.pollInterval)
        }
    }

    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }

        guard await ensureLibrary() else { return }

        if let local = await onAgentQueue({ ZTLPAgent.status() }) {
            isEnrolled = local.enrolled
            nodeName = local.nodeName
            zone = local.zone
        } else {
            isEnrolled = await onAgentQueue { ZTLPAgent.isEnrolled }
        }

        guard isEnrolled else {
            tunnelPhase = .unknown
            agentStatus = nil
            trust = .unknown
            return
        }

        await tunnel.loadIfNeeded()
        tunnelPhase = await tunnel.phase()
        agentStatus = tunnelPhase == .connected ? await tunnel.providerStatus() : nil
        if tunnelPhase == .connected, diagPending {
            diagPending = false
            Self.runPathProbes()
        }

        if readiness.tunnel.isReady {
            await probeTrustIfDue()
        } else {
            trust = .unknown
            lastTrustProbe = .distantPast
        }
    }

    /// The app came back to the foreground (for example from Settings after
    /// trusting the certificate): check right away.
    func didBecomeActive() async {
        endBackgroundTask()
        diagPending = true
        lastTrustProbe = .distantPast
        await refresh()
    }

    // MARK: - Enrollment

    /// A ztlp:// link opened the app.
    func handleIncomingURL(_ url: URL) {
        guard let code = EnrollmentCode.fromIncomingURL(url) else {
            actionError = "That link is not a ZTLP enrollment code."
            return
        }
        guard !isEnrolled else {
            actionError = "This device is already enrolled. To enroll again, remove it in Settings first."
            return
        }
        incomingCode = code
        enrollmentError = nil
        showEnrollment = true
    }

    /// Returns true when the device is enrolled.
    @discardableResult
    func enroll(code rawCode: String, deviceName rawName: String) async -> Bool {
        guard !isEnrolling else { return false }
        let code: String
        switch EnrollmentCode.normalize(rawCode) {
        case .success(let value): code = value
        case .failure(let problem):
            enrollmentError = problem.message
            return false
        }
        let name = DeviceName.clean(rawName)

        isEnrolling = true
        enrollmentError = nil
        defer { isEnrolling = false }

        guard await ensureLibrary() else {
            enrollmentError = fatalError ?? "ZTLP could not start."
            return false
        }

        let result = await onAgentQueue { ZTLPAgent.enroll(uri: code, deviceName: name) }
        if case .failure(let error) = result {
            enrollmentError = error.message
            return false
        }

        incomingCode = nil
        await refresh()
        await setUpTunnel()
        return true
    }

    // MARK: - Tunnel

    /// Save the VPN configuration (iOS asks the user once) and start it.
    func setUpTunnel() async {
        do {
            try await tunnel.installAndStart()
            actionError = nil
        } catch {
            actionError = "iOS did not save the ZTLP configuration: \(error.localizedDescription)"
        }
        await refresh()
    }

    // MARK: - HTTPS trust

    /// Hand the root certificate to Safari so iOS offers to install it.
    func installCertificate() async {
        guard await ensureLibrary() else { return }
        let pemResult: Result<String, AgentError> = await onAgentQueue {
            if case .failure(let error) = ZTLPAgent.ensureCA() { return .failure(error) }
            return ZTLPAgent.caRootPEM()
        }
        let pem: String
        switch pemResult {
        case .success(let value): pem = value
        case .failure(let error):
            actionError = error.message
            return
        }
        guard let der = CertificateEncoding.derFromPEM(pem) else {
            actionError = "The certificate could not be read."
            return
        }
        do {
            let url = try await certificateServer.start(der: der)
            // Safari fetches the file while this app is in the background.
            beginBackgroundTask()
            let opened = await UIApplication.shared.open(url)
            if opened {
                actionError = nil
            } else {
                endBackgroundTask()
                actionError = "Could not open Safari."
            }
        } catch {
            actionError = error.localizedDescription
        }
    }

    private nonisolated static func systemTrust() async -> Bool? {
        await Task.detached(priority: .utility) {
            SharedPaths.container.flatMap { TrustDiag.systemTrust(container: $0) }
        }.value
    }

    private func probeTrustIfDue() async {
        let interval: TimeInterval = trust == .trusted ? 60 : 5
        guard Date().timeIntervalSince(lastTrustProbe) >= interval else { return }
        lastTrustProbe = Date()
        // Ask iOS directly whether it accepts the agent's certificates. If
        // none has been issued yet, one request to the agent makes it issue
        // one, then ask again.
        var verdict = await Self.systemTrust()
        if verdict == nil {
            _ = await TrustProbe.run()
            verdict = await Self.systemTrust()
        }
        trust = verdict.map { $0 ? .trusted : .notTrusted } ?? .unreachable
        if trust == .trusted { certificateServer.stop() }
    }

    // MARK: - Settings

    enum LogKind: String, CaseIterable, Identifiable {
        case agent = "Agent"
        case tunnelExtension = "Extension"
        var id: String { rawValue }
    }

    func logTail(_ kind: LogKind) async -> [String] {
        guard let container = SharedPaths.container else { return [] }
        let url = kind == .agent
            ? SharedPaths.agentLog(in: container)
            : SharedPaths.extensionLog(in: container)
        return await Task.detached(priority: .utility) {
            LogTail.read(url: url, maxLines: 200)
        }.value
    }

    /// Stop and delete the VPN configuration and erase the identity.
    func removeDevice() async {
        certificateServer.stop()
        await tunnel.remove()
        if let container = SharedPaths.container {
            let state = SharedPaths.stateDirectory(in: container)
            let extensionLog = SharedPaths.extensionLog(in: container)
            let failure: String? = await Task.detached {
                let fm = FileManager.default
                try? fm.removeItem(at: extensionLog)
                guard fm.fileExists(atPath: state.path) else { return nil }
                do {
                    try fm.removeItem(at: state)
                    return nil
                } catch {
                    return error.localizedDescription
                }
            }.value
            if let failure {
                actionError = "Could not erase this device's identity: \(failure)"
            } else {
                actionError = nil
            }
        }
        isEnrolled = false
        nodeName = ""
        zone = ""
        agentStatus = nil
        trust = .unknown
        tunnelPhase = .unknown
        await refresh()
    }

    // MARK: - Helpers

    private func ensureLibrary() async -> Bool {
        if libraryReady { return true }
        guard let container = SharedPaths.container else {
            fatalError = "Shared storage is not available. Reinstall ZTLP."
            return false
        }
        let result = await onAgentQueue { ZTLPAgent.initialize(home: container) }
        switch result {
        case .success:
            libraryReady = true
            fatalError = nil
            return true
        case .failure(let error):
            fatalError = error.message
            return false
        }
    }

    /// Run blocking library work off the main thread, one call at a time.
    private func onAgentQueue<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { continuation in
            agentQueue.async { continuation.resume(returning: work()) }
        }
    }

    private func beginBackgroundTask() {
        endBackgroundTask()
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "ztlp-certificate") { [weak self] in
            Task { @MainActor in self?.endBackgroundTask() }
        }
    }

    private func endBackgroundTask() {
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }
}
