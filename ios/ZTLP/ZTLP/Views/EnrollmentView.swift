// EnrollmentView.swift
// Scan or paste the ztlp://enroll/... code, pick a device name, enroll.

@preconcurrency import AVFoundation
import SwiftUI
import UIKit

struct EnrollmentView: View {
    @ObservedObject var model: AppModel
    let startWithScanner: Bool

    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var deviceName = DeviceName.clean(UIDevice.current.name)
    @State private var showScanner = false
    @State private var cameraDenied = false
    @FocusState private var codeFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("ztlp://enroll/...", text: $code, axis: .vertical)
                        .lineLimit(3...6)
                        .font(.system(.footnote, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.asciiCapable)
                        .focused($codeFocused)
                        .accessibilityIdentifier("enroll.code")

                    Button {
                        Task { await openScanner() }
                    } label: {
                        Label("Scan QR code", systemImage: "qrcode.viewfinder")
                    }
                    Button {
                        if let pasted = UIPasteboard.general.string { code = pasted }
                    } label: {
                        Label("Paste code", systemImage: "doc.on.clipboard")
                    }
                } header: {
                    Text("Enrollment code")
                } footer: {
                    if cameraDenied {
                        Text("Camera access is off. Allow it in Settings > ZTLP, or paste the code.")
                    } else {
                        Text("Your administrator shows this code in the ZTLP panel.")
                    }
                }

                Section {
                    TextField("Device name", text: $deviceName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("enroll.name")
                } header: {
                    Text("Device name")
                } footer: {
                    let cleaned = DeviceName.clean(deviceName)
                    if cleaned != deviceName {
                        Text("Will be registered as \(cleaned).")
                    }
                }

                if let error = model.enrollmentError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Color.ztlpRed)
                            .font(.footnote)
                    }
                }

                Section {
                    Button {
                        codeFocused = false
                        Task {
                            if await model.enroll(code: code, deviceName: deviceName) {
                                dismiss()
                            }
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if model.isEnrolling {
                                ProgressView()
                            } else {
                                Text("Enroll").fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(model.isEnrolling || code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .navigationTitle("Enroll this device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(model.isEnrolling)
                }
            }
            .interactiveDismissDisabled(model.isEnrolling)
            .fullScreenCover(isPresented: $showScanner) {
                ScannerScreen { scanned in
                    showScanner = false
                    code = scanned
                } onCancel: {
                    showScanner = false
                }
            }
            .task {
                if let incoming = model.incomingCode {
                    code = incoming
                } else if startWithScanner {
                    await openScanner()
                }
            }
            .task(id: model.incomingCode) {
                // A ztlp:// link arrived while the form was already open.
                if let incoming = model.incomingCode { code = incoming }
            }
        }
    }

    private func openScanner() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            cameraDenied = false
            showScanner = true
        case .notDetermined:
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            cameraDenied = !granted
            showScanner = granted
        default:
            cameraDenied = true
        }
    }
}

/// Full-screen camera with a Cancel button.
private struct ScannerScreen: View {
    let onCode: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        ZStack(alignment: .bottom) {
            QRScannerView(onCodeScanned: onCode)
                .ignoresSafeArea()
            VStack(spacing: 14) {
                Text("Point the camera at the enrollment QR code.")
                    .font(.callout)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.black.opacity(0.55), in: Capsule())
                Button("Cancel", action: onCancel)
                    .buttonStyle(.borderedProminent)
                    .tint(.white.opacity(0.9))
                    .foregroundStyle(.black)
            }
            .padding(.bottom, 36)
        }
        .background(Color.black)
    }
}

// MARK: - QR scanner (AVFoundation)

struct QRScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.onCodeScanned = onCodeScanned
        return controller
    }

    func updateUIViewController(_ controller: QRScannerViewController, context: Context) {}
}

final class QRScannerViewController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    var onCodeScanned: ((String) -> Void)?

    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "com.ztlp.app.camera")
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        // Delivered on the main queue, which is what the conformance relies on.
        output.setMetadataObjectsDelegate(self, queue: .main)
        if output.availableMetadataObjectTypes.contains(.qr) {
            output.metadataObjectTypes = [.qr]
        }

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let session = self.session
        sessionQueue.async {
            if !session.isRunning { session.startRunning() }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = self.session
        sessionQueue.async {
            if session.isRunning { session.stopRunning() }
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasScanned,
              let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = object.stringValue, !value.isEmpty else { return }
        hasScanned = true
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        onCodeScanned?(value)
    }
}
