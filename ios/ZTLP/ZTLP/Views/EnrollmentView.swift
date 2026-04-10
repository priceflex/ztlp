// EnrollmentView.swift
// ZTLP
//
// QR code enrollment scanner with manual entry fallback.
// Streamlined flow: scan/paste → review → enroll → done.

import SwiftUI
import AVFoundation

struct EnrollmentView: View {
    @ObservedObject var viewModel: EnrollmentViewModel
    @Environment(\.dismiss) private var dismiss

    /// Callback when enrollment completes successfully.
    var onComplete: (() -> Void)?

    @State private var showManualEntry = false
    @State private var manualURI = ""

    var body: some View {
        NavigationStack {
            ZStack {
                Color(.systemGroupedBackground).ignoresSafeArea()

                switch viewModel.state {
                case .idle:
                    scannerView
                case .tokenParsed:
                    tokenReviewView
                case .enrolling:
                    enrollingView
                case .success:
                    successView
                case .error:
                    errorView
                }
            }
            .navigationTitle("Enroll Device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    if viewModel.state != .enrolling {
                        Button("Cancel") { dismiss() }
                    }
                }
            }
        }
    }

    // MARK: - Scanner View

    private var scannerView: some View {
        VStack(spacing: 24) {
            // Camera scanner
            ZStack {
                if viewModel.hasCameraPermission {
                    QRScannerView(onCodeScanned: { code in
                        viewModel.parseToken(from: code)
                    })
                    .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))

                    // Scanner overlay
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .strokeBorder(Color.ztlpBlue, lineWidth: 2)

                    // Corner markers
                    ScannerCornersOverlay()
                } else {
                    VStack(spacing: 16) {
                        Image(systemName: "camera.fill")
                            .font(.system(size: 40))
                            .foregroundStyle(.secondary)
                        Text("Camera access required")
                            .font(.headline)
                        Text("Allow camera access to scan enrollment QR codes.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)

                        Button("Open Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) {
                                UIApplication.shared.open(url)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(Color.ztlpBlue)
                    }
                    .padding(32)
                    .frame(maxWidth: .infinity, maxHeight: 300)
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                }
            }
            .frame(height: 300)
            .padding(.horizontal)

            // Instructions
            VStack(spacing: 8) {
                Text("Scan QR Code")
                    .font(.headline)
                Text("Point your camera at a ZTLP enrollment QR code")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            // Manual entry
            Button {
                showManualEntry = true
            } label: {
                Label("Enter URI Manually", systemImage: "text.cursor")
                    .font(.subheadline)
            }
            .sheet(isPresented: $showManualEntry) {
                manualEntrySheet
            }

            Spacer()
        }
        .padding(.top, 16)
        .onAppear {
            viewModel.requestCameraPermission()
        }
    }

    // MARK: - Token Review

    private var tokenReviewView: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(Color.ztlpGreen)
                    .padding(.top, 20)

                Text("Enrollment Token Found")
                    .font(.title3.weight(.bold))

                // Token details card
                VStack(alignment: .leading, spacing: 16) {
                    if let zone = viewModel.parsedZone {
                        TokenDetailRow(label: "Zone", value: zone, icon: "globe.americas")
                    }
                    if let relay = viewModel.parsedRelay {
                        TokenDetailRow(label: "Relay", value: relay, icon: "point.3.connected.trianglepath.dotted")
                    }
                    if let gateway = viewModel.parsedGateway {
                        TokenDetailRow(label: "Gateway", value: gateway, icon: "server.rack")
                    }
                    if let ns = viewModel.parsedNS {
                        TokenDetailRow(label: "Name Server", value: ns, icon: "network")
                    }
                }
                .ztlpCard()
                .padding(.horizontal)

                // Security note
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "lock.fill")
                        .foregroundStyle(Color.ztlpBlue)
                    Text("A Noise_XX identity will be generated and enrolled in this zone. Keys are stored in the Secure Enclave when available.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 24)

                // Enroll button
                Button {
                    viewModel.enroll()
                } label: {
                    Text("Enroll This Device")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(
                            LinearGradient.ztlpConnected,
                            in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                        )
                        .foregroundColor(.white)
                }
                .padding(.horizontal, 24)

                Button("Scan Again") {
                    viewModel.reset()
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Enrolling

    private var enrollingView: some View {
        VStack(spacing: 24) {
            Spacer()

            ProgressView()
                .scaleEffect(1.5)

            VStack(spacing: 8) {
                Text("Enrolling\u{2026}")
                    .font(.title3.weight(.semibold))
                Text("Generating identity and registering with the zone.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            Spacer()
        }
    }

    // MARK: - Success

    private var successView: some View {
        VStack(spacing: 24) {
            Spacer()

            ZStack {
                Circle()
                    .fill(Color.ztlpGreen.opacity(0.1))
                    .frame(width: 120, height: 120)
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(Color.ztlpGreen)
            }

            VStack(spacing: 8) {
                Text("Enrolled!")
                    .font(.title2.weight(.bold))
                Text("Your device is now enrolled in the ZTLP zone.\nYou can connect to the tunnel from the Home screen.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Button {
                onComplete?()
                dismiss()
            } label: {
                Text("Get Started")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(
                        LinearGradient.ztlpConnected,
                        in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                    )
                    .foregroundColor(.white)
            }
            .padding(.horizontal, 24)

            Spacer()
        }
    }

    // MARK: - Error

    private var errorView: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(Color.ztlpOrange)

            VStack(spacing: 8) {
                Text("Enrollment Failed")
                    .font(.title3.weight(.bold))
                if let error = viewModel.errorMessage {
                    Text(error)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
            }

            VStack(spacing: 12) {
                Button {
                    viewModel.enroll()
                } label: {
                    Text("Retry")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color.ztlpBlue, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .foregroundColor(.white)
                }

                Button("Start Over") {
                    viewModel.reset()
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 24)

            Spacer()
        }
    }

    // MARK: - Manual Entry Sheet

    private var manualEntrySheet: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Text("Paste your enrollment URI below:")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                TextEditor(text: $manualURI)
                    .font(.caption.monospaced())
                    .frame(height: 120)
                    .padding(8)
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(Color.ztlpBlue.opacity(0.3), lineWidth: 1)
                    )

                Text("Format: ztlp://enroll?zone=\u{2026}&relay=\u{2026}&gw=\u{2026}")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)

                Button {
                    viewModel.parseToken(from: manualURI.trimmingCharacters(in: .whitespacesAndNewlines))
                    showManualEntry = false
                } label: {
                    Text("Parse Token")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color.ztlpBlue, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .foregroundColor(.white)
                }
                .disabled(manualURI.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                Spacer()
            }
            .padding()
            .navigationTitle("Manual Entry")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cancel") { showManualEntry = false }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        if let clipboard = UIPasteboard.general.string {
                            manualURI = clipboard
                        }
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                }
            }
        }
    }
}

// MARK: - Token Detail Row

private struct TokenDetailRow: View {
    let label: String
    let value: String
    let icon: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.body)
                .foregroundStyle(Color.ztlpBlue)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.subheadline.monospaced())
            }
        }
    }
}

// MARK: - Scanner Corners Overlay

private struct ScannerCornersOverlay: View {
    var body: some View {
        GeometryReader { geometry in
            let size = min(geometry.size.width, geometry.size.height) * 0.6
            let offsetX = (geometry.size.width - size) / 2
            let offsetY = (geometry.size.height - size) / 2
            let cornerLength: CGFloat = 30
            let lineWidth: CGFloat = 3

            // Top-left
            Path { path in
                path.move(to: CGPoint(x: offsetX, y: offsetY + cornerLength))
                path.addLine(to: CGPoint(x: offsetX, y: offsetY))
                path.addLine(to: CGPoint(x: offsetX + cornerLength, y: offsetY))
            }
            .stroke(Color.ztlpBlue, lineWidth: lineWidth)

            // Top-right
            Path { path in
                path.move(to: CGPoint(x: offsetX + size - cornerLength, y: offsetY))
                path.addLine(to: CGPoint(x: offsetX + size, y: offsetY))
                path.addLine(to: CGPoint(x: offsetX + size, y: offsetY + cornerLength))
            }
            .stroke(Color.ztlpBlue, lineWidth: lineWidth)

            // Bottom-left
            Path { path in
                path.move(to: CGPoint(x: offsetX, y: offsetY + size - cornerLength))
                path.addLine(to: CGPoint(x: offsetX, y: offsetY + size))
                path.addLine(to: CGPoint(x: offsetX + cornerLength, y: offsetY + size))
            }
            .stroke(Color.ztlpBlue, lineWidth: lineWidth)

            // Bottom-right
            Path { path in
                path.move(to: CGPoint(x: offsetX + size - cornerLength, y: offsetY + size))
                path.addLine(to: CGPoint(x: offsetX + size, y: offsetY + size))
                path.addLine(to: CGPoint(x: offsetX + size, y: offsetY + size - cornerLength))
            }
            .stroke(Color.ztlpBlue, lineWidth: lineWidth)
        }
    }
}

// MARK: - QR Scanner UIKit Bridge

struct QRScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let vc = QRScannerViewController()
        vc.onCodeScanned = onCodeScanned
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}
}

class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCodeScanned: ((String) -> Void)?
    private var captureSession: AVCaptureSession?
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()
        setupCamera()
    }

    private func setupCamera() {
        let session = AVCaptureSession()
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else { return }

        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.frame = view.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)

        captureSession = session

        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasScanned,
              let metadata = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = metadata.stringValue else { return }

        hasScanned = true
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        onCodeScanned?(value)
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        captureSession?.stopRunning()
    }
}

// MARK: - Previews

#Preview("Scanner") {
    EnrollmentView(
        viewModel: EnrollmentViewModel(configuration: ZTLPConfiguration())
    )
}
