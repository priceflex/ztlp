// EnrollmentView.swift
// ZTLP
//
// QR code scanner for enrollment. Scans ztlp://enroll/ URIs,
// displays parsed token info, and executes the enrollment flow.

import SwiftUI
import AVFoundation

struct EnrollmentView: View {
    @ObservedObject var viewModel: EnrollmentViewModel
    @Environment(\.dismiss) private var dismiss

    /// For manual entry when camera isn't available.
    @State private var manualEntryText = ""
    @State private var showManualEntry = false

    var body: some View {
        NavigationStack {
            Group {
                switch viewModel.state {
                case .idle:
                    idleView
                case .scanning:
                    scannerView
                case .tokenParsed(let tokenInfo):
                    tokenReviewView(tokenInfo)
                case .enrolling:
                    enrollingView
                case .success(let zoneName):
                    successView(zoneName)
                case .error(let message):
                    errorView(message)
                }
            }
            .navigationTitle("Enroll Device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }

    // MARK: - State Views

    /// Idle state — prompt to scan.
    private var idleView: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 80))
                .foregroundStyle(Color.ztlpBlue)
                .accessibilityHidden(true)

            Text("Scan Enrollment QR Code")
                .font(.title2.weight(.semibold))

            Text("Your administrator will provide a QR code to enroll this device in your ZTLP zone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            Spacer()

            VStack(spacing: 12) {
                Button {
                    viewModel.startScanning()
                } label: {
                    Label("Scan QR Code", systemImage: "camera")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .controlSize(.large)
                .disabled(!viewModel.cameraAuthorized)

                Button {
                    showManualEntry = true
                } label: {
                    Text("Enter code manually")
                        .font(.callout)
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
        .sheet(isPresented: $showManualEntry) {
            manualEntrySheet
        }
    }

    /// QR scanner using AVFoundation.
    private var scannerView: some View {
        ZStack {
            QRScannerView { code in
                viewModel.handleScannedCode(code)
            }
            .ignoresSafeArea()

            // Overlay with viewfinder
            VStack {
                Spacer()

                // Viewfinder frame
                RoundedRectangle(cornerRadius: 16)
                    .stroke(.white.opacity(0.8), lineWidth: 3)
                    .frame(width: 250, height: 250)
                    .background(.clear)

                Spacer()

                // Instructions
                Text("Point camera at enrollment QR code")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(.white)
                    .padding()
                    .background(.ultraThinMaterial, in: Capsule())
                    .padding(.bottom, 48)
            }

            // Cancel button overlay
            VStack {
                HStack {
                    Spacer()
                    Button {
                        viewModel.cancelScanning()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title)
                            .foregroundStyle(.white.opacity(0.8))
                    }
                    .padding()
                }
                Spacer()
            }
        }
    }

    /// Token review before enrollment.
    private func tokenReviewView(_ tokenInfo: EnrollmentTokenInfo) -> some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "checkmark.seal")
                .font(.system(size: 60))
                .foregroundStyle(Color.ztlpBlue)

            Text("Enrollment Token Found")
                .font(.title2.weight(.semibold))

            // Token details
            VStack(alignment: .leading, spacing: 12) {
                tokenRow(label: "Zone", value: tokenInfo.zone, systemImage: "globe")
                tokenRow(label: "Name Service", value: tokenInfo.nsAddress, systemImage: "server.rack")

                if !tokenInfo.relayAddresses.isEmpty {
                    tokenRow(
                        label: "Relays",
                        value: tokenInfo.relayAddresses.joined(separator: ", "),
                        systemImage: "antenna.radiowaves.left.and.right"
                    )
                }

                if let gateway = tokenInfo.gatewayAddress {
                    tokenRow(label: "Gateway", value: gateway, systemImage: "door.left.hand.open")
                }

                tokenRow(
                    label: "Expires",
                    value: tokenInfo.expiryDescription,
                    systemImage: "clock"
                )
            }
            .padding()
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
            .padding(.horizontal, 24)

            Spacer()

            VStack(spacing: 12) {
                Button {
                    viewModel.enroll()
                } label: {
                    Label("Enroll Device", systemImage: "checkmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .controlSize(.large)

                Button {
                    viewModel.reset()
                } label: {
                    Text("Cancel")
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
    }

    /// Enrolling progress.
    private var enrollingView: some View {
        VStack(spacing: 24) {
            Spacer()
            ProgressView()
                .scaleEffect(1.5)
            Text("Enrolling…")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("Generating identity and registering with the zone.")
                .font(.callout)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
            Spacer()
        }
    }

    /// Enrollment success.
    private func successView(_ zoneName: String) -> some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 80))
                .foregroundStyle(Color.ztlpGreen)

            Text("Enrolled!")
                .font(.title.weight(.bold))

            Text("Your device is now enrolled in zone **\(zoneName)**.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            Spacer()

            Button {
                dismiss()
            } label: {
                Text("Done")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.ztlpBlue)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
    }

    /// Enrollment error.
    private func errorView(_ message: String) -> some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 60))
                .foregroundStyle(Color.ztlpOrange)

            Text("Enrollment Failed")
                .font(.title2.weight(.semibold))

            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            Spacer()

            VStack(spacing: 12) {
                Button {
                    viewModel.startScanning()
                } label: {
                    Label("Try Again", systemImage: "arrow.clockwise")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .controlSize(.large)

                Button {
                    viewModel.reset()
                } label: {
                    Text("Cancel")
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
    }

    /// Manual entry sheet.
    private var manualEntrySheet: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Text("Paste your enrollment URI below:")
                    .font(.callout)
                    .foregroundStyle(.secondary)

                TextField("ztlp://enroll/...", text: $manualEntryText, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .font(.callout.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .lineLimit(3...6)
                    .padding(.horizontal)

                Button {
                    showManualEntry = false
                    viewModel.handleManualEntry(manualEntryText)
                } label: {
                    Text("Submit")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.ztlpBlue)
                .disabled(manualEntryText.isEmpty)
                .padding(.horizontal)

                Spacer()
            }
            .padding(.top)
            .navigationTitle("Manual Entry")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showManualEntry = false }
                }
            }
        }
        .presentationDetents([.medium])
    }

    // MARK: - Components

    /// A row showing a token detail field.
    private func tokenRow(label: String, value: String, systemImage: String) -> some View {
        HStack {
            Label(label, systemImage: systemImage)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 120, alignment: .leading)
            Text(value)
                .font(.callout.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }
}

// MARK: - QR Scanner (AVFoundation)

/// UIViewRepresentable wrapping AVCaptureSession for QR code scanning.
struct QRScannerView: UIViewRepresentable {
    let onCodeScanned: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCodeScanned: onCodeScanned)
    }

    func makeUIView(context: Context) -> UIView {
        let view = UIView(frame: .zero)

        let session = AVCaptureSession()
        context.coordinator.session = session

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return view
        }

        if session.canAddInput(input) {
            session.addInput(input)
        }

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(context.coordinator, queue: .main)
            output.metadataObjectTypes = [.qr]
        }

        let previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.videoGravity = .resizeAspectFill
        previewLayer.frame = UIScreen.main.bounds
        view.layer.addSublayer(previewLayer)
        context.coordinator.previewLayer = previewLayer

        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }

        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        context.coordinator.previewLayer?.frame = uiView.bounds
    }

    static func dismantleUIView(_ uiView: UIView, coordinator: Coordinator) {
        coordinator.session?.stopRunning()
    }

    class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let onCodeScanned: (String) -> Void
        var session: AVCaptureSession?
        var previewLayer: AVCaptureVideoPreviewLayer?
        private var hasScanned = false

        init(onCodeScanned: @escaping (String) -> Void) {
            self.onCodeScanned = onCodeScanned
        }

        func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            guard !hasScanned,
                  let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  let code = object.stringValue,
                  code.hasPrefix("ztlp://") else { return }

            hasScanned = true
            session?.stopRunning()

            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            onCodeScanned(code)
        }
    }
}

// MARK: - Previews

#Preview("Idle") {
    EnrollmentView(viewModel: EnrollmentViewModel(configuration: ZTLPConfiguration()))
}
