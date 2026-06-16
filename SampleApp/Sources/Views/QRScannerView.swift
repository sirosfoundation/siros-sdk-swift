// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

#if canImport(AVFoundation)
import AVFoundation
#endif

/// QR code scanner using the device camera.
struct QRScannerView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var pasteUri = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ZStack {
                    #if targetEnvironment(simulator)
                    simulatorFallback
                    #else
                    CameraQRScanner { code in
                        // Only accept wallet-relevant URIs
                        if isWalletUri(code) {
                            viewModel.handleQrResult(code)
                        }
                    }
                    #endif

                    // Viewfinder overlay
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(.white, lineWidth: 3)
                        .frame(width: 250, height: 250)
                        .shadow(radius: 8)
                }

                // Paste URI fallback (always visible, like Kotlin)
                VStack(spacing: 8) {
                    Text("Or paste a URI:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        TextField("openid-credential-offer://...", text: $pasteUri)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        Button("Redeem") {
                            let trimmed = pasteUri.trimmingCharacters(in: .whitespacesAndNewlines)
                            guard !trimmed.isEmpty else { return }
                            viewModel.handleQrResult(trimmed)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(pasteUri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                .padding()
                .background(.regularMaterial)
            }
            .ignoresSafeArea(edges: .top)
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { viewModel.closeQrScanner() }
                }
            }
        }
    }

    private var simulatorFallback: some View {
        VStack(spacing: 16) {
            Image(systemName: "camera.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Camera not available in Simulator")
                .font(.headline)
            Text("Use the paste field below to enter a URI.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black.opacity(0.8))
    }

    /// Only accept QR codes that are credential offers or presentation requests.
    private func isWalletUri(_ value: String) -> Bool {
        switch DeepLinkClassifier.classify(value) {
        case .credentialOffer, .presentationRequest:
            return true
        default:
            return false
        }
    }
}

// MARK: - Camera QR Scanner (UIKit bridge)

#if canImport(UIKit) && canImport(AVFoundation)
import UIKit

struct CameraQRScanner: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let vc = QRScannerViewController()
        vc.onCodeScanned = onCodeScanned
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}
}

final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCodeScanned: ((String) -> Void)?
    private let captureSession = AVCaptureSession()
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()

        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video),
              let videoInput = try? AVCaptureDeviceInput(device: videoCaptureDevice),
              captureSession.canAddInput(videoInput) else {
            return
        }

        captureSession.addInput(videoInput)

        let metadataOutput = AVCaptureMetadataOutput()
        guard captureSession.canAddOutput(metadataOutput) else { return }
        captureSession.addOutput(metadataOutput)
        metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
        metadataOutput.metadataObjectTypes = [.qr]

        let previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
        previewLayer.frame = view.layer.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.captureSession.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession.isRunning {
            captureSession.stopRunning()
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasScanned,
              let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let stringValue = object.stringValue else {
            return
        }
        hasScanned = true
        captureSession.stopRunning()
        onCodeScanned?(stringValue)
    }
}
#endif
