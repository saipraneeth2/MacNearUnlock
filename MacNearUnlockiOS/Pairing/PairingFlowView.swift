import AVFoundation
import MacNearUnlockShared
import Network
import SwiftUI
import UIKit

@MainActor
final class PairingFlowModel: ObservableObject {
    enum Step: Equatable {
        case choose
        case scanning
        case manual
        case connecting(String)
        case verify(sas: ShortAuthenticationString, macName: String, account: String, fingerprint: String)
        case confirming
        case done(String)
        case failed(String)
    }

    @Published var step: Step = .choose
    private var client: PairingClient?
    private var keyTag: String?
    private var completed = false
    weak var companion: CompanionModel?

    var availabilityError: String? {
        do {
            try BiometricSigner.checkAvailability()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    func handleScanned(_ text: String) {
        guard step == .scanning else { return }
        guard let url = URL(string: text), let invitation = try? PairingInvitation(url: url), let serviceName = invitation.serviceName else {
            step = .failed("That QR code is not a MacNearUnlock pairing invitation.")
            return
        }
        start(invitation: invitation, serviceName: serviceName)
    }

    func startManual(code: String, serviceName: String) {
        do {
            start(invitation: try PairingInvitation(manualCode: code, serviceName: serviceName), serviceName: serviceName)
        } catch {
            step = .failed("That code is not valid. It has 16 characters, like ABCD-EFGH-JKMN-PQRS.")
        }
    }

    private func start(invitation: PairingInvitation, serviceName: String) {
        let tag = "com.macnearunlock.pairing." + UUID().uuidString
        let signer: BiometricSigner
        do {
            signer = try BiometricSigner.create(tag: tag)
        } catch {
            step = .failed(error.localizedDescription)
            return
        }
        keyTag = tag
        let client = PairingClient(invitation: invitation, deviceName: UIDevice.current.name, signer: signer)
        client.onVerificationCode = { [weak self] sas, challenge in
            DispatchQueue.main.async {
                self?.step = .verify(sas: sas, macName: challenge.macName, account: challenge.macUsername, fingerprint: KeyFingerprint.display(challenge.macPublicKey))
            }
        }
        client.onComplete = { [weak self] outcome in
            DispatchQueue.main.async { self?.finish(outcome) }
        }
        client.onFailure = { [weak self] error in
            DispatchQueue.main.async { self?.fail(error) }
        }
        self.client = client
        step = .connecting(serviceName)
        client.start(endpoint: MacBrowser.pairingEndpoint(serviceName: serviceName))
    }

    func confirm() {
        step = .confirming
        Task { await client?.confirm() }
    }

    func reject() {
        client?.cancel(reason: "Verification code did not match on iPhone")
    }

    func cancel() {
        guard !completed else { return }
        client?.cancel()
        client = nil
        if let keyTag { BiometricSigner.delete(tag: keyTag) }
        keyTag = nil
    }

    private func finish(_ outcome: PairingOutcome) {
        guard let keyTag, let companion else { return }
        do {
            try companion.add(outcome: outcome, keyTag: keyTag, biometryState: BiometricSigner.currentBiometryState())
            completed = true
            step = .done(outcome.mac.macName)
        } catch {
            BiometricSigner.delete(tag: keyTag)
            step = .failed("Could not save the pairing: \(error.localizedDescription)")
        }
    }

    private func fail(_ error: PairingError) {
        guard !completed else { return }
        if let keyTag { BiometricSigner.delete(tag: keyTag) }
        keyTag = nil
        switch error {
        case .fingerprintMismatch:
            step = .failed("The Mac that answered does not match the QR code. Pairing was stopped to protect you from interception.")
        case .connectionFailed:
            step = .failed("Could not reach the Mac or the code was wrong. Make sure both are on the same network and the invitation is still open.")
        case .aborted(let reason):
            step = .failed(reason)
        default:
            step = .failed("Pairing failed (\(error)).")
        }
    }
}

struct PairingFlowView: View {
    @EnvironmentObject private var companion: CompanionModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var flow = PairingFlowModel()
    @State private var manualCode = ""
    @State private var selectedService: String?

    var body: some View {
        NavigationStack {
            Group {
                switch flow.step {
                case .choose: choose
                case .scanning: scanning
                case .manual: manual
                case .connecting(let name):
                    ProgressView("Connecting to \(name)…").padding()
                case .verify(let sas, let macName, let account, let fingerprint):
                    verify(sas: sas, macName: macName, account: account, fingerprint: fingerprint)
                case .confirming:
                    ProgressView("Waiting for Face ID and the Mac's confirmation…").padding()
                case .done(let name):
                    ContentUnavailableView {
                        Label("Paired with \(name)", systemImage: "checkmark.seal.fill")
                    } description: {
                        Text("Open this app and tap Approve with Face ID whenever you want to unlock or test.")
                    } actions: {
                        Button("Done") { dismiss() }.buttonStyle(.borderedProminent)
                    }
                case .failed(let message):
                    ContentUnavailableView {
                        Label("Pairing Stopped", systemImage: "xmark.octagon")
                    } description: {
                        Text(message)
                    } actions: {
                        Button("Start Over") { flow.step = .choose }.buttonStyle(.borderedProminent)
                    }
                }
            }
            .navigationTitle("Pair a Mac")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
        .onAppear { flow.companion = companion }
        .onDisappear { flow.cancel() }
    }

    private var choose: some View {
        List {
            if let error = flow.availabilityError {
                Section { Label(error, systemImage: "faceid").foregroundStyle(.red) }
            }
            Section {
                Button { flow.step = .scanning } label: { Label("Scan QR Code", systemImage: "qrcode.viewfinder") }
                Button { flow.step = .manual } label: { Label("Enter Code Manually", systemImage: "keyboard") }
            } footer: {
                Text("On your Mac choose Pair iPhone… in the MacNearUnlock menu. A new Face ID–protected key is created on this iPhone for each Mac; it never leaves the Secure Enclave.")
            }
        }
        .disabled(flow.availabilityError != nil)
    }

    private var scanning: some View {
        VStack(spacing: 16) {
            QRScannerView { flow.handleScanned($0) }
                .frame(height: 340)
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .padding()
                .accessibilityLabel("Camera viewfinder for the pairing QR code")
            Text("Point the camera at the QR code on your Mac.").foregroundStyle(.secondary)
            Button("Enter Code Instead") { flow.step = .manual }
            Spacer()
        }
    }

    private var manual: some View {
        Form {
            Section("Mac showing a pairing code") {
                if companion.browser.pairingServices.isEmpty {
                    Text("Looking for Macs in pairing mode on this network…").foregroundStyle(.secondary)
                }
                Picker("Mac", selection: $selectedService) {
                    Text("Choose…").tag(String?.none)
                    ForEach(companion.browser.pairingServices, id: \.self) { Text($0).tag(String?.some($0)) }
                }
            }
            Section {
                TextField("ABCD-EFGH-JKMN-PQRS", text: $manualCode)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
            } header: {
                Text("Pairing code")
            } footer: {
                Text("Without the QR code, comparing the verification code on both screens is what protects against a look-alike Mac.")
            }
            Button("Connect") {
                if let selectedService { flow.startManual(code: manualCode, serviceName: selectedService) }
            }
            .disabled(selectedService == nil || manualCode.filter { $0.isLetter || $0.isNumber }.count != 16)
        }
    }

    private func verify(sas: ShortAuthenticationString, macName: String, account: String, fingerprint: String) -> some View {
        ScrollView {
            VStack(spacing: 18) {
                Text("Compare with your Mac").font(.title2.bold())
                Text("Continue only if \(macName) shows exactly this code and these words.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                Text(sas.digits)
                    .font(.system(size: 44, weight: .bold, design: .monospaced))
                    .accessibilityLabel("Verification code \(sas.digits)")
                Text(sas.phrase).font(.title3)
                VStack(spacing: 4) {
                    Text("Mac account: \(account)")
                    Text("Mac key: \(fingerprint)").font(.caption.monospaced())
                }
                .foregroundStyle(.secondary)
                Button {
                    flow.confirm()
                } label: {
                    Label("Codes Match — Confirm with Face ID", systemImage: "faceid").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                Button("They Don't Match", role: .destructive) { flow.reject() }
            }
            .padding()
        }
    }
}

// MARK: - QR scanner

struct QRScannerView: UIViewControllerRepresentable {
    var onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onCode = onCode
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var delivered = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            DispatchQueue.main.async {
                guard let self else { return }
                if granted { self.configure() } else { self.showMessage("Camera access is off. Enter the code manually instead.") }
            }
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = self.session
        DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else {
            showMessage("No camera available. Enter the code manually instead.")
            return
        }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        preview = layer
        let session = self.session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    private func showMessage(_ text: String) {
        let label = UILabel()
        label.text = text
        label.textColor = .white
        label.numberOfLines = 0
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
        ])
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !delivered,
              let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let value = object.stringValue
        else { return }
        delivered = true
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        onCode?(value)
    }
}
