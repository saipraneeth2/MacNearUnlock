import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import MacNearUnlockShared
import SwiftUI

struct PairingWindowView: View {
    @EnvironmentObject private var model: AppModel
    /// Closes the hosting window (provided by `PairingWindowPresenter`).
    var onClose: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            switch model.pairing {
            case .idle, .starting:
                ProgressView("Opening pairing invitation…")
                    .padding(40)
            case .waiting(let invitation):
                waiting(invitation)
            case .confirm(let sas, let name, let fingerprint, let phoneConfirmed, let macConfirmed):
                confirm(sas: sas, deviceName: name, fingerprint: fingerprint, phoneConfirmed: phoneConfirmed, macConfirmed: macConfirmed)
            case .done(let name):
                Image(systemName: "checkmark.seal.fill").font(.system(size: 48)).foregroundStyle(.green)
                Text("Paired with \(name)").font(.title2.bold())
                Text("Approvals from this iPhone will be verified against its pinned Secure Enclave key.")
                    .multilineTextAlignment(.center).foregroundStyle(.secondary)
                Button("Done") { close() }.keyboardShortcut(.defaultAction)
            case .failed(let message):
                Image(systemName: "xmark.octagon.fill").font(.system(size: 48)).foregroundStyle(.red)
                Text("Pairing stopped").font(.title2.bold())
                Text(message).multilineTextAlignment(.center).foregroundStyle(.secondary)
                HStack {
                    Button("Close") { close() }
                    Button("Try Again") { model.startPairing() }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(28)
        .frame(width: 460)
        .onAppear {
            if case .idle = model.pairing { model.startPairing() }
            if case .done = model.pairing { model.startPairing() }
            if case .failed = model.pairing { model.startPairing() }
        }
        .onDisappear { model.cancelPairing() }
    }

    @ViewBuilder
    private func waiting(_ invitation: PairingInvitation) -> some View {
        Label("MacNearUnlock runs in the menu bar — look for the lock icon at the top right of your screen.", systemImage: "menubar.arrow.up.rectangle")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        Text("Pair an iPhone").font(.title2.bold())
        Text("In MacNearUnlock on your iPhone, tap + and scan this code.")
            .foregroundStyle(.secondary)
        if let image = QRCode.image(for: invitation.url.absoluteString) {
            Image(nsImage: image)
                .interpolation(.none)
                .resizable()
                .frame(width: 220, height: 220)
                .padding(10)
                .background(Color.white, in: RoundedRectangle(cornerRadius: 12))
                .accessibilityLabel("Pairing QR code")
        }
        VStack(spacing: 4) {
            Text("No camera? Enter this code:").font(.caption).foregroundStyle(.secondary)
            Text(invitation.displayCode)
                .font(.system(.title2, design: .monospaced).weight(.semibold))
                .textSelection(.enabled)
                .accessibilityLabel("Pairing code \(invitation.displayCode.map { String($0) }.joined(separator: " "))")
        }
        if let identity = model.identity {
            Text("Mac key fingerprint: \(identity.fingerprint)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
        }
        Text("This invitation works once, expires in \(Int(MNUProtocol.pairingWindow / 60)) minutes and is burned after \(MNUProtocol.maxPairingHandshakeFailures) wrong attempts.")
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        Button("Cancel") { close() }
    }

    @ViewBuilder
    private func confirm(sas: ShortAuthenticationString, deviceName: String, fingerprint: String, phoneConfirmed: Bool, macConfirmed: Bool) -> some View {
        Text("Compare with your iPhone").font(.title2.bold())
        Text("“\(deviceName)” wants to pair. Trust it only if your iPhone shows exactly the same code and words.")
            .multilineTextAlignment(.center)
            .foregroundStyle(.secondary)
        Text(sas.digits)
            .font(.system(size: 44, weight: .bold, design: .monospaced))
            .accessibilityLabel("Verification code \(sas.digits)")
        Text(sas.phrase).font(.title3)
        Text("iPhone key fingerprint: \(fingerprint)")
            .font(.caption.monospaced())
            .foregroundStyle(.secondary)
        VStack(alignment: .leading, spacing: 6) {
            Label(macConfirmed ? "Confirmed on this Mac" : "Waiting for your confirmation on this Mac", systemImage: macConfirmed ? "checkmark.circle.fill" : "circle")
            Label(phoneConfirmed ? "Confirmed on iPhone with Face ID" : "Waiting for Face ID confirmation on iPhone", systemImage: phoneConfirmed ? "checkmark.circle.fill" : "circle")
        }
        .font(.callout)
        HStack {
            Button("Codes Don't Match") { model.rejectPairingCode() }
            Button("Codes Match — Trust This iPhone") { model.confirmPairingCode() }
                .keyboardShortcut(.defaultAction)
                .disabled(macConfirmed)
        }
    }

    private func close() {
        model.cancelPairing()
        onClose()
    }
}

enum QRCode {
    static func image(for text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        guard let cgImage = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: scaled.extent.width, height: scaled.extent.height))
    }
}
