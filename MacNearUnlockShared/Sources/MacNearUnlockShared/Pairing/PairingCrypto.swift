import CryptoKit
import Foundation

public enum PairingError: Error, Equatable, Sendable {
    case invalidInvitation
    case invalidCode
    case fingerprintMismatch
    case badTranscriptSignature
    case badConfirmationSignature
    case badCompletionSignature
    case unexpectedMessage
    case aborted(String)
    case expired
    case keyAgreementFailed
    case storageFailed
    case connectionFailed(String)
}

/// Out-of-band pairing invitation shown by the Mac as a QR code and as a typed code.
///
/// * `code` — 80-bit one-time secret. It keys the pairing TLS-PSK tunnel, so only
///   someone who saw the Mac's screen can even reach the pairing protocol. The
///   Mac burns the invitation after `MNUProtocol.maxPairingHandshakeFailures` failed
///   TLS handshakes or after `MNUProtocol.pairingWindow` seconds.
/// * `macFingerprint` — SHA-256 of the Mac identity key, present only in the QR
///   code. The iPhone refuses a Mac key that does not match it.
public struct PairingInvitation: Equatable, Sendable {
    public static let codeLength = 10
    public static let pskIdentity = "mnu1-pair"
    public static let urlScheme = "macnearunlock"

    public let code: Data
    public let macFingerprint: Data?
    public let serviceName: String?

    public init(code: Data, macFingerprint: Data?, serviceName: String?) throws {
        guard code.count == PairingInvitation.codeLength else { throw PairingError.invalidCode }
        if let macFingerprint, macFingerprint.count != 32 { throw PairingError.invalidInvitation }
        if let serviceName, serviceName.isEmpty || serviceName.utf8.count > 63 { throw PairingError.invalidInvitation }
        self.code = code
        self.macFingerprint = macFingerprint
        self.serviceName = serviceName
    }

    public static func generate(macPublicKey: Data, serviceName: String) -> PairingInvitation {
        // Force-try is safe: sizes are constructed to be valid.
        try! PairingInvitation(
            code: SecureRandom.bytes(codeLength),
            macFingerprint: KeyFingerprint.sha256(macPublicKey),
            serviceName: String(serviceName.prefix(63))
        )
    }

    /// "ABCD-EFGH-JKMN-PQRS" (Crockford Base32, 16 characters, 80 bits).
    public var displayCode: String {
        let raw = CrockfordBase32.encode(code)
        return stride(from: 0, to: raw.count, by: 4).map { offset -> String in
            let start = raw.index(raw.startIndex, offsetBy: offset)
            let end = raw.index(start, offsetBy: min(4, raw.count - offset))
            return String(raw[start..<end])
        }.joined(separator: "-")
    }

    public var url: URL {
        var components = URLComponents()
        components.scheme = PairingInvitation.urlScheme
        components.host = "pair"
        var items = [
            URLQueryItem(name: "v", value: String(MNUProtocol.protocolVersion)),
            URLQueryItem(name: "c", value: CrockfordBase32.encode(code)),
        ]
        if let macFingerprint { items.append(URLQueryItem(name: "f", value: macFingerprint.base64URLEncoded)) }
        if let serviceName { items.append(URLQueryItem(name: "n", value: serviceName)) }
        components.queryItems = items
        return components.url!
    }

    /// Parses a scanned QR payload. Any deviation is rejected.
    public init(url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == PairingInvitation.urlScheme,
              components.host == "pair",
              let items = components.queryItems,
              items.count <= 4
        else { throw PairingError.invalidInvitation }
        var values: [String: String] = [:]
        for item in items {
            guard let value = item.value, values[item.name] == nil else { throw PairingError.invalidInvitation }
            values[item.name] = value
        }
        guard values["v"] == String(MNUProtocol.protocolVersion),
              let codeText = values["c"], let code = CrockfordBase32.decode(codeText),
              let fingerprintText = values["f"], let fingerprint = Data(base64URLEncoded: fingerprintText)
        else { throw PairingError.invalidInvitation }
        try self.init(code: code, macFingerprint: fingerprint, serviceName: values["n"])
    }

    /// Manual entry path (no camera). Without the QR fingerprint the user's
    /// comparison of the verification code on both screens is the MITM defence.
    public init(manualCode: String, serviceName: String?) throws {
        guard let code = CrockfordBase32.decode(manualCode) else { throw PairingError.invalidCode }
        try self.init(code: code, macFingerprint: nil, serviceName: serviceName)
    }

    /// TLS-PSK for the pairing tunnel.
    public var pskKey: Data {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: code),
            salt: Data("MacNearUnlock pairing salt v1".utf8),
            info: Data(SigningDomain.pairingPSK.rawValue.utf8),
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Data($0) }
    }
}

/// Short authentication string shown on both devices after the key exchange.
public struct ShortAuthenticationString: Equatable, Sendable {
    /// "123 456"
    public let digits: String
    /// e.g. ["amber", "orbit", "tulip", "kayak"]
    public let words: [String]

    public var phrase: String { words.joined(separator: " · ") }
}

public enum PairingCrypto {
    /// Canonical pairing transcript: every field of both handshake messages (except
    /// the Mac's signature) plus the TLS exporter of the pairing tunnel.
    public static func transcript(hello: PairHello, challenge: PairChallenge, exporter: Data) -> Data {
        var writer = CanonicalWriter(domain: .pairingTranscript)
        writer.append(1, uint16: hello.protocolVersion)
        writer.append(2, uuid: hello.deviceID)
        writer.append(3, string: hello.deviceName)
        writer.append(4, hello.devicePublicKey)
        writer.append(5, hello.ephemeralPublicKey)
        writer.append(6, hello.nonce)
        writer.append(7, uint16: challenge.protocolVersion)
        writer.append(8, uuid: challenge.pairingID)
        writer.append(9, uuid: challenge.macID)
        writer.append(10, string: challenge.macName)
        writer.append(11, string: challenge.macUsername)
        writer.append(12, challenge.macPublicKey)
        writer.append(13, challenge.ephemeralPublicKey)
        writer.append(14, challenge.nonce)
        writer.append(15, exporter)
        return writer.bytes
    }

    public static func transcriptHash(hello: PairHello, challenge: PairChallenge, exporter: Data) -> Data {
        Data(SHA256.hash(data: transcript(hello: hello, challenge: challenge, exporter: exporter)))
    }

    public static func confirmBytes(transcriptHash: Data) -> Data {
        var writer = CanonicalWriter(domain: .pairingConfirm)
        writer.append(1, transcriptHash)
        return writer.bytes
    }

    public static func completeBytes(transcriptHash: Data, pairingID: UUID) -> Data {
        var writer = CanonicalWriter(domain: .pairingComplete)
        writer.append(1, transcriptHash)
        writer.append(2, uuid: pairingID)
        return writer.bytes
    }

    public static func shortAuthenticationString(transcriptHash: Data) -> ShortAuthenticationString {
        var writer = CanonicalWriter(domain: .shortAuthString)
        writer.append(1, transcriptHash)
        let digest = Array(SHA256.hash(data: writer.bytes))
        let number = (UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])) % 1_000_000
        let padded = String(format: "%06u", number)
        let digits = String(padded.prefix(3)) + " " + String(padded.suffix(3))
        let words = digest[4..<8].map { VerificationWords.list[Int($0)] }
        return ShortAuthenticationString(digits: digits, words: words)
    }

    /// Per-pairing 256-bit channel key from the ephemeral X25519 exchange, salted
    /// with the transcript hash. Never derived from the (short) pairing code alone,
    /// so a recorded pairing session cannot be decrypted by guessing the code.
    public static func channelKey(privateKey: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: Data, transcriptHash: Data) throws -> Data {
        guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey),
              let shared = try? privateKey.sharedSecretFromKeyAgreement(with: peer)
        else { throw PairingError.keyAgreementFailed }
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: transcriptHash,
            sharedInfo: Data(SigningDomain.channelPSK.rawValue.utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }
}

/// HMAC-SHA256 binders over the TLS exporter. They prove that the peer holds the
/// pairing's channel key *within this TLS session*, and tie the claimed pairing ID
/// to the PSK actually used (the TLS layer alone does not report which PSK the
/// client selected).
public enum ChannelBinding {
    public static func clientBinder(channelKey: Data, pairingID: UUID, deviceID: UUID, exporter: Data) -> Data {
        var writer = CanonicalWriter(domain: .clientHelloBinder)
        writer.append(1, uuid: pairingID)
        writer.append(2, uuid: deviceID)
        writer.append(3, exporter)
        return Data(HMAC<SHA256>.authenticationCode(for: writer.bytes, using: SymmetricKey(data: channelKey)))
    }

    public static func serverBinder(channelKey: Data, pairingID: UUID, macID: UUID, exporter: Data) -> Data {
        var writer = CanonicalWriter(domain: .serverHelloBinder)
        writer.append(1, uuid: pairingID)
        writer.append(2, uuid: macID)
        writer.append(3, exporter)
        return Data(HMAC<SHA256>.authenticationCode(for: writer.bytes, using: SymmetricKey(data: channelKey)))
    }

    public static func matches(_ received: Data, expected: Data) -> Bool {
        ConstantTime.equals(received, expected)
    }
}

// MARK: - Encodings

public enum CrockfordBase32 {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    public static func encode(_ data: Data) -> String {
        var output = ""
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                output.append(alphabet[Int((buffer >> UInt32(bits - 5)) & 0x1F)])
                bits -= 5
            }
        }
        if bits > 0 {
            output.append(alphabet[Int((buffer << UInt32(5 - bits)) & 0x1F)])
        }
        return output
    }

    /// Decodes a code of exactly `PairingInvitation.codeLength` bytes. Accepts
    /// lowercase, hyphens and spaces; maps the usual look-alikes (O→0, I/L→1).
    public static func decode(_ text: String, expectedBytes: Int = PairingInvitation.codeLength) -> Data? {
        let cleaned = text.uppercased().filter { $0 != "-" && $0 != " " }.map { character -> Character in
            switch character {
            case "O": return "0"
            case "I", "L": return "1"
            default: return character
            }
        }
        guard cleaned.count == (expectedBytes * 8 + 4) / 5 else { return nil }
        var buffer: UInt32 = 0
        var bits = 0
        var output = Data()
        for character in cleaned {
            guard let value = alphabet.firstIndex(of: character) else { return nil }
            buffer = (buffer << 5) | UInt32(value)
            bits += 5
            if bits >= 8 {
                output.append(UInt8((buffer >> UInt32(bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        // Leftover padding bits must be zero for a canonical encoding.
        guard bits < 5, buffer & ((1 << UInt32(bits)) - 1) == 0, output.count == expectedBytes else { return nil }
        return output
    }
}

extension Data {
    public var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public init?(base64URLEncoded text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        self.init(base64Encoded: base64)
    }
}
