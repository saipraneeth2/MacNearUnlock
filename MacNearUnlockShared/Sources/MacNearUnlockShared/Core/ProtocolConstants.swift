import Foundation

/// Fixed protocol parameters. Changing any value that affects the wire format or
/// signing bytes requires bumping `protocolVersion`.
public enum MNUProtocol {
    /// Wire and signing format version. Peers reject any other value.
    public static let protocolVersion: UInt16 = 1

    /// Bonjour service for paired sessions (TLS-PSK keyed per pairing).
    public static let serviceType = "_mnunlock._tcp"
    /// Bonjour service advertised only while the Mac shows a pairing invitation.
    public static let pairingServiceType = "_mnupair._tcp"
    /// Preferred listening port for paired sessions; falls back to any free port.
    public static let preferredPort: UInt16 = 47_311

    /// Upper bound for one framed message, header excluded. Every legitimate
    /// message is far below 4 KiB; anything larger is hostile or broken.
    public static let maxFrameLength = 16 * 1024

    /// Challenge nonce size: 256 bits.
    public static let nonceLength = 32
    /// Uncompressed X9.63 P-256 public key: 0x04 || X || Y.
    public static let p256PublicKeyLength = 65
    /// Raw Curve25519 public key.
    public static let x25519PublicKeyLength = 32
    /// HMAC-SHA256 output.
    public static let binderLength = 32
    /// DER ECDSA P-256 signatures are 8...72 bytes.
    public static let signatureLengthRange = 8...72

    /// Approval lifetime bounds (seconds). The Mac clamps its setting to this range
    /// and the iPhone rejects requests whose advertised lifetime exceeds the maximum.
    public static let approvalLifetimeRange: ClosedRange<TimeInterval> = 10...120
    public static let defaultApprovalLifetime: TimeInterval = 30
    /// Allowed wall-clock disagreement between Mac and iPhone.
    public static let clockSkewTolerance: TimeInterval = 120
    /// How long consumed/invalidated request IDs are remembered for replay detection.
    /// Must exceed the maximum lifetime plus skew.
    public static let replayRetention: TimeInterval = 600

    /// A connected peer must send its hello within this time or be dropped.
    public static let helloTimeout: TimeInterval = 5
    /// Pairing invitations expire after this long.
    public static let pairingWindow: TimeInterval = 120
    /// Failed TLS handshakes tolerated per pairing invitation before it is burned.
    public static let maxPairingHandshakeFailures = 3

    /// Maximum simultaneous connections accepted by the Mac.
    public static let maxConnections = 8

    /// TLS exporter label used for channel binding (RFC 5705).
    public static let exporterLabel = "EXPORTER-MacNearUnlock-v1"
    public static let exporterLength = 32

    /// String limits (UTF-8 bytes) for untrusted input.
    public static let maxNameBytes = 128
    public static let maxUsernameBytes = 64
    public static let maxShortTextBytes = 256
}
