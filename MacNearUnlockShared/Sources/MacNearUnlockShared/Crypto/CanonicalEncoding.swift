import Foundation

/// Domain-separation labels. Every signed or MACed byte string starts with one of
/// these, so a signature produced for one purpose can never verify for another.
public enum SigningDomain: String, CaseIterable, Sendable {
    case unlockRequest = "MacNearUnlock/v1/unlock-request"
    case unlockApproval = "MacNearUnlock/v1/unlock-approval"
    case pairingTranscript = "MacNearUnlock/v1/pairing-transcript"
    case pairingConfirm = "MacNearUnlock/v1/pairing-confirm"
    case pairingComplete = "MacNearUnlock/v1/pairing-complete"
    case clientHelloBinder = "MacNearUnlock/v1/client-hello"
    case serverHelloBinder = "MacNearUnlock/v1/server-hello"
    case shortAuthString = "MacNearUnlock/v1/sas"
    case channelPSK = "MacNearUnlock/v1/channel-psk"
    case pairingPSK = "MacNearUnlock/v1/pairing-psk"
}

/// Deterministic, unambiguous binary encoding used for every signature and MAC.
///
/// Layout:
///
///     "MNU1" | u16be(len(domain)) | domain
///     then for each field, in strictly increasing tag order:
///     u8 tag | u32be(len(value)) | value
///
/// Properties that JSON cannot guarantee:
/// * one byte string per logical value (no whitespace, key-order, number or
///   escaping variants);
/// * length prefixes make field boundaries unambiguous, so ("ab","c") and
///   ("a","bc") encode differently;
/// * tags must strictly increase, so fields cannot be reordered, repeated or
///   silently omitted by one side only;
/// * strings are NFC-normalised UTF-8, so visually identical names in different
///   Unicode forms cannot produce different signing bytes on each device.
public struct CanonicalWriter: Sendable {
    public static let magic = Data("MNU1".utf8)

    public private(set) var bytes: Data
    private var lastTag: Int = -1

    public init(domain: SigningDomain) {
        bytes = CanonicalWriter.magic
        let label = Data(domain.rawValue.utf8)
        precondition(label.count <= Int(UInt16.max))
        bytes.append(contentsOf: UInt16(label.count).bigEndianBytes)
        bytes.append(label)
    }

    public mutating func append(_ tag: UInt8, _ value: Data) {
        precondition(Int(tag) > lastTag, "Canonical tags must strictly increase")
        precondition(value.count <= Int(UInt32.max))
        lastTag = Int(tag)
        bytes.append(tag)
        bytes.append(contentsOf: UInt32(value.count).bigEndianBytes)
        bytes.append(value)
    }

    public mutating func append(_ tag: UInt8, string: String) {
        append(tag, Data(string.precomposedStringWithCanonicalMapping.utf8))
    }

    public mutating func append(_ tag: UInt8, uint64 value: UInt64) {
        append(tag, Data(value.bigEndianBytes))
    }

    public mutating func append(_ tag: UInt8, uint16 value: UInt16) {
        append(tag, Data(value.bigEndianBytes))
    }

    public mutating func append(_ tag: UInt8, uuid: UUID) {
        append(tag, uuid.rawBytes)
    }
}

extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: self.bigEndian) { Array($0) }
    }
}
