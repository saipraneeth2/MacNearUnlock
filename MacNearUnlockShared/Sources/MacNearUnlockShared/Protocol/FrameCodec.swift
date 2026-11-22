import Foundation

public enum FrameError: Error, Equatable, Sendable {
    case emptyFrame
    case frameTooLarge(Int)
    case malformedHeader
    case malformedBody
    case invalidMessage(String)
}

/// Length-prefixed framing: `u32be(length) | JSON(WireMessage)`.
///
/// JSON is used only as a transport container. Nothing is ever signed or verified
/// over JSON bytes; signatures cover `CanonicalWriter` output rebuilt locally.
public enum FrameCodec {
    public static let headerLength = 4

    public static func encode(_ message: WireMessage) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let body = try encoder.encode(message)
        guard !body.isEmpty else { throw FrameError.emptyFrame }
        guard body.count <= MNUProtocol.maxFrameLength else { throw FrameError.frameTooLarge(body.count) }
        var frame = Data(UInt32(body.count).bigEndianBytes)
        frame.append(body)
        return frame
    }

    /// Parses and bounds-checks a frame header before any body bytes are read, so
    /// a hostile length can never cause a large allocation.
    public static func bodyLength(fromHeader header: Data) throws -> Int {
        guard header.count == headerLength else { throw FrameError.malformedHeader }
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0 else { throw FrameError.emptyFrame }
        guard length <= MNUProtocol.maxFrameLength else { throw FrameError.frameTooLarge(length) }
        return length
    }

    public static func decodeBody(_ body: Data) throws -> WireMessage {
        guard !body.isEmpty else { throw FrameError.emptyFrame }
        guard body.count <= MNUProtocol.maxFrameLength else { throw FrameError.frameTooLarge(body.count) }
        let message: WireMessage
        do {
            message = try JSONDecoder().decode(WireMessage.self, from: body)
        } catch {
            throw FrameError.malformedBody
        }
        do {
            try message.validate()
        } catch {
            throw FrameError.invalidMessage(message.typeName)
        }
        return message
    }
}

/// Incremental decoder for byte streams (used by tests and any transport that does
/// not deliver exact-length reads).
public struct FrameAccumulator: Sendable {
    private var buffer = Data()

    public init() {}

    public mutating func append(_ data: Data) throws -> [WireMessage] {
        buffer.append(data)
        var messages: [WireMessage] = []
        while buffer.count >= FrameCodec.headerLength {
            let length = try FrameCodec.bodyLength(fromHeader: Data(buffer.prefix(FrameCodec.headerLength)))
            guard buffer.count >= FrameCodec.headerLength + length else { break }
            let body = Data(buffer.dropFirst(FrameCodec.headerLength).prefix(length))
            buffer = Data(buffer.dropFirst(FrameCodec.headerLength + length))
            messages.append(try FrameCodec.decodeBody(body))
        }
        return messages
    }
}
