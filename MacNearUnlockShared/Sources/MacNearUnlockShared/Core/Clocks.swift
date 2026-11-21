import Foundation

/// A point on a monotonic timeline (nanoseconds). Unaffected by wall-clock changes,
/// NTP adjustments, or a user editing the date. On Darwin `CLOCK_MONOTONIC` keeps
/// counting while the machine sleeps, so a challenge issued before sleep is
/// correctly seen as old afterwards.
public struct MonotonicInstant: Comparable, Hashable, Sendable {
    public let nanoseconds: UInt64

    public init(nanoseconds: UInt64) {
        self.nanoseconds = nanoseconds
    }

    public func advanced(bySeconds seconds: TimeInterval) -> MonotonicInstant {
        precondition(seconds >= 0)
        return MonotonicInstant(nanoseconds: nanoseconds &+ UInt64(seconds * 1_000_000_000))
    }

    public func seconds(since earlier: MonotonicInstant) -> TimeInterval {
        guard nanoseconds >= earlier.nanoseconds else { return 0 }
        return TimeInterval(nanoseconds - earlier.nanoseconds) / 1_000_000_000
    }

    public static func < (lhs: MonotonicInstant, rhs: MonotonicInstant) -> Bool {
        lhs.nanoseconds < rhs.nanoseconds
    }
}

public protocol MonotonicClock: Sendable {
    func now() -> MonotonicInstant
}

public protocol WallClock: Sendable {
    func now() -> Date
}

public struct SystemMonotonicClock: MonotonicClock {
    public init() {}
    public func now() -> MonotonicInstant {
        MonotonicInstant(nanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC))
    }
}

public struct SystemWallClock: WallClock {
    public init() {}
    public func now() -> Date { Date() }
}

extension Date {
    /// Milliseconds since 1970, the integer representation used on the wire and in
    /// signing bytes (avoids floating-point encoding ambiguity).
    public var millisecondsSince1970: UInt64 {
        let value = timeIntervalSince1970 * 1000
        return value <= 0 ? 0 : UInt64(value.rounded(.down))
    }

    public init(millisecondsSince1970 ms: UInt64) {
        self.init(timeIntervalSince1970: TimeInterval(ms) / 1000)
    }
}
