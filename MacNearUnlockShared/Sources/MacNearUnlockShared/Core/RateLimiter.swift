import Foundation

/// Token bucket over a monotonic clock. Not thread-safe; owners confine it to a
/// queue or lock.
public struct TokenBucket: Sendable {
    public let capacity: Double
    public let refillPerSecond: Double
    private var tokens: Double
    private var lastRefill: MonotonicInstant?

    public init(capacity: Double, refillPerSecond: Double) {
        precondition(capacity >= 1 && refillPerSecond > 0)
        self.capacity = capacity
        self.refillPerSecond = refillPerSecond
        self.tokens = capacity
    }

    public mutating func tryConsume(at now: MonotonicInstant, cost: Double = 1) -> Bool {
        if let lastRefill {
            tokens = min(capacity, tokens + now.seconds(since: lastRefill) * refillPerSecond)
        }
        lastRefill = now
        guard tokens >= cost else { return false }
        tokens -= cost
        return true
    }
}

/// Keyed sliding-window counter: at most `limit` events per `window` seconds per key.
public struct SlidingWindowLimiter<Key: Hashable & Sendable>: Sendable {
    public let limit: Int
    public let window: TimeInterval
    private var events: [Key: [MonotonicInstant]] = [:]

    public init(limit: Int, window: TimeInterval) {
        precondition(limit > 0 && window > 0)
        self.limit = limit
        self.window = window
    }

    public mutating func allow(_ key: Key, at now: MonotonicInstant) -> Bool {
        var recent = (events[key] ?? []).filter { now.seconds(since: $0) < window }
        guard recent.count < limit else {
            events[key] = recent
            return false
        }
        recent.append(now)
        events[key] = recent
        return true
    }

    public mutating func reset(_ key: Key) {
        events[key] = nil
    }
}
