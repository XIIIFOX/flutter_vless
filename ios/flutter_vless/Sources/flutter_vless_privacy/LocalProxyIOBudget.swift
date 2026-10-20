import Foundation

/// One monotonic deadline shared by all operations in a native health probe.
/// Cancellation must be a cheap, nonblocking ownership check.
public struct LocalProxyIOBudget {
    private let deadline: TimeInterval
    private let now: () -> TimeInterval
    private let isCancelled: () -> Bool

    public init(timeout: TimeInterval, isCancelled: @escaping () -> Bool = { false }) {
        self.init(timeout: timeout, isCancelled: isCancelled, now: { ProcessInfo.processInfo.systemUptime })
    }

    // Actual production arithmetic is injectable without a wall clock or I/O.
    init(timeout: TimeInterval, isCancelled: @escaping () -> Bool = { false },
         now: @escaping () -> TimeInterval) {
        let start = now()
        let end = start + timeout
        deadline = start.isFinite && timeout.isFinite && timeout > 0 && end.isFinite && end > start ? end : -.infinity
        self.now = now
        self.isCancelled = isCancelled
    }

    private init(deadline: TimeInterval, now: @escaping () -> TimeInterval,
                 isCancelled: @escaping () -> Bool) {
        self.deadline = deadline; self.now = now; self.isCancelled = isCancelled
    }

    public var canContinue: Bool {
        let current = now()
        return current.isFinite && current < deadline && !isCancelled()
    }

    /// A phase may shorten the caller's deadline; it never refreshes it.
    public func limited(to timeout: TimeInterval) -> LocalProxyIOBudget {
        let current = now(), end = current + timeout
        let valid = current.isFinite && timeout.isFinite && timeout > 0 && end.isFinite && end > current
        return LocalProxyIOBudget(deadline: valid ? min(deadline, end) : -.infinity,
                                  now: now, isCancelled: isCancelled)
    }

    func waitMilliseconds(maximum: Int32 = 100) -> Int32 {
        guard maximum > 0, canContinue else { return 0 }
        let remaining = deadline - now()
        guard remaining.isFinite, remaining > 0 else { return 0 }
        return Int32(max(1, min(Double(maximum), (remaining * 1000).rounded(.up))))
    }
}
