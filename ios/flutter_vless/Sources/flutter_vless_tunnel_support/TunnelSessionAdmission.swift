import Foundation

/// One provider session owns every asynchronous startup/recovery callback.
/// Stop revokes that ownership synchronously, independently of native drains.
public final class TunnelSessionAdmission: @unchecked Sendable {
    public struct Epoch: Equatable, Sendable {
        fileprivate let identity = UUID()
    }

    private let lock = NSLock()
    private var epoch: Epoch?
    private var activated = false
    private var suspended = false

    public init() {}

    @discardableResult
    public func begin() -> Epoch {
        lock.lock(); defer { lock.unlock() }
        let next = Epoch()
        epoch = next
        activated = false
        suspended = false
        return next
    }

    /// Only an explicit new start can create ownership after this call.
    @discardableResult
    public func revoke() -> Epoch? {
        lock.lock(); defer { lock.unlock() }
        let previous = epoch
        epoch = nil
        activated = false
        suspended = true
        return previous
    }

    public var currentEpoch: Epoch? {
        lock.lock(); defer { lock.unlock() }
        return epoch
    }

    public func isCurrent(_ expected: Epoch) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return epoch == expected
    }

    /// Final startup handoff. A stopped or already handed-off start cannot arm
    /// a watchdog. Callers serialize their short state setup on its owner queue.
    @discardableResult
    public func activate(_ expected: Epoch) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard epoch == expected, !activated else { return false }
        activated = true
        return true
    }

    @discardableResult
    public func suspend(_ expected: Epoch) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard epoch == expected, activated else { return false }
        suspended = true
        return true
    }

    @discardableResult
    public func resume(_ expected: Epoch) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard epoch == expected, activated else { return false }
        suspended = false
        return true
    }

    public func permitsRuntime(_ expected: Epoch) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return epoch == expected && activated && !suspended
    }
}
