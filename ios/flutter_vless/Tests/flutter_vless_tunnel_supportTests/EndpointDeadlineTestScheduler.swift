import Foundation

/// A deterministic monotonic clock and asynchronous serial-queue scheduler.
/// Advancing time enqueues due actions; queue barriers let tests distinguish
/// an answer at 1.9 seconds from the unchanged collection deadline at 2 seconds.
final class EndpointDeadlineTestScheduler: @unchecked Sendable {
    private final class Entry {
        let due: TimeInterval
        let queue: DispatchQueue
        let action: () -> Void
        var dispatched = false
        var cancelled = false
        init(due: TimeInterval, queue: DispatchQueue, action: @escaping () -> Void) {
            self.due = due; self.queue = queue; self.action = action
        }
    }
    private let lock = NSLock()
    private var time: TimeInterval = 0
    private var entries: [Entry] = []
    private var cancellations = 0
    var scheduled: (() -> Void)?

    func now() -> TimeInterval {
        lock.lock(); defer { lock.unlock() }
        return time
    }

    func schedule(_ queue: DispatchQueue, _ delay: TimeInterval, _ action: @escaping () -> Void) -> (() -> Void) {
        lock.lock()
        let entry = Entry(due: time + delay, queue: queue, action: action)
        entries.append(entry)
        lock.unlock()
        scheduled?()
        return {
            self.lock.lock(); defer { self.lock.unlock() }
            self.cancellations += 1
            entry.cancelled = true
        }
    }

    func advance(to value: TimeInterval) {
        lock.lock()
        precondition(value >= time)
        time = value
        let due = entries.filter { !$0.dispatched && !$0.cancelled && $0.due <= time }
        for entry in due { entry.dispatched = true }
        lock.unlock()
        for entry in due {
            entry.queue.async {
                self.lock.lock(); let permitted = !entry.cancelled; self.lock.unlock()
                if permitted { entry.action() }
            }
        }
    }

    private func registeredQueue() -> DispatchQueue? {
        lock.lock(); defer { lock.unlock() }
        return entries.first?.queue
    }

    func drain() async {
        if let queue = registeredQueue() {
            await withCheckedContinuation { c in queue.async { c.resume() } }
        }
    }

    var snapshot: (deadlines: [TimeInterval], cancellations: Int) {
        lock.lock(); defer { lock.unlock() }
        return (entries.map(\.due), cancellations)
    }
}
