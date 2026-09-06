import Foundation

/// Orders asynchronous preference writes, including stop after a pending start.
/// The order is established synchronously when the command is submitted.
final class NativeOperationQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var tail: Task<Void, Never>?

    func submit<Value>(
        _ operation: @escaping () async throws -> Value
    ) -> Task<Value, Error> {
        lock.lock()
        defer { lock.unlock() }
        let previous = tail
        let next = Task {
            await previous?.value
            return try await operation()
        }
        tail = Task { _ = try? await next.value }
        return next
    }
}

/// A provider reply, SDK error and deadline may race during tunnel recovery.
final class NativeReplyGate<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Result<Value, Error>) -> Void)?

    init(_ completion: @escaping (Result<Value, Error>) -> Void) {
        self.completion = completion
    }

    func resolve(_ result: Result<Value, Error>) {
        lock.lock()
        let callback = completion
        completion = nil
        lock.unlock()
        callback?(result)
    }
}
