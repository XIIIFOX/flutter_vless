import Foundation

actor Barrier {
    private var started = false
    private var waiting: CheckedContinuation<Void, Never>?
    func hold() async {
        started = true
        await withCheckedContinuation { waiting = $0 }
    }
    func hasStarted() -> Bool { started }
    func release() { waiting?.resume(); waiting = nil }
}
actor State {
    var values: [String] = []
    func append(_ value: String) { values.append(value) }
    func snapshot() -> [String] { values }
}
enum ProbeError: Error { case failed }
@main struct Probe {
    static func main() async throws {
        let queue = NativeOperationQueue(), barrier = Barrier(), state = State()
        let start = queue.submit {
            await state.append("start entered")
            await barrier.hold()
            await state.append("start completed")
        }
        while !(await barrier.hasStarted()) { await Task.yield() }
        let stop = queue.submit { await state.append("stop completed") }
        for _ in 0..<10 { await Task.yield() }
        let pending = await state.snapshot()
        precondition(pending == ["start entered"], "Stop must not race the in-flight preference write")
        await barrier.release()
        try await start.value; try await stop.value
        let result = await state.snapshot()
        precondition(result == ["start entered", "start completed", "stop completed"])
        let failed = queue.submit { () throws -> Void in throw ProbeError.failed }
        let cleanup = queue.submit { await state.append("cleanup after failure") }
        do { try await failed.value; preconditionFailure("Expected failure") } catch ProbeError.failed {}
        try await cleanup.value
        let afterFailure = await state.snapshot()
        precondition(afterFailure.last == "cleanup after failure")
        let lock = NSLock();var replies = 0
        let reply = NativeReplyGate<Int> { _ in lock.lock();replies += 1;lock.unlock() }
        DispatchQueue.concurrentPerform(iterations: 100) { i in
            if i.isMultiple(of: 2) { reply.resolve(.success(i)) }
            else { reply.resolve(.failure(ProbeError.failed)) }
        }
        precondition(replies == 1, "Concurrent SDK reply, timeout and error must complete once")
        print("PASS: pending start then stop; failed start then cleanup; concurrent reply/error/deadline")
    }
}
