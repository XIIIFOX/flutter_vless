import Foundation
import Darwin

private final class Clock {
    var value = 0.0, cancelled = false
    func budget(_ timeout: Double) -> LocalProxyIOBudget {
        LocalProxyIOBudget(timeout: timeout, isCancelled: { self.cancelled }, now: { self.value })
    }
}

private final class FakeIO: LocalSOCKS5SocketIO {
    let clock = Clock()
    var lastError: Int32 = 0, originalFlags: Int32 = 0x400
    var created = 0, closed = 0, reads = 0, writes = 0
    var flagWrites: [Int32] = [], waits: [Int32] = [], sent: [[UInt8]] = []
    var bytes: [UInt8] = [], readResults: [Int] = [], writeResults: [Int] = []
    var readAdvance = 0.0, writeAdvance = 0.0
    var pollResults: [Int32] = [], pollAdvances = false
    var connectResult: Int32 = 0, connectError: Int32 = EINPROGRESS, socketError: Int32? = 0
    var failRestore = false, failConfiguration = false
    var afterRead: (() -> Void)?, afterSend: (() -> Void)?, afterWait: (() -> Void)?, afterConnect: (() -> Void)?
    var afterConfigure: (() -> Void)?, afterFlags: (() -> Void)?, afterSetFlags: (() -> Void)?, connects = 0, flagReads = 0
    func createSocket() -> Int32 { created += 1; return 7 }
    func configure(fd: Int32, timeout: TimeInterval) -> Bool { afterConfigure?(); return !failConfiguration }
    func flags(fd: Int32) -> Int32 { flagReads += 1; afterFlags?(); return originalFlags }
    func setFlags(fd: Int32, flags: Int32) -> Bool { flagWrites.append(flags); afterSetFlags?(); return !(failRestore && flags == originalFlags) }
    func connectLoopback(fd: Int32, port: Int) -> Int32 { connects += 1; lastError = connectError; afterConnect?(); return connectResult }
    func connectionError(fd: Int32) -> Int32? { socketError }
    func wait(fd: Int32, write: Bool, milliseconds: Int32) -> Int32 {
        precondition(waits.count < 1000 && (1...100).contains(milliseconds))
        waits.append(milliseconds)
        if pollAdvances { clock.value += Double(milliseconds) / 1000 }
        afterWait?()
        let result = pollResults.isEmpty ? 1 : pollResults.removeFirst()
        lastError = result < 0 ? EINTR : 0
        return result
    }
    func send(fd: Int32, pointer: UnsafeRawPointer, count: Int) -> Int {
        precondition(writes < 1000); writes += 1; clock.value += writeAdvance
        let result = writeResults.isEmpty ? count : writeResults.removeFirst()
        lastError = result < 0 ? EINTR : 0
        if result > 0 { sent.append(Array(UnsafeBufferPointer(start: pointer.assumingMemoryBound(to: UInt8.self), count: result))) }
        afterSend?(); return result
    }
    func receive(fd: Int32, pointer: UnsafeMutableRawPointer, count: Int) -> Int {
        precondition(reads < 1000); reads += 1; clock.value += readAdvance
        let result = readResults.isEmpty ? min(1, min(count, bytes.count)) : readResults.removeFirst()
        lastError = result < 0 ? EINTR : 0
        if result > 0 {
            precondition(result <= count && result <= bytes.count)
            for index in 0..<result { pointer.storeBytes(of: bytes.removeFirst(), toByteOffset: index, as: UInt8.self) }
        }
        afterRead?(); return result
    }
    func close(fd: Int32) { closed += 1 }
}

@main struct SOCKS5BudgetProbe {
    static func main() throws {
        var passed = 0
        func check(_ name: String, _ value: @autoclosure () -> Bool) {
            precondition(value(), name); passed += 1; print("PASS " + name)
        }
        let credentials = try LocalProxyCredentials(username: "u", password: "p")
        for timeout in [Double.nan, .infinity, -.infinity, 0, -1] {
            let io = FakeIO()
            let result = try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: credentials, timeout: 2, budget: io.clock.budget(timeout), io: io)
            precondition(result == nil && io.created == 0 && io.waits.isEmpty)
        }
        check("invalid budgets refuse before descriptor creation", true)
        do {
            let io = FakeIO(), timeout: TimeInterval = 8
            check("budgeted CONNECT refuses before fake descriptor creation", (try? LocalSOCKS5Client.openConnection(proxyPort: 10808, credentials: nil, host: "192.0.2.1", port: 80, timeout: timeout, budget: io.clock.budget(-1), io: io)) == nil && io.created == 0 && io.waits.isEmpty)
        }
        do {
            let io = FakeIO(), budget = io.clock.budget(1); io.clock.value = 1
            check("closed deadline boundary does no I/O", LocalSOCKS5Client.receiveExactly(fd: 7, count: 1, budget: budget, io: io) == nil && io.reads == 0 && io.waits.isEmpty)
        }
        do {
            let io = FakeIO(); io.bytes = [1, 2, 3]; io.readResults = [1, -1, 1, 1]; io.readAdvance = 0.1
            check("partial receive and EINTR preserve frame", LocalSOCKS5Client.receiveExactly(fd: 7, count: 3, budget: io.clock.budget(1), io: io) == [1, 2, 3] && io.reads == 4)
        }
        do {
            let io = FakeIO(); io.bytes = [1, 2, 3]; io.readResults = [1, -1, 1, 1]; io.readAdvance = 0.4
            check("partial receive and EINTR cannot refresh deadline", LocalSOCKS5Client.receiveExactly(fd: 7, count: 3, budget: io.clock.budget(1), io: io) == nil && io.reads == 3)
        }
        do {
            let io = FakeIO(); io.writeResults = [1, -1, 1, 1]; io.writeAdvance = 0.4
            check("partial send and EINTR cannot refresh deadline", !LocalSOCKS5Client.sendAll(fd: 7, bytes: [1, 2, 3], budget: io.clock.budget(1), io: io) && io.writes == 3)
        }
        do {
            let io = FakeIO(); io.bytes = [1, 2, 3]; io.afterRead = { io.clock.cancelled = true }
            check("cancelled read performs no subsequent I/O", LocalSOCKS5Client.receiveExactly(fd: 7, count: 3, budget: io.clock.budget(8), io: io) == nil && io.reads == 1 && io.closed == 0)
        }
        do {
            let io = FakeIO(); io.afterWait = { io.clock.cancelled = true }
            check("cancelled wait never sends", !LocalSOCKS5Client.sendAll(fd: 7, bytes: [1], budget: io.clock.budget(8), io: io) && io.writes == 0)
        }
        do {
            let io = FakeIO(); io.bytes = [1]; io.readAdvance = 1
            check("late last byte cannot succeed", LocalSOCKS5Client.receiveExactly(fd: 7, count: 1, budget: io.clock.budget(1), io: io) == nil)
        }
        do {
            let io = FakeIO(); io.pollResults = Array(repeating: 0, count: 20); io.pollAdvances = true
            check("poll waits are sliced and share one deadline", LocalSOCKS5Client.receiveExactly(fd: 7, count: 1, budget: io.clock.budget(1), io: io) == nil && io.reads == 0 && io.clock.value <= 1.0011 && io.waits.allSatisfy { $0 <= 100 })
        }
        do {
            let io = FakeIO(); io.bytes = [9]; io.pollResults = [-1, -1, 1]; io.pollAdvances = true
            check("poll EINTR preserves deadline and positive framing", LocalSOCKS5Client.receiveSome(fd: 7, maxCount: 4, budget: io.clock.budget(1), io: io) == [9])
        }
        do {
            let io = FakeIO()
            check("EOF refuses incomplete frame", LocalSOCKS5Client.receiveExactly(fd: 7, count: 1, budget: io.clock.budget(1), io: io) == nil && io.reads == 1)
        }
        do {
            let io = FakeIO(); io.bytes = [5, 0]
            check("explicit noauth framing", LocalSOCKS5Client.authenticate(fd: 7, credentials: nil, budget: io.clock.budget(2), io: io) && io.sent == [[5, 1, 0]])
        }
        do {
            let io = FakeIO(); io.bytes = [5, 2, 1, 0]
            check("authentication framing", LocalSOCKS5Client.authenticate(fd: 7, credentials: credentials, budget: io.clock.budget(2), io: io) && io.sent == [[5, 1, 2], Array(credentials.socksAuthenticationRequest)])
        }
        do {
            let io = FakeIO(); io.bytes = [5, 0]
            check("credentials never fall back to noauth", !LocalSOCKS5Client.authenticate(fd: 7, credentials: credentials, budget: io.clock.budget(2), io: io) && io.sent == [[5, 1, 2]])
        }
        for host in ["192.0.2.1", "2001:db8::1", "probe.invalid"] {
            let io = FakeIO(); io.bytes = [5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: 10808, credentials: credentials, host: host, port: 80, timeout: 8, budget: io.clock.budget(15), io: io)
            precondition(fd == 7 && io.flagWrites == [io.originalFlags | O_NONBLOCK, io.originalFlags] && io.closed == 0 && io.sent.count == 3)
            let request = io.sent[2]; precondition(request.first == 5 && request.suffix(2) == [0, 80])
            precondition(request[3] == (host == "192.0.2.1" ? 1 : host == "2001:db8::1" ? 4 : 3))
        }
        check("CONNECT address framing and original flags restored", true)
        do {
            let io = FakeIO(); io.bytes = [5, 0]; io.connectResult = -1
            let fd = try LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)
            check("nonblocking connect checks SO_ERROR", fd == 7 && !io.waits.isEmpty && io.closed == 0)
        }
        do {
            let io = FakeIO(); io.connectResult = -1; io.socketError = ECONNREFUSED
            check("connect failure closes only owned descriptor", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)) == nil && io.closed == 1 && io.writes == 0)
        }
        do {
            let io = FakeIO(); io.failRestore = true
            check("flag restore failure closes owned descriptor", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)) == nil && io.closed == 1 && io.writes == 0)
        }
        do {
            let io = FakeIO(); io.afterConnect = { io.clock.cancelled = true }
            check("cancelled connect never authenticates or returns descriptor", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)) == nil && io.closed == 1 && io.writes == 0)
        }
        do {
            let io = FakeIO(); io.afterConfigure = { io.clock.cancelled = true }
            check("cancelled configuration cannot query flags or connect", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)) == nil && io.flagReads == 0 && io.connects == 0 && io.closed == 1)
        }
        do {
            let io = FakeIO(); io.afterFlags = { io.clock.cancelled = true }
            check("cancelled flags query cannot mutate flags or connect", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)) == nil && io.flagWrites.isEmpty && io.connects == 0 && io.closed == 1)
        }
        do {
            let io = FakeIO(); io.afterSetFlags = { io.clock.cancelled = true }
            check("cancelled flag transition cannot connect", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: io.clock.budget(15), io: io)) == nil && io.connects == 0 && io.closed == 1)
        }
        do {
            let io = FakeIO(); io.bytes = [5, 0]; io.readAdvance = 1.1; let caller = io.clock.budget(15)
            check("phase limit cannot use remaining caller budget", (try? LocalSOCKS5Client.openProxyConnection(proxyPort: 10808, credentials: nil, timeout: 2, budget: caller, io: io)) == nil && io.closed == 1 && caller.canContinue)
        }
        do {
            let io = FakeIO(); io.bytes = [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]; io.readAdvance = 0.1
            let budget = io.clock.budget(2)
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: 10808, credentials: nil, host: "192.0.2.1", port: 80, timeout: 8, budget: budget, io: io)
            io.writeAdvance = 0.4
            precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: [1], budget: budget, io: io))
            io.bytes = [9]; io.readAdvance = 0.5
            check("caller deadline spans CONNECT and later HTTP I/O", LocalSOCKS5Client.receiveSome(fd: fd, maxCount: 4, budget: budget, io: io) == nil && !budget.canContinue)
        }
        do {
            let io = FakeIO(); io.bytes = [1]
            _ = LocalSOCKS5Client.receiveSome(fd: 7, maxCount: 1, budget: io.clock.budget(1), io: io)
            check("borrowed descriptors retain flags and ownership", io.flagWrites.isEmpty && io.created == 0 && io.closed == 0)
        }
        print("APPLE_SOCKS5_BUDGET_PASS=\(passed)")
    }
}
