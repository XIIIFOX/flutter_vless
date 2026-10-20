// CI-only real loopback coverage of the opt-in deadline path; no Core or SDK.
import Foundation
import Darwin

private final class Cancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var timestamp: TimeInterval?
    func cancel() { lock.lock(); timestamp = ProcessInfo.processInfo.systemUptime; lock.unlock() }
    var observedAt: TimeInterval? { lock.lock(); defer { lock.unlock() }; return timestamp }
}

@main struct BudgetLoopbackProbe {
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 4, let port = Int(args[2]), (1...65535).contains(port),
              args[3].utf8.count == 32, args[3].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { exit(2) }
        let credentials = try LocalProxyCredentials(username: "budget-user", password: "budget-password")
        let now = { ProcessInfo.processInfo.systemUptime }
        switch args[1] {
        case "positive":
            let budget = LocalProxyIOBudget(timeout: 3)
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                host: "probe.invalid", port: 18083, timeout: 0.75, budget: budget)
            defer { close(fd) }
            precondition(fcntl(fd, F_GETFL) & O_NONBLOCK == 0)
            var duration = timeval(), size = socklen_t(MemoryLayout<timeval>.size)
            precondition(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &duration, &size) == 0 && duration.tv_sec == 0 && duration.tv_usec > 0)
            let payload = Array(args[3].utf8), expected = Array(("reply:" + args[3]).utf8)
            precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: payload, budget: budget))
            precondition(LocalSOCKS5Client.receiveExactly(fd: fd, count: expected.count, budget: budget) == expected)
        case "drip":
            let start = now(), budget = LocalProxyIOBudget(timeout: 0.25)
            let fd = try? LocalSOCKS5Client.openProxyConnection(proxyPort: port, credentials: credentials, timeout: 2, budget: budget)
            if let fd { close(fd) }
            let elapsed = now() - start
            precondition(fd == nil && !budget.canContinue && elapsed >= 0.20 && elapsed <= 1.0)
        case "cancel":
            let cancellation = Cancellation()
            let budget = LocalProxyIOBudget(timeout: 3, isCancelled: { cancellation.observedAt != nil })
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                host: "probe.invalid", port: 18083, budget: budget)
            defer { close(fd) }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) { cancellation.cancel() }
            let value = LocalSOCKS5Client.receiveSome(fd: fd, maxCount: 64, budget: budget)
            let after = now()
            guard let cancelledAt = cancellation.observedAt else { exit(3) }
            precondition(value == nil && after >= cancelledAt && after - cancelledAt <= 0.45 && !budget.canContinue)
        case "downgrade":
            let fd = try? LocalSOCKS5Client.openProxyConnection(proxyPort: port, credentials: credentials,
                timeout: 2, budget: LocalProxyIOBudget(timeout: 2))
            if let fd { close(fd) }
            precondition(fd == nil)
        default: exit(2)
        }
        print("APPLE_SOCKS5_BUDGET_LOOPBACK_CASE_PASS=" + args[1])
    }
}
