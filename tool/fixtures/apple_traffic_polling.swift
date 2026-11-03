import Foundation

// PRODUCTION_RATE_HELPER

private enum FixturePrivacy { case `public` }
private struct FixtureLogMessage: ExpressibleByStringInterpolation {
    init(stringLiteral value: String) {}
    init(stringInterpolation: StringInterpolation) {}
    struct StringInterpolation: StringInterpolationProtocol {
        init(literalCapacity: Int, interpolationCount: Int) {}
        mutating func appendLiteral(_ literal: String) {}
        mutating func appendInterpolation<T>(_ value: T) {}
        mutating func appendInterpolation<T>(_ value: T, privacy: FixturePrivacy) {}
    }
}
private struct FixtureLog {
    func info(_ message: FixtureLogMessage) {}
    func error(_ message: FixtureLogMessage) {}
}
private let pluginLog = FixtureLog()
private func pluginDebug(_ message: String) {}
private enum NativeLogPrivacy {
    static func operationError(_ error: Error) -> NSError { error as NSError }
}
private enum FixtureStatus: Int { case invalid, disconnected, connecting, connected, reasserting }
private final class PacketTunnelManager {
    var status: FixtureStatus? = .connected
    var connectedDate: Date? = Date(timeIntervalSince1970: 100)
    var isRecoveryEnabled = false
    var holdRefresh = false
    var refreshCount = 0
    var refreshReplies: [CheckedContinuation<Void, Never>] = []
    var replies: [CheckedContinuation<Data?, Error>?] = []

    func refreshForwardingState(isCurrent: () -> Bool = { true }) async {
        refreshCount += 1
        if holdRefresh {
            await withCheckedContinuation { refreshReplies.append($0) }
        }
    }
    func sendProviderMessage(data: Data) async throws -> Data? {
        precondition(data == Data("xray_traffic".utf8))
        return try await withCheckedThrowingContinuation { replies.append($0) }
    }
    func finish(_ index: Int, _ text: String? = nil, failure: Bool = false) {
        guard replies.indices.contains(index), let reply = replies[index] else { return }
        replies[index] = nil
        if failure { reply.resume(throwing: NSError(domain: "fixture", code: 1)) }
        else { reply.resume(returning: text.map { Data($0.utf8) }) }
    }
    func finishRefresh() {
        let pending = refreshReplies
        refreshReplies.removeAll()
        pending.forEach { $0.resume() }
    }
    func finishAll() {
        finishRefresh()
        for index in replies.indices { finish(index) }
    }
}
private final class ProxyOnlyRunner {
    var isRunning = false
    var connectedDate: Date? = Date()
    func queryTrafficStats() -> (upload: Int, download: Int, uploadSpeed: Int, downloadSpeed: Int) {
        (70, 80, 7, 8)
    }
}
private final class PollingHost {
    var packetTunnelManager: PacketTunnelManager?
    let proxyOnlyRunner = ProxyOnlyRunner()
    var timer: Timer?
    var readinessTimer: Timer?
    var readinessPollingOwner: (manager: PacketTunnelManager, connectedDate: Date?, generation: UInt64)?
    var eventSink: (() -> Void)?
    var totalUpload = 0, totalDownload = 0, uploadSpeed = 0, downloadSpeed = 0
    var trafficPollingGeneration: UInt64 = 0
    var trafficPollInFlight = false
    var previousTrafficSampleTime: UInt64?
    var previousTrafficUpload: Int?
    var previousTrafficDownload: Int?
    var fixtureTime: UInt64 = 1_000_000_000
    lazy var trafficClock: () -> UInt64 = { [unowned self] in self.fixtureTime }
    var lastTrafficLogDate = Date.distantPast
    var lastProviderDebugLogDate = Date.distantPast
    var lastNetworkSnapshotLogDate = Date.distantPast
    var lastAppNetworkProbeDate = Date.distantPast
    var didScheduleConnectedDiagnostics = false
    var emitted: [String] = []

    init(_ manager: PacketTunnelManager) { packetTunnelManager = manager }
    func currentRuntimeState() -> String {
        packetTunnelManager?.status == .connected ? "CONNECTED" : "CONNECTING"
    }
    func currentWireState() -> String { currentRuntimeState() }
    func currentDurationSeconds() -> Int { 0 }
    func emitStatus(duration: Int, state: String, reason: String) { emitted.append(state) }
    func logProviderDebugSnapshot() {}
    func logSystemNetworkSnapshot(reason: String) {}

// PRODUCTION_TIMER_METHODS
}

@main private enum Probe {
    @MainActor static func settle() async {
        for _ in 0..<30 { await Task.yield() }
    }
    @MainActor static func waitFor(_ predicate: () -> Bool) async {
        for _ in 0..<1000 {
            if predicate() { return }
            await Task.yield()
        }
        preconditionFailure("provider boundary was not reached")
    }
    @MainActor static func main() async {
        var failures: [String] = []
        var checks = 0
        func check(_ condition: Bool, _ name: String) {
            checks += 1
            if !condition { failures.append(name) }
        }
        func prepared() -> (PollingHost, PacketTunnelManager) {
            let manager = PacketTunnelManager()
            let host = PollingHost(manager)
            host.startTimer()
            return (host, manager)
        }

        do {
            let (host, manager) = prepared()
            host.timer!.fire(); await waitFor { manager.replies.count == 1 }
            manager.finish(0, "10,20"); await settle()
            check(host.totalUpload == 10 && host.totalDownload == 20 && host.uploadSpeed == 0 && host.downloadSpeed == 0, "first counters have no rate baseline")
            host.timer!.fire(); await waitFor { manager.replies.count == 2 }
            host.fixtureTime = 3_000_000_000
            manager.finish(1, "4,30"); await settle()
            check(host.totalUpload == 4 && host.totalDownload == 30 && host.uploadSpeed == 0 && host.downloadSpeed == 5, "worker reset and two-second interval")
            for index in 2..<5 {
                host.uploadSpeed = 5; host.downloadSpeed = 6
                host.timer!.fire(); await waitFor { manager.replies.count == index + 1 }
                manager.finish(index, index == 3 ? "malformed" : nil, failure: index == 4)
                await settle()
                check(host.totalUpload == 4 && host.totalDownload == 30 && host.uploadSpeed == 0 && host.downloadSpeed == 0, "missing sample clears stale rate \(index)")
            }
            host.fixtureTime = 8_000_000_000
            host.timer!.fire(); await waitFor { manager.replies.count == 6 }
            manager.finish(5, "50,70"); await settle()
            check(host.totalUpload == 50 && host.totalDownload == 70 && host.uploadSpeed == 0 && host.downloadSpeed == 0,
                  "first counters after failed samples restart the rate baseline")
            host.stopTimer()
        }
        do {
            let (host, manager) = prepared()
            host.timer!.fire(); await waitFor { manager.replies.count == 1 }
            manager.finish(0, "100,200"); await settle()
            host.timer!.fire(); await waitFor { manager.replies.count == 2 }
            for _ in 0..<4 { host.timer!.fire() }
            host.fixtureTime = 4_000_000_000
            manager.finish(1, "400,800"); await settle()
            check(host.uploadSpeed == 100 && host.downloadSpeed == 200 && manager.replies.count == 2,
                  "held reply and skipped ticks use actual three-second elapsed time")
            host.timer!.fire(); await waitFor { manager.replies.count == 3 }
            host.fixtureTime = 4_500_000_000
            manager.finish(2, "450,900"); await settle()
            check(host.uploadSpeed == 100 && host.downloadSpeed == 200,
                  "half-second sample is scaled to bytes per second")
            host.timer!.fire(); await waitFor { manager.replies.count == 4 }
            manager.finish(3, "460,920"); await settle()
            check(host.uploadSpeed == 0 && host.downloadSpeed == 0, "zero elapsed interval cannot create a rate")
            host.stopTimer()
        }
        do {
            let (host, manager) = prepared()
            host.timer!.fire(); host.timer!.fire()
            await waitFor { !manager.replies.isEmpty }; await settle()
            check(manager.replies.count == 1, "only one provider request in flight")
            manager.finishAll(); await settle(); host.stopTimer()
        }
        do {
            let (host, manager) = prepared()
            host.proxyOnlyRunner.isRunning = true
            host.timer!.fire()
            check(host.totalUpload == 70 && host.totalDownload == 80 && host.uploadSpeed == 7 && host.downloadSpeed == 8 && manager.replies.isEmpty,
                  "proxy counters remain synchronous and do not poll the VPN")
            host.stopTimer()
        }
        for mode in ["stop", "manager", "session", "proxy"] {
            let (host, manager) = prepared()
            host.timer!.fire(); await waitFor { manager.replies.count == 1 }
            switch mode {
            case "stop": host.stopTimer()
            case "manager": host.packetTunnelManager = PacketTunnelManager()
            case "session": manager.connectedDate = Date(timeIntervalSince1970: 200)
            default: host.proxyOnlyRunner.isRunning = true
            }
            let emissions = host.emitted.count
            manager.finish(0, "900,1000"); await settle()
            check(host.totalUpload == 0 && host.totalDownload == 0 && host.uploadSpeed == 0 && host.downloadSpeed == 0, "late \(mode) reply discarded")
            check(host.emitted.count == emissions, "late \(mode) reply cannot emit status")
            host.stopTimer()
        }
        do {
            let (host, manager) = prepared()
            host.timer!.fire(); await waitFor { manager.replies.count == 1 }
            host.stopTimer(); host.startTimer(); host.timer!.fire()
            await waitFor { manager.replies.count == 2 }
            manager.finish(0, "900,1000"); await settle()
            host.timer!.fire(); await settle()
            check(manager.replies.count == 2, "old completion cannot unlock a newer poll")
            manager.finish(1, "30,40"); await settle()
            check(host.totalUpload == 30 && host.totalDownload == 40 && host.uploadSpeed == 0 && host.downloadSpeed == 0, "restart accepts only new counters and restarts rate baseline")
            manager.finishAll(); await settle(); host.stopTimer()
        }
        check(trafficBytesPerSecond(Int64.max, elapsed: 1) == Int64.max,
              "short interval saturates without overflow")
        check(trafficBytesPerSecond(Int64.max, elapsed: 1_000_000_000) == Int64.max,
              "int64 boundary preserves exact one-second rate")
        check(trafficBytesPerSecond(Int64.max, elapsed: 3_000_000_000) == Int64.max / 3,
              "large integer scaling remains exact")
        check(trafficBytesPerSecond(-1, elapsed: 1) == 0 && trafficBytesPerSecond(1, elapsed: 0) == 0,
              "invalid delta or elapsed never yields a rate")
        let vectorPath = ProcessInfo.processInfo.environment["FLVLESS_TRAFFIC_RATE_VECTORS"]!
        let vectors = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: vectorPath))) as! [[String: String]]
        precondition(vectors.count == 24)
        for (index, vector) in vectors.enumerated() {
            check(trafficBytesPerSecond(Int64(vector["delta"]!)!, elapsed: UInt64(vector["elapsedNanoseconds"]!)!) == Int64(vector["bytesPerSecond"]!)!,
                  "exact integer shared rate vector \(index)")
        }
        do {
            let (host, manager) = prepared()
            manager.holdRefresh = true
            host.timer!.fire(); await waitFor { manager.refreshCount == 1 }
            host.stopTimer()
            let emissions = host.emitted.count
            manager.finishRefresh(); await settle()
            check(manager.replies.isEmpty && host.emitted.count == emissions, "stopped readiness reply cannot begin traffic poll or emit connected")
            manager.finishAll(); await settle()
        }
        for failure in failures { print("APPLE_TRAFFIC_POLL_FAILURE=\(failure)") }
#if IOS
        print("IOS_TRAFFIC_POLL_CHECKS=\(checks)")
#else
        print("MACOS_TRAFFIC_POLL_CHECKS=\(checks)")
#endif
        if !failures.isEmpty { exit(1) }
    }
}
