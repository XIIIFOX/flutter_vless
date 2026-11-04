
typealias FlutterResult = (Any?) -> Void
let pluginLog = FixtureLogger()
struct FixtureLogger { func info(_ message: NativeDiagnosticMessage) {} }
func pluginDebug(_ message: NativeDiagnosticMessage) { Trace.append(message.text) }

enum Trace {
    private static let lock = NSLock()
    private static var lines: [String] = []
    static func append(_ value: String) { lock.lock(); lines.append(value); lock.unlock() }
    static func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return lines }
    static func reset() { lock.lock(); lines.removeAll(); lock.unlock() }
    static func count(_ phase: String) -> Int { snapshot().filter { $0.contains("phase=" + phase + " ") }.count }
}

actor Gate<Value> {
    private(set) var entered = false
    private var continuation: CheckedContinuation<Value, Never>?
    func hold() async -> Value {
        entered = true
        return await withCheckedContinuation { continuation = $0 }
    }
    func release(_ value: Value) { continuation?.resume(returning: value); continuation = nil }
    func waitUntilEntered() async { while !entered { await Task.yield() } }
}

private final class Reply {
    private let lock = NSLock()
    private var answer: Bool?
    func resolve(_ value: Any?) { lock.lock(); answer = value as? Bool; lock.unlock() }
    private func read() -> Bool? { lock.lock(); defer { lock.unlock() }; return answer }
    func value() async -> Bool { while true { if let answer = read() { return answer }; await Task.yield() } }
}

enum Status: Equatable { case connected, reasserting, disconnected }
final class Session {}
final class PacketTunnelManager {
    var manager: Session? = Session()
    var status: Status? = .connected
    var connectedDate: Date? = Date(timeIntervalSince1970: 100)
    var forwardingReady = false
    var permission: Gate<Bool>?
    var response: Gate<Data?>?
    func testSaveAndLoadProfile() async -> Bool { await permission?.hold() ?? false }
    func sendProviderMessage(data: Data) async throws -> Data? {
        precondition(data == Data("xray_runtime_state".utf8))
        return await response?.hold()
    }
// ACTUAL_READINESS
}
final class Host {
    let commands = NativeOperationQueue()
    var packetTunnelManager: PacketTunnelManager?
// ACTUAL_PERMISSION
}

@main enum Probe {
    @MainActor static func settle() async { for _ in 0..<100 { await Task.yield() } }
    @MainActor static func main() async {
        var failures: [String] = [], checks = 0
        func check(_ value: Bool, _ name: String) { checks += 1; if !value { failures.append(name) } }
        Trace.reset()
        let host = Host(), manager = PacketTunnelManager()
        host.packetTunnelManager = manager
        let preceding = Gate<Void>(), permission = Gate<Bool>(), reply = Reply()
        manager.permission = permission
        let pending = host.commands.submit { await preceding.hold() }
        await preceding.waitUntilEntered()
        host.requestPermission { reply.resolve($0) }
        await settle()
        check(Trace.count("host-permission-request") == 1, "request is visible before its queue lease")
        check(Trace.count("host-permission-dequeued") == 0 && Trace.count("host-permission-complete") == 0,
              "queued permission cannot report execution or completion")
        await preceding.release(())
        _ = try? await pending.value
        await permission.waitUntilEntered()
        check(Trace.count("host-permission-dequeued") == 1 && Trace.count("host-permission-complete") == 0,
              "permission remains incomplete while preferences are held")
        await permission.release(true)
        let granted = await reply.value()
        check(granted && Trace.count("host-permission-complete") == 1, "original granted result is preserved")
        check(Trace.snapshot().last?.contains("granted=true") == true, "permission scalar is rendered")
        let deniedPermission = Gate<Bool>(), deniedReply = Reply()
        manager.permission = deniedPermission
        host.requestPermission { deniedReply.resolve($0) }
        await deniedPermission.waitUntilEntered(); await deniedPermission.release(false)
        let denied = await deniedReply.value()
        check(!denied && Trace.count("host-permission-complete") == 2, "original denied result is preserved")
        check(Trace.snapshot().last?.contains("granted=false") == true, "denied scalar is rendered without error details")

        Trace.reset()
        let first = Gate<Data?>(); manager.response = first
        let readiness = Task { await manager.refreshForwardingState() }
        await first.waitUntilEntered()
        check(!manager.forwardingReady && Trace.count("host-forwarding-ready") == 0,
              "held readiness reply cannot emit ready timing")
        await first.release(Data("ready".utf8)); await readiness.value
        check(manager.forwardingReady && Trace.count("host-forwarding-ready") == 1,
              "actual admitted first ready emits one monotonic mark")
        let again = Gate<Data?>(); manager.response = again
        let repeated = Task { await manager.refreshForwardingState() }
        await again.waitUntilEntered(); await again.release(Data("ready".utf8)); await repeated.value
        check(Trace.count("host-forwarding-ready") == 1, "ordinary ready polling does not add timing spam")

        manager.forwardingReady = false
        let stale = Gate<Data?>(); manager.response = stale
        let oldOwner = Task { await manager.refreshForwardingState() }
        await stale.waitUntilEntered(); manager.manager = Session()
        await stale.release(Data("ready".utf8)); await oldOwner.value
        check(!manager.forwardingReady && Trace.count("host-forwarding-ready") == 1,
              "old manager response cannot emit a new ready mark")
        let oldDate = Gate<Data?>(); manager.response = oldDate
        let oldConnection = Task { await manager.refreshForwardingState() }
        await oldDate.waitUntilEntered(); manager.connectedDate = Date(timeIntervalSince1970: 200)
        await oldDate.release(Data("ready".utf8)); await oldConnection.value
        check(!manager.forwardingReady && Trace.count("host-forwarding-ready") == 1,
              "old connection response cannot emit a new ready mark")
        let guarded = Gate<Data?>(); manager.response = guarded
        var current = true
        let cancelled = Task { await manager.refreshForwardingState { current } }
        await guarded.waitUntilEntered(); current = false
        await guarded.release(Data("ready".utf8)); await cancelled.value
        check(!manager.forwardingReady && Trace.count("host-forwarding-ready") == 1,
              "superseded readiness lease cannot emit a mark")
        manager.status = .reasserting
        let recovering = Gate<Data?>(); manager.response = recovering
        let reasserting = Task { await manager.refreshForwardingState() }
        await recovering.waitUntilEntered(); await recovering.release(Data("ready".utf8)); await reasserting.value
        check(!manager.forwardingReady && Trace.count("host-forwarding-ready") == 1,
              "reasserting cannot be reported as ready")
        manager.status = .connected
        let waiting = Gate<Data?>(); manager.response = waiting
        let notReady = Task { await manager.refreshForwardingState() }
        await waiting.waitUntilEntered(); await waiting.release(Data("waiting".utf8)); await notReady.value
        check(!manager.forwardingReady && Trace.count("host-forwarding-ready") == 1,
              "negative readiness preserves the existing state contract")

        let marks = Trace.snapshot().filter { $0.contains("phase=host-forwarding-ready ") }
        check(marks.allSatisfy { $0.range(of: #"uptimeMs=[0-9]+$"#, options: .regularExpression) != nil },
              "absolute marks contain typed monotonic integers")
        print("MACOS_STARTUP_TIMING checks=\(checks) failures=\(failures)")
        if !failures.isEmpty { fatalError("inert startup timing regression") }
    }
}
