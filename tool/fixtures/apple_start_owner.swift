import Foundation

typealias FlutterResult = (Any?) -> Void
struct FlutterMethodCall { let arguments: Any? }
struct FlutterError { let code: String; let message: String; let details: Any? }
enum NativeRoutingIntent { case fixture }
enum TunnelSecretError: Error { case fixture }
enum DesktopTunnelError: Error { case fixture }
enum FixturePrivacy { case `public` }
struct LogMessage: ExpressibleByStringInterpolation {
    init(stringLiteral value: String) {}
    init(stringInterpolation: StringInterpolation) {}
    struct StringInterpolation: StringInterpolationProtocol {
        init(literalCapacity: Int, interpolationCount: Int) {}
        mutating func appendLiteral(_ value: String) {}
        mutating func appendInterpolation<T>(_ value: T) {}
        mutating func appendInterpolation<T>(_ value: T, privacy: FixturePrivacy) {}
    }
}
struct Logger { func info(_ value: LogMessage) {}; func error(_ value: LogMessage) {}; func warning(_ value: String) {} }
let pluginLog = Logger()
func pluginDebug(_ value: String) {}
enum NativeLogPrivacy {
    static func operationError(_ error: Error) -> NSError { NSError(domain: "redacted", code: 1) }
    static func runtimeEvent(_ value: String) -> String { "redacted" }
}
enum Kernel {
    static var events: [String] = []
    static var onCheck: (() -> Void)?
    static var checkCode: Int64 = 0
    static var stopBarrier: Barrier?
    static func reset() { events = []; onCheck = nil; checkCode = 0; stopBarrier = nil }
}
func FLVlessHasCorePreflight() -> Bool { true }
func FLVlessCheckCorePrivate(_ bytes: Data) -> Int64 {
    Kernel.events.append("check"); Kernel.onCheck?(); return Kernel.checkCode
}
func configureXrayAssetLocation(_ value: String?) throws { Kernel.events.append("assets") }
enum BoundedNativeLogStore { static func configure(enabled: Bool, maxBytes: Int, maxLines: Int) {} }
enum VlessSystemControl {
    static func configure(group: String, provider: String, options: VlessNativeOptions) {}
    static func authorizeProfile(group: String, provider: String, reference: Data) {}
    static func clear(group: String) { Kernel.events.append("clear:" + group) }
}
final class PluginDebugStore { static let shared = PluginDebugStore(); func configure(groupIdentifier: String) {} }
final class VlessMenuBarControl { init(group: String, provider: String, options: VlessNativeOptions) {} }
final class PacketTunnelManager {
    let group: String
    var nativeOptions = try! VlessNativeOptions()
    var remark = "old", xrayConfig = Data("old".utf8), bypassSubnets: [String] = []
    var proxyOnly = false, geoAssetsDirectory: String?, certificateAssetsDirectory: String?
    var vpnRouting: NativeRoutingIntent?
    var didSaveQuickProfile: ((Data) -> Void)?
    init(providerBundleIdentifier: String, groupIdentifier: String, keychainAccessGroup: String?) { group = groupIdentifier }
    func start() async throws { Kernel.events.append("start:" + group + ":" + String(nativeOptions.initialDelayMs)) }
    func stop(waitForDisconnect: Bool) async throws {
        precondition(waitForDisconnect); Kernel.events.append("stop:" + group)
        if let barrier = Kernel.stopBarrier { await barrier.hold() }
    }
}
final class Proxy {
    struct Prepared { let data: Data; let changes: [NativePreparationReport.Change] = [] }
    var isRunning = false
    func stop() { Kernel.events.append("proxy-stop") }
    func clearDiagnostics() { Kernel.events.append("clear-diagnostics") }
    func start(prepared: Prepared, geoAssetsDirectory: String?) throws { Kernel.events.append("proxy-start") }
}
actor Barrier {
    var entered = false
    var continuation: CheckedContinuation<Void, Never>?
    func hold() async { entered = true; await withCheckedContinuation { continuation = $0 } }
    func release() { continuation?.resume(); continuation = nil }
    func waitUntilEntered() async { while !entered { await Task.yield() } }
}
final class Reply {
    private let lock = NSLock()
    private var completed = false
    private var result: Any?
    func resolve(_ value: Any?) { lock.lock(); result = value; completed = true; lock.unlock() }
    private func read() -> (Bool, Any?) { lock.lock(); defer { lock.unlock() }; return (completed, result) }
    func value() async -> Any? {
        while true { let state = read(); if state.0 { return state.1 }; await Task.yield() }
    }
}
final class Subject {
    let commands = NativeOperationQueue(), proxyOnlyRunner = Proxy()
    var packetTunnelManager: PacketTunnelManager?
    var nativeOptions = try! VlessNativeOptions()
    var controlGroup: String?, controlProvider: String?
    let controlCenterAvailable = true, controlsConfigured = true
    var menuBarControl: VlessMenuBarControl?
    func refreshRuntimePolling(reason: String) {}
    // ACTUAL_INITIALIZE_ADMISSION
    func initialize(_ group: String, invalid: Bool = false, delay: Int = 100) -> FlutterError? {
        var options: [String: Any] = ["reconnect": ["initialDelayMs": delay, "maxDelayMs": 200, "maxAttempts": 1], "protection": ["onDemand": "disabled"]]
        if invalid { options["diagnostics"] = ["maxBytes": 4095] }
        var error: FlutterError?
        initializeVless(call: FlutterMethodCall(arguments: ["providerBundleIdentifier": "fixture", "groupIdentifier": group, "options": options])) { error = $0 as? FlutterError }
        return error
    }
    func start(proxyOnly: Bool, result: @escaping FlutterResult) {
        let changes = Set<NativePreparationReport.Change>()
        let effectiveConfigData = Data("private-config-canary".utf8)
        let preparedProxyConfig: Proxy.Prepared? = proxyOnly ? Proxy.Prepared(data: effectiveConfigData) : nil
        let geoAssetsDirectory: String? = nil, certificateAssetsDirectory: String? = nil
        let vpnRouting: NativeRoutingIntent? = nil
        let bypassSubnets: [String]? = [], remark = "private-remark-canary"
        // ACTUAL_START_TRANSACTION
    }
    func reply(proxyOnly: Bool) async -> Any? { await withCheckedContinuation { continuation in start(proxyOnly: proxyOnly) { continuation.resume(returning: $0) } } }
}
@main struct Main {
    static func main() async {
        var failures = 0, count = 0
        func check(_ name: String, _ passed: Bool) {
            count += 1; if !passed { failures += 1 }; print("APPLE_START_OWNER_CASE=" + name + ";PASS=" + String(passed))
        }
        func cancelled(_ result: Any?) -> Bool {
            guard let error = result as? FlutterError else { return false }
            return error.code == "VPN_START_CANCELLED" && error.details as? [String: String] == ["stage": "prepare"] && !error.message.contains("private-")
        }
        for proxy in [false, true] {
            Kernel.reset(); let subject = Subject(); precondition(subject.initialize("A") == nil)
            let barrier = Barrier(); let blocker = subject.commands.submit { await barrier.hold() }
            await barrier.waitUntilEntered()
            let reply = Reply(); subject.start(proxyOnly: proxy, result: reply.resolve)
            // Same-group option changes also create a replacement owner.
            precondition(subject.initialize(proxy ? "B" : "A", delay: 200) == nil)
            await barrier.release(); _ = try? await blocker.value
            let result = await reply.value()
            check("queued-reinitialize-" + String(proxy), cancelled(result) && Kernel.events.isEmpty && subject.packetTunnelManager?.xrayConfig == Data("old".utf8))
        }
        Kernel.reset(); let invalid = Subject(); precondition(invalid.initialize("A") == nil)
        let old = invalid.packetTunnelManager
        let invalidBarrier = Barrier(); let invalidBlocker = invalid.commands.submit { await invalidBarrier.hold() }
        await invalidBarrier.waitUntilEntered()
        let invalidPending = Reply(); invalid.start(proxyOnly: false, result: invalidPending.resolve)
        let invalidError = invalid.initialize("B", invalid: true)
        await invalidBarrier.release(); _ = try? await invalidBlocker.value
        let validReply = await invalidPending.value()
        check("invalid-initialize-preserves-owner", invalidError?.code == "INVALID_OPTIONS" && invalid.packetTunnelManager === old && validReply is [String: Any] && Kernel.events == ["assets", "check", "proxy-stop", "clear-diagnostics", "start:A:100"])
        Kernel.reset(); let current = Subject(); precondition(current.initialize("A") == nil)
        let currentReply = await current.reply(proxyOnly: true)
        check("current-proxy-owner", currentReply is [String: Any] && Kernel.events == ["assets", "check", "stop:A", "clear:A", "proxy-start"])
        Kernel.reset(); let duringCheck = Subject(); precondition(duringCheck.initialize("A") == nil)
        Kernel.onCheck = { precondition(duringCheck.initialize("B") == nil) }
        let checkedReply = await duringCheck.reply(proxyOnly: false)
        check("preflight-owner-replaced", cancelled(checkedReply) && Kernel.events == ["assets", "check"] && duringCheck.packetTunnelManager?.xrayConfig == Data("old".utf8))
        Kernel.reset(); let staleRejection = Subject(); precondition(staleRejection.initialize("A") == nil)
        Kernel.checkCode = 3; Kernel.onCheck = { precondition(staleRejection.initialize("B") == nil) }
        let staleError = await staleRejection.reply(proxyOnly: false)
        check("obsolete-preflight-rejection-cancelled", cancelled(staleError) && Kernel.events == ["assets", "check"] && staleRejection.packetTunnelManager?.xrayConfig == Data("old".utf8))
        Kernel.reset(); let duringStop = Subject(); precondition(duringStop.initialize("A") == nil)
        let barrier = Barrier(); Kernel.stopBarrier = barrier
        let stoppedReply = Task { await duringStop.reply(proxyOnly: true) }
        await barrier.waitUntilEntered(); precondition(duringStop.initialize("B") == nil); await barrier.release()
        check("async-stop-does-not-touch-replacement", cancelled(await stoppedReply.value) && Kernel.events == ["assets", "check", "stop:A"])
        Kernel.reset(); let rejected = Subject(); precondition(rejected.initialize("A") == nil); Kernel.checkCode = 3
        let rejectedReply = await rejected.reply(proxyOnly: false) as? FlutterError
        check("preflight-error-preserved", rejectedReply?.code == "CORE_CONFIG_ERROR" && Kernel.events == ["assets", "check"] && rejected.packetTunnelManager?.xrayConfig == Data("old".utf8))
        print("APPLE_START_OWNER_CASES=" + String(count)); print("APPLE_START_OWNER_FAILURES=" + String(failures))
        exit(failures == 0 ? 0 : 7)
    }
}
