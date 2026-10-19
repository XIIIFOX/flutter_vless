import Foundation

private var events: [String] = []
private var available = true
private var coreCode: Int64 = 0
private var assetFailure = false
private var rejectPreparedCheck = false
private var checkedData: [Data] = []
private var startedData: [Data] = []
private var proxyStartedData: [Data] = []
private var prepareCount = 0
private func FLVlessHasCorePreflight() -> Bool { available }
private func FLVlessCheckCorePrivate(_ data: Data) -> Int64 {
    events.append("check"); checkedData.append(data)
    return rejectPreparedCheck && data == Data("prepared-new".utf8) ? 3 : coreCode
}
private func configureXrayAssetLocation(_ directory: String?) throws {
    events.append("assets")
    if assetFailure { throw NSError(domain: "fixture", code: 1) }
}
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
private struct Log {
    func warning(_ text: String) { events.append("unavailable") }
    func info(_ text: FixtureLogMessage) {}
}
private let pluginLog = Log()
private struct LocalProxyCredentials {}
private struct NativeRoutingIntent {}
private final class PluginXRayLogger {
    func reset() {}
    func record(source: String, message: String) {}
}
private enum NativeLogPrivacy {
    static func operationError(_ error: Error) -> NSError {
        NSError(domain: "fixture.redacted", code: 1)
    }
    static func runtimeEvent(_ text: String) -> String { "redacted" }
}
private func XRaySetMemoryLimit() {}
private func XRayStartPrivate(_ data: Data, _ logger: PluginXRayLogger,
                             _ error: UnsafeMutablePointer<NSError?>?) -> Bool {
    events.append("core-start"); startedData.append(data); return true
}
private func XRayStop() { events.append("core-stop") }
private enum SystemProxyHelper {
    static func setSystemProxy(config: String) throws { events.append("system-proxy") }
    static func clearSystemProxy() { events.append("clear-system-proxy") }
}
private enum VlessSystemControl { static func clear(group: String) { events.append("clear-control") } }
private final class Proxy {
    struct Prepared { let data: Data }
    var isRunning = false
    func stop() { events.append("proxy-stop") }
    func clearDiagnostics() { events.append("clear-diagnostics") }
    func start(configData: Data, geoAssetsDirectory: String?) throws {
        try start(prepared: Prepared(data: Data("prepared-new".utf8)), geoAssetsDirectory: geoAssetsDirectory)
    }
    func start(prepared: Prepared, geoAssetsDirectory: String?) throws {
        events.append("proxy-start"); proxyStartedData.append(prepared.data)
    }
}
private final class Manager {
    var remark = "old", xrayConfig = Data("old".utf8), bypassSubnets: [String] = []
    var proxyOnly = false, geoAssetsDirectory: String?
    var vpnRouting: NativeRoutingIntent?
    var certificateAssetsDirectory: String? = "/fixture/old-certificate-assets"
    func stop(waitForDisconnect: Bool) async throws { precondition(waitForDisconnect); events.append("vpn-stop") }
    func start() async throws { events.append("vpn-start") }
}

// PREFLIGHT_TRANSACTION_SOURCE is replaced by the production operation body.
// PROXY_RUNNER_START_SOURCE is replaced by the production runner methods.

@main struct TransactionTest {
    static func main() async throws {
        for proxyOnly in [false, true] {
            for failure in ["core", "assets", "active"] {
                events = []; available = true; assetFailure = failure == "assets"
                coreCode = failure == "core" ? 3 | 2 << 8 | 1 << 16 : 0
                let subject = StartProbe()
                subject.proxyOnlyRunner.isRunning = failure == "active"
                do {
                    try await subject.start(proxyOnly: proxyOnly).value
                    preconditionFailure("Rejected candidate was started")
                } catch {}
                precondition(subject.packetTunnelManager!.xrayConfig == Data("old".utf8))
                precondition(subject.packetTunnelManager!.certificateAssetsDirectory == "/fixture/old-certificate-assets")
                precondition(!events.contains { $0.contains("start") || $0.contains("stop") || $0.contains("clear") })
                precondition(events == (failure == "core" ? ["assets", "check"] : failure == "assets" ? ["assets"] : []))
            }
        }
        events = []; available = true; assetFailure = false; coreCode = 0
        let subject = StartProbe()
        try await subject.start(proxyOnly: false).value
        precondition(events == ["assets", "check", "proxy-stop", "clear-diagnostics", "vpn-start"])
        precondition(subject.packetTunnelManager!.xrayConfig == Data("new".utf8))
        precondition(subject.packetTunnelManager!.certificateAssetsDirectory == "/fixture/new-certificate-assets")
        events = []; available = false
        try await StartProbe().start(proxyOnly: true).value
        precondition(events == ["unavailable", "vpn-stop", "proxy-start"])

        // A raw source can pass Check while its transformed proxy candidate
        // fails. No active VPN/profile mutation may precede final admission.
        events = []; checkedData = []; proxyStartedData = []
        available = true; coreCode = 0; rejectPreparedCheck = true
        let rejected = StartProbe()
        do {
            try await rejected.start(proxyOnly: true).value
            preconditionFailure("Transformed proxy candidate bypassed preflight")
        } catch {
            precondition(!error.localizedDescription.contains("prepared-new"))
        }
        precondition(events == ["assets", "check"])
        precondition(checkedData == [Data("prepared-new".utf8)] && proxyStartedData.isEmpty)
        precondition(rejected.packetTunnelManager!.xrayConfig == Data("old".utf8))

        events = []; checkedData = []; proxyStartedData = []; rejectPreparedCheck = false
        try await StartProbe().start(proxyOnly: true).value
        precondition(checkedData == [Data("prepared-new".utf8)])
        precondition(proxyStartedData == checkedData)

        // Exercise the actual extracted runner, including its direct-call
        // convenience entry used by the runtime fixtures. Fakes do no I/O.
        events = []; checkedData = []; startedData = []; prepareCount = 0
        available = true; coreCode = 0; rejectPreparedCheck = true
        let running = ActualProxyRunner()
        running.fixtureSetRunning()
        do {
            try running.start(configData: Data("new".utf8), geoAssetsDirectory: nil)
            preconditionFailure("Rejected proxy candidate replaced a running proxy")
        } catch let error as CorePreflightError {
            precondition(error.stage == "active-session")
        }
        precondition(running.isRunning)
        precondition(events.isEmpty && prepareCount == 0 && checkedData.isEmpty && startedData.isEmpty)

        events = []; checkedData = []; startedData = []; prepareCount = 0
        do {
            try ActualProxyRunner().start(configData: Data("new".utf8), geoAssetsDirectory: nil)
            preconditionFailure("Final proxy candidate bypassed the runner's check")
        } catch {
            precondition(!error.localizedDescription.contains("prepared-new"))
        }
        precondition(events == ["assets", "check"])
        precondition(prepareCount == 1 && checkedData == [Data("prepared-new".utf8)] && startedData.isEmpty)

        events = []; checkedData = []; startedData = []; prepareCount = 0
        rejectPreparedCheck = false
        try ActualProxyRunner().start(configData: Data("new".utf8), geoAssetsDirectory: nil)
        precondition(prepareCount == 1 && checkedData == [Data("prepared-new".utf8)] && startedData == checkedData)

        events = []; checkedData = []; startedData = []; prepareCount = 0
        available = false
        try ActualProxyRunner().start(configData: Data("new".utf8), geoAssetsDirectory: nil)
        precondition(prepareCount == 1 && checkedData.isEmpty && startedData == [Data("prepared-new".utf8)])
        print("PASS: production Apple start transaction checks before stop/profile replacement; active sessions and asset failures preserved")
        print("PASS: exact prepared proxy bytes admitted before stop and reused by actual runner; legacy admission preserved")
    }
}
