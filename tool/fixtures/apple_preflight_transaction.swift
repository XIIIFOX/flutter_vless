import Foundation
import CoreFoundation

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
    if assetFailure { throw NSError(domain: "fixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "private-asset-path-canary"]) }
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
#if APPLE_PROXY_COUNTER_TEST
private var counterReply = ""
private func XRayQueryStats(_ tag: String?) -> String { counterReply }
#endif
private enum SystemProxyHelper {
    static func setSystemProxy(config: String) throws { events.append("system-proxy") }
    static func clearSystemProxy() { events.append("clear-system-proxy") }
}
private enum VlessSystemControl { static func clear(group: String) { events.append("clear-control") } }
private final class Proxy {
    struct Prepared { let data: Data; var changes: [NativePreparationReport.Change] = [] }
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
        let reply = try await StartProbe().startReply(proxyOnly: false)
        guard let envelope = reply as? [String: Any], let report = envelope["preparationReport"] as? [String: Any],
              report["version"] as? Int == 1, report["scope"] as? String == "host",
              report["coreCheck"] as? String == "passed" else {
            print("FAIL: actual Apple start success omitted its per-invocation preparation report")
            exit(1)
        }
        for (hasCheck, code) in [(false, Int64(0)), (true, Int64(-1)), (true, Int64(0))] {
            available = hasCheck; coreCode = code; events = []; checkedData = []; proxyStartedData = []
            let reply = try await StartProbe().startReply(proxyOnly: true) as! [String: Any]
            let report = reply["preparationReport"] as! [String: Any]
            let passed = hasCheck && code == 0
            precondition(report["coreCheck"] as? String == (passed ? "passed" : "unavailable"))
            precondition(report["scope"] as? String == (passed ? "runtimeFinal" : "host"))
            precondition(!hasCheck || checkedData == proxyStartedData)
        }
        available = true; coreCode = 0; events = []; checkedData = []
        let concurrent = StartProbe()
        let first = concurrent.start(proxyOnly: false, data: Data("first-secret-canary".utf8), changes: [.addressEnvironmentBound])
        let second = concurrent.start(proxyOnly: false, data: Data("second-secret-canary".utf8), changes: [.portEnvironmentBound])
        let firstReport = try await first.value, secondReport = try await second.value
        precondition(firstReport.changes == [.addressEnvironmentBound] && secondReport.changes == [.portEnvironmentBound])
        precondition(checkedData == [Data("first-secret-canary".utf8), Data("second-secret-canary".utf8)])
        let serialized = try JSONSerialization.data(withJSONObject: [firstReport.flutterResult, secondReport.flutterResult])
        precondition(!String(decoding: serialized, as: UTF8.self).contains("secret-canary"))
        print("PASS: actual Apple success reply, legacy unavailable, exact proxy bytes and queued invocation reports")
        for proxyOnly in [false, true] {
            for failure in ["core", "assets", "active"] {
                events = []; available = true; assetFailure = failure == "assets"
                coreCode = failure == "core" ? 3 | 2 << 8 | 1 << 16 : 0
                let subject = StartProbe()
                subject.proxyOnlyRunner.isRunning = failure == "active"
                do {
                    _ = try await subject.startReply(proxyOnly: proxyOnly)
                    preconditionFailure("Rejected candidate returned a successful report")
                } catch {
                    if failure == "assets" {
                        guard let closed = error as? CorePreflightError,
                              closed.stage == "prepare",
                              closed.details as NSDictionary == ["stage": "prepare"] as NSDictionary,
                              !closed.localizedDescription.contains("private-asset-path-canary") else {
                            fputs("FAIL: actual Apple asset setup failure omitted its safe preparation stage\n", stderr)
                            exit(1)
                        }
                    }
                }
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
#if APPLE_PROXY_COUNTER_TEST
        try preparationReportChecks()
        try counterChecks()
#endif
    }

#if APPLE_PROXY_COUNTER_TEST
    static func preparationReportChecks() throws {
        let safe: [String: Any] = ["log": ["access": "none", "error": "none", "loglevel": "warning", "dnsLog": false],
            "inbounds": [["listen": "127.0.0.1", "port": 18095, "protocol": "socks"]], "outbounds": [["protocol": "freedom"]]]
        var opaque = safe
        opaque["custom"] = ["access": "secret-canary", "tlsSettings": ["masterKeyLog": "secret-canary"], "type": "xicmp"]
        let baseline = try ActualProxyRunner.prepare(configData: JSONSerialization.data(withJSONObject: safe))
        let untouched = try ActualProxyRunner.prepare(configData: JSONSerialization.data(withJSONObject: opaque))
        precondition(baseline.changes.isEmpty && untouched.changes.isEmpty)
        var privateLog = safe; privateLog["log"] = ["access": "secret-canary", "error": "none", "loglevel": "warning", "dnsLog": false]
        let changed = try ActualProxyRunner.prepare(configData: JSONSerialization.data(withJSONObject: privateLog))
        precondition(changed.changes == [.privateLoggingApplied])
        var noListener = safe; noListener.removeValue(forKey: "inbounds")
        let listener = try ActualProxyRunner.prepare(configData: JSONSerialization.data(withJSONObject: noListener))
        precondition(listener.changes == [.privateListenerAdded])
        let encoded = try JSONSerialization.data(withJSONObject: NativePreparationReport(proxyOnly: true, coreCheckPassed: true, changes: changed.changes).flutterResult)
        precondition(!String(decoding: encoded, as: UTF8.self).contains("secret-canary"))
        print("PASS: actual proxy preparation reports only typed privacy/listener changes and ignores opaque metadata")
    }

    static func counterChecks() throws {
        var failures = 0
        let enabled = ["statsInboundUplink": true, "statsInboundDownlink": true,
                       "statsOutboundUplink": true, "statsOutboundDownlink": true]
        func check(_ name: String, _ ok: Bool, actual: (Int64, Int64)? = nil) {
            print("APPLE_PROXY_COUNTER_CASE=\(name);PASS=\(ok)" +
                  (actual.map { ";UP=\($0.0);DOWN=\($0.1)" } ?? ""))
            if !ok { failures += 1 }
        }
        func sample(_ name: String, tag: String? = "selected-primary", policy: Any? = nil,
                    extraInputs: [[String: Any]] = [], reply: (String) -> String,
                    expected: (Int64?, Int64?), after: ((ActualProxyRunner, String) -> Void)? = nil) throws {
            var primary: [String: Any] = ["listen": "127.0.0.1", "port": 18095, "protocol": "socks"]
            if let tag { primary["tag"] = tag }
            var source: [String: Any] = [
                "inbounds": [primary,
                             ["tag": "unrelated-uplink", "listen": "127.0.0.1", "port": 18096, "protocol": "socks"]] + extraInputs,
                "outbounds": [["tag": "edge-live", "protocol": "freedom"]]]
            if let policy { source["policy"] = policy }
            let sourceData = try JSONSerialization.data(withJSONObject: source)
            events = []; checkedData = []; startedData = []; prepareCount = 0
            available = true; coreCode = 0; assetFailure = false; rejectPreparedCheck = false
            let subject = ActualProxyRunner()
            try subject.start(configData: sourceData, geoAssetsDirectory: nil)
            defer { subject.stop() }
            precondition(prepareCount == 1 && startedData.count == 1 && checkedData == startedData)
            let prepared = try JSONSerialization.jsonObject(with: startedData[0]) as! [String: Any]
            let inputs = prepared["inbounds"] as! [[String: Any]]
            let selected = inputs.first { ["socks", "http"].contains($0["protocol"] as? String ?? "") }!
            let selectedTag = selected["tag"] as? String
            precondition(selectedTag == tag && inputs as NSArray == source["inbounds"] as! NSArray)
            if let policy {
                precondition(NSDictionary(dictionary: ["value": prepared["policy"]!]) == NSDictionary(dictionary: ["value": policy]))
            } else {
                let system = (prepared["policy"] as! [String: Any])["system"] as! [String: Any]
                check("absent-policy-inbound-default", system["statsInboundUplink"] as? Bool == true && system["statsInboundDownlink"] as? Bool == true)
            }
            counterReply = reply(selectedTag ?? "")
            let actual = subject.queryTrafficStats()
            let optional = subject.fixtureCounterDirections()
            check(name, actual.upload == (expected.0 ?? 0) && actual.download == (expected.1 ?? 0) &&
                  optional.0 == expected.0 && optional.1 == expected.1 &&
                  actual.uploadSpeed == 0 && actual.downloadSpeed == 0, actual: (actual.upload, actual.download))
            // QueryStats is cumulative and non-resetting; repeat the same reply.
            let again = subject.queryTrafficStats()
            check(name + "-repeat", again.upload == (expected.0 ?? 0) && again.download == (expected.1 ?? 0) &&
                  again.uploadSpeed == 0 && again.downloadSpeed == 0, actual: (again.upload, again.download))
            after?(subject, selectedTag ?? "")
            subject.stop()
            let stopped = subject.queryTrafficStats()
            let absent = subject.fixtureCounterDirections()
            check(name + "-stop", absent.0 == nil && absent.1 == nil && stopped.upload == 0 && stopped.download == 0 &&
                  stopped.uploadSpeed == 0 && stopped.downloadSpeed == 0)
        }
        func owned(_ tag: String, _ up: Int64, _ down: Int64) -> String {
            "inbound>>>\(tag)>>>traffic>>>uplink>>>\(up)\ninbound>>>\(tag)>>>traffic>>>downlink>>>\(down)\n"
        }
        let noise = "inbound>>>unrelated-uplink>>>traffic>>>uplink>>>100\n" +
                    "outbound>>>edge-live>>>traffic>>>downlink>>>200\nuser>>>unrelated>>>traffic>>>uplink>>>300\n"
        try sample("owned-exact", policy: ["system": enabled], reply: { owned($0, 11, 22) + noise }, expected: (11, 22))
        try sample("available-zero", policy: ["system": enabled], reply: { owned($0, 0, 0) + noise }, expected: (0, 0))
        try sample("missing-owned", policy: ["system": enabled], reply: { _ in noise }, expected: (nil, nil))
        try sample("direction-word-tag", tag: "selected-downlink-uplink", policy: ["system": enabled], reply: { owned($0, 11, 22) }, expected: (11, 22))
        try sample("partial-direction", policy: ["system": ["statsInboundUplink": true, "statsInboundDownlink": false]],
                   reply: { "inbound>>>\($0)>>>traffic>>>uplink>>>11\n" + noise }, expected: (11, nil))
        try sample("line-ambiguous-tag", tag: "selected\r\nprimary", policy: ["system": enabled], reply: { owned($0, 11, 22) }, expected: (nil, nil))
        try sample("untagged-primary", tag: nil, policy: ["system": enabled], reply: { _ in noise }, expected: (nil, nil))
        try sample("duplicate-tag", policy: ["system": enabled],
                   extraInputs: [["tag": "selected-primary", "protocol": "socks", "port": 18097]],
                   reply: { owned($0, 11, 22) }, expected: (nil, nil))
        try sample("ambiguous-endpoint", policy: ["system": enabled],
                   extraInputs: [["tag": "second", "protocol": "socks", "port": 18095]],
                   reply: { owned($0, 11, 22) }, expected: (nil, nil))
        try sample("disabled-policy", policy: ["system": enabled.mapValues { _ in false }], reply: { _ in "" }, expected: (nil, nil))
        try sample("null-policy", policy: NSNull(), reply: { _ in "" }, expected: (nil, nil))
        try sample("levels-only-policy", policy: ["levels": ["0": ["bufferSize": 3]]], reply: { _ in "" }, expected: (nil, nil))
        try sample("default-policy", reply: { _ in "" }, expected: (nil, nil))
        for invalid in ["", "-1", "not-a-number", "9223372036854775808"] {
            try sample("invalid-up-\(invalid)", policy: ["system": enabled],
                       reply: { "inbound>>>\($0)>>>traffic>>>uplink>>>\(invalid)\n" +
                                "inbound>>>\($0)>>>traffic>>>downlink>>>22\n" }, expected: (nil, 22))
        }
        try sample("baseline-gaps-reset", policy: ["system": enabled], reply: { owned($0, 0, 0) }, expected: (0, 0)) { subject, tag in
            counterReply = owned(tag, 5, 7)
            let increased = subject.queryTrafficStats()
            check("zero-is-available-baseline", increased.uploadSpeed == 5 && increased.downloadSpeed == 7)
            counterReply = "inbound>>>\(tag)>>>traffic>>>downlink>>>9\n"
            let partial = subject.queryTrafficStats()
            check("gap-direction-local", partial.uploadSpeed == 0 && partial.downloadSpeed == 2)
            counterReply = owned(tag, 8, 1)
            let resumed = subject.queryTrafficStats()
            check("gap-and-reset-first-speed-zero", resumed.uploadSpeed == 0 && resumed.downloadSpeed == 0)
            subject.stop()
            try! subject.start(configData: startedData[0], geoAssetsDirectory: nil)
            let restarted = subject.queryTrafficStats()
            check("restart-clears-baselines", restarted.upload == 8 && restarted.download == 1 &&
                  restarted.uploadSpeed == 0 && restarted.downloadSpeed == 0)
        }

        // The shared CLI corpus contains exact int64 values. Reconstruct the
        // mobile text wire (including explicit zero); do not round via Double.
        func integer(_ value: Any) -> Int64 {
            guard let number = value as? NSNumber,
                  ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: number.objCType)),
                  CFGetTypeID(number) != CFBooleanGetTypeID(), let result = Int64(number.stringValue) else {
                preconditionFailure("Shared counter fixture must contain signed int64 values")
            }
            return result
        }
        let fixturePath = ProcessInfo.processInfo.environment["APPLE_TRAFFIC_COUNTER_FIXTURE"]!
        let corpus = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: fixturePath))) as! [[String: Any]]
        precondition(corpus.count == 11)
        for item in corpus {
            let expected = item["expected"] as! [String: Any]
            let up = expected["uplink"] is NSNull ? nil : integer(expected["uplink"]!)
            let down = expected["downlink"] is NSNull ? nil : integer(expected["downlink"]!)
            let text = (item["counters"] as? [[String: Any]] ?? []).map {
                ($0["name"] as! String) + ">>>" + String(integer($0["value"]!)) + "\n"
            }.joined()
            try sample("shared-" + (item["name"] as! String), tag: item["tag"] as? String,
                       policy: ["system": enabled], reply: { _ in text }, expected: (up, down))
        }
        print("APPLE_PROXY_COUNTER_SHARED_CASES=\(corpus.count)")
        precondition(!events.contains("system-proxy") || events.contains("core-start"))
        print("APPLE_PROXY_COUNTER_FAILURES=\(failures)")
        if failures != 0 { exit(7) }
    }
#endif
}
