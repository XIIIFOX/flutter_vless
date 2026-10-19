import Foundation

private var events: [String] = []
private var available = true
private var coreCode: Int64 = 0
private var assetFailure = false
private func FLVlessHasCorePreflight() -> Bool { available }
private func FLVlessCheckCorePrivate(_ data: Data) -> Int64 { events.append("check"); return coreCode }
private func configureXrayAssetLocation(_ directory: String?) throws {
    events.append("assets")
    if assetFailure { throw NSError(domain: "fixture", code: 1) }
}
private struct Log { func warning(_ text: String) { events.append("unavailable") } }
private let pluginLog = Log()
private enum VlessSystemControl { static func clear(group: String) { events.append("clear-control") } }
private final class Proxy {
    var isRunning = false
    func stop() { events.append("proxy-stop") }
    func clearDiagnostics() { events.append("clear-diagnostics") }
    func start(configData: Data, geoAssetsDirectory: String?) throws { events.append("proxy-start") }
}
private final class Manager {
    var remark = "old", xrayConfig = Data("old".utf8), bypassSubnets: [String] = []
    var proxyOnly = false, geoAssetsDirectory: String?
    var certificateAssetsDirectory: String? = "/fixture/old-certificate-assets"
    func stop(waitForDisconnect: Bool) async throws { precondition(waitForDisconnect); events.append("vpn-stop") }
    func start() async throws { events.append("vpn-start") }
}

// PREFLIGHT_TRANSACTION_SOURCE is replaced by the production operation body.

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
        print("PASS: production Apple start transaction checks before stop/profile replacement; active sessions and asset failures preserved")
    }
}
