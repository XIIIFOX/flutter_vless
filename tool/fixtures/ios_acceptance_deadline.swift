import Foundation

enum DeadlineClock {
    static var jobs: [(Int, DispatchWorkItem)] = []
    static func schedule(_ seconds: Int, _ work: DispatchWorkItem) { jobs.append((seconds, work)) }
    static func fire(_ index: Int) { jobs[index].1.perform() }
}
final class NETunnelProviderProtocol {
    var providerBundleIdentifier: String?
    var providerConfiguration: [String: Any]?
    init(_ identifier: String = "owned.provider", _ reference: Data = Data([1])) {
        providerBundleIdentifier = identifier; providerConfiguration = ["xrayConfigReference": reference]
    }
}
final class FakeConnection {
    var stops = 0
    var onStop: (() -> Void)?
    func stopVPNTunnel() { stops += 1; onStop?() }
}
final class NETunnelProviderManager {
    static var load: ((@escaping ([NETunnelProviderManager]?, Error?) -> Void) -> Void)?
    var protocolConfiguration: Any?
    let connection = FakeConnection()
    init(_ configuration: NETunnelProviderProtocol) { protocolConfiguration = configuration }
    static func loadAllFromPreferences(completionHandler: @escaping ([NETunnelProviderManager]?, Error?) -> Void) {
        load!(completionHandler)
    }
}
struct VlessNativeOptions {
    var reconnectEnabled = false
    var onDemand = "disabled"
    var enableOnDemand = false
    var quickAccessEnabled = false
}
var logs: [String] = []
func rememberTunnelLog(_ text: String) { logs.append(text) }
final class PacketTunnelProvider {
    let sessionAdmission = TunnelSessionAdmission()
    var protocolConfiguration: Any? = NETunnelProviderProtocol()
    var cancelled = 0
    func cancelTunnelWithError(_ error: Error?) { cancelled += 1 }
    func tunnelError(_ text: String) -> Error { NSError(domain: "fake", code: 1) }
    #if FLUTTER_VLESS_ACCEPTANCE_TESTING
    // ACTUAL_DEADLINE_SOURCE
    #endif
}

@main struct Tests {
    static func main() throws {
        #if FLUTTER_VLESS_ACCEPTANCE_TESTING && FLUTTER_VLESS_ACCEPTANCE_SESSION_DEADLINE
        var checks = 0
        func check(_ value: Bool) { precondition(value); checks += 1 }
        func fixture() -> (PacketTunnelProvider, NETunnelProviderManager) {
            DeadlineClock.jobs = []; logs = []
            let provider = PacketTunnelProvider()
            let manager = NETunnelProviderManager(provider.protocolConfiguration as! NETunnelProviderProtocol)
            NETunnelProviderManager.load = { $0([manager], nil) }
            return (provider, manager)
        }
        do {
            let (p, m) = fixture()
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            check(DeadlineClock.jobs.count == 1 && DeadlineClock.jobs[0].0 == 110)
            check(m.connection.stops == 0)
            var callback: (([NETunnelProviderManager]?, Error?) -> Void)?
            NETunnelProviderManager.load = { callback = $0 }
            DeadlineClock.fire(0); check(DeadlineClock.jobs[1].0 == 5)
            callback?([m], nil); callback?([m], nil); DeadlineClock.fire(1)
            // This manager never completes provider Stop: local cancellation is independently requested.
            check(m.connection.stops == 1 && p.cancelled == 1)
        }
        do {
            let (p, m) = fixture()
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            _ = p.revokeAcceptanceSessionDeadline(); DeadlineClock.fire(0)
            check(m.connection.stops == 0 && p.cancelled == 0)
        }
        do {
            let (p, m) = fixture()
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            DeadlineClock.fire(0); check(m.connection.stops == 0)
            DeadlineClock.fire(1); check(m.connection.stops == 1)
        }
        do {
            let (p, m) = fixture()
            var callback: (([NETunnelProviderManager]?, Error?) -> Void)?
            NETunnelProviderManager.load = { callback = $0 }
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            DeadlineClock.fire(0)
            _ = p.revokeAcceptanceSessionDeadline()
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            callback?([m], nil); DeadlineClock.fire(1)
            check(m.connection.stops == 0 && p.cancelled == 0)
        }
        do {
            let (p, m) = fixture()
            let old = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            // A synchronous manager callback can revoke and replace the session.
            m.connection.onStop = {
                _ = p.revokeAcceptanceSessionDeadline()
                _ = try! p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            }
            DeadlineClock.fire(0)
            check(m.connection.stops == 1 && p.cancelled == 0 && p.sessionAdmission.currentEpoch != old)
        }
        for mode in ["wrong-reference", "foreign", "ambiguous"] {
            let (p, m) = fixture()
            let wrong = NETunnelProviderManager(NETunnelProviderProtocol(mode == "foreign" ? "other.provider" : "owned.provider", Data([2])))
            NETunnelProviderManager.load = { $0(mode == "ambiguous" ? [m, m] : [wrong], nil) }
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            DeadlineClock.fire(0); DeadlineClock.fire(1)
            check(m.connection.stops == 0 && wrong.connection.stops == 0 && p.cancelled == 0)
        }
        for timedOut in [false, true] {
            let (p, m) = fixture()
            var callback: (([NETunnelProviderManager]?, Error?) -> Void)?
            NETunnelProviderManager.load = { callback = $0 }
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            DeadlineClock.fire(0)
            if timedOut { DeadlineClock.fire(1) }
            else { callback?(nil, NSError(domain: "fake", code: 1)) }
            callback?([m], nil); DeadlineClock.fire(1)
            check(m.connection.stops == 0 && p.cancelled == 1)
        }
        do {
            let (p, m) = fixture()
            var callback: (([NETunnelProviderManager]?, Error?) -> Void)?
            NETunnelProviderManager.load = { callback = $0 }
            _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: VlessNativeOptions())
            DeadlineClock.fire(0)
            p.protocolConfiguration = NETunnelProviderProtocol("owned.provider", Data([2]))
            callback?([m], nil); DeadlineClock.fire(1)
            check(m.connection.stops == 0 && p.cancelled == 0)
        }
        for property in ["reconnect", "onDemand", "quick"] {
            let (p, _) = fixture(); var options = VlessNativeOptions()
            if property == "reconnect" { options.reconnectEnabled = true }
            if property == "onDemand" { options.onDemand = "enabled"; options.enableOnDemand = true }
            if property == "quick" { options.quickAccessEnabled = true }
            var refused = false
            do { _ = try p.beginAcceptanceSessionDeadline(configuration: p.protocolConfiguration as! NETunnelProviderProtocol, options: options) }
            catch { refused = true }
            check(refused && DeadlineClock.jobs.isEmpty && p.sessionAdmission.currentEpoch == nil)
        }
        print("IOS_ACCEPTANCE_SESSION_DEADLINE_FAKE_PASS=\(checks)")
        #else
        precondition(DeadlineClock.jobs.isEmpty)
        print("IOS_ACCEPTANCE_SESSION_DEADLINE_ABSENT_PASS=1")
        #endif
    }
}
