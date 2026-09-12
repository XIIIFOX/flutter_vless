// Private supplied profiles are bundled temporarily by the test orchestrator.
// Real Xray runs only as a loopback proxy; no NetworkExtension is installed.
import flutter_vless_tunnel_support

final class RoutingLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ text: String?) { /* Native text never enters the test report. */ }
}

func routingIPv4(_ host: String) -> String? {
    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_STREAM
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &result) == 0, let result else { return nil }
    defer { freeaddrinfo(result) }
    var address = result.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
    return String(cString: buffer)
}

func runPrivateRouting() async {
    setbuf(stdout, nil)
    do {
        let profile = try Data(contentsOf: Bundle.main.url(forResource: "profile", withExtension: "json")!)
        let mode = Bundle.main.object(forInfoDictionaryKey: "RoutingMode") as! String
        let proxy = ProxyOnlyRunner()
        let logger = RoutingLogger()
        if mode == "original" {
            do { try LocalProxyAccessPolicy.validateVPN(configData: profile); print("ROUTING_UNSAFE_ACCEPT"); exit(1) }
            catch LocalProxyAccessError.incompatibleInbounds { print("ROUTING_ORIGINAL_VPN_REJECT_PASS") }
            try proxy.start(configData: profile, geoAssetsDirectory: nil)
        } else {
            let credentials = try LocalProxyCredentials(username: "routing-fixture-user", password: "routing-fixture-password")
            guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: profile, credentials: credentials,
                                                                  resolveIPv4: routingIPv4) else {
                print("ROUTING_PREPARATION_FAILED"); exit(1)
            }
            var error: NSError?
            guard XRayStartPrivate(prepared.data, logger, &error) else { print("ROUTING_NATIVE_START_FAILED"); exit(1) }
        }
        print("ROUTING_READY")
        // The parent always terminates/uninstalls this disposable app. Bound a
        // lost parent as well; retain the real runner/logger for the full probe.
        for _ in 0..<3000 {
            var counters: [String: Int64] = [:]
            for tag in ["direct", "proxy"] {
                for line in XRayQueryStats(tag).split(separator: "\n") {
                    let fields = line.components(separatedBy: ">>>")
                    guard fields.count >= 4, fields[0] == "outbound", fields[1] == tag,
                          let value = Int64(fields.last!) else { continue }
                    counters[tag, default: 0] += value
                }
            }
            print("ROUTING_COUNTERS=\(counters["direct", default: 0]),\(counters["proxy", default: 0])")
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        withExtendedLifetime(logger) { proxy.stop(); XRayStop() }
        exit(0)
    } catch { print("ROUTING_PROBE_FAILED"); exit(1) }
}

final class RoutingDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        Task { await runPrivateRouting() }
        return true
    }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(RoutingDelegate.self))
