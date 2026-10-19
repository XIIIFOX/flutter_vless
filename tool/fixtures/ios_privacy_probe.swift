// Test-only UIKit harness, concatenated after the actual private runner source.
final class ProbeLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ s: String?) { print("CALLBACK=\(s ?? "nil")") }
}
let canary = "privacy-canary.invalid"
private enum ProbePhaseReceipt {
    enum Phase: Int {
        case sleepEnter = 1, sleepReturn, closeEnter, closeReturn
        case stopEnter, stopReturn, modePass, complete
    }
#if os(iOS)
    private static var file: URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent("flutter-vless-probe-phase.json")
    }
#endif
    static func start() {
#if os(iOS)
        if let file { try? FileManager.default.removeItem(at: file) }
        print("PROBE_APP_PID=\(getpid())")
        fflush(stdout)
#endif
    }
    static func record(_ phase: Phase, completedModes: Int) {
#if os(iOS)
        // Diagnostic only: never change an operation, its assertion, or exit.
        guard (0...12).contains(completedModes), let file,
              let data = try? JSONSerialization.data(withJSONObject: [
                "schema": 1, "pid": Int(getpid()), "phase": phase.rawValue,
                "completed_modes": completedModes]), data.count <= 512 else { return }
        do {
            try data.write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch { /* The strict stdout qualifier remains the authority. */ }
#endif
    }
}
private func runtimeProbeSocket() -> Int32 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { print("PROBE_SOCKET_FAILED=create"); exit(1) }
    var noSignal: Int32 = 1
    guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
        close(fd)
        print("PROBE_SOCKET_FAILED=nosigpipe")
        exit(1)
    }
    return fd
}
func runRawRuntimeProbe() {
    let logger = ProbeLogger()
    print("RUNTIME=\(XRayGetVersion())")
    let malformed = Data("{\"outbounds\":[{\"protocol\":\"\(canary)\"}]}".utf8)
    var error: NSError?
    print("BUILD_RESULT=\(XRayStart(malformed, logger, &error)); ERROR=\(error?.localizedDescription ?? "nil")")
    let config = Data("""
    {"log":{"access":"","error":"","loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":18095,"protocol":"http","tag":"probe"}],"outbounds":[{"protocol":"blackhole","tag":"block"}]}
    """.utf8)
    error = nil
    if XRayStart(config, logger, &error) {
        let fd = runtimeProbeSocket()
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(18095).bigEndian
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
        _ = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        let request = Array("GET http://\(canary)/synthetic-password-canary HTTP/1.1\r\nHost: \(canary)\r\nConnection: close\r\n\r\n".utf8)
        _ = request.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
        Thread.sleep(forTimeInterval: 1)
        close(fd)
        XRayStop()
        print("LOCAL_ACCESS_PROBE_DONE")
    } else { print("START_ERROR=\(error?.localizedDescription ?? "nil")") }
    fflush(stdout)
}
extension ProxyOnlyRunner { static func prepared(_ data: Data) throws -> Data { try buildProxyOnlyConfigData(configData: data) } }
extension ServerDelayRunner { static func prepared(_ data: Data) throws -> Data { try buildDelayConfigData(config: String(decoding: data, as: UTF8.self), proxyPort: 18095, credentials: LocalProxyCredentials.generate()) } }
func runModes() async {
    setbuf(stdout, nil)
    ProbePhaseReceipt.start()
    print("MODES_BEGIN")
    runRawRuntimeProbe()
    do { try await runLocalAuthRuntimeChecks() } catch { print("AUTH_RUNTIME_FAILED"); exit(1) }
    do { try runDomainRoutingChecks() } catch { print("DOMAIN_ROUTING_FAILED"); exit(1) }
    do { try runDNSRuntimeChecks() } catch { print("DNS_RUNTIME_FAILED"); exit(1) }
    do { try runAssetRuntimeChecks() } catch { print("ASSET_RUNTIME_FAILED"); exit(1) }
    do { try runDirectOnlyRuntimeChecks() } catch { print("DIRECT_ONLY_RUNTIME_FAILED"); exit(1) }
    if ProcessInfo.processInfo.environment["REQUIRE_VPN_ROUTING"] == "1" {
        do { try runNativeRoutingRuntimeChecks() } catch { print("NATIVE_ROUTING_RUNTIME_FAILED"); exit(1) }
    }
    let markers = ["privacy-canary.invalid", "d2719f44-f51f-4c35-aeae-246230d21f38", "synthetic-password-canary"]
    let logger = ProbeLogger()
    var completedModes = 0
    for level in ["debug", "warning", "error", "none"] {
        let raw: [String:Any] = ["log": ["loglevel": level, "access": "", "error": "", "dnsLog": true],
            "inbounds": [["listen":"127.0.0.1","port":18095,"protocol":"socks","tag":"probe"]],
            "outbounds": [["protocol":"blackhole","tag":"block"],
                          ["protocol":"vless","tag":"proxy","settings":["vnext":[["address":"127.0.0.1","port":9,"users":[["id":markers[1],"encryption":"none"]]]]]]],
            "routing":["rules":[["type":"field","network":"tcp,udp","outboundTag":"block"]]],
            "remarks":markers.joined(separator:" ")]
        do {
            let data = try JSONSerialization.data(withJSONObject: raw)
            guard let tunnel = TunnelXrayConfigPreparer.prepare(jsonData:data, credentials: try LocalProxyCredentials.generate())?.data else { print("TUNNEL_PREPARE_FAILED");exit(1) }
            for (mode, prepared) in [("tunnel",tunnel),("proxy-only",try ProxyOnlyRunner.prepared(data)),("delay",try ServerDelayRunner.prepared(data))] {
                let decoded = try JSONSerialization.jsonObject(with:prepared) as! [String:Any]
                let log = decoded["log"] as! [String:Any]
                precondition(log["access"] as? String == "none" && log["error"] as? String == "none")
                precondition(log["loglevel"] as? String == (["error","none"].contains(level) ? level : "warning"))
                print("MODE_BEGIN=\(mode);LEVEL=\(level)")
                func stage(_ name: String, _ detail: String = "") {
                    print("MODE_STAGE=\(name);MODE=\(mode);LEVEL=\(level)\(detail)")
                    fflush(stdout)
                    if mode == "delay" && level == "none",
                       let phase = ["close-enter": ProbePhaseReceipt.Phase.closeEnter,
                                    "close-return": .closeReturn, "stop-enter": .stopEnter,
                                    "stop-return": .stopReturn][name] {
                        ProbePhaseReceipt.record(phase, completedModes: completedModes)
                    }
                }
                var error: NSError?
                stage("start-enter")
                let started = XRayStartPrivate(prepared,logger,&error)
                stage("start-return", ";OK=\(started)")
                if !started { print("START_FAILURE mode=\(mode) error=\(error?.localizedDescription ?? "nil")");exit(1) }
                stage("socket-enter")
                let fd = runtimeProbeSocket()
                stage("socket-return", ";FD=\(fd)")
                var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                let port = (decoded["inbounds"] as! [[String: Any]])[0]["port"] as! Int
                address.sin_family = sa_family_t(AF_INET);address.sin_port = UInt16(port).bigEndian
                inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)
                let connected = withUnsafePointer(to:&address) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { connect(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                let connectError = errno
                stage("connect-return", ";RESULT=\(connected);ERRNO=\(connectError)")
                precondition(connected == 0)
                let request = Array("GET http://\(markers[0])/\(markers[2]) HTTP/1.1\r\nHost: \(markers[0])\r\nConnection: close\r\n\r\n".utf8)
                let sent = request.withUnsafeBytes { send(fd,$0.baseAddress,$0.count,0) }
                let sendError = errno
                stage("send-return", ";RESULT=\(sent);ERRNO=\(sendError)")
                if mode == "delay" && level == "none" { ProbePhaseReceipt.record(.sleepEnter, completedModes: completedModes) }
                try await Task.sleep(nanoseconds: 100_000_000)
                if mode == "delay" && level == "none" { ProbePhaseReceipt.record(.sleepReturn, completedModes: completedModes) }
                stage("close-enter");close(fd);stage("close-return")
                stage("stop-enter");XRayStop();stage("stop-return")
                print("MODE_PASS=\(mode);LEVEL=\(level)")
                completedModes += 1
                if mode == "delay" && level == "none" { ProbePhaseReceipt.record(.modePass, completedModes: completedModes) }
            }
            // Exercise real app-process start/stop/snapshot and async delay runner.
            if level == "warning" {
                let runner = ProxyOnlyRunner()
                try runner.start(configData:data,geoAssetsDirectory:nil)
                precondition(!markers.contains { runner.debugSnapshot().contains($0) })
                runner.stop()
                let delay = await ServerDelayRunner().measure(config:String(decoding:data,as:UTF8.self),url:"http://127.0.0.1:9/",geoAssetsDirectory:nil)
                precondition(delay == -1) // blocked destination must not report false readiness
                print("RUNNER_SNAPSHOT_AND_DELAY_PASS")
            }
        } catch { print("MODE_TEST_FAILED");exit(1) }
    }
    fflush(stdout)
    ProbePhaseReceipt.record(.complete, completedModes: completedModes)
    exit(0)
}
class ModeDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey:Any]?) -> Bool {
        Task { await runModes() }; return true
    }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv,nil,NSStringFromClass(ModeDelegate.self))
