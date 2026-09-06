// Test-only UIKit harness, concatenated after the actual private runner source.
final class ProbeLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ s: String?) { print("CALLBACK=\(s ?? "nil")") }
}
let canary = "privacy-canary.invalid"
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
        let fd = socket(AF_INET, SOCK_STREAM, 0)
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
extension ServerDelayRunner { static func prepared(_ data: Data) throws -> Data { try buildDelayConfigData(config: String(decoding: data, as: UTF8.self), proxyPort: 18095) } }
func runModes() async {
    setbuf(stdout, nil)
    print("MODES_BEGIN")
    runRawRuntimeProbe()
    let markers = ["privacy-canary.invalid", "d2719f44-f51f-4c35-aeae-246230d21f38", "synthetic-password-canary"]
    let logger = ProbeLogger()
    for level in ["debug", "warning", "error", "none"] {
        let raw: [String:Any] = ["log": ["loglevel": level, "access": "", "error": "", "dnsLog": true],
            "inbounds": [["listen":"127.0.0.1","port":18095,"protocol":"http","tag":"probe"]],
            "outbounds": [["protocol":"blackhole","tag":"block"],
                          ["protocol":"vless","tag":"proxy","settings":["vnext":[["address":"127.0.0.1","port":9,"users":[["id":markers[1],"encryption":"none"]]]]]]],
            "routing":["rules":[["type":"field","network":"tcp,udp","outboundTag":"block"]]],
            "remarks":markers.joined(separator:" ")]
        do {
            let data = try JSONSerialization.data(withJSONObject: raw)
            guard let tunnel = TunnelXrayConfigPreparer.prepare(jsonData:data)?.data else { print("TUNNEL_PREPARE_FAILED");exit(1) }
            for (mode, prepared) in [("tunnel",tunnel),("proxy-only",try ProxyOnlyRunner.prepared(data)),("delay",try ServerDelayRunner.prepared(data))] {
                let decoded = try JSONSerialization.jsonObject(with:prepared) as! [String:Any]
                let log = decoded["log"] as! [String:Any]
                precondition(log["access"] as? String == "none" && log["error"] as? String == "none")
                precondition(log["loglevel"] as? String == (["error","none"].contains(level) ? level : "warning"))
                var error: NSError?
                if !XRayStartPrivate(prepared,logger,&error) { print("START_FAILURE mode=\(mode) error=\(error?.localizedDescription ?? "nil")");exit(1) }
                let fd = socket(AF_INET, SOCK_STREAM, 0)
                var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                address.sin_family = sa_family_t(AF_INET);address.sin_port = UInt16(18095).bigEndian
                inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)
                let connected = withUnsafePointer(to:&address) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { connect(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                precondition(connected == 0)
                let request = Array("GET http://\(markers[0])/\(markers[2]) HTTP/1.1\r\nHost: \(markers[0])\r\nConnection: close\r\n\r\n".utf8)
                _ = request.withUnsafeBytes { send(fd,$0.baseAddress,$0.count,0) }
                try await Task.sleep(nanoseconds: 100_000_000);close(fd);XRayStop()
                print("MODE_PASS=\(mode);LEVEL=\(level)")
            }
            // Exercise real app-process start/stop/snapshot and async delay runner.
            if level == "warning" {
                let runner = ProxyOnlyRunner()
                try runner.start(configData:data,geoAssetsDirectory:nil)
                precondition(!markers.contains { runner.debugSnapshot().contains($0) })
                runner.stop()
                let delay = await ServerDelayRunner().measure(config:String(decoding:data,as:UTF8.self),url:"http://127.0.0.1:9/",geoAssetsDirectory:nil)
                precondition(delay >= 0)
                print("RUNNER_SNAPSHOT_AND_DELAY_PASS")
            }
        } catch { print("MODE_TEST_FAILED");exit(1) }
    }
    fflush(stdout);exit(0)
}
class ModeDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey:Any]?) -> Bool {
        Task { await runModes() }; return true
    }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv,nil,NSStringFromClass(ModeDelegate.self))
