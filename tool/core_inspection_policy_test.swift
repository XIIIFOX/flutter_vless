import Foundation

@main struct CoreInspectionPolicyTest {
    static func main() throws {
        let config = "{\"outbounds\":[{\"protocol\":\"freedom\"}]}"
        let argument = ["config": config]
        let capabilities = NativeCoreInspection.capabilities(coreVersion: "Xray 26.11.9 fixture",
            profileValidation: true, vpnRouting: 1, geoDataUpdates: 1, xdrive: 2, balancerSelections: true)
        precondition(capabilities as NSDictionary == [
            "coreVersion": "Xray 26.11.9 fixture", "profileValidation": true, "vpnRouting": true,
            "geoDataUpdates": true, "xdrive": true, "balancerSelections": true,
        ] as NSDictionary)
        let unavailable = NativeCoreInspection.capabilities(coreVersion: "", profileValidation: false,
            vpnRouting: 2, geoDataUpdates: 2, xdrive: 1, balancerSelections: false)
        precondition(unavailable["coreVersion"] == nil)
        precondition(unavailable.values.allSatisfy { $0 as? Bool == false })

        func inspect(_ arguments: [String: Any]?, supported: Bool = true, geodata: Int64 = 1, xdrive: Int64 = 2,
                     check: (Data) -> Int64 = { _ in preconditionFailure("Unexpected Core invocation") }) -> NSDictionary {
            NativeCoreInspection.validate(arguments, supported: supported,
                geodataCapability: geodata, xdriveCapability: xdrive, check: check) as NSDictionary
        }

        precondition(inspect(nil) == ["status": "invalid", "stage": "prepare"])
        precondition(inspect(["config": "not JSON"]) == ["status": "invalid", "stage": "prepare"])
        precondition(inspect(["config": config, "geo_assets_directory": 1]) == ["status": "invalid", "stage": "prepare"])
        precondition(inspect(["config": config, "certificate_assets_directory": "relative-canary"]) == ["status": "invalid", "stage": "prepare"])
        precondition(inspect(argument, supported: false) == ["status": "unsupported"])
        precondition(inspect(argument) { _ in -1 } == ["status": "unsupported"])
        precondition(inspect(argument) { _ in 4 } == ["status": "unavailable"])
        precondition(inspect(argument) { _ in Int64.max } == ["status": "unavailable"])
        precondition(inspect(argument) { _ in 2 } == ["status": "invalid", "stage": "coreCheck"])
        precondition(inspect(argument) { _ in 3 | 2 << 8 | 3 << 16 } ==
            ["status": "invalid", "stage": "coreCheck", "section": "outbounds", "index": 2])
        precondition(inspect(argument) { _ in 3 | 7 << 8 | 3 << 16 } == ["status": "invalid", "stage": "coreCheck"])
        precondition(inspect(["config": "{\"Env\":{\"private-inspection-canary\":null}}"]) == ["status": "unsupported"])
        precondition(inspect(["config": "{\"geodata\":{\"cron\":\"@every 1h\"}}"], geodata: 0) ==
            ["status": "unsupported"])
        let drive = """
            {"outbounds":[{"protocol":"vless","streamSettings":{"network":"xdrive",
                "xdriveSettings":{"service":"google-drive","remoteFolder":"fixture",
                "secrets":["synthetic-id","synthetic-secret","synthetic-token"]}}}]}
            """
        precondition(inspect(["config": drive], xdrive: 1) == ["status": "unsupported"])
        precondition(inspect(["config": drive]) { _ in 0 } == ["status": "valid"])

        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        precondition(inspect(["config": config, "geo_assets_directory": root.path]) == ["status": "unsupported"])
        let update = """
            {"geodata":{"cron":"@every 1h","assets":[{"file":"geoip.dat","url":"https://example.test/geoip.dat"}]}}
            """
        precondition(inspect(["config": update]) == ["status": "unsupported"])
        precondition(inspect(["config": "{\"geodata\":{\"cron\":\"@every 1h\",\"assets\":[]}}"]) {
            _ in 0
        } == ["status": "valid"])
        let contents = try FileManager.default.contentsOfDirectory(atPath: root.path)
        precondition(contents.isEmpty)

        let certificateConfig = """
            {"outbounds":[{"protocol":"vless","streamSettings":{"security":"tls",
                "tlsSettings":{"certificates":[{"certificateFile":"cert.pem","keyFile":"key.pem"}]}}}]}
            """
        precondition(inspect(["config": certificateConfig, "certificate_assets_directory": root.path]) { data in
            let object = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
            let outbound = (object["outbounds"] as! [[String: Any]])[0]
            let stream = outbound["streamSettings"] as! [String: Any]
            let tls = stream["tlsSettings"] as! [String: Any]
            let cert = (tls["certificates"] as! [[String: Any]])[0]
            precondition(cert["certificateFile"] as? String == root.appendingPathComponent("cert.pem").path)
            precondition(cert["keyFile"] as? String == root.appendingPathComponent("key.pem").path)
            return 0
        } == ["status": "valid"])
        print("PASS: Apple SDK capability flags, file-only validation, scoped certificates and closed results")
    }
}
