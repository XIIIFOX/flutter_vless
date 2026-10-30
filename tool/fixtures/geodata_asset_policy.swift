import Foundation

@main struct GeoDatPolicyChecks {
    static func rejects(_ operation: () throws -> Void) {
        do { try operation() } catch { return }
        FileHandle.standardError.write(Data("GeoDAT invalid preparation admitted\n".utf8))
        exit(1)
    }
    static func main() throws {
        let manager=FileManager.default
        let root=manager.temporaryDirectory.appendingPathComponent("flutter-vless-geodat-\(UUID().uuidString)",isDirectory:true)
        try manager.createDirectory(at:root.appendingPathComponent("nested"),withIntermediateDirectories:true)
        defer { try? manager.removeItem(at:root) }
        let file=root.appendingPathComponent("nested/custom.DAT")
        let original=Data("caller-full-dataset".utf8)
        try original.write(to:file)
        let active=Data(#"{"geodata":{"cron":"@daily","assets":[{"url":"https://example.test/full.dat","file":"nested/custom.DAT"}]}}"#.utf8)
        let required = try GeoDatAssetPolicy.requiresLifetime(active)
        precondition(required)
        rejects {try GeoDatAssetPolicy.validate(active,directory:root.path,lifetimeCapability:0)}
        rejects {try GeoDatAssetPolicy.validate(active,directory:nil,lifetimeCapability:1)}
        try GeoDatAssetPolicy.validate(active,directory:root.path,lifetimeCapability:1)
        let saved = try Data(contentsOf:file)
        precondition(saved==original)
        let children = try manager.contentsOfDirectory(atPath:root.appendingPathComponent("nested").path)
        precondition(children==["custom.DAT"])
        precondition(!manager.fileExists(atPath:root.appendingPathComponent("geoip.dat").path))
        for json in [#"{}"#,#"{"geodata":null}"#,#"{"geodata":{"cron":""}}"#] {
            try GeoDatAssetPolicy.validate(Data(json.utf8),directory:nil,lifetimeCapability:0)
        }
        let reload=Data(#"{"geodata":{"cron":"@daily"}}"#.utf8)
        rejects {try GeoDatAssetPolicy.validate(reload,directory:nil,lifetimeCapability:0)}
        try GeoDatAssetPolicy.validate(reload,directory:nil,lifetimeCapability:1)
        for name in ["../escape.dat","/absolute.dat","missing.dat","nested//custom.DAT","script.lua"] {
            let data=try JSONSerialization.data(withJSONObject:["geodata":["cron":"@daily","assets":[["file":name]]]])
            rejects {try GeoDatAssetPolicy.validate(data,directory:root.path,lifetimeCapability:1)}
        }
        let nested=root.appendingPathComponent("nested")
        try manager.setAttributes([.posixPermissions:0o500],ofItemAtPath:nested.path)
        rejects {try GeoDatAssetPolicy.validate(active,directory:root.path,lifetimeCapability:1)}
        try manager.setAttributes([.posixPermissions:0o700],ofItemAtPath:nested.path)
        let after = try Data(contentsOf:file)
        precondition(after==original)
        let afterChildren = try manager.contentsOfDirectory(atPath:nested.path)
        precondition(afterChildren==["custom.DAT"])
        let alias=Data(#"{"GEODATA":{"Cron":"@daily","Aſſets":[]}}"#.utf8)
        try GeoDatAssetPolicy.validate(alias,directory:nil,lifetimeCapability:1)
        let cloud = Data(#"{"outbounds":[{"protocol":"socks","streamSettings":{"network":"xdrive","xdriveSettings":{"service":"s3","remoteFolder":"synthetic-idle-worker","secrets":["synthetic-access","synthetic-secret"],"s3":{"endpoint":"https://example.test","bucket":"synthetic","pathStyle":true}}}}]}"#.utf8)
        for oldOrUnknown: Int64 in [0, 1, 3, -1] {
            rejects { try ManagedServiceAssetPolicy.validate(cloud,directory:nil,geodataCapability:1,xdriveCapability:oldOrUnknown) }
        }
        try ManagedServiceAssetPolicy.validate(cloud,directory:nil,geodataCapability:1,xdriveCapability:2)
        try ManagedServiceAssetPolicy.validate(cloud,directory:nil,geodataCapability:0,xdriveCapability:2)
        try ManagedServiceAssetPolicy.validate(Data("{}".utf8),directory:nil,geodataCapability:0,xdriveCapability:0)
        rejects { try ManagedServiceAssetPolicy.validate(reload,directory:nil,geodataCapability:0,xdriveCapability:2) }
        try ManagedServiceAssetPolicy.validate(reload,directory:nil,geodataCapability:1,xdriveCapability:0)
        print("PASS managed service exact Geo1/Xdrive2; r2 and unknown XDRIVE denied")
        print("PASS GeoDAT actual policy old-capability/default-readonly/custom-root/atomic-probe/cleanup")
    }
}
