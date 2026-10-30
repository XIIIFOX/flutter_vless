import Foundation

@main struct GeoDatPolicyChecks {
    static func rejects(_ operation: () throws -> Void) {
        do { try operation(); preconditionFailure("GeoDAT invalid preparation admitted") } catch {}
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
        print("PASS GeoDAT actual policy old-capability/default-readonly/custom-root/atomic-probe/cleanup")
    }
}
