import Foundation
import Darwin

public enum GeoDatAssetError: Error, LocalizedError {
    case invalidConfiguration, runtimeUnavailable, writableRootRequired, assetUnavailable, atomicReplacement, cleanupFailed
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Invalid GeoDAT updater configuration"
        case .runtimeUnavailable: return "Scheduled GeoDAT or XDRIVE requires an updated managed-service Xray runtime"
        case .writableRootRequired: return "GeoDAT downloads require an existing writable geoAssetsDirectory; Apple app bundles are read-only"
        case .assetUnavailable: return "GeoDAT updater files must already exist as local regular DAT files"
        case .atomicReplacement: return "GeoDAT updater requires atomic file replacement in its asset directory"
        case .cleanupFailed: return "GeoDAT updater write-check cleanup failed"
        }
    }
}

public enum GeoDatAssetPolicy {
    private static func field(_ object: [String: Any], _ name: String) throws -> Any? {
        let keys = object.keys.filter { XrayJSONField.matches($0, name) }
        guard keys.count <= 1 else { throw GeoDatAssetError.invalidConfiguration }
        guard let key = keys.first, !(object[key] is NSNull) else { return nil }
        return object[key]
    }
    private static func section(_ data: Data) throws -> [String: Any]? {
        guard let config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw GeoDatAssetError.invalidConfiguration }
        guard let value = try field(config, "geodata") else { return nil }
        guard let object = value as? [String: Any] else { throw GeoDatAssetError.invalidConfiguration }
        return object
    }
    public static func requiresLifetime(_ data: Data) throws -> Bool {
        guard let object = try section(data), let value = try field(object, "cron") else { return false }
        guard let cron = value as? String else { throw GeoDatAssetError.invalidConfiguration }
        return !cron.isEmpty
    }
    public static func validate(_ data: Data, directory: String?, lifetimeCapability: Int64) throws {
        guard try requiresLifetime(data) else { return }
        guard lifetimeCapability == 1 else { throw GeoDatAssetError.runtimeUnavailable }
        let object = try section(data)!
        guard let raw = try field(object, "assets") else { return } // Reload only.
        guard let assets = raw as? [[String: Any]], assets.count <= 100 else { throw GeoDatAssetError.invalidConfiguration }
        if assets.isEmpty { return }
        var isDirectory: ObjCBool = false
        guard let directory, directory.hasPrefix("/"), !directory.contains("\0"),
              FileManager.default.fileExists(atPath: directory, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw GeoDatAssetError.writableRootRequired
        }
        let root = URL(fileURLWithPath: directory, isDirectory: true)
        var parents = Set<URL>()
        for asset in assets {
            guard let name = try field(asset, "file") as? String,
                  !name.hasPrefix("/"), !name.contains("\0"), name.lowercased().hasSuffix(".dat"),
                  name.split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
                throw GeoDatAssetError.assetUnavailable
            }
            let file = root.appendingPathComponent(name)
            guard (try? file.resolvingSymlinksInPath().resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
                throw GeoDatAssetError.assetUnavailable
            }
            parents.insert(file.deletingLastPathComponent())
        }
        for parent in parents { try probe(parent) }
    }
    private static func probe(_ parent: URL) throws {
        let prefix = ".flutter-vless-geodat-check-\(UUID().uuidString)"
        let first = parent.appendingPathComponent(prefix + "-one.tmp")
        let second = parent.appendingPathComponent(prefix + "-two.tmp")
        var owned: [URL] = []
        var failure: Error?
        do {
            for file in [first, second] {
                let descriptor = Darwin.open(file.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, mode_t(0o600))
                guard descriptor >= 0 else { throw GeoDatAssetError.writableRootRequired }
                owned.append(file)
                guard Darwin.close(descriptor) == 0 else { throw GeoDatAssetError.atomicReplacement }
            }
            guard Darwin.rename(first.path, second.path) == 0 else { throw GeoDatAssetError.atomicReplacement }
        } catch { failure = error }
        var clean = true
        for file in owned {
            if Darwin.unlink(file.path) != 0 && errno != ENOENT { clean = false }
        }
        guard clean else { throw GeoDatAssetError.cleanupFailed }
        if let failure { throw failure }
    }
}

/// Both managed features are checked before any current session is released.
public enum ManagedServiceAssetPolicy {
    public static func validate(_ data: Data, directory: String?, geodataCapability: Int64, xdriveCapability: Int64) throws {
        if try XdriveServicePolicy.requiresLifetime(data), xdriveCapability != 1 { throw GeoDatAssetError.runtimeUnavailable }
        try GeoDatAssetPolicy.validate(data, directory: directory, lifetimeCapability: geodataCapability)
    }
}
