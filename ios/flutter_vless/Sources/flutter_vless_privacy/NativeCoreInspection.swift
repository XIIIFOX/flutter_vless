import Foundation

/// App-process Core inspection. Uses the installed SDK's file-only checker
/// and never configures the active runtime or its process-wide asset location.
public enum NativeCoreInspection {
    public static func capabilities(coreVersion: String, profileValidation: Bool, vpnRouting: Int64,
                                    geoDataUpdates: Int64, xdrive: Int64,
                                    balancerSelections: Bool) -> [String: Any] {
        var result: [String: Any] = [
            "profileValidation": profileValidation,
            "vpnRouting": vpnRouting == 1,
            "geoDataUpdates": geoDataUpdates == 1,
            "xdrive": xdrive == 2,
            "balancerSelections": balancerSelections,
        ]
        if !coreVersion.isEmpty { result["coreVersion"] = coreVersion }
        return result
    }

    /// Validates a candidate without starting workers or replacing the active
    /// configuration. A caller-owned certificate root is bound to the copy.
    /// The installed Apple ABI has no request-scoped GeoDAT path override.
    public static func validate(_ arguments: [String: Any]?, supported: Bool,
                                geodataCapability: Int64, xdriveCapability: Int64,
                                check: (Data) -> Int64) -> [String: Any] {
        guard let arguments, let source = arguments["config"] as? String else {
            return ["status": "invalid", "stage": "prepare"]
        }
        let assetRoot = arguments["geo_assets_directory"]
        let certificateRoot = arguments["certificate_assets_directory"]
        guard (assetRoot == nil || assetRoot is NSNull || assetRoot is String),
              (certificateRoot == nil || certificateRoot is NSNull || certificateRoot is String) else {
            return ["status": "invalid", "stage": "prepare"]
        }
        guard supported else { return ["status": "unsupported"] }

        let configuration: Data
        do {
            configuration = try XrayCertificatePaths.bind(configData: Data(source.utf8), directory: certificateRoot as? String)
            if let directory = assetRoot as? String {
                var isDirectory: ObjCBool = false
                guard directory.hasPrefix("/"), !directory.contains("\0"),
                      FileManager.default.fileExists(atPath: directory, isDirectory: &isDirectory), isDirectory.boolValue else {
                    return ["status": "invalid", "stage": "prepare"]
                }
                return ["status": "unsupported"]
            }
            // The app's default asset lookup can check reload-only schedules.
            // Scheduled downloads need the writable root passed at startup.
            try ManagedServiceAssetPolicy.validate(configuration, directory: nil,
                geodataCapability: geodataCapability, xdriveCapability: xdriveCapability)
        } catch GeoDatAssetError.runtimeUnavailable {
            return ["status": "unsupported"]
        } catch GeoDatAssetError.writableRootRequired {
            return ["status": "unsupported"]
        } catch {
            return ["status": "invalid", "stage": "prepare"]
        }

        do {
            let accepted = try CorePreflightPolicy.validate(configuration, check: check)
            return ["status": accepted ? "valid" : "unsupported"]
        } catch let error as CorePreflightError {
            if error.stage == "environment-policy" { return ["status": "unsupported"] }
            if error.stage == "internal" { return ["status": "unavailable"] }
            var result: [String: Any] = ["status": "invalid", "stage": "coreCheck"]
            if let section = error.section, let index = error.index {
                result["section"] = section
                result["index"] = index
            }
            return result
        } catch {
            return ["status": "unavailable"]
        }
    }
}
