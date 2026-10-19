import Foundation

/// Binds Core TLS file references before handing JSON to another process.
/// The directory is a resolution base, not a filesystem sandbox or file owner.
public enum XrayCertificatePaths {
    public enum Failure: Error { case invalidDirectory, malformedConfiguration, invalidFilePath }

    public static func bind(configData: Data, directory: String?) throws -> Data {
        guard let directory else { return configData }
        guard directory.hasPrefix("/"), !directory.contains("\0") else { throw Failure.invalidDirectory }
        let base = clean(directory)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: base, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw Failure.invalidDirectory
        }
        guard var config = try JSONSerialization.jsonObject(with: configData) as? [String: Any] else {
            throw Failure.malformedConfiguration
        }
        var changed = false

        func key(_ object: [String: Any], _ name: String) throws -> String? {
            let matches = object.keys.filter { XrayJSONField.matches($0, name) }
            guard matches.count <= 1 else { throw Failure.malformedConfiguration }
            return matches.first
        }
        func stream(_ input: [String: Any]) throws -> [String: Any] {
            var output = input
            if let security = try key(output, "security"), (output[security] as? String)?.lowercased() == "tls",
               let tlsKey = try key(output, "tlsSettings"), var tls = output[tlsKey] as? [String: Any],
               let certificatesKey = try key(tls, "certificates"), var certificates = tls[certificatesKey] as? [Any] {
                for index in certificates.indices {
                    guard var certificate = certificates[index] as? [String: Any] else { continue }
                    for name in ["certificateFile", "keyFile"] {
                        guard let fileKey = try key(certificate, name), let path = certificate[fileKey] as? String, !path.isEmpty else { continue }
                        guard !path.contains("\0") else { throw Failure.invalidFilePath }
                        if !path.hasPrefix("/") {
                            // Core's file field takes precedence over inline
                            // data. Join lexically, including caller '..'.
                            certificate[fileKey] = clean(base + "/" + path)
                            changed = true
                        }
                    }
                    certificates[index] = certificate
                }
                tls[certificatesKey] = certificates
                output[tlsKey] = tls
            }

            // StreamConfig.Build builds the preferred XHTTP settings even if
            // another parent network is selected. Null preferred alias falls
            // back; any extra presence replaces the outer download config.
            let preferred = try key(output, "xhttpSettings")
            let selected: String?
            if let preferred, !(output[preferred] is NSNull) { selected = preferred }
            else { selected = try key(output, "splithttpSettings") }
            if let selected, var settings = output[selected] as? [String: Any] {
                if let extraKey = try key(settings, "extra") {
                    if var extra = settings[extraKey] as? [String: Any],
                       let downloadKey = try key(extra, "downloadSettings"), let download = extra[downloadKey] as? [String: Any] {
                        extra[downloadKey] = try stream(download)
                        settings[extraKey] = extra
                    }
                } else if let downloadKey = try key(settings, "downloadSettings"), let download = settings[downloadKey] as? [String: Any] {
                    settings[downloadKey] = try stream(download)
                }
                output[selected] = settings
            }
            return output
        }

        for name in ["inbounds", "outbounds"] {
            guard let listKey = try key(config, name), var entries = config[listKey] as? [Any] else { continue }
            for index in entries.indices {
                guard var entry = entries[index] as? [String: Any],
                      let streamKey = try key(entry, "streamSettings"), let settings = entry[streamKey] as? [String: Any] else { continue }
                entry[streamKey] = try stream(settings)
                entries[index] = entry
            }
            config[listKey] = entries
        }
        return changed ? try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]) : configData
    }

    private static func clean(_ path: String) -> String {
        var parts: [Substring] = []
        for component in path.split(separator: "/") {
            if component == "." { continue }
            if component == ".." { if !parts.isEmpty { parts.removeLast() }; continue }
            parts.append(component)
        }
        return "/" + parts.joined(separator: "/")
    }
}
