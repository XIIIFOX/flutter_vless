import Foundation
import Darwin
#if os(macOS)
import flutter_vless_macos_tunnel_support
import flutter_vless_macos_privacy
#else
import flutter_vless_tunnel_support
import flutter_vless_privacy
#endif

// File-only acceptance adapter for the production JSON preparer. No Core,
// resolver, socket, NetworkExtension, or route API is started here.
let arguments = CommandLine.arguments
if arguments.count == 5 && arguments[1] == "--bind-certificate-fixture" {
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: arguments[2]))
        let bound = try XrayCertificatePaths.bind(configData: data, directory: arguments[4])
        try bound.write(to: URL(fileURLWithPath: arguments[3]), options: .atomic)
        exit(0)
    } catch {
        fputs("native certificate fixture rejected\n", stderr)
        exit(3)
    }
}
if arguments.count == 4 && arguments[1] == "--allocate-service-tags-fixture" {
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: arguments[2]))
        guard let input = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let config = input["config"], let requests = input["requests"] as? [String] else { exit(3) }
        var allocator = XrayServiceTags(configuration: config)
        let tags = requests.map { allocator.next($0) }
        try JSONSerialization.data(withJSONObject: tags).write(to: URL(fileURLWithPath: arguments[3]), options: .atomic)
        exit(0)
    } catch {
        fputs("native tag fixture file operation failed\n", stderr)
        exit(4)
    }
}
guard arguments.count == 7, arguments[1] == "--prepare-dns-fixture" else {
    fputs("native DNS fixture arguments rejected\n", stderr)
    exit(2)
}
do {
    let source = try Data(contentsOf: URL(fileURLWithPath: arguments[2]))
    let credentials = try LocalProxyCredentials(username: "session-user", password: "session-password")
    var unexpectedBootstrap = false
    guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: credentials,
        resolveIPv4: { name in
            guard name == arguments[5] else { unexpectedBootstrap = true; return nil }
            return arguments[6]
        }), !unexpectedBootstrap else {
        fputs("native DNS fixture preparation rejected\n", stderr)
        exit(3)
    }
    // Interface is a Windows physical binding option. Apple protects these
    // same numeric pins through NetworkExtension route exclusions at startup.
    try prepared.data.write(to: URL(fileURLWithPath: arguments[3]), options: .atomic)
} catch {
    fputs("native DNS fixture file operation failed\n", stderr)
    exit(4)
}
