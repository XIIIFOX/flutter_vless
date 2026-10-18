import Foundation
import Darwin
#if os(macOS)
import flutter_vless_macos_tunnel_support
#else
import flutter_vless_tunnel_support
#endif

// File-only acceptance adapter for the production JSON preparer. No Core,
// resolver, socket, NetworkExtension, or route API is started here.
let arguments = CommandLine.arguments
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
