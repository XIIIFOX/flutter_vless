import Foundation
import Darwin
#if DNS_PREPARER_IOS_SOURCE
import flutter_vless_privacy
import flutter_vless_tunnel_support
#else
import flutter_vless_macos_privacy
import flutter_vless_macos_tunnel_support
#endif

// Actual production preparation only, including an explicit empty environment
// image. No real port checker, resolver, Core, SDK or NetworkExtension is used.
guard CommandLine.arguments.count == 3,
      CommandLine.arguments[1] != CommandLine.arguments[2] else { exit(2) }
do {
    let source = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
    let credentials = try LocalProxyCredentials(username: "inert-user", password: "inert-password")
    var resolverCalls = 0
    var availabilityCalls = 0
    let prepared = TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: credentials,
        tcpPortAvailable: { _ in availabilityCalls += 1; return true },
        environmentSnapshot: XrayEnvironmentSnapshot(rawEntries: []),
        resolveIPv4: { _ in resolverCalls += 1; return nil })
    var dnsEqual = false
    if let prepared {
        let original = try JSONSerialization.jsonObject(with: source) as! [String: Any]
        let effective = try JSONSerialization.jsonObject(with: prepared.data) as! [String: Any]
        dnsEqual = (original["dns"] as? NSDictionary) == (effective["dns"] as? NSDictionary)
        try prepared.data.write(to: URL(fileURLWithPath: CommandLine.arguments[2]), options: .atomic)
    }
    let summary: [String: Any] = ["accepted": prepared != nil, "resolver_calls": resolverCalls,
        "availability_calls": availabilityCalls, "dns_equal": dnsEqual]
    let data = try JSONSerialization.data(withJSONObject: summary, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
    exit(prepared == nil ? 3 : 0)
} catch {
    fputs("inert DNS preparation file operation failed\n", stderr)
    exit(4)
}
