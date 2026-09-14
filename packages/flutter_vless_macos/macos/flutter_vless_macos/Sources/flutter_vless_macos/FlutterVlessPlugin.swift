// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import Foundation
import FlutterMacOS
import AppKit
import SystemConfiguration
import Security
import NetworkExtension
import Combine

import CXRay
#if canImport(flutter_vless_macos_privacy)
import flutter_vless_macos_privacy
#endif

import os
import CFNetwork
import Darwin

// MARK: - macOS App-Side Maintenance Notes
//
// This file runs in the Flutter Runner process, not in the Network Extension.
// It owns the MethodChannel/EventChannel API, proxy-only Xray lifecycle,
// NETunnelProviderManager persistence, status timers, and diagnostics that make
// Packet Tunnel regressions visible from the app console.
//
// There are two distinct macOS networking modes:
//
// - Proxy-only mode:
//   Runs Xray in the app process and configures macOS system proxy settings
//   through SystemConfiguration. It cannot capture UDP/QUIC
//   and cannot force apps that ignore system proxy settings.
//
// - Packet Tunnel mode:
//   Starts `XrayTunnel.appex`, installs utun routes, and lets the extension run
//   Xray plus HEV tun2socks. This is the full VPN path and has its own DNS and
//   route invariants documented in `doc/macos_packet_tunnel_architecture.md`.
//
// Keep these modes separate. A passing proxy-only delay probe proves the config
// can work through a local proxy; it does not prove the Network Extension,
// utun, DNS resolver, server host-route exclusion, or HEV path.

private let pluginLog = NativePrivacyLogger(
    subsystem: Bundle.main.bundleIdentifier ?? "flutter_vless.Runner",
    category: "FlutterVlessPlugin"
)

/// App-process debug file writer.
///
/// Provider logs live in the extension process, so the app keeps its own debug
/// trail in the same App Group container. The two files together let us compare
/// app-side manager events with provider-side tunnel startup evidence after a
/// real-device run.
private final class PluginDebugStore {
    static let shared = PluginDebugStore()

    private let lock = NSLock()
    private var fileURL: URL?

    func configure(groupIdentifier: String?) {
        lock.lock()
        defer { lock.unlock() }
        guard let groupIdentifier,
              !groupIdentifier.isEmpty,
              let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier) else {
            fileURL = nil
            return
        }
        try? FileManager.default.removeItem(at: containerURL.appendingPathComponent("flutter_vless_app_debug.log"))
        fileURL = containerURL.appendingPathComponent("flutter_vless_app_private_v2.log")
        try? "FlutterVless app debug log\n".write(to: fileURL!, atomically: true, encoding: .utf8)
    }

    func append(_ message: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) \(message)"
        lock.lock()
        defer { lock.unlock() }
        guard let fileURL else {
            return
        }
        if let handle = try? FileHandle(forWritingTo: fileURL) {
            defer { try? handle.close() }
            if let size = try? handle.seekToEnd(), size > 128 * 1024 {
                try? handle.truncate(atOffset: 0)
                try? handle.seek(toOffset: 0)
            }
            if let data = "\(line)\n".data(using: .utf8) {
                try? handle.write(contentsOf: data)
            }
        }
    }

    func snapshot(maxLines: Int = 220) -> String {
        lock.lock()
        defer { lock.unlock() }
        guard let fileURL,
              let data = try? Data(contentsOf: fileURL),
              let content = String(data: data, encoding: .utf8) else {
            return ""
        }
        return content.split(separator: "\n").suffix(maxLines).joined(separator: "\n")
    }
}

private func pluginDebug(_ message: NativeDiagnosticMessage) {
    PluginDebugStore.shared.append(message.text)
    pluginLog.info(message)
}

/// Captures the system routing and resolver state from the app process.
///
/// The Packet Tunnel provider can prove Xray/HEV health, but the app process is
/// the most convenient place to run macOS CLI diagnostics such as `route get`,
/// `netstat`, and `scutil --dns`. These snapshots are intentionally verbose
/// because the final bug was only obvious when comparing:
///
/// - default route before and after `NEVPNStatus.connected`,
/// - DNS host routes (`1.1.1.1`, `8.8.8.8`) versus resolver ownership,
/// - server host route outside utun,
/// - empty/unreachable DNS resolver states.
private struct SystemNetworkDiagnostics {
    static func logSnapshot(reason: String) {
        DispatchQueue.global(qos: .utility).async {
            var sections: [(String, String, [String])] = [
                ("route-default", "/sbin/route", ["-n", "get", "default"]),
                ("route-dns-1.1.1.1", "/sbin/route", ["-n", "get", "1.1.1.1"]),
                ("route-dns-8.8.8.8", "/sbin/route", ["-n", "get", "8.8.8.8"]),
                ("netstat-inet", "/usr/sbin/netstat", ["-rn", "-f", "inet"]),
                ("netstat-inet6", "/usr/sbin/netstat", ["-rn", "-f", "inet6"]),
                ("scutil-dns", "/usr/sbin/scutil", ["--dns"])
            ]
            let interfaceNames = allInterfaceNames()
            if let defaultInterface = currentDefaultInterface() {
                sections.append(("ifconfig-default-\(defaultInterface)", "/sbin/ifconfig", [defaultInterface]))
            }
            if interfaceNames.contains("en0") {
                sections.append(("ifconfig-en0", "/sbin/ifconfig", ["en0"]))
            }
            for utun in interfaceNames.filter({ $0.hasPrefix("utun") }).suffix(4) {
                sections.append(("ifconfig-\(utun)", "/sbin/ifconfig", [utun]))
            }
            var output = [
                "System network snapshot reason=\(reason)",
                "interfaces=\(interfaceNames.joined(separator: ",")) defaultIf=\(currentDefaultInterface() ?? "nil") routeIf1.1.1.1=\(routeInterface(for: "1.1.1.1") ?? "nil") routeIf8.8.8.8=\(routeInterface(for: "8.8.8.8") ?? "nil")"
            ]
            for (name, executable, arguments) in sections {
                output.append("--- \(name) ---")
                output.append(run(executable: executable, arguments: arguments))
            }
            pluginDebug("System network snapshot omitted from private diagnostics")
        }
    }

    static func currentDefaultInterface() -> String? {
        routeInterface(for: "default")
    }

    static func routeInterface(for destination: String) -> String? {
        let output = run(executable: "/sbin/route", arguments: ["-n", "get", destination])
        return parseRouteInterface(output)
    }

    static func allInterfaceNames() -> [String] {
        guard let first = if_nameindex() else {
            return []
        }
        defer { if_freenameindex(first) }

        var names: [String] = []
        var pointer = first
        while pointer.pointee.if_index != 0 {
            if let namePointer = pointer.pointee.if_name {
                names.append(String(cString: namePointer))
            }
            pointer = pointer.advanced(by: 1)
        }
        return names
    }

    static func currentDNSServers() -> [String] {
        let output = run(executable: "/usr/sbin/scutil", arguments: ["--dns"])
        let primarySection = output.components(separatedBy: "DNS configuration (for scoped queries)").first ?? output
        var servers: [String] = []
        for line in primarySection.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("nameserver"),
                  let value = trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespacesAndNewlines),
                  isIPv4Literal(value),
                  !servers.contains(value) else {
                continue
            }
            servers.append(value)
        }
        pluginDebug("Detected current system DNS servers before VPN: \(servers.isEmpty ? "none" : servers.joined(separator: ","))")
        return servers
    }

    private static func run(executable: String, arguments: [String]) -> String {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? ""
            return String(text.prefix(6000))
        } catch {
            return "failed: \(error.localizedDescription)"
        }
    }

    private static func parseRouteInterface(_ output: String) -> String? {
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("interface:") else {
                continue
            }
            return trimmed
                .dropFirst("interface:".count)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    private static func isIPv4Literal(_ address: String) -> Bool {
        var addr = in_addr()
        return address.withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }
}


private struct SystemProxyHelper {
    private static let lock = NSLock()
    private static var previous: [String: [String: Any]] = [:]
    private static var installed: [String: [String: Any]] = [:]
    // Keep the authorization for restoration as well as installation. Creating
    // an ordinary SCPreferences session fails with permission denied for a
    // normal desktop user, even outside App Sandbox.
    private static var authorization: AuthorizationRef?

    private static func failure(_ message: NativeDiagnosticMessage, code: Int) -> NSError {
        NSError(domain: "flutter_vless.proxy", code: code,
                userInfo: [NSLocalizedDescriptionKey: message.text])
    }

    private static func preferences() throws -> SCPreferences {
        if authorization == nil {
            guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
                  authorization != nil else {
                throw failure("System proxy authorization failed", code: 1)
            }
        }
        // SystemConfiguration requests the required rights through the macOS
        // authorization dialog. Never run the app or a shell command as root.
        guard let preferences = SCPreferencesCreateWithAuthorization(nil, "flutter_vless" as CFString, nil, authorization),
              SCPreferencesLock(preferences, true) else {
            throw failure("System proxy authorization or preferences lock failed", code: 1)
        }
        return preferences
    }

    private static func releaseUnusedAuthorization() {
        guard installed.isEmpty else { return }
        previous.removeAll()
        if let authorization { AuthorizationFree(authorization, []) }
        authorization = nil
    }

    static func setSystemProxy(config: String) throws {
        guard let data = config.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw LocalProxyAccessError.malformedConfiguration }
        // Match the primary listener used by connected-delay probes. A second
        // SOCKS inbound may deliberately route direct; it must not replace the
        // primary proxy just because it is the last inbound in an import.
        guard let inbound = (json["inbounds"] as? [[String: Any]])?.first(where: {
            ["socks", "http"].contains($0["protocol"] as? String ?? "")
        }), let port = inbound["port"] as? Int, (1...65535).contains(port) else {
            throw LocalProxyAccessError.incompatibleInbounds
        }
        let keys = inbound["protocol"] as? String == "socks" ? ["SOCKS"] : ["HTTP", "HTTPS"]
        let host = inbound["listen"] as? String ?? "127.0.0.1"
        guard ["127.0.0.1", "::1", "localhost"].contains(host) else {
            throw LocalProxyAccessError.incompatibleInbounds
        }
        lock.lock(); defer { releaseUnusedAuthorization(); lock.unlock() }
        let prefs = try preferences(); defer { SCPreferencesUnlock(prefs) }
        guard let set = SCNetworkSetCopyCurrent(prefs), let services = SCNetworkSetCopyServices(set) as? [SCNetworkService] else {
            throw failure("System proxy has no network services", code: 2)
        }
        var originals: [String: [String: Any]] = [:]
        var changes: [String: [String: Any]] = [:]
        for service in services {
            guard let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies),
                  let id = SCNetworkServiceGetServiceID(service) as String? else { continue }
            let current = SCNetworkProtocolGetConfiguration(proto) as? [String: Any] ?? [:]
            var next = current
            next["ProxyAutoConfigEnable"] = 0; next["ProxyAutoDiscoveryEnable"] = 0
            next["HTTPEnable"] = 0; next["HTTPSEnable"] = 0; next["SOCKSEnable"] = 0
            for key in keys { next[key + "Enable"] = 1; next[key + "Proxy"] = host; next[key + "Port"] = port }
            originals[id] = current
            guard SCNetworkProtocolSetConfiguration(proto, next as CFDictionary) else {
                throw failure("System proxy configuration failed", code: 3)
            }
            changes[id] = next
        }
        guard !changes.isEmpty, SCPreferencesCommitChanges(prefs) else {
            throw failure("System proxy preferences commit failed", code: 4)
        }
        // Take ownership only after commit; a failed staging transaction must
        // not leave a stale snapshot that overwrites later user changes.
        previous.merge(originals) { old, _ in old }
        installed.merge(changes) { _, new in new }
        guard SCPreferencesApplyChanges(prefs) else {
            throw failure("System proxy preferences apply failed", code: 5)
        }
    }

    static func clearSystemProxy() {
        lock.lock(); defer { releaseUnusedAuthorization(); lock.unlock() }
        guard !installed.isEmpty, let prefs = try? preferences() else { return }
        defer { SCPreferencesUnlock(prefs) }
        guard let services = SCNetworkServiceCopyAll(prefs) as? [SCNetworkService] else { return }
        var restored: [String] = []
        for service in services {
            guard let id = SCNetworkServiceGetServiceID(service) as String?, let owned = installed[id], let original = previous[id],
                  let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else { continue }
            // A user/another application may have taken over the proxy meanwhile.
            guard let current = SCNetworkProtocolGetConfiguration(proto) as? [String: Any],
                  NSDictionary(dictionary: owned).isEqual(to: current) else {
                installed.removeValue(forKey: id); previous.removeValue(forKey: id)
                continue
            }
            if SCNetworkProtocolSetConfiguration(proto, original as CFDictionary) { restored.append(id) }
        }
        guard !restored.isEmpty, SCPreferencesCommitChanges(prefs) else { return }
        // If apply fails after commit, the next cleanup still owns the saved
        // values and must retry applying them to the live network configuration.
        for id in restored { installed[id] = previous[id] }
        guard SCPreferencesApplyChanges(prefs) else { return }
        for id in restored { installed.removeValue(forKey: id); previous.removeValue(forKey: id) }
    }
}


private func normalizeXrayRuntimeConfig(_ value: Any) -> Any {
    if var map = value as? [String: Any] {
        func moveAlias(_ from: String, _ to: String) {
            guard let aliasValue = map.removeValue(forKey: from) else {
                return
            }
            if map[to] == nil {
                map[to] = aliasValue
            }
        }

        moveAlias("xHTTPSettings", "xhttpSettings")
        moveAlias("httpUpgradeSettings", "httpupgradeSettings")
        moveAlias("splitHTTPSettings", "splithttpSettings")
        map.removeValue(forKey: "allowInsecure")
        if let network = map["network"] as? String {
            map["network"] = network.lowercased()
        }
        for (key, item) in map {
            map[key] = normalizeXrayRuntimeConfig(item)
        }
        return map
    }
    if let list = value as? [Any] {
        return list.map { normalizeXrayRuntimeConfig($0) }
    }
    return value
}

/// Xray logger used by app-process delay/proxy-only runs.
///
/// The Packet Tunnel provider has its own logger and debug store. Keeping the
/// loggers separate makes it clear whether a message came from the app process
/// or the extension process.
private final class PluginXRayLogger: NSObject, XRayLoggerProtocol {
    private let store = BoundedNativeLogStore()

    func logInput(_ s: String?) {
        if let message = s {
            store.append(source: "xray", message: NativeLogPrivacy.runtimeEvent(message).text)
            pluginLog.info(NativeLogPrivacy.runtimeEvent(message))
        }
    }

    func reset() {
        store.reset()
    }

    func snapshot() -> String {
        store.snapshot()
    }

    func record(source: String, message: NativeDiagnosticMessage) {
        store.append(source: source, message: message.text)
    }
}

/// One-shot app-process Xray runner used for server delay probes.
///
/// This is intentionally not the VPN implementation. It starts a temporary
/// local HTTP proxy, measures a URL through that proxy, and stops Xray. A pass
/// here is a config/server signal only; it says nothing about Packet Tunnel
/// routes or DNS.
private actor ServerDelayRunner {
    private let logger = PluginXRayLogger()

    func measure(config: String, url: String, geoAssetsDirectory: String? = nil) async -> Int64 {
        do {
            guard URL(string: url) != nil else {
                throw NSError(domain: "FlutterVless", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid probe URL"])
            }

            let proxyPort = Self.findFreePort()
            let credentials = try LocalProxyCredentials.generate()
            let delayConfig = try Self.buildDelayConfigData(config: config, proxyPort: proxyPort, credentials: credentials)

            XRaySetMemoryLimit()
            try configureXrayAssetLocation(geoAssetsDirectory)
            var startError: NSError?
            let started = XRayStartPrivate(delayConfig, logger, &startError)
            guard started else {
                throw startError.map { NativeLogPrivacy.operationError($0) } ?? NSError(domain: "FlutterVless", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to start XRay delay probe"])
            }
            defer {
                XRayStop()
                pluginLog.info("Stopped XRay delay probe")
            }

            pluginLog.info("Started XRay delay probe on HTTP proxy port \(proxyPort, privacy: .public)")
            try await Task.sleep(nanoseconds: 1_000_000_000)
            return try await Self.measureURL(url, proxyPort: proxyPort, credentials: credentials)
        } catch {
            pluginLog.error("Server delay probe failed: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
            return -1
        }
    }

    private static func buildDelayConfigData(config: String, proxyPort: Int, credentials: LocalProxyCredentials) throws -> Data {
        guard let data = config.data(using: .utf8) else {
            throw NSError(domain: "FlutterVless", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid XRay config JSON"])
        }

        var json = try LocalProxyAccessPolicy.normalizedConfig(configData: data)

        guard XrayPrivacyConfig.apply(to: &json) else {
            throw NSError(domain: "FlutterVless", code: 13, userInfo: [NSLocalizedDescriptionKey: "Invalid private Xray configuration"])
        }

        // A probe owns one listener. Reject extra user proxy listeners before
        // replacing the selected inbound, preserving its routing tag.
        let inbounds = json["inbounds"] as? [[String: Any]] ?? []
        let proxyInbounds = inbounds.filter {
            ["http", "socks"].contains(($0["protocol"] as? String ?? "").lowercased())
        }
        guard proxyInbounds.count <= 1,
              inbounds.count == proxyInbounds.count else {
            throw NSError(domain: "FlutterVless", code: 14,
                userInfo: [NSLocalizedDescriptionKey: "Delay probes require at most one local proxy inbound"])
        }
        json["inbounds"] = [[
            "tag": proxyInbounds.first?["tag"] as? String ?? "in_proxy",
            "port": proxyPort, "listen": "127.0.0.1", "protocol": "http",
            "settings": ["accounts": [["user": credentials.username, "pass": credentials.password]]]
        ]]
        return try JSONSerialization.data(withJSONObject: json, options: [])
    }

    private static func measureURL(_ url: String, proxyPort: Int,
                                   credentials: LocalProxyCredentials) async throws -> Int64 {
        guard let probeURL = URL(string: url) else { throw URLError(.badURL) }
        return try await LocalHTTPProxyClient(port: proxyPort, credentials: credentials).measure(url: probeURL)
    }

    private static func findFreePort() -> Int {
        let fallbackPort = 10806
        let socketDescriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else {
            return fallbackPort
        }
        defer { close(socketDescriptor) }

        var reuse: Int32 = 1
        setsockopt(socketDescriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(0).bigEndian
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)

        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(socketDescriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            return fallbackPort
        }

        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(socketDescriptor, $0, &length)
            }
        }
        guard nameResult == 0 else {
            return fallbackPort
        }

        return Int(UInt16(bigEndian: address.sin_port))
    }
}

private final class ProxyOnlyRunner {
    private let logger = PluginXRayLogger()
    private(set) var isRunning = false
    private(set) var connectedDate: Date?
    private var delayEndpoint: (protocolName: String, port: Int, credentials: LocalProxyCredentials?)?

    func start(configData: Data, geoAssetsDirectory: String?) throws {
        let preparedConfig = try Self.buildProxyOnlyConfigData(configData: configData)
        let endpoint = try Self.findDelayEndpoint(preparedConfig)
        if isRunning {
            stop()
        }

        logger.reset()
        do {
            XRaySetMemoryLimit()
            try configureXrayAssetLocation(geoAssetsDirectory)
            var startError: NSError?
            let started = XRayStartPrivate(preparedConfig, logger, &startError)
            guard started else {
                throw startError ?? NSError(domain: "FlutterVless", code: 10, userInfo: [NSLocalizedDescriptionKey: "Failed to start XRay proxy-only mode"])
            }

            do { try SystemProxyHelper.setSystemProxy(config: String(decoding: preparedConfig, as: UTF8.self)) }
            catch { SystemProxyHelper.clearSystemProxy(); XRayStop(); throw error }
            isRunning = true
            delayEndpoint = endpoint
            connectedDate = Date()
            pluginLog.info("Started XRay proxy-only mode configBytes=\(preparedConfig.count, privacy: .public)")
        } catch {
            logger.record(source: "runtime", message: "Proxy-only start failed: \(NativeLogPrivacy.runtimeEvent(NativeLogPrivacy.operationError(error).localizedDescription))")
            throw NativeLogPrivacy.operationError(error)
        }
    }

    func stop() {
        // Retry pending restoration even after a failed startup or earlier stop.
        SystemProxyHelper.clearSystemProxy()
        guard isRunning else {
            return
        }
        XRayStop()
        isRunning = false
        delayEndpoint = nil
        connectedDate = nil
        pluginLog.info("Stopped XRay proxy-only mode")
    }

    func measureConnectedDelay(url: String) async -> Int64 {
        guard isRunning, let endpoint = delayEndpoint, let url = URL(string: url) else { return -1 }
        if endpoint.protocolName == "http" {
            return (try? await LocalHTTPProxyClient(port: endpoint.port, credentials: endpoint.credentials).measure(url: url)) ?? -1
        }
        return await withCheckedContinuation { continuation in
            LocalProxyDelayClient.measure(url: url, port: endpoint.port, credentials: endpoint.credentials) {
                continuation.resume(returning: $0)
            }
        }
    }

    private static func findDelayEndpoint(_ data: Data) throws -> (protocolName: String, port: Int, credentials: LocalProxyCredentials?)? {
        let json = try LocalProxyAccessPolicy.normalizedConfig(configData: data)
        for inbound in json["inbounds"] as? [[String: Any]] ?? [] {
            guard let proto = inbound["protocol"] as? String, ["socks", "http"].contains(proto),
                  let port = inbound["port"] as? Int else { continue }
            let settings = inbound["settings"] as? [String: Any] ?? [:]
            let accounts = settings["accounts"] as? [[String: Any]] ?? settings["users"] as? [[String: Any]] ?? []
            let auth = settings["auth"] as? String ?? "noauth"
            guard proto == "http" || ["noauth", "password"].contains(auth) else {
                throw LocalProxyAccessError.invalidCredentials
            }
            var credentials: LocalProxyCredentials?
            if proto == "http" && !accounts.isEmpty || proto == "socks" && auth == "password" {
                guard let account = accounts.first, let user = account["user"] as? String,
                      let pass = account["pass"] as? String else { throw LocalProxyAccessError.invalidCredentials }
                credentials = try LocalProxyCredentials(username: user, password: pass)
            }
            return (proto, port, credentials)
        }
        return nil
    }

    private(set) var totalUpload: Int64 = 0
    private(set) var totalDownload: Int64 = 0
    func queryTrafficStats() -> (upload: Int64, download: Int64) {
        guard isRunning else { return (0, 0) }
        let raw = XRayQueryStats("")
        var up: Int64 = 0, down: Int64 = 0
        for line in raw.components(separatedBy: "\n") {
            guard let last = line.components(separatedBy: ">>>").last,
                  let value = Int64(last.trimmingCharacters(in: .whitespaces)), value >= 0 else { continue }
            if line.contains("uplink"), value <= Int64.max - up { up += value }
            if line.contains("downlink"), value <= Int64.max - down { down += value }
        }
        totalUpload = up; totalDownload = down
        return (up, down)
    }
    func forceCleanup() { stop() }

    func debugSnapshot() -> String {
        logger.snapshot()
    }

    func clearDiagnostics() {
        logger.reset()
    }

    fileprivate static func buildProxyOnlyConfigData(configData: Data) throws -> Data {
        var json = try LocalProxyAccessPolicy.normalizedConfig(configData: configData)

        guard XrayPrivacyConfig.apply(to: &json) else {
            throw NSError(domain: "FlutterVless", code: 13, userInfo: [NSLocalizedDescriptionKey: "Invalid private Xray configuration"])
        }

        if json["inbounds"] as? [[String: Any]] == nil {
            json["inbounds"] = [
                [
                    "tag": "socks",
                    "listen": "127.0.0.1",
                    "port": 10807,
                    "protocol": "socks",
                    "settings": ["auth": "noauth", "udp": true]
                ]
            ]
        }

        let prepared = try JSONSerialization.data(withJSONObject: json, options: [])
        _ = try findDelayEndpoint(prepared)
        return prepared
    }
}

public class FlutterVlessPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private var packetTunnelManager: PacketTunnelManager? = nil
    private let serverDelayRunner = ServerDelayRunner()
    private let commands = NativeOperationQueue()
    private let proxyOnlyRunner = ProxyOnlyRunner()

    private var timer: Timer?
    private var eventSink: FlutterEventSink?
    private var totalUpload: Int = 0
    private var totalDownload: Int = 0
    private var uploadSpeed: Int = 0
    private var downloadSpeed: Int = 0
    private var lastTrafficLogDate: Date = .distantPast
    private var lastProviderDebugLogDate: Date = .distantPast
    private var lastNetworkSnapshotLogDate: Date = .distantPast
    private var lastAppNetworkProbeDate: Date = .distantPast
    private var didScheduleConnectedDiagnostics = false

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "flutter_vless", binaryMessenger: registrar.messenger)
        let instance = FlutterVlessPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        let eventChannel = FlutterEventChannel(name: "flutter_vless/status", binaryMessenger: registrar.messenger)
        eventChannel.setStreamHandler(instance)

        // CRITICAL: Register for app termination to clean up system proxy.
        // Without this, closing the app while connected leaves a dead SOCKS proxy
        // configured in System Preferences, which kills all network traffic.
        NotificationCenter.default.addObserver(
            instance,
            selector: #selector(applicationWillTerminate(_:)),
            name: NSApplication.willTerminateNotification,
            object: nil
        )
        // Also handle unexpected termination signals
        instance.installSignalHandlers()
        pluginLog.info("FlutterVlessPlugin registered with app termination cleanup")
    }

    /// Called when the application is about to terminate (Cmd+Q, Xcode stop, etc.).
    @objc private func applicationWillTerminate(_ notification: Notification) {
        pluginLog.info("Application will terminate — cleaning up proxy settings")
        proxyOnlyRunner.forceCleanup()
        stopTimer()
    }

    /// Installs POSIX signal handlers so that even SIGTERM/SIGINT clears the proxy.
    private func installSignalHandlers() {
        let handler: @convention(c) (Int32) -> Void = { signal in
            SystemProxyHelper.clearSystemProxy()
            // Re-raise the signal with default handler
            Darwin.signal(signal, SIG_DFL)
            Darwin.raise(signal)
        }
        signal(SIGTERM, handler)
        signal(SIGINT, handler)
    }

    deinit {
        proxyOnlyRunner.forceCleanup()
        timer?.invalidate()
        NotificationCenter.default.removeObserver(self)
        pluginLog.info("FlutterVlessPlugin deinit — cleanup completed")
    }

    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        pluginDebug("Status stream attached mainThread=\(Thread.isMainThread)")
        self.eventSink = events
        emitStatus(duration: 0, state: "DISCONNECTED", reason: "stream-attached")
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        pluginDebug("Status stream detached mainThread=\(Thread.isMainThread)")
        self.eventSink = nil
        return nil
    }

    /// Starts the shared UI/status polling timer.
    ///
    /// The same timer supports proxy-only and Packet Tunnel mode, but it reads
    /// counters differently:
    ///
    /// - proxy-only uses Xray stats from the app-process core;
    /// - VPN mode asks the provider for HEV byte counters via `xray_traffic`.
    ///
    /// The timer also periodically asks for `xray_debug`, which is why final
    /// user logs contain both app-side route snapshots and provider-side golden
    /// health checks.
    private func startTimer(reason: String = "unspecified", initialState: String? = nil) {
        guard Thread.isMainThread else {
            pluginDebug("startTimer requested off main thread reason=\(reason); dispatching to main")
            DispatchQueue.main.async { [weak self] in
                self?.startTimer(reason: reason, initialState: initialState)
            }
            return
        }

        if self.timer != nil {
            pluginDebug("Traffic polling timer already running reason=\(reason) eventSink=\(self.eventSink != nil) vpnStatus=\(self.packetTunnelManager?.status?.rawValue ?? -1)")
            emitStatus(duration: currentDurationSeconds(), state: initialState ?? currentWireState(), reason: "timer-already-running:\(reason)")
            return
        }

        pluginDebug("Starting traffic polling timer reason=\(reason) mainThread=\(Thread.isMainThread) eventSink=\(self.eventSink != nil) vpnStatus=\(self.packetTunnelManager?.status?.rawValue ?? -1)")
        self.timer?.invalidate()
        emitStatus(duration: currentDurationSeconds(), state: initialState ?? currentWireState(), reason: "timer-start:\(reason)")
        logSystemNetworkSnapshot(reason: "timer-start:\(reason)")
        let timer = Timer(timeInterval: 1, repeats: true, block: { [weak self] _ in
            guard let self = self else { return }
            if self.proxyOnlyRunner.isRunning {
                let elapsed = Date().timeIntervalSince(self.proxyOnlyRunner.connectedDate ?? Date())
                let seconds = Int(elapsed)
                // Query real traffic stats from XRay stats API
                let stats = self.proxyOnlyRunner.queryTrafficStats()
                let currentUp = stats.upload
                let currentDown = stats.download
                let upSpeed = max(0, currentUp - Int64(self.totalUpload))
                let downSpeed = max(0, currentDown - Int64(self.totalDownload))
                self.totalUpload = Int(currentUp)
                self.totalDownload = Int(currentDown)
                self.uploadSpeed = Int(upSpeed)
                self.downloadSpeed = Int(downSpeed)
                self.emitStatus(duration: seconds, state: "CONNECTED", reason: "timer-proxy")
                return
            }

            if let status = self.packetTunnelManager?.status,
               status == .invalid || status == .disconnected, self.packetTunnelManager?.isRecoveryEnabled != true {
                pluginDebug("Packet tunnel is no longer active while polling status=\(status.rawValue)")
                self.stopTimer(reason: "vpn-status-\(status.rawValue)")
                return
            }
            if self.packetTunnelManager?.status == .connected {
            }

            let elapsed = Date().timeIntervalSince(self.packetTunnelManager?.connectedDate ?? Date())
            let seconds = Int(elapsed)
            self.emitStatus(duration: seconds, state: self.currentWireState(), reason: "timer-vpn")
            Task{
                await self.packetTunnelManager?.refreshForwardingState()
                do{
                    let response =  try await self.packetTunnelManager?.sendProviderMessage(data: "xray_traffic".data(using: .utf8)!)
                    if response != nil{
                        let traffic = String(decoding: response!, as: UTF8.self)
                        let parts = traffic.split(separator: ",")
                        if parts.count >= 2, let up = Int(parts[0]), let down = Int(parts[1]) {
                            self.uploadSpeed = up - self.totalUpload
                            self.downloadSpeed = down - self.totalDownload
                            self.totalUpload = up
                            self.totalDownload = down
                            if Date().timeIntervalSince(self.lastTrafficLogDate) >= 5 {
                                self.lastTrafficLogDate = Date()
                                pluginDebug("Traffic stats up=\(up) down=\(down) upSpeed=\(self.uploadSpeed) downSpeed=\(self.downloadSpeed) vpnStatus=\(self.packetTunnelManager?.status?.rawValue ?? -1)")
                                self.logProviderDebugSnapshot()
                            }
                        } else {
                            pluginDebug("Traffic response parse failed raw=\(traffic)")
                        }
                    } else {
                        pluginDebug("Traffic polling returned nil provider response")
                    }
                }catch{
                    pluginDebug("Error polling traffic: \(error.localizedDescription)")
                }
            }
        })
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    /// Stops status polling and resets counters.
    ///
    /// Resetting `lastProviderDebugLogDate` and `lastNetworkSnapshotLogDate`
    /// matters for repeated manual test runs: after a stop/start cycle we want
    /// the first new run to emit fresh diagnostics immediately.
    private func stopTimer(reason: String = "unspecified") {
        guard Thread.isMainThread else {
            pluginDebug("stopTimer requested off main thread reason=\(reason); dispatching to main")
            DispatchQueue.main.async { [weak self] in
                self?.stopTimer(reason: reason)
            }
            return
        }

        pluginDebug("Stopping traffic polling timer reason=\(reason) hadTimer=\(self.timer != nil) eventSink=\(self.eventSink != nil)")
        self.timer?.invalidate()
        self.timer = nil
        emitStatus(duration: 0, state: "DISCONNECTED", reason: "timer-stop:\(reason)")
        self.uploadSpeed = 0
        self.downloadSpeed = 0
        self.totalUpload = 0
        self.totalDownload = 0
        self.lastProviderDebugLogDate = .distantPast
        self.lastNetworkSnapshotLogDate = .distantPast
        self.lastAppNetworkProbeDate = .distantPast
        self.didScheduleConnectedDiagnostics = false
    }

    private func currentDurationSeconds() -> Int {
        if proxyOnlyRunner.isRunning {
            return Int(Date().timeIntervalSince(proxyOnlyRunner.connectedDate ?? Date()))
        }
        return Int(Date().timeIntervalSince(packetTunnelManager?.connectedDate ?? Date()))
    }

    private func refreshRuntimePolling(reason: String) {
        if currentWireState() == "DISCONNECTED" { stopTimer(reason: reason) }
        else { startTimer(reason: reason) }
    }

    private func currentWireState() -> String {
        if proxyOnlyRunner.isRunning {
            return "CONNECTED"
        }
        if packetTunnelManager?.isRecoveryEnabled == true && packetTunnelManager?.forwardingReady != true { return "CONNECTING" }
        switch packetTunnelManager?.status {
        case .connected:
            return packetTunnelManager?.forwardingReady == true ? "CONNECTED" : "CONNECTING"
        case .connecting, .reasserting:
            return "CONNECTING"
        case .disconnecting:
            return "DISCONNECTING"
        case .disconnected, .invalid:
            return "DISCONNECTED"
        default:
            return "UNKNOWN"
        }
    }

    private func emitStatus(duration: Int, state: String, reason: String) {
        let payload = ["\(duration)", "\(uploadSpeed)", "\(downloadSpeed)", "\(totalUpload)", "\(totalDownload)", state]
        if Date().timeIntervalSince(lastTrafficLogDate) >= 5 || state != "CONNECTED" {
            pluginDebug("Status event reason=\(reason) payload=\(payload.joined(separator: ",")) eventSink=\(eventSink != nil) vpnStatus=\(packetTunnelManager?.status?.rawValue ?? -1)")
        }
        eventSink?(payload)
    }

    private func logSystemNetworkSnapshot(reason: String, force: Bool = false) {
        guard force || Date().timeIntervalSince(lastNetworkSnapshotLogDate) >= 10 else {
            return
        }
        lastNetworkSnapshotLogDate = Date()
        SystemNetworkDiagnostics.logSnapshot(reason: reason)
    }



    /// Requests provider-side debug evidence.
    ///
    /// Primary path is `sendProviderMessage("xray_debug")`. The shared App
    /// Group file is the fallback because NetworkExtension sessions can return
    /// nil during startup/shutdown even when the provider already wrote useful
    /// data.
    private func logProviderDebugSnapshot() {
        guard Date().timeIntervalSince(lastProviderDebugLogDate) >= 5 else {
            return
        }
        lastProviderDebugLogDate = Date()
        Task {
            do {
                guard let response = try await self.packetTunnelManager?.sendProviderMessage(data: Data(NativeLogPrivacy.snapshotCommand.utf8)) else {
                    if let snapshot = self.packetTunnelManager?.readSharedDebugLog(), !snapshot.isEmpty {
                        pluginLog.info("Provider shared debug snapshot:\n\(snapshot, privacy: .public)")
                    } else {
                        pluginLog.warning("Provider debug snapshot unavailable")
                    }
                    return
                }
                let snapshot = String(decoding: response, as: UTF8.self)
                if !snapshot.isEmpty {
                    pluginLog.info("Provider debug snapshot:\n\(snapshot, privacy: .public)")
                }
            } catch {
                pluginLog.error("Provider debug snapshot failed: \(error.localizedDescription, privacy: .public)")
                if let snapshot = self.packetTunnelManager?.readSharedDebugLog(), !snapshot.isEmpty {
                    pluginLog.info("Provider shared debug snapshot:\n\(snapshot, privacy: .public)")
                }
            }
        }
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        pluginLog.info("Method call: \(call.method, privacy: .public)")
        switch call.method {
        case "requestPermission":
            requestPermission(result: result)
        case "initializeVless":
            initializeVless(call: call, result: result)
        case "startVless":
            startVless(call: call, result: result)
        case "stopVless":
            stopVless(result: result)
        case "getCoreVersion":
            getCoreVersion(result: result)
        case "getConnectedServerDelay":
            getConnectedServerDelay(call: call, result: result)
        case "getServerDelay":
            getServerDelay(call: call, result: result)
        case "getProviderDebugSnapshot":
            getProviderDebugSnapshot(result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    /// Stops both macOS modes.
    ///
    /// Calling both cleanup paths is deliberate. It is safe when one mode is not
    /// running and prevents stale system proxy settings from surviving a switch
    /// between proxy-only and VPN mode.
    private func stopVless(result: @escaping FlutterResult) {
        pluginLog.info("stopVless requested")
        let operation = commands.submit {
            self.proxyOnlyRunner.stop()
            try await self.packetTunnelManager?.stop()
        }
        Task {
            do {
                try await operation.value
                refreshRuntimePolling(reason: "stopVless")
                result(nil)
            } catch {
                result(FlutterError(code: "VPN_STOP_ERROR", message: "Unable to disable VPN recovery. Retry stopping the VPN.", details: nil))
            }
        }
    }

    private func getConnectedServerDelay(call: FlutterMethodCall, result: @escaping FlutterResult){
        guard let arguments = call.arguments as? [String: Any],
              let url = arguments["url"] as? String else{
            result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments for getConnectedServerDelay.", details: nil))
            return
        }
        Task {
            do {
                if self.proxyOnlyRunner.isRunning {
                    let delay = await self.proxyOnlyRunner.measureConnectedDelay(url: url)
                    result(Int(delay))
                    return
                }
                let delay = try await packetTunnelManager?.sendProviderMessage(data: "xray_delay\(url)".data(using: .utf8)!) ?? "-1".data(using: .utf8)!
                pluginLog.info("Connected delay response: \(String(decoding: delay, as: UTF8.self), privacy: .public)")
                result(Int(String(decoding: delay, as: UTF8.self)))
            }catch{
                pluginLog.error("Connected delay failed: \(error.localizedDescription, privacy: .public)")
                result(-1)
            }
        }
    }

    private func getProviderDebugSnapshot(result: @escaping FlutterResult) {
        Task {
            let proxySnapshot = proxyOnlyRunner.debugSnapshot()
            if !proxySnapshot.isEmpty {
                result(boundedNativeDiagnosticsSnapshot(
                    "--- macOS app-process Xray diagnostics ---\n\(proxySnapshot)"
                ))
                return
            }
            do {
                guard let response = try await packetTunnelManager?.sendProviderMessage(data: Data(NativeLogPrivacy.snapshotCommand.utf8)) else {
                    result(boundedNativeDiagnosticsSnapshot(
                        packetTunnelManager?.readSharedDebugLog() ?? ""
                    ))
                    return
                }
                result(boundedNativeDiagnosticsSnapshot(
                    String(decoding: response, as: UTF8.self)
                ))
            } catch {
                pluginLog.error("Provider debug snapshot request failed: \(error.localizedDescription, privacy: .public)")
                result(boundedNativeDiagnosticsSnapshot(
                    packetTunnelManager?.readSharedDebugLog() ?? ""
                ))
            }
        }
    }

    private func getServerDelay(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let url = arguments["url"] as? String,
              let config = arguments["config"] as? String else{
            result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments for getServerDelay.", details: nil))
            return
        }
        let operation = commands.submit {
            // The app-process Xray is a singleton; a temporary probe must not
            // replace an intentionally running proxy-only runtime.
            guard !self.proxyOnlyRunner.isRunning else { return Int64(-1) }
            return await self.serverDelayRunner.measure(
                config: config,
                url: url,
                geoAssetsDirectory: arguments["geo_assets_directory"] as? String
            )
        }
        Task { result((try? await operation.value) ?? -1) }
    }

    /// Starts either proxy-only mode or Packet Tunnel VPN mode.
    ///
    /// For VPN mode, the config is stored in `NETunnelProviderProtocol` so the
    /// extension can read it at startup. If a VPN is already active with the same
    /// config, the method avoids unnecessary profile rewrites because rewriting
    /// preferences while NetworkExtension is active can emit extra configuration
    /// changes and transient status noise.
    private func startVless(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let remark = arguments["remark"] as? String,
              let config = arguments["config"] as? String,
              let configData = config.data(using: .utf8) else {
            result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments for startVless.", details: nil))
            return
        }
        let proxyOnly = arguments["proxy_only"] as? Bool ?? false
        let bypassArgument = arguments["bypass_subnets"]
        let bypassSubnets = bypassArgument as? [String]
        let hasBypassArgument = bypassArgument != nil && !(bypassArgument is NSNull)
        let geoAssetsDirectory = arguments["geo_assets_directory"] as? String
        guard !hasBypassArgument || bypassSubnets != nil else {
            result(FlutterError(code: "INCOMPATIBLE_ROUTING", message: "bypassSubnets must be a list of IPv4 CIDRs", details: nil)); return
        }
        do {
            try DesktopBypassPolicy.validate(bypassSubnets ?? [])
            if proxyOnly {
                _ = try ProxyOnlyRunner.buildProxyOnlyConfigData(configData: configData)
            } else {
                try LocalProxyAccessPolicy.validateVPN(configData: configData)
            }
        } catch {
            result(FlutterError(code: "INCOMPATIBLE_LOCAL_PROXY",
                message: "VPN requires one supported loopback SOCKS inbound without extra proxy listeners.", details: nil))
            return
        }
        let operation = commands.submit {
            if proxyOnly {
                // Switching modes is an explicit request to release the system VPN.
                try await self.packetTunnelManager?.stop(waitForDisconnect: true)
                try self.proxyOnlyRunner.start(configData: configData, geoAssetsDirectory: geoAssetsDirectory)
            } else {
                guard let manager = self.packetTunnelManager else {
                    throw NSError(domain: "VPN", code: 1, userInfo: nil)
                }
                self.proxyOnlyRunner.stop()
                self.proxyOnlyRunner.clearDiagnostics()
                manager.remark = remark
                manager.xrayConfig = configData
                manager.bypassSubnets = bypassSubnets ?? []
                manager.proxyOnly = false
                manager.geoAssetsDirectory = geoAssetsDirectory
                try await manager.start()
            }
        }
        Task {
            do {
                try await operation.value
                self.refreshRuntimePolling(reason: "startVless-success")
                result(nil)
            } catch {
                pluginLog.error("Failed to start runtime: \(NativeLogPrivacy.runtimeEvent(NativeLogPrivacy.operationError(error).localizedDescription))")
                result(FlutterError(code: error is TunnelSecretError ? "VPN_KEYCHAIN_ERROR" : (proxyOnly ? "PROXY_ONLY_ERROR" : "VPN_ERROR"),
                    message: error is TunnelSecretError || error is DesktopTunnelError ? error.localizedDescription : NativeLogPrivacy.operationError(error).localizedDescription,
                    details: nil))
                self.refreshRuntimePolling(reason: "startVless-error")
            }
        }
    }

    /// Creates/saves/loads the VPN profile to trigger macOS permission flow.
    ///
    /// This intentionally skips preference rewrites while the VPN is active.
    /// Re-saving an active tunnel profile can cause configuration-change storms
    /// and, on some machines, makes the system briefly lose the manager we are
    /// observing.
    private func requestPermission(result: @escaping FlutterResult) {
        let operation = commands.submit { await self.packetTunnelManager?.testSaveAndLoadProfile() ?? false }
        Task {
            let isGranted = (try? await operation.value) ?? false
            pluginLog.info("requestPermission result=\(isGranted, privacy: .public)")
            result(isGranted)
        }
    }

    private func getCoreVersion(result: @escaping FlutterResult) {
        Task {
            let version = XRayGetVersion()
            pluginLog.info("XRay core version: \(version, privacy: .public)")
            result(version)
        }
    }

    /// Initializes the app-side Packet Tunnel manager.
    ///
    /// Dart passes the base app bundle id. The plugin appends `.XrayTunnel`
    /// because the generated macOS extension target always uses that suffix.
    /// Passing the extension id from Dart would produce
    /// `<base>.XrayTunnel.XrayTunnel` and the manager lookup would fail.
    private func initializeVless(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let providerBundleIdentifier = arguments["providerBundleIdentifier"] as? String,
              let groupIdentifier = arguments["groupIdentifier"] as? String else {
            result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments for initializeVless.", details: nil))
            return
        }
        PluginDebugStore.shared.configure(groupIdentifier: groupIdentifier)
        pluginDebug("initializeVless providerBundleIdentifier=\(providerBundleIdentifier) groupIdentifier=\(groupIdentifier)")
        self.packetTunnelManager = PacketTunnelManager(providerBundleIdentifier: "\(providerBundleIdentifier).XrayTunnel", groupIdentifier: groupIdentifier, keychainAccessGroup: arguments["keychainAccessGroup"] as? String)
        self.packetTunnelManager?.statusDidChange = { [weak self] status in
            guard let self else { return }
            pluginDebug("PacketTunnelManager status callback raw=\(status?.rawValue ?? -1) timerRunning=\(self.timer != nil) proxyOnly=\(self.proxyOnlyRunner.isRunning)")
            switch status {
            case .connecting, .connected, .reasserting:
                self.startTimer(reason: "vpn-status-\(status?.rawValue ?? -1)")
                if status == .connected, !self.didScheduleConnectedDiagnostics {
                    self.didScheduleConnectedDiagnostics = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                        self?.logSystemNetworkSnapshot(reason: "vpn-connected-delayed", force: true)
                    }
                }
            case .disconnected, .invalid:
                self.didScheduleConnectedDiagnostics = false
                if !self.proxyOnlyRunner.isRunning && self.packetTunnelManager?.isRecoveryEnabled != true {
                    self.stopTimer(reason: "vpn-status-\(status?.rawValue ?? -1)")
                }
            default:
                break
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            if self.packetTunnelManager?.connectedDate != nil{
                self.startTimer(reason: "initialize-existing-connected-date")
            }
        }
        result(nil)
    }
}

/// Thin wrapper around `NETunnelProviderManager`.
///
/// This class centralizes the macOS profile lifecycle:
///
/// - load the existing tunnel manager from preferences;
/// - save Xray config bytes and route options into providerConfiguration;
/// - start/stop `NETunnelProviderSession`;
/// - forward status/configuration notifications back to the plugin;
/// - bridge provider messages for traffic and debug snapshots.
///
/// NetworkExtension preferences are eventually consistent and noisy. The code
/// therefore reloads on `NEVPNConfigurationChange`, listens to
/// `NEVPNStatusDidChange`, and logs every status transition with raw values.
final class PacketTunnelManager: ObservableObject {
    var providerBundleIdentifier: String?
    var groupIdentifier: String?
    let keychainAccessGroup: String?
    private let keychainClient: TunnelKeychainClient
    private let preferenceOperations = NativeOperationQueue()
    var remark: String = "Xray"
    var xrayConfig: Data = "".data(using: .utf8)!
    var bypassSubnets: [String] = []
    var proxyOnly: Bool = false
    var geoAssetsDirectory: String?
    var statusDidChange: ((NEVPNStatus?) -> Void)?
    private(set) var forwardingReady = false

    private var cancellables: Set<AnyCancellable> = []

    @Published private var manager: NETunnelProviderManager?

    @Published private(set) var isProcessing: Bool = false

    var status: NEVPNStatus? {
        manager.flatMap { $0.connection.status }
    }

    var connectedDate: Date? {
        manager.flatMap { $0.connection.connectedDate }
    }

    var isRecoveryEnabled: Bool {
        manager?.isEnabled == true && manager?.isOnDemandEnabled == true
            && (manager?.protocolConfiguration?.includeAllNetworks == true)
    }

    init(providerBundleIdentifier: String, groupIdentifier: String, keychainAccessGroup: String? = nil,
         keychainClient: TunnelKeychainClient = SystemTunnelKeychainClient()) {
        self.providerBundleIdentifier = providerBundleIdentifier
        self.groupIdentifier = groupIdentifier
        self.keychainAccessGroup = keychainAccessGroup
        self.keychainClient = keychainClient
        isProcessing = true
        Task(priority: .userInitiated) {
            await self.reload()
            await MainActor.run {
                self.isProcessing = false
            }
        }
    }


    func reload() async {
        self.cancellables.removeAll()
        do { try await self.preferenceOperations.submit { try await self.loadAndMigrate() }.value } catch { /* Retain the last known policy. */ }
        pluginLog.info("Reloaded tunnel manager: \(self.manager != nil, privacy: .public)")
        statusDidChange?(self.status)
        NotificationCenter.default
            .publisher(for: .NEVPNConfigurationChange, object: nil)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                pluginLog.info("NEVPNConfigurationChange received")
                Task(priority: .high) {
                    do { try await self.preferenceOperations.submit { try await self.loadAndMigrate() }.value } catch { /* Retain the last known policy. */ }
                    await MainActor.run {
                        self.statusDidChange?(self.status)
                    }
                }
            }
            .store(in: &cancellables)
        NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] notification in
                // Preference reads create temporary connections which also
                // publish status. Reacting to those recursively reloads them
                // during secret cleanup, flooding the app with status events.
                guard let connection = notification.object as? NEVPNConnection,
                      connection === self.manager?.connection else { return }
                if self.status != .connected { self.forwardingReady = false }
                pluginLog.info("NEVPNStatusDidChange status=\(self.status?.rawValue ?? -1, privacy: .public)")
                self.statusDidChange?(self.status)
                objectWillChange.send()
                if self.status == .disconnected || self.status == .invalid {
                    _ = self.preferenceOperations.submit { try await self.cleanupUnusedSecrets() }
                }
            }
            .store(in: &cancellables)
    }

    /// Permission is a disabled placeholder: no config, secret, or on-demand.
    func saveToPreferences() async throws {
        try await preferenceOperations.submit { try await self.savePermissionProfile() }.value
    }

    private func validateRouting() throws {
        _ = try DesktopBypassPolicy.validate(bypassSubnets)
    }

    private func secretStore(accessGroup: String? = nil) throws -> TunnelSecretStore {
        try TunnelSecretStore(accessGroup: accessGroup ?? keychainAccessGroup ?? groupIdentifier,
            providerBundleIdentifier: providerBundleIdentifier ?? "", client: keychainClient)
    }

    private func protectedProtocol() throws -> NETunnelProviderProtocol {
        guard let providerBundleIdentifier else { throw TunnelSecretError.invalidProfile }
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerBundleIdentifier
        configuration.serverAddress = "Xray"
        configuration.includeAllNetworks = true
        configuration.excludeLocalNetworks = false
        configuration.disconnectOnSleep = false
        if #available(macOS 13.3, *) {
            configuration.excludeAPNs = false
            configuration.excludeCellularServices = false
        }
        return configuration
    }

    private func savePermissionProfile() async throws {
        // Existing permission checks must not migrate, replace, or disarm a
        // live profile merely to display the operating system's consent sheet.
        if let existing = try await loadTunnelProviderManager() {
            manager = existing
            return
        }
        let manager = NETunnelProviderManager()
        let configuration = try protectedProtocol()
        configuration.providerConfiguration = ["configSchemaVersion": TunnelSecretProfile.schemaVersion,
                                               "groupIdentifier": groupIdentifier ?? ""]
        manager.protocolConfiguration = configuration
        manager.localizedDescription = remark
        manager.isEnabled = false
        manager.isOnDemandEnabled = false
        manager.onDemandRules = nil
        try await manager.saveToPreferences()
        self.manager = manager
        try await manager.loadFromPreferences()
    }

    /// Runs only on preferenceOperations, including notification-driven loads.
    private func loadAndMigrate() async throws {
        guard let loaded = try await loadTunnelProviderManager() else {
            manager = nil
            try? secretStore().reconcile(keeping: [])
            return
        }
        manager = loaded
        if let old = (loaded.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
           let legacy = old["xrayConfig"] as? Data {
            let store = try secretStore()
            var safe = launchMetadata(from: old)
            safe["keychainAccessGroup"] = store.accessGroup
            try await persist(legacy, metadata: safe, manager: loaded, activate: loaded.isEnabled,
                              preserveRecoveryPolicy: true, store: store)
        }
        try await cleanupUnusedSecrets()
    }

    private func launchMetadata(from old: [String: Any]? = nil) -> [String: Any] {
        // Allowlist metadata; never carry arbitrary legacy dictionary entries
        // (including passwords/private keys) into the new preference schema.
        var result: [String: Any] = ["configSchemaVersion": TunnelSecretProfile.schemaVersion,
            "groupIdentifier": old?["groupIdentifier"] as? String ?? groupIdentifier ?? "",
            "bypassSubnets": old?["bypassSubnets"] as? [String] ?? bypassSubnets,
            "proxyOnly": old?["proxyOnly"] as? Bool ?? proxyOnly]
        if let directory = old?["geoAssetsDirectory"] as? String ?? geoAssetsDirectory {
            result["geoAssetsDirectory"] = directory
        }
        return result
    }

    private func persist(_ config: Data, metadata: [String: Any], manager: NETunnelProviderManager,
                         activate: Bool, preserveRecoveryPolicy: Bool = false,
                         store: TunnelSecretStore) async throws {
        // Fail before any preference/session mutation, including oversized data
        // rejected by Security. There is no truncation or plaintext fallback.
        let reference = try store.insert(config)
        do { guard try store.read(reference) == config else { throw TunnelSecretError.profileVerificationFailed } }
        catch { try? store.remove(reference); throw error }
        let previousProtocol = manager.protocolConfiguration
        let previousDescription = manager.localizedDescription
        let previousEnabled = manager.isEnabled
        let previousOnDemand = manager.isOnDemandEnabled
        let previousRules = manager.onDemandRules
        let configuration = try protectedProtocol()
        var safe = metadata
        safe["xrayConfigReference"] = reference
        safe["keychainAccessGroup"] = store.accessGroup
        configuration.providerConfiguration = safe
        manager.protocolConfiguration = configuration
        manager.localizedDescription = remark
        if !preserveRecoveryPolicy {
            manager.isEnabled = activate
            if activate {
                let rule = NEOnDemandRuleConnect()
                rule.interfaceTypeMatch = .any
                manager.onDemandRules = [rule]
                manager.isOnDemandEnabled = true
            } else {
                manager.isOnDemandEnabled = false
                manager.onDemandRules = nil
            }
        }
        var persisted = false
        do {
            try await manager.saveToPreferences()
            persisted = true
            self.manager = manager
            try await manager.loadFromPreferences()
            let readback = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
            guard try TunnelSecretProfile.reference(in: readback) == reference,
                  try store.read(reference) == config else { throw TunnelSecretError.profileVerificationFailed }
        } catch {
            // Restore the prior version. Keep an already activated protective
            // policy armed even when the SDK refresh fails after saving it.
            manager.protocolConfiguration = previousProtocol
            manager.localizedDescription = previousDescription
            if !persisted {
                manager.isEnabled = previousEnabled
                manager.isOnDemandEnabled = previousOnDemand
                manager.onDemandRules = previousRules
            }
            do { try await manager.saveToPreferences() }
            catch {
                // Even a failed save callback can have an uncertain outcome.
                // Keep both immutable revisions until a successful readback.
                self.manager = manager
                throw TunnelSecretError.profileVerificationFailed
            }
            self.manager = manager
            // A provider may have launched while the new preferences existed.
            // Reconciliation after disconnect safely retires either revision.
            try? await cleanupUnusedSecrets()
            throw error
        }
        self.manager = manager
        try await cleanupUnusedSecrets()
        pluginLog.info("VPN preferences saved with Keychain reference active=\(activate, privacy: .public)")
    }

    private func saveConfiguration(activate: Bool) async throws {
        try validateRouting()
        let store = try secretStore()
        let manager = try await loadTunnelProviderManager() ?? NETunnelProviderManager()
        let existingGroup = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["keychainAccessGroup"] as? String
        guard existingGroup == nil || existingGroup == store.accessGroup else {
            // Moving a live profile between groups loses the durable inventory
            // of its prior revisions. Require explicit profile removal first.
            throw TunnelSecretError.accessGroupChanged
        }
        try await persist(xrayConfig, metadata: launchMetadata(), manager: manager, activate: activate, store: store)
    }

    /// Reconcile only while the provider cannot still hold an earlier revision.
    /// Delete failures leave inventory entries for retry, never break forwarding.
    private func cleanupUnusedSecrets() async throws {
        guard let current = try await loadTunnelProviderManager() else {
            try? secretStore().reconcile(keeping: [])
            return
        }
        guard current.connection.status == .disconnected || current.connection.status == .invalid else { return }
        // Armed on-demand can race an observed disconnected state. Keep every
        // revision until explicit stop has also persisted disarming.
        guard !current.isOnDemandEnabled else { return }
        let metadata = (current.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let references = (try? TunnelSecretProfile.reference(in: metadata)).map { Set([$0]) } ?? []
        try? secretStore(accessGroup: metadata["keychainAccessGroup"] as? String).reconcile(keeping: references)
    }

    func removeFromPreferences() async throws {
        try await preferenceOperations.submit {
            guard let manager = try await self.loadTunnelProviderManager() else {
                try? self.secretStore().reconcile(keeping: [])
                return
            }
            let oldGroup = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["keychainAccessGroup"] as? String
            try await self.stopLoaded(manager, waitForDisconnect: true)
            try await manager.removeFromPreferences()
            self.manager = nil
            // No profile and no active provider can own an item now. Failures
            // remain in the scoped Keychain inventory and retry on next load.
            try? self.secretStore(accessGroup: oldGroup).reconcile(keeping: [])
        }.value
    }

    func start() async throws {
        try await preferenceOperations.submit {
            try self.validateRouting()
            if let active = try await self.loadTunnelProviderManager(),
               [.connecting, .connected, .reasserting].contains(active.connection.status) {
                self.manager = active
                guard self.storedConfigurationMatches(xrayConfig: self.xrayConfig,
                    bypassSubnets: self.bypassSubnets, proxyOnly: self.proxyOnly) else {
                    throw DesktopTunnelError.configurationInUse
                }
                // Do not persist a revision that the running provider has not read.
                return
            }
            // Storage validation precedes changing the current readiness flag.
            try await self.saveConfiguration(activate: true)
            self.forwardingReady = false
            guard let manager = self.manager else { throw TunnelSecretError.invalidProfile }
            switch manager.connection.status {
            case .connecting, .connected, .reasserting: return
            default: try manager.connection.startVPNTunnel()
            }
        }.value
    }

    func stop(waitForDisconnect: Bool = false) async throws {
        try await preferenceOperations.submit {
            guard let manager = try await self.loadTunnelProviderManager() else {
                self.manager = nil
                return
            }
            try await self.stopLoaded(manager, waitForDisconnect: waitForDisconnect)
            try await self.cleanupUnusedSecrets()
        }.value
    }

    private func stopLoaded(_ manager: NETunnelProviderManager, waitForDisconnect: Bool) async throws {
        let enabled = manager.isEnabled
        let onDemand = manager.isOnDemandEnabled
        let rules = manager.onDemandRules
        manager.isOnDemandEnabled = false
        manager.onDemandRules = nil
        manager.isEnabled = false
        do { try await manager.saveToPreferences() }
        catch {
            manager.isEnabled = enabled
            manager.isOnDemandEnabled = onDemand
            manager.onDemandRules = rules
            throw error
        }
        self.manager = manager
        try await manager.loadFromPreferences()
        manager.connection.stopVPNTunnel()
        if waitForDisconnect {
            let deadline = Date().addingTimeInterval(20)
            while manager.connection.status != .disconnected && manager.connection.status != .invalid {
                guard Date() < deadline else {
                    throw NSError(domain: "VPN", code: 4,
                        userInfo: [NSLocalizedDescriptionKey: "Timed out waiting for the VPN to stop"])
                }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
        }
        pluginLog.info("VPN recovery disabled; manual stop requested")
    }

    func refreshForwardingState() async {
        guard isRecoveryEnabled else { return }
        let session = manager
        let response = try? await sendProviderMessage(data: Data("xray_runtime_state".utf8))
        // Ignore a reply from a session replaced by a queued start/stop.
        guard session === manager else { return }
        forwardingReady = response == Data("ready".utf8) && status == .connected
    }

    @discardableResult
    func sendProviderMessage(data: Data) async throws -> Data? {
        guard let manager = manager else {
            pluginLog.warning("sendProviderMessage skipped: manager is nil")
            return nil
        }

        guard let session = manager.connection as? NETunnelProviderSession else {
            pluginLog.error("sendProviderMessage failed: invalid connection type")
            throw NSError(domain: "VPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid connection type"])
        }

        guard session.status == .connected || session.status == .reasserting else {
            return nil
        }

        return try await withCheckedThrowingContinuation { continuation in
            let reply = NativeReplyGate<Data?> { continuation.resume(with: $0) }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
                reply.resolve(.failure(NSError(domain: "VPN", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Provider reply timed out"])))
            }
            do {
                try session.sendProviderMessage(data) { response in
                    reply.resolve(.success(response))
                }
            } catch {
                reply.resolve(.failure(error))
            }
        }
    }

    func testSaveAndLoadProfile() async -> Bool {
        do {
            try await saveToPreferences()
            return true
        } catch {
            pluginLog.error("Error during permission profile save: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
            return false
        }
    }

    func sharedProviderDebugSnapshot() -> String {
        guard let groupIdentifier,
              !groupIdentifier.isEmpty,
              let containerURL = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: groupIdentifier
              ) else {
            return ""
        }
        NativeLogPrivacy.removeLegacyProviderLog(in: containerURL)
        let providerURL = containerURL.appendingPathComponent(NativeLogPrivacy.providerLogFilename)
        let hevURL = containerURL.appendingPathComponent("hev-socks5-tunnel-error-v2.log")
        var sections: [String] = []

        if let provider = boundedFileTail(at: providerURL, maxLines: 200) {
            sections.append(provider.content)
        }
        if let attributes = try? FileManager.default.attributesOfItem(atPath: hevURL.path),
           let size = attributes[.size] as? NSNumber {
            sections.append("HEV diagnostic file bytes=\(size.uint64Value); raw contents omitted")
        }
        return sections.joined(separator: "\n")
    }

    private func boundedFileTail(
        at url: URL,
        maxBytes: UInt64 = 64 * 1024,
        maxLines: Int
    ) -> (content: String, size: UInt64)? {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return nil
        }
        defer { try? handle.close() }
        do {
            let size = try handle.seekToEnd()
            let start = size > maxBytes ? size - maxBytes : 0
            try handle.seek(toOffset: start)
            var data = try handle.readToEnd() ?? Data()
            if start > 0, let newline = data.firstIndex(of: 0x0a) {
                data = Data(data[data.index(after: newline)...])
            }
            guard let content = String(data: data, encoding: .utf8) else {
                return nil
            }
            let tail = content
                .split(separator: "\n", omittingEmptySubsequences: true)
                .suffix(maxLines)
                .joined(separator: "\n")
            return tail.isEmpty ? nil : (tail, size)
        } catch {
            return nil
        }
    }


    private func loadTunnelProviderManager() async throws -> NETunnelProviderManager? {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            pluginLog.info("Loaded \(managers.count, privacy: .public) tunnel manager(s) from preferences")


            guard let reval = managers.first(where: {
                guard let configuration = $0.protocolConfiguration as? NETunnelProviderProtocol else {
                    return false
                }
                return configuration.providerBundleIdentifier == providerBundleIdentifier
            }) else {
                pluginLog.warning("No tunnel manager found for provider=\(self.providerBundleIdentifier ?? "nil", privacy: .public)")
                return nil
            }

            try await reval.loadFromPreferences()
            pluginLog.info("Loaded matching tunnel manager enabled=\(reval.isEnabled, privacy: .public) status=\(reval.connection.status.rawValue, privacy: .public)")
            return reval
        } catch {
            pluginLog.error("Error loading tunnel provider manager: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
            throw error
        }
    }
    var isActive: Bool { [.connected, .connecting, .reasserting, .disconnecting].contains(status ?? .invalid) }
    func readSharedDebugLog() -> String? { sharedProviderDebugSnapshot() }
    func waitUntilInactive(timeoutSeconds: TimeInterval = 20) async throws {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while isActive {
            guard Date() < deadline else { throw NSError(domain: "VPN", code: 4, userInfo: [NSLocalizedDescriptionKey: "Timed out waiting for VPN shutdown"]) }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
    }
    func storedConfigurationMatches(xrayConfig: Data, bypassSubnets: [String], proxyOnly: Bool) -> Bool {
        guard isRecoveryEnabled,
              let configuration = manager?.protocolConfiguration as? NETunnelProviderProtocol,
              let metadata = configuration.providerConfiguration,
              let stored = try? TunnelSecretProfile.load(metadata, providerBundleIdentifier: providerBundleIdentifier ?? "", client: keychainClient) else { return false }
        return stored == xrayConfig && (metadata["bypassSubnets"] as? [String] ?? []) == bypassSubnets
            && (metadata["geoAssetsDirectory"] as? String) == geoAssetsDirectory && !proxyOnly
    }

}

private func configureXrayAssetLocation(_ directory: String?) throws {
    if directory?.isEmpty == true {
        throw NSError(
            domain: "FlutterVless",
            code: 12,
            userInfo: [NSLocalizedDescriptionKey: "Xray geo asset directory must not be empty"]
        )
    }
    var error: NSError?
    let configured = XRaySetAssetLocation(directory ?? "", &error)
    guard configured else {
        throw NativeLogPrivacy.operationError(error ?? NSError(
            domain: "FlutterVless",
            code: 13,
            userInfo: [NSLocalizedDescriptionKey: "Failed to configure Xray geo asset directory"]
        ))
    }
    if let directory {
        pluginLog.info("Configured Xray geo asset directory: \(directory, privacy: .public)")
    } else {
        pluginLog.info("Using Xray default geo asset lookup")
    }
}
