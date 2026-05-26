// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import Foundation
import FlutterMacOS
import AppKit
import NetworkExtension
import Combine

#if canImport(CXRay)
import CXRay
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
//   with `networksetup`. It is useful and fast, but it cannot capture UDP/QUIC
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

private let pluginLog = Logger(
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
        fileURL = containerURL.appendingPathComponent("flutter_vless_app_debug.log")
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
            try? handle.seekToEnd()
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

private func pluginDebug(_ message: String) {
    PluginDebugStore.shared.append(message)
    pluginLog.info("\(message, privacy: .public)")
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
            let sections: [(String, String, [String])] = [
                ("route-default", "/sbin/route", ["-n", "get", "default"]),
                ("route-dns-1.1.1.1", "/sbin/route", ["-n", "get", "1.1.1.1"]),
                ("route-dns-8.8.8.8", "/sbin/route", ["-n", "get", "8.8.8.8"]),
                ("netstat-inet", "/usr/sbin/netstat", ["-rn", "-f", "inet"]),
                ("netstat-inet6", "/usr/sbin/netstat", ["-rn", "-f", "inet6"]),
                ("scutil-dns", "/usr/sbin/scutil", ["--dns"])
            ]
            var output = ["System network snapshot reason=\(reason)"]
            for (name, executable, arguments) in sections {
                output.append("--- \(name) ---")
                output.append(run(executable: executable, arguments: arguments))
            }
            pluginDebug(output.joined(separator: "\n"))
        }
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
}

// MARK: - System Proxy Helper (macOS only)
/// Wrapper around macOS `networksetup` for proxy-only mode.
///
/// This helper must never be used as a substitute for Packet Tunnel routing.
/// macOS system proxy settings affect cooperative TCP clients only. They do not
/// capture UDP/QUIC and do not guarantee that all apps use the proxy. Packet
/// Tunnel mode clears system proxies before startup so the two modes do not
/// mask each other's behavior during debugging.
private struct SystemProxyHelper {
    static func getNetworkServices() -> [String] {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        task.arguments = ["-listallnetworkservices"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                return output.components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty && !$0.contains("*") && $0 != "An asterisk (*) denotes that a network service is disabled." }
            }
        } catch {
            pluginLog.error("Error getting network services: \(error.localizedDescription, privacy: .public)")
        }
        
        return ["Wi-Fi", "Ethernet"] // Fallback
    }

    /// Parses the XRay config to find the proxy inbound port.
    /// Prefers HTTP inbound (tag "http_proxy"), then falls back to SOCKS, then "in_proxy".
    static func parseProxyPort(config: String) -> (httpPort: String?, socksPort: String?) {
        guard let data = config.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let inbounds = json["inbounds"] as? [[String: Any]] else {
            return (nil, nil)
        }
        var httpPort: String? = nil
        var socksPort: String? = nil
        for inbound in inbounds {
            let proto = inbound["protocol"] as? String ?? ""
            let tag = inbound["tag"] as? String ?? ""
            guard let port = inbound["port"] as? Int else { continue }
            if proto == "http" || tag == "http_proxy" {
                httpPort = String(port)
            }
            if proto == "socks" || tag == "in_proxy" || tag == "socks" {
                socksPort = String(port)
            }
        }
        return (httpPort, socksPort)
    }

    /// Extracts outbound addresses so proxy-only mode can bypass the proxy
    /// server itself.
    ///
    /// Without this bypass, a system proxy configuration can accidentally make
    /// Xray's own outbound connection try to reach the server through the local
    /// proxy it is currently providing.
    static func parseOutboundAddresses(config: String) -> [String] {
        var addresses: [String] = []
        guard let data = config.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }
        var rawAddresses: [String] = []
        if let outbounds = json["outbounds"] as? [[String: Any]] {
            for outbound in outbounds {
                if let settings = outbound["settings"] as? [String: Any] {
                    if let vnext = settings["vnext"] as? [[String: Any]] {
                        for server in vnext {
                            if let address = server["address"] as? String, !address.isEmpty {
                                rawAddresses.append(address)
                            }
                        }
                    }
                    if let servers = settings["servers"] as? [[String: Any]] {
                        for server in servers {
                            if let address = server["address"] as? String, !address.isEmpty {
                                rawAddresses.append(address)
                            }
                        }
                    }
                }
            }
        }
        if let outbound = json["outbound"] as? [String: Any] {
            if let settings = outbound["settings"] as? [String: Any] {
                if let vnext = settings["vnext"] as? [[String: Any]] {
                    for server in vnext {
                        if let address = server["address"] as? String, !address.isEmpty {
                            rawAddresses.append(address)
                        }
                    }
                }
                if let servers = settings["servers"] as? [[String: Any]] {
                    for server in servers {
                        if let address = server["address"] as? String, !address.isEmpty {
                            rawAddresses.append(address)
                        }
                    }
                }
            }
        }
        for addr in rawAddresses {
            let resolved = resolveDomainToIPs(addr)
            for r in resolved {
                if !addresses.contains(r) {
                    addresses.append(r)
                }
            }
        }
        return addresses
    }

    /// Resolves domains for proxy bypass lists.
    ///
    /// The original domain is kept in the returned list as a fallback because
    /// `networksetup -setproxybypassdomains` accepts both hostnames and IPs, and
    /// DNS can change between setup time and connection time.
    static func resolveDomainToIPs(_ domain: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        
        var res: UnsafeMutablePointer<addrinfo>? = nil
        let status = getaddrinfo(domain, nil, &hints, &res)
        guard status == 0, let firstAddr = res else {
            return [domain]
        }
        
        var ips: [String] = []
        var ptr: UnsafeMutablePointer<addrinfo>? = firstAddr
        while ptr != nil {
            guard let info = ptr?.pointee else { break }
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.ai_addr, info.ai_addrlen, &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: hostname)
                if !ip.isEmpty {
                    ips.append(ip)
                }
            }
            ptr = info.ai_next
        }
        freeaddrinfo(res)
        
        var result = Array(Set(ips))
        if !result.contains(domain) {
            result.append(domain)
        }
        return result
    }

    /// Configures macOS system proxy settings (HTTP + HTTPS + SOCKS) for all network services.
    ///
    /// ОЧЕНЬ ВАЖНЫЙ НЮАНС (ПРОБЛЕМА QUIC / UDP):
    /// Системные прокси в macOS (networksetup) физически не поддерживают перехват UDP-трафика.
    /// Современные сайты (например, Google, YouTube, ChatGPT, 2ip.ru) по умолчанию используют
    /// протокол HTTP/3 (QUIC), который работает поверх UDP. 
    /// Если браузер отправляет запрос по QUIC, он ПОЛНОСТЬЮ ИГНОРИРУЕТ системный прокси и идёт напрямую!
    /// В результате пользователь видит свой реальный IP-адрес.
    /// 
    /// Единственный способ перехватить весь трафик (включая UDP и QUIC) на macOS/iOS — 
    /// использовать полноценный VPN-туннель (PacketTunnelProvider / NetworkExtension), 
    /// а не Proxy-Only режим. Для локального тестирования VPN-режима необходим платный
    /// Apple Developer Account. В Proxy-Only режиме пользователи могут отключать QUIC
    /// в настройках браузера (например, chrome://flags/#enable-quic), чтобы трафик шел через TCP (Proxy).
    static func setSystemProxy(config: String) {
        let services = getNetworkServices()
        let ports = parseProxyPort(config: config)

        var bypassDomains = ["localhost", "127.0.0.1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "*.local"]
        let outbounds = parseOutboundAddresses(config: config)
        for addr in outbounds {
            if !bypassDomains.contains(addr) {
                bypassDomains.append(addr)
            }
        }

        for service in services {
            // Set HTTP proxy (most apps check this)
            if let httpPort = ports.httpPort {
                runNetworkSetup(["-setwebproxy", service, "127.0.0.1", httpPort])
                runNetworkSetup(["-setwebproxystate", service, "on"])
                // Set HTTPS proxy (same HTTP proxy handles CONNECT for HTTPS)
                runNetworkSetup(["-setsecurewebproxy", service, "127.0.0.1", httpPort])
                runNetworkSetup(["-setsecurewebproxystate", service, "on"])
            }

            // Set SOCKS proxy (for apps that support SOCKS5)
            if let socksPort = ports.socksPort {
                runNetworkSetup(["-setsocksfirewallproxy", service, "127.0.0.1", socksPort])
                runNetworkSetup(["-setsocksfirewallproxystate", service, "on"])
            }

            // Set bypass domains
            runNetworkSetup(["-setproxybypassdomains", service] + bypassDomains)
        }
        pluginLog.info("System proxy set: HTTP=\(ports.httpPort ?? "none", privacy: .public) SOCKS=\(ports.socksPort ?? "none", privacy: .public) services=\(services.count, privacy: .public)")
    }

    /// Clears ALL system proxy settings (HTTP + HTTPS + SOCKS).
    static func clearSystemProxy() {
        let services = getNetworkServices()
        for service in services {
            runNetworkSetup(["-setwebproxystate", service, "off"])
            runNetworkSetup(["-setsecurewebproxystate", service, "off"])
            runNetworkSetup(["-setsocksfirewallproxystate", service, "off"])
        }
        pluginLog.info("System proxy cleared for \(services.count, privacy: .public) services")
    }

    /// Helper to run networksetup commands.
    private static func runNetworkSetup(_ arguments: [String]) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        task.arguments = arguments
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        try? task.run()
        task.waitUntilExit()
    }
}

// MARK: - Core Classes

/// Xray logger used by app-process delay/proxy-only runs.
///
/// The Packet Tunnel provider has its own logger and debug store. Keeping the
/// loggers separate makes it clear whether a message came from the app process
/// or the extension process.
private final class PluginXRayLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ s: String?) {
        if let message = s {
            pluginLog.info("XRay delay probe: \(message, privacy: .public)")
        }
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

    func measure(config: String, url: String) async -> Int64 {
        do {
            guard URL(string: url) != nil else {
                throw NSError(domain: "FlutterVless", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid probe URL"])
            }

            let proxyPort = Self.findFreePort()
            let delayConfig = try Self.buildDelayConfigData(config: config, proxyPort: proxyPort)

            XRaySetMemoryLimit()
            var startError: NSError?
            let started = XRayStart(delayConfig, logger, &startError)
            guard started else {
                throw startError ?? NSError(domain: "FlutterVless", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to start XRay delay probe"])
            }
            defer {
                XRayStop()
                pluginLog.info("Stopped XRay delay probe")
            }

            pluginLog.info("Started XRay delay probe on HTTP proxy port \(proxyPort, privacy: .public)")
            try await Task.sleep(nanoseconds: 1_000_000_000)
            return try await Self.measureURL(url, proxyPort: proxyPort)
        } catch {
            pluginLog.error("Server delay probe failed: \(error.localizedDescription, privacy: .public)")
            return -1
        }
    }

    /// Builds a temporary HTTP-proxy config for delay measurement.
    ///
    /// We rewrite only the local inbound used by the probe. Outbound protocol
    /// details are preserved so the delay test exercises the same server and
    /// credentials as the real start request.
    private static func buildDelayConfigData(config: String, proxyPort: Int) throws -> Data {
        guard
            let data = config.data(using: .utf8),
            var json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        else {
            throw NSError(domain: "FlutterVless", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid XRay config JSON"])
        }

        var inbounds = json["inbounds"] as? [[String: Any]] ?? []
        var hasProxyInbound = false

        for index in inbounds.indices {
            guard
                inbounds[index]["protocol"] as? String == "http" ||
                inbounds[index]["protocol"] as? String == "socks"
            else {
                continue
            }
            inbounds[index]["protocol"] = "http"
            inbounds[index]["port"] = proxyPort
            inbounds[index]["listen"] = "127.0.0.1"
            inbounds[index]["settings"] = [:]
            hasProxyInbound = true
            break
        }

        if !hasProxyInbound {
            inbounds.append([
                "tag": "socks",
                "port": proxyPort,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": [:]
            ])
        }

        if var log = json["log"] as? [String: Any] {
            log["access"] = ""
            log["error"] = ""
            log["dnsLog"] = false
            json["log"] = log
        }

        json["inbounds"] = inbounds
        return try JSONSerialization.data(withJSONObject: json, options: [])
    }

    private static func measureURL(_ url: String, proxyPort: Int) async throws -> Int64 {
        guard let probeURL = URL(string: url) else {
            throw NSError(domain: "FlutterVless", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid probe URL"])
        }

        var request = URLRequest(url: probeURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.timeoutInterval = 5

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 5
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable as String: true,
            kCFNetworkProxiesHTTPProxy as String: "127.0.0.1",
            kCFNetworkProxiesHTTPPort as String: proxyPort,
            "HTTPSEnable": true,
            "HTTPSProxy": "127.0.0.1",
            "HTTPSPort": proxyPort
        ]

        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        let start = DispatchTime.now().uptimeNanoseconds
        let (_, response) = try await session.data(for: request)
        let elapsed = (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
        if let httpResponse = response as? HTTPURLResponse {
            pluginLog.info("Server delay probe response=\(httpResponse.statusCode, privacy: .public) delay=\(elapsed, privacy: .public)ms")
        } else {
            pluginLog.info("Server delay probe delay=\(elapsed, privacy: .public)ms")
        }
        return Int64(elapsed)
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

/// App-process proxy-only runtime.
///
/// Proxy-only is valuable for fast local checks and for users who explicitly
/// want system proxy behavior, but it has known limits:
///
/// - it cannot capture UDP/QUIC;
/// - browsers may bypass it for HTTP/3 unless QUIC is disabled or blocked;
/// - stale proxy settings can break all network access if not cleaned up.
///
/// For that reason cleanup happens on normal stop, app termination, and signal
/// handlers. Packet Tunnel mode always stops proxy-only mode before saving or
/// starting the VPN profile.
private final class ProxyOnlyRunner {
    private let logger = PluginXRayLogger()
    private(set) var isRunning = false
    private(set) var connectedDate: Date?
    /// Tracks total bytes uploaded since last start.
    private(set) var totalUpload: Int64 = 0
    /// Tracks total bytes downloaded since last start.
    private(set) var totalDownload: Int64 = 0

    func start(configData: Data, configString: String, configureSystemProxy: Bool) throws {
        if isRunning {
            stop()
        }

        let preparedConfig = try Self.buildProxyOnlyConfigData(configData: configData)
        XRaySetMemoryLimit()
        var startError: NSError?
        let started = XRayStart(preparedConfig, logger, &startError)
        guard started else {
            throw startError ?? NSError(domain: "FlutterVless", code: 10, userInfo: [NSLocalizedDescriptionKey: "Failed to start XRay proxy-only mode"])
        }

        if configureSystemProxy {
            // IMPORTANT: pass preparedConfig (not original configString) so setSystemProxy
            // can see the HTTP inbound that buildProxyOnlyConfigData added.
            let preparedConfigString = String(data: preparedConfig, encoding: .utf8) ?? configString
            SystemProxyHelper.setSystemProxy(config: preparedConfigString)
        }

        isRunning = true
        connectedDate = Date()
        totalUpload = 0
        totalDownload = 0
        pluginLog.info("Started XRay proxy-only mode configBytes=\(preparedConfig.count, privacy: .public)")
    }

    func stop() {
        // Always clear system proxy first — even if isRunning is somehow false,
        // this guarantees we never leave a dead proxy configured.
        SystemProxyHelper.clearSystemProxy()
        guard isRunning else {
            return
        }
        XRayStop()
        isRunning = false
        connectedDate = nil
        totalUpload = 0
        totalDownload = 0
        pluginLog.info("Stopped XRay proxy-only mode")
    }

    /// Unconditional emergency cleanup — called when the process is about to exit.
    /// Does NOT check `isRunning` because the app might crash at any time.
    /// 
    /// ВАЖНО: Если приложение завершится некорректно (краш или принудительная остановка в Xcode)
    /// и системные настройки прокси не будут очищены, на Mac полностью пропадет интернет!
    /// (так как macOS будет пытаться отправлять весь трафик на выключенный локальный порт XRay).
    func forceCleanup() {
        SystemProxyHelper.clearSystemProxy()
        XRayStop()
        isRunning = false
        connectedDate = nil
        pluginLog.info("Force cleanup: cleared system proxy and stopped XRay")
    }

    func measureConnectedDelay(url: String) -> Int64 {
        guard isRunning else {
            return -1
        }
        var error: NSError?
        var delay: Int64 = -1
        XRayMeasureDelay(url, &delay, &error)
        if let error {
            pluginLog.error("Proxy-only connected delay failed: \(error.localizedDescription, privacy: .public)")
            return -1
        }
        return delay
    }

    /// Queries real traffic stats via XRay stats gRPC API.
    func queryTrafficStats() -> (upload: Int64, download: Int64) {
        guard isRunning else { return (0, 0) }
        let raw = XRayQueryStats("") ?? ""
        guard !raw.isEmpty else { return (totalUpload, totalDownload) }
        var up: Int64 = 0
        var down: Int64 = 0
        for line in raw.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: ">>>")
            guard parts.count >= 2, let value = Int64(parts.last!.trimmingCharacters(in: .whitespaces)) else { continue }
            if line.contains("uplink") { up += value }
            else if line.contains("downlink") { down += value }
        }
        totalUpload = up
        totalDownload = down
        return (up, down)
    }

    /// Normalizes a config for app-process proxy-only mode.
    ///
    /// This is separate from `TunnelXrayConfigPreparer` because proxy-only has
    /// different constraints:
    ///
    /// - it needs an HTTP inbound for macOS system web/secure-web proxy fields;
    /// - it should keep a SOCKS inbound for apps that support SOCKS;
    /// - it injects Xray stats API plumbing for local traffic counters;
    /// - it does not install utun routes or NetworkExtension DNS settings.
    private static func buildProxyOnlyConfigData(configData: Data) throws -> Data {
        guard var json = try JSONSerialization.jsonObject(with: configData, options: []) as? [String: Any] else {
            throw NSError(domain: "FlutterVless", code: 11, userInfo: [NSLocalizedDescriptionKey: "Invalid XRay config JSON"])
        }

        if var log = json["log"] as? [String: Any] {
            log["access"] = ""
            log["error"] = ""
            log["dnsLog"] = false
            json["log"] = log
        } else {
            json["log"] = ["access": "", "error": "", "dnsLog": false, "loglevel": "warning"]
        }

        // Ensure stats are enabled for traffic tracking
        if json["stats"] == nil {
            json["stats"] = [String: Any]()
        }

        // Ensure policy.system.statsOutboundUplink/Downlink are enabled
        var policy = json["policy"] as? [String: Any] ?? [:]
        var system = policy["system"] as? [String: Any] ?? [:]
        system["statsOutboundUplink"] = true
        system["statsOutboundDownlink"] = true
        policy["system"] = system
        json["policy"] = policy

        // Ensure we have both HTTP and SOCKS inbounds for maximum compatibility.
        var inbounds = json["inbounds"] as? [[String: Any]] ?? []
        
        // Check if HTTP inbound exists
        let hasHTTP = inbounds.contains { ($0["protocol"] as? String) == "http" }
        // Check if SOCKS inbound exists
        let hasSOCKS = inbounds.contains {
            let proto = $0["protocol"] as? String
            return proto == "socks"
        }

        // If the config has an "in_proxy" tag with socks/http, use it.
        // Otherwise add our own inbounds.
        if !hasHTTP {
            // Find a free port for HTTP (use SOCKS port + 1 if SOCKS exists)
            let httpPort: Int
            if let existingSOCKS = inbounds.first(where: { ($0["protocol"] as? String) == "socks" }),
               let socksPort = existingSOCKS["port"] as? Int {
                httpPort = socksPort + 1
            } else {
                httpPort = 10809
            }
            
            // ВАЖНО: Мы добавляем HTTP Inbound, так как системные прокси macOS лучше работают
            // с HTTP-прокси (особенно для HTTPS CONNECT запросов). 
            // Также мы ОБЯЗАТЕЛЬНО включаем 'sniffing', чтобы XRay мог извлекать доменные имена
            // (SNI) из трафика. Без sniffing правила маршрутизации по доменам (routing -> domain)
            // работать не будут, и трафик может пойти напрямую.
            inbounds.append([
                "tag": "http_proxy",
                "listen": "127.0.0.1",
                "port": httpPort,
                "protocol": "http",
                "settings": ["allowTransparent": false],
                "sniffing": ["enabled": true, "destOverride": ["http", "tls", "quic"]]
            ])
        }

        if !hasSOCKS && !inbounds.contains(where: { ($0["tag"] as? String) == "in_proxy" }) {
            inbounds.append([
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": ["auth": "noauth", "udp": true]
            ])
        }

        json["inbounds"] = inbounds

        // Inject XRay API service (gRPC on 127.0.0.1:10085) for stats queries.
        // Only add if not already present.
        let hasAPI = (json["api"] as? [String: Any]) != nil
        if !hasAPI {
            json["api"] = [
                "tag": "api",
                "services": ["StatsService"]
            ]
            // Add routing rule to direct API traffic to the API inbound
            var routing = json["routing"] as? [String: Any] ?? ["domainStrategy": "AsIs"]
            var rules = routing["rules"] as? [[String: Any]] ?? []
            // Prepend the API rule so it takes priority
            let apiRule: [String: Any] = [
                "type": "field",
                "inboundTag": ["api"],
                "outboundTag": "api"
            ]
            rules.insert(apiRule, at: 0)
            routing["rules"] = rules
            json["routing"] = routing

            // Add the API inbound listener on 10085
            inbounds.append([
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": ["address": "127.0.0.1"]
            ])
            json["inbounds"] = inbounds

            // ВАЖНО: Если мы добавили правило маршрутизации с `outboundTag: "api"`,
            // мы ОБЯЗАНЫ добавить outbound с тегом "api" в конфигурацию!
            // Если XRay встретит правило маршрутизации, ссылающееся на несуществующий outbound,
            // его внутренний роутер (dispatcher) может начать сбрасывать весь трафик.
            // Если XRay начнет сбрасывать (drop) TCP-соединения, браузеры (Chrome, Safari)
            // решат, что прокси "мертв", и автоматически начнут слать трафик напрямую (fallback to direct).
            var outbounds = json["outbounds"] as? [[String: Any]] ?? []
            if !outbounds.contains(where: { ($0["tag"] as? String) == "api" }) {
                outbounds.append([
                    "tag": "api",
                    "protocol": "freedom",
                    "settings": [:]
                ])
                json["outbounds"] = outbounds
            }
        }

        return try JSONSerialization.data(withJSONObject: json, options: [])
    }
}

/// Flutter-facing macOS plugin implementation.
///
/// Responsibilities:
///
/// - MethodChannel dispatch for initialize/start/stop/delay/debug calls.
/// - EventChannel status stream for UI duration/speed/counter updates.
/// - App-process proxy-only lifecycle.
/// - Packet Tunnel profile management through `PacketTunnelManager`.
/// - Repeated provider/debug polling while the VPN is active.
///
/// The status stream is intentionally optimistic when `startVPNTunnel` returns:
/// the UI can show "connecting/connected" quickly, but the provider debug
/// snapshot remains the source of truth for whether DNS, server routes, Xray,
/// HEV, and real HTTPS all worked.
public class FlutterVlessPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private var packetTunnelManager: PacketTunnelManager? = nil
    private let serverDelayRunner = ServerDelayRunner()
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
    private func startTimer(reason: String = "unspecified") {
        guard Thread.isMainThread else {
            pluginDebug("startTimer requested off main thread reason=\(reason); dispatching to main")
            DispatchQueue.main.async { [weak self] in
                self?.startTimer(reason: reason)
            }
            return
        }

        if self.timer != nil {
            pluginDebug("Traffic polling timer already running reason=\(reason) eventSink=\(self.eventSink != nil) vpnStatus=\(self.packetTunnelManager?.status?.rawValue ?? -1)")
            emitStatus(duration: currentDurationSeconds(), state: "CONNECTED", reason: "timer-already-running:\(reason)")
            return
        }

        pluginDebug("Starting traffic polling timer reason=\(reason) mainThread=\(Thread.isMainThread) eventSink=\(self.eventSink != nil) vpnStatus=\(self.packetTunnelManager?.status?.rawValue ?? -1)")
        self.timer?.invalidate()
        emitStatus(duration: currentDurationSeconds(), state: "CONNECTED", reason: "timer-start:\(reason)")
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
               status == .invalid || status == .disconnected {
                pluginDebug("Packet tunnel is no longer active while polling status=\(status.rawValue)")
                self.stopTimer(reason: "vpn-status-\(status.rawValue)")
                return
            }

            let elapsed = Date().timeIntervalSince(self.packetTunnelManager?.connectedDate ?? Date())
            let seconds = Int(elapsed)
            self.emitStatus(duration: seconds, state: "CONNECTED", reason: "timer-vpn")
            Task{
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
    }

    private func currentDurationSeconds() -> Int {
        if proxyOnlyRunner.isRunning {
            return Int(Date().timeIntervalSince(proxyOnlyRunner.connectedDate ?? Date()))
        }
        return Int(Date().timeIntervalSince(packetTunnelManager?.connectedDate ?? Date()))
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
                guard let response = try await self.packetTunnelManager?.sendProviderMessage(data: "xray_debug".data(using: .utf8)!) else {
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
    private func stopVless(result: FlutterResult) {
        pluginLog.info("stopVless requested")
        proxyOnlyRunner.stop()
        packetTunnelManager?.stop()
        stopTimer()
        result(nil)
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
                    let delay = self.proxyOnlyRunner.measureConnectedDelay(url: url)
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
            do {
                guard let response = try await packetTunnelManager?.sendProviderMessage(data: "xray_debug".data(using: .utf8)!) else {
                    result(packetTunnelManager?.readSharedDebugLog() ?? "")
                    return
                }
                result(String(decoding: response, as: UTF8.self))
            } catch {
                pluginLog.error("Provider debug snapshot request failed: \(error.localizedDescription, privacy: .public)")
                result(packetTunnelManager?.readSharedDebugLog() ?? "")
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
        Task {
            let delay = await serverDelayRunner.measure(config: config, url: url)
            result(delay)
        }
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
        let setSystemProxy = arguments["set_system_proxy"] as? Bool ?? true
        if proxyOnly {
            do {
                try proxyOnlyRunner.start(
                    configData: configData,
                    configString: config,
                    configureSystemProxy: setSystemProxy
                )
                pluginLog.info("Proxy-only start requested successfully remark=\(remark, privacy: .public)")
                startTimer()
                result(nil)
            } catch {
                pluginLog.error("Failed to start proxy-only mode: \(error.localizedDescription, privacy: .public)")
                result(FlutterError(code: "PROXY_ONLY_ERROR",
                                    message: "Failed to start proxy-only mode: \(error.localizedDescription)",
                                    details: nil))
            }
            return
        }

        proxyOnlyRunner.stop()
        packetTunnelManager?.remark = remark
        let bypassSubnets = arguments["bypass_subnets"] as? [String] ?? []
        pluginDebug("startVless VPN remark=\(remark) configBytes=\(configData.count) currentProxyOnly=\(self.packetTunnelManager?.proxyOnly ?? false) bypassCount=\(self.packetTunnelManager?.bypassSubnets.count ?? 0) hasEventSink=\(eventSink != nil)")
        
        Task {
            do {
                if self.packetTunnelManager?.isActive == true {
                    if self.packetTunnelManager?.storedConfigurationMatches(
                        xrayConfig: configData,
                        bypassSubnets: bypassSubnets,
                        proxyOnly: false
                    ) == true {
                        pluginDebug("VPN already active with same configuration; skipping preference save/start")
                        self.startTimer(reason: "vpn-already-active")
                        result(nil)
                        return
                    }
                    pluginDebug("VPN active with a different configuration; stopping before restart")
                    self.packetTunnelManager?.stop()
                    try await self.packetTunnelManager?.waitUntilInactive()
                }

                self.packetTunnelManager?.xrayConfig = configData
                self.packetTunnelManager?.bypassSubnets = bypassSubnets
                self.packetTunnelManager?.proxyOnly = false
                try await packetTunnelManager?.saveToPreferences()
                try await packetTunnelManager?.start()
                pluginDebug("VPN start requested successfully; starting UI/traffic timer")
                startTimer(reason: "startVless-success")
                result(nil)
                return
            } catch {
                pluginDebug("Failed to start VPN: \(error.localizedDescription)")
                result(FlutterError(code: "VPN_ERROR",
                                    message: "Failed to start VPN: \(error.localizedDescription)",
                                    details: nil))
                stopTimer(reason: "startVless-error")
                return
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
        Task {
            if self.packetTunnelManager?.isActive == true {
                pluginDebug("requestPermission skipped preference rewrite because VPN is active")
                result(true)
                return
            }
            let isGranted = await packetTunnelManager?.testSaveAndLoadProfile() ?? false
            pluginDebug("requestPermission result=\(isGranted)")
            result(isGranted)
        }
    }

    private func getCoreVersion(result: @escaping FlutterResult) {
        Task {
            let version = String(cString: XRayGetVersion())
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
        self.packetTunnelManager = PacketTunnelManager(providerBundleIdentifier: "\(providerBundleIdentifier).XrayTunnel", groupIdentifier: groupIdentifier)
        self.packetTunnelManager?.statusDidChange = { [weak self] status in
            guard let self else { return }
            pluginDebug("PacketTunnelManager status callback raw=\(status?.rawValue ?? -1) timerRunning=\(self.timer != nil) proxyOnly=\(self.proxyOnlyRunner.isRunning)")
            switch status {
            case .connecting, .connected, .reasserting:
                self.startTimer(reason: "vpn-status-\(status?.rawValue ?? -1)")
                if status == .connected {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                        self?.logSystemNetworkSnapshot(reason: "vpn-connected-delayed", force: true)
                    }
                }
            case .disconnected, .invalid:
                if !self.proxyOnlyRunner.isRunning {
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
    var remark: String = "Xray"
    var xrayConfig: Data = "".data(using: .utf8)!
    var bypassSubnets: [String] = []
    var proxyOnly: Bool = false
    var statusDidChange: ((NEVPNStatus?) -> Void)?

    private var cancellables: Set<AnyCancellable> = []

    @Published private var manager: NETunnelProviderManager?

    @Published private(set) var isProcessing: Bool = false

    var status: NEVPNStatus? {
        manager.flatMap { $0.connection.status }
    }

    var connectedDate: Date? {
        manager.flatMap { $0.connection.connectedDate }
    }

    var isActive: Bool {
        guard let status else {
            return false
        }
        return status == .connecting || status == .connected || status == .reasserting
    }

    init(providerBundleIdentifier: String, groupIdentifier: String) {
        self.providerBundleIdentifier = providerBundleIdentifier
        self.groupIdentifier = groupIdentifier
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
        self.manager = await self.loadTunnelProviderManager()
        pluginDebug("Reloaded tunnel manager exists=\(self.manager != nil) status=\(self.status?.rawValue ?? -1)")
        statusDidChange?(self.status)
        NotificationCenter.default
            .publisher(for: .NEVPNConfigurationChange, object: nil)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                pluginDebug("NEVPNConfigurationChange received currentStatus=\(self.status?.rawValue ?? -1)")
                Task(priority: .high) {
                    self.manager = await self.loadTunnelProviderManager()
                    await MainActor.run {
                        pluginDebug("NEVPNConfigurationChange reload complete status=\(self.status?.rawValue ?? -1)")
                        self.statusDidChange?(self.status)
                    }
                }
            }
            .store(in: &cancellables)
        NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                pluginDebug("NEVPNStatusDidChange status=\(self.status?.rawValue ?? -1)")
                self.statusDidChange?(self.status)
                objectWillChange.send()
            }
            .store(in: &cancellables)
    }

    /// Saves the Packet Tunnel profile with the current runtime config.
    ///
    /// `providerConfiguration` is the only structured handoff from the app
    /// process to the extension at startup. Keep values small and serializable:
    /// raw Xray config bytes, bypass subnets, proxy-only flag for diagnostics,
    /// and App Group id for shared debug logs.
    ///
    /// Route flags are deliberate:
    ///
    /// - `includeAllNetworks = true`: macOS should capture normal app traffic.
    /// - `excludeLocalNetworks = true`: local network/LAN behavior remains sane.
    /// - `enforceRoutes = false`: forcing routes made the provider's own access
    ///   to excluded DNS/server routes less reliable during bring-up.
    func saveToPreferences() async throws {
        guard let providerBundleIdentifier = providerBundleIdentifier else {
            throw NSError(domain: "VPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Provider bundle identifier is missing."])
        }

        do {
            let manager = self.manager ?? NETunnelProviderManager()
            self.manager = manager
            manager.localizedDescription = remark
            manager.protocolConfiguration = {
                let configuration = NETunnelProviderProtocol()
                configuration.providerBundleIdentifier = providerBundleIdentifier
                configuration.serverAddress = "Xray"
                configuration.providerConfiguration = [
                    "xrayConfig": self.xrayConfig,
                    "bypassSubnets": self.bypassSubnets,
                    "proxyOnly": self.proxyOnly,
                    "groupIdentifier": self.groupIdentifier ?? ""
                ]
                // The packet tunnel installs IPv4/IPv6 default routes, but
                // macOS may keep ordinary app traffic on the primary interface
                // unless the profile captures all networks. Do not combine this
                // with enforceRoutes: that made the provider process lose
                // reliable access to the excluded Xray server route.
                configuration.includeAllNetworks = true
                configuration.excludeLocalNetworks = true
                configuration.enforceRoutes = false
                return configuration
            }()
            manager.isEnabled = true
            if let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol {
                pluginDebug("Saving VPN preferences provider=\(providerBundleIdentifier) configBytes=\(self.xrayConfig.count) includeAllNetworks=\(configuration.includeAllNetworks) excludeLocalNetworks=\(configuration.excludeLocalNetworks) enforceRoutes=\(configuration.enforceRoutes) hasManager=\(self.manager != nil)")
            } else {
                pluginDebug("Saving VPN preferences provider=\(providerBundleIdentifier) configBytes=\(self.xrayConfig.count)")
            }
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            pluginDebug("VPN preferences saved and reloaded status=\(manager.connection.status.rawValue) enabled=\(manager.isEnabled)")
        } catch {
            pluginDebug("Error saving VPN preferences: \(error.localizedDescription)")
            throw error
        }
    }

    func removeFromPreferences() async throws {
        guard let manager = manager else {
            return
        }
        pluginLog.info("Removing VPN preferences")
        try await manager.removeFromPreferences()
    }

    /// Starts the saved VPN profile.
    ///
    /// `startVPNTunnel` returning successfully does not mean provider health is
    /// complete. It means macOS accepted the start request. The plugin starts UI
    /// polling after this, while provider health checks prove the real data path.
    func start() async throws {
        guard let manager = manager else {
            throw NSError(domain: "VPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not found"])
        }

        if manager.connection.status == .connected || manager.connection.status == .connecting {
            pluginDebug("Skipping startVPNTunnel because status=\(manager.connection.status.rawValue)")
            return
        }

        if !manager.isEnabled {
            manager.isEnabled = true
            try await manager.saveToPreferences()
        }

        do {
            pluginDebug("Calling startVPNTunnel currentStatus=\(manager.connection.status.rawValue) enabled=\(manager.isEnabled)")
            try manager.connection.startVPNTunnel()
            pluginDebug("startVPNTunnel returned currentStatus=\(manager.connection.status.rawValue)")
        } catch {
            pluginDebug("Failed to start VPN tunnel: \(error.localizedDescription)")
            throw error
        }
    }

    func stop() {
        guard let manager = manager else {
            return
        }
        pluginDebug("Calling stopVPNTunnel currentStatus=\(manager.connection.status.rawValue)")
        manager.connection.stopVPNTunnel()
    }

    func waitUntilInactive(timeoutSeconds: TimeInterval = 5) async throws {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while isActive && Date() < deadline {
            try await Task.sleep(nanoseconds: 150_000_000)
        }
    }

    /// Avoids restarting an already-active VPN with identical provider config.
    ///
    /// This reduces preference churn and repeated configuration notifications
    /// during manual testing from the example app.
    func storedConfigurationMatches(xrayConfig: Data, bypassSubnets: [String], proxyOnly: Bool) -> Bool {
        guard
            let configuration = manager?.protocolConfiguration as? NETunnelProviderProtocol,
            let providerConfiguration = configuration.providerConfiguration
        else {
            return false
        }
        let storedConfig = providerConfiguration["xrayConfig"] as? Data
        let storedBypassSubnets = providerConfiguration["bypassSubnets"] as? [String] ?? []
        let storedProxyOnly = providerConfiguration["proxyOnly"] as? Bool ?? false
        return storedConfig == xrayConfig &&
            storedBypassSubnets == bypassSubnets &&
            storedProxyOnly == proxyOnly
    }

    /// Fallback reader for provider debug evidence.
    ///
    /// Used when `sendProviderMessage("xray_debug")` returns nil or throws
    /// during extension startup/shutdown.
    func readSharedDebugLog() -> String? {
        guard let groupIdentifier,
              !groupIdentifier.isEmpty,
              let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier) else {
            return nil
        }
        let url = containerURL.appendingPathComponent("flutter_vless_tunnel_debug.log")
        guard let data = try? Data(contentsOf: url),
              let content = String(data: data, encoding: .utf8),
              !content.isEmpty else {
            return nil
        }
        return content.split(separator: "\n").suffix(160).joined(separator: "\n")
    }

    /// Sends an internal control/debug message to the Packet Tunnel provider.
    ///
    /// Do not use this for high-frequency data transfer. It is for status,
    /// counters, health evidence, and connected delay probes. The actual VPN
    /// traffic flows through utun/HEV/Xray, not provider messages.
    @discardableResult
    func sendProviderMessage(data: Data) async throws -> Data? {
        guard let manager = manager else {
            pluginDebug("sendProviderMessage skipped: manager is nil bytes=\(data.count)")
            return nil
        }

        guard let session = manager.connection as? NETunnelProviderSession else {
            pluginDebug("sendProviderMessage failed: invalid connection type status=\(manager.connection.status.rawValue) bytes=\(data.count)")
            throw NSError(domain: "VPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid connection type"])
        }

        let message = String(data: data, encoding: .utf8) ?? "<\(data.count) bytes>"
        pluginDebug("sendProviderMessage begin message=\(message) status=\(manager.connection.status.rawValue)")
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    pluginDebug("sendProviderMessage response message=\(message) responseBytes=\(response?.count ?? -1)")
                    continuation.resume(with: .success(response))
                }
            } catch {
                pluginDebug("sendProviderMessage throw message=\(message) error=\(error.localizedDescription)")
                continuation.resume(with: .failure(error))
            }
        }
    }

    func testSaveAndLoadProfile() async -> Bool {
        do {
            try await saveToPreferences()
            let _ = await loadTunnelProviderManager()
            pluginDebug("testSaveAndLoadProfile succeeded status=\(self.status?.rawValue ?? -1)")
            return true
        } catch {
            pluginDebug("Error during save and load test: \(error.localizedDescription)")
            return false
        }
    }

    private func loadTunnelProviderManager() async -> NETunnelProviderManager? {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            pluginDebug("Loaded \(managers.count) tunnel manager(s) from preferences")

            guard let reval = managers.first(where: {
                guard let configuration = $0.protocolConfiguration as? NETunnelProviderProtocol else {
                    return false
                }
                return configuration.providerBundleIdentifier == providerBundleIdentifier
            }) else {
                pluginDebug("No tunnel manager found for provider=\(self.providerBundleIdentifier ?? "nil")")
                return nil
            }

            try await reval.loadFromPreferences()
            pluginDebug("Loaded matching tunnel manager enabled=\(reval.isEnabled) status=\(reval.connection.status.rawValue) connectedDate=\(String(describing: reval.connection.connectedDate))")
            return reval
        } catch {
            pluginDebug("Error loading tunnel provider manager: \(error.localizedDescription)")
            return nil
        }
    }
}
