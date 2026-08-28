// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import Flutter
import UIKit
import NetworkExtension
import Combine
import XRay
import os
import CFNetwork
import Darwin

private let pluginLog = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "flutter_vless.Runner",
    category: "FlutterVlessPlugin"
)

private final class PluginXRayLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ s: String?) {
        if let message = s {
            pluginLog.info("XRay delay probe: \(message, privacy: .public)")
        }
    }
}

private actor ServerDelayRunner {
    private let logger = PluginXRayLogger()

    func measure(config: String, url: String, geoAssetsDirectory: String?) async -> Int64 {
        do {
            guard URL(string: url) != nil else {
                throw NSError(domain: "FlutterVless", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid probe URL"])
            }

            let proxyPort = Self.findFreePort()
            let delayConfig = try Self.buildDelayConfigData(config: config, proxyPort: proxyPort)

            XRaySetMemoryLimit()
            try configureXrayAssetLocation(geoAssetsDirectory)
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
        request.httpMethod = "HEAD"
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

private final class ProxyOnlyRunner {
    private let logger = PluginXRayLogger()
    private(set) var isRunning = false
    private(set) var connectedDate: Date?

    func start(configData: Data, geoAssetsDirectory: String?) throws {
        if isRunning {
            stop()
        }

        let preparedConfig = try Self.buildProxyOnlyConfigData(configData: configData)
        XRaySetMemoryLimit()
        try configureXrayAssetLocation(geoAssetsDirectory)
        var startError: NSError?
        let started = XRayStart(preparedConfig, logger, &startError)
        guard started else {
            throw startError ?? NSError(domain: "FlutterVless", code: 10, userInfo: [NSLocalizedDescriptionKey: "Failed to start XRay proxy-only mode"])
        }

        isRunning = true
        connectedDate = Date()
        pluginLog.info("Started XRay proxy-only mode configBytes=\(preparedConfig.count, privacy: .public)")
    }

    func stop() {
        guard isRunning else {
            return
        }
        XRayStop()
        isRunning = false
        connectedDate = nil
        pluginLog.info("Stopped XRay proxy-only mode")
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

        return try JSONSerialization.data(withJSONObject: json, options: [])
    }
}

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

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "flutter_vless", binaryMessenger: registrar.messenger())
        let instance = FlutterVlessPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        let eventChannel = FlutterEventChannel(name: "flutter_vless/status", binaryMessenger: registrar.messenger())
        eventChannel.setStreamHandler(instance)
    }


    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        pluginLog.info("Status stream attached")
        self.eventSink = events
        emitStatus(duration: currentDurationSeconds(), state: currentRuntimeState(), reason: "stream-attached")
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        pluginLog.info("Status stream detached")
        self.eventSink = nil
        return nil
    }

    /// Polls traffic counters and periodically mirrors provider diagnostics.
    ///
    /// The packet tunnel lives in a separate extension process. Emitting the
    /// provider snapshot every few seconds keeps real-device evidence in the
    /// Runner console while the public status follows the real NEVPN state.
    private func startTimer(reason: String = "unspecified") {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.startTimer(reason: reason)
            }
            return
        }

        if self.timer != nil {
            emitStatus(duration: currentDurationSeconds(), state: currentRuntimeState(), reason: "timer-already-running:\(reason)")
            return
        }

        pluginLog.info("Starting traffic polling timer reason=\(reason, privacy: .public)")
        self.timer?.invalidate()
        emitStatus(duration: currentDurationSeconds(), state: currentRuntimeState(), reason: "timer-start:\(reason)")
        let timer = Timer(timeInterval: 1, repeats: true, block: { [weak self] _ in
            guard let self else { return }
            if self.proxyOnlyRunner.isRunning {
                let elapsed = Date().timeIntervalSince(self.proxyOnlyRunner.connectedDate ?? Date())
                let seconds = Int(elapsed)
                self.emitStatus(duration: seconds, state: "CONNECTED", reason: "timer-proxy")
                return
            }

            let state = self.currentRuntimeState()
            if state == "DISCONNECTED" || state == "UNKNOWN" {
                self.stopTimer(reason: "vpn-state-\(state)")
                return
            }

            let elapsed = Date().timeIntervalSince(self.packetTunnelManager?.connectedDate ?? Date())
            let seconds = Int(elapsed)
            self.emitStatus(duration: seconds, state: state, reason: "timer-vpn")
            guard state == "CONNECTED" else {
                return
            }

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
                                pluginLog.info("Traffic stats up=\(up, privacy: .public) down=\(down, privacy: .public) upSpeed=\(self.uploadSpeed, privacy: .public) downSpeed=\(self.downloadSpeed, privacy: .public)")
                                self.logProviderDebugSnapshot()
                            }
                        }
                    }
                }catch{
                    pluginLog.error("Error polling traffic: \(error.localizedDescription, privacy: .public)")
                }
            }
        })
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    private func stopTimer(reason: String = "unspecified") {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.stopTimer(reason: reason)
            }
            return
        }

        pluginLog.info("Stopping traffic polling timer reason=\(reason, privacy: .public)")
        self.timer?.invalidate()
        self.timer = nil
        emitStatus(duration: 0, state: "DISCONNECTED", reason: "timer-stop:\(reason)")
        self.uploadSpeed = 0
        self.downloadSpeed = 0
        self.totalUpload = 0
        self.totalDownload = 0
        self.lastProviderDebugLogDate = .distantPast
    }

    private func currentDurationSeconds() -> Int {
        if proxyOnlyRunner.isRunning {
            return Int(Date().timeIntervalSince(proxyOnlyRunner.connectedDate ?? Date()))
        }
        return Int(Date().timeIntervalSince(packetTunnelManager?.connectedDate ?? Date()))
    }

    private func currentRuntimeState() -> String {
        if proxyOnlyRunner.isRunning {
            return "CONNECTED"
        }
        guard let status = packetTunnelManager?.status else {
            return "DISCONNECTED"
        }
        switch status {
        case .invalid, .disconnected:
            return "DISCONNECTED"
        case .connecting:
            return "CONNECTING"
        case .connected, .reasserting:
            return "CONNECTED"
        case .disconnecting:
            return "DISCONNECTING"
        @unknown default:
            return "UNKNOWN"
        }
    }

    private func emitStatus(duration: Int, state: String, reason: String) {
        let payload = ["\(duration)", "\(uploadSpeed)", "\(downloadSpeed)", "\(totalUpload)", "\(totalDownload)", state]
        if state != "CONNECTED" || Date().timeIntervalSince(lastTrafficLogDate) >= 5 {
            pluginLog.info("Status event reason=\(reason, privacy: .public) payload=\(payload.joined(separator: ","), privacy: .public) vpnStatus=\(self.packetTunnelManager?.status?.rawValue ?? -1, privacy: .public)")
        }
        eventSink?(payload)
    }

    /// Sends a lightweight debug request to the NetworkExtension provider.
    ///
    /// The snapshot is intentionally verbose enough to compare transports:
    /// TCP/Reality must show the SOCKS HTTP health check as `ok`, while XHTTP
    /// failures usually show where the chain stopped.
    private func logProviderDebugSnapshot() {
        guard Date().timeIntervalSince(lastProviderDebugLogDate) >= 5 else {
            return
        }
        lastProviderDebugLogDate = Date()
        Task {
            do {
                guard let response = try await self.packetTunnelManager?.sendProviderMessage(data: "xray_debug".data(using: .utf8)!) else {
                    let persisted = self.packetTunnelManager?.sharedProviderDebugSnapshot() ?? ""
                    if persisted.isEmpty {
                        pluginLog.warning("Provider debug snapshot unavailable")
                    } else {
                        pluginLog.info("Provider persisted debug snapshot:\n\(persisted, privacy: .public)")
                    }
                    return
                }
                let snapshot = String(decoding: response, as: UTF8.self)
                if !snapshot.isEmpty {
                    pluginLog.info("Provider debug snapshot:\n\(snapshot, privacy: .public)")
                }
            } catch {
                pluginLog.error("Provider debug snapshot failed: \(error.localizedDescription, privacy: .public)")
                let persisted = self.packetTunnelManager?.sharedProviderDebugSnapshot() ?? ""
                if !persisted.isEmpty {
                    pluginLog.info("Provider persisted debug snapshot:\n\(persisted, privacy: .public)")
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

    private func stopVless(result: FlutterResult) {
        pluginLog.info("stopVless requested")
        proxyOnlyRunner.stop()
        packetTunnelManager?.stop()
        stopTimer(reason: "stopVless")
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

    /// Test/manual diagnostic hook used by the example app and integration test.
    ///
    /// This is not traffic data for UI counters; it is a structured escape hatch
    /// from the extension sandbox so XHTTP and TCP/Reality can be compared from
    /// the same Xcode session.
    private func getProviderDebugSnapshot(result: @escaping FlutterResult) {
        Task {
            do {
                guard let response = try await packetTunnelManager?.sendProviderMessage(data: "xray_debug".data(using: .utf8)!) else {
                    result(packetTunnelManager?.sharedProviderDebugSnapshot() ?? "")
                    return
                }
                result(String(decoding: response, as: UTF8.self))
            } catch {
                pluginLog.error("Provider debug snapshot request failed: \(error.localizedDescription, privacy: .public)")
                let persisted = packetTunnelManager?.sharedProviderDebugSnapshot() ?? ""
                if persisted.isEmpty {
                    result(FlutterError(code: "PROVIDER_DEBUG_FAILED", message: error.localizedDescription, details: nil))
                } else {
                    result(persisted)
                }
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
            let delay = await serverDelayRunner.measure(
                config: config,
                url: url,
                geoAssetsDirectory: arguments["geo_assets_directory"] as? String
            )
            result(delay)
        }
    }

    private func startVless(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let remark = arguments["remark"] as? String,
              let config = arguments["config"] as? String,
              let configData = config.data(using: .utf8) else {
            result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments for startVless.", details: nil))
            return
        }
        let proxyOnly = arguments["proxy_only"] as? Bool ?? false
        let geoAssetsDirectory = arguments["geo_assets_directory"] as? String
        if proxyOnly {
            do {
                try proxyOnlyRunner.start(
                    configData: configData,
                    geoAssetsDirectory: geoAssetsDirectory
                )
                pluginLog.info("Proxy-only start requested successfully remark=\(remark, privacy: .public)")
                startTimer(reason: "proxy-only-started")
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
        packetTunnelManager?.xrayConfig = configData
        packetTunnelManager?.bypassSubnets = arguments["bypass_subnets"] as? [String] ?? []
        packetTunnelManager?.proxyOnly = false
        packetTunnelManager?.geoAssetsDirectory = geoAssetsDirectory
        pluginLog.info("startVless remark=\(remark, privacy: .public) configBytes=\(configData.count, privacy: .public) proxyOnly=\(self.packetTunnelManager?.proxyOnly ?? false, privacy: .public) bypassCount=\(self.packetTunnelManager?.bypassSubnets.count ?? 0, privacy: .public)")
        pluginLog.info("\(self.describeConfig(configData), privacy: .public)")
        Task {
            do {
                try await packetTunnelManager?.saveToPreferences()
                try await packetTunnelManager?.start()
                pluginLog.info("VPN start requested successfully")
                self.startTimer(reason: "startVless-success")
                result(nil)
                return
            } catch {
                pluginLog.error("Failed to start VPN: \(error.localizedDescription, privacy: .public)")
                result(FlutterError(code: "VPN_ERROR",
                                    message: "Failed to start VPN: \(error.localizedDescription)",
                                    details: nil))
                stopTimer(reason: "startVless-error")
                return
            }
        }
    }

    private func requestPermission(result: @escaping FlutterResult) {
        Task {
            let isGranted = await packetTunnelManager?.testSaveAndLoadProfile() ?? false
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

    private func initializeVless(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let providerBundleIdentifier = arguments["providerBundleIdentifier"] as? String,
              let groupIdentifier = arguments["groupIdentifier"] as? String else {
            result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments for initializeVless.", details: nil))
            return
        }
        pluginLog.info("initializeVless providerBundleIdentifier=\(providerBundleIdentifier, privacy: .public) groupIdentifier=\(groupIdentifier, privacy: .public)")
        self.packetTunnelManager = PacketTunnelManager(providerBundleIdentifier: "\(providerBundleIdentifier).XrayTunnel", groupIdentifier: groupIdentifier)
        self.packetTunnelManager?.statusDidChange = { [weak self] status in
            guard let self else { return }
            switch status {
            case .connecting, .connected, .reasserting, .disconnecting:
                self.startTimer(reason: "vpn-status-\(status?.rawValue ?? -1)")
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

    /// Logs only transport-shape metadata, never credentials.
    ///
    /// The summary answers the first debugging question quickly: did the parser
    /// actually create `tcp/reality`, `xhttp/reality`, or `xhttp/none`, and did
    /// an XHTTP `extra` object survive URL decoding.
    private func describeConfig(_ data: Data) -> String {
        guard
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let inbounds = json["inbounds"] as? [[String: Any]],
            let outbounds = json["outbounds"] as? [[String: Any]]
        else {
            return "Config summary unavailable"
        }
        let inboundSummary = inbounds.compactMap { inbound -> String? in
            guard let proto = inbound["protocol"] as? String else { return nil }
            return "\(proto):\(inbound["port"] ?? "?")"
        }.joined(separator: ",")
        let outboundSummary = outbounds.enumerated().map { index, outbound -> String in
            let tag = outbound["tag"] as? String ?? "\(index)"
            let proto = outbound["protocol"] as? String ?? "?"
            let stream = outbound["streamSettings"] as? [String: Any]
            let network = stream?["network"] as? String ?? "?"
            let security = stream?["security"] as? String ?? "?"
            let hasXhttpExtra = ((stream?["xhttpSettings"] as? [String: Any])?["extra"] != nil)
            return "\(tag)/\(proto)/\(network)/\(security)/xhttpExtra=\(hasXhttpExtra)"
        }.joined(separator: ",")
        return "Config summary inbounds=[\(inboundSummary)] outbounds=[\(outboundSummary)]"
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
        throw error ?? NSError(
            domain: "FlutterVless",
            code: 13,
            userInfo: [NSLocalizedDescriptionKey: "Failed to configure Xray geo asset directory"]
        )
    }
    if let directory {
        pluginLog.info("Configured Xray geo asset directory: \(directory, privacy: .public)")
    } else {
        pluginLog.info("Using Xray default geo asset lookup")
    }
}

final class PacketTunnelManager: ObservableObject {
    var providerBundleIdentifier: String?
    var groupIdentifier: String?
    var remark: String = "Xray"
    var xrayConfig: Data = "".data(using: .utf8)!
    var bypassSubnets: [String] = []
    var proxyOnly: Bool = false
    var geoAssetsDirectory: String?
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
        pluginLog.info("Reloaded tunnel manager: \(self.manager != nil, privacy: .public)")
        statusDidChange?(self.status)
        NotificationCenter.default
            .publisher(for: .NEVPNConfigurationChange, object: nil)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                pluginLog.info("NEVPNConfigurationChange received")
                Task(priority: .high) {
                    self.manager = await self.loadTunnelProviderManager()
                    await MainActor.run {
                        self.statusDidChange?(self.status)
                    }
                }
            }
            .store(in: &cancellables)
        NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                pluginLog.info("NEVPNStatusDidChange status=\(self.status?.rawValue ?? -1, privacy: .public)")
                self.statusDidChange?(self.status)
                objectWillChange.send()
            }
            .store(in: &cancellables)
    }

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
                var providerConfiguration: [String: Any] = [
                    "xrayConfig": self.xrayConfig,
                    "bypassSubnets": self.bypassSubnets,
                    "proxyOnly": self.proxyOnly,
                    "groupIdentifier": self.groupIdentifier ?? ""
                ]
                if let geoAssetsDirectory = self.geoAssetsDirectory {
                    providerConfiguration["geoAssetsDirectory"] = geoAssetsDirectory
                }
                configuration.providerConfiguration = providerConfiguration
                if #available(iOS 14.2, *) {
                    configuration.excludeLocalNetworks = true
                } else {
                    // Fallback on earlier versions
                }
                return configuration
            }()
            manager.isEnabled = true
            pluginLog.info("Saving VPN preferences provider=\(providerBundleIdentifier, privacy: .public) configBytes=\(self.xrayConfig.count, privacy: .public) bypassCount=\(self.bypassSubnets.count, privacy: .public) proxyOnly=\(self.proxyOnly, privacy: .public)")
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            pluginLog.info("VPN preferences saved and reloaded")
        } catch {
            pluginLog.error("Error saving VPN preferences: \(error.localizedDescription, privacy: .public)")
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

    func start() async throws {
        guard let manager = manager else {
            throw NSError(domain: "VPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not found"])
        }

        if !manager.isEnabled {
            manager.isEnabled = true
            try await manager.saveToPreferences()
        }

        do {
            pluginLog.info("Calling startVPNTunnel currentStatus=\(manager.connection.status.rawValue, privacy: .public)")
            try  manager.connection.startVPNTunnel()
            pluginLog.info("startVPNTunnel returned currentStatus=\(manager.connection.status.rawValue, privacy: .public)")
        } catch {
            pluginLog.error("Failed to start VPN tunnel: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    func stop() {
        guard let manager = manager else {
            return
        }
        pluginLog.info("Calling stopVPNTunnel currentStatus=\(manager.connection.status.rawValue, privacy: .public)")
        manager.connection.stopVPNTunnel()
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

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    continuation.resume(with: .success(response))
                }
            } catch {
                continuation.resume(with: .failure(error))
            }
        }
    }

    func testSaveAndLoadProfile() async -> Bool{
        do {
            try await saveToPreferences()

            // Now reload the manager after saving
            let _ = await loadTunnelProviderManager()
            pluginLog.info("testSaveAndLoadProfile succeeded")
            return true

        } catch {
            pluginLog.error("Error during save and load test: \(error.localizedDescription, privacy: .public)")
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
        let providerURL = containerURL.appendingPathComponent("flutter_vless_tunnel_debug.log")
        let hevURL = containerURL.appendingPathComponent("hev-socks5-tunnel.log")
        var sections: [String] = []

        if let provider = boundedFileTail(at: providerURL, maxLines: 200) {
            sections.append(provider.content)
        }
        if let hev = boundedFileTail(at: hevURL, maxLines: 80) {
            sections.append("--- HEV persisted log tail bytes=\(hev.size) ---\n\(hev.content)")
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


    private func loadTunnelProviderManager() async -> NETunnelProviderManager? {
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
            pluginLog.error("Error loading tunnel provider manager: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }
}
