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
#if canImport(flutter_vless_privacy)
import flutter_vless_privacy
#endif

private let pluginLog = NativePrivacyLogger(
    subsystem: Bundle.main.bundleIdentifier ?? "flutter_vless.Runner",
    category: "FlutterVlessPlugin"
)

private final class PluginXRayLogger: NSObject, XRayLoggerProtocol {
    private let store = BoundedNativeLogStore()

    func logInput(_ s: String?) {
        if let message = s {
            let event = NativeLogPrivacy.runtimeEvent(message)
            store.append(source: "xray", message: event.text)
            pluginLog.info(event)
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
            let started = XRayStartPrivate(delayConfig, logger, &startError)
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
            pluginLog.error("Server delay probe failed: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
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

        guard XrayPrivacyConfig.apply(to: &json) else {
            throw NSError(domain: "FlutterVless", code: 13, userInfo: [NSLocalizedDescriptionKey: "Invalid private Xray configuration"])
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

        logger.reset()
        do {
            let preparedConfig = try Self.buildProxyOnlyConfigData(configData: configData)
            XRaySetMemoryLimit()
            try configureXrayAssetLocation(geoAssetsDirectory)
            var startError: NSError?
            let started = XRayStartPrivate(preparedConfig, logger, &startError)
            guard started else {
                throw startError ?? NSError(domain: "FlutterVless", code: 10, userInfo: [NSLocalizedDescriptionKey: "Failed to start XRay proxy-only mode"])
            }

            isRunning = true
            connectedDate = Date()
            pluginLog.info("Started XRay proxy-only mode configBytes=\(preparedConfig.count, privacy: .public)")
        } catch {
            logger.record(source: "runtime", message: "Proxy-only start failed: \(NativeLogPrivacy.operationError(error).localizedDescription)")
            throw NativeLogPrivacy.operationError(error)
        }
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
            pluginLog.error("Proxy-only connected delay failed: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
            return -1
        }
        return delay
    }

    func debugSnapshot() -> String {
        logger.snapshot()
    }

    func clearDiagnostics() {
        logger.reset()
    }

    private static func buildProxyOnlyConfigData(configData: Data) throws -> Data {
        guard var json = try JSONSerialization.jsonObject(with: configData, options: []) as? [String: Any] else {
            throw NSError(domain: "FlutterVless", code: 11, userInfo: [NSLocalizedDescriptionKey: "Invalid XRay config JSON"])
        }

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

        return try JSONSerialization.data(withJSONObject: json, options: [])
    }
}

public class FlutterVlessPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private var packetTunnelManager: PacketTunnelManager? = nil
    private let serverDelayRunner = ServerDelayRunner()
    private let proxyOnlyRunner = ProxyOnlyRunner()
    private let commands = NativeOperationQueue()

    private var timer: Timer?
    private var eventSink: FlutterEventSink?
    private var totalUpload: Int = 0
    private var totalDownload: Int = 0
    private var uploadSpeed: Int = 0
    private var downloadSpeed: Int = 0
    private var lastTrafficLogDate: Date = .distantPast

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

    /// Polls traffic counters. Diagnostics are read only on explicit request.
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
            guard self.packetTunnelManager?.status == .connected
                    || self.packetTunnelManager?.status == .reasserting else {
                return
            }

            Task{
                do{
                    await self.packetTunnelManager?.refreshForwardingState()
                    self.emitStatus(duration: seconds, state: self.currentRuntimeState(), reason: "provider-readiness")
                    guard self.currentRuntimeState() == "CONNECTED" else { return }
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
                            }
                        }
                    }
                }catch{
                    pluginLog.error("Error polling traffic: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
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
    }

    private func currentDurationSeconds() -> Int {
        if proxyOnlyRunner.isRunning {
            return Int(Date().timeIntervalSince(proxyOnlyRunner.connectedDate ?? Date()))
        }
        return Int(Date().timeIntervalSince(packetTunnelManager?.connectedDate ?? Date()))
    }

    private func refreshRuntimePolling(reason: String) {
        if currentRuntimeState() == "DISCONNECTED" {
            stopTimer(reason: reason)
        } else {
            startTimer(reason: reason)
        }
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
            return packetTunnelManager?.isRecoveryEnabled == true ? "CONNECTING" : "DISCONNECTED"
        case .connecting, .reasserting:
            return "CONNECTING"
        case .connected:
            return packetTunnelManager?.isRecoveryEnabled == true
                && packetTunnelManager?.forwardingReady != true ? "CONNECTING" : "CONNECTED"
        case .disconnecting:
            return packetTunnelManager?.isRecoveryEnabled == true ? "CONNECTING" : "DISCONNECTING"
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
                    let delay = self.proxyOnlyRunner.measureConnectedDelay(url: url)
                    result(Int(delay))
                    return
                }
                let delay = try await packetTunnelManager?.sendProviderMessage(data: "xray_delay\(url)".data(using: .utf8)!) ?? "-1".data(using: .utf8)!
                pluginLog.info("Connected delay response: \(String(decoding: delay, as: UTF8.self), privacy: .public)")
                result(Int(String(decoding: delay, as: UTF8.self)))
            }catch{
                pluginLog.error("Connected delay failed: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
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
            let proxySnapshot = proxyOnlyRunner.debugSnapshot()
            if !proxySnapshot.isEmpty {
                result(boundedNativeDiagnosticsSnapshot(
                    "--- iOS app-process Xray diagnostics ---\n\(proxySnapshot)"
                ))
                return
            }
            do {
                guard let response = try await packetTunnelManager?.sendProviderMessage(data: NativeLogPrivacy.snapshotCommand.data(using: .utf8)!) else {
                    result(boundedNativeDiagnosticsSnapshot(
                        packetTunnelManager?.sharedProviderDebugSnapshot() ?? ""
                    ))
                    return
                }
                result(boundedNativeDiagnosticsSnapshot(
                    String(decoding: response, as: UTF8.self)
                ))
            } catch {
                pluginLog.error("Provider debug snapshot request failed: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
                let persisted = packetTunnelManager?.sharedProviderDebugSnapshot() ?? ""
                result(boundedNativeDiagnosticsSnapshot(persisted))
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
        let bypassArgument = arguments["bypass_subnets"]
        let bypassSubnets = bypassArgument as? [String]
        let hasBypassArgument = bypassArgument != nil && !(bypassArgument is NSNull)
        let geoAssetsDirectory = arguments["geo_assets_directory"] as? String
        guard proxyOnly || !hasBypassArgument || bypassSubnets?.isEmpty == true else {
            result(FlutterError(code: "INCOMPATIBLE_ROUTING",
                message: "iOS VPN requires traffic protection and cannot exclude system routes. Use Xray direct routing rules.", details: nil))
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
                pluginLog.error("Failed to start runtime: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
                result(FlutterError(code: proxyOnly ? "PROXY_ONLY_ERROR" : "VPN_ERROR",
                    message: NativeLogPrivacy.operationError(error).localizedDescription, details: nil))
                self.refreshRuntimePolling(reason: "startVless-error")
            }
        }
    }

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
                if self.packetTunnelManager?.isRecoveryEnabled == true {
                    self.startTimer(reason: "vpn-recovery")
                } else if !self.proxyOnlyRunner.isRunning {
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

final class PacketTunnelManager: ObservableObject {
    var providerBundleIdentifier: String?
    var groupIdentifier: String?
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
        do { self.manager = try await self.loadTunnelProviderManager() } catch { /* Retain the last known policy. */ }
        pluginLog.info("Reloaded tunnel manager: \(self.manager != nil, privacy: .public)")
        statusDidChange?(self.status)
        NotificationCenter.default
            .publisher(for: .NEVPNConfigurationChange, object: nil)
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                pluginLog.info("NEVPNConfigurationChange received")
                Task(priority: .high) {
                    do { self.manager = try await self.loadTunnelProviderManager() } catch { /* Retain the last known policy. */ }
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
                if self.status != .connected { self.forwardingReady = false }
                pluginLog.info("NEVPNStatusDidChange status=\(self.status?.rawValue ?? -1, privacy: .public)")
                self.statusDidChange?(self.status)
                objectWillChange.send()
            }
            .store(in: &cancellables)
    }

    /// Saves an inactive profile for permission/configuration setup.
    func saveToPreferences() async throws {
        try await saveConfiguration(activate: false)
    }

    private func validateRouting() throws {
        guard bypassSubnets.isEmpty else {
            throw NSError(domain: "VPN", code: 2, userInfo: [NSLocalizedDescriptionKey:
                "System route exclusions are incompatible with iOS traffic protection"])
        }
    }

    private func saveConfiguration(activate: Bool) async throws {
        guard let providerBundleIdentifier else {
            throw NSError(domain: "VPN", code: 1, userInfo: nil)
        }
        try validateRouting()
        let manager = try await loadTunnelProviderManager() ?? NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerBundleIdentifier
        configuration.serverAddress = "Xray"
        var providerConfiguration: [String: Any] = [
            "xrayConfig": xrayConfig,
            "bypassSubnets": bypassSubnets,
            "proxyOnly": proxyOnly,
            "groupIdentifier": groupIdentifier ?? ""
        ]
        if let geoAssetsDirectory {
            providerConfiguration["geoAssetsDirectory"] = geoAssetsDirectory
        }
        configuration.providerConfiguration = providerConfiguration
        configuration.includeAllNetworks = true
        configuration.excludeLocalNetworks = false
        configuration.disconnectOnSleep = false
        if #available(iOS 16.4, *) {
            configuration.excludeAPNs = false
            configuration.excludeCellularServices = false
        }
        manager.protocolConfiguration = configuration
        manager.localizedDescription = remark
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
        try await manager.saveToPreferences()
        // The policy is already persisted even if refreshing the SDK object fails.
        self.manager = manager
        try await manager.loadFromPreferences()
        self.manager = manager
        pluginLog.info("VPN preferences saved active=\(activate, privacy: .public)")
    }

    func removeFromPreferences() async throws {
        guard let manager = try await loadTunnelProviderManager() else { return }
        try await manager.removeFromPreferences()
        self.manager = nil
    }

    func start() async throws {
        try validateRouting()
        forwardingReady = false
        try await saveConfiguration(activate: true)
        guard let manager else {
            throw NSError(domain: "VPN", code: 1, userInfo: nil)
        }
        // On-demand may already have started the same tunnel after the save.
        switch manager.connection.status {
        case .connecting, .connected, .reasserting:
            return
        default:
            try manager.connection.startVPNTunnel()
        }
    }

    func stop(waitForDisconnect: Bool = false) async throws {
        guard let manager = try await loadTunnelProviderManager() else {
            self.manager = nil
            return
        }
        // Persist disarming before requesting stop; otherwise on-demand can
        // immediately reconnect after an explicit user disconnect.
        manager.isOnDemandEnabled = false
        manager.onDemandRules = nil
        manager.isEnabled = false
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        self.manager = manager
        manager.connection.stopVPNTunnel()
        if waitForDisconnect {
            // Proxy-only may reuse the extension's listening ports. Wait for
            // native teardown before starting the app-process Xray instance.
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

    func testSaveAndLoadProfile() async -> Bool{
        do {
            if let existing = try await loadTunnelProviderManager() {
                self.manager = existing
                return true
            }
            try await saveToPreferences()

            // Now reload the manager after saving
            let _ = try await loadTunnelProviderManager()
            pluginLog.info("testSaveAndLoadProfile succeeded")
            return true

        } catch {
            pluginLog.error("Error during save and load test: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
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
        let hevURL = containerURL.appendingPathComponent("hev-socks5-tunnel.log")
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
}
