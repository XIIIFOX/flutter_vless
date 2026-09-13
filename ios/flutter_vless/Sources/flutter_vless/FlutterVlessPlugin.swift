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
            let credentials = try LocalProxyCredentials.generate()
            let delayConfig = try Self.buildDelayConfigData(config: config, proxyPort: proxyPort, credentials: credentials)

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

            isRunning = true
            delayEndpoint = endpoint
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
        case "getSecurityCapabilities":
            result(["iosKeychainReference": true, "androidProxyDns": false])
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
                    let delay = await self.proxyOnlyRunner.measureConnectedDelay(url: url)
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
        do {
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
                pluginLog.error("Failed to start runtime: \(NativeLogPrivacy.operationError(error).localizedDescription, privacy: .public)")
                result(FlutterError(code: error is TunnelSecretError ? "VPN_KEYCHAIN_ERROR" : (proxyOnly ? "PROXY_ONLY_ERROR" : "VPN_ERROR"),
                    message: error is TunnelSecretError ? error.localizedDescription : NativeLogPrivacy.operationError(error).localizedDescription,
                    details: nil))
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
        let keychainAccessGroup = arguments["keychainAccessGroup"] as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "FlutterVlessKeychainAccessGroup") as? String
        self.packetTunnelManager = PacketTunnelManager(providerBundleIdentifier: "\(providerBundleIdentifier).XrayTunnel",
            groupIdentifier: groupIdentifier, keychainAccessGroup: keychainAccessGroup)
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
        guard bypassSubnets.isEmpty else {
            throw NSError(domain: "VPN", code: 2, userInfo: [NSLocalizedDescriptionKey:
                "System route exclusions are incompatible with iOS traffic protection"])
        }
    }

    private func secretStore(accessGroup: String? = nil) throws -> TunnelSecretStore {
        try TunnelSecretStore(accessGroup: accessGroup ?? keychainAccessGroup,
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
        if #available(iOS 16.4, *) {
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
}
