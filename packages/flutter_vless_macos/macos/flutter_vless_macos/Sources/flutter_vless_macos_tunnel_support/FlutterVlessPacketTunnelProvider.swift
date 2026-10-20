//
//  PacketTunnelProvider.swift
//  XrayTunnel
//
//  Created by Vladimir Khudiakov on 17.08.2025. https://tfox.dev.
//

import NetworkExtension
import flutter_vless_macos_privacy
import Network
import CXRay
import flutter_vless_macos_core_compat
import Tun2SocksKitC
import HevSocks5Tunnel
import Tun2SocksKit
import flutter_vless_macos_privacy
import os
import Darwin

private let tunnelLog = NativePrivacyLogger(
    subsystem: Bundle.main.bundleIdentifier ?? "flutter_vless.XrayTunnel",
    category: "PacketTunnel"
)
private let tunnelMTU = 1500
private let dnsServers = [TunnelDNSPolicy.virtualServer]
private let hevStartupGraceSeconds: TimeInterval = 0.25
private let hevShutdownTimeoutSeconds: TimeInterval = 2
private let watchdogIntervalSeconds: TimeInterval = 60

/// macOS runs this extension in a separate process from the Flutter app, and the
/// Runner console does not reliably show extension stdout. Keeping a small
/// in-memory ring buffer lets the app ask the provider for the exact startup
/// and health-check evidence that matters on a real device.
private final class TunnelDebugStore {
    static let shared = TunnelDebugStore()
    private let lock = NSLock()
    private var lines: [String] = []
    private var options = try! VlessNativeOptions()
    private var group: String?
    private var fileURL: URL?

    func configure(groupIdentifier: String?, options: VlessNativeOptions) {
        lock.lock(); defer { lock.unlock() }
        self.options = options; self.group = groupIdentifier
        lines.removeAll()
        guard let groupIdentifier, !groupIdentifier.isEmpty,
              let directory = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier) else { fileURL = nil; return }
        NativeLogPrivacy.removeLegacyProviderLog(in: directory)
        fileURL = directory.appendingPathComponent(NativeLogPrivacy.providerLogFilename)
        if !options.diagnosticsEnabled, let fileURL { try? FileManager.default.removeItem(at: fileURL) }
    }

    private func currentOptions() -> VlessNativeOptions {
        group.flatMap { VlessSystemControl.options(group: $0) } ?? options
    }

    func append(_ message: NativeDiagnosticMessage) {
        lock.lock(); defer { lock.unlock() }
        let options = currentOptions()
        guard options.diagnosticsEnabled else {
            lines.removeAll(); if let fileURL { try? FileManager.default.removeItem(at: fileURL) }; return
        }
        lines.append("\(ISO8601DateFormatter().string(from: Date())) \(message.text)")
        while !lines.isEmpty && (lines.count > options.diagnosticsMaxLines || lines.reduce(0, { $0 + $1.utf8.count + 1 }) > options.diagnosticsMaxBytes) { lines.removeFirst() }
        if let fileURL { try? lines.joined(separator: "\n").write(to: fileURL, atomically: true, encoding: .utf8) }
    }

    func snapshot() -> String {
        lock.lock(); defer { lock.unlock() }
        let options = currentOptions()
        guard options.diagnosticsEnabled else { return "" }
        return lines.suffix(options.diagnosticsMaxLines).joined(separator: "\n")
    }

    func logDirectoryURL() -> URL? {
        lock.lock()
        defer { lock.unlock() }
        return fileURL?.deletingLastPathComponent()
    }
}

private func rememberTunnelLog(_ message: NativeDiagnosticMessage) {
    TunnelDebugStore.shared.append(message)
}

open class FlutterVlessPacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = CustomXRayLogger()
    private let hevLifecycle = TunnelProcessLifecycle()
    private let watchdogQueue = DispatchQueue(label: "dev.tfox.flutter-vless.macos-watchdog", qos: .utility)
    private var lastTrafficLogDate: Date = .distantPast
    private var hevLogURL: URL?
    private var watchdogTimer: DispatchSourceTimer?
    private var pathMonitor: NWPathMonitor?
    private var watchdogPolicy = TunnelWatchdogFailurePolicy(failureThreshold: 3)
    private var watchdogSuspended = false
    private var watchdogInboundPort: Int?
    private var recoveryCheck: DispatchWorkItem?
    private let sessionAdmission = TunnelSessionAdmission()
    private var watchdogInboundHealthy = false
    private let runtimeQueue = DispatchQueue(label: "dev.tfox.flutter-vless.macos-runtime")
    private let forwardingLock = NSLock()
    private var forwardingReady = false
    private var startupPreparation: (epoch: TunnelSessionAdmission.Epoch, task: Task<TunnelPreparedConfig, Error>)?
    private var forwardingEpoch: TunnelSessionAdmission.Epoch?
    private var runtimeSpec: RuntimeSpec?
    private var runtimeRecoveryInFlight = false
    private var nativeOptions = try! VlessNativeOptions()
    private var recoveryFailures = 0
    private var recoveryExhausted = false
    private var initialRuntimeAttempted = false
    // Accessed only on runtimeQueue.
    private var hasStartedHEV = false
    private var hevStopSignal: DispatchGroup?
    private var nativeRuntimeEpoch: TunnelSessionAdmission.Epoch?
    private var packetBridge: TunnelPacketBridge?
    private var packetBridgeEpoch: TunnelSessionAdmission.Epoch?

    private struct RuntimeSpec {
        let epoch: TunnelSessionAdmission.Epoch
        let options: VlessNativeOptions
        let config: Data
        let port: Int
        let geoAssetsDirectory: String?
        let credentials: LocalProxyCredentials
        let routingMetadata: Data?

        init(epoch: TunnelSessionAdmission.Epoch, options: VlessNativeOptions, config: Data, port: Int,
             geoAssetsDirectory: String?, credentials: LocalProxyCredentials, routingMetadata: Data? = nil) {
            self.epoch = epoch; self.options = options; self.config = config; self.port = port
            self.geoAssetsDirectory = geoAssetsDirectory; self.credentials = credentials
            self.routingMetadata = routingMetadata
        }
    }

    private func setForwardingReady(_ ready: Bool, epoch: TunnelSessionAdmission.Epoch) {
        forwardingLock.lock()
        defer { forwardingLock.unlock() }
        guard sessionAdmission.isCurrent(epoch) else { return }
        forwardingEpoch = epoch
        forwardingReady = ready
        reasserting = !ready
    }

    private func isForwardingReady() -> Bool {
        forwardingLock.lock()
        defer { forwardingLock.unlock() }
        guard let epoch = forwardingEpoch, sessionAdmission.isCurrent(epoch) else { return false }
        return forwardingReady && hevLifecycle.isRunning
    }

    open override func startTunnel(options: [String : NSObject]? = nil) async throws {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol else {
            throw tunnelError("Missing tunnel provider configuration")
        }
        let providerConfiguration = configuration.providerConfiguration ?? [:]
        // An old system profile cannot provide the required OS routing policy.
        // Restart from the host app to save the current protected configuration.
        guard configuration.includeAllNetworks && !configuration.excludeLocalNetworks else {
            throw tunnelError("VPN profile requires traffic protection; reconnect from the app")
        }
        if #available(macOS 13.3, *), configuration.excludeAPNs || configuration.excludeCellularServices {
            throw tunnelError("VPN profile has unsupported service exclusions; reconnect from the app")
        }
        let bypassSubnets = providerConfiguration["bypassSubnets"] as? [String] ?? []
        let storedConfig = try TunnelSecretProfile.load(providerConfiguration,
            providerBundleIdentifier: configuration.providerBundleIdentifier ?? "")
        let config = try DesktopBypassPolicy.apply(to: storedConfig, cidrs: bypassSubnets)
        let routingIntent = try NativeRoutingIntent.parse(providerConfiguration["vpnRouting"])
        if routingIntent != nil { try NativeRoutingSpec.requireRuntime(FLVlessCoreRoutingCapability()) }
        try NativeRoutingSpec.validateSource(storedConfig, intent: routingIntent)
        let options = try VlessNativeOptions(providerConfiguration["options"] as? [String: Any])
        TunnelDebugStore.shared.configure(groupIdentifier: providerConfiguration["groupIdentifier"] as? String, options: options)
        let epoch = sessionAdmission.begin()
        setForwardingReady(false, epoch: epoch)
        rememberTunnelLog("Starting Xray packet tunnel")
        // A system-initiated Connect after a manual Stop must rearm crash
        // recovery even when the containing application is not running.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            TunnelOnDemandPolicy.enableForStart(configuration: configuration,
                isCancelled: { !self.sessionAdmission.isCurrent(epoch) }) { result in
                switch result {
                case .success:
                    rememberTunnelLog("On-demand recovery policy applied: enabled=\(options.enableOnDemand)")
                    continuation.resume()
                case .failure:
                    rememberTunnelLog("Unable to arm on-demand recovery for tunnel session")
                    continuation.resume(throwing: self.tunnelError("Unable to enable VPN recovery; reconnect from the app"))
                }
            }
        }
        guard sessionAdmission.isCurrent(epoch) else { throw CancellationError() }
        // Endpoint bootstrap precedes virtual DNS installation. Reuse the
        // prepared endpoints when restarting workers within this same tunnel.
        let credentials = try LocalProxyCredentials.generate()
        let preparation = Task {
            try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: config, credentials: credentials, routingIntent: routingIntent,
                tcpPortAvailable: LocalProxyAccessPolicy.isTCPPortAvailable,
                resolveIPv4: {
                    rememberTunnelLog("Resolving VPN transport endpoint")
                    return try await TunnelEndpointResolver.resolveIPv4($0, event: rememberTunnelLog)
                })
        }
        setStartupPreparation(preparation, epoch: epoch)
        defer { setStartupPreparation(nil, epoch: epoch) }
        let prepared: TunnelPreparedConfig
        do { prepared = try await preparation.value }
        catch {
            if error is CancellationError || !sessionAdmission.isCurrent(epoch) { throw CancellationError() }
            switch error {
            case TunnelXrayConfigPreparer.StartupError.endpointUnavailable:
                rememberTunnelLog("Tunnel endpoint DNS unavailable before route installation")
                throw tunnelError("Unable to resolve VPN transport endpoint")
            case TunnelXrayConfigPreparer.StartupError.invalidConfiguration:
                rememberTunnelLog("Tunnel configuration rejected before route installation")
                throw tunnelError("Unable to prepare tunnel configuration")
            default: break
            }
            rememberTunnelLog("Tunnel preparation failed before route installation")
            throw tunnelError("Unable to prepare tunnel configuration or resolve its endpoint")
        }
        guard sessionAdmission.isCurrent(epoch), !preparation.isCancelled,
              let parsed = parseConfig(jsonData: prepared.data),
              TunnelDNSPolicy.allowsRouteExclusions(prepared.bootstrapAddresses.map { "\($0)/32" }) else {
            throw tunnelError("Tunnel preparation cancelled or incompatible")
        }
        let addresses = prepared.bootstrapAddresses
        guard (routingIntent == nil) == (prepared.routingEnvelope == nil) else {
            throw NativeRoutingSpecError.invalidIntent
        }

        // Native Control Center/On Demand starts bypass the app entry point.
        // Check the final generated document before installing protected routes.
        if prepared.routingEnvelope != nil || FLVlessHasCorePreflight() {
            var assetError: NSError?
            guard XRaySetAssetLocation(providerConfiguration["geoAssetsDirectory"] as? String ?? "", &assetError) else {
                throw tunnelError("Xray asset configuration failed before route installation")
            }
            if let envelope = prepared.routingEnvelope {
                try NativeRoutingSpec.check(envelope, capability: FLVlessCoreRoutingCapability, check: FLVlessCheckCoreRoutingPrivate)
            } else {
                try CorePreflightPolicy.validate(prepared.data, check: FLVlessCheckCorePrivate)
            }
            rememberTunnelLog("Core configuration checked before route installation")
        } else {
            rememberTunnelLog("Core preflight unavailable in legacy runtime")
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        settings.mtu = NSNumber(value: tunnelMTU)
        let ipv4 = NEIPv4Settings(addresses: ["10.0.85.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default(), NEIPv4Route(destinationAddress: TunnelDNSPolicy.virtualServer, subnetMask: "255.255.255.255")]
        ipv4.excludedRoutes = buildIPv4ExcludedRoutes(
            serverAddresses: addresses.filter { isIPv4Literal($0) }
        )
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = TunnelIPv6Policy.networkSettings(proxyAddresses: addresses)
        let dns = NEDNSSettings(servers: dnsServers)
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        guard sessionAdmission.isCurrent(epoch) else { throw CancellationError() }
        try await setTunnelNetworkSettings(settings)
        guard sessionAdmission.isCurrent(epoch), !preparation.isCancelled else { throw CancellationError() }
        rememberTunnelLog("Protected tunnel routes and virtual DNS installed")

        let spec = RuntimeSpec(epoch: epoch, options: options, config: prepared.routingEnvelope?.configurationData ?? prepared.data, port: parsed.inboundPort,
            geoAssetsDirectory: providerConfiguration["geoAssetsDirectory"] as? String, credentials: credentials,
            routingMetadata: prepared.routingEnvelope?.metadataData)
        guard startTunnelWatchdog(spec) else { throw CancellationError() }
        // NE connected only means the routes are installed. The plugin
        // queries forwarding readiness before publishing CONNECTED.
        watchdogQueue.async { self.scheduleNativeRecovery(after: 0, epoch: epoch) }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let stoppedEpoch = sessionAdmission.revoke()
        forwardingLock.lock()
        let preparation = startupPreparation?.epoch == stoppedEpoch ? startupPreparation?.task : nil
        if startupPreparation?.epoch == stoppedEpoch { startupPreparation = nil }
        if forwardingEpoch == stoppedEpoch || sessionAdmission.currentEpoch == nil {
            forwardingReady = false
            forwardingEpoch = nil
            reasserting = false
        }
        forwardingLock.unlock()
        preparation?.cancel()
        rememberTunnelLog("Stopping Xray packet tunnel, reason=\(reason.rawValue)")
        stopTunnelWatchdog(epoch: stoppedEpoch)
        let teardown = DispatchGroup()
        teardown.enter()
        if let configuration = protocolConfiguration as? NETunnelProviderProtocol {
            TunnelOnDemandPolicy.disableForUserStop(reason: reason, configuration: configuration) { result in
                switch result {
                case .success(.preservedForRecovery):
                    rememberTunnelLog("System stop preserves on-demand recovery")
                case .success:
                    rememberTunnelLog("User stop: on-demand recovery disabled")
                case .failure:
                    rememberTunnelLog("User stop: unable to disable on-demand recovery; use Disconnect in the app")
                }
                teardown.leave()
            }
        } else {
            teardown.leave()
        }
        teardown.enter()
        runtimeQueue.async {
            guard stoppedEpoch != nil || self.sessionAdmission.currentEpoch == nil else {
                teardown.leave()
                return
            }
            if self.stopNativeRuntime(ownedBy: stoppedEpoch) {
                self.packetBridge?.shutdown()
                self.packetBridge = nil
                self.packetBridgeEpoch = nil
            }
            teardown.leave()
        }
        teardown.notify(queue: .main, execute: completionHandler)
    }

    private func setStartupPreparation(_ task: Task<TunnelPreparedConfig, Error>?, epoch: TunnelSessionAdmission.Epoch) {
        forwardingLock.lock()
        let current = sessionAdmission.isCurrent(epoch)
        if current {
            if let task { startupPreparation = (epoch, task) }
            else if startupPreparation?.epoch == epoch { startupPreparation = nil }
        }
        forwardingLock.unlock()
        if !current { task?.cancel() }
    }

    private func isStartupStopped() -> Bool { sessionAdmission.currentEpoch == nil }

    private func startNativeRuntime(_ spec: RuntimeSpec) throws {
        // Commit the attempt at the last pre-Core admission boundary, after
        // the old runtime drained. Sleep-cancelled work consumes no budget.
        let admitted = watchdogQueue.sync {
            guard sessionAdmission.permitsRuntime(spec.epoch), runtimeSpec?.epoch == spec.epoch,
                  !watchdogSuspended else { return false }
            let initial = !initialRuntimeAttempted
            guard initial || (!recoveryExhausted && nativeOptions.mayRetry(failures: recoveryFailures)) else { return false }
            if initial { initialRuntimeAttempted = true }
            else { recoveryFailures += 1 }
            return true
        }
        guard admitted else { throw CancellationError() }
        nativeRuntimeEpoch = spec.epoch
        try startXRay(xrayConfig: spec.config, geoAssetsDirectory: spec.geoAssetsDirectory, routingMetadata: spec.routingMetadata)
        guard sessionAdmission.permitsRuntime(spec.epoch) else { throw CancellationError() }
        try startSocks5Tunnel(serverPort: spec.port, credentials: spec.credentials, epoch: spec.epoch)
        guard sessionAdmission.permitsRuntime(spec.epoch) else { throw CancellationError() }
    }

    /// Runs on runtimeQueue. A blocked native quit must not stall NE teardown.
    private func stopNativeRuntime(ownedBy epoch: TunnelSessionAdmission.Epoch? = nil) -> Bool {
        // A delayed teardown from an old session cannot stop a newer runtime.
        if let epoch, let running = nativeRuntimeEpoch, running != epoch { return false }
        if let epoch, let bridgeEpoch = packetBridgeEpoch, bridgeEpoch != epoch { return false }
        packetBridge?.pause()
        var stopped = true
        if hasStartedHEV {
            requestHEVStop()
            stopped = hevLifecycle.waitForExit(timeout: hevShutdownTimeoutSeconds)
            if let signal = hevStopSignal,
               signal.wait(timeout: .now() + hevShutdownTimeoutSeconds) != .success {
                stopped = false
            }
        }
        stopXRay()
        if stopped { nativeRuntimeEpoch = nil }
        if !stopped { rememberTunnelLog("Native shutdown pending; protected traffic remains blocked") }
        return stopped
    }

    /// Runs on watchdogQueue. Keep the NE routes/DNS installed during recovery.
    private func scheduleNativeRecovery(after delay: TimeInterval, epoch: TunnelSessionAdmission.Epoch) {
        guard sessionAdmission.permitsRuntime(epoch), !watchdogSuspended, !runtimeRecoveryInFlight,
              let spec = runtimeSpec, spec.epoch == epoch else { return }
        let isInitialLaunch = !initialRuntimeAttempted
        guard isInitialLaunch || (!recoveryExhausted && nativeOptions.mayRetry(failures: recoveryFailures)) else {
            recoveryExhausted = true
            setForwardingReady(false, epoch: epoch)
            rememberTunnelLog("Native retry limit reached; protected traffic remains blocked")
            return
        }
        let retryDelay = isInitialLaunch ? 0 : nativeOptions.retryDelay(failures: recoveryFailures)
        runtimeRecoveryInFlight = true
        setForwardingReady(false, epoch: epoch)
        runtimeQueue.asyncAfter(deadline: .now() + max(delay, retryDelay)) {
            var started = false
            defer {
                let runtimeStarted = started
                self.watchdogQueue.async {
                    guard self.sessionAdmission.isCurrent(epoch), self.runtimeSpec?.epoch == epoch else { return }
                    self.runtimeRecoveryInFlight = false
                    guard self.sessionAdmission.permitsRuntime(epoch), !self.watchdogSuspended else { return }
                    self.watchdogPolicy.reset()
                    if runtimeStarted {
                        self.performTunnelHealthCheck(trigger: "native-restart", epoch: epoch)
                    } else {
                        self.scheduleNativeRecovery(after: 3, epoch: epoch)
                    }
                }
            }
            guard self.watchdogQueue.sync(execute: {
                self.sessionAdmission.permitsRuntime(epoch)
                    && self.runtimeSpec?.epoch == epoch && !self.watchdogSuspended
            }) else { return }
            if self.stopNativeRuntime() {
                // Stop can revoke this epoch while the native drain blocks.
                guard self.sessionAdmission.permitsRuntime(epoch) else { return }
                do {
                    try self.startNativeRuntime(spec)
                    started = true
                } catch is CancellationError {
                    _ = self.stopNativeRuntime(ownedBy: epoch)
                } catch {
                    rememberTunnelLog("Native restart failed; protected traffic remains blocked")
                    _ = self.stopNativeRuntime(ownedBy: epoch)
                }
            }
        }
    }

    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let message = String(data: messageData, encoding: .utf8) {
            if message == "xray_runtime_state" {
                completionHandler?(Data((isForwardingReady() ? "ready" : "recovering").utf8))
            } else if (message == "xray_traffic"){
                logTrafficStats(context: "poll")
                let stats = Socks5Tunnel.stats
                completionHandler?("\(stats.up.bytes),\(stats.down.bytes)".data(using: .utf8))
            } else if (message == "xray_debug" || message == NativeLogPrivacy.snapshotCommand) {
                // This bridge is intentionally part of the runtime API used by
                // smoke tests and manual Xcode runs. It is the fastest way to
                // compare TCP/Reality and XHTTP behavior without attaching LLDB
                // to the extension process separately.
                var snapshot = TunnelDebugStore.shared.snapshot()
                snapshot += "\nHEV diagnostic file bytes=\(hevLogSizeBytes()); raw contents omitted"
                completionHandler?(snapshot.data(using: .utf8))
            }else if (message.hasPrefix("xray_delay")){
                let rawURL = String(message.dropFirst(10))
                watchdogQueue.async {
                    guard self.isForwardingReady(), let spec = self.runtimeSpec,
                          let url = URL(string: rawURL) else {
                        completionHandler?(Data("-1".utf8))
                        return
                    }
                    LocalProxyDelayClient.measure(url: url, port: spec.port, credentials: spec.credentials) { delay in
                        completionHandler?(Data("\(delay)".utf8))
                    }
                }
            }
            else{
                tunnelLog.info("Echoing unknown provider message: \(message, privacy: .public)")
                completionHandler?(messageData)
            }

        }else{
            tunnelLog.warning("Received non-UTF8 provider message bytes=\(messageData.count, privacy: .public)")
            completionHandler?(messageData)
        }
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        rememberTunnelLog("Packet tunnel sleep; suspending watchdog")
        tunnelLog.info("Packet tunnel sleep")
        if let epoch = sessionAdmission.currentEpoch, sessionAdmission.suspend(epoch) {
            watchdogQueue.async {
                guard self.sessionAdmission.isCurrent(epoch), !self.sessionAdmission.permitsRuntime(epoch) else { return }
                self.watchdogSuspended = true
                self.watchdogPolicy.reset()
            }
        }
        completionHandler()
    }

    open override func wake() {
        rememberTunnelLog("Packet tunnel wake; scheduling health check")
        tunnelLog.info("Packet tunnel wake")
        // Admission follows callback entry order, independently of a blocked
        // watchdog queue. Queued work only mirrors the latest sleep/wake state.
        guard let epoch = sessionAdmission.currentEpoch, sessionAdmission.resume(epoch) else { return }
        watchdogQueue.async {
            guard self.sessionAdmission.permitsRuntime(epoch), self.runtimeSpec?.epoch == epoch else { return }
            self.watchdogSuspended = false
            self.watchdogPolicy.reset()
            self.scheduleTunnelHealthCheck(trigger: "wake", after: 1.5, epoch: epoch)
        }
    }

    private func requestHEVStop() {
        let shouldSignal = hevLifecycle.requestStop()
        // HEV 2.15 quit waits for its event descriptor. After run has returned
        // that descriptor is gone, so signalling an exited worker would hang.
        if shouldSignal {
            // The native worker may also exit between the state check and the
            // signal. Never let HEV's blocking quit stall NE's teardown callback.
            let signal = DispatchGroup()
            signal.enter()
            hevStopSignal = signal
            DispatchQueue.global(qos: .utility).async {
                defer { signal.leave() }
                if !self.hevLifecycle.waitForExit(timeout: 0) { Socks5Tunnel.quit() }
            }
        }
    }

    private func startSocks5Tunnel(serverPort port: Int, credentials: LocalProxyCredentials, epoch: TunnelSessionAdmission.Epoch) throws {
        guard sessionAdmission.permitsRuntime(epoch) else { throw CancellationError() }
        // HEV is the tun2socks bridge: it reads IP packets from NetworkExtension
        // and forwards them into the local SOCKS inbound opened by Xray.
        // Xray alone can start successfully while user traffic still cannot
        // leave the device; HEV logs close that gap during real-device tests.
        let logDirectory = TunnelDebugStore.shared.logDirectoryURL()
            ?? FileManager.default.temporaryDirectory
        try TunnelHEVLogPolicy.removeLegacyLogs(
            appGroupDirectory: TunnelDebugStore.shared.logDirectoryURL(),
            temporaryDirectory: FileManager.default.temporaryDirectory,
            workerStopped: !hasStartedHEV || hevLifecycle.waitForExit(timeout: 0)
        )
        let logURL = logDirectory.appendingPathComponent(TunnelHEVLogPolicy.filename)
        hevLogURL = logURL
        try? TunnelFileLog.trimIfNeeded(logURL)
        try? TunnelFileLog.append(
            "--- HEV session started \(ISO8601DateFormatter().string(from: Date())) ---",
            to: logURL,
            maxFileBytes: 512 * 1024,
            retainedBytes: 256 * 1024
        )
        let config = TunnelHEVConfiguration.make(port: port, credentials: credentials, mtu: tunnelMTU, logURL: logURL)
        rememberTunnelLog("Starting HEV socks5 tunnel on 127.0.0.1:\(port), log=\(logURL.path)")
        tunnelLog.info("Starting HEV socks5 tunnel on 127.0.0.1:\(port, privacy: .public), mtu \(tunnelMTU, privacy: .public)")
        let bridge: TunnelPacketBridge
        if let existing = packetBridge, packetBridgeEpoch == epoch {
            bridge = existing
        } else {
            packetBridge?.shutdown()
            bridge = try TunnelPacketBridge(flow: packetFlow, mtu: tunnelMTU) { [weak self] in
                self?.watchdogQueue.async { [weak self] in
                    guard let self, self.sessionAdmission.permitsRuntime(epoch), !self.watchdogSuspended else { return }
                    self.setForwardingReady(false, epoch: epoch)
                    rememberTunnelLog("Packet flow bridge failed; restarting protected native workers")
                    self.scheduleNativeRecovery(after: 0, epoch: epoch)
                }
            }
            packetBridge = bridge
            packetBridgeEpoch = epoch
        }
        bridge.start()
        rememberTunnelLog("Public packetFlow bridge ready for HEV")
        guard sessionAdmission.permitsRuntime(epoch) else { throw CancellationError() }
        hasStartedHEV = true
        hevLifecycle.beginStart()
        DispatchQueue.global(qos: .userInitiated).async {
            defer { withExtendedLifetime(bridge) {} }
            tunnelLog.info("HEV socks5 tunnel thread entered")
            self.hevLifecycle.markThreadEntered()
            guard self.sessionAdmission.permitsRuntime(epoch), !self.hevLifecycle.isStopRequested else {
                self.hevLifecycle.markExited(code: 0)
                return
            }
            let exitCode = config.withCString { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: config.utf8.count) {
                    hev_socks5_tunnel_main_from_str($0, UInt32(config.utf8.count), bridge.workerDescriptor)
                }
            }
            let exitedUnexpectedly = self.hevLifecycle.markExited(code: exitCode)
            rememberTunnelLog("HEV socks5 tunnel exited with code \(exitCode)")
            tunnelLog.error("HEV socks5 tunnel exited with code \(exitCode, privacy: .public)")
            NSLog("HEV_SOCKS5_TUNNEL_MAIN: \(exitCode)")
            if exitedUnexpectedly {
                self.reportTerminalFailure(
                    "HEV socks5 tunnel exited unexpectedly with code \(exitCode)",
                    code: Int(exitCode), epoch: epoch
                )
            }
        }

        switch hevLifecycle.waitForStableStartup(gracePeriod: hevStartupGraceSeconds) {
        case .running:
            rememberTunnelLog("HEV remained running through startup grace period")
        case .exited(let code):
            throw tunnelError("HEV exited during startup with code \(code)")
        case .timedOut:
            requestHEVStop()
            throw tunnelError("Timed out waiting for HEV startup")
        }
    }

    private func startXRay(xrayConfig: Data, geoAssetsDirectory: String?, routingMetadata: Data? = nil) throws {
        if routingMetadata != nil { try NativeRoutingSpec.requireRuntime(FLVlessCoreRoutingCapability()) }
        // This limits the Go runtime only. HEV session caps and bounded Swift/C
        // diagnostics below protect the rest of the extension memory budget.
        XRaySetMemoryLimit()

        // Create an error pointer
        var error: NSError?

        // This must cross the gomobile bridge: Swift setenv() is not visible to
        // Go's os.LookupEnv after the Go runtime has initialized on iOS.
        if geoAssetsDirectory?.isEmpty == true {
            throw tunnelError("Xray geo asset directory must not be empty")
        }
        guard XRaySetAssetLocation(geoAssetsDirectory ?? "", &error) else {
            rememberTunnelLog("Xray asset configuration failed")
            throw NativeLogPrivacy.operationError(error ?? tunnelError("Xray asset configuration failed"))
        }
        if let geoAssetsDirectory {
            rememberTunnelLog("Using Xray geo assets from \(geoAssetsDirectory)")
            tunnelLog.info("Using custom Xray geo asset directory: \(geoAssetsDirectory, privacy: .public)")
        } else {
            rememberTunnelLog("Using Xray default geo asset lookup")
        }

        // Start XRay with the config data
        tunnelLog.info("Starting XRay version=\(XRayGetVersion(), privacy: .public) configBytes=\(xrayConfig.count, privacy: .public)")
        let started: Bool
        if let routingMetadata {
            started = FLVlessStartCoreRoutingPrivate(xrayConfig, routingMetadata, logger, &error)
        } else {
            started = XRayStartPrivate(xrayConfig, logger, &error)
        }

        if started {
            rememberTunnelLog("XRay started successfully")
            tunnelLog.info("XRay started successfully")
        } else if let error = error {
            rememberTunnelLog("Failed to start XRay: \(error.localizedDescription)")
            tunnelLog.error("Failed to start XRay: \(error.localizedDescription, privacy: .public)")
            throw NativeLogPrivacy.operationError(error)
        } else {
            rememberTunnelLog("Failed to start XRay with unknown error")
            throw tunnelError("Failed to start XRay with unknown error")
        }
    }

    private func stopXRay() {
        XRayStop()
        tunnelLog.info("XRay stopped \(XRayGetVersion(), privacy: .public)")
    }

    private struct ParsedConfig {
        let inboundPort: Int
        let serverAddress: String?
    }

    private func parseConfig(jsonData: Data) -> ParsedConfig? {
        guard let parsed = TunnelXrayConfigPreparer.parseConfig(jsonData: jsonData) else {
            tunnelLog.error("Failed to parse tunnel Xray config")
            return nil
        }
        if let serverAddress = parsed.serverAddress {
            tunnelLog.info("Parsed outbound server address: \(serverAddress, privacy: .public)")
        } else {
            tunnelLog.warning("Could not parse outbound server address; VPN routing loop exclusion will be skipped")
        }
        return ParsedConfig(inboundPort: parsed.inboundPort, serverAddress: parsed.serverAddress)
    }

    private func buildIPv4ExcludedRoutes(serverAddresses: [String]) -> [NEIPv4Route] {
        let routes = serverAddresses.map {
            NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
        }
        return routes
    }

    private func startTunnelWatchdog(_ spec: RuntimeSpec) -> Bool {
        watchdogQueue.sync {
            guard sessionAdmission.activate(spec.epoch) else { return false }
            let epoch = spec.epoch
            runtimeSpec = spec
            nativeOptions = spec.options
            recoveryFailures = 0
            recoveryExhausted = false
            initialRuntimeAttempted = false
            runtimeRecoveryInFlight = false
            watchdogInboundPort = spec.port
            watchdogPolicy.reset()
            watchdogInboundHealthy = false
            watchdogSuspended = false

            watchdogTimer?.cancel()
            let timer = DispatchSource.makeTimerSource(queue: watchdogQueue)
            timer.schedule(
                deadline: .now() + 2,
                repeating: watchdogIntervalSeconds,
                leeway: .seconds(5)
            )
            timer.setEventHandler { [weak self] in
                self?.performTunnelHealthCheck(trigger: "periodic", epoch: epoch)
            }
            watchdogTimer = timer
            timer.resume()

            pathMonitor?.cancel()
            let monitor = NWPathMonitor()
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self, self.sessionAdmission.permitsRuntime(epoch) else { return }
                rememberTunnelLog("Network path changed status=\(String(describing: path.status))")
                if path.status == .satisfied {
                    self.watchdogPolicy.reset()
                    self.scheduleTunnelHealthCheck(trigger: "path-change", after: 2, epoch: epoch)
                }
            }
            pathMonitor = monitor
            monitor.start(queue: watchdogQueue)
            return sessionAdmission.isCurrent(epoch)
        }
    }

    private func stopTunnelWatchdog(epoch: TunnelSessionAdmission.Epoch?) {
        watchdogQueue.sync {
            if let current = runtimeSpec?.epoch, current != epoch { return }
            runtimeSpec = nil
            runtimeRecoveryInFlight = false
            recoveryCheck?.cancel()
            recoveryCheck = nil
            watchdogSuspended = true
            watchdogPolicy.reset()
            watchdogTimer?.cancel()
            watchdogTimer = nil
            pathMonitor?.cancel()
            pathMonitor = nil
            watchdogInboundPort = nil
        }
    }

    /// Must be called while already executing on `watchdogQueue`.
    private func scheduleTunnelHealthCheck(trigger: String, after delay: TimeInterval, epoch: TunnelSessionAdmission.Epoch) {
        watchdogQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard self?.sessionAdmission.permitsRuntime(epoch) == true else { return }
            self?.performTunnelHealthCheck(trigger: trigger, epoch: epoch)
        }
    }

    private func scheduleRecoveryCheck(epoch: TunnelSessionAdmission.Epoch) {
        guard sessionAdmission.permitsRuntime(epoch), recoveryCheck == nil else { return }
        let check = DispatchWorkItem { [weak self] in
            guard let self, self.sessionAdmission.isCurrent(epoch), self.runtimeSpec?.epoch == epoch else { return }
            // Sleep blocks runtime work but must release this session's slot
            // so a subsequent wake can schedule a fresh failed-health retry.
            self.recoveryCheck = nil
            guard self.sessionAdmission.permitsRuntime(epoch) else { return }
            self.performTunnelHealthCheck(trigger: "recovery", epoch: epoch)
        }
        recoveryCheck = check
        watchdogQueue.asyncAfter(deadline: .now() + 3, execute: check)
    }

    /// Checks both the HEV worker state and the Xray SOCKS-to-Internet path.
    /// Recovery keeps protected sessions scoped to the tunnel. A dead local
    /// runtime is restarted by the saved on-demand policy.
    @discardableResult
    private func performTunnelHealthCheck(trigger: String, epoch: TunnelSessionAdmission.Epoch) -> Bool {
        guard sessionAdmission.permitsRuntime(epoch), runtimeSpec?.epoch == epoch, !watchdogSuspended,
              !runtimeRecoveryInFlight,
              let port = watchdogInboundPort,
              let credentials = runtimeSpec?.credentials else {
            return false
        }
        guard !hevLifecycle.isStopRequested, hevLifecycle.isRunning else {
            setForwardingReady(false, epoch: epoch)
            scheduleNativeRecovery(after: 3, epoch: epoch)
            return false
        }

        // Share one deadline across every handshake, fragment and HTTP read.
        // Stop/sleep revoke admission directly, without waiting for this queue.
        let budget = LocalProxyIOBudget(timeout: 15, isCancelled: { [weak self] in
            self?.sessionAdmission.permitsRuntime(epoch) != true
        })
        let inboundResult = socksInboundHealthCheck(port: port, credentials: credentials, budget: budget)
        guard sessionAdmission.permitsRuntime(epoch) else { return false }
        watchdogInboundHealthy = inboundResult.hasPrefix("ok")
        let connectResult = budget.canContinue
            ? socksConnectHealthCheck(port: port, credentials: credentials, budget: budget)
            : "health deadline elapsed"
        guard sessionAdmission.permitsRuntime(epoch) else { return false }
        let httpResult = budget.canContinue
            ? socksHTTPHealthCheck(port: port, credentials: credentials, budget: budget)
            : "health deadline elapsed"
        guard sessionAdmission.permitsRuntime(epoch) else { return false }
        if let hevLogURL {
            try? TunnelFileLog.trimIfNeeded(hevLogURL)
        }
        let success = inboundResult.hasPrefix("ok")
            && connectResult.hasPrefix("ok")
            && httpResult.hasPrefix("ok")

        rememberTunnelLog(
            "Watchdog \(trigger): success=\(success) inbound=[\(inboundResult)] connect=[\(connectResult)] http=[\(httpResult)]"
        )
        guard sessionAdmission.permitsRuntime(epoch) else { return false }
        setForwardingReady(success, epoch: epoch)
        if success {
            recoveryFailures = 0
            tunnelLog.info("Tunnel watchdog \(trigger, privacy: .public) passed")
            recoveryCheck?.cancel()
            recoveryCheck = nil
            rememberTunnelLog("Protected tunnel forwarding restored")
        } else {
            tunnelLog.warning("Tunnel watchdog \(trigger, privacy: .public) failed")
            scheduleRecoveryCheck(epoch: epoch)
        }

        if watchdogPolicy.record(success: success) {
            reportTerminalFailure(
                "Tunnel watchdog failed \(watchdogPolicy.consecutiveFailures) consecutive checks",
                code: 2, epoch: epoch
            )
        }
        return success
    }

    private func reportTerminalFailure(_ message: NativeDiagnosticMessage, code: Int, epoch: TunnelSessionAdmission.Epoch) {
        watchdogQueue.async {
            self.handleRuntimeFailure(message, code: code, epoch: epoch)
        }
    }

    /// Runs on the watchdog queue; native recovery retains the tunnel routes.
    private func handleRuntimeFailure(_ message: NativeDiagnosticMessage, code: Int, epoch: TunnelSessionAdmission.Epoch) {
        guard sessionAdmission.permitsRuntime(epoch), runtimeSpec?.epoch == epoch, !watchdogSuspended else { return }
        setForwardingReady(false, epoch: epoch)
        if hevLifecycle.isRunning && watchdogInboundHealthy {
            rememberTunnelLog("Protected tunnel waiting for transport recovery")
            return
        }
        rememberTunnelLog("Restarting native workers inside the protected tunnel")
        scheduleNativeRecovery(after: 0, epoch: epoch)
    }

    private func socksInboundHealthCheck(port: Int, credentials: LocalProxyCredentials,
                                         budget: LocalProxyIOBudget) -> String {
        do {
            let fd = try LocalSOCKS5Client.openProxyConnection(proxyPort: port, credentials: credentials,
                                                              timeout: 2, budget: budget)
            close(fd)
            return "ok authenticated"
        } catch { return "authentication failed" }
    }

    private func socksConnectHealthCheck(port: Int, credentials: LocalProxyCredentials,
                                         budget: LocalProxyIOBudget) -> String {
        do {
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                                                        host: "1.1.1.1", port: 80, timeout: 5, budget: budget)
            close(fd)
            return "ok authenticated connect"
        } catch { return "authenticated connect failed" }
    }

    /// Requires authenticated CONNECT and a successful HTTP response from the proxy path.
    private func socksHTTPHealthCheck(port: Int, credentials: LocalProxyCredentials,
                                      budget: LocalProxyIOBudget) -> String {
        let httpBudget = budget.limited(to: 8)
        do {
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                                                        host: "www.gstatic.com", port: 80, budget: httpBudget)
            defer { close(fd) }
            let request = "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"
            guard LocalSOCKS5Client.sendAll(fd: fd, bytes: Array(request.utf8), budget: httpBudget),
                  let response = LocalSOCKS5Client.receiveSome(fd: fd, maxCount: 512, budget: httpBudget),
                  let status = String(bytes: response, encoding: .utf8)?.split(separator: " ").dropFirst().first,
                  let code = Int(status), (200...399).contains(code) else { return "HTTP response failed" }
            return "ok authenticated HTTP"
        } catch { return "authenticated HTTP connection failed" }
    }


    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    private func hevLogSizeBytes() -> UInt64 {
        guard let hevLogURL,
              let attributes = try? FileManager.default.attributesOfItem(atPath: hevLogURL.path),
              let size = attributes[.size] as? NSNumber else {
            return 0
        }
        return size.uint64Value
    }

    private func isIPv4Literal(_ address: String) -> Bool {
        var addr = in_addr()
        return address.withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }

    private func isIPv6Literal(_ address: String) -> Bool {
        var addr = in6_addr()
        return address.withCString { inet_pton(AF_INET6, $0, &addr) } == 1
    }

    private func tunnelError(_ message: NativeDiagnosticMessage) -> NSError {
        tunnelLog.error(message)
        return NSError(domain: "flutter_vless.packet_tunnel", code: 1, userInfo: [
            NSLocalizedDescriptionKey: message.text
        ])
    }

    private func logTrafficStats(context: String) {
        guard Date().timeIntervalSince(lastTrafficLogDate) >= 5 || context != "poll" else {
            return
        }
        lastTrafficLogDate = Date()
        let stats = Socks5Tunnel.stats
        rememberTunnelLog("Traffic \(context): upPackets=\(stats.up.packets) upBytes=\(stats.up.bytes) downPackets=\(stats.down.packets) downBytes=\(stats.down.bytes)")
        runtimeQueue.async {
            if let bridge = self.packetBridge?.statistics() {
                rememberTunnelLog("Packet bridge: upPackets=\(bridge.upPackets) downPackets=\(bridge.downPackets) backpressureWaits=\(bridge.backpressureWaits) queuedBytes=\(bridge.queuedBytes) peakQueuedBytes=\(bridge.peakQueuedBytes) receiveBufferBytes=\(bridge.receiveBufferBytes)")
            }
        }
        tunnelLog.info("Traffic stats context=\(context, privacy: .public) upPackets=\(stats.up.packets, privacy: .public) upBytes=\(stats.up.bytes, privacy: .public) downPackets=\(stats.down.packets, privacy: .public) downBytes=\(stats.down.bytes, privacy: .public)")
    }
}


class CustomXRayLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ s: String?) {
        if let logMessage = s {
            let event = NativeLogPrivacy.runtimeEvent(logMessage)
            TunnelDebugStore.shared.append(event)
            tunnelLog.info(event)
        }
    }
}
