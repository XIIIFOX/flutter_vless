//
//  PacketTunnelProvider.swift
//  XrayTunnel
//
//  Created by Vladimir Khudiakov on 17.08.2025. https://tfox.dev.
//

import NetworkExtension
import Network
import CXRay
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
    private let maxLines = 120
    private var fileURL: URL?

    func configure(groupIdentifier: String?) {
        lock.lock()
        defer { lock.unlock() }
        guard let groupIdentifier,
              !groupIdentifier.isEmpty,
              let containerURL = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: groupIdentifier
              ) else {
            fileURL = nil
            return
        }
        NativeLogPrivacy.removeLegacyProviderLog(in: containerURL)
        fileURL = containerURL.appendingPathComponent(NativeLogPrivacy.providerLogFilename)
    }

    func append(_ message: NativeDiagnosticMessage) {
        lock.lock()
        defer { lock.unlock() }
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "\(timestamp) \(message.text)"
        lines.append(line)
        if lines.count > maxLines {
            lines.removeFirst(lines.count - maxLines)
        }
        if let fileURL {
            try? TunnelFileLog.append(line, to: fileURL)
        }
    }

    func snapshot() -> String {
        lock.lock()
        defer { lock.unlock() }
        if let fileURL,
           let persisted = try? TunnelFileLog.tail(of: fileURL),
           !persisted.isEmpty {
            return persisted
        }
        return lines.joined(separator: "\n")
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
    private var watchdogGeneration = 0
    private var watchdogInboundHealthy = false
    private let runtimeQueue = DispatchQueue(label: "dev.tfox.flutter-vless.macos-runtime")
    private let forwardingLock = NSLock()
    private var forwardingReady = false
    private var startupPreparation: Task<TunnelPreparedConfig, Error>?
    private var startupStopped = false
    private var runtimeSpec: RuntimeSpec?
    private var runtimeRecoveryInFlight = false
    // Accessed only on runtimeQueue.
    private var hasStartedHEV = false
    private var hevStopSignal: DispatchGroup?

    private struct RuntimeSpec {
        let config: Data
        let port: Int
        let geoAssetsDirectory: String?
        let credentials: LocalProxyCredentials
    }

    private func setForwardingReady(_ ready: Bool) {
        forwardingLock.lock()
        forwardingReady = ready
        forwardingLock.unlock()
        reasserting = !ready
    }

    private func isForwardingReady() -> Bool {
        forwardingLock.lock()
        defer { forwardingLock.unlock() }
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
        TunnelDebugStore.shared.configure(groupIdentifier: providerConfiguration["groupIdentifier"] as? String)
        beginStartup()
        setForwardingReady(false)
        rememberTunnelLog("Starting Xray packet tunnel")
        // Endpoint bootstrap precedes virtual DNS installation. Reuse the
        // prepared endpoints when restarting workers within this same tunnel.
        let credentials = try LocalProxyCredentials.generate()
        let preparation = Task {
            try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: config, credentials: credentials,
                resolveIPv4: { resolveIPv4Addresses(for: $0).first })
        }
        setStartupPreparation(preparation)
        defer { setStartupPreparation(nil) }
        let prepared: TunnelPreparedConfig
        do { prepared = try await preparation.value }
        catch {
            rememberTunnelLog("Tunnel preparation failed before route installation")
            throw tunnelError("Unable to prepare tunnel configuration or resolve its endpoint")
        }
        guard !preparation.isCancelled,
              let parsed = parseConfig(jsonData: prepared.data),
              TunnelDNSPolicy.allowsRouteExclusions(prepared.bootstrapAddresses.map { "\($0)/32" }) else {
            throw tunnelError("Tunnel preparation cancelled or incompatible")
        }
        let addresses = prepared.bootstrapAddresses

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        settings.mtu = NSNumber(value: tunnelMTU)
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default(), NEIPv4Route(destinationAddress: TunnelDNSPolicy.virtualServer, subnetMask: "255.255.255.255")]
        ipv4.excludedRoutes = buildIPv4ExcludedRoutes(
            serverAddresses: addresses.filter { isIPv4Literal($0) }
        )
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = TunnelIPv6Policy.networkSettings(proxyAddresses: addresses)
        let dns = NEDNSSettings(servers: dnsServers)
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        try await setTunnelNetworkSettings(settings)
        guard !preparation.isCancelled else { throw CancellationError() }
        rememberTunnelLog("Protected tunnel routes and virtual DNS installed")

        runtimeSpec = RuntimeSpec(config: prepared.data, port: parsed.inboundPort,
            geoAssetsDirectory: providerConfiguration["geoAssetsDirectory"] as? String, credentials: credentials)
        startTunnelWatchdog(port: runtimeSpec?.port)
        // NE connected only means the routes are installed. The plugin
        // queries forwarding readiness before publishing CONNECTED.
        watchdogQueue.async { self.scheduleNativeRecovery(after: 0) }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        forwardingLock.lock()
        startupStopped = true
        startupPreparation?.cancel()
        forwardingLock.unlock()
        rememberTunnelLog("Stopping Xray packet tunnel, reason=\(reason.rawValue)")
        setForwardingReady(false)
        stopTunnelWatchdog()
        runtimeQueue.async {
            _ = self.stopNativeRuntime()
            completionHandler()
        }
    }

    private func setStartupPreparation(_ task: Task<TunnelPreparedConfig, Error>?) {
        forwardingLock.lock()
        if startupStopped { task?.cancel() }
        startupPreparation = task
        forwardingLock.unlock()
    }

    private func beginStartup() {
        forwardingLock.lock()
        startupStopped = false
        forwardingLock.unlock()
    }

    private func startNativeRuntime(_ spec: RuntimeSpec) throws {
        try startXRay(xrayConfig: spec.config, geoAssetsDirectory: spec.geoAssetsDirectory)
        try startSocks5Tunnel(serverPort: spec.port, credentials: spec.credentials)
    }

    /// Runs on runtimeQueue. A blocked native quit must not stall NE teardown.
    private func stopNativeRuntime() -> Bool {
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
        if !stopped { rememberTunnelLog("Native shutdown pending; protected traffic remains blocked") }
        return stopped
    }

    /// Runs on watchdogQueue. Keep the NE routes/DNS installed during recovery.
    private func scheduleNativeRecovery(after delay: TimeInterval) {
        guard !watchdogSuspended, !runtimeRecoveryInFlight,
              let spec = runtimeSpec else { return }
        runtimeRecoveryInFlight = true
        setForwardingReady(false)
        let generation = watchdogGeneration
        runtimeQueue.asyncAfter(deadline: .now() + delay) {
            guard self.watchdogQueue.sync(execute: {
                guard self.watchdogGeneration == generation else { return false }
                if self.watchdogSuspended {
                    self.runtimeRecoveryInFlight = false
                    return false
                }
                return true
            }) else { return }
            var started = false
            if self.stopNativeRuntime() {
                do {
                    try self.startNativeRuntime(spec)
                    started = true
                } catch {
                    rememberTunnelLog("Native restart failed; protected traffic remains blocked")
                    _ = self.stopNativeRuntime()
                }
            }
            let runtimeStarted = started
            self.watchdogQueue.async {
                guard self.watchdogGeneration == generation else { return }
                self.runtimeRecoveryInFlight = false
                guard !self.watchdogSuspended else { return }
                self.watchdogPolicy.reset()
                if runtimeStarted {
                    self.performTunnelHealthCheck(trigger: "native-restart")
                } else {
                    self.scheduleNativeRecovery(after: 3)
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
        watchdogQueue.async {
            self.watchdogSuspended = true
            self.watchdogPolicy.reset()
        }
        completionHandler()
    }

    open override func wake() {
        rememberTunnelLog("Packet tunnel wake; scheduling health check")
        tunnelLog.info("Packet tunnel wake")
        watchdogQueue.async {
            self.watchdogSuspended = false
            self.watchdogPolicy.reset()
            self.scheduleTunnelHealthCheck(trigger: "wake", after: 1.5)
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

    private func startSocks5Tunnel(serverPort port: Int, credentials: LocalProxyCredentials) throws {
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
        guard let tunnelFD = packetFlowFileDescriptor() else {
            throw tunnelError("Unable to identify this provider's packet-flow descriptor")
        }
        hasStartedHEV = true
        hevLifecycle.beginStart()
        DispatchQueue.global(qos: .userInitiated).async {
            tunnelLog.info("HEV socks5 tunnel thread entered")
            self.hevLifecycle.markThreadEntered()
            guard !self.hevLifecycle.isStopRequested else {
                self.hevLifecycle.markExited(code: 0)
                return
            }
            let exitCode = config.withCString { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: config.utf8.count) {
                    hev_socks5_tunnel_main_from_str($0, UInt32(config.utf8.count), tunnelFD)
                }
            }
            let exitedUnexpectedly = self.hevLifecycle.markExited(code: exitCode)
            rememberTunnelLog("HEV socks5 tunnel exited with code \(exitCode)")
            tunnelLog.error("HEV socks5 tunnel exited with code \(exitCode, privacy: .public)")
            NSLog("HEV_SOCKS5_TUNNEL_MAIN: \(exitCode)")
            if exitedUnexpectedly {
                self.reportTerminalFailure(
                    "HEV socks5 tunnel exited unexpectedly with code \(exitCode)",
                    code: Int(exitCode)
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

    private func packetFlowFileDescriptor() -> Int32? {
        var attempts: [String] = []
        for attempt in 1...12 {
            let rawValue = packetFlow.value(forKeyPath: "socket.fileDescriptor")
            let rawType = rawValue.map { String(describing: type(of: $0)) } ?? "nil"
            let rawDescription = String(describing: rawValue)
            if let fileDescriptor = int32FileDescriptor(from: rawValue), utunUnit(for: fileDescriptor) != nil {
                let validation = describeUtunFileDescriptor(fileDescriptor)
                attempts.append("#\(attempt) rawType=\(rawType) raw=\(rawDescription) fd=\(fileDescriptor) \(validation)")
                rememberTunnelLog("packetFlow fd KVC attempts: \(attempts.joined(separator: " | "))")
                rememberTunnelLog("Detected utun fd candidates before HEV start: \(describeUtunFileDescriptorCandidates(utunFileDescriptorCandidates()))")
                rememberTunnelLog("Using explicit packetFlow file descriptor \(fileDescriptor) for HEV")
                tunnelLog.info("Using explicit packetFlow file descriptor \(fileDescriptor, privacy: .public) for HEV")
                return fileDescriptor
            }
            attempts.append("#\(attempt) rawType=\(rawType) raw=\(rawDescription) converted=nil")
            usleep(50_000)
        }
        rememberTunnelLog("Unable to identify packetFlow descriptor; refusing descriptor autodetection")
        return nil
    }

    private func int32FileDescriptor(from value: Any?) -> Int32? {
        if let value = value as? Int32 {
            return value >= 0 ? value : nil
        }
        if let value = value as? Int {
            return value >= 0 && value <= Int(Int32.max) ? Int32(value) : nil
        }
        if let value = value as? NSNumber {
            let intValue = value.intValue
            return intValue >= 0 && intValue <= Int(Int32.max) ? Int32(intValue) : nil
        }
        return nil
    }

    private func describeUtunFileDescriptor(_ fd: Int32) -> String {
        guard let unit = utunUnit(for: fd) else {
            return "utunValidation=not-utun"
        }
        return "utunValidation=ok unit=\(unit)"
    }

    private struct UtunFileDescriptorCandidate {
        let fd: Int32
        let unit: UInt32

        var interfaceName: String {
            guard unit > 0 else {
                return "utun?"
            }
            return "utun\(unit - 1)"
        }

        var logDescription: String {
            "fd=\(fd)/unit=\(unit)/if=\(interfaceName)"
        }
    }

    private func utunFileDescriptorCandidates() -> [UtunFileDescriptorCandidate] {
        var candidates: [UtunFileDescriptorCandidate] = []
        for fd in Int32(0)...Int32(1024) {
            if let unit = utunUnit(for: fd) {
                candidates.append(UtunFileDescriptorCandidate(fd: fd, unit: unit))
            }
        }
        return candidates
    }

    private func describeUtunFileDescriptorCandidates(_ candidates: [UtunFileDescriptorCandidate]) -> String {
        if candidates.isEmpty {
            return "none"
        }
        return candidates.map(\.logDescription).joined(separator: ", ")
    }

    private func utunUnit(for fd: Int32) -> UInt32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }

        var address = sockaddr_ctl()
        var length = socklen_t(MemoryLayout.size(ofValue: address))
        let peerResult = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(fd, $0, &length)
            }
        }
        guard peerResult == 0, address.sc_family == AF_SYSTEM else {
            return nil
        }
        guard ioctl(fd, CTLIOCGINFO, &ctlInfo) == 0 else {
            return nil
        }
        guard address.sc_id == ctlInfo.ctl_id else {
            return nil
        }
        return address.sc_unit
    }

    private func startXRay(xrayConfig: Data, geoAssetsDirectory: String?) throws {
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
        let started = XRayStartPrivate(xrayConfig, logger, &error)

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

    private func startTunnelWatchdog(port: Int?) {
        watchdogQueue.sync {
            watchdogGeneration += 1
            runtimeRecoveryInFlight = false
            watchdogInboundPort = port
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
                self?.performTunnelHealthCheck(trigger: "periodic")
            }
            watchdogTimer = timer
            timer.resume()

            pathMonitor?.cancel()
            let monitor = NWPathMonitor()
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                rememberTunnelLog("Network path changed status=\(String(describing: path.status))")
                if path.status == .satisfied {
                    self.watchdogPolicy.reset()
                    self.scheduleTunnelHealthCheck(trigger: "path-change", after: 2)
                }
            }
            pathMonitor = monitor
            monitor.start(queue: watchdogQueue)
        }
    }

    private func stopTunnelWatchdog() {
        watchdogQueue.sync {
            watchdogGeneration += 1
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
    private func scheduleTunnelHealthCheck(trigger: String, after delay: TimeInterval) {
        let generation = watchdogGeneration
        watchdogQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard self?.watchdogGeneration == generation else { return }
            self?.performTunnelHealthCheck(trigger: trigger)
        }
    }

    private func scheduleRecoveryCheck() {
        guard recoveryCheck == nil else { return }
        let check = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.recoveryCheck = nil
            self.performTunnelHealthCheck(trigger: "recovery")
        }
        recoveryCheck = check
        watchdogQueue.asyncAfter(deadline: .now() + 3, execute: check)
    }

    /// Checks both the HEV worker state and the Xray SOCKS-to-Internet path.
    /// Recovery keeps protected sessions scoped to the tunnel. A dead local
    /// runtime is restarted by the saved on-demand policy.
    @discardableResult
    private func performTunnelHealthCheck(trigger: String) -> Bool {
        guard !watchdogSuspended,
              !runtimeRecoveryInFlight,
              let port = watchdogInboundPort,
              let credentials = runtimeSpec?.credentials else {
            return false
        }
        guard !hevLifecycle.isStopRequested, hevLifecycle.isRunning else {
            setForwardingReady(false)
            scheduleNativeRecovery(after: 3)
            return false
        }

        let inboundResult = socksInboundHealthCheck(port: port, credentials: credentials)
        watchdogInboundHealthy = inboundResult.hasPrefix("ok")
        let connectResult = socksConnectHealthCheck(port: port, credentials: credentials)
        let httpResult = socksHTTPHealthCheck(port: port, credentials: credentials)
        if let hevLogURL {
            try? TunnelFileLog.trimIfNeeded(hevLogURL)
        }
        let success = inboundResult.hasPrefix("ok")
            && connectResult.hasPrefix("ok")
            && httpResult.hasPrefix("ok")

        rememberTunnelLog(
            "Watchdog \(trigger): success=\(success) inbound=[\(inboundResult)] connect=[\(connectResult)] http=[\(httpResult)]"
        )
        setForwardingReady(success)
        if success {
            tunnelLog.info("Tunnel watchdog \(trigger, privacy: .public) passed")
            reasserting = false
            recoveryCheck?.cancel()
            recoveryCheck = nil
            rememberTunnelLog("Protected tunnel forwarding restored")
        } else {
            tunnelLog.warning("Tunnel watchdog \(trigger, privacy: .public) failed")
            reasserting = true
            scheduleRecoveryCheck()
        }

        if watchdogPolicy.record(success: success) {
            reportTerminalFailure(
                "Tunnel watchdog failed \(watchdogPolicy.consecutiveFailures) consecutive checks",
                code: 2
            )
        }
        return success
    }

    private func reportTerminalFailure(_ message: NativeDiagnosticMessage, code: Int) {
        watchdogQueue.async {
            self.handleRuntimeFailure(message, code: code)
        }
    }

    /// Runs on the watchdog queue; native recovery retains the tunnel routes.
    private func handleRuntimeFailure(_ message: NativeDiagnosticMessage, code: Int) {
        guard !watchdogSuspended else { return }
        setForwardingReady(false)
        if hevLifecycle.isRunning && watchdogInboundHealthy {
            rememberTunnelLog("Protected tunnel waiting for transport recovery")
            return
        }
        rememberTunnelLog("Restarting native workers inside the protected tunnel")
        scheduleNativeRecovery(after: 0)
    }

    private func socksInboundHealthCheck(port: Int, credentials: LocalProxyCredentials) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else {
            return "inet_pton failed"
        }

        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            return "connect 127.0.0.1:\(port) failed errno=\(errno)"
        }

        return LocalSOCKS5Client.authenticate(fd: fd, credentials: credentials) ? "ok authenticated" : "authentication failed"
    }

    private func socksConnectHealthCheck(port: Int, credentials: LocalProxyCredentials) -> String {
        do {
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                                                        host: "1.1.1.1", port: 80, timeout: 5)
            close(fd)
            return "ok authenticated connect"
        } catch { return "authenticated connect failed" }
    }

    /// Requires authenticated CONNECT and a successful HTTP response from the proxy path.
    private func socksHTTPHealthCheck(port: Int, credentials: LocalProxyCredentials) -> String {
        do {
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                                                        host: "www.gstatic.com", port: 80)
            defer { close(fd) }
            let request = "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"
            guard LocalSOCKS5Client.sendAll(fd: fd, bytes: Array(request.utf8)),
                  let response = recvSome(fd: fd, maxCount: 512),
                  let status = String(bytes: response, encoding: .utf8)?.split(separator: " ").dropFirst().first,
                  let code = Int(status), (200...399).contains(code) else { return "HTTP response failed" }
            return "ok authenticated HTTP"
        } catch { return "authenticated HTTP connection failed" }
    }

    private func recvSome(fd: Int32, maxCount: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: maxCount)
        let received = buffer.withUnsafeMutableBytes {
            recv(fd, $0.baseAddress, maxCount, 0)
        }
        guard received > 0 else {
            return nil
        }
        return Array(buffer.prefix(received))
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

    private func resolveIPv4Addresses(for host: String) -> [String] {
        if isIPv4Literal(host) {
            return [host]
        }
        return resolveAddresses(for: host, family: AF_INET)
    }

    private func resolveIPv6Addresses(for host: String) -> [String] {
        if isIPv6Literal(host) {
            return [host]
        }
        return resolveAddresses(for: host, family: AF_INET6)
    }

    private func resolveAddresses(for host: String, family: Int32) -> [String] {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: family,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0, let first = result else {
            tunnelLog.warning("Failed to resolve \(host, privacy: .public): \(String(cString: gai_strerror(status)), privacy: .public)")
            return []
        }
        defer { freeaddrinfo(first) }

        var addresses: [String] = []
        var pointer: UnsafeMutablePointer<addrinfo>? = first
        while let current = pointer {
            if current.pointee.ai_family == AF_INET {
                var addr = current.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    addresses.append(String(cString: buffer))
                }
            } else if current.pointee.ai_family == AF_INET6 {
                var addr = current.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    addresses.append(String(cString: buffer))
                }
            }
            pointer = current.pointee.ai_next
        }
        return Array(Set(addresses)).sorted()
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
