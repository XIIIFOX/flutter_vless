//
//  PacketTunnelProvider.swift
//  XrayTunnel
//
//  Created by Vladimir Khudiakov on 17.08.2025. https://tfox.dev.
//

import NetworkExtension
import Network
import XRay
import Tun2SocksKit
import flutter_vless_tunnel_support
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

/// iOS runs this extension in a separate process from the Flutter app, and the
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

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = CustomXRayLogger()
    private let hevLifecycle = TunnelProcessLifecycle()
    private let watchdogQueue = DispatchQueue(label: "dev.tfox.flutter-vless.ios-watchdog", qos: .utility)
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
    private let runtimeQueue = DispatchQueue(label: "dev.tfox.flutter-vless.ios-runtime")
    private let forwardingLock = NSLock()
    private var forwardingReady = false
    private var runtimeSpec: RuntimeSpec?
    private var runtimeRecoveryInFlight = false
    // Accessed only on runtimeQueue.
    private var hasStartedHEV = false
    private var hevStopSignal: DispatchGroup?

    private struct RuntimeSpec {
        let config: Data
        let port: Int
        let geoAssetsDirectory: String?
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

    override func startTunnel(options: [String : NSObject]? = nil) async throws {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol else {
            throw tunnelError("Missing tunnel provider configuration")
        }
        let providerConfiguration = configuration.providerConfiguration ?? [:]
        // An old system profile cannot provide the required OS routing policy.
        // Restart from the host app to save the current protected configuration.
        guard configuration.includeAllNetworks && !configuration.excludeLocalNetworks else {
            throw tunnelError("VPN profile requires traffic protection; reconnect from the app")
        }
        if #available(iOS 16.4, *), configuration.excludeAPNs || configuration.excludeCellularServices {
            throw tunnelError("VPN profile has unsupported service exclusions; reconnect from the app")
        }
        let bypassArgument = providerConfiguration["bypassSubnets"]
        guard bypassArgument == nil || bypassArgument is NSNull || (bypassArgument as? [String])?.isEmpty == true else {
            throw tunnelError("System route exclusions are unsupported; use Xray direct rules")
        }
        TunnelDebugStore.shared.configure(groupIdentifier: providerConfiguration["groupIdentifier"] as? String)
        setForwardingReady(false)
        rememberTunnelLog("Starting Xray packet tunnel")
        let config = providerConfiguration["xrayConfig"] as? Data ?? Data()
        // Endpoint bootstrap precedes virtual DNS installation. Reuse the
        // prepared endpoints when restarting workers within this same tunnel.
        let prepared = prepareXrayConfigForTunnel(config)
        let parsed = prepared.flatMap { parseConfig(jsonData: $0.data) }
        let addresses = prepared?.bootstrapAddresses ?? []
        let compatible = TunnelDNSPolicy.allowsRouteExclusions(addresses.map { "\($0)/32" })
        let usable = prepared != nil && parsed != nil && compatible

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
        rememberTunnelLog("Protected tunnel routes and virtual DNS installed")

        if usable, let prepared, let parsed {
            runtimeSpec = RuntimeSpec(config: prepared.data, port: parsed.inboundPort,
                geoAssetsDirectory: providerConfiguration["geoAssetsDirectory"] as? String)
        } else {
            runtimeSpec = nil
            rememberTunnelLog("Tunnel configuration rejected; protected traffic remains blocked")
        }
        startTunnelWatchdog(port: runtimeSpec?.port)
        // NE connected only means the routes are installed. The plugin
        // queries forwarding readiness before publishing CONNECTED.
        watchdogQueue.async { self.scheduleNativeRecovery(after: 0) }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        rememberTunnelLog("Stopping Xray packet tunnel, reason=\(reason.rawValue)")
        setForwardingReady(false)
        stopTunnelWatchdog()
        runtimeQueue.async {
            _ = self.stopNativeRuntime()
            completionHandler()
        }
    }

    private func startNativeRuntime(_ spec: RuntimeSpec) throws {
        try startXRay(xrayConfig: spec.config, geoAssetsDirectory: spec.geoAssetsDirectory)
        try startSocks5Tunnel(serverPort: spec.port)
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

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
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
                var error: NSError?
                var delay: Int64 = -1
                let url = String(message[message.index(message.startIndex, offsetBy: 10)...])
                tunnelLog.info("Measuring connected delay url=\(url, privacy: .public)")
                XRayMeasureDelay(url, &delay, &error)
                if let error {
                    tunnelLog.error("Connected delay error: \(error.localizedDescription, privacy: .public)")
                } else {
                    tunnelLog.info("Connected delay result=\(delay, privacy: .public)")
                }
                completionHandler?("\(delay)".data(using: .utf8))
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

    override func sleep(completionHandler: @escaping () -> Void) {
        rememberTunnelLog("Packet tunnel sleep; suspending watchdog")
        tunnelLog.info("Packet tunnel sleep")
        watchdogQueue.async {
            self.watchdogSuspended = true
            self.watchdogPolicy.reset()
        }
        completionHandler()
    }

    override func wake() {
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

    private func startSocks5Tunnel(serverPort port: Int) throws {
        // HEV is the tun2socks bridge: it reads IP packets from NetworkExtension
        // and forwards them into the local SOCKS inbound opened by Xray.
        // Xray alone can start successfully while user traffic still cannot
        // leave the device; HEV logs close that gap during real-device tests.
        let logDirectory = TunnelDebugStore.shared.logDirectoryURL()
            ?? FileManager.default.temporaryDirectory
        let logURL = logDirectory.appendingPathComponent("hev-socks5-tunnel.log")
        hevLogURL = logURL
        try? TunnelFileLog.trimIfNeeded(logURL)
        try? TunnelFileLog.append(
            "--- HEV session started \(ISO8601DateFormatter().string(from: Date())) ---",
            to: logURL,
            maxFileBytes: 512 * 1024,
            retainedBytes: 256 * 1024
        )
        let config = """
        tunnel:
          mtu: \(tunnelMTU)
        socks5:
          port: \(port)
          address: 127.0.0.1
          udp: 'udp'
        misc:
          task-stack-size: 86016
          tcp-buffer-size: 65536
          max-session-count: 512
          connect-timeout: 5000
          tcp-read-write-timeout: 300000
          udp-read-write-timeout: 60000
          log-file: \(logURL.path)
          log-level: error
          limit-nofile: 65535
        """
        rememberTunnelLog("Starting HEV socks5 tunnel on 127.0.0.1:\(port), log=\(logURL.path)")
        tunnelLog.info("Starting HEV socks5 tunnel on 127.0.0.1:\(port, privacy: .public), mtu \(tunnelMTU, privacy: .public)")
        hasStartedHEV = true
        hevLifecycle.beginStart()
        DispatchQueue.global(qos: .userInitiated).async {
            tunnelLog.info("HEV socks5 tunnel thread entered")
            self.hevLifecycle.markThreadEntered()
            guard !self.hevLifecycle.isStopRequested else {
                self.hevLifecycle.markExited(code: 0)
                return
            }
            let exitCode = Socks5Tunnel.run(withConfig: .string(content: config))
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

    /// Normalizes imported Xray JSON for iOS packet-tunnel constraints.
    ///
    /// The same URL parser is used for standalone Xray configs and for this
    /// extension, but iOS has tighter rules: file logs may be denied inside the
    /// extension sandbox, DNS must line up with `NEDNSSettings`, and the remote
    /// proxy server must not be reached through the tunnel that depends on it.
    private func prepareXrayConfigForTunnel(_ jsonData: Data) -> TunnelPreparedConfig? {
        guard let prepared = TunnelXrayConfigPreparer.prepare(
            jsonData: jsonData,
            resolveIPv4: { resolveIPv4Addresses(for: $0).first }
        ) else {
            tunnelLog.warning("Could not prepare Xray config for iOS tunnel")
            return nil
        }
        rememberTunnelLog("Xray configuration prepared, steps=\(prepared.logMessages.count)")
        return prepared
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
              let port = watchdogInboundPort else {
            return false
        }
        guard !hevLifecycle.isStopRequested, hevLifecycle.isRunning else {
            setForwardingReady(false)
            scheduleNativeRecovery(after: 3)
            return false
        }

        let inboundResult = socksInboundHealthCheck(port: port)
        watchdogInboundHealthy = inboundResult.hasPrefix("ok")
        let connectResult = socksConnectHealthCheck(port: port)
        let httpResult = socksHTTPHealthCheck(port: port)
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

    private func socksInboundHealthCheck(port: Int) -> String {
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

        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        let sent = greeting.withUnsafeBytes {
            send(fd, $0.baseAddress, greeting.count, 0)
        }
        guard sent == greeting.count else {
            return "send greeting failed sent=\(sent) errno=\(errno)"
        }

        var response = [UInt8](repeating: 0, count: 2)
        let responseCount = response.count
        let received = response.withUnsafeMutableBytes {
            recv(fd, $0.baseAddress, responseCount, 0)
        }
        guard received == 2 else {
            return "recv greeting failed received=\(received) errno=\(errno)"
        }

        return "ok response=\(response.map { String(format: "%02x", $0) }.joined(separator: " "))"
    }

    private func socksConnectHealthCheck(port: Int) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 5, tv_usec: 0)
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

        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        guard sendAll(fd: fd, bytes: greeting) else {
            return "send greeting failed errno=\(errno)"
        }
        guard let greetingResponse = recvExact(fd: fd, count: 2) else {
            return "recv greeting failed errno=\(errno)"
        }
        guard greetingResponse == [0x05, 0x00] else {
            return "unexpected greeting=\(hex(greetingResponse))"
        }

        let request: [UInt8] = [
            0x05, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x01, 0x01,
            0x00, 0x50
        ]
        guard sendAll(fd: fd, bytes: request) else {
            return "send connect failed errno=\(errno)"
        }
        guard let header = recvExact(fd: fd, count: 4) else {
            return "recv connect header failed errno=\(errno)"
        }
        guard header.count == 4 else {
            return "short connect header=\(hex(header))"
        }
        let atyp = header[3]
        let remaining: Int
        switch atyp {
        case 0x01:
            remaining = 6
        case 0x03:
            guard let lengthBytes = recvExact(fd: fd, count: 1), let length = lengthBytes.first else {
                return "recv domain length failed errno=\(errno)"
            }
            remaining = Int(length) + 2
        case 0x04:
            remaining = 18
        default:
            return "unexpected connect atyp=\(String(format: "%02x", atyp)) header=\(hex(header))"
        }
        let tail = recvExact(fd: fd, count: remaining) ?? []
        let status = header[1] == 0x00 ? "ok" : "failed"
        return "\(status) response=\(hex(header + tail))"
    }

    /// Performs an HTTP request through the same local SOCKS inbound used by HEV.
    ///
    /// This is the decisive regression signal for the current investigation:
    /// TCP/Reality returned `HTTP/1.1 204 No Content` on device, while failing
    /// XHTTP links reached earlier stages but did not return usable page bytes.
    private func socksHTTPHealthCheck(port: Int) -> String {
        let host = "www.gstatic.com"
        let path = "/generate_204"
        let hostBytes = Array(host.utf8)
        guard hostBytes.count <= 255 else {
            return "host too long"
        }

        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 8, tv_usec: 0)
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

        guard sendAll(fd: fd, bytes: [0x05, 0x01, 0x00]),
              let greetingResponse = recvExact(fd: fd, count: 2),
              greetingResponse == [0x05, 0x00] else {
            return "socks greeting failed errno=\(errno)"
        }

        var request: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)]
        request.append(contentsOf: hostBytes)
        request.append(0x00)
        request.append(0x50)
        guard sendAll(fd: fd, bytes: request) else {
            return "send connect failed errno=\(errno)"
        }
        guard let header = recvExact(fd: fd, count: 4) else {
            return "recv connect header failed errno=\(errno)"
        }
        guard header.count == 4, header[1] == 0x00 else {
            return "connect failed response=\(hex(header)) errno=\(errno)"
        }
        let atyp = header[3]
        let remaining: Int
        switch atyp {
        case 0x01:
            remaining = 6
        case 0x03:
            guard let lengthBytes = recvExact(fd: fd, count: 1), let length = lengthBytes.first else {
                return "recv domain length failed errno=\(errno)"
            }
            remaining = Int(length) + 2
        case 0x04:
            remaining = 18
        default:
            return "unexpected connect atyp=\(String(format: "%02x", atyp))"
        }
        _ = recvExact(fd: fd, count: remaining)

        let httpRequest = """
        GET \(path) HTTP/1.1\r
        Host: \(host)\r
        User-Agent: flutter-vless-healthcheck\r
        Connection: close\r
        \r

        """
        guard sendAll(fd: fd, bytes: Array(httpRequest.utf8)) else {
            return "send http failed errno=\(errno)"
        }
        guard let response = recvSome(fd: fd, maxCount: 512), !response.isEmpty else {
            return "recv http failed errno=\(errno)"
        }
        let text = String(decoding: response, as: UTF8.self)
        let firstLine = text.components(separatedBy: "\r\n").first ?? text
        return "ok \(host)\(path) \(firstLine)"
    }

    private func sendAll(fd: Int32, bytes: [UInt8]) -> Bool {
        var sentTotal = 0
        while sentTotal < bytes.count {
            let sent = bytes.withUnsafeBytes {
                send(fd, $0.baseAddress!.advanced(by: sentTotal), bytes.count - sentTotal, 0)
            }
            guard sent > 0 else {
                return false
            }
            sentTotal += sent
        }
        return true
    }

    private func recvExact(fd: Int32, count: Int) -> [UInt8]? {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        while result.count < count {
            var buffer = [UInt8](repeating: 0, count: count - result.count)
            let bufferCount = buffer.count
            let received = buffer.withUnsafeMutableBytes {
                recv(fd, $0.baseAddress, bufferCount, 0)
            }
            guard received > 0 else {
                return nil
            }
            result.append(contentsOf: buffer.prefix(received))
        }
        return result
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
