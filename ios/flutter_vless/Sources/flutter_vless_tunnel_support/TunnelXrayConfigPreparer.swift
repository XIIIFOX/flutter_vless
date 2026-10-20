import Foundation
import Darwin
@_exported import flutter_vless_privacy

public struct TunnelParsedConfig: Equatable {
    public let inboundPort: Int
    public let serverAddress: String?

    public init(inboundPort: Int, serverAddress: String?) {
        self.inboundPort = inboundPort
        self.serverAddress = serverAddress
    }
}

public struct TunnelEndpointSelection: Equatable, Sendable {
    public let logicalHost: String
    public let candidates: TunnelEndpointCandidates
    public let selected: TunnelEndpointCandidate

    public init(logicalHost: String, candidates: TunnelEndpointCandidates, selected: TunnelEndpointCandidate) {
        self.logicalHost = logicalHost
        self.candidates = candidates
        self.selected = selected
    }
}

public struct TunnelPreparedConfig {
    public let data: Data
    public let logMessages: [String]
    public let proxyUsesXhttp: Bool
    public let bootstrapAddresses: [String]
    public let routingEnvelope: NativeRoutingEnvelope?
    public let endpointPath: TunnelEndpointPath?
    public let endpointSelections: [TunnelEndpointSelection]

    public init(data: Data, logMessages: [String], proxyUsesXhttp: Bool, bootstrapAddresses: [String] = [], routingEnvelope: NativeRoutingEnvelope? = nil,
                endpointPath: TunnelEndpointPath? = nil, endpointSelections: [TunnelEndpointSelection] = []) {
        self.data = data
        self.logMessages = logMessages
        self.proxyUsesXhttp = proxyUsesXhttp
        self.bootstrapAddresses = bootstrapAddresses
        self.routingEnvelope = routingEnvelope
        self.endpointPath = endpointPath
        self.endpointSelections = endpointSelections
    }
}

/// Pure JSON normalizer for the iOS Packet Tunnel.
///
/// Keep this logic outside `NEPacketTunnelProvider` so we can unit-test the
/// failure-prone parts without launching a real NetworkExtension process. The
/// helper intentionally preserves proxy credentials and VLESS
/// `users[].encryption` values byte-for-byte; the XHTTP/none incident proved
/// that mutating or dropping those server-provisioned values can produce a VPN
/// that connects locally but cannot fetch HTTP bytes.
public enum TunnelXrayConfigPreparer {
    public enum StartupError: Error { case invalidConfiguration, endpointUnavailable }

    /// Prepare from one immutable underlay generation. Candidate selection is
    /// private to physical endpoints; caller DNS and logical destinations stay intact.
    public static func prepareForStartup(
        jsonData: Data,
        credentials: LocalProxyCredentials,
        routingIntent: NativeRoutingIntent? = nil,
        tcpPortAvailable: ((Int) -> Bool)? = nil,
        environmentSnapshot: XrayEnvironmentSnapshot = .capture(),
        endpointPath: TunnelEndpointPath,
        selectedAttempt: UInt64 = 0,
        resolveCandidates: (String) async throws -> TunnelEndpointCandidates,
        isCurrent: () -> Bool = { true },
        attempts: Int = 5,
        retryDelay: () async throws -> Void = { try await Task.sleep(nanoseconds: 3_000_000_000) },
        now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) async throws -> TunnelPreparedConfig {
        struct AnswerSnapshot {
            let answers: TunnelEndpointCandidates
            let lookupBegan: TimeInterval
            let lookupFinished: TimeInterval
        }
        func checkOwnership() throws {
            try Task.checkCancellation()
            guard isCurrent() else { throw CancellationError() }
        }
        func key(_ host: String) -> String {
            (host.hasSuffix(".") ? String(host.dropLast()) : host).lowercased()
        }
        func matchesLogicalHost(_ candidate: TunnelEndpointCandidate, _ host: String) -> Bool {
            let literal = TunnelEndpointAddress(text: host, source: .literal)
            switch candidate.origin {
            case .literal:
                return literal?.text == candidate.address.text
            case .systemIPv4Translation(let original):
                return literal?.family == .ipv4 && candidate.address.family == .ipv6
                    && TunnelEndpointAddress(text: original, source: .literal)?.text == literal?.text
            case .systemNameAnswer, .encryptedIPv4Answer:
                return literal == nil
            }
        }
        func usable(_ snapshot: AnswerSnapshot, host: String, at time: TimeInterval) -> [TunnelEndpointCandidate] {
            snapshot.answers.candidates.filter { candidate in
                let freshZero = candidate.isSingleAttemptOnly
                    && candidate.receivedAt >= snapshot.lookupBegan && candidate.receivedAt <= snapshot.lookupFinished
                return candidate.isUsable(on: endpointPath, at: time, allowFreshZeroTTL: freshZero)
                    && matchesLogicalHost(candidate, host)
            }
        }
        try checkOwnership()
        let began = now()
        guard began.isFinite else { throw StartupError.endpointUnavailable }
        let deadline = began + 25
        for attempt in 0..<max(1, attempts) {
            try checkOwnership()
            // Each preparation retry owns new answers. In particular, a zero-TTL
            // record is never reused by another worker or preparation attempt.
            var answers: [String: AnswerSnapshot] = [:]
            var names: [String] = []
            while true {
                try checkOwnership()
                guard now().isFinite, now() < deadline else { throw StartupError.endpointUnavailable }
                var missingHost: String?
                var expired = false
                let discovery = prepareSnapshot(jsonData: jsonData, credentials: credentials,
                    routingIntent: routingIntent, tcpPortAvailable: tcpPortAvailable,
                    environmentSnapshot: environmentSnapshot, endpointPath: endpointPath) { host in
                        guard let snapshot = answers[key(host)] else { missingHost = host; return nil }
                        let values = usable(snapshot, host: host, at: now())
                        guard !values.isEmpty else { expired = true; return nil }
                        var ordinal = selectedAttempt
                        for previous in names {
                            if key(previous) == key(host) { break }
                            guard let earlier = answers[key(previous)] else { expired = true; return nil }
                            let count = usable(earlier, host: previous, at: now()).count
                            guard count > 0 else { expired = true; return nil }
                            ordinal /= UInt64(count)
                        }
                        return values[Int(ordinal % UInt64(values.count))].address.text
                    }
                try checkOwnership()
                if expired { break }
                if discovery != nil {
                    // Mixed radix visits every combination without multiplication
                    // overflow. The first discovered endpoint is the low digit.
                    var ordinal = selectedAttempt
                    var selections: [TunnelEndpointSelection] = []
                    for host in names {
                        guard let snapshot = answers[key(host)] else { throw StartupError.invalidConfiguration }
                        let values = usable(snapshot, host: host, at: now())
                        guard !values.isEmpty else { throw StartupError.endpointUnavailable }
                        let index = Int(ordinal % UInt64(values.count))
                        ordinal /= UInt64(values.count)
                        selections.append(TunnelEndpointSelection(logicalHost: host, candidates: snapshot.answers,
                                                                  selected: values[index]))
                    }
                    let selected = Dictionary(uniqueKeysWithValues: selections.map { (key($0.logicalHost), $0.selected.address.text) })
                    guard let prepared = prepareSnapshot(jsonData: jsonData, credentials: credentials,
                        routingIntent: routingIntent, tcpPortAvailable: tcpPortAvailable,
                        environmentSnapshot: environmentSnapshot, endpointPath: endpointPath,
                        resolveIPv4: { selected[key($0)] }) else { throw StartupError.invalidConfiguration }
                    try checkOwnership()
                    guard now() < deadline, selections.allSatisfy({ selection in
                        guard let snapshot = answers[key(selection.logicalHost)] else { return false }
                        return usable(snapshot, host: selection.logicalHost, at: now()).contains(selection.selected)
                    }) else { throw StartupError.endpointUnavailable }
                    guard prepared.bootstrapAddresses == Array(Set(selections.map { $0.selected.address.text })).sorted() else {
                        throw StartupError.invalidConfiguration
                    }
                    return TunnelPreparedConfig(data: prepared.data, logMessages: prepared.logMessages,
                        proxyUsesXhttp: prepared.proxyUsesXhttp, bootstrapAddresses: prepared.bootstrapAddresses,
                        routingEnvelope: prepared.routingEnvelope, endpointPath: endpointPath, endpointSelections: selections)
                }
                guard let host = missingHost else { throw StartupError.invalidConfiguration }
                guard answers.count < 64 else { throw StartupError.invalidConfiguration }
                let lookupBegan = now()
                let result: TunnelEndpointCandidates
                do { result = try await resolveCandidates(host) }
                catch { try checkOwnership(); throw error }
                try checkOwnership()
                let lookupFinished = now()
                guard lookupFinished.isFinite, lookupFinished >= lookupBegan, lookupFinished < deadline,
                      result.path == endpointPath else { throw StartupError.endpointUnavailable }
                let snapshot = AnswerSnapshot(answers: result, lookupBegan: lookupBegan, lookupFinished: lookupFinished)
                let values = usable(snapshot, host: host, at: lookupFinished)
                guard !values.isEmpty else { break }
                if values.contains(where: { !$0.address.isLoopback }) {
                    guard endpointPath.interfaceIndex != 0, let name = endpointPath.interfaceName,
                          !name.isEmpty, !name.utf8.contains(0) else { throw StartupError.endpointUnavailable }
                }
                names.append(host)
                answers[key(host)] = snapshot
            }
            if attempt + 1 < attempts {
                do { try await retryDelay() }
                catch { try checkOwnership(); throw error }
                try checkOwnership()
            }
        }
        throw StartupError.endpointUnavailable
    }

    /// Resolve only physical endpoints. The typed answer retains its actual
    /// numeric family; a system AAAA answer does not imply proven DNS64.
    /// Session ownership is rechecked around every asynchronous boundary.
    public static func prepareForStartup(
        jsonData: Data,
        credentials: LocalProxyCredentials,
        routingIntent: NativeRoutingIntent? = nil,
        tcpPortAvailable: ((Int) -> Bool)? = nil,
        environmentSnapshot: XrayEnvironmentSnapshot = .capture(),
        resolveEndpoint: (String) async throws -> TunnelEndpointAddress?,
        isCurrent: () -> Bool = { true },
        attempts: Int = 5,
        retryDelay: () async throws -> Void = { try await Task.sleep(nanoseconds: 3_000_000_000) }
    ) async throws -> TunnelPreparedConfig {
        try await prepareForStartup(jsonData: jsonData, credentials: credentials,
            routingIntent: routingIntent, tcpPortAvailable: tcpPortAvailable,
            environmentSnapshot: environmentSnapshot,
            resolveIPv4: { try await resolveEndpoint($0)?.text }, isCurrent: isCurrent,
            attempts: attempts, retryDelay: retryDelay)
    }

    /// Retry transient endpoint resolution only before virtual DNS/routes exist.
    /// A failed preparation must never create a connected tunnel with no runtime
    /// to recover. Exhaustion is a startup error handled by NetworkExtension.
    public static func prepareForStartup(
        jsonData: Data,
        credentials: LocalProxyCredentials,
        routingIntent: NativeRoutingIntent? = nil,
        tcpPortAvailable: ((Int) -> Bool)? = nil,
        environmentSnapshot: XrayEnvironmentSnapshot = .capture(),
        resolveIPv4: (String) async throws -> String?,
        isCurrent: () -> Bool = { true },
        attempts: Int = 5,
        retryDelay: () async throws -> Void = { try await Task.sleep(nanoseconds: 3_000_000_000) }
    ) async throws -> TunnelPreparedConfig {
        func checkOwnership() throws {
            try Task.checkCancellation()
            guard isCurrent() else { throw CancellationError() }
        }
        try checkOwnership()
        var resolved: [String: String] = [:]
        // A monotonic deadline compatible with the iOS 15 deployment target.
        let deadline = ProcessInfo.processInfo.systemUptime + 25
        for attempt in 0..<max(1, attempts) {
            try checkOwnership()
            // Discover only transport endpoints requested by the existing
            // normalizer. Never resolve routing/sniffing domains or TLS SNI.
            while true {
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw StartupError.endpointUnavailable }
                var missingHost: String?
                let prepared = prepare(jsonData: jsonData, credentials: credentials, routingIntent: routingIntent, tcpPortAvailable: tcpPortAvailable, environmentSnapshot: environmentSnapshot) { host in
                    if let address = resolved[host] { return address }
                    missingHost = host
                    return nil
                }
                try checkOwnership()
                if let prepared { return prepared }
                guard let host = missingHost else { throw StartupError.invalidConfiguration }
                guard resolved.count < 64 else { throw StartupError.invalidConfiguration }
                let address: String?
                do { address = try await resolveIPv4(host) }
                catch { try checkOwnership(); throw error }
                try checkOwnership()
                guard let address else { break }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw StartupError.endpointUnavailable }
                resolved[host] = address
            }
            if attempt + 1 < attempts {
                do { try await retryDelay() }
                catch { try checkOwnership(); throw error }
                try checkOwnership()
            }
        }
        throw StartupError.endpointUnavailable
    }

    /// Resolve typed Address references before persisting a session for a
    /// separate provider process. Keep the editor's original JSON separately.
    public static func bindingEndpointEnvironment(configData: Data) throws -> Data {
        try XrayAddressEnvironment.bind(configData: configData)
    }

    public static func bindingEndpointEnvironment(configData: Data, environment: [String: String]) throws -> Data {
        try XrayAddressEnvironment.bind(configData: configData, environment: environment)
    }

    public static func bindingEndpointEnvironment(configData: Data, environmentSnapshot: XrayEnvironmentSnapshot) throws -> Data {
        try XrayAddressEnvironment.bind(configData: configData, environmentSnapshot: environmentSnapshot)
    }

    public static func parseConfig(jsonData: Data) -> TunnelParsedConfig? {
        guard
            let configJSON = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any],
            let inboundPort = firstLocalInboundPort(configJSON: configJSON)
        else {
            return nil
        }
        return TunnelParsedConfig(
            inboundPort: inboundPort,
            serverAddress: parseServerAddress(configJSON: configJSON)
        )
    }

    public static func prepare(
        jsonData: Data,
        credentials: LocalProxyCredentials,
        routingIntent: NativeRoutingIntent? = nil,
        tcpPortAvailable: ((Int) -> Bool)? = nil,
        environmentSnapshot: XrayEnvironmentSnapshot = .capture(),
        resolveIPv4: (String) -> String? = { _ in nil }
    ) -> TunnelPreparedConfig? {
        prepareSnapshot(jsonData: jsonData, credentials: credentials, routingIntent: routingIntent,
            tcpPortAvailable: tcpPortAvailable, environmentSnapshot: environmentSnapshot,
            endpointPath: nil, resolveIPv4: resolveIPv4)
    }

    private static func prepareSnapshot(
        jsonData: Data,
        credentials: LocalProxyCredentials,
        routingIntent: NativeRoutingIntent?,
        tcpPortAvailable: ((Int) -> Bool)?,
        environmentSnapshot: XrayEnvironmentSnapshot,
        endpointPath: TunnelEndpointPath?,
        resolveIPv4: (String) -> String?
    ) -> TunnelPreparedConfig? {
        do {
            let listenerBound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: jsonData, environmentSnapshot: environmentSnapshot)
            let bound = try XrayAddressEnvironment.bind(configData: listenerBound, environmentSnapshot: environmentSnapshot)
            guard let input = try JSONSerialization.jsonObject(with: bound, options: []) as? [String: Any],
                  var configJSON = TunnelConfigKeys.normalize(input) else {
                return nil
            }
            try NativeRoutingSpec.validateSource(jsonData, intent: routingIntent)
            var messages: [String] = []
            let importedCount = (configJSON["inbounds"] as? [[String: Any]])?.count ?? 0
            if let index = routingIntent?.sourceInboundIndex {
                guard index >= 0 && index < importedCount else { return nil }
            }

            try LocalProxyAccessPolicy.applyVPN(to: &configJSON, credentials: credentials, tcpPortAvailable: tcpPortAvailable, environmentSnapshot: environmentSnapshot)
            guard let managedTag = (configJSON["inbounds"] as? [[String: Any]])?.first?["tag"] as? String else { return nil }
            messages.append("Applied session authentication to the managed loopback SOCKS inbound")

            guard XrayPrivacyConfig.apply(to: &configJSON) else { return nil }
            messages.append("Applied private Xray logging policy")

            if var routing = configJSON["routing"] as? [String: Any] {
                if routing["domainStrategy"] == nil { routing["domainStrategy"] = "AsIs" }
                configJSON["routing"] = routing
            } else {
                configJSON["routing"] = ["domainStrategy": "AsIs"]
            }

            var proxyUsesXhttp = false
            var ownGuards: [Int] = []
            if var outbounds = configJSON["outbounds"] as? [[String: Any]],
               let index = TunnelDNSPolicy.primaryEndpointIndex(in: outbounds) {
                var streamSettings = outbounds[index]["streamSettings"] as? [String: Any] ?? [:]
                normalizeStreamSettingsAliases(streamSettings: &streamSettings, messages: &messages)
                proxyUsesXhttp = ["xhttp", "splithttp"].contains(TunnelDNSPolicy.effectiveTransport(in: streamSettings))
                outbounds[index]["streamSettings"] = streamSettings
                configJSON["outbounds"] = outbounds
            }

            if proxyUsesXhttp {
                let blackholeTag = blackholeOutboundTag(configJSON: &configJSON)
                if ensureUdp443BlockRule(configJSON: &configJSON, outboundTag: blackholeTag, inboundTag: managedTag, privateScopeOnly: routingIntent != nil) {
                    ownGuards.append(0)
                    messages.append("Added XHTTP UDP/443 block rule to force browser TCP fallback")
                }
            }

            var dnsPrefixCount = 0
            guard let bootstrapAddresses = TunnelDNSPolicy.apply(to: &configJSON, managedInboundTag: managedTag,
                generatedRuleCount: { dnsPrefixCount = $0 }, environmentSnapshot: environmentSnapshot, endpointPath: endpointPath, resolveIPv4: resolveIPv4) else {
                return nil
            }
            messages.append("Configured system address DNS through the caller Core DNS policy")
            guard TunnelIPv6Policy.apply(to: &configJSON, managedInboundTag: managedTag) else { return nil }
            messages.append("Captured IPv6 follows caller routing")
            let data = try JSONSerialization.data(withJSONObject: configJSON, options: [])
            // DNS prepends its own rules. Preserve insertion provenance when
            // shifting the earlier XHTTP guard; caller rules never enter this list.
            let guards = Array(0..<dnsPrefixCount) + ownGuards.map { $0 + dnsPrefixCount }
            let envelope = try NativeRoutingSpec.freeze(finalData: data, managedInboundIndex: 0,
                managedInboundTag: managedTag, authUser: credentials.username, intent: routingIntent,
                sourceInboundFinalIndex: routingIntent?.sourceInboundIndex.map { $0 + 1 }, guardRuleIndices: guards)
            return TunnelPreparedConfig(data: data, logMessages: messages, proxyUsesXhttp: proxyUsesXhttp,
                                        bootstrapAddresses: bootstrapAddresses, routingEnvelope: envelope)
        } catch {
            return nil
        }
    }

    public static func parseServerAddress(configJSON: [String: Any]) -> String? {
        guard let outbounds = configJSON["outbounds"] as? [[String: Any]] else {
            return nil
        }
        guard let index = TunnelDNSPolicy.primaryEndpointIndex(in: outbounds),
              let settings = outbounds[index]["settings"] as? [String: Any] else { return nil }
        if let address = settings["address"] as? String, !address.isEmpty { return address }
        for key in ["vnext", "servers"] {
            if let servers = settings[key] as? [[String: Any]],
               let address = servers.first?["address"] as? String, !address.isEmpty { return address }
        }
        return nil
    }

    private static func firstLocalInboundPort(configJSON: [String: Any]) -> Int? {
        guard let inbounds = configJSON["inbounds"] as? [[String: Any]] else {
            return nil
        }
        for inbound in inbounds {
            guard let protocolType = inbound["protocol"] as? String,
                  let port = inbound["port"] as? Int else {
                continue
            }
            if protocolType == "socks" || protocolType == "http" {
                return port
            }
        }
        return nil
    }

    private static func blackholeOutboundTag(configJSON: inout [String: Any]) -> String {
        var outbounds = configJSON["outbounds"] as? [[String: Any]] ?? []
        if let outbound = outbounds.first(where: {
            TunnelDNSPolicy.protocolRole($0["protocol"]) == "blackhole" && !(($0["tag"] as? String) ?? "").isEmpty
        }), let tag = outbound["tag"] as? String { return tag }
        var tags = XrayServiceTags(configuration: configJSON)
        let tag = tags.next("flutter-vless-xhttp-block")
        outbounds.append(["tag": tag, "protocol": "blackhole"])
        configJSON["outbounds"] = outbounds
        return tag
    }

    private static func ensureUdp443BlockRule(configJSON: inout [String: Any], outboundTag: String, inboundTag: String, privateScopeOnly: Bool = false) -> Bool {
        var routing = configJSON["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        let alreadyExists = rules.contains { rule in
            (rule["type"] as? String) == "field" &&
            (rule["network"] as? String) == "udp" &&
            String(describing: rule["port"] ?? "") == "443" &&
            (rule["outboundTag"] as? String) == outboundTag &&
                (rule["inboundTag"] == nil || (rule["inboundTag"] as? [String]) == [inboundTag])
        }
        if alreadyExists && !privateScopeOnly {
            return false
        }
        rules.insert([
            "type": "field",
            "network": "udp",
            "port": "443",
            "inboundTag": [inboundTag],
            "outboundTag": outboundTag
        ], at: 0)
        routing["rules"] = rules
        configJSON["routing"] = routing
        return true
    }

    private static func normalizeStreamSettingsAliases(
        streamSettings: inout [String: Any],
        messages: inout [String]
    ) {
        if let network = streamSettings["network"] as? String {
            let normalizedNetwork = network.lowercased()
            if normalizedNetwork != network {
                streamSettings["network"] = normalizedNetwork
            }
        }

        if let legacyXhttpSettings = streamSettings.removeValue(forKey: "xHTTPSettings") {
            if streamSettings["xhttpSettings"] == nil {
                streamSettings["xhttpSettings"] = legacyXhttpSettings
                messages.append("Normalized xHTTPSettings to xhttpSettings for Xray XHTTP transport")
            }
        }

        if let legacyHTTPUpgradeSettings = streamSettings.removeValue(forKey: "httpUpgradeSettings") {
            if streamSettings["httpupgradeSettings"] == nil {
                streamSettings["httpupgradeSettings"] = legacyHTTPUpgradeSettings
                messages.append("Normalized httpUpgradeSettings to httpupgradeSettings for Xray HTTPUpgrade transport")
            }
        }

        if let legacySplitHTTPSettings = streamSettings.removeValue(forKey: "splitHTTPSettings") {
            if streamSettings["splithttpSettings"] == nil {
                streamSettings["splithttpSettings"] = legacySplitHTTPSettings
                messages.append("Normalized splitHTTPSettings to splithttpSettings for Xray SplitHTTP transport")
            }
        }

        if var tlsSettings = streamSettings["tlsSettings"] as? [String: Any],
           tlsSettings.removeValue(forKey: "allowInsecure") != nil {
            streamSettings["tlsSettings"] = tlsSettings
            messages.append("Removed deprecated tlsSettings.allowInsecure for Xray 26.x")
        }
    }

}
