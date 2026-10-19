import Foundation
import Darwin
@_exported import flutter_vless_macos_privacy

public struct TunnelParsedConfig: Equatable {
    public let inboundPort: Int
    public let serverAddress: String?

    public init(inboundPort: Int, serverAddress: String?) {
        self.inboundPort = inboundPort
        self.serverAddress = serverAddress
    }
}

public struct TunnelPreparedConfig {
    public let data: Data
    public let logMessages: [String]
    public let proxyUsesXhttp: Bool
    public let bootstrapAddresses: [String]
    public let routingEnvelope: NativeRoutingEnvelope?

    public init(data: Data, logMessages: [String], proxyUsesXhttp: Bool, bootstrapAddresses: [String] = [], routingEnvelope: NativeRoutingEnvelope? = nil) {
        self.data = data
        self.logMessages = logMessages
        self.proxyUsesXhttp = proxyUsesXhttp
        self.bootstrapAddresses = bootstrapAddresses
        self.routingEnvelope = routingEnvelope
    }
}

/// Pure JSON normalizer for the macOS Packet Tunnel.
///
/// Keep this logic outside `NEPacketTunnelProvider` so we can unit-test the
/// failure-prone parts without launching a real NetworkExtension process. The
/// helper intentionally preserves proxy credentials and VLESS
/// `users[].encryption` values byte-for-byte; the XHTTP/none incident proved
/// that mutating or dropping those server-provisioned values can produce a VPN
/// that connects locally but cannot fetch HTTP bytes.
public enum TunnelXrayConfigPreparer {
    public enum StartupError: Error { case invalidConfiguration, endpointUnavailable }

    /// Retry transient endpoint resolution only before virtual DNS/routes exist.
    /// A failed preparation must never create a connected tunnel with no runtime
    /// to recover. Exhaustion is a startup error handled by NetworkExtension.
    public static func prepareForStartup(
        jsonData: Data,
        credentials: LocalProxyCredentials,
        routingIntent: NativeRoutingIntent? = nil,
        tcpPortAvailable: ((Int) -> Bool)? = nil,
        resolveIPv4: (String) async throws -> String?,
        attempts: Int = 5,
        retryDelay: () async throws -> Void = { try await Task.sleep(nanoseconds: 3_000_000_000) }
    ) async throws -> TunnelPreparedConfig {
        var resolved: [String: String] = [:]
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(25))
        for attempt in 0..<max(1, attempts) {
            try Task.checkCancellation()
            // Discover only transport endpoints requested by the existing
            // normalizer. Never resolve routing/sniffing domains or TLS SNI.
            while true {
                guard clock.now < deadline else { throw StartupError.endpointUnavailable }
                var missingHost: String?
                let prepared = prepare(jsonData: jsonData, credentials: credentials, routingIntent: routingIntent, tcpPortAvailable: tcpPortAvailable) { host in
                    if let address = resolved[host] { return address }
                    missingHost = host
                    return nil
                }
                try Task.checkCancellation()
                if let prepared { return prepared }
                guard let host = missingHost else { throw StartupError.invalidConfiguration }
                guard resolved.count < 64 else { throw StartupError.invalidConfiguration }
                guard let address = try await resolveIPv4(host) else { break }
                try Task.checkCancellation()
                guard clock.now < deadline else { throw StartupError.endpointUnavailable }
                resolved[host] = address
            }
            if attempt + 1 < attempts { try await retryDelay() }
        }
        throw StartupError.endpointUnavailable
    }

    /// Resolve typed Address references before persisting a session for a
    /// separate provider process. Keep the editor's original JSON separately.
    public static func bindingEndpointEnvironment(configData: Data,
        environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Data {
        try XrayAddressEnvironment.bind(configData: configData, environment: environment)
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
        resolveIPv4: (String) -> String? = { _ in nil }
    ) -> TunnelPreparedConfig? {
        do {
            guard let input = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any],
                  var configJSON = TunnelConfigKeys.normalize(input) else {
                return nil
            }
            try NativeRoutingSpec.validateSource(jsonData, intent: routingIntent)
            var messages: [String] = []
            let importedCount = (configJSON["inbounds"] as? [[String: Any]])?.count ?? 0
            if let index = routingIntent?.sourceInboundIndex {
                guard index >= 0 && index < importedCount else { return nil }
            }

            try LocalProxyAccessPolicy.applyVPN(to: &configJSON, credentials: credentials, tcpPortAvailable: tcpPortAvailable)
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
                generatedRuleCount: { dnsPrefixCount = $0 }, resolveIPv4: resolveIPv4) else {
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
