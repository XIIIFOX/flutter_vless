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

public struct TunnelPreparedConfig {
    public let data: Data
    public let logMessages: [String]
    public let proxyUsesXhttp: Bool
    public let bootstrapAddresses: [String]

    public init(data: Data, logMessages: [String], proxyUsesXhttp: Bool, bootstrapAddresses: [String] = []) {
        self.data = data
        self.logMessages = logMessages
        self.proxyUsesXhttp = proxyUsesXhttp
        self.bootstrapAddresses = bootstrapAddresses
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
        resolveIPv4: (String) -> String? = { _ in nil }
    ) -> TunnelPreparedConfig? {
        do {
            guard let input = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any],
                  var configJSON = TunnelConfigKeys.normalize(input) else {
                return nil
            }
            var messages: [String] = []

            guard XrayPrivacyConfig.apply(to: &configJSON) else { return nil }
            messages.append("Applied private Xray logging policy")

            if var routing = configJSON["routing"] as? [String: Any] {
                routing["domainStrategy"] = "AsIs"
                configJSON["routing"] = routing
            } else {
                configJSON["routing"] = ["domainStrategy": "AsIs"]
            }

            if var inbounds = configJSON["inbounds"] as? [[String: Any]] {
                for index in inbounds.indices {
                    let protocolType = inbounds[index]["protocol"] as? String
                    guard protocolType == "socks" || protocolType == "http" else {
                        continue
                    }
                    inbounds[index]["sniffing"] = [
                        "enabled": true,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": false
                    ]
                }
                configJSON["inbounds"] = inbounds
            }

            var proxyUsesXhttp = false
            if var outbounds = configJSON["outbounds"] as? [[String: Any]] {
                for index in outbounds.indices {
                    let tag = outbounds[index]["tag"] as? String
                    let protocolType = outbounds[index]["protocol"] as? String
                    guard tag == "proxy" || protocolType != "freedom" && protocolType != "blackhole" else {
                        continue
                    }
                    var streamSettings = outbounds[index]["streamSettings"] as? [String: Any] ?? [:]
                    normalizeStreamSettingsAliases(streamSettings: &streamSettings, messages: &messages)
                    let network = (streamSettings["network"] as? String ?? "?").lowercased()
                    proxyUsesXhttp = network == "xhttp"

                    outbounds[index]["streamSettings"] = streamSettings
                    break
                }
                configJSON["outbounds"] = outbounds
            }

            if proxyUsesXhttp {
                let blackholeTag = blackholeOutboundTag(configJSON: configJSON)
                if ensureUdp443BlockRule(configJSON: &configJSON, outboundTag: blackholeTag) {
                    messages.append("Added XHTTP UDP/443 block rule to force browser TCP fallback")
                }
            }

            guard let bootstrapAddresses = TunnelDNSPolicy.apply(to: &configJSON, resolveIPv4: resolveIPv4) else {
                return nil
            }
            messages.append("Configured system DNS over TCP through the selected proxy")
            guard TunnelIPv6Policy.apply(to: &configJSON) else { return nil }
            messages.append("Captured IPv6 is blocked; IPv4 remains available")
            let data = try JSONSerialization.data(withJSONObject: configJSON, options: [])
            return TunnelPreparedConfig(data: data, logMessages: messages, proxyUsesXhttp: proxyUsesXhttp,
                                        bootstrapAddresses: bootstrapAddresses)
        } catch {
            return nil
        }
    }

    public static func parseServerAddress(configJSON: [String: Any]) -> String? {
        guard let outbounds = configJSON["outbounds"] as? [[String: Any]] else {
            return nil
        }
        for outbound in outbounds {
            let tag = outbound["tag"] as? String
            let protocolType = outbound["protocol"] as? String
            guard tag == "proxy" || protocolType != "freedom" && protocolType != "blackhole" else {
                continue
            }
            guard let settings = outbound["settings"] as? [String: Any] else {
                continue
            }
            if let vnext = settings["vnext"] as? [[String: Any]],
               let address = vnext.first?["address"] as? String,
               !address.isEmpty {
                return address
            }
            if let servers = settings["servers"] as? [[String: Any]],
               let address = servers.first?["address"] as? String,
               !address.isEmpty {
                return address
            }
            if let address = settings["address"] as? String, !address.isEmpty {
                return address
            }
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

    private static func blackholeOutboundTag(configJSON: [String: Any]) -> String {
        guard let outbounds = configJSON["outbounds"] as? [[String: Any]] else {
            return "blackhole"
        }
        return outbounds.first(where: { outbound in
            (outbound["protocol"] as? String) == "blackhole"
        })?["tag"] as? String ?? "blackhole"
    }

    private static func ensureUdp443BlockRule(configJSON: inout [String: Any], outboundTag: String) -> Bool {
        var routing = configJSON["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        let alreadyExists = rules.contains { rule in
            (rule["type"] as? String) == "field" &&
            (rule["network"] as? String) == "udp" &&
            String(describing: rule["port"] ?? "") == "443" &&
            (rule["outboundTag"] as? String) == outboundTag
        }
        if alreadyExists {
            return false
        }
        rules.insert([
            "type": "field",
            "network": "udp",
            "port": "443",
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
