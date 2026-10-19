import Foundation
import CryptoKit
#if ROUTING_MACOS
import flutter_vless_macos_privacy
#else
import flutter_vless_privacy
#endif

@main struct NativeRoutingSpecTest {
    static let managedTag = "managed-private-canary"
    static let authUser = "session-user-canary"
    static var checks = 0

    static func document() -> [String: Any] {
        ["inbounds": [
            ["tag": managedTag, "listen": "127.0.0.1", "port": 19891, "protocol": "socks",
             "settings": ["auth": "password", "accounts": [["user": authUser, "pass": "session-password-canary"]], "udp": true]],
            ["tag": "caller", "listen": "127.0.0.1", "port": 19892, "protocol": "socks", "settings": ["auth": "noauth"]],
            ["listen": "127.0.0.1", "port": 19893, "protocol": "socks", "settings": ["auth": "noauth"]]
        ], "outbounds": [["tag": "blocked", "protocol": "blackhole"], ["tag": "selected", "protocol": "freedom"]],
         "routing": ["rules": [
            ["inboundTag": [managedTag], "ip": ["198.18.0.2/32"], "outboundTag": "selected"],
            ["inboundTag": ["caller"], "outboundTag": "blocked"],
            ["inboundTag": ["private-bootstrap"], "outboundTag": "blocked"]
         ]], "dns": ["hosts": ["source-canary.invalid": "192.0.2.1"], "servers": ["tcp://1.1.1.1"]],
         "api": ["services": ["StatsService"]]]
    }

    static func encoded(_ document: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys, .prettyPrinted])
    }

    static func freeze(_ data: Data, intent: NativeRoutingIntent? = try! NativeRoutingIntent(sourceInboundIndex: 0, defaultOutboundTag: "selected"),
                       mapped: Int? = 1, managed: Int = 0, guards: [Int] = [0, 2],
                       tag: String = managedTag, user: String = authUser) throws -> NativeRoutingEnvelope? {
        try NativeRoutingSpec.freeze(finalData: data, managedInboundIndex: managed, managedInboundTag: tag,
            authUser: user, intent: intent, sourceInboundFinalIndex: mapped, guardRuleIndices: guards)
    }

    static func rejected(_ body: () throws -> Void) {
        do { try body(); preconditionFailure("Invalid native metadata accepted") }
        catch {
            precondition(error is NativeRoutingSpecError)
            precondition(!error.localizedDescription.contains("canary"))
            precondition(!String(reflecting: error).contains("canary"))
            checks += 1
        }
    }

    static func main() throws {
        let original = try encoded(document())
        let intent = try NativeRoutingIntent(sourceInboundIndex: 0, defaultOutboundTag: "selected")
        let envelope = try freeze(original, intent: intent)!
        let metadata = try JSONSerialization.jsonObject(with: envelope.metadataData) as! [String: Any]
        let digest = SHA256.hash(data: original).map { String(format: "%02x", $0) }.joined()
        precondition(envelope.configurationData == original && envelope.sourceSHA256 == digest)
        precondition(metadata["source_sha256"] as? String == digest && metadata["version"] as? Int == 1)
        precondition(metadata["managed_inbound_index"] as? Int == 0 && metadata["managed_inbound_tag"] as? String == managedTag)
        precondition(metadata["auth_user"] as? String == authUser && metadata["source_inbound_index"] as? Int == 1)
        precondition(metadata["default_outbound_tag"] as? String == "selected" && metadata["guard_rule_indices"] as? [Int] == [0, 2])
        precondition(Set(metadata.keys) == ["version", "source_sha256", "managed_inbound_index", "managed_inbound_tag", "auth_user", "source_inbound_index", "default_outbound_tag", "guard_rule_indices"])
        precondition(intent.sourceInboundIndex == 0 && intent.defaultOutboundTag == "selected")
        precondition(!String(reflecting: envelope).contains("canary") && !String(describing: intent).contains("selected"))
        checks += 1

        // The digest covers exact frozen bytes, including otherwise irrelevant JSON whitespace.
        var differentBytes = original
        differentBytes.append(contentsOf: [0x20, 0x0a])
        let different = try freeze(differentBytes)!
        precondition(different.sourceSHA256 != envelope.sourceSHA256 && different.configurationData == differentBytes)
        precondition(original == envelope.configurationData)
        var releasedCopy = envelope.configurationData
        releasedCopy[releasedCopy.startIndex] = 0
        var metadataCopy = envelope.metadataData
        metadataCopy[metadataCopy.startIndex] = 0
        precondition(envelope.configurationData == original && envelope.metadataData.first == UInt8(ascii: "{"))
        checks += 1

        let mutable = NSMutableData(data: original)
        let borrowed = Data(referencing: mutable)
        let frozenBorrowed = try freeze(borrowed)!
        var zero: UInt8 = 0
        mutable.replaceBytes(in: NSRange(location: 0, length: 1), withBytes: &zero)
        precondition(frozenBorrowed.configurationData == original && frozenBorrowed.sourceSHA256 == digest)
        checks += 1

        // Caller JSON cannot opt itself in; nil trusted intent leaves the ordinary path alone.
        var callerEnabled = document()
        callerEnabled["nativeRoutingSpec"] = metadata
        callerEnabled["source_inbound_index"] = 2
        let callerCannotEnable = try freeze(try encoded(callerEnabled), intent: nil, mapped: nil)
        let ordinaryDoesNotDecode = try freeze(Data("not-json".utf8), intent: nil, mapped: nil)
        precondition(callerCannotEnable == nil && ordinaryDoesNotDecode == nil)
        let selected = try freeze(try encoded(callerEnabled))!
        let selectedMetadata = try JSONSerialization.jsonObject(with: selected.metadataData) as! [String: Any]
        precondition(selectedMetadata["source_inbound_index"] as? Int == 1)
        checks += 1

        for defaultTag: String? in [nil, ""] {
            let empty = try NativeRoutingIntent(sourceInboundIndex: nil, defaultOutboundTag: defaultTag)
            let result = try freeze(original, intent: empty, mapped: nil)!
            let fields = try JSONSerialization.jsonObject(with: result.metadataData) as! [String: Any]
            precondition(fields["source_inbound_index"] == nil && fields["default_outbound_tag"] == nil)
            precondition(fields["guard_rule_indices"] as? [Int] == [0, 2])
            checks += 1
        }
        let untagged = try freeze(original, mapped: 2)!
        let untaggedMetadata = try JSONSerialization.jsonObject(with: untagged.metadataData) as! [String: Any]
        precondition(untaggedMetadata["source_inbound_index"] as? Int == 2)
        checks += 1

        rejected { _ = try NativeRoutingIntent(sourceInboundIndex: -1) }
        for index in [-1, 0, 3, Int.max] { rejected { _ = try freeze(original, mapped: index) } }
        rejected { _ = try freeze(original, mapped: nil) }
        rejected { _ = try freeze(original, intent: NativeRoutingIntent(), mapped: 1) }
        for index in [-1, 3, Int.max] { rejected { _ = try freeze(original, managed: index) } }
        rejected { _ = try freeze(original, tag: "foreign-canary") }
        rejected { _ = try freeze(original, user: "foreign-canary") }
        rejected { _ = try freeze(original, tag: "") }
        rejected { _ = try freeze(original, user: "") }
        rejected { _ = try freeze(Data("not-json".utf8)) }
        rejected { _ = try freeze(Data("[]".utf8)) }
        for guards in [[-1], [3], [0, 0]] { rejected { _ = try freeze(original, guards: guards) } }
        for tag in ["missing-canary", "selected "] {
            rejected { _ = try freeze(original, intent: NativeRoutingIntent(defaultOutboundTag: tag), mapped: nil) }
        }
        var duplicate = document()
        var inputs = duplicate["inbounds"] as! [[String: Any]]
        inputs[1]["tag"] = managedTag
        duplicate["inbounds"] = inputs
        rejected { _ = try freeze(try encoded(duplicate)) }
        var duplicateOutput = document()
        var outputs = duplicateOutput["outbounds"] as! [[String: Any]]
        outputs.append(outputs[1]); duplicateOutput["outbounds"] = outputs
        rejected { _ = try freeze(try encoded(duplicateOutput)) }

        // Core identities compare UTF-8 bytes; Swift canonical equality must not grant a match.
        let composed = "native-\u{00e9}"
        let decomposed = "native-e\u{0301}"
        precondition(composed == decomposed && !composed.utf8.elementsEqual(decomposed.utf8))
        var unicodeOutput = document()
        unicodeOutput["outbounds"] = [["tag": composed, "protocol": "freedom"]]
        rejected { _ = try freeze(try encoded(unicodeOutput), intent: NativeRoutingIntent(defaultOutboundTag: decomposed), mapped: nil) }
        var unicodeInput = document()
        var unicodeInputs = unicodeInput["inbounds"] as! [[String: Any]]
        unicodeInputs[0]["tag"] = composed; unicodeInput["inbounds"] = unicodeInputs
        rejected { _ = try freeze(try encoded(unicodeInput), tag: decomposed) }
        unicodeInputs[0]["tag"] = managedTag
        unicodeInputs[0]["settings"] = ["auth": "password", "accounts": [["user": composed, "pass": "private-password-canary"]]]
        unicodeInput["inbounds"] = unicodeInputs
        rejected { _ = try freeze(try encoded(unicodeInput), user: decomposed) }

        // Types and identities of generated input/guard fields are checked before metadata is minted.
        for mutation: (inout [String: Any]) -> Void in [
            { $0["protocol"] = "http" }, { $0["listen"] = "0.0.0.0" }, { $0["port"] = true },
            { $0["port"] = 0 }, { $0["port"] = "19891-19892" },
            { $0["settings"] = ["auth": "noauth"] },
            { $0["settings"] = ["auth": "password", "accounts": [["user": authUser, "pass": ""]]] }
        ] {
            var bad = document(); var values = bad["inbounds"] as! [[String: Any]]
            mutation(&values[0]); bad["inbounds"] = values
            rejected { _ = try freeze(try encoded(bad)) }
        }
        for mutation: (inout [String: Any]) -> Void in [
            { $0["inboundTag"] = [] }, { $0["inboundTag"] = [""] }, { $0["inboundTag"] = [NSNull()] },
            { $0["outboundTag"] = "" }, { $0["balancerTag"] = "caller" }, { $0["webhook"] = [:] }
        ] {
            var bad = document(); var routing = bad["routing"] as! [String: Any]
            var values = routing["rules"] as! [[String: Any]]; mutation(&values[0]); routing["rules"] = values; bad["routing"] = routing
            rejected { _ = try freeze(try encoded(bad)) }
        }
        var folded = document()
        folded["INBOUNDS"] = folded.removeValue(forKey: "inbounds")
        let foldedResult = try freeze(try encoded(folded))!
        let foldedBytes = try encoded(folded)
        precondition(foldedResult.configurationData == foldedBytes)
        folded["inbounds"] = []
        rejected { _ = try freeze(try encoded(folded)) }
        checks += 1
        print("NATIVE_ROUTING_SPEC_PURE_PASS=\(checks)")
    }
}
