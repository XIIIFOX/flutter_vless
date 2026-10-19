import Foundation
import XCTest
@testable import flutter_vless_macos_tunnel_support

final class NativePrivacyTests: XCTestCase {
    func testCallerAPIStatsAndPolicyArePreservedThroughPrivatePreparation() throws {
        let api: [String: Any] = ["Tag": "caller-management", "Listen": "127.0.0.1:+10809", "Services": ["HandlerService", "StatsService", "RoutingService"]]
        let stats: [String: Any] = ["caller-metadata": ["keep": true]]
        let policy: [String: Any] = ["Levels": ["7": ["handshake": 3, "statsUserUplink": true]], "System": ["StatsOutboundUplink": false, "statsOutboundDownlink": false, "statsInboundUplink": true]]
        let raw: [String: Any] = ["API": api, "Stats": stats, "Policy": policy, "inbounds": [["protocol": "socks", "port": 10808]], "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "203.0.113.9", "port": 443]]], "log": ["access": "/private/canary", "dnsLog": true]]
        let credentials = try LocalProxyCredentials(username: "fixture-user", password: "fixture-password")
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: raw), credentials: credentials))
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        XCTAssertEqual(output["api"] as? NSDictionary, api as NSDictionary)
        XCTAssertEqual(output["stats"] as? NSDictionary, stats as NSDictionary)
        XCTAssertEqual(output["policy"] as? NSDictionary, policy as NSDictionary)
        XCTAssertEqual((output["log"] as? [String: Any])?["access"] as? String, "none")
        XCTAssertEqual((output["log"] as? [String: Any])?["dnsLog"] as? Bool, false)
        XCTAssertEqual((output["inbounds"] as? [[String: Any]])?.first?["port"] as? Int, 10810)
    }

    func testExistingNullLevelsOnlyAndExplicitCounterFlagsDoNotAcquireDefaults() {
        let policies: [Any] = [NSNull(), [String: Any](), ["levels": ["0": ["handshake": 7]]], ["system": NSNull()], ["System": ["StatsOutboundUplink": false, "statsOutboundDownlink": false]]]
        for policy in policies {
            for stats: Any in [NSNull(), [String: Any](), ["caller-field": "preserved"]] {
                var config: [String: Any] = ["Policy": policy, "STATS": stats]
                XCTAssertTrue(XrayPrivacyConfig.apply(to: &config))
                XCTAssertNotNil(config["policy"])
                XCTAssertNotNil(config["stats"])
                if let actualPolicy = config["policy"], let actualStats = config["stats"] {
                    XCTAssertEqual(["value": actualPolicy] as NSDictionary, ["value": policy] as NSDictionary)
                    XCTAssertEqual(["value": actualStats] as NSDictionary, ["value": stats] as NSDictionary)
                }
            }
        }
    }

    func testStatisticsDefaultsOnlyFillAbsentRootSections() throws {
        var missing: [String: Any] = [:]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &missing))
        XCTAssertEqual(missing["stats"] as? NSDictionary, [:] as NSDictionary)
        let system = try XCTUnwrap((missing["policy"] as? [String: Any])?["system"] as? [String: Any])
        XCTAssertEqual(system as NSDictionary, ["statsInboundUplink": true, "statsInboundDownlink": true,
                                               "statsOutboundUplink": true, "statsOutboundDownlink": true] as NSDictionary)
        var explicitNull: [String: Any] = ["stats": NSNull(), "policy": NSNull()]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &explicitNull))
        XCTAssertTrue(explicitNull["stats"] is NSNull)
        XCTAssertTrue(explicitNull["policy"] is NSNull)
        var levelsOnly: [String: Any] = ["policy": ["levels": ["7": ["handshake": 3]]]]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &levelsOnly))
        XCTAssertEqual(levelsOnly["stats"] as? NSDictionary, [:] as NSDictionary)
        XCTAssertEqual(levelsOnly["policy"] as? NSDictionary, ["levels": ["7": ["handshake": 3]]] as NSDictionary)
    }

    func testSharedFullConfigServiceCorpusPreservesCallerSubtrees() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/full-config.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/full-config.json"))) as? [[String: Any]])
        let credentials = try LocalProxyCredentials(username: "fixture-user", password: "fixture-password")
        for item in cases {
            let source = try XCTUnwrap(item["config"] as? [String: Any])
            let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: credentials, resolveIPv4: { _ in "203.0.113.9" }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            for name in ["api", "stats", "policy"] {
                let key = source.keys.first { XrayJSONField.matches($0, name) }
                if let key, let expected = source[key] {
                    let actual = try XCTUnwrap(output[name], "Missing caller service section: \(item["name"] as? String ?? "fixture")")
                    XCTAssertEqual(["value": actual] as NSDictionary, ["value": expected] as NSDictionary)
                } else if name == "api" {
                    XCTAssertNil(output[name], "Apple must not create a management listener for UI counters")
                }
            }
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), data)
        }
    }

    func testEveryLogLevelAndMissingLogDisableContentSinks() {
        for level in [nil, "debug", "info", "warning", "ERROR", "none"] as [String?] {
            var config: [String: Any] = [:]
            if let level { config["LOG"] = ["LogLevel": level, "Access": "/private/canary", "Error": "", "DNSLOG": true] }
            XCTAssertTrue(XrayPrivacyConfig.apply(to: &config))
            let log = config["log"] as! [String: Any]
            XCTAssertEqual(log["access"] as? String, "none")
            XCTAssertEqual(log["error"] as? String, "none")
            XCTAssertEqual(log["dnsLog"] as? Bool, false)
            XCTAssertEqual(log["loglevel"] as? String, ["ERROR", "none"].contains(level) ? level?.lowercased() : "warning")
        }
    }

    func testAllStreamCopiesDisableRealityPrintsAndKeyFilesWithoutChangingCredentials() throws {
        let stream: [String: Any] = [
            "TLSSettings": ["MasterKeyLog": "/private/tls-canary", "serverName": "sni-canary.invalid"],
            "RealitySettings": ["SHOW": true, "masterKeyLog": "/private/reality-canary", "publicKey": "key-canary"],
            "XHTTPSettings": ["headers": ["Log": "header-canary", "SHOW": "keep"],
                              "Extra": ["DownloadSettings": ["RealitySettings": ["SHOW": true, "MasterKeyLog": "nested-canary"]]]]
        ]
        var config: [String: Any] = ["Inbounds": [["StreamSettings": stream]], "Outbounds": [["StreamSettings": stream, "settings": ["password": "password-canary", "id": "uuid-canary"]]]]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config))
        for key in ["inbounds", "outbounds"] {
            let entry = (config[key] as! [[String: Any]])[0]
            let prepared = entry["streamSettings"] as! [String: Any]
            let reality = prepared["realitySettings"] as! [String: Any]
            XCTAssertEqual(reality["show"] as? Bool, false)
            XCTAssertEqual(reality["masterKeyLog"] as? String, "")
            XCTAssertEqual(reality["publicKey"] as? String, "key-canary")
            let tls = prepared["tlsSettings"] as! [String: Any]
            XCTAssertEqual(tls["masterKeyLog"] as? String, "")
            XCTAssertEqual(tls["serverName"] as? String, "sni-canary.invalid")
            let http = prepared["xhttpSettings"] as! [String: Any]
            XCTAssertEqual(http["headers"] as? [String: String], ["Log": "header-canary", "SHOW": "keep"])
            let download = (http["extra"] as! [String: Any])["downloadSettings"] as! [String: Any]
            XCTAssertEqual((download["realitySettings"] as! [String: Any])["show"] as? Bool, false)
        }
        XCTAssertEqual(((config["outbounds"] as! [[String: Any]])[0]["settings"] as! [String: String])["password"], "password-canary")
    }

    func testRealmFinalMaskDisablesKeyFileAndQuicDebug() {
        var config: [String: Any] = ["outbounds": [["streamSettings": ["FinalMask": [
            "QuicParams": ["Debug": true],
            "UDP": [["Type": "realm", "Settings": ["TLSConfig": ["MasterKeyLog": "realm-key-canary", "serverName": "sni-canary"]]]]
        ]]]]]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config))
        let stream = (config["outbounds"] as! [[String: Any]])[0]["streamSettings"] as! [String: Any]
        let mask = stream["finalmask"] as! [String: Any]
        XCTAssertEqual((mask["quicParams"] as! [String: Any])["debug"] as? Bool, false)
        let settings = (mask["udp"] as! [[String: Any]])[0]["settings"] as! [String: Any]
        let tls = settings["tlsConfig"] as! [String: Any]
        XCTAssertEqual(tls["masterKeyLog"] as? String, "")
        XCTAssertEqual(tls["serverName"] as? String, "sni-canary")
    }

    func testAmbiguousAndMalformedPrivacyObjectsAreRejected() {
        let cases: [[String: Any]] = [
            ["log": [:], "LOG": [:]], ["log": ["access": "none", "ACCESS": ""]],
            ["outbounds": [["streamSettings": ["realitySettings": ["show": false, "Show": true]]]]],
            ["log": "canary"], ["inbounds": ["canary"]],
            ["outbounds": [["streamSettings": ["xhttpSettings": ["extra": ["downloadSettings": "canary"]]]]]]
        ]
        for var config in cases { XCTAssertFalse(XrayPrivacyConfig.apply(to: &config)) }
    }

    func testDynamicValuesCannotReachProviderFileOrSnapshot() throws {
        let secret = "uuid-password-domain-canary.invalid"
        let error = NSError(domain: secret, code: 27, userInfo: [NSLocalizedDescriptionKey: secret])
        let message: NativeDiagnosticMessage = "Stage connect port=\(1080) ok=\(true) name=\(secret, privacy: .public) error=\(error) bytes=\(Data(secret.utf8))"
        XCTAssertEqual(message.text, "Stage connect port=1080 ok=true name=<redacted> error=<redacted> bytes=<redacted>")
        XCTAssertFalse(NativeLogPrivacy.operationError(error).description.contains(secret))
        XCTAssertEqual(NativeLogPrivacy.runtimeEvent(secret).text, "Xray diagnostic details omitted")
        XCTAssertEqual(NativeLogPrivacy.runtimeEvent("Xray startup failed: build configuration").text, "Xray startup failed: build configuration")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let legacy = directory.appendingPathComponent("flutter_vless_tunnel_debug.log")
        try secret.write(to: legacy, atomically: true, encoding: .utf8)
        NativeLogPrivacy.removeLegacyProviderLog(in: directory)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacy.path))
        let target = directory.appendingPathComponent(NativeLogPrivacy.providerLogFilename)
        try TunnelFileLog.append(message.text, to: target)
        XCTAssertFalse(try String(contentsOf: target).contains(secret))
        XCTAssertNotEqual(NativeLogPrivacy.snapshotCommand, "xray_debug")
    }
}
