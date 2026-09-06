import Foundation
import XCTest
@testable import flutter_vless_tunnel_support

final class NativePrivacyTests: XCTestCase {
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
