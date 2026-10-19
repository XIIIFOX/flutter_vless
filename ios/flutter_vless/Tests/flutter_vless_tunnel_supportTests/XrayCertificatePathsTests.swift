import Foundation
import XCTest
@testable import flutter_vless_privacy

final class XrayCertificatePathsTests: XCTestCase {
    private func directory() throws -> URL {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: path) }
        return path
    }

    func testSharedCertificatePathsBindOnlyCoreBuiltFileFields() throws {
        func replacing(_ object: Any, path: ArraySlice<String>, root: String) -> Any {
            guard let component = path.first else { return root + "/" + (object as! String) }
            if var map = object as? [String: Any] {
                map[component] = replacing(map[component]!, path: path.dropFirst(), root: root); return map
            }
            var list = object as! [Any]; let index = Int(component)!
            list[index] = replacing(list[index], path: path.dropFirst(), root: root); return list
        }
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/certificate-paths.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/certificate-paths.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 8)
        let base = try directory().path
        for item in cases {
            let source = try XCTUnwrap(item["config"] as? [String: Any])
            let input = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            var expected: Any = source
            for pointer in try XCTUnwrap(item["bind"] as? [String]) {
                let path = pointer.split(separator: "/").map { String($0).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~") }
                expected = replacing(expected, path: ArraySlice(path), root: base)
            }
            let bound = try XrayCertificatePaths.bind(configData: input, directory: base)
            XCTAssertEqual(try JSONSerialization.jsonObject(with: bound) as? NSDictionary, expected as? NSDictionary, "Only declared Core-built file fields may change: \(item["name"] ?? "")")
            XCTAssertEqual(try XrayCertificatePaths.bind(configData: bound, directory: base), bound)
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), input)
        }
    }

    func testNilDirectoryKeepsLegacyBytesAndCertificateEnvironment() throws {
        let input = Data("not-json: legacy validation owns this".utf8)
        let before = ["XRAY_LOCATION_CERT", "xray.location.cert"].map { ProcessInfo.processInfo.environment[$0] }
        XCTAssertEqual(try XrayCertificatePaths.bind(configData: input, directory: nil), input)
        let base = try directory().path
        let config = Data(#"{"outbounds":[{"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"fixture.pem"}]}}}]}"#.utf8)
        _ = try XrayCertificatePaths.bind(configData: config, directory: base)
        XCTAssertEqual(["XRAY_LOCATION_CERT", "xray.location.cert"].map { ProcessInfo.processInfo.environment[$0] }, before)
    }

    func testDirectoryValidationRejectsBeforeAnyPublication() throws {
        let base = try directory()
        let file = base.appendingPathComponent("ordinary-file")
        try Data().write(to: file)
        let input = Data(#"{"outbounds":[{"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"fixture.pem"}]}}}]}"#.utf8)
        for invalid in ["", "relative", base.appendingPathComponent("missing").path, file.path, base.path + "\0hidden"] {
            XCTAssertThrowsError(try XrayCertificatePaths.bind(configData: input, directory: invalid))
        }
        XCTAssertNoThrow(try XrayCertificatePaths.bind(configData: Data("{}".utf8), directory: base.path))
    }

    func testRelativeJoinMatchesCoreWithoutChangingAbsoluteInlineOrOpaqueFields() throws {
        let base = try directory().path
        let relative = ["sub/../fixture.pem", "../sibling.pem", "~literal.pem", "back\\slash.pem"]
        let expected = [base + "/fixture.pem", URL(fileURLWithPath: base).deletingLastPathComponent().path + "/sibling.pem", base + "/~literal.pem", base + "/back\\slash.pem"]
        let absolute = "/caller/link/../absolute.pem"
        let certificates: [[String: Any]] = relative.map { ["certificateFile": $0, "keyFile": "", "certificate": ["inline untouched"]] } + [["certificateFile": absolute, "keyFile": NSNull()]]
        let source: [String: Any] = ["outbounds": [["streamSettings": ["security": "tls", "tlsSettings": ["certificates": certificates]]]], "custom": ["certificateFile": "opaque.pem"]]
        let input = try JSONSerialization.data(withJSONObject: source)
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: XrayCertificatePaths.bind(configData: input, directory: base)) as? [String: Any])
        let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
        let tls = try XCTUnwrap((outbounds[0]["streamSettings"] as? [String: Any])?["tlsSettings"] as? [String: Any])
        let actual = try XCTUnwrap(tls["certificates"] as? [[String: Any]])
        XCTAssertEqual(actual.prefix(4).compactMap { $0["certificateFile"] as? String }, expected)
        XCTAssertEqual(actual.last?["certificateFile"] as? String, absolute)
        XCTAssertEqual(actual[0]["certificate"] as? [String], ["inline untouched"], "A file still takes precedence over inline certificate data")
        XCTAssertEqual(output["custom"] as? NSDictionary, source["custom"] as? NSDictionary)
    }

    func testFoldedFieldsAndNulAreScopedToEffectiveTLS() throws {
        let base = try directory().path
        let source: [String: Any] = ["OuTbOuNdS": [["StReAmSeTtInGs": ["SeCuRiTy": "TLS", "TlSsEtTiNgS": ["CeRtIfIcAtEs": [["CeRtIfIcAtEfIlE": "fixture.pem", "KeYfIlE": "fixture.key"]]]]]]]
        let result = try XrayCertificatePaths.bind(configData: JSONSerialization.data(withJSONObject: source), directory: base)
        let expected: [String: Any] = ["OuTbOuNdS": [["StReAmSeTtInGs": ["SeCuRiTy": "TLS", "TlSsEtTiNgS": ["CeRtIfIcAtEs": [["CeRtIfIcAtEfIlE": base + "/fixture.pem", "KeYfIlE": base + "/fixture.key"]]]]]]]
        XCTAssertEqual(try JSONSerialization.jsonObject(with: result) as? NSDictionary, expected as NSDictionary)
        let invalid: [String: Any] = ["outbounds": [["streamSettings": ["security": "tls", "tlsSettings": ["certificates": [["certificateFile": "private\0canary.pem"]]]]]]]
        XCTAssertThrowsError(try XrayCertificatePaths.bind(configData: JSONSerialization.data(withJSONObject: invalid), directory: base))
        let inactive = Data(#"{"outbounds":[{"streamSettings":{"security":"none","tlsSettings":{"certificates":[{"certificateFile":"bad\u0000inactive.pem"}]}}}]}"#.utf8)
        XCTAssertEqual(try XrayCertificatePaths.bind(configData: inactive, directory: base), inactive)
    }

    func testTypedMaskTLSUsesFoldedKeysAndKeepsOpaqueLookalikes() throws {
        let base = try directory().path
        let source = Data(#"{"outbounds":[{"streamSettings":{"finalmask":{"udp":[{"TyPe":"ReAlM","SeTtInGs":{"TlSCoNfIg":{"CeRtIfIcAtEs":[{"CeRtIfIcAtEfIlE":"fixture.pem","KeYfIlE":"fixture.key","custom":{"certificateFile":"opaque.pem"}}]}}},{"type":"XdNs","settings":{"ReSoLvErS":[{"TlSCoNfIg":{"certificates":[{"certificateFile":"fixture.pem"},{"certificateFile":null,"keyFile":""}]}}]}},{"type":"xdnſ","settings":{"resolvers":[{"tlsConfig":{"certificates":[{"certificateFile":"opaque.pem"}]}}]}}],"tcp":[{"type":"realm","settings":{"tlsConfig":{"certificates":[{"certificateFile":"opaque.pem"}]}}}]}},"custom":{"tlsConfig":{"certificates":[{"certificateFile":"opaque.pem"}]}}}]}"#.utf8)
        var expected = String(decoding: source, as: UTF8.self)
        for name in ["fixture.pem", "fixture.key"] {
            expected = expected.replacingOccurrences(of: "\"" + name + "\"", with: "\"" + base + "/" + name + "\"")
        }
        let bound = try XrayCertificatePaths.bind(configData: source, directory: base)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: bound) as? NSDictionary,
                       try JSONSerialization.jsonObject(with: Data(expected.utf8)) as? NSDictionary)
        XCTAssertEqual(try XrayCertificatePaths.bind(configData: bound, directory: base), bound)
    }

    func testTypedMaskFileValidationDoesNotInspectOtherOwners() throws {
        let base = try directory().path
        for type in ["realm", "xdns"] {
            for certificate in [#"{"certificateFile":"bad\u0000.pem"}"#,
                                #"{"certificateFile":"fixture.pem","CERTIFICATEFILE":"other.pem"}"#] {
                let tls = #"{"certificates":["# + certificate + "]}"
                let settings = type == "realm" ? #"{"tlsConfig":"# + tls + "}" : #"{"resolvers":[{"tlsConfig":"# + tls + "}]}"
                let source = #"{"inbounds":[{"streamSettings":{"finalmask":{"udp":[{"type":""# + type + #"","settings":"# + settings + "}]}}}]}"
                XCTAssertThrowsError(try XrayCertificatePaths.bind(configData: Data(source.utf8), directory: base), type)
            }
        }
        for source in [#"{"outbounds":[{"streamSettings":{"finalmask":{"udp":[{"type":"noise","settings":{"tlsConfig":{"certificates":[{"certificateFile":"bad\u0000.pem"}]}}}]}}}]}"#,
                       #"{"outbounds":[{"streamSettings":{"finalmask":{"udp":[{"type":"realm","settings":{"tlsConfig":null}},{"type":"xdns","settings":{"resolvers":null}}]}}}]}"#] {
            let data = Data(source.utf8)
            XCTAssertEqual(try XrayCertificatePaths.bind(configData: data, directory: base), data)
        }
    }

    func testTypedMaskTLSFollowsExistingEffectiveDownloadBuildSelection() throws {
        let base = try directory().path
        let source = Data(#"{"outbounds":[{"streamSettings":{"network":"tcp","xhttpSettings":{"downloadSettings":{"finalmask":{"udp":[{"type":"realm","settings":{"tlsConfig":{"certificates":[{"certificateFile":"missing-outer.pem"}]}}}]}},"extra":{"downloadSettings":{"finalmask":{"udp":[{"type":"realm","settings":{"tlsConfig":{"certificates":[{"certificateFile":"fixture.pem"}]}}}]}}}},"splithttpSettings":{"downloadSettings":{"finalmask":{"udp":[{"type":"realm","settings":{"tlsConfig":{"certificates":[{"certificateFile":"missing-alias.pem"}]}}}]}}}}}]}"#.utf8)
        let expected = Data(String(decoding: source, as: UTF8.self).replacingOccurrences(of: "\"fixture.pem\"", with: "\"" + base + "/fixture.pem\"").utf8)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: XrayCertificatePaths.bind(configData: source, directory: base)) as? NSDictionary,
                       try JSONSerialization.jsonObject(with: expected) as? NSDictionary)
        let inactive = Data(#"{"outbounds":[{"streamSettings":{"xhttpSettings":{"extra":null,"downloadSettings":{"finalmask":{"udp":[{"type":"realm","settings":{"tlsConfig":{"certificates":[{"certificateFile":"bad\u0000.pem"}]}}}]}}}}}]}"#.utf8)
        XCTAssertEqual(try XrayCertificatePaths.bind(configData: inactive, directory: base), inactive)
    }

    func testBothNativeChannelsBindBeforeQueuingAndPublishCapability() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/certificate-paths.json").path) { break }
            root.deleteLastPathComponent()
        }
        for path in ["ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift",
                     "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift"] {
            let source = try String(contentsOf: root.appendingPathComponent(path))
            for method in ["getServerDelay", "startVless"] {
                let start = try XCTUnwrap(source.range(of: "    private func " + method + "(call:"))
                let remaining = source[start.upperBound...]
                let binding = try XCTUnwrap(remaining.range(of: "XrayCertificatePaths.bind(configData:"))
                let queue = try XCTUnwrap(remaining.range(of: "let operation = commands.submit"))
                XCTAssertLessThan(binding.lowerBound, queue.lowerBound, "Certificate paths must validate before any session mutation")
                XCTAssertTrue(remaining[..<binding.lowerBound].contains("certificate_assets_directory"))
            }
            XCTAssertTrue(source.contains("config: effectiveConfig,"), "Delay must consume the bound profile")
            // Dart queries this distinct security channel before sending a non-null root.
            // A flag under getCapabilities must never satisfy this public contract.
            let securityCase = try XCTUnwrap(source.range(of: "        case \"getSecurityCapabilities\":"), path)
            let securityTail = source[securityCase.upperBound...]
            let nextCase = try XCTUnwrap(securityTail.range(of: "\n        case "), path)
            let securityBody = securityTail[..<nextCase.lowerBound]
            XCTAssertTrue(securityBody.contains("\"certificateAssetsDirectory\": true"), path)
            XCTAssertFalse(securityBody.contains("result(capabilities())"), path)
            XCTAssertTrue(source.contains("result[\"certificateAssetsDirectory\"] = directory"))
            XCTAssertTrue(source.contains("manager.certificateAssetsDirectory = certificateAssetsDirectory"))
        }
    }
}
