import Foundation
import XCTest
@testable import flutter_vless_macos_tunnel_support

final class PrivateBalancerDiagnosticsTests: XCTestCase {
    func testSnapshotsBoundOnlyValidatedOrdinals() {
        let rows = Data("1,1,5\n2,1,7\n3,1,5\n".utf8)
        XCTAssertEqual(PrivateBalancerDiagnostics.snapshot(rows, maxBytes: 100, maxLines: 2), "2,1,7\n3,1,5")
        XCTAssertEqual(PrivateBalancerDiagnostics.snapshot(rows, maxBytes: 5, maxLines: 3), "3,1,5")
        XCTAssertEqual(PrivateBalancerDiagnostics.snapshot(rows, maxBytes: 4, maxLines: 3), "")

        for invalid in ["1,1,1\n1,1,4", "1,1,proxy.example", "1,0,3", "1,01,3", "1,1,9223372036854775808"] {
            XCTAssertEqual(PrivateBalancerDiagnostics.snapshot(Data(invalid.utf8), maxBytes: 100, maxLines: 1), "")
        }
        XCTAssertEqual(PrivateBalancerDiagnostics.snapshot(Data(repeating: 49, count: 18_001), maxBytes: 18_001, maxLines: 300), "")
    }

    func testStartupKeepsTheGeneratedScopeSeparateFromAnAuthoredInbound() async throws {
        let authoredTag = LocalProxyAccessPolicy.managedTagPrefix
        let source = try JSONSerialization.data(withJSONObject: [
            "inbounds": [["tag": authoredTag, "protocol": "socks", "listen": "127.0.0.1", "port": 12345]],
            "outbounds": [["tag": "direct", "protocol": "freedom"]],
            "dns": ["servers": ["1.1.1.1"]]
        ])
        let credentials = try LocalProxyCredentials(username: "fixture-user", password: "fixture-password")
        let path = TunnelEndpointPath(generation: 1, interfaceIndex: 4, interfaceName: "en0",
            supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
        let prepared = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: source,
            credentials: credentials, tcpPortAvailable: { _ in true }, endpointPath: path,
            resolveCandidates: { _ in throw TunnelXrayConfigPreparer.StartupError.endpointUnavailable }, attempts: 1)
        let config = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        let inbounds = try XCTUnwrap(config["inbounds"] as? [[String: Any]])
        let managedTag = try XCTUnwrap(prepared.managedInboundTag)
        XCTAssertEqual(inbounds.first?["tag"] as? String, managedTag)
        XCTAssertNotEqual(managedTag, authoredTag)
        XCTAssertEqual(inbounds.dropFirst().first?["tag"] as? String, authoredTag)
        XCTAssertEqual((inbounds.first?["settings"] as? [String: Any])?["auth"] as? String, "password")
    }
}
