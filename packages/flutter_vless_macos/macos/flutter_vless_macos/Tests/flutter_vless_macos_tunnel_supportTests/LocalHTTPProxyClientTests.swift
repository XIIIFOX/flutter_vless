import XCTest
@testable import flutter_vless_macos_tunnel_support

final class LocalHTTPProxyClientTests: XCTestCase {
    func testCredentialsAreScopedToConnectHandshake() throws {
        let credentials = try LocalProxyCredentials(username: "user", password: "secret")
        let bytes = try LocalHTTPProxyClient.connectRequest(host: "origin.invalid", port: 443, credentials: credentials)
        let request = String(decoding: bytes, as: UTF8.self)
        XCTAssertTrue(request.hasPrefix("CONNECT origin.invalid:443 HTTP/1.1\r\n"))
        XCTAssertTrue(request.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"))
        XCTAssertFalse(request.contains("secret"))
        let noauth = try LocalHTTPProxyClient.connectRequest(host: "origin.invalid", port: 80, credentials: nil)
        XCTAssertFalse(String(decoding: noauth, as: UTF8.self).contains("Proxy-Authorization"))
    }
    func testRejectsHeaderInjectionAndMalformedDestination() {
        for host in ["origin.invalid\r\nX-Evil: yes", "origin.invalid/path", "u@origin.invalid", ""] {
            XCTAssertThrowsError(try LocalHTTPProxyClient.connectRequest(host: host, port: 443, credentials: nil))
        }
        XCTAssertThrowsError(try LocalHTTPProxyClient.connectRequest(host: "origin.invalid", port: 0, credentials: nil))
    }
}
