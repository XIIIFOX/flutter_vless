import XCTest
@testable import flutter_vless_macos_tunnel_support

final class TunnelEndpointResolverTests: XCTestCase {
    private let host = "vpn.example.com"

    func testEncryptedBootstrapSmokeWhenRequested() async throws {
        guard ProcessInfo.processInfo.environment["FLUTTER_VLESS_TEST_BOOTSTRAP_NETWORK"] == "1" else {
            throw XCTSkip("Opt-in public endpoint check; no VPN or route changes")
        }
        let address = try await TunnelEndpointResolver.encryptedLookup("example.com")
        XCTAssertNotNil(address)
    }

    func testSystemSuccessDoesNotUsePublicFallback() async throws {
        let address = try await TunnelEndpointResolver.resolveIPv4(host,
            system: { _ in "192.0.2.7" },
            fallback: { _ in XCTFail("Successful system resolution must remain authoritative"); return nil })
        XCTAssertEqual(address, "192.0.2.7")
    }

    func testUnavailableSystemResolverUsesEndpointOnlyFallback() async throws {
        var requested: [String] = []
        var messages: [String] = []
        let address = try await TunnelEndpointResolver.resolveIPv4(host,
            system: { _ in nil }, fallback: { requested.append($0); return "192.0.2.8" },
            event: { messages.append($0.text) })
        XCTAssertEqual(requested, [host])
        XCTAssertEqual(address, "192.0.2.8")
        XCTAssertEqual(messages.count, 2)
        XCTAssertFalse(messages.joined().contains(host))
        XCTAssertFalse(messages.joined().contains("192.0.2.8"))
    }

    func testLocalNamesNeverReachPublicFallback() async throws {
        for name in ["router", "router.local", "router.LOCAL.", "vpn.internal", "vpn.home.arpa", "vpn.invalid", "bad..name", "a/b.example.com"] {
            let address = try await TunnelEndpointResolver.resolveIPv4(name,
                system: { _ in nil }, fallback: { _ in XCTFail("Private/invalid name leaked"); return nil })
            XCTAssertNil(address)
        }
    }

    func testFallbackFailureIsRetryableButCancellationPropagates() async throws {
        let result = try await TunnelEndpointResolver.resolveIPv4(host,
            system: { _ in nil }, fallback: { _ in throw URLError(.timedOut) })
        XCTAssertNil(result)
        do {
            _ = try await TunnelEndpointResolver.resolveIPv4(host,
                system: { _ in nil }, fallback: { _ in throw CancellationError() })
            XCTFail("Cancellation must not retry or install routes")
        } catch { XCTAssertTrue(error is CancellationError) }
    }

    func testSystemLookupDeadlineAndCancellation() async throws {
        // Reserved .invalid names never target a real VPN server. A zero deadline
        // exercises DNSServiceRef cleanup regardless of resolver availability.
        let start = Date()
        let result = try await SystemEndpointLookup.resolve("bootstrap.invalid", timeout: 0)
        XCTAssertNil(result)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        let task = Task { try await SystemEndpointLookup.resolve("bootstrap.invalid", timeout: 30) }
        task.cancel()
        do { _ = try await task.value; XCTFail("Cancelled lookup completed") }
        catch { XCTAssertTrue(error is CancellationError) }
    }

    func testResponseRequiresMatchingQuestionAndSuccessfulStatus() throws {
        let record: [String: Any] = ["name": host + ".", "type": 1, "data": "192.0.2.9"]
        XCTAssertEqual(TunnelEndpointResolver.address(in: try response([record]), for: host), "192.0.2.9")
        XCTAssertNil(TunnelEndpointResolver.address(in: try response([record], status: 3), for: host))
        XCTAssertNil(TunnelEndpointResolver.address(in: try response([record], question: "other.example.com"), for: host))
        XCTAssertNil(TunnelEndpointResolver.address(in: Data("{}".utf8), for: host))
        XCTAssertNil(TunnelEndpointResolver.address(in: Data(repeating: 32, count: 65_537), for: host))
    }

    func testCNAMEChainAcceptsOnlyRelatedIPv4Answer() throws {
        let records: [[String: Any]] = [
            ["name": "unrelated.example.com.", "type": 1, "data": "192.0.2.99"],
            ["name": "edge.example.com.", "type": 28, "data": "2001:db8::1"],
            ["name": "edge.example.com.", "type": 1, "data": "192.0.2.10"],
            ["name": host.uppercased() + ".", "type": 5, "data": "edge.example.com."]
        ]
        XCTAssertEqual(TunnelEndpointResolver.address(in: try response(records), for: host), "192.0.2.10")
        XCTAssertNil(TunnelEndpointResolver.address(in: try response(Array(records.prefix(3))), for: host))
        let loop: [[String: Any]] = [
            ["name": host, "type": 5, "data": "edge.example.com."],
            ["name": "edge.example.com.", "type": 5, "data": host]
        ]
        XCTAssertNil(TunnelEndpointResolver.address(in: try response(loop), for: host))
        XCTAssertNil(TunnelEndpointResolver.address(in: try response([["name": host, "type": 1, "data": "999.1.1.1"]]), for: host))
    }

    func testAsyncPreparationResolvesTransportNamesOnlyAndPreservesSNI() async throws {
        let input = Data(#"{"inbounds":[{"protocol":"socks","port":10808}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"fixture-user"}]}]},"streamSettings":{"security":"reality","realitySettings":{"serverName":"sni.example.com"},"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"download.example.com"}}}}],"routing":{"rules":[{"domain":["domain:ru"],"outboundTag":"proxy"}]}}"#.utf8)
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        var names: [String] = []
        let prepared = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
            resolveIPv4: {
                await Task.yield()
                names.append($0)
                return $0 == "vpn.example.com" ? "192.0.2.11" : "192.0.2.12"
            })
        XCTAssertEqual(names, ["vpn.example.com", "download.example.com"])
        XCTAssertEqual(prepared.bootstrapAddresses, ["192.0.2.11", "192.0.2.12"])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        let outbounds = try XCTUnwrap(json["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual((stream["realitySettings"] as? [String: Any])?["serverName"] as? String, "sni.example.com")
    }

    func testCancellationDuringAsyncResolutionCannotPublishRuntime() async throws {
        let waiting = expectation(description: "endpoint lookup entered")
        let input = Data(#"{"inbounds":[{"protocol":"socks","port":10808}],"outbounds":[{"protocol":"http","settings":{"address":"vpn.example.com","port":443}}]}"#.utf8)
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        let task = Task {
            try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
                resolveIPv4: { _ in
                    waiting.fulfill()
                    try await Task.sleep(nanoseconds: 30_000_000_000)
                    return "192.0.2.13"
                }, retryDelay: { XCTFail("Cancelled lookup must not retry") })
        }
        await fulfillment(of: [waiting], timeout: 2)
        task.cancel()
        do { _ = try await task.value; XCTFail("Cancelled bootstrap published a runtime") }
        catch { XCTAssertTrue(error is CancellationError) }
    }

    private func response(_ answers: [[String: Any]], status: Int = 0, question: String? = nil) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "Status": status, "TC": false,
            "Question": [["name": question ?? host + ".", "type": 1]], "Answer": answers
        ])
    }
}
