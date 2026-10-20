import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelEndpointResolverTests: XCTestCase {
    private let host = "vpn.example.com"

    func testTypedNumericAddressDerivesFamilyAndKeepsHonestSource() throws {
        let v4 = try XCTUnwrap(TunnelEndpointAddress(text: "192.0.2.7", source: .systemNameAnswer))
        XCTAssertEqual(v4.text, "192.0.2.7")
        XCTAssertEqual(v4.family, .ipv4)
        XCTAssertEqual(v4.source, .systemNameAnswer)
        let v6 = try XCTUnwrap(TunnelEndpointAddress(text: "2001:DB8::7", source: .systemNameAnswer))
        XCTAssertEqual(v6.text, "2001:db8::7")
        XCTAssertEqual(v6.family, .ipv6)
        // A system AAAA result does not identify whether DNS64 synthesized it.
        XCTAssertEqual(v6.source, .systemNameAnswer)
        let mapped = try XCTUnwrap(TunnelEndpointAddress(text: "::ffff:192.0.2.7", source: .systemNameAnswer))
        XCTAssertEqual(mapped.family, .ipv4)
        XCTAssertEqual(mapped.text, "192.0.2.7")
    }

    func testTypedNumericAddressRejectsTruncationJunkAndEncryptedIPv6() {
        for text in ["", "endpoint.example.com", "192.0.2.7\u{0}junk", "2001:db8::7\u{0}junk",
                     "192.0.2.7 trailing", " 192.0.2.7", "[2001:db8::7]", "fe80::7%en0", "2001:db8:::7"] {
            XCTAssertNil(TunnelEndpointAddress(text: text, source: .systemNameAnswer), text)
        }
        XCTAssertNil(TunnelEndpointAddress(text: "2001:db8::7", source: .encryptedIPv4Answer))
    }

    func testNamedEndpointKeepsIPv4FirstAndDoesNotQueryIPv6OrFallback() async throws {
        var calls: [TunnelEndpointAddress.Family] = []
        let result = try await TunnelEndpointResolver.resolveEndpoint(host, system: { _, family in
            calls.append(family)
            return "192.0.2.7"
        }, fallback: { _ in XCTFail("System IPv4 result must remain authoritative"); return nil })
        XCTAssertEqual(calls, [.ipv4])
        XCTAssertEqual(result?.text, "192.0.2.7")
        XCTAssertEqual(result?.source, .systemNameAnswer)
    }

    func testNamedEndpointUsesSystemIPv6BeforePublicIPv4Fallback() async throws {
        var calls: [TunnelEndpointAddress.Family] = []
        let result = try await TunnelEndpointResolver.resolveEndpoint(host, system: { name, family in
            XCTAssertEqual(name, self.host)
            calls.append(family)
            return family == .ipv4 ? nil : "2001:db8::7"
        }, fallback: { _ in XCTFail("Successful system AAAA must not reach public fallback"); return nil })
        XCTAssertEqual(calls, [.ipv4, .ipv6])
        XCTAssertEqual(result?.text, "2001:db8::7")
        XCTAssertEqual(result?.family, .ipv6)
        XCTAssertEqual(result?.source, .systemNameAnswer)
    }

    func testNamedEndpointFallbackRunsOnlyAfterBothSystemFamilies() async throws {
        var calls: [String] = []
        var messages: [String] = []
        let result = try await TunnelEndpointResolver.resolveEndpoint(host, system: { _, family in
            calls.append(family == .ipv4 ? "ipv4" : "ipv6")
            return nil
        }, fallback: { _ in calls.append("fallback"); return "192.0.2.8" },
            event: { messages.append($0.text) })
        XCTAssertEqual(calls, ["ipv4", "ipv6", "fallback"])
        XCTAssertEqual(result?.family, .ipv4)
        XCTAssertEqual(result?.source, .encryptedIPv4Answer)
        XCTAssertEqual(messages.count, 2)
        XCTAssertFalse(messages.joined().contains(host))
        XCTAssertFalse(messages.joined().contains("192.0.2.8"))
    }

    func testNamedEndpointRejectsWrongFamilyAndInvalidBoundaryValues() async throws {
        var calls: [TunnelEndpointAddress.Family] = []
        let result = try await TunnelEndpointResolver.resolveEndpoint(host, system: { _, family in
            calls.append(family)
            return family == .ipv4 ? "2001:db8::7" : "192.0.2.7"
        }, fallback: { _ in "192.0.2.8\u{0}junk" })
        XCTAssertEqual(calls, [.ipv4, .ipv6])
        XCTAssertNil(result)
    }

    func testNamedEndpointPrivateNamesNeverReachPublicFallback() async throws {
        let result = try await TunnelEndpointResolver.resolveEndpoint("router.local", system: { _, _ in nil },
            fallback: { _ in XCTFail("Private name leaked to public resolver"); return nil })
        XCTAssertNil(result)
    }

    func testNamedEndpointChecksCancellationAfterEveryAwait() async throws {
        for cancelledBoundary in 0...2 {
            var calls: [Int] = []
            let task = Task {
                try await TunnelEndpointResolver.resolveEndpoint(self.host, system: { _, family in
                    let boundary = family == .ipv4 ? 0 : 1
                    calls.append(boundary)
                    if boundary == cancelledBoundary {
                        withUnsafeCurrentTask { $0?.cancel() }
                        return family == .ipv4 ? "192.0.2.7" : "2001:db8::7"
                    }
                    return nil
                }, fallback: { _ in
                    calls.append(2)
                    withUnsafeCurrentTask { $0?.cancel() }
                    return "192.0.2.8"
                })
            }
            do { _ = try await task.value; XCTFail("Cancelled boundary published an address") }
            catch { XCTAssertTrue(error is CancellationError) }
            XCTAssertEqual(calls, Array(0...cancelledBoundary))
        }
    }

    func testLegacyIPv4ResolverRejectsIPv6SystemAndFallbackAnswers() async throws {
        let result = try await TunnelEndpointResolver.resolveIPv4(host,
            system: { _ in "2001:db8::7" }, fallback: { _ in "2001:db8::8" })
        XCTAssertNil(result)
    }

    func testNamedEndpointPropagatesSystemErrorWithoutChangingLegacyRetryPolicy() async throws {
        var calls = 0
        do {
            _ = try await TunnelEndpointResolver.resolveEndpoint(host, system: { _, _ in
                calls += 1
                throw URLError(.networkConnectionLost)
            }, fallback: { _ in XCTFail("Thrown system errors must propagate"); return nil })
            XCTFail("System error was hidden")
        } catch { XCTAssertEqual((error as? URLError)?.code, .networkConnectionLost) }
        XCTAssertEqual(calls, 1)
    }

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
        let input = Data(#"{"inbounds":[{"protocol":"socks","port":10808}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"fixture-user"}]}]},"streamSettings":{"security":"reality","realitySettings":{"serverName":"sni.example.com"},"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"download.example.com","port":8443,"network":"xhttp"}}}}],"routing":{"rules":[{"domain":["domain:ru"],"outboundTag":"proxy"}]}}"#.utf8)
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        var names: [String] = []
        let prepared = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
            environmentSnapshot: XrayEnvironmentSnapshot(rawEntries: []), resolveIPv4: {
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
                environmentSnapshot: XrayEnvironmentSnapshot(rawEntries: []), resolveIPv4: { _ in
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
