import XCTest
import Darwin
@testable import flutter_vless_macos_tunnel_support

final class NamedIPv6BootstrapTests: XCTestCase {
    private let input = Data(#"{"dns":{"queryStrategy":"UseIP","hosts":{"dns.fixture.invalid":"192.0.2.53"},"servers":[{"address":"https://dns.fixture.invalid/dns-query","domains":["domain:fixture.invalid"]}]},"inbounds":[{"tag":"caller","protocol":"socks","listen":"127.0.0.1","port":10808}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"vpn.fixture.invalid","port":443,"id":"fixture-user","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"identity.fixture.invalid","masterKeyLog":""},"network":"tcp"}}],"routing":{"rules":[{"domain":["full:caller.fixture.invalid"],"outboundTag":"proxy"}]}}"#.utf8)

    func testNamedIPv6IsPinnedWithoutChangingCallerDNSOrTLS() throws {
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        var names: [String] = []
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: credentials,
            tcpPortAvailable: { _ in true }, environmentSnapshot: XrayEnvironmentSnapshot(rawEntries: []),
            resolveIPv4: { names.append($0); return "2001:db8:1234::7" }))
        XCTAssertEqual(names, ["vpn.fixture.invalid"])
        XCTAssertEqual(prepared.bootstrapAddresses, ["2001:db8:1234::7"])
        let before = try XCTUnwrap(JSONSerialization.jsonObject(with: input) as? [String: Any])
        let after = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        XCTAssertEqual(before["dns"] as? NSDictionary, after["dns"] as? NSDictionary)
        let outputs = try XCTUnwrap(after["outbounds"] as? [[String: Any]])
        let original = try XCTUnwrap((before["outbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual(outputs[0]["settings"] as? NSDictionary, original["settings"] as? NSDictionary)
        XCTAssertEqual((outputs[0]["streamSettings"] as? [String: Any])?["tlsSettings"] as? NSDictionary,
                       (original["streamSettings"] as? [String: Any])?["tlsSettings"] as? NSDictionary)
        XCTAssertEqual(outputs.filter { ($0["settings"] as? [String: Any])?["redirect"] as? String == "[2001:db8:1234::7]:0" }.count, 1)
        let routes = TunnelIPv6Policy.networkSettings(proxyAddresses: prepared.bootstrapAddresses).excludedRoutes ?? []
        XCTAssertEqual(routes.count, 1)
        XCTAssertEqual(routes.first?.destinationAddress, "2001:db8:1234::7")
        XCTAssertEqual(routes.first?.destinationNetworkPrefixLength, 128)
        let rules = try XCTUnwrap((after["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        let caller = try XCTUnwrap((before["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(Array(rules.suffix(caller.count)) as NSArray, caller as NSArray)
    }

    func testTypedAsyncIPv6AnswerReachesThePrivatePin() async throws {
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        var queries = 0
        let prepared = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
            tcpPortAvailable: { _ in true }, environmentSnapshot: XrayEnvironmentSnapshot(rawEntries: []),
            resolveEndpoint: { host in
                queries += 1
                XCTAssertEqual(host, "vpn.fixture.invalid")
                await Task.yield()
                return TunnelEndpointAddress(text: "2001:db8:5678::7", source: .systemNameAnswer)
            }, attempts: 1, retryDelay: { XCTFail("Successful typed answer must not retry") })
        XCTAssertEqual(queries, 1)
        XCTAssertEqual(prepared.bootstrapAddresses, ["2001:db8:5678::7"])
    }

    func testRevokedSessionDoesNotBeginPreparation() async throws {
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        do {
            _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
                tcpPortAvailable: { _ in XCTFail("Revoked request allocated a listener"); return true },
                resolveEndpoint: { _ in XCTFail("Revoked request performed DNS"); return nil },
                isCurrent: { false }, retryDelay: { XCTFail("Revoked request retried") })
            XCTFail("Revoked request published a configuration")
        } catch { XCTAssertTrue(error is CancellationError) }
    }

    func testStopAndReplacementDuringLookupDiscardBothSuccessAndUnavailableAnswers() async throws {
        for replacement in [false, true] {
            for answer in [false, true] {
                let admission = TunnelSessionAdmission()
                let epoch = admission.begin()
                let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
                var lookups = 0
                do {
                    _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
                        tcpPortAvailable: { _ in true }, resolveEndpoint: { _ in
                            lookups += 1
                            if replacement { admission.begin() } else { admission.revoke() }
                            await Task.yield()
                            return answer ? TunnelEndpointAddress(text: "2001:db8::9", source: .systemNameAnswer) : nil
                        }, isCurrent: { admission.isCurrent(epoch) },
                        retryDelay: { XCTFail("Late result retried after revocation") })
                    XCTFail("Late result escaped session ownership")
                } catch { XCTAssertTrue(error is CancellationError) }
                XCTAssertEqual(lookups, 1)
            }
        }
    }

    func testRevokedLookupErrorIsCancellationRatherThanAStaleDNSFailure() async throws {
        let admission = TunnelSessionAdmission()
        let epoch = admission.begin()
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        do {
            _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
                tcpPortAvailable: { _ in true }, resolveEndpoint: { _ in
                    admission.revoke()
                    throw URLError(.cannotFindHost)
                }, isCurrent: { admission.isCurrent(epoch) },
                retryDelay: { XCTFail("Revoked DNS failure must not retry") })
            XCTFail("Revoked DNS failure published configuration")
        } catch { XCTAssertTrue(error is CancellationError) }
    }

    func testStopDuringRetryDelayDoesNotResolveAgain() async throws {
        let admission = TunnelSessionAdmission()
        let epoch = admission.begin()
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        var lookups = 0, delays = 0
        do {
            _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
                tcpPortAvailable: { _ in true }, resolveEndpoint: { _ in lookups += 1; return nil },
                isCurrent: { admission.isCurrent(epoch) }, attempts: 3,
                retryDelay: { delays += 1; admission.revoke(); await Task.yield() })
            XCTFail("Revoked delay published a configuration")
        } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(lookups, 1)
        XCTAssertEqual(delays, 1)
    }

    func testNamedIPv4KeepsItsExistingPin() throws {
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: credentials,
            tcpPortAvailable: { _ in true }, resolveIPv4: { _ in "192.0.2.7" }))
        XCTAssertEqual(prepared.bootstrapAddresses, ["192.0.2.7"])
    }

    func testInvalidResolvedTextCannotPublishAnyPreparedConfiguration() throws {
        let credentials = try LocalProxyCredentials(username: "fixture", password: "fixture-password")
        for bad in ["not-an-IP", "2001:db8::zz", "[2001:db8::1]", "fe80::1%en0", "2001:db8::1\u{0}extra"] {
            XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: credentials,
                tcpPortAvailable: { _ in true }, resolveIPv4: { _ in bad }), bad)
        }
    }
}
