import XCTest
@testable import flutter_vless_macos_tunnel_support

/// Tests real endpoint preparation with injected answers, without DNS or sockets.
final class TunnelNat64ContractTests: XCTestCase {
    private let ipv6Only = TunnelEndpointPath(generation: 3, interfaceIndex: 4,
        interfaceName: "en0", supportsIPv4: false, supportsIPv6: true, supportsDNS: true)

    func testNat64LiteralsRemainIPv6AndDoNotInventTranslationOrResolve() async throws {
        for text in ["64:ff9b::c000:207", "64:ff9b:1::c000:207"] {
            let result = try await TunnelEndpointResolver.resolveCandidates(text, on: ipv6Only,
                deadline: 20, now: { 10 },
                system: { _, _, _ in XCTFail("Numeric NAT64 must not use DNS"); return [] },
                synthesis: { _, _ in XCTFail("Already IPv6 must not be resynthesized"); return [] },
                fallback: { _, _ in XCTFail("Numeric endpoint must not reach public fallback"); return nil })
            let value = try XCTUnwrap(result.candidates.first)
            XCTAssertEqual(value.address.text, text)
            XCTAssertEqual(value.address.family, .ipv6)
            XCTAssertEqual(value.address.source, .literal)
            XCTAssertEqual(value.origin, .literal)
            XCTAssertEqual(value.lookupScope, .literal)
        }
    }

    func testNat64LookingNameAnswerKeepsItsSystemScopeAndTTL() async throws {
        let address = try XCTUnwrap(TunnelEndpointAddress(text: "64:ff9b::c000:207", source: .systemNameAnswer))
        let answer = TunnelEndpointCandidate(address: address, origin: .systemNameAnswer,
            receivedAt: 10, validUntil: 15, lookupScope: .interface(index: 4))
        let result = try await TunnelEndpointResolver.resolveCandidates("endpoint.example.com", on: ipv6Only,
            deadline: 20, now: { 11 }, system: { _, _, _ in [answer] },
            synthesis: { _, _ in XCTFail("Do not infer a translation witness from a prefix"); return [] },
            fallback: { _, _ in XCTFail("Valid AAAA must suppress public fallback"); return nil })
        XCTAssertEqual(result.candidates, [answer])
        XCTAssertTrue(result.usable(at: 15).isEmpty)
        XCTAssertEqual(result.candidates.first?.origin, .systemNameAnswer)
    }
}
