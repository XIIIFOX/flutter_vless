import XCTest
@testable import flutter_vless_macos_tunnel_support

/// Every asynchronous backend in this suite is injected. No DNS/socket call runs.
final class TunnelEndpointCandidatesTests: XCTestCase {
    private let dual = TunnelEndpointPath(generation: 7, interfaceIndex: 4, interfaceName: "en0",
        supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    private func candidate(_ text: String, at: TimeInterval = 10, until: TimeInterval? = 30) -> TunnelEndpointCandidate {
        TunnelEndpointCandidate(address: TunnelEndpointAddress(text: text, source: .systemNameAnswer)!,
            origin: .systemNameAnswer, receivedAt: at, validUntil: until, lookupScope: .interface(index: 4))
    }

    func testOrderedDedupIsBoundedAndDoesNotInventTTL() {
        let first = candidate("2001:db8::1")
        let duplicate = candidate("2001:0DB8:0:0::1", until: 40)
        let values = [first, duplicate] + (1...30).map { candidate("192.0.2.\($0)") }
        let set = TunnelEndpointCandidates(path: dual, candidates: values)
        XCTAssertEqual(set.candidates.count, 16)
        XCTAssertEqual(set.candidates.first, first)
        XCTAssertEqual(set.usable(at: 20).count, 16)
        XCTAssertTrue(set.usable(at: 30).isEmpty)
        let literal = TunnelEndpointCandidate(address: TunnelEndpointAddress(text: "192.0.2.7", source: .literal)!,
            origin: .literal, receivedAt: 10)
        XCTAssertNil(literal.validUntil)
        XCTAssertEqual(literal.lookupScope, .literal)
    }

    func testCapabilityHintsFilterFamilyWithoutClaimingTranslation() {
        let v6 = TunnelEndpointPath(generation: 7, interfaceIndex: 4, interfaceName: "en0",
            supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        XCTAssertFalse(candidate("192.0.2.7").isUsable(on: v6, at: 20))
        XCTAssertTrue(candidate("2001:db8::7").isUsable(on: v6, at: 20))
        XCTAssertEqual(candidate("2001:db8::7").origin, .systemNameAnswer)
        XCTAssertFalse(candidate("2001:db8::7").isUsable(on: v6, at: .infinity))
        XCTAssertFalse(candidate("2001:db8::7", at: 21).isUsable(on: v6, at: 20))
    }

    func testZeroTTLRequiresExplicitFreshSingleAttemptAndSource() {
        let value = candidate("2001:db8::7", at: 10, until: 10)
        XCTAssertTrue(value.isSingleAttemptOnly)
        XCTAssertFalse(value.isUsable(on: dual, at: 11))
        XCTAssertTrue(value.isUsable(on: dual, at: 11, allowFreshZeroTTL: true))
        let forged = TunnelEndpointCandidate(address: TunnelEndpointAddress(text: "192.0.2.7", source: .literal)!,
            origin: .literal, receivedAt: 10, validUntil: 10)
        XCTAssertFalse(forged.isUsable(on: dual, at: 11, allowFreshZeroTTL: true))
    }

    func testTranslationRequiresNumericIPv4WitnessIPv6AndHonestScope() {
        let address = TunnelEndpointAddress(text: "2001:db8:64::c000:207", source: .systemIPv4Translation)!
        let translated = TunnelEndpointCandidate(address: address,
            origin: .systemIPv4Translation(originalIPv4: "192.0.2.7"), receivedAt: 10)
        XCTAssertTrue(translated.isUsable(on: dual, at: 20))
        XCTAssertEqual(translated.lookupScope, .processDefault)
        for witness in ["inside.example.com", "2001:db8::1", "192.0.2.7\u{0}tail"] {
            let invalid = TunnelEndpointCandidate(address: address,
                origin: .systemIPv4Translation(originalIPv4: witness), receivedAt: 10)
            XCTAssertFalse(invalid.isUsable(on: dual, at: 20))
        }
        let wrongSource = TunnelEndpointCandidate(address: candidate("2001:db8::7").address,
            origin: .systemIPv4Translation(originalIPv4: "192.0.2.7"), receivedAt: 10)
        XCTAssertFalse(wrongSource.isUsable(on: dual, at: 20))
    }

    func testDNSAccumulatorCollectsBothFamiliesUpdatesTTLAndRemoves() {
        var collection = TunnelEndpointDNSAccumulator(host: "vpn.example.com", path: dual)
        collection.accept(.init(hostname: "VPN.EXAMPLE.COM.", text: "192.0.2.7", interfaceIndex: 4, ttl: 5, added: true), at: 10)
        collection.accept(.init(hostname: "vpn.example.com", text: "2001:db8::7", interfaceIndex: 4, ttl: 10, added: true), at: 11)
        collection.accept(.init(hostname: "vpn.example.com", text: "192.0.2.7", interfaceIndex: 4, ttl: 20, added: true), at: 12)
        XCTAssertEqual(collection.snapshot(at: 16).map(\.address.text), ["192.0.2.7", "2001:db8::7"])
        XCTAssertEqual(collection.snapshot(at: 16).first?.validUntil, 32)
        collection.accept(.init(hostname: "vpn.example.com", text: "192.0.2.7", interfaceIndex: 4, ttl: 20, added: false), at: 17)
        XCTAssertEqual(collection.snapshot(at: 20).map(\.address.text), ["2001:db8::7"])
        XCTAssertTrue(collection.snapshot(at: 21).isEmpty)
    }

    func testDNSAccumulatorRejectsWrongQuestionInterfaceAndMalformedAddress() {
        var collection = TunnelEndpointDNSAccumulator(host: "vpn.example.com", path: dual)
        for value in [TunnelEndpointDNSAnswer(hostname: "other.example.com", text: "192.0.2.7", interfaceIndex: 4, ttl: 5, added: true),
                      .init(hostname: "vpn.example.com", text: "192.0.2.7", interfaceIndex: 5, ttl: 5, added: true),
                      .init(hostname: "vpn.example.com", text: "192.0.2.7\u{0}tail", interfaceIndex: 4, ttl: 5, added: true)] {
            collection.accept(value, at: 10)
        }
        XCTAssertTrue(collection.snapshot(at: 11).isEmpty)
        collection.accept(.init(hostname: "vpn.example.com", text: "::ffff:192.0.2.7", interfaceIndex: 4, ttl: 0, added: true), at: 10)
        let single = collection.snapshot(at: 11)
        XCTAssertEqual(single.first?.address.family, .ipv4)
        XCTAssertTrue(single.first?.isSingleAttemptOnly == true)
    }

    func testResolverKeepsBothFamiliesAndScopedTTL() async throws {
        let values = [candidate("192.0.2.7"), candidate("2001:db8::7")]
        let set = try await TunnelEndpointResolver.resolveCandidates("vpn.example.com", on: dual, deadline: 25,
            now: { 20 }, system: { _, path, deadline in
                XCTAssertEqual(path, self.dual); XCTAssertEqual(deadline, 25); return values
            }, synthesis: { _, _ in XCTFail("Named query must use DNSService first"); return [] },
            fallback: { _, _ in XCTFail("Usable system answers must suppress fallback"); return nil })
        XCTAssertEqual(set.candidates, values)
    }

    func testNumericIPv4SynthesisOnlyOnIPv6OnlyPath() async throws {
        let v6 = TunnelEndpointPath(generation: 8, interfaceIndex: 4, interfaceName: "en0",
            supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        let set = try await TunnelEndpointResolver.resolveCandidates("192.0.2.7", on: v6, deadline: 25,
            now: { 20 }, system: { _, _, _ in XCTFail("Literal must not start named DNS"); return [] },
            synthesis: { input, deadline in
                XCTAssertEqual(input, "192.0.2.7"); XCTAssertEqual(deadline, 25)
                return ["192.0.2.7", "2001:db8:64::c000:207", "2001:0db8:64:0:0:0:c000:207"]
            }, fallback: { _, _ in XCTFail("Literal must never reach public fallback"); return nil })
        XCTAssertEqual(set.candidates.count, 1)
        XCTAssertEqual(set.candidates.first?.origin, .systemIPv4Translation(originalIPv4: "192.0.2.7"))
        XCTAssertEqual(set.candidates.first?.lookupScope, .processDefault)
        let direct = try await TunnelEndpointResolver.resolveCandidates("192.0.2.7", on: dual, deadline: 25,
            now: { 20 }, system: { _, _, _ in XCTFail(); return [] },
            synthesis: { _, _ in XCTFail("IPv4 capability retains literal without synthesis"); return [] }, fallback: { _, _ in nil })
        XCTAssertEqual(direct.candidates.first?.origin, .literal)
    }

    func testNoTranslationDoesNotInventPrefixOrLeakLiteral() async throws {
        let v6 = TunnelEndpointPath(generation: 8, interfaceIndex: 4, supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        let set = try await TunnelEndpointResolver.resolveCandidates("192.0.2.7", on: v6, deadline: 25,
            now: { 20 }, system: { _, _, _ in XCTFail(); return [] }, synthesis: { _, _ in ["192.0.2.7"] },
            fallback: { _, _ in XCTFail(); return nil })
        XCTAssertTrue(set.candidates.isEmpty)
    }

    func testEncryptedFallbackIsProcessDefaultIPv4AndNeverLeaksPrivateNames() async throws {
        var calls = 0
        for name in ["vpn.example.com", "router.local"] {
            let set = try await TunnelEndpointResolver.resolveCandidates(name, on: dual, deadline: 25,
                now: { 20 }, system: { _, _, _ in [] }, synthesis: { _, _ in XCTFail(); return [] },
                fallback: { host, timeout in calls += 1; XCTAssertEqual(host, "vpn.example.com"); XCTAssertEqual(timeout, 5); return "192.0.2.8" })
            XCTAssertEqual(set.candidates.count, name == "vpn.example.com" ? 1 : 0)
            if let value = set.candidates.first { XCTAssertEqual(value.lookupScope, .processDefault); XCTAssertEqual(value.origin, .encryptedIPv4Answer) }
        }
        XCTAssertEqual(calls, 1)
    }

    func testDeadlineAndOwnershipAreCheckedAfterInjectedAwait() async throws {
        for revoke in [false, true] {
            var current = true
            var tick: TimeInterval = 20
            do {
                _ = try await TunnelEndpointResolver.resolveCandidates("vpn.example.com", on: dual, deadline: 25,
                    now: { tick }, system: { _, _, _ in current = !revoke; tick = 25; return [self.candidate("192.0.2.7")] },
                    synthesis: { _, _ in XCTFail(); return [] }, fallback: { _, _ in XCTFail(); return nil }, isCurrent: { current })
                XCTFail("Late result must not be adopted")
            } catch {
                if revoke { XCTAssertTrue(error is CancellationError) }
                else { XCTAssertEqual(error as? TunnelEndpointResolver.CandidateFailure, .deadlineExceeded) }
            }
        }
    }

    func testDNSCollectionCancellationClosesExactlyOnceAndIgnoresLateCallback() async throws {
        let started = expectation(description: "fake query started")
        var closes = 0
        var callback: ((TunnelEndpointDNSAnswer) -> Void)?
        let task = Task {
            try await TunnelEndpointDNSCollection.collect("vpn.example.com", path: dual, deadline: now + 10,
                query: { _, index, _, receive in
                    XCTAssertEqual(index, 4); callback = receive; started.fulfill()
                    return { closes += 1 }
                })
        }
        await fulfillment(of: [started], timeout: 1)
        task.cancel()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        callback?(.init(hostname: "vpn.example.com", text: "192.0.2.7", interfaceIndex: 4, ttl: 10, added: true))
        XCTAssertEqual(closes, 1)
    }

    func testDNSCollectionDoesNotCompleteOnFirstIPv4AndReturnsBothAtBound() async throws {
        var closes = 0
        let values = try await TunnelEndpointDNSCollection.collect("vpn.example.com", path: dual, deadline: now + 0.03,
            query: { _, _, _, receive in
                receive(.init(hostname: "vpn.example.com", text: "192.0.2.7", interfaceIndex: 4, ttl: 10, added: true))
                receive(.init(hostname: "vpn.example.com", text: "2001:db8::7", interfaceIndex: 4, ttl: 10, added: true))
                return { closes += 1 }
            })
        XCTAssertEqual(values.map(\.address.family), [.ipv4, .ipv6])
        XCTAssertEqual(closes, 1)
    }

    func testBlockingSynthesisCancellationKeepsOneOutstandingSlotUntilNativeReturns() async throws {
        let entered = expectation(description: "fake blocking backend entered")
        let release = DispatchSemaphore(value: 0)
        let exited = expectation(description: "fake blocking backend returned")
        let worker = TunnelIPv4SynthesisWorker(lookup: { _ in entered.fulfill(); release.wait(); exited.fulfill(); return ["2001:db8::7"] })
        let task = Task { try await worker.resolve("192.0.2.7", deadline: now + 10) }
        await fulfillment(of: [entered], timeout: 1)
        task.cancel()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let busy = try await worker.resolve("192.0.2.8", deadline: now + 1)
        XCTAssertTrue(busy.isEmpty, "Cancellation cannot claim the blocking native call has stopped")
        release.signal()
        await fulfillment(of: [exited], timeout: 1)
    }
    func testSynthesisRevokedBeforeNativeEntryDoesNotCallBackend() async throws {
        let lock = NSLock()
        var checks = 0
        var calls = 0
        let worker = TunnelIPv4SynthesisWorker(lookup: { _ in calls += 1; return ["2001:db8::7"] })
        do {
            _ = try await worker.resolve("192.0.2.7", deadline: now + 1, isCurrent: {
                lock.lock(); defer { lock.unlock() }
                checks += 1
                return checks == 1 // owner revoked after initial admission, before queued work
            })
            XCTFail("Revoked owner completed")
        } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(calls, 0, "A queued stale owner must not enter even the uncancellable backend")
    }

    func testSynthesisDeadlineDiscardsLateResultWithoutReleasingNativeSlotEarly() async throws {
        let entered = expectation(description: "fake backend started")
        let release = DispatchSemaphore(value: 0)
        let exited = expectation(description: "fake backend returned")
        let worker = TunnelIPv4SynthesisWorker(lookup: { _ in entered.fulfill(); release.wait(); exited.fulfill(); return ["2001:db8::7"] })
        let task = Task { try await worker.resolve("192.0.2.7", deadline: now + 0.03) }
        await fulfillment(of: [entered], timeout: 1)
        do { _ = try await task.value; XCTFail("Late native result was adopted") }
        catch { XCTAssertEqual(error as? TunnelEndpointResolver.CandidateFailure, .deadlineExceeded) }
        let stillBusy = try await worker.resolve("192.0.2.8", deadline: now + 1)
        XCTAssertTrue(stillBusy.isEmpty)
        release.signal()
        await fulfillment(of: [exited], timeout: 1)
    }

    func testDNSCollectionRefusesExpiredOrRevokedStartBeforeCreatingQuery() async throws {
        for revoked in [false, true] {
            do {
                _ = try await TunnelEndpointDNSCollection.collect("vpn.example.com", path: dual, deadline: now - 1,
                    isCurrent: { !revoked }, query: { _, _, _, _ in XCTFail("Query created after admission expired"); return nil })
                XCTFail()
            } catch {
                if revoked { XCTAssertTrue(error is CancellationError) }
                else { XCTAssertEqual(error as? TunnelEndpointResolver.CandidateFailure, .deadlineExceeded) }
            }
        }
    }

    func testWrongInterfaceMetadataCannotBeSelectedAndLegacyAPIsRemainIPv4First() async throws {
        let other = TunnelEndpointCandidate(address: candidate("192.0.2.7").address, origin: .systemNameAnswer,
            receivedAt: 10, validUntil: 30, lookupScope: .interface(index: 5))
        XCTAssertFalse(other.isUsable(on: dual, at: 20))
        XCTAssertEqual(dual.rebased(generation: 9).interfaceName, "en0")
        XCTAssertEqual(dual.rebased(generation: 9).generation, 9)
        var families: [TunnelEndpointAddress.Family] = []
        let old = try await TunnelEndpointResolver.resolveEndpoint("vpn.example.com", system: { _, family in
            families.append(family); return "192.0.2.7"
        }, fallback: { _ in XCTFail(); return nil })
        XCTAssertEqual(families, [.ipv4])
        XCTAssertEqual(old?.text, "192.0.2.7")
        let ipv4 = try await TunnelEndpointResolver.resolveIPv4("vpn.example.com", system: { _ in "2001:db8::7" }, fallback: { _ in "192.0.2.8" })
        XCTAssertEqual(ipv4, "192.0.2.8")
    }

    func testLiteralLoopbackNeverNeedsPhysicalFamilyOrSynthesis() async throws {
        let v6 = TunnelEndpointPath(generation: 8, interfaceIndex: 4, interfaceName: "en0",
            supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        for host in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            let set = try await TunnelEndpointResolver.resolveCandidates(host, on: v6, deadline: 25,
                now: { 20 }, system: { _, _, _ in XCTFail("Loopback must not use scoped DNS"); return [] },
                synthesis: { _, _ in XCTFail("Loopback must not use underlay synthesis"); return [] },
                fallback: { _, _ in XCTFail("Loopback must not reach public fallback"); return nil })
            XCTAssertEqual(set.candidates.count, 1)
            XCTAssertEqual(set.candidates.first?.origin, .literal)
            XCTAssertEqual(set.candidates.first?.lookupScope, .literal)
            XCTAssertEqual(set.usable(at: 20).count, 1)
        }
    }

}
