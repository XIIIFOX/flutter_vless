import Foundation
import XCTest
@testable import flutter_vless_macos_tunnel_support

final class TunnelEndpointDiscoveryTests: XCTestCase {
    private let dual = TunnelEndpointPath(generation: 7, interfaceIndex: 4, interfaceName: "en0",
        supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    private final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: T
        init(_ value: T) { self.value = value }
        func get() -> T { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ value: T) { lock.lock(); self.value = value; lock.unlock() }
        func update(_ body: (inout T) -> Void) { lock.lock(); body(&value); lock.unlock() }
    }

    private final class Backend: @unchecked Sendable {
        struct Entry { let queue: DispatchQueue; let receive: (TunnelEndpointDiscovery.FamilyEvent) -> Void }
        private let lock = NSLock()
        private var entries: [String: Entry] = [:]
        private var closes: Set<String> = []
        private var active = 0
        private var peak = 0
        var started: ((String, Int, Int) -> Void)?
        var didClose: (() -> Void)?
        private func key(_ name: String, _ family: TunnelEndpointAddress.Family) -> String {
            name.lowercased() + (family == .ipv4 ? "|4" : "|6")
        }
        func query(_ name: String, _ index: UInt32, _ family: TunnelEndpointAddress.Family, _ queue: DispatchQueue,
                   _ receive: @escaping (TunnelEndpointDiscovery.FamilyEvent) -> Void) -> (() -> Void)? {
            XCTAssertEqual(index, 4)
            let identity = key(name, family)
            lock.lock()
            XCTAssertNil(entries[identity], "One query per canonical host/family")
            entries[identity] = Entry(queue: queue, receive: receive)
            active += 1; peak = max(peak, active)
            let count = entries.count, current = active
            lock.unlock()
            started?(name, count, current)
            return {
                self.lock.lock()
                XCTAssertTrue(self.closes.insert(identity).inserted, "Each reference closes once")
                self.active -= 1
                self.lock.unlock()
                self.didClose?()
            }
        }
        func emit(_ name: String, _ family: TunnelEndpointAddress.Family, _ event: TunnelEndpointDiscovery.FamilyEvent) {
            lock.lock(); let callback = entries[key(name, family)]?.receive; lock.unlock()
            XCTAssertNotNil(callback)
            callback?(event)
        }
        private func registeredQueue() -> DispatchQueue? {
            lock.lock(); defer { lock.unlock() }
            return entries.values.first?.queue
        }
        func drain() async {
            let queue = registeredQueue()
            if let queue { await withCheckedContinuation { c in queue.async { c.resume() } } }
        }
        func enqueue(_ body: @escaping () -> Void) { registeredQueue()?.async(execute: body) }
        var counts: (registered: Int, closed: Int, active: Int, peak: Int) {
            lock.lock(); defer { lock.unlock() }
            return (entries.count, closes.count, active, peak)
        }
    }

    private func answer(_ host: String, _ text: String, ttl: UInt32 = 30, added: Bool = true,
                        index: UInt32 = 0, more: Bool = false) -> TunnelEndpointDiscovery.FamilyEvent {
        .answer(.init(hostname: host, text: text, interfaceIndex: index, ttl: ttl, added: added), moreComing: more)
    }

    private func make(_ backend: Backend, path: TunnelEndpointPath? = nil, window: TimeInterval = 2,
                      clock: (() -> TimeInterval)? = nil, current: @escaping () -> Bool = { true },
                      event: @escaping (NativeDiagnosticMessage) -> Void = { _ in },
                      invalidated: @escaping () -> Void = {},
                      schedule: @escaping TunnelEndpointDNSCollection.Schedule = TunnelEndpointDNSCollection.scheduleDeadline) -> TunnelEndpointDiscovery {
        let clock = clock ?? { ProcessInfo.processInfo.systemUptime }
        return TunnelEndpointDiscovery(path: path ?? dual, deadline: clock() + 5, now: clock,
            isCurrent: current, event: event, onInvalidated: invalidated, query: backend.query, collectionWindow: window, schedule: schedule)
    }

    private func selection(_ host: String, _ result: TunnelEndpointCandidates) -> [TunnelEndpointSelection] {
        [TunnelEndpointSelection(logicalHost: host, candidates: result, selected: result.candidates[0])]
    }

    private func awaitSealWaiters(_ group: TunnelEndpointDiscovery, count: Int) async {
        let deadline = now + 1
        while group.pendingInitialSealWaiterCount != count, now < deadline { await Task.yield() }
        XCTAssertEqual(group.pendingInitialSealWaiterCount, count)
    }

    func testReadyPublicationRequiresCurrentUncancelledAdmittedLiveWitness() async throws {
        for boundary in ["cancel", "expiry", "remove", "owner"] {
            let backend = Backend(), clock = EndpointDeadlineTestScheduler(), current = Box(true)
            let registered = expectation(description: "publication boundary " + boundary)
            backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
            let group = make(backend, clock: clock.now, current: current.get, schedule: clock.schedule)
            let task = Task { try await group.resolveCandidates("publication.fixture.invalid") }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("publication.fixture.invalid", .ipv4, answer("publication.fixture.invalid", "192.0.2.1"))
            backend.emit("publication.fixture.invalid", .ipv6, .failure(.noRecord))
            let values = try await task.value
            XCTAssertFalse(group.permitsForwardingReady, "A DNS reply alone is not an admitted witness")
            XCTAssertTrue(group.admitSelections(selection("publication.fixture.invalid", values)))
            XCTAssertTrue(group.finishAdmission())
            XCTAssertTrue(group.permitsForwardingReady)
            switch boundary {
            case "cancel": group.cancel()
            case "expiry":
                clock.advance(to: 2); await clock.drain(); await backend.drain()
                clock.advance(to: 31); await clock.drain()
                XCTAssertFalse(group.isInvalidated, "Ordinary sealed expiry does not borrow initial correction")
            case "remove":
                backend.emit("publication.fixture.invalid", .ipv4, answer("publication.fixture.invalid", "192.0.2.1", added: false))
                await backend.drain()
            default: current.set(false)
            }
            XCTAssertFalse(group.permitsForwardingReady, boundary)
            group.cancel(); await backend.drain()
            XCTAssertEqual(backend.counts.closed, 2)
        }
    }

    func testOnlyBothTerminalUsableFamilyFailuresSealBeforeOriginalBound() async throws {
        for failure in [TunnelEndpointDNSAnswer.Failure.serviceUnavailable, .defunct, .policyDenied] {
            let backend = Backend(), clock = EndpointDeadlineTestScheduler(), ready = Box(false)
            let registered = expectation(description: "terminal family registrations")
            backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
            let group = make(backend, clock: clock.now, schedule: clock.schedule)
            let task = Task { let result = try await group.resolveCandidates("terminal.fixture.invalid"); ready.set(true); return result }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("terminal.fixture.invalid", .ipv4, .failure(failure))
            await backend.drain()
            XCTAssertFalse(ready.get(), "One dead family cannot discard a later system AAAA")
            backend.emit("terminal.fixture.invalid", .ipv6, .failure(failure))
            let limit = now + 1
            while !ready.get(), now < limit { await Task.yield() }
            XCTAssertTrue(ready.get(), "Both dead references require no collection timer")
            if !ready.get() { group.cancel() }
            let values = try await task.value
            XCTAssertTrue(values.candidates.isEmpty)
            XCTAssertEqual(clock.now(), 0, "No shortened replacement timer is needed")
            await backend.drain(); XCTAssertEqual(backend.counts.closed, 2)
            group.cancel()
        }
    }

    func testOneFailedRegistrationKeepsOtherFamilyWindowAndLateAAAA() async throws {
        let backend = Backend(), clock = EndpointDeadlineTestScheduler(), ready = Box(false)
        let registered = expectation(description: "remaining AAAA reference")
        backend.started = { _, count, _ in if count == 1 { registered.fulfill() } }
        let group = TunnelEndpointDiscovery(path: dual, deadline: 5, now: clock.now,
            isCurrent: { true }, onInvalidated: {}, query: { host, index, family, queue, callback in
                if family == .ipv4 { return nil }
                return backend.query(host, index, family, queue, callback)
            }, schedule: clock.schedule)
        let task = Task { let values = try await group.resolveCandidates("remaining.fixture.invalid"); ready.set(true); return values }
        await fulfillment(of: [registered], timeout: 1)
        clock.advance(to: 1.8); await clock.drain(); await backend.drain()
        XCTAssertFalse(ready.get())
        backend.emit("remaining.fixture.invalid", .ipv6, answer("remaining.fixture.invalid", "2001:db8::8"))
        await backend.drain()
        clock.advance(to: 2); await clock.drain()
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.text), ["2001:db8::8"])
        group.cancel(); await backend.drain(); XCTAssertEqual(backend.counts.closed, 1)
    }

    func testTimeoutAndUnknownFailureKeepOriginalWindowAndAcceptLaterAAAA() async throws {
        for failure in [TunnelEndpointDNSAnswer.Failure.timeout, .other] {
            let backend = Backend(), clock = EndpointDeadlineTestScheduler(), ready = Box(false)
            let registered = expectation(description: "recoverable family outcomes")
            backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
            let group = make(backend, clock: clock.now, schedule: clock.schedule)
            let task = Task { let value = try await group.resolveCandidates("recoverable.fixture.invalid"); ready.set(true); return value }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("recoverable.fixture.invalid", .ipv4, .failure(failure))
            backend.emit("recoverable.fixture.invalid", .ipv6, .failure(failure))
            await backend.drain(); XCTAssertFalse(ready.get())
            clock.advance(to: 1.9); await clock.drain()
            backend.emit("recoverable.fixture.invalid", .ipv6, answer("recoverable.fixture.invalid", "2001:db8::9"))
            await backend.drain(); XCTAssertFalse(ready.get())
            clock.advance(to: 2); await clock.drain()
            let result = try await task.value
            XCTAssertEqual(result.candidates.map(\.address.text), ["2001:db8::9"])
            group.cancel(); await backend.drain()
        }
    }

    func testBothInitialFamiliesRequiredAndMoreComingDoesNotReleasePartialBatch() async throws {
        let backend = Backend(), registered = expectation(description: "two family queries")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend); defer { group.cancel() }
        let ready = Box(false), began = now
        let task = Task { let result = try await group.resolveCandidates("vpn.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("vpn.fixture.invalid", .ipv4, answer("vpn.fixture.invalid", "192.0.2.1", more: true))
        backend.emit("vpn.fixture.invalid", .ipv6, .failure(.noRecord))
        await backend.drain()
        XCTAssertFalse(ready.get(), "Other-family reply cannot finish an unfinished IPv4 batch")
        backend.emit("vpn.fixture.invalid", .ipv4, answer("vpn.fixture.invalid", "192.0.2.2"))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.text), ["192.0.2.1", "192.0.2.2"])
        XCTAssertLessThan(now - began, 1, "Complete initial batches avoid the fixed two seconds")
        XCTAssertEqual(backend.counts.closed, 0, "An initial snapshot does not close the subscription")
        group.cancel(); await backend.drain()
        XCTAssertEqual(backend.counts.closed, 2)
    }

    func testIndependentRegistrationMatchesNativeDualRequestOrderWithoutSortingAnswers() async throws {
        let backend = Backend(), registered = expectation(description: "both native-family registrations")
        let order = Box<[TunnelEndpointAddress.Family]>([])
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = TunnelEndpointDiscovery(path: dual, deadline: now + 5, now: { ProcessInfo.processInfo.systemUptime },
            isCurrent: { true }, onInvalidated: {}, query: { host, index, family, queue, callback in
                order.update { $0.append(family) }
                return backend.query(host, index, family, queue, callback)
            })
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("native-order.fixture.invalid") }
        await fulfillment(of: [registered], timeout: 1)
        XCTAssertEqual(order.get(), [.ipv6, .ipv4],
            "The old combined GetAddrInfo path creates AAAA before A; this does not prove family reachability")
        backend.emit("native-order.fixture.invalid", .ipv6, answer("native-order.fixture.invalid", "2001:db8::1"))
        backend.emit("native-order.fixture.invalid", .ipv4, answer("native-order.fixture.invalid", "192.0.2.1"))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.family), [.ipv6, .ipv4],
            "Keep actual backend callback order rather than imposing a new family preference")
    }

    func testPendingAAAAAt1900MillisecondsIsRetainedBeforeInitialAdmission() async throws {
        let backend = Backend(), registered = expectation(description: "deadline registered")
        let clock = EndpointDeadlineTestScheduler()
        clock.scheduled = { registered.fulfill() }
        let group = make(backend, clock: clock.now, schedule: clock.schedule)
        defer { group.cancel() }
        let ready = Box(false)
        let task = Task { let result = try await group.resolveCandidates("late.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        XCTAssertEqual(clock.snapshot.deadlines, [2])
        backend.emit("late.fixture.invalid", .ipv4, answer("late.fixture.invalid", "192.0.2.1"))
        await backend.drain()
        clock.advance(to: 1.9)
        await clock.drain()
        XCTAssertFalse(ready.get(), "The first A is not an initial dual-family quorum")
        backend.emit("late.fixture.invalid", .ipv6, answer("late.fixture.invalid", "2001:db8::1"))
        let result = try await task.value
        XCTAssertEqual(clock.now(), 1.9)
        XCTAssertEqual(result.candidates.map(\.address.family), [.ipv4, .ipv6])
        XCTAssertEqual(backend.counts.closed, 0, "The bounded subscription remains after initial return")
        clock.advance(to: 2)
        await clock.drain()
        XCTAssertEqual(backend.counts.closed, 2)
        XCTAssertEqual(clock.snapshot.cancellations, 1)
    }

    func testNegativeAAAAIsNotTerminalAndLateAAAAAfterSettingsIsObservedWithoutRestart() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let logs = Box<[String]>([]), invalidations = Box(0)
        let group = make(backend, event: { m in logs.update { $0.append(m.text) } }, invalidated: { invalidations.update { $0 += 1 } })
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("stream.fixture.invalid") }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("stream.fixture.invalid", .ipv4, answer("stream.fixture.invalid", "192.0.2.1"))
        backend.emit("stream.fixture.invalid", .ipv6, .failure(.noRecord))
        let first = try await task.value
        let selected = selection("stream.fixture.invalid", first)
        XCTAssertTrue(group.admitSelections(selected))
        group.noteProtectedSettingsInstalled()
        XCTAssertTrue(group.finishAdmission())
        backend.emit("stream.fixture.invalid", .ipv6, answer("stream.fixture.invalid", "2001:db8::1"))
        backend.emit("stream.fixture.invalid", .ipv6, answer("stream.fixture.invalid", "2001:db8::2"))
        await backend.drain()
        let later = try await group.resolveCandidates("stream.fixture.invalid")
        XCTAssertEqual(later.candidates.map(\.address.text), ["192.0.2.1", "2001:db8::1", "2001:db8::2"])
        XCTAssertTrue(group.isFresh(selected))
        XCTAssertEqual(invalidations.get(), 0, "A later alternative alone must not restart a healthy Core")
        XCTAssertEqual(logs.get().filter { $0.contains("lateAAAAAfterSettingsMs=") }.count, 1)
        XCTAssertTrue(logs.get().contains { $0.contains("usable=true initialReady=true") })
        XCTAssertEqual(backend.counts.closed, 0)
    }

    func testAllNegativeMustContinueUntilLateUsableIPv6RatherThanFallbackEarly() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend), ready = Box(false); defer { group.cancel() }
        let task = Task { let result = try await group.resolveCandidates("negative.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("negative.fixture.invalid", .ipv4, .failure(.noRecord))
        backend.emit("negative.fixture.invalid", .ipv6, .failure(.noRecord))
        await backend.drain(); XCTAssertFalse(ready.get())
        backend.emit("negative.fixture.invalid", .ipv6, answer("negative.fixture.invalid", "2001:db8::1"))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.family), [.ipv6])
    }

    func testIPv6OnlyWaitsForAAAAAndNeverReinterpretsAAsNAT64() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let path = TunnelEndpointPath(generation: 7, interfaceIndex: 4, interfaceName: "en0", supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        let group = make(backend, path: path), ready = Box(false); defer { group.cancel() }
        let task = Task { let result = try await group.resolveCandidates("v6.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("v6.fixture.invalid", .ipv4, answer("v6.fixture.invalid", "192.0.2.1"))
        await backend.drain(); XCTAssertFalse(ready.get())
        backend.emit("v6.fixture.invalid", .ipv6, answer("v6.fixture.invalid", "2001:db8:64::c000:201"))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.family), [.ipv6])
        XCTAssertEqual(result.candidates.first?.origin, .systemNameAnswer)
    }

    func testZeroTTLAndShortTTLDoNotUseEarlySnapshot() async throws {
        for ttl: UInt32 in [0, 1] {
            let backend = Backend(), registered = expectation(description: "registered")
            backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
            let group = make(backend), ready = Box(false), began = now
            let task = Task { let result = try await group.resolveCandidates("ttl.fixture.invalid"); ready.set(true); return result }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("ttl.fixture.invalid", .ipv4, answer("ttl.fixture.invalid", "192.0.2.1", ttl: ttl))
            backend.emit("ttl.fixture.invalid", .ipv6, .failure(.noRecord))
            await backend.drain(); XCTAssertFalse(ready.get())
            let result = try await task.value
            XCTAssertGreaterThanOrEqual(now - began, 1.99)
            XCTAssertEqual(result.candidates.count, ttl == 0 ? 1 : 0)
            if ttl == 0 { XCTAssertTrue(result.candidates[0].isSingleAttemptOnly) }
            group.cancel(); await backend.drain()
        }
    }

    func testSelectedRemovalInvalidatesBeforeAndAfterNativeAdmissionExactlyOnce() async throws {
        for finish in [false, true] {
            let backend = Backend(), registered = expectation(description: "registered")
            backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
            let invalidations = Box(0)
            let group = make(backend, invalidated: { invalidations.update { $0 += 1 } })
            defer { group.cancel() }
            let task = Task { try await group.resolveCandidates("remove.fixture.invalid") }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("remove.fixture.invalid", .ipv4, answer("remove.fixture.invalid", "192.0.2.1"))
            backend.emit("remove.fixture.invalid", .ipv6, .failure(.noRecord))
            let selected = selection("remove.fixture.invalid", try await task.value)
            XCTAssertTrue(group.admitSelections(selected))
            if finish { XCTAssertTrue(group.finishAdmission()) }
            backend.emit("remove.fixture.invalid", .ipv4, answer("remove.fixture.invalid", "192.0.2.1", added: false))
            await backend.drain()
            XCTAssertTrue(group.isInvalidated)
            XCTAssertFalse(group.isFresh(selected))
            XCTAssertFalse(group.finishAdmission())
            XCTAssertEqual(invalidations.get(), 1)
            backend.emit("remove.fixture.invalid", .ipv4, answer("remove.fixture.invalid", "192.0.2.1", added: false))
            await backend.drain(); XCTAssertEqual(invalidations.get(), 1)
        }
    }

    func testInvalidAnswersCannotCompleteARequiredFamily() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend), ready = Box(false); defer { group.cancel() }
        let task = Task { let result = try await group.resolveCandidates("valid.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("valid.fixture.invalid", .ipv4, answer("valid.fixture.invalid", "192.0.2.1"))
        backend.emit("valid.fixture.invalid", .ipv6, answer("alias.fixture.invalid", "2001:db8::1"))
        backend.emit("valid.fixture.invalid", .ipv6, answer("valid.fixture.invalid", "2001:db8::1", index: 5))
        backend.emit("valid.fixture.invalid", .ipv6, answer("valid.fixture.invalid", "malformed"))
        backend.emit("valid.fixture.invalid", .ipv6, .failure(.timeout))
        await backend.drain(); XCTAssertFalse(ready.get())
        backend.emit("valid.fixture.invalid", .ipv6, .failure(.noRecord))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.text), ["192.0.2.1"])
    }

    func testActiveQueriesBoundedAtEightAndFifthHostStartsAfterAFullClose() async throws {
        let backend = Backend(), firstFour = expectation(description: "eight references"), fifth = expectation(description: "fifth starts after slot release")
        backend.started = { _, count, active in
            if count == 8 { firstFour.fulfill() }
            if count == 9 { XCTAssertLessThanOrEqual(active, 7); fifth.fulfill() }
        }
        let group = make(backend, window: 0.2); defer { group.cancel() }
        // Sequentially release each initial result while retaining its query.
        var tasks: [Task<TunnelEndpointCandidates, Error>] = []
        for index in 1...5 { tasks.append(Task { try await group.resolveCandidates("h\(index).fixture.invalid") }) }
        await fulfillment(of: [firstFour], timeout: 1)
        XCTAssertEqual(backend.counts.registered, 8)
        await fulfillment(of: [fifth], timeout: 1)
        // Empty snapshots finish at the ceiling without any public lookup.
        for task in tasks { _ = try await task.value }
        XCTAssertEqual(backend.counts.registered, 10)
        XCTAssertLessThanOrEqual(backend.counts.peak, 8)
        XCTAssertEqual(backend.counts.closed, 10)
    }

    func testCancelClosesActiveAndQueuedWaitersAndIgnoresLateReplies() async throws {
        let backend = Backend(), registered = expectation(description: "eight references")
        backend.started = { _, count, _ in if count == 8 { registered.fulfill() } }
        let group = make(backend)
        let tasks = (1...5).map { index in Task { try await group.resolveCandidates("c\(index).fixture.invalid") } }
        await fulfillment(of: [registered], timeout: 1)
        group.cancel()
        for task in tasks {
            do { _ = try await task.value; XCTFail("Cancelled group returned a result") }
            catch { XCTAssertTrue(error is CancellationError) }
        }
        await backend.drain()
        XCTAssertEqual(backend.counts.registered, 8)
        XCTAssertEqual(backend.counts.closed, 8)
        XCTAssertEqual(backend.counts.active, 0)
    }

    func testLiteralAndEncryptedFallbackSelectionsDoNotRequireSystemLeases() async throws {
        let backend = Backend()
        let group = TunnelEndpointDiscovery(path: dual, deadline: now + 5, now: { ProcessInfo.processInfo.systemUptime },
            isCurrent: { true }, onInvalidated: {}, query: { _, _, _, _, _ in nil },
            fallback: { _, _ in "192.0.2.9" })
        defer { group.cancel() }
        let literal = try await group.resolveCandidates("192.0.2.8")
        XCTAssertEqual(literal.candidates[0].origin, .literal)
        XCTAssertTrue(group.admitSelections(selection("192.0.2.8", literal)))
        let fallback = try await group.resolveCandidates("vpn.example.com")
        XCTAssertEqual(fallback.candidates[0].origin, .encryptedIPv4Answer)
        XCTAssertTrue(group.admitSelections(selection("vpn.example.com", fallback)))
        XCTAssertTrue(group.finishAdmission())
        XCTAssertTrue(group.isFresh(selection("vpn.example.com", fallback)))
        XCTAssertEqual(backend.counts.registered, 0)
    }

    func testRemovalWithoutInitialAddDoesNotCertifyFamilyCompletion() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend), ready = Box(false); defer { group.cancel() }
        let task = Task { let value = try await group.resolveCandidates("remove-only.fixture.invalid"); ready.set(true); return value }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("remove-only.fixture.invalid", .ipv4, answer("remove-only.fixture.invalid", "192.0.2.1"))
        backend.emit("remove-only.fixture.invalid", .ipv6, answer("remove-only.fixture.invalid", "2001:db8::1", added: false))
        await backend.drain(); XCTAssertFalse(ready.get())
        backend.emit("remove-only.fixture.invalid", .ipv6, .failure(.noRecord))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.text), ["192.0.2.1"])
    }

    func testRevocationDuringFirstRegistrationDrainsAllOtherCallersWithoutSecondQuery() async throws {
        let current = Box(true), entered = expectation(description: "first native registration")
        let release = DispatchSemaphore(value: 0), registered = Box(0), closed = Box(0)
        let group = TunnelEndpointDiscovery(path: dual, deadline: now + 5, now: { ProcessInfo.processInfo.systemUptime },
            isCurrent: current.get, onInvalidated: {}, query: { _, _, _, _, _ in
                registered.update { $0 += 1 }
                entered.fulfill()
                XCTAssertEqual(release.wait(timeout: .now() + 2), .success)
                return { closed.update { $0 += 1 } }
            })
        let first = Task { try await group.resolveCandidates("first.fixture.invalid") }
        await fulfillment(of: [entered], timeout: 1)
        let later = (1...5).map { n in Task { try await group.resolveCandidates("queued\(n).fixture.invalid") } }
        current.set(false); release.signal()
        for task in [first] + later {
            do { _ = try await task.value; XCTFail("Revoked group returned a candidate") }
            catch { XCTAssertTrue(error is CancellationError) }
        }
        XCTAssertEqual(registered.get(), 1)
        XCTAssertEqual(closed.get(), 1)
        group.cancel()
    }

    func testLateAAAAEvidenceRequiresCheckpointAndReportsUnsupportedFamilyHonestly() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let path = TunnelEndpointPath(generation: 7, interfaceIndex: 4, interfaceName: "en0", supportsIPv4: true, supportsIPv6: false, supportsDNS: true)
        let logs = Box<[String]>([])
        let group = make(backend, path: path, event: { message in logs.update { $0.append(message.text) } })
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("v4.fixture.invalid") }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("v4.fixture.invalid", .ipv4, answer("v4.fixture.invalid", "192.0.2.1"))
        let result = try await task.value
        XCTAssertTrue(group.admitSelections(selection("v4.fixture.invalid", result)))
        backend.emit("v4.fixture.invalid", .ipv6, answer("v4.fixture.invalid", "2001:db8::1"))
        await backend.drain()
        XCTAssertFalse(logs.get().contains { $0.contains("lateAAAAAfterSettingsMs=") })
        group.noteProtectedSettingsInstalled(); group.noteProtectedSettingsInstalled()
        backend.emit("v4.fixture.invalid", .ipv6, answer("v4.fixture.invalid", "2001:db8::2"))
        await backend.drain()
        XCTAssertEqual(logs.get().filter { $0.contains("protectedSettingsMs=") }.count, 1)
        XCTAssertTrue(logs.get().contains { $0.contains("usable=false initialReady=true") })
        XCTAssertTrue(logs.get().allSatisfy { !$0.contains("v4.fixture.invalid") && !$0.contains("2001:db8") })
    }

    func testAnyUsableZeroTTLRecordPreventsEarlySnapshotEvenWhenFirstRecordIsLongLived() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend, window: 0.2), ready = Box(false), began = now
        defer { group.cancel() }
        let task = Task { let value = try await group.resolveCandidates("mixed-ttl.fixture.invalid"); ready.set(true); return value }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("mixed-ttl.fixture.invalid", .ipv4, answer("mixed-ttl.fixture.invalid", "192.0.2.1", more: true))
        backend.emit("mixed-ttl.fixture.invalid", .ipv4, answer("mixed-ttl.fixture.invalid", "192.0.2.2", ttl: 0))
        backend.emit("mixed-ttl.fixture.invalid", .ipv6, .failure(.noRecord))
        await backend.drain(); XCTAssertFalse(ready.get())
        let result = try await task.value
        XCTAssertGreaterThanOrEqual(now - began, 0.19)
        XCTAssertEqual(result.candidates.map(\.address.text), ["192.0.2.1", "192.0.2.2"])
    }

    func testTotalHostBoundRejectsSixtyFifthWithoutOpeningMoreReferences() async throws {
        let backend = Backend(), rejected = expectation(description: "host capacity rejected")
        let group = make(backend), invalidConfigurations = Box(0)
        let tasks = (1...65).map { n in Task {
            do { _ = try await group.resolveCandidates("bounded\(n).fixture.invalid") }
            catch {
                if case TunnelXrayConfigPreparer.StartupError.invalidConfiguration = error {
                    invalidConfigurations.update { $0 += 1 }; rejected.fulfill()
                } else { XCTAssertTrue(error is CancellationError) }
            }
        } }
        await fulfillment(of: [rejected], timeout: 1)
        group.cancel()
        for task in tasks { await task.value }
        await backend.drain()
        XCTAssertEqual(invalidConfigurations.get(), 1)
        XCTAssertEqual(backend.counts.registered, 8)
        XCTAssertEqual(backend.counts.closed, 8)
        XCTAssertEqual(backend.counts.peak, 8)
    }

    func testDeadlineRecheckedBeforeStartingTheSecondFamily() async throws {
        let clock = Box<TimeInterval>(10), queries = Box(0), closes = Box(0)
        let group = TunnelEndpointDiscovery(path: dual, deadline: 15, now: clock.get,
            isCurrent: { true }, onInvalidated: {}, query: { _, _, _, _, _ in
                queries.update { $0 += 1 }
                clock.set(16)
                return { closes.update { $0 += 1 } }
            })
        do { _ = try await group.resolveCandidates("deadline.fixture.invalid"); XCTFail("Expired admission succeeded") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(queries.get(), 1)
        XCTAssertEqual(closes.get(), 1)
        group.cancel()
    }

    func testInvalidationNotificationCanReenterAndCancelWithoutHoldingTheLock() async throws {
        let backend = Backend(), registered = expectation(description: "registered"), notified = expectation(description: "outside-lock notification")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let holder = Box<TunnelEndpointDiscovery?>(nil)
        let group = make(backend, invalidated: {
            XCTAssertTrue(holder.get()?.isInvalidated == true)
            holder.get()?.cancel()
            notified.fulfill()
        })
        holder.set(group); defer { holder.set(nil); group.cancel() }
        let task = Task { try await group.resolveCandidates("reentry.fixture.invalid") }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("reentry.fixture.invalid", .ipv4, answer("reentry.fixture.invalid", "192.0.2.1"))
        backend.emit("reentry.fixture.invalid", .ipv6, .failure(.noRecord))
        let result = try await task.value
        XCTAssertTrue(group.admitSelections(selection("reentry.fixture.invalid", result)))
        backend.emit("reentry.fixture.invalid", .ipv4, answer("reentry.fixture.invalid", "192.0.2.1", added: false))
        await fulfillment(of: [notified], timeout: 1)
        await backend.drain()
        XCTAssertEqual(backend.counts.closed, 2)
    }

    func testTaskCancelledBeforeAdmissionNeverRegistersAQuery() async throws {
        let backend = Backend(), admission = DispatchSemaphore(value: 0)
        let group = make(backend)
        let task = Task { admission.wait(); return try await group.resolveCandidates("cancelled.fixture.invalid") }
        task.cancel(); admission.signal()
        do { _ = try await task.value; XCTFail("Cancelled task resolved") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(backend.counts.registered, 0)
        XCTAssertFalse(group.isFresh([]))
    }

    func testRemoveAddReplacementBatchDoesNotInvalidateSelectedAddressBeforeOrAfterCore() async throws {
        for finish in [false, true] {
            let backend = Backend(), registered = expectation(description: "registered")
            backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
            let invalidations = Box(0)
            let group = make(backend, invalidated: { invalidations.update { $0 += 1 } })
            defer { group.cancel() }
            let task = Task { try await group.resolveCandidates("batch.fixture.invalid") }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("batch.fixture.invalid", .ipv4, answer("batch.fixture.invalid", "192.0.2.1"))
            backend.emit("batch.fixture.invalid", .ipv6, .failure(.noRecord))
            let selected = selection("batch.fixture.invalid", try await task.value)
            XCTAssertTrue(group.admitSelections(selected))
            if finish { XCTAssertTrue(group.finishAdmission()) }
            backend.emit("batch.fixture.invalid", .ipv4,
                answer("batch.fixture.invalid", "192.0.2.1", added: false, more: true))
            await backend.drain()
            XCTAssertTrue(group.isFresh(selected), "A queued replacement must not expose a transient removal")
            XCTAssertFalse(group.isInvalidated)
            backend.emit("batch.fixture.invalid", .ipv4, answer("batch.fixture.invalid", "192.0.2.1", ttl: 60))
            await backend.drain()
            XCTAssertTrue(group.isFresh(selected))
            XCTAssertEqual(invalidations.get(), 0)
            XCTAssertTrue(group.finishAdmission())
        }
    }

    func testCrossFamilyBatchesCommitTogetherAndNegativeErrorCannotCloseAnOpenBatch() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let invalidations = Box(0)
        let group = make(backend, invalidated: { invalidations.update { $0 += 1 } })
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("cross.fixture.invalid") }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("cross.fixture.invalid", .ipv4, answer("cross.fixture.invalid", "192.0.2.1"))
        backend.emit("cross.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("cross.fixture.invalid", try await task.value)
        XCTAssertTrue(group.admitSelections(selected))
        backend.emit("cross.fixture.invalid", .ipv4,
            answer("cross.fixture.invalid", "192.0.2.1", added: false, more: true))
        backend.emit("cross.fixture.invalid", .ipv6, answer("cross.fixture.invalid", "2001:db8::1", more: true))
        backend.emit("cross.fixture.invalid", .ipv4, .failure(.noRecord))
        backend.emit("cross.fixture.invalid", .ipv6, answer("cross.fixture.invalid", "2001:db8::2"))
        await backend.drain()
        XCTAssertTrue(group.isFresh(selected), "IPv6 completion or an error cannot close the outstanding IPv4 batch")
        XCTAssertEqual(invalidations.get(), 0)
        backend.emit("cross.fixture.invalid", .ipv4,
            answer("cross.fixture.invalid", "192.0.2.1", added: false))
        await backend.drain()
        XCTAssertTrue(group.isInvalidated, "The complete batch now genuinely removes the selected address")
        XCTAssertEqual(invalidations.get(), 1)
    }

    func testDanglingBatchFlushesOnlyAtTheOriginalCollectionBound() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend, window: 0.2), ready = Box(false), began = now
        defer { group.cancel() }
        let task = Task { let result = try await group.resolveCandidates("dangling.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("dangling.fixture.invalid", .ipv4, answer("dangling.fixture.invalid", "192.0.2.1", more: true))
        backend.emit("dangling.fixture.invalid", .ipv6, .failure(.noRecord))
        backend.emit("dangling.fixture.invalid", .ipv4, .failure(.noRecord))
        await backend.drain()
        XCTAssertFalse(ready.get(), "NoSuchRecord has no defined batch flags and cannot close the open batch")
        let result = try await task.value
        XCTAssertGreaterThanOrEqual(now - began, 0.19)
        XCTAssertEqual(result.candidates.map(\.address.text), ["192.0.2.1"], "At the ceiling preserve the old complete-window accumulation")
    }

    func testOneCompleteFamilyStillWaitsForTheOtherInitialFamily() async throws {
        let backend = Backend(), registered = expectation(description: "registered")
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        let group = make(backend), ready = Box(false)
        defer { group.cancel() }
        let task = Task { let result = try await group.resolveCandidates("quorum.fixture.invalid"); ready.set(true); return result }
        await fulfillment(of: [registered], timeout: 1)
        backend.emit("quorum.fixture.invalid", .ipv4, answer("quorum.fixture.invalid", "192.0.2.1"))
        await backend.drain()
        XCTAssertFalse(ready.get(), "MoreComing=false on A alone is not proof that AAAA finished")
        backend.emit("quorum.fixture.invalid", .ipv6, answer("quorum.fixture.invalid", "2001:db8::1"))
        let result = try await task.value
        XCTAssertEqual(result.candidates.map(\.address.family), [.ipv4, .ipv6])
    }

    func testDroppingLastOwnerAfterEarlyReturnClosesBothReferencesAndIgnoresLateCallbacks() async throws {
        let backend = Backend(), registered = expectation(description: "both references open")
        let closed = expectation(description: "both references closed by deinit")
        closed.expectedFulfillmentCount = 2
        backend.started = { _, count, _ in if count == 2 { registered.fulfill() } }
        backend.didClose = { closed.fulfill() }
        let messages = Box<[String]>([])
        var discovery: TunnelEndpointDiscovery? = make(backend, event: { message in
            messages.update { $0.append(message.text) }
        })
        weak var weakDiscovery = discovery
        let result = try await withThrowingTaskGroup(of: TunnelEndpointCandidates.self) { tasks in
            tasks.addTask { [owner = discovery!] in try await owner.resolveCandidates("deinit.fixture.invalid") }
            await fulfillment(of: [registered], timeout: 1)
            backend.emit("deinit.fixture.invalid", .ipv4, answer("deinit.fixture.invalid", "192.0.2.1"))
            backend.emit("deinit.fixture.invalid", .ipv6, .failure(.noRecord))
            return try await tasks.next()!
        }
        XCTAssertEqual(result.candidates.map(\.address.text), ["192.0.2.1"])
        XCTAssertEqual(backend.counts.closed, 0, "Initial return must leave both subscriptions alive")
        let beforeDrop = messages.get()
        discovery = nil
        XCTAssertNil(weakDiscovery, "No timer, callback or completed child task may retain the owner")
        await fulfillment(of: [closed], timeout: 1)
        XCTAssertEqual(backend.counts.closed, 2)
        backend.emit("deinit.fixture.invalid", .ipv4,
            answer("deinit.fixture.invalid", "192.0.2.1", added: false))
        backend.emit("deinit.fixture.invalid", .ipv6, answer("deinit.fixture.invalid", "2001:db8::1"))
        await backend.drain()
        XCTAssertEqual(messages.get(), beforeDrop, "Late callbacks cannot revive an abandoned discovery")
        XCTAssertEqual(backend.counts.closed, 2)
        XCTAssertEqual(backend.counts.active, 0)
    }

    func testLiveTTLRefreshRemainsAuthoritativeAfterTheOriginalSelectedTTLExpires() async throws {
        let backend = Backend(), scheduled = expectation(description: "deadline registered")
        let clock = EndpointDeadlineTestScheduler()
        clock.scheduled = { scheduled.fulfill() }
        let group = make(backend, clock: clock.now, schedule: clock.schedule)
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("refresh.fixture.invalid") }
        await fulfillment(of: [scheduled], timeout: 1)
        backend.emit("refresh.fixture.invalid", .ipv4, answer("refresh.fixture.invalid", "192.0.2.1"))
        backend.emit("refresh.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("refresh.fixture.invalid", try await task.value)
        XCTAssertTrue(group.admitSelections(selected))
        XCTAssertTrue(group.finishAdmission())
        clock.advance(to: 1)
        backend.emit("refresh.fixture.invalid", .ipv4, answer("refresh.fixture.invalid", "192.0.2.1", ttl: 60))
        await backend.drain()
        clock.advance(to: 2); await clock.drain()
        clock.advance(to: 31)
        XCTAssertFalse(selected[0].selected.isUsable(on: dual, at: clock.now()))
        XCTAssertTrue(group.isFresh(selected, at: clock.now()), "The same address's accepted TTL update must not cause an unnecessary Core refresh")
        XCTAssertFalse(group.claimInitialInvalidationIfNeeded())
        XCTAssertFalse(group.isInvalidated)
    }

    func testLiveSelectedExpiryCanBeClaimedOnceWithTheLatchVisibleBeforeReentrantCancel() async throws {
        let backend = Backend(), scheduled = expectation(description: "deadline registered")
        let clock = EndpointDeadlineTestScheduler(), invalidations = Box(0)
        clock.scheduled = { scheduled.fulfill() }
        let holder = Box<TunnelEndpointDiscovery?>(nil)
        let group = make(backend, clock: clock.now, invalidated: {
            XCTAssertTrue(holder.get()?.isInvalidated == true)
            invalidations.update { $0 += 1 }
            holder.get()?.cancel()
        }, schedule: clock.schedule)
        holder.set(group); defer { holder.set(nil); group.cancel() }
        let task = Task { try await group.resolveCandidates("shorten.fixture.invalid") }
        await fulfillment(of: [scheduled], timeout: 1)
        backend.emit("shorten.fixture.invalid", .ipv4, answer("shorten.fixture.invalid", "192.0.2.1"))
        backend.emit("shorten.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("shorten.fixture.invalid", try await task.value)
        XCTAssertTrue(group.admitSelections(selected))
        XCTAssertTrue(group.finishAdmission())
        clock.advance(to: 0.2)
        backend.emit("shorten.fixture.invalid", .ipv4, answer("shorten.fixture.invalid", "192.0.2.1", ttl: 1))
        await backend.drain()
        clock.advance(to: 1.3)
        XCTAssertFalse(group.isFresh(selected, at: clock.now()))
        XCTAssertTrue(group.claimInitialInvalidationIfNeeded())
        XCTAssertFalse(group.claimInitialInvalidationIfNeeded())
        XCTAssertEqual(invalidations.get(), 1)
        await backend.drain()
        XCTAssertEqual(backend.counts.closed, 2)
    }

    func testOrdinarySelectedExpiryAfterSealNeverClaimsInitialCorrection() async throws {
        let backend = Backend(), scheduled = expectation(description: "deadline registered")
        let clock = EndpointDeadlineTestScheduler(), invalidations = Box(0)
        clock.scheduled = { scheduled.fulfill() }
        let group = make(backend, clock: clock.now, invalidated: { invalidations.update { $0 += 1 } }, schedule: clock.schedule)
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("sealed.fixture.invalid") }
        await fulfillment(of: [scheduled], timeout: 1)
        backend.emit("sealed.fixture.invalid", .ipv4, answer("sealed.fixture.invalid", "192.0.2.1"))
        backend.emit("sealed.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("sealed.fixture.invalid", try await task.value)
        XCTAssertTrue(group.admitSelections(selected))
        clock.advance(to: 1.5)
        backend.emit("sealed.fixture.invalid", .ipv4, answer("sealed.fixture.invalid", "192.0.2.1", ttl: 1))
        await backend.drain()
        clock.advance(to: 2); await clock.drain()
        clock.advance(to: 2.6)
        XCTAssertFalse(group.isFresh(selected, at: clock.now()))
        XCTAssertFalse(group.claimInitialInvalidationIfNeeded())
        XCTAssertFalse(group.isInvalidated)
        XCTAssertEqual(invalidations.get(), 0)
    }

    func testRecordHealedBetweenFreshnessCheckAndClaimDoesNotRevokeThePlan() async throws {
        let backend = Backend(), scheduled = expectation(description: "deadline registered")
        let clock = EndpointDeadlineTestScheduler(), invalidations = Box(0)
        clock.scheduled = { scheduled.fulfill() }
        let group = make(backend, clock: clock.now, invalidated: { invalidations.update { $0 += 1 } }, schedule: clock.schedule)
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("healed.fixture.invalid") }
        await fulfillment(of: [scheduled], timeout: 1)
        backend.emit("healed.fixture.invalid", .ipv4, answer("healed.fixture.invalid", "192.0.2.1"))
        backend.emit("healed.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("healed.fixture.invalid", try await task.value)
        XCTAssertTrue(group.admitSelections(selected))
        clock.advance(to: 0.2)
        backend.emit("healed.fixture.invalid", .ipv4, answer("healed.fixture.invalid", "192.0.2.1", ttl: 1))
        await backend.drain()
        clock.advance(to: 1.3)
        XCTAssertFalse(group.isFresh(selected, at: clock.now()))
        backend.emit("healed.fixture.invalid", .ipv4, answer("healed.fixture.invalid", "192.0.2.1"))
        await backend.drain()
        XCTAssertFalse(group.claimInitialInvalidationIfNeeded())
        XCTAssertTrue(group.isFresh(selected, at: clock.now()))
        XCTAssertFalse(group.isInvalidated)
        XCTAssertEqual(invalidations.get(), 0)
    }

    func testAnotherHostsOpenLeaseCannotTurnSealedOrdinaryExpiryIntoInitialCorrection() async throws {
        let backend = Backend(), first = expectation(description: "first deadline"), second = expectation(description: "second deadline")
        let clock = EndpointDeadlineTestScheduler(), scheduledCount = Box(0), invalidations = Box(0)
        clock.scheduled = {
            scheduledCount.update { $0 += 1 }
            if scheduledCount.get() == 1 { first.fulfill() } else { second.fulfill() }
        }
        let group = make(backend, clock: clock.now, invalidated: { invalidations.update { $0 += 1 } }, schedule: clock.schedule)
        defer { group.cancel() }
        let a = Task { try await group.resolveCandidates("a.fixture.invalid") }
        await fulfillment(of: [first], timeout: 1)
        backend.emit("a.fixture.invalid", .ipv4, answer("a.fixture.invalid", "192.0.2.1", ttl: 3))
        backend.emit("a.fixture.invalid", .ipv6, .failure(.noRecord))
        let selectedA = selection("a.fixture.invalid", try await a.value)
        clock.advance(to: 1.5)
        let b = Task { try await group.resolveCandidates("b.fixture.invalid") }
        await fulfillment(of: [second], timeout: 1)
        backend.emit("b.fixture.invalid", .ipv4, answer("b.fixture.invalid", "192.0.2.2"))
        backend.emit("b.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selectedA + selection("b.fixture.invalid", try await b.value)
        XCTAssertTrue(group.admitSelections(selected))
        clock.advance(to: 2); await clock.drain()
        clock.advance(to: 3.1)
        backend.emit("b.fixture.invalid", .ipv6, answer("b.fixture.invalid", "2001:db8::2"))
        await backend.drain()
        XCTAssertFalse(group.isFresh(selected, at: clock.now()), "Host A has an ordinary expired sealed witness")
        XCTAssertFalse(group.claimInitialInvalidationIfNeeded(), "Host B's still-open window must not lend authority to host A")
        XCTAssertFalse(group.isInvalidated)
        XCTAssertEqual(invalidations.get(), 0)
    }

    func testCancelledEarlySelectionRetainsItsIncompleteCollectionWitnessWhileSealedOneDoesNot() async throws {
        for sealFirst in [false, true] {
            let backend = Backend(), scheduled = expectation(description: "deadline registered")
            let clock = EndpointDeadlineTestScheduler(), invalidations = Box(0)
            clock.scheduled = { scheduled.fulfill() }
            let current = Box(true)
            let group = make(backend, clock: clock.now, current: current.get,
                invalidated: { invalidations.update { $0 += 1 } }, schedule: clock.schedule)
            defer { group.cancel() }
            XCTAssertFalse(group.hasUnsealedSystemSelections, "No admitted selection is provisional")
            let task = Task { try await group.resolveCandidates("sleep.fixture.invalid") }
            await fulfillment(of: [scheduled], timeout: 1)
            backend.emit("sleep.fixture.invalid", .ipv4, answer("sleep.fixture.invalid", "192.0.2.1"))
            backend.emit("sleep.fixture.invalid", .ipv6, .failure(.noRecord))
            let selected = selection("sleep.fixture.invalid", try await task.value)
            XCTAssertTrue(group.admitSelections(selected))
            XCTAssertTrue(group.finishAdmission())
            XCTAssertTrue(group.hasUnsealedSystemSelections, "Native start alone cannot finish the DNS window")
            if sealFirst { clock.advance(to: 2); await clock.drain() }
            current.set(false)
            group.cancel(); await backend.drain()
            XCTAssertEqual(group.hasUnsealedSystemSelections, !sealFirst,
                "Wake must retain the original collection boundary even after Sleep revokes the token and cancels queries")
            XCTAssertEqual(invalidations.get(), 0, "Reading incompleteness and cancellation do not invent a Remove")
            XCTAssertEqual(backend.counts.closed, 2)
        }
    }

    func testUnselectedOpenHostCannotMakeASealedAdmittedSelectionProvisional() async throws {
        let backend = Backend(), first = expectation(description: "selected host deadline"), second = expectation(description: "unselected host deadline")
        let clock = EndpointDeadlineTestScheduler(), scheduledCount = Box(0)
        clock.scheduled = {
            scheduledCount.update { $0 += 1 }
            if scheduledCount.get() == 1 { first.fulfill() } else { second.fulfill() }
        }
        let group = make(backend, clock: clock.now, schedule: clock.schedule)
        defer { group.cancel() }
        let a = Task { try await group.resolveCandidates("selected.fixture.invalid") }
        await fulfillment(of: [first], timeout: 1)
        backend.emit("selected.fixture.invalid", .ipv4, answer("selected.fixture.invalid", "192.0.2.1"))
        backend.emit("selected.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("selected.fixture.invalid", try await a.value)
        XCTAssertTrue(group.admitSelections(selected))
        clock.advance(to: 2); await clock.drain()
        let b = Task { try await group.resolveCandidates("unselected.fixture.invalid") }
        await fulfillment(of: [second], timeout: 1)
        XCTAssertFalse(group.hasUnsealedSystemSelections,
            "An unrelated unsealed query is not the selected endpoint's initial transaction")
        group.cancel()
        do { _ = try await b.value; XCTFail("Cancelled unselected query returned") }
        catch { XCTAssertTrue(error is CancellationError) }
        await backend.drain()
        XCTAssertFalse(group.hasUnsealedSystemSelections)
        XCTAssertEqual(backend.counts.closed, 4)
    }

    func testSleepDrainUsesTheExistingWindowAndRetainsLateAAAAUntilActualSeal() async throws {
        let backend = Backend(), scheduled = expectation(description: "existing deadline")
        let clock = EndpointDeadlineTestScheduler(), completed = Box(false)
        clock.scheduled = { scheduled.fulfill() }
        let group = make(backend, clock: clock.now, schedule: clock.schedule)
        defer { group.cancel() }
        let task = Task { try await group.resolveCandidates("drain.fixture.invalid") }
        await fulfillment(of: [scheduled], timeout: 1)
        backend.emit("drain.fixture.invalid", .ipv4, answer("drain.fixture.invalid", "192.0.2.1"))
        backend.emit("drain.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("drain.fixture.invalid", try await task.value)
        XCTAssertTrue(group.admitSelections(selected)); XCTAssertTrue(group.finishAdmission())
        clock.advance(to: 1.5)
        let drain = Task { try await group.waitForInitialSelectionsToSeal(); completed.set(true) }
        await awaitSealWaiters(group, count: 1)
        XCTAssertEqual(clock.snapshot.deadlines, [2], "Sleep must not create another collection timer")
        clock.advance(to: 1.9)
        backend.emit("drain.fixture.invalid", .ipv6, answer("drain.fixture.invalid", "2001:db8::1"))
        await backend.drain()
        XCTAssertFalse(completed.get())
        XCTAssertEqual(backend.counts.closed, 0)
        clock.advance(to: 2); await clock.drain()
        try await drain.value
        XCTAssertFalse(group.hasUnsealedSystemSelections)
        XCTAssertTrue(group.isFresh(selected, at: clock.now()))
        let final = try await group.resolveCandidates("drain.fixture.invalid")
        XCTAssertEqual(final.candidates.map(\.address.text), ["192.0.2.1", "2001:db8::1"])
        XCTAssertEqual(backend.counts.registered, 2)
        XCTAssertEqual(backend.counts.closed, 2)
    }

    func testSleepDrainFailsAllWaitersOnCancelOrPendingRemovalFlushedAtOriginalSeal() async throws {
        for cancel in [false, true] {
            let backend = Backend(), scheduled = expectation(description: "existing deadline")
            let clock = EndpointDeadlineTestScheduler(), invalidations = Box(0)
            clock.scheduled = { scheduled.fulfill() }
            let group = make(backend, clock: clock.now,
                invalidated: { invalidations.update { $0 += 1 } }, schedule: clock.schedule)
            defer { group.cancel() }
            let task = Task { try await group.resolveCandidates("drain-failure.fixture.invalid") }
            await fulfillment(of: [scheduled], timeout: 1)
            backend.emit("drain-failure.fixture.invalid", .ipv4, answer("drain-failure.fixture.invalid", "192.0.2.1"))
            backend.emit("drain-failure.fixture.invalid", .ipv6, .failure(.noRecord))
            let selected = selection("drain-failure.fixture.invalid", try await task.value)
            XCTAssertTrue(group.admitSelections(selected))
            let waits = (0..<2).map { _ in Task { try await group.waitForInitialSelectionsToSeal() } }
            await awaitSealWaiters(group, count: 2)
            if cancel { group.cancel() }
            else {
                clock.advance(to: 1.9)
                backend.emit("drain-failure.fixture.invalid", .ipv4,
                    answer("drain-failure.fixture.invalid", "192.0.2.1", added: false, more: true))
                await backend.drain()
                XCTAssertTrue(group.isFresh(selected, at: clock.now()), "Pending removal is not yet visible")
                clock.advance(to: 2); await clock.drain()
            }
            for wait in waits {
                do { try await wait.value; XCTFail("Unhealthy collection was reported sealed successfully") }
                catch { XCTAssertTrue(error is CancellationError) }
            }
            await backend.drain()
            XCTAssertEqual(group.pendingInitialSealWaiterCount, 0)
            XCTAssertEqual(backend.counts.closed, 2)
            XCTAssertEqual(invalidations.get(), cancel ? 0 : 1)
        }
    }

    func testCancelingOneSleepDrainBeforeOrAfterRegistrationKeepsDiscoveryAndOtherWaiterAlive() async throws {
        for beforeRegistration in [false, true] {
            let backend = Backend(), scheduled = expectation(description: "existing deadline")
            let clock = EndpointDeadlineTestScheduler(), active = Box(false)
            clock.scheduled = { scheduled.fulfill() }
            let group = make(backend, clock: clock.now, schedule: clock.schedule)
            defer { group.cancel() }
            let task = Task { try await group.resolveCandidates("drain-cancel.fixture.invalid") }
            await fulfillment(of: [scheduled], timeout: 1)
            backend.emit("drain-cancel.fixture.invalid", .ipv4, answer("drain-cancel.fixture.invalid", "192.0.2.1"))
            backend.emit("drain-cancel.fixture.invalid", .ipv6, .failure(.noRecord))
            let selected = selection("drain-cancel.fixture.invalid", try await task.value)
            XCTAssertTrue(group.admitSelections(selected))
            let release = DispatchSemaphore(value: 0)
            if beforeRegistration {
                let blocked = expectation(description: "registration blocked")
                backend.enqueue { blocked.fulfill(); release.wait() }
                await fulfillment(of: [blocked], timeout: 1)
            }
            let abandoned = Task { try await group.waitForInitialSelectionsToSeal() }
            if !beforeRegistration { await awaitSealWaiters(group, count: 1) }
            abandoned.cancel()
            do { try await abandoned.value; XCTFail("Canceled drain returned success") }
            catch { XCTAssertTrue(error is CancellationError) }
            if beforeRegistration { release.signal() }
            await backend.drain()
            XCTAssertTrue(group.isFresh(selected, at: clock.now()), "Wake cancels only its preparatory wait")
            XCTAssertFalse(group.isInvalidated)
            XCTAssertEqual(backend.counts.closed, 0)
            let retained = Task { try await group.waitForInitialSelectionsToSeal(); active.set(true) }
            await awaitSealWaiters(group, count: 1)
            XCTAssertFalse(active.get())
            clock.advance(to: 2); await clock.drain()
            try await retained.value
            XCTAssertEqual(backend.counts.closed, 2)
        }
    }

    func testSleepDrainReturnsImmediatelyForSealedSelectedHostsDespiteUnselectedOpenQuery() async throws {
        let backend = Backend(), first = expectation(description: "selected deadline"), second = expectation(description: "unselected deadline")
        let clock = EndpointDeadlineTestScheduler(), count = Box(0)
        clock.scheduled = {
            count.update { $0 += 1 }
            if count.get() == 1 { first.fulfill() } else { second.fulfill() }
        }
        let group = make(backend, clock: clock.now, schedule: clock.schedule)
        defer { group.cancel() }
        try await group.waitForInitialSelectionsToSeal()
        XCTAssertEqual(backend.counts.registered, 0, "No selected host creates no DNS work")
        let a = Task { try await group.resolveCandidates("drain-selected.fixture.invalid") }
        await fulfillment(of: [first], timeout: 1)
        backend.emit("drain-selected.fixture.invalid", .ipv4, answer("drain-selected.fixture.invalid", "192.0.2.1"))
        backend.emit("drain-selected.fixture.invalid", .ipv6, .failure(.noRecord))
        let selected = selection("drain-selected.fixture.invalid", try await a.value)
        XCTAssertTrue(group.admitSelections(selected))
        clock.advance(to: 2); await clock.drain()
        let b = Task { try await group.resolveCandidates("drain-unselected.fixture.invalid") }
        await fulfillment(of: [second], timeout: 1)
        try await group.waitForInitialSelectionsToSeal()
        XCTAssertEqual(clock.now(), 2)
        XCTAssertEqual(backend.counts.registered, 4)
        XCTAssertEqual(backend.counts.closed, 2, "Unselected subscriptions keep their own existing window")
        group.cancel()
        do { _ = try await b.value; XCTFail("Canceled unselected query returned") }
        catch { XCTAssertTrue(error is CancellationError) }
    }
}
