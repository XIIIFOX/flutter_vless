import Foundation
import XCTest
@testable import flutter_vless_macos_tunnel_support

/// Real-clock DNS preparation measurements, not a system VPN benchmark.
/// Only DNS-SD callbacks and encrypted lookup are injected. Production discovery,
/// collection timers, family admission, fallback policy and cancellation execute
/// unchanged. The same file also runs against the 9d18 baseline; CI compares the
/// printed timings instead of choosing different assertions for old/new code.
final class TunnelEndpointStartupTimingTests: XCTestCase {
    private let dual = TunnelEndpointPath(generation: 19, interfaceIndex: 4,
        interfaceName: "en0", supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    private final class Locked<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Value
        init(_ value: Value) { self.value = value }
        func read() -> Value { lock.lock(); defer { lock.unlock() }; return value }
        func change(_ body: (inout Value) -> Void) { lock.lock(); defer { lock.unlock() }; body(&value) }
    }

    private final class Backend: @unchecked Sendable {
        enum Script { case unavailable, negativeThenAAAA, silence, pathRevocation }
        struct Counts {
            var registered = 0; var closed = 0; var active = 0
            var callbackCount = 0; var lateAAAACallbackCount = 0
            var lateAAAACallbackAt: TimeInterval?
        }
        private let script: Script
        private let lock = NSLock()
        private var counts = Counts()
        private var registeredQueue: DispatchQueue?
        private var measurementStart: TimeInterval?
        var onRegistered: (() -> Void)?
        init(_ script: Script) { self.script = script }
        var snapshot: Counts { lock.lock(); defer { lock.unlock() }; return counts }

        func beginMeasurement(at start: TimeInterval) {
            lock.lock(); defer { lock.unlock() }; measurementStart = start
        }

        var lateAAAACallbackMilliseconds: Double? {
            lock.lock(); defer { lock.unlock() }
            guard let start = measurementStart, let delivered = counts.lateAAAACallbackAt else { return nil }
            return (delivered - start) * 1000
        }

        private func recordDelivery(lateAAAA: Bool) {
            let delivered = ProcessInfo.processInfo.systemUptime
            lock.lock(); defer { lock.unlock() }
            counts.callbackCount += 1
            if lateAAAA { counts.lateAAAACallbackCount += 1; counts.lateAAAACallbackAt = delivered }
        }

        func query(_ host: String, _ index: UInt32, _ family: TunnelEndpointAddress.Family,
                   _ queue: DispatchQueue, _ receive: @escaping (TunnelEndpointDiscovery.FamilyEvent) -> Void) -> (() -> Void)? {
            XCTAssertEqual(index, 4)
            lock.lock(); registeredQueue = queue; counts.registered += 1; counts.active += 1
            let complete = counts.registered == 2; lock.unlock()
            let closed = Locked(false)
            var work: [DispatchWorkItem] = []
            func enqueue(after delay: TimeInterval, _ event: TunnelEndpointDiscovery.FamilyEvent, lateAAAA: Bool = false) {
                let item = DispatchWorkItem {
                    guard !closed.read() else { return }
                    // Use the exact queue supplied by production for reference
                    // callbacks and disposal, matching DNSServiceRef ownership.
                    self.recordDelivery(lateAAAA: lateAAAA)
                    receive(event)
                }
                work.append(item)
                queue.asyncAfter(deadline: .now() + delay, execute: item)
            }
            switch script {
            case .unavailable:
                enqueue(after: 0.020, .failure(.serviceUnavailable))
            case .negativeThenAAAA:
                enqueue(after: 0.020, .failure(.noRecord))
                if family == .ipv6 {
                    // The exact 1.9s edge remains in deterministic production
                    // DiscoveryTests. This real-clock probe leaves 500ms of
                    // scheduling headroom inside the unchanged 2s collection.
                    enqueue(after: 1.500, .answer(.init(hostname: host, text: "2001:db8::19",
                        interfaceIndex: 0, ttl: 30, added: true), moreComing: false), lateAAAA: true)
                }
            case .pathRevocation:
                enqueue(after: 0.080, .failure(.serviceUnavailable))
            case .silence:
                break
            }
            if complete { onRegistered?() }
            let scheduledWork = work
            return {
                closed.change { value in XCTAssertFalse(value, "Each real query reference closes once"); value = true }
                scheduledWork.forEach { $0.cancel() }
                self.lock.lock(); self.counts.closed += 1; self.counts.active -= 1; self.lock.unlock()
            }
        }

        private func callbackQueue() -> DispatchQueue? {
            lock.lock(); defer { lock.unlock() }; return registeredQueue
        }

        func drain() async {
            if let queue = callbackQueue() {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    queue.async { continuation.resume() }
                }
            }
        }
    }

    private struct Measurement: Sendable { let result: TunnelEndpointCandidates; let elapsed: TimeInterval }

    private func discovery(_ backend: Backend, path: TunnelEndpointPath? = nil,
                           current: @escaping () -> Bool = { true },
                           fallbackCalls: Locked<Int>, synthesisCalls: Locked<Int>,
                           events: Locked<[String]>? = nil) -> TunnelEndpointDiscovery {
        TunnelEndpointDiscovery(path: path ?? dual, deadline: now + 3.5,
            now: { ProcessInfo.processInfo.systemUptime }, isCurrent: current,
            event: { message in
                // These reserved mock scenarios never query real DNS. Retain
                // only bounded production discovery/fallback diagnostics.
                let text = message.text
                guard text.hasPrefix("Endpoint DNS discovery ") || text.hasPrefix("Endpoint DNS encryptedBootstrapMs=") ||
                    text == "System endpoint DNS unavailable; trying encrypted endpoint bootstrap" ||
                    text == "Encrypted endpoint bootstrap completed" || text == "Encrypted endpoint bootstrap unavailable" else { return }
                events?.change { if $0.count < 16 { $0.append(String(text.prefix(512))) } }
            }, onInvalidated: {}, query: backend.query,
            synthesis: { _, _ in synthesisCalls.change { $0 += 1 }; return [] },
            fallback: { _, remaining in
                XCTAssertGreaterThan(remaining, 0)
                fallbackCalls.change { $0 += 1 }
                try await Task.sleep(nanoseconds: 100_000_000)
                return "192.0.2.19"
            })
    }

    private func printMetric(_ name: String, sample: Int = 0, elapsed: TimeInterval,
                             backend: Backend, fallbackCalls: Int,
                             families: [TunnelEndpointAddress.Family] = [], productionEvents: [String] = []) throws {
        let counts = backend.snapshot
        let delivered: Any = backend.lateAAAACallbackMilliseconds.map { $0 as Any } ?? NSNull()
        // This clock starts before query registration. A false value alone
        // does not establish delivery after the production collection deadline.
        let beforeTwoSeconds: Any = backend.lateAAAACallbackMilliseconds.map { ($0 < 2000) as Any } ?? NSNull()
        let row: [String: Any] = ["schema": 1, "case": name, "sample": sample,
            "elapsed_ms": elapsed * 1000, "fallback_calls": fallbackCalls,
            "registered_refs": counts.registered, "closed_refs": counts.closed,
            "callback_count": counts.callbackCount, "late_aaaa_callback_count": counts.lateAAAACallbackCount,
            "late_aaaa_callback_ms": delivered, "late_aaaa_before_measurement_2s": beforeTwoSeconds,
            "production_events": productionEvents,
            "candidate_families": families.map { $0 == .ipv4 ? "ipv4" : "ipv6" },
            "mode": ProcessInfo.processInfo.environment["FLVLESS_TIMING_MODE"] ?? "unspecified",
            "dns_only": true, "live_ne_vpn": false]
        let bytes = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys])
        print("FLVLESS_ENDPOINT_STARTUP_TIMING " + String(decoding: bytes, as: UTF8.self))
    }

    private func measuredResolve(_ name: String, host: String, script: Backend.Script,
                                 path: TunnelEndpointPath? = nil, sample: Int = 0,
                                 expectedFallbacks: Int, expectedFamily: TunnelEndpointAddress.Family?) async throws {
        let backend = Backend(script), calls = Locked(0), synthesis = Locked(0), events = Locked<[String]>([])
        let registered = expectation(description: name + " registered both DNS-SD references")
        backend.onRegistered = { registered.fulfill() }
        let group = discovery(backend, path: path, fallbackCalls: calls, synthesisCalls: synthesis, events: events)
        defer { group.cancel() }
        let began = now
        backend.beginMeasurement(at: began)
        let task = Task { () async throws -> Measurement in
            let result = try await group.resolveCandidates(host)
            return Measurement(result: result, elapsed: self.now - began)
        }
        await fulfillment(of: [registered], timeout: 1)
        let measured = try await task.value
        let families = measured.result.candidates.map(\.address.family)
        let evidence = "callbacks=\(backend.snapshot.callbackCount) lateAAAACallbackMs=\(String(describing: backend.lateAAAACallbackMilliseconds)) lateBeforeMeasurement2s=\(String(describing: backend.lateAAAACallbackMilliseconds.map { $0 < 2000 })) production=\(events.read())"
        XCTAssertLessThan(measured.elapsed, 3.5, "A shared deadline also applies to the baseline")
        XCTAssertEqual(calls.read(), expectedFallbacks)
        XCTAssertEqual(synthesis.read(), 0, "Named-host failure must not invent NAT64/literal synthesis")
        if let expectedFamily { XCTAssertEqual(families, [expectedFamily], evidence) }
        else { XCTAssertTrue(measured.result.candidates.isEmpty, evidence) }
        if name == "no_record_late_aaaa" {
            XCTAssertGreaterThanOrEqual(measured.elapsed, 1.3, "Negative records are not terminal-service failures; " + evidence)
            XCTAssertEqual(backend.snapshot.callbackCount, 3, evidence)
            XCTAssertEqual(backend.snapshot.lateAAAACallbackCount, 1, evidence)
            XCTAssertNotNil(backend.lateAAAACallbackMilliseconds, evidence)
            if let delivered = backend.lateAAAACallbackMilliseconds {
                XCTAssertGreaterThanOrEqual(measured.elapsed * 1000, delivered, "Result must follow the actual IPv6 callback; " + evidence)
            }
            XCTAssertEqual(measured.result.candidates.first?.origin, .systemNameAnswer, evidence)
            XCTAssertEqual(measured.result.candidates.first?.address.text, "2001:db8::19", evidence)
        }
        if name == "silence_fallback" {
            XCTAssertGreaterThanOrEqual(measured.elapsed, 1.75, "Silence retains the production collection window")
        }
        if name == "terminal_unavailable_fallback" {
            XCTAssertEqual(measured.result.candidates.first?.origin, .encryptedIPv4Answer)
            let selected = measured.result.candidates.map {
                TunnelEndpointSelection(logicalHost: host, candidates: measured.result, selected: $0)
            }
            XCTAssertTrue(group.admitSelections(selected))
            XCTAssertTrue(group.finishAdmission())
            XCTAssertTrue(group.permitsForwardingReady, "Only the actually admitted current candidate may authorize readiness")
        }
        group.cancel(); await backend.drain()
        XCTAssertEqual(backend.snapshot.registered, 2)
        XCTAssertEqual(backend.snapshot.closed, 2)
        XCTAssertEqual(backend.snapshot.active, 0)
        try printMetric(name, sample: sample, elapsed: measured.elapsed, backend: backend,
            fallbackCalls: calls.read(), families: families, productionEvents: events.read())
    }

    func testTerminalUnavailableFallbackRealClockThreeSamples() async throws {
        for sample in 0..<3 {
            try await measuredResolve("terminal_unavailable_fallback", host: "timing.example.com",
                script: .unavailable, sample: sample, expectedFallbacks: 1, expectedFamily: .ipv4)
        }
    }

    func testNegativeRecordsRetainLateAAAAAt1500Milliseconds() async throws {
        try await measuredResolve("no_record_late_aaaa", host: "late.fixture.invalid",
            script: .negativeThenAAAA, expectedFallbacks: 0, expectedFamily: .ipv6)
    }

    func testSilenceRetainsCollectionWindowAndBoundedFallback() async throws {
        try await measuredResolve("silence_fallback", host: "silent.example.com",
            script: .silence, expectedFallbacks: 1, expectedFamily: .ipv4)
    }

    func testPrivateNameNeverReachesInjectedPublicFallback() async throws {
        try await measuredResolve("private_name_no_fallback", host: "private.internal",
            script: .unavailable, expectedFallbacks: 0, expectedFamily: nil)
    }

    func testIPv6OnlyPathNeverUsesIPv4Fallback() async throws {
        let path = TunnelEndpointPath(generation: 19, interfaceIndex: 4, interfaceName: "en0",
            supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        try await measuredResolve("ipv6_only_no_ipv4_fallback", host: "v6.example.com",
            script: .unavailable, path: path, expectedFallbacks: 0, expectedFamily: nil)
    }

    func testStopAndPathRevocationPromptlyDrainRealReferences() async throws {
        for changedPath in [false, true] {
            let name = changedPath ? "path_cancel" : "stop_cancel"
            let backend = Backend(changedPath ? .pathRevocation : .silence)
            let current = Locked(true), calls = Locked(0), synthesis = Locked(0), events = Locked<[String]>([])
            let registered = expectation(description: name + " references registered")
            backend.onRegistered = { registered.fulfill() }
            let group = discovery(backend, current: { current.read() }, fallbackCalls: calls, synthesisCalls: synthesis, events: events)
            defer { group.cancel() }
            let task = Task { try await group.resolveCandidates("cancel.example.com") }
            await fulfillment(of: [registered], timeout: 1)
            try await Task.sleep(nanoseconds: 20_000_000)
            let began = now
            backend.beginMeasurement(at: began)
            if changedPath { current.change { $0 = false } }
            else { group.cancel() }
            do { _ = try await task.value; XCTFail("Stopped or obsolete discovery returned a candidate") }
            catch { XCTAssertTrue(error is CancellationError) }
            let elapsed = now - began
            await backend.drain()
            XCTAssertLessThan(elapsed, 0.9)
            XCTAssertEqual(calls.read(), 0)
            XCTAssertEqual(synthesis.read(), 0)
            XCTAssertFalse(group.permitsForwardingReady)
            XCTAssertEqual(backend.snapshot.closed, 2)
            XCTAssertEqual(backend.snapshot.active, 0)
            try printMetric(name, elapsed: elapsed, backend: backend, fallbackCalls: calls.read(), productionEvents: events.read())
        }
    }
}
