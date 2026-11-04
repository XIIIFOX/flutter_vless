import Foundation
import XCTest
@testable import flutter_vless_tunnel_support

/// Every query is injected. These cases exercise collection scheduling and
/// ownership without starting DNS, a VPN, Core, or a recurring background timer.
final class TunnelEndpointCollectionScheduleTests: XCTestCase {
    private let path = TunnelEndpointPath(generation: 1, interfaceIndex: 4, interfaceName: "en0",
        supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    private final class Capture: @unchecked Sendable {
        private let lock = NSLock()
        private var closes = 0
        private var messages: [String] = []
        private var callback: ((TunnelEndpointDNSAnswer) -> Void)?
        private var queue: DispatchQueue?
        private var current = true

        func didClose() {
            lock.lock(); defer { lock.unlock() }
            closes += 1
        }

        func record(_ message: NativeDiagnosticMessage) {
            lock.lock(); defer { lock.unlock() }
            messages.append(message.text)
        }

        func didRegister(_ callback: @escaping (TunnelEndpointDNSAnswer) -> Void, queue: DispatchQueue) {
            lock.lock(); defer { lock.unlock() }
            self.callback = callback
            self.queue = queue
        }

        func revoke() {
            lock.lock(); defer { lock.unlock() }
            current = false
        }

        func isCurrent() -> Bool {
            lock.lock(); defer { lock.unlock() }
            return current
        }

        var snapshot: (closes: Int, messages: [String], callback: ((TunnelEndpointDNSAnswer) -> Void)?, queue: DispatchQueue?) {
            lock.lock(); defer { lock.unlock() }
            return (closes, messages, callback, queue)
        }
    }

    func testFullTwoSecondWindowRetainsAAAAArrivingAt1900Milliseconds() async throws {
        let capture = Capture()
        let began = now
        let answers = try await TunnelEndpointDNSCollection.collect("schedule.fixture.invalid", path: path,
            deadline: now + 4, event: capture.record, query: { host, _, _, receive in
                receive(.init(hostname: host, text: "192.0.2.197", interfaceIndex: 0, ttl: 30, added: true))
                // A sleeping inert worker avoids coalescing this late answer
                // with the timer under test. It completes before collection ends.
                let workerEntered = DispatchSemaphore(value: 0)
                DispatchQueue.global(qos: .userInitiated).async {
                    workerEntered.signal()
                    Thread.sleep(forTimeInterval: 1.9)
                    receive(.init(hostname: host, text: "2001:db8::197", interfaceIndex: 0, ttl: 30, added: true))
                }
                XCTAssertEqual(workerEntered.wait(timeout: .now() + 1), .success,
                    "The inert late-answer worker must enter before collection is armed")
                return { capture.didClose() }
            })
        XCTAssertGreaterThanOrEqual(now - began, 1.99, "The timer must retain the original full collection window")
        XCTAssertEqual(answers.map(\.address.family), [.ipv4, .ipv6])
        XCTAssertEqual(capture.snapshot.closes, 1)
        XCTAssertEqual(capture.snapshot.messages.count, 2)
    }

    func testShortRemainingDeadlineIsNotRenewedAndDoesNotFireEarly() async throws {
        let capture = Capture()
        let began = now
        let answers = try await TunnelEndpointDNSCollection.collect("schedule.fixture.invalid", path: path,
            deadline: now + 0.25, event: capture.record, query: { host, _, queue, receive in
                queue.asyncAfter(deadline: .now() + 0.1) {
                    receive(.init(hostname: host, text: "192.0.2.197", interfaceIndex: 0, ttl: 30, added: true))
                }
                return { capture.didClose() }
            })
        XCTAssertGreaterThanOrEqual(now - began, 0.24)
        XCTAssertLessThan(now - began, 1, "A short remaining deadline must not become a fresh two-second wait")
        XCTAssertEqual(answers.count, 1)
        XCTAssertEqual(capture.snapshot.closes, 1)
    }

    func testCancellationClosesOnceAndLateCallbackCannotRestartTimer() async throws {
        let capture = Capture()
        let entered = expectation(description: "inert query registered")
        let task = Task {
            try await TunnelEndpointDNSCollection.collect("schedule.fixture.invalid", path: path,
                deadline: now + 4, event: capture.record, query: { _, _, queue, receive in
                    capture.didRegister(receive, queue: queue)
                    entered.fulfill()
                    return { capture.didClose() }
                })
        }
        await fulfillment(of: [entered], timeout: 1)
        task.cancel()
        do { _ = try await task.value; XCTFail("Cancelled collection succeeded") }
        catch { XCTAssertTrue(error is CancellationError) }

        let before = capture.snapshot
        let drained = expectation(description: "late callback drained")
        before.callback?(.init(hostname: "schedule.fixture.invalid", text: "192.0.2.197", interfaceIndex: 0, ttl: 30, added: true))
        try XCTUnwrap(before.queue).async { drained.fulfill() }
        await fulfillment(of: [drained], timeout: 1)
        XCTAssertEqual(capture.snapshot.closes, 1)
        XCTAssertEqual(capture.snapshot.messages, before.messages)
    }

    func testSupersessionBeforeDeadlineCancelsInsteadOfAdoptingAnswer() async throws {
        let capture = Capture()
        do {
            _ = try await TunnelEndpointDNSCollection.collect("schedule.fixture.invalid", path: path,
                deadline: now + 0.1, isCurrent: capture.isCurrent, event: capture.record,
                query: { host, _, queue, receive in
                    receive(.init(hostname: host, text: "192.0.2.197", interfaceIndex: 0, ttl: 30, added: true))
                    queue.asyncAfter(deadline: .now() + 0.03) { capture.revoke() }
                    return { capture.didClose() }
                })
            XCTFail("Superseded collection adopted an answer")
        } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(capture.snapshot.closes, 1)
    }

    func testCancellationBeforeAdmissionNeverStartsQueryOrTimer() async throws {
        let capture = Capture()
        let admission = DispatchSemaphore(value: 0)
        let task = Task {
            // Release only after cancellation, so admission does not depend on
            // whether the task happens to begin before the test calls cancel().
            admission.wait()
            return try await TunnelEndpointDNSCollection.collect("schedule.fixture.invalid", path: path,
                deadline: now + 4, event: capture.record, query: { _, _, _, _ in
                    XCTFail("Cancelled collection entered its backend")
                    return { capture.didClose() }
                })
        }
        task.cancel()
        admission.signal()
        do { _ = try await task.value; XCTFail("Cancelled collection succeeded") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(capture.snapshot.closes, 0)
    }

    func testUnavailableRegistrationDoesNotLeaveAnArmedTimer() async throws {
        let capture = Capture()
        let began = now
        let answers = try await TunnelEndpointDNSCollection.collect("schedule.fixture.invalid", path: path,
            deadline: now + 4, event: capture.record, query: { _, _, _, _ in nil })
        XCTAssertTrue(answers.isEmpty)
        XCTAssertLessThan(now - began, 0.5)
        XCTAssertEqual(capture.snapshot.closes, 0)
        XCTAssertEqual(capture.snapshot.messages.count, 2)
    }
}
