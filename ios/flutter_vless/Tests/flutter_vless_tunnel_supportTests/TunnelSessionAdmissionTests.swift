import Foundation
import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelSessionAdmissionTests: XCTestCase {
    func testOnlyCurrentActivatedSessionMayStartWorkers() {
        let gate = TunnelSessionAdmission()
        let epoch = gate.begin()
        XCTAssertTrue(gate.isCurrent(epoch))
        XCTAssertFalse(gate.permitsRuntime(epoch), "Preparation alone cannot start workers")
        XCTAssertTrue(gate.activate(epoch))
        XCTAssertFalse(gate.activate(epoch), "A duplicate startup completion cannot rearm a watchdog")
        XCTAssertTrue(gate.permitsRuntime(epoch))
        XCTAssertEqual(gate.revoke(), epoch)
        XCTAssertNil(gate.currentEpoch)
        XCTAssertFalse(gate.isCurrent(epoch))
        XCTAssertFalse(gate.permitsRuntime(epoch))
    }

    func testStopRevokesDuringBlockedDrainWithoutWaitingForIt() {
        let gate = TunnelSessionAdmission()
        let epoch = gate.begin()
        XCTAssertTrue(gate.activate(epoch))
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let completed = expectation(description: "drain returned")
        let state = LockedState()
        DispatchQueue.global().async {
            guard gate.permitsRuntime(epoch) else { return XCTFail("Initial admission failed") }
            entered.signal()
            guard release.wait(timeout: .now() + 2) == .success else { return XCTFail("Missing drain release") }
            if gate.permitsRuntime(epoch) { state.recordStart() }
            completed.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(gate.revoke(), epoch)
        XCTAssertFalse(gate.permitsRuntime(epoch))
        release.signal()
        wait(for: [completed], timeout: 2)
        XCTAssertEqual(state.starts, 0)
    }

    func testStoppedWakeTimerFailureAndStartupCompletionCannotRearm() {
        let gate = TunnelSessionAdmission()
        let epoch = gate.begin()
        XCTAssertTrue(gate.activate(epoch))
        gate.revoke()
        for _ in 0..<20 {
            XCTAssertFalse(gate.resume(epoch))
            XCTAssertFalse(gate.suspend(epoch))
            XCTAssertFalse(gate.activate(epoch))
            XCTAssertFalse(gate.isCurrent(epoch))
            XCTAssertFalse(gate.permitsRuntime(epoch))
        }
        XCTAssertNil(gate.revoke(), "Repeated Stop stays closed")
    }

    func testNewSessionRejectsOldAndForeignEpochs() {
        let gate = TunnelSessionAdmission(), other = TunnelSessionAdmission()
        let old = gate.begin()
        XCTAssertTrue(gate.activate(old))
        gate.revoke()
        let current = gate.begin(), foreign = other.begin()
        XCTAssertNotEqual(old, current)
        XCTAssertNotEqual(current, foreign)
        XCTAssertFalse(gate.activate(old))
        XCTAssertFalse(gate.activate(foreign))
        XCTAssertTrue(gate.activate(current))
        XCTAssertFalse(gate.resume(old))
        XCTAssertFalse(gate.suspend(old))
        XCTAssertFalse(gate.permitsRuntime(old))
        XCTAssertTrue(gate.permitsRuntime(current))
    }

    func testSleepAndWakeOnlyAffectTheActivatedCurrentSession() {
        let gate = TunnelSessionAdmission(), epoch = gate.begin()
        XCTAssertFalse(gate.resume(epoch), "A wake during preparation cannot publish startup")
        XCTAssertFalse(gate.suspend(epoch))
        XCTAssertTrue(gate.activate(epoch))
        XCTAssertTrue(gate.suspend(epoch))
        XCTAssertFalse(gate.permitsRuntime(epoch))
        XCTAssertTrue(gate.isCurrent(epoch), "Sleep keeps the same session")
        XCTAssertTrue(gate.resume(epoch))
        XCTAssertTrue(gate.permitsRuntime(epoch))
    }

    func testConcurrentLateAdmissionsNeverReopenRevokedEpoch() {
        for _ in 0..<40 {
            let gate = TunnelSessionAdmission(), epoch = gate.begin()
            let group = DispatchGroup()
            for _ in 0..<4 {
                group.enter()
                DispatchQueue.global().async {
                    _ = gate.activate(epoch); _ = gate.suspend(epoch); _ = gate.resume(epoch)
                    group.leave()
                }
            }
            gate.revoke()
            XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
            XCTAssertNil(gate.currentEpoch)
            XCTAssertFalse(gate.activate(epoch))
            XCTAssertFalse(gate.resume(epoch))
            XCTAssertFalse(gate.permitsRuntime(epoch))
        }
    }
}

private final class LockedState: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var starts: Int { lock.lock(); defer { lock.unlock() }; return count }
    func recordStart() { lock.lock(); defer { lock.unlock() }; count += 1 }
}
