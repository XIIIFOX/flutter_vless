import Foundation
import XCTest
import Darwin
@testable import flutter_vless_tunnel_support

final class TunnelRuntimeSupportTests: XCTestCase {
    func testLifecycleRejectsImmediateWorkerExit() {
        let lifecycle = TunnelProcessLifecycle()
        lifecycle.beginStart()

        DispatchQueue.global().async {
            lifecycle.markThreadEntered()
            lifecycle.markExited(code: -1)
        }

        XCTAssertEqual(
            lifecycle.waitForStableStartup(gracePeriod: 0.05),
            .exited(-1)
        )
    }

    func testLifecycleWaitsForExpectedShutdown() {
        let lifecycle = TunnelProcessLifecycle()
        lifecycle.beginStart()
        lifecycle.markThreadEntered()

        XCTAssertEqual(
            lifecycle.waitForStableStartup(gracePeriod: 0.01),
            .running
        )
        XCTAssertTrue(lifecycle.isRunning)

        lifecycle.requestStop()
        XCTAssertFalse(lifecycle.markExited(code: 0))
        XCTAssertTrue(lifecycle.waitForExit(timeout: 0.01))
        XCTAssertTrue(lifecycle.isStopRequested)
    }

    func testLifecycleMarksUnrequestedExitAsUnexpected() {
        let lifecycle = TunnelProcessLifecycle()
        lifecycle.beginStart()
        lifecycle.markThreadEntered()

        XCTAssertTrue(lifecycle.markExited(code: 9))
        XCTAssertFalse(lifecycle.requestStop(), "Never signal HEV after its event descriptor is closed")
    }

    func testConcurrentStopSignalsWorkerOnlyOnce() {
        let lifecycle = TunnelProcessLifecycle()
        lifecycle.beginStart()
        lifecycle.markThreadEntered()
        let lock = NSLock()
        var signals = 0
        DispatchQueue.concurrentPerform(iterations: 40) { _ in
            if lifecycle.requestStop() {
                lock.lock()
                signals += 1
                lock.unlock()
            }
        }
        XCTAssertEqual(signals, 1)
        XCTAssertFalse(lifecycle.markExited(code: 0))
        XCTAssertFalse(lifecycle.requestStop())
    }

    func testWatchdogRequiresConsecutiveFailures() {
        var policy = TunnelWatchdogFailurePolicy(failureThreshold: 3)

        XCTAssertFalse(policy.record(success: false))
        XCTAssertFalse(policy.record(success: false))
        XCTAssertFalse(policy.record(success: true))
        XCTAssertEqual(policy.consecutiveFailures, 0)
        XCTAssertFalse(policy.record(success: false))
        XCTAssertFalse(policy.record(success: false))
        XCTAssertTrue(policy.record(success: false))
    }

    func testFileLogRotatesAndReturnsOnlyBoundedTail() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = directory.appendingPathComponent("tunnel.log")
        defer { try? FileManager.default.removeItem(at: directory) }

        for index in 0..<100 {
            try TunnelFileLog.append(
                "line-\(index)-xxxxxxxxxxxxxxxxxxxxxxxx",
                to: url,
                maxFileBytes: 512,
                retainedBytes: 256
            )
        }

        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let size = try XCTUnwrap(attributes[.size] as? NSNumber).intValue
        let tail = try TunnelFileLog.tail(of: url, maxBytes: 180, maxLines: 3)

        XCTAssertLessThanOrEqual(size, 512)
        XCTAssertFalse(tail.contains("line-0-"))
        XCTAssertTrue(tail.contains("line-99-"))
        XCTAssertLessThanOrEqual(tail.split(separator: "\n").count, 3)
    }
    func testExternalAppendWriterSurvivesRotationAndPostStopReads() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("hev.log")
        // Match the actual packaged HEV logger's open flags.
        let writer = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        XCTAssertGreaterThanOrEqual(writer, 0)
        guard writer >= 0 else { return }
        var closed = false
        defer { if !closed { close(writer) } }
        let inode = try FileManager.default.attributesOfItem(atPath: url.path)[.systemFileNumber] as? NSNumber
        let before = (0..<100).map { "error-stage-\($0)\n" }.joined()
        XCTAssertEqual(before.withCString { write(writer, $0, strlen($0)) }, before.utf8.count)
        try TunnelFileLog.trimIfNeeded(url, maxFileBytes: 512, retainedBytes: 256)
        let after = "after-rotation-fixed-stage\n"
        XCTAssertEqual(after.withCString { write(writer, $0, strlen($0)) }, after.utf8.count)
        close(writer)
        closed = true
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual(inode, attributes[.systemFileNumber] as? NSNumber)
        XCTAssertLessThanOrEqual((attributes[.size] as! NSNumber).intValue, 256 + after.utf8.count)
        let tail = try TunnelFileLog.tail(of: url)
        XCTAssertTrue(tail.contains("after-rotation-fixed-stage"))
        XCTAssertFalse(tail.contains("error-stage-0\n"))
        XCTAssertEqual(try TunnelFileLog.tail(of: url), tail)
    }

}
