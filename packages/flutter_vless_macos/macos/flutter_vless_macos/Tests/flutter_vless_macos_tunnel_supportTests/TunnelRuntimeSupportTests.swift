import Foundation
import XCTest
@testable import flutter_vless_macos_tunnel_support

final class TunnelRuntimeSupportTests: XCTestCase {
    func testPreparerForcesWarningLogging() throws {
        let source = try JSONSerialization.data(withJSONObject: [
            "log": ["loglevel": "debug"],
            "inbounds": [["protocol": "socks", "port": 10808]],
            "outbounds": [["protocol": "socks", "tag": "proxy", "settings": ["servers": [["address": "127.0.0.1", "port": 9999]]]]]
        ])

        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: try LocalProxyCredentials.generate()))
        let output = try XCTUnwrap(
            JSONSerialization.jsonObject(with: prepared.data) as? [String: Any]
        )
        let log = try XCTUnwrap(output["log"] as? [String: Any])
        XCTAssertEqual(log["loglevel"] as? String, "warning")
        XCTAssertEqual(log["access"] as? String, "none")
        XCTAssertEqual(log["error"] as? String, "none")
    }

    func testImmediateWorkerExitFailsStartup() {
        let lifecycle = TunnelProcessLifecycle()
        lifecycle.beginStart()
        DispatchQueue.global().async {
            lifecycle.markThreadEntered()
            lifecycle.markExited(code: 7)
        }

        XCTAssertEqual(lifecycle.waitForStableStartup(gracePeriod: 0.05), .exited(7))
    }

    func testRequestedStopIsNotUnexpected() {
        let lifecycle = TunnelProcessLifecycle()
        lifecycle.beginStart()
        lifecycle.markThreadEntered()
        XCTAssertEqual(lifecycle.waitForStableStartup(gracePeriod: 0.01), .running)

        lifecycle.requestStop()
        XCTAssertFalse(lifecycle.markExited(code: 0))
        XCTAssertTrue(lifecycle.waitForExit(timeout: 0.01))
    }

    func testWatchdogRequiresThreeConsecutiveFailures() {
        var policy = TunnelWatchdogFailurePolicy(failureThreshold: 3)
        XCTAssertFalse(policy.record(success: false))
        XCTAssertFalse(policy.record(success: false))
        XCTAssertFalse(policy.record(success: true))
        XCTAssertFalse(policy.record(success: false))
        XCTAssertFalse(policy.record(success: false))
        XCTAssertTrue(policy.record(success: false))
    }

    func testFileLogRotatesAndReadsBoundedTail() throws {
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

        let tail = try TunnelFileLog.tail(of: url, maxBytes: 180, maxLines: 3)
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let size = try XCTUnwrap(attributes[.size] as? NSNumber).intValue
        XCTAssertLessThanOrEqual(size, 512)
        XCTAssertFalse(tail.contains("line-0-"))
        XCTAssertTrue(tail.contains("line-99-"))
        XCTAssertLessThanOrEqual(tail.split(separator: "\n").count, 3)
    }
}
