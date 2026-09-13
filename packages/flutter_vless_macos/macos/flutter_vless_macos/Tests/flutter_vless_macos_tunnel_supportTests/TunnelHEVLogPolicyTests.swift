import XCTest
@testable import flutter_vless_macos_tunnel_support

final class TunnelHEVLogPolicyTests: XCTestCase {
    func testMigrationRemovesOnlyLegacyLibraryFilesAndNeverCopiesSecrets() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let group = root.appendingPathComponent("group")
        let temporary = root.appendingPathComponent("extension-temp")
        for directory in [group, temporary] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data("historic.private.invalid password-canary".utf8).write(to: directory.appendingPathComponent(TunnelHEVLogPolicy.legacyFilename))
            try Data("preserve user data".utf8).write(to: directory.appendingPathComponent("unrelated.log"))
        }
        let current = group.appendingPathComponent(TunnelHEVLogPolicy.filename)
        try TunnelFileLog.append("error-only session", to: current)
        XCTAssertThrowsError(try TunnelHEVLogPolicy.removeLegacyLogs(appGroupDirectory: group, temporaryDirectory: temporary, workerStopped: false))
        XCTAssertTrue(FileManager.default.fileExists(atPath: group.appendingPathComponent(TunnelHEVLogPolicy.legacyFilename).path))
        try TunnelHEVLogPolicy.removeLegacyLogs(appGroupDirectory: group, temporaryDirectory: temporary, workerStopped: true)
        for directory in [group, temporary] {
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent(TunnelHEVLogPolicy.legacyFilename).path))
            XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("unrelated.log").path))
        }
        // Idempotent migration does not delete the error-only file of later sessions.
        try TunnelHEVLogPolicy.removeLegacyLogs(appGroupDirectory: group, temporaryDirectory: temporary, workerStopped: true)
        XCTAssertEqual(try TunnelFileLog.tail(of: current), "error-only session")
        XCTAssertThrowsError(try TunnelHEVLogPolicy.removeLegacyLogs(appGroupDirectory: group, temporaryDirectory: temporary, workerStopped: false))
        XCTAssertEqual(try TunnelFileLog.tail(of: current), "error-only session")
    }

    func testHEVConfigUsesVerifiedAuthKeysAndErrorOnlyFile() throws {
        let credentials = try LocalProxyCredentials(username: "session-user", password: "safe'quoted-password")
        let config = TunnelHEVConfiguration.make(port: 1080, credentials: credentials, mtu: 1500,
            logURL: URL(fileURLWithPath: "/tmp/\(TunnelHEVLogPolicy.filename)"))
        XCTAssertTrue(config.contains("username: 'session-user'"))
        XCTAssertTrue(config.contains("password: 'safe''quoted-password'"))
        XCTAssertTrue(config.contains("pipeline: false"))
        XCTAssertTrue(config.contains("log-level: error"))
        XCTAssertFalse(config.contains(TunnelHEVLogPolicy.legacyFilename))
    }
}
