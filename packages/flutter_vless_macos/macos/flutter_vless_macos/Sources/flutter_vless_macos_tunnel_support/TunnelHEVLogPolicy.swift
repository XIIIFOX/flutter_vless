import Foundation

/// Migration only unlinks known library files; old contents are never read.
public enum TunnelHEVLogPolicy {
    public static let filename = "hev-socks5-tunnel-error-v2.log"
    public static let legacyFilename = "hev-socks5-tunnel.log"
    public enum Failure: Error { case workerStillActive }

    public static func removeLegacyLogs(appGroupDirectory: URL?, temporaryDirectory: URL,
                                        workerStopped: Bool) throws {
        guard workerStopped else { throw Failure.workerStillActive }
        let directories = Set(([appGroupDirectory].compactMap { $0 } + [temporaryDirectory]).map { $0.standardizedFileURL })
        for directory in directories {
            let legacy = directory.appendingPathComponent(legacyFilename)
            do { try FileManager.default.removeItem(at: legacy) }
            catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileNoSuchFileError { }
        }
    }
}

public enum TunnelHEVConfiguration {
    /// Tun2SocksKit 5.15.0 / HEV 2.15 accepts socks5.username/password. Disable
    /// pipelining so authentication completes before CONNECT/UDP ASSOCIATE.
    public static func make(port: Int, credentials: LocalProxyCredentials, mtu: Int, logURL: URL) -> String {
        func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "''") + "'" }
        return """
        tunnel:
          mtu: \(mtu)
        socks5:
          port: \(port)
          address: 127.0.0.1
          udp: 'udp'
          pipeline: false
          username: \(quote(credentials.username))
          password: \(quote(credentials.password))
        misc:
          task-stack-size: 86016
          tcp-buffer-size: 65536
          max-session-count: 512
          connect-timeout: 5000
          tcp-read-write-timeout: 300000
          udp-read-write-timeout: 60000
          log-file: \(quote(logURL.path))
          log-level: error
          limit-nofile: 65535
        """
    }
}
