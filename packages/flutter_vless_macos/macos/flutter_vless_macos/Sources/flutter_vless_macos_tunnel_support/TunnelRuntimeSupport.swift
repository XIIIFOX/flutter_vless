import Foundation

/// Thread-safe lifecycle state for a long-running tunnel worker such as HEV.
///
/// `NEPacketTunnelProvider.startTunnel` must not report success when the worker
/// exits immediately, and `stopTunnel` must be able to distinguish an expected
/// shutdown from a worker crash. This class keeps that coordination independent
/// from NetworkExtension so it can be unit-tested on the host.
public final class TunnelProcessLifecycle: @unchecked Sendable {
    public enum StartupResult: Equatable {
        case running
        case exited(Int32)
        case timedOut
    }

    private enum State {
        case idle
        case starting
        case running(Date)
        case stopping
        case exited(Int32)
    }

    private let condition = NSCondition()
    private var state: State = .idle
    private var stopRequested = false

    public init() {}

    public func beginStart() {
        condition.lock()
        state = .starting
        stopRequested = false
        condition.broadcast()
        condition.unlock()
    }

    public func markThreadEntered() {
        condition.lock()
        if case .starting = state {
            state = .running(Date())
        }
        condition.broadcast()
        condition.unlock()
    }

    /// Records worker termination and returns `true` for an unexpected exit.
    @discardableResult
    public func markExited(code: Int32) -> Bool {
        condition.lock()
        let unexpected = !stopRequested
        state = .exited(code)
        condition.broadcast()
        condition.unlock()
        return unexpected
    }

    /// Returns true only for the first stop request for a running worker.
    @discardableResult
    public func requestStop() -> Bool {
        condition.lock()
        let shouldSignal: Bool
        if case .running = state {
            shouldSignal = !stopRequested
        } else {
            shouldSignal = false
        }
        stopRequested = true
        if case .exited = state {
            // Preserve the exit code for callers waiting on it.
        } else {
            state = .stopping
        }
        condition.broadcast()
        condition.unlock()
        return shouldSignal
    }

    /// Waits for the worker to enter its blocking run loop and remain there for
    /// `gracePeriod`. A worker that returns immediately is reported as failed.
    public func waitForStableStartup(gracePeriod: TimeInterval) -> StartupResult {
        let entryDeadline = Date().addingTimeInterval(gracePeriod)
        condition.lock()
        defer { condition.unlock() }

        while true {
            switch state {
            case .running(let enteredAt):
                let stabilityDeadline = enteredAt.addingTimeInterval(gracePeriod)
                if Date() >= stabilityDeadline {
                    return .running
                }
                _ = condition.wait(until: stabilityDeadline)
            case .exited(let code):
                return .exited(code)
            case .starting:
                if Date() >= entryDeadline {
                    return .timedOut
                }
                _ = condition.wait(until: entryDeadline)
            case .idle, .stopping:
                return .timedOut
            }
        }
    }

    @discardableResult
    public func waitForExit(timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        condition.lock()
        defer { condition.unlock() }

        while true {
            if case .exited = state {
                return true
            }
            if Date() >= deadline {
                return false
            }
            _ = condition.wait(until: deadline)
        }
    }

    public var isRunning: Bool {
        condition.lock()
        defer { condition.unlock() }
        if case .running = state {
            return true
        }
        return false
    }

    public var isStopRequested: Bool {
        condition.lock()
        defer { condition.unlock() }
        return stopRequested
    }
}

/// Counts consecutive watchdog failures without reacting to transient errors.
public struct TunnelWatchdogFailurePolicy: Equatable {
    public let failureThreshold: Int
    public private(set) var consecutiveFailures = 0

    public init(failureThreshold: Int = 3) {
        precondition(failureThreshold > 0)
        self.failureThreshold = failureThreshold
    }

    /// Returns `true` once the configured failure threshold has been reached.
    @discardableResult
    public mutating func record(success: Bool) -> Bool {
        if success {
            consecutiveFailures = 0
            return false
        }
        consecutiveFailures += 1
        return consecutiveFailures >= failureThreshold
    }

    public mutating func reset() {
        consecutiveFailures = 0
    }
}

/// Bounded append-only diagnostics used by the provider and containing app.
public enum TunnelFileLog {
    public static func append(
        _ line: String,
        to url: URL,
        maxFileBytes: Int = 256 * 1024,
        retainedBytes: Int = 128 * 1024
    ) throws {
        precondition(maxFileBytes > 0)
        precondition(retainedBytes > 0 && retainedBytes < maxFileBytes)

        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if !fileManager.fileExists(atPath: url.path) {
            _ = fileManager.createFile(atPath: url.path, contents: nil)
        }

        let handle = try FileHandle(forWritingTo: url)
        defer { handle.closeFile() }
        handle.seekToEndOfFile()
        handle.write(Data("\(line)\n".utf8))

        let size = handle.seekToEndOfFile()
        guard size > UInt64(maxFileBytes) else {
            return
        }
        handle.closeFile()
        try trimIfNeeded(
            url,
            maxFileBytes: maxFileBytes,
            retainedBytes: retainedBytes
        )
    }

    /// Truncates an externally-written log in place so an active writer keeps
    /// using the same inode. This is used for HEV's C logger.
    public static func trimIfNeeded(
        _ url: URL,
        maxFileBytes: Int = 512 * 1024,
        retainedBytes: Int = 256 * 1024
    ) throws {
        precondition(maxFileBytes > 0)
        precondition(retainedBytes > 0 && retainedBytes < maxFileBytes)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }

        let handle = try FileHandle(forUpdating: url)
        defer { handle.closeFile() }
        let size = handle.seekToEndOfFile()
        guard size > UInt64(maxFileBytes) else {
            return
        }
        let start = size - UInt64(retainedBytes)
        handle.seek(toFileOffset: start)
        let data = handle.readDataToEndOfFile()
        let aligned = droppingPartialFirstLine(data, startedMidFile: true)
        handle.seek(toFileOffset: 0)
        handle.write(aligned)
        handle.truncateFile(atOffset: UInt64(aligned.count))
        handle.synchronizeFile()
    }

    public static func tail(
        of url: URL,
        maxBytes: Int = 64 * 1024,
        maxLines: Int = 200
    ) throws -> String {
        precondition(maxBytes > 0)
        precondition(maxLines > 0)

        guard FileManager.default.fileExists(atPath: url.path) else {
            return ""
        }
        let result = try rawTail(of: url, maxBytes: maxBytes)
        let aligned = droppingPartialFirstLine(result.data, startedMidFile: result.startedMidFile)
        guard let content = String(data: aligned, encoding: .utf8) else {
            return ""
        }
        return content
            .split(separator: "\n", omittingEmptySubsequences: true)
            .suffix(maxLines)
            .joined(separator: "\n")
    }

    private static func rawTail(of url: URL, maxBytes: Int) throws -> (data: Data, startedMidFile: Bool) {
        let handle = try FileHandle(forReadingFrom: url)
        defer { handle.closeFile() }
        let size = handle.seekToEndOfFile()
        let start = size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0
        handle.seek(toFileOffset: start)
        return (handle.readDataToEndOfFile(), start > 0)
    }

    private static func droppingPartialFirstLine(_ data: Data, startedMidFile: Bool) -> Data {
        guard startedMidFile, let newline = data.firstIndex(of: 0x0a) else {
            return data
        }
        let next = data.index(after: newline)
        return Data(data[next...])
    }
}
