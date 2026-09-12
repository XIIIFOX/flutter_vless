// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import Foundation

private func boundedNativeUTF8Tail(_ value: String, maxBytes: Int) -> String {
    var tail = Array(value.utf8.suffix(max(0, maxBytes)))
    while let first = tail.first, first & 0xc0 == 0x80 {
        tail.removeFirst()
    }
    return String(decoding: tail, as: UTF8.self)
}

func boundedNativeDiagnosticsSnapshot(
    _ snapshot: String,
    maxBytes: Int = 64 * 1024
) -> String {
    let bytes = Array(snapshot.utf8)
    guard bytes.count > maxBytes else {
        return snapshot
    }

    let marker = "--- Earlier diagnostics truncated ---\n"
    let budget = max(0, maxBytes - marker.utf8.count)
    var tail = boundedNativeUTF8Tail(snapshot, maxBytes: budget)
    if let newline = tail.firstIndex(of: "\n"), tail.index(after: newline) < tail.endIndex {
        tail.removeSubrange(tail.startIndex...newline)
    }
    return marker + tail
}

/// Thread-safe, bounded in-memory output from an app-process Xray runtime.
///
/// Packet Tunnel diagnostics are persisted separately because the extension is
/// a different process. This store covers proxy-only Xray callbacks and keeps
/// the most recent failed/stopped session available to MethodChannel callers.
final class BoundedNativeLogStore {
    private let maxStoredBytes: Int
    private let maxSnapshotBytes: Int
    private let maxSnapshotLines: Int
    private let maxLineBytes: Int
    private let lock = NSLock()
    private var lines: [String] = []
    private var storedBytes = 0

    init(
        maxStoredBytes: Int = 128 * 1024,
        maxSnapshotBytes: Int = 64 * 1024 - 128,
        maxSnapshotLines: Int = 300,
        maxLineBytes: Int = 16 * 1024
    ) {
        self.maxStoredBytes = maxStoredBytes
        self.maxSnapshotBytes = maxSnapshotBytes
        self.maxSnapshotLines = maxSnapshotLines
        self.maxLineBytes = maxLineBytes
    }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        lines.removeAll(keepingCapacity: true)
        storedBytes = 0
    }

    func append(source: String, message: String) {
        let safeSource = source
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
        let normalized = message
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let newLines = normalized
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map { value -> String in
                let bytes = value.utf8
                let bounded = bytes.count > maxLineBytes
                    ? boundedNativeUTF8Tail(String(value), maxBytes: maxLineBytes)
                    : String(value)
                return "[\(safeSource)] \(bounded)"
            }
        guard !newLines.isEmpty else {
            return
        }

        lock.lock()
        defer { lock.unlock() }
        for line in newLines {
            lines.append(line)
            storedBytes += line.utf8.count + 1
        }
        while !lines.isEmpty && storedBytes > maxStoredBytes {
            storedBytes -= lines.removeFirst().utf8.count + 1
        }
    }

    func snapshot() -> String {
        lock.lock()
        defer { lock.unlock() }
        guard !lines.isEmpty else {
            return ""
        }

        var selected: [String] = []
        var selectedBytes = 0
        for line in lines.reversed() {
            let lineBytes = line.utf8.count + 1
            if !selected.isEmpty &&
                (selected.count >= maxSnapshotLines ||
                 selectedBytes + lineBytes > maxSnapshotBytes) {
                break
            }
            selected.append(line)
            selectedBytes += lineBytes
        }
        return selected.reversed().joined(separator: "\n")
    }
}
