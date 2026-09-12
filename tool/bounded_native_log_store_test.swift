import Foundation
import Dispatch

@main
struct BoundedNativeLogStoreTest {
    static func main() {
        let store = BoundedNativeLogStore()
        precondition(store.snapshot().isEmpty)

        store.append(source: "xray", message: "started\ntransport ready")
        store.append(source: "runtime", message: "session connected")
        var snapshot = store.snapshot()
        precondition(snapshot.contains("[xray] started"))
        precondition(snapshot.contains("[runtime] session connected"))

        for index in 0..<100 {
            store.append(
                source: "xray",
                message: "message-\(index) " + String(repeating: "x", count: 4096)
            )
        }
        snapshot = store.snapshot()
        precondition(snapshot.contains("message-99"))
        precondition(!snapshot.contains("message-0 "))
        precondition(snapshot.utf8.count < 64 * 1024)

        let combined = (0..<4000)
            .map { "provider-line-\($0) " + String(repeating: "y", count: 40) }
            .joined(separator: "\n")
        let bounded = boundedNativeDiagnosticsSnapshot(combined)
        precondition(bounded.utf8.count <= 64 * 1024)
        precondition(bounded.contains("Earlier diagnostics truncated"))
        precondition(bounded.contains("provider-line-3999"))
        precondition(!bounded.contains("provider-line-0 "))

        let unicode = String(repeating: "🛰️", count: 40_000)
        let boundedUnicode = boundedNativeDiagnosticsSnapshot(unicode)
        precondition(boundedUnicode.utf8.count <= 64 * 1024)
        precondition(!boundedUnicode.contains("�"))

        store.append(source: "unicode", message: unicode)
        let unicodeSnapshot = store.snapshot()
        precondition(unicodeSnapshot.utf8.count < 64 * 1024)
        precondition(!unicodeSnapshot.contains("�"))

        let concurrentStore = BoundedNativeLogStore()
        DispatchQueue.concurrentPerform(iterations: 1_000) { index in
            concurrentStore.append(
                source: "worker-\(index % 8)",
                message: "concurrent-message-\(index)"
            )
        }
        let concurrentSnapshot = concurrentStore.snapshot()
        precondition(!concurrentSnapshot.isEmpty)
        precondition(concurrentSnapshot.utf8.count < 64 * 1024)
        precondition(!concurrentSnapshot.contains("�"))

        store.reset()
        precondition(store.snapshot().isEmpty)
    }
}
