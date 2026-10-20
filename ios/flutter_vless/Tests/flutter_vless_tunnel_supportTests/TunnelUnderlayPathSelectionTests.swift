import Foundation
import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelUnderlayPathSelectionTests: XCTestCase {
    typealias Selection = TunnelUnderlayPathSelection
    private func path(_ index: UInt32, _ name: String, v4: Bool = true, v6: Bool = false) -> Selection.ScopedPath {
        .init(satisfied: true, interfaces: [.init(index: index, name: name)],
              supportsIPv4: v4, supportsIPv6: v6, supportsDNS: true)
    }

    func testPreferenceChoosesInterfaceAndItsOwnFamilyHints() throws {
        let value = try XCTUnwrap(Selection.choose(preferred: [8, 7],
            scoped: [.wifi: path(7, "en0"), .cellular: path(8, "pdp_ip0", v4: false, v6: true)], excluding: []))
        XCTAssertEqual(value.interfaceIndex, 8)
        XCTAssertEqual(value.interfaceName, "pdp_ip0")
        XCTAssertFalse(value.supportsIPv4)
        XCTAssertTrue(value.supportsIPv6)
        XCTAssertEqual(value.generation, 0)
    }

    func testOwnTunnelCapabilitiesNeverTransferToAnotherInterface() {
        var own = path(99, "utun9", v4: true, v6: true)
        own = .init(satisfied: true, interfaces: own.interfaces + [.init(index: 42, name: "ipsec2")],
                    supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
        XCTAssertNil(Selection.choose(preferred: [99, 42], scoped: [.other: own], excluding: [99]))
    }

    func testExcludedOwnTunnelLeavesScopedPhysicalCandidate() throws {
        let value = try XCTUnwrap(Selection.choose(preferred: [99, 7],
            scoped: [.other: path(99, "utun9", v4: true, v6: true), .wifi: path(7, "en0", v4: false, v6: true)], excluding: [99]))
        XCTAssertEqual(value.interfaceIndex, 7)
        XCTAssertFalse(value.supportsIPv4)
    }

    func testInvalidPreferredIdentityIsNotSilentlyReplaced() {
        for first in [Selection.Interface(index: 0, name: "en0"), .init(index: 7, name: "en0\0evil"),
                      .init(index: 7, name: "../en0"), .init(index: 7, name: String(repeating: "e", count: 16))] {
            let snapshot = Selection.ScopedPath(satisfied: true, interfaces: [first, .init(index: 8, name: "en1")],
                supportsIPv4: true, supportsIPv6: false, supportsDNS: true)
            XCTAssertNil(Selection.choose(preferred: [7, 8], scoped: [.wifi: snapshot], excluding: []))
        }
    }

    func testUnavailableAndNoFamilyNeverInventDualStack() {
        let unavailable = Selection.ScopedPath(satisfied: false, interfaces: [.init(index: 7, name: "en0")],
            supportsIPv4: true, supportsIPv6: true, supportsDNS: true)
        XCTAssertNil(Selection.choose(preferred: [7], scoped: [.wifi: unavailable], excluding: []))
        XCTAssertNil(Selection.choose(preferred: [7], scoped: [.wifi: path(7, "en0", v4: false, v6: false)], excluding: []))
        XCTAssertNil(Selection.choose(preferred: [], scoped: [:], excluding: []))
    }

    private final class Driver: @unchecked Sendable {
        let installed = XCTestExpectation(description: "fake boundary installed")
        private let lock = NSLock()
        private var queue: DispatchQueue?
        private var event: (@Sendable (TunnelPhysicalPathObserver.Event) -> Void)?
        private var count = 0
        var cancellations: Int { lock.lock(); defer { lock.unlock() }; return count }
        func install(_ queue: DispatchQueue, _ event: @escaping @Sendable (TunnelPhysicalPathObserver.Event) -> Void) -> [() -> Void] {
            lock.lock(); self.queue = queue; self.event = event; lock.unlock()
            installed.fulfill()
            return (0..<5).map { _ in { self.lock.lock(); self.count += 1; self.lock.unlock() } }
        }
        func send(_ value: TunnelPhysicalPathObserver.Event) {
            lock.lock(); let queue = queue, callback = event; lock.unlock()
            queue?.async { callback?(value) }
        }
        func initial(holding held: Selection.Kind? = nil) {
            send(.preference([99, 7, 8]))
            for kind in Selection.Kind.allCases {
                if kind == held { continue }
                let snapshot = Selection.ScopedPath(satisfied: kind == .wifi || kind == .other,
                    interfaces: [.init(index: kind == .other ? 99 : 7, name: kind == .other ? "utun9" : "en0")],
                    supportsIPv4: kind != .wifi, supportsIPv6: true, supportsDNS: true)
                send(.scoped(kind, snapshot, changed: true))
            }
        }
    }
    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var stored = 0
        var value: Int { lock.lock(); defer { lock.unlock() }; return stored }
        func add() { lock.lock(); stored += 1; lock.unlock() }
    }
    private final class OwnedIndexes: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Set<UInt32>? = [99]
        func read() -> Set<UInt32>? { lock.lock(); defer { lock.unlock() }; return stored }
        func makeUnknown() { lock.lock(); stored = nil; lock.unlock() }
    }
    private func observer(_ driver: Driver) -> TunnelPhysicalPathObserver {
        .init(boundary: .init(install: driver.install, ownedIndexes: { [99] }))
    }

    func testObserverRequiresAllScopedInitialEvidenceAndReturnsChosenFamily() async throws {
        let driver = Driver(), changes = Counter()
        let target = self.observer(driver)
        target.start { _ in changes.add() }
        await fulfillment(of: [driver.installed], timeout: 1)
        let waiter = Task { try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1) }
        driver.initial(holding: .cellular)
        try? await Task.sleep(nanoseconds: 10_000_000)
        XCTAssertEqual(changes.value, 0)
        driver.send(.scoped(.cellular, .init(satisfied: false, interfaces: [],
            supportsIPv4: false, supportsIPv6: false, supportsDNS: false), changed: true))
        let selected = try await waiter.value
        XCTAssertEqual(selected.interfaceIndex, 7)
        XCTAssertFalse(selected.supportsIPv4)
        XCTAssertTrue(selected.supportsIPv6)
        target.cancel()
    }

    func testNoSnapshotTimesOutAndLateEventsCannotResumeItAgain() async {
        let driver = Driver()
        let value = observer(driver)
        value.start { _ in }
        await fulfillment(of: [driver.installed], timeout: 1)
        do {
            _ = try await value.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 0.02)
            XCTFail("No fabricated default path")
        } catch TunnelPhysicalPathObserver.Failure.unavailable {
        } catch { XCTFail("Unexpected error") }
        driver.initial()
        try? await Task.sleep(nanoseconds: 10_000_000)
        value.cancel()
    }

    func testCancelledWaitCannotAdoptALaterSnapshot() async {
        let driver = Driver(), target = observer(driver)
        target.start { _ in }
        await fulfillment(of: [driver.installed], timeout: 1)
        let waiter = Task { try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1) }
        waiter.cancel()
        driver.initial()
        do { _ = try await waiter.value; XCTFail("Cancelled wait must fail") }
        catch { XCTAssertTrue(error is CancellationError) }
        target.cancel()
    }

    func testCancelTearsDownEveryMonitorAndIgnoresLateEvents() async {
        let driver = Driver(), target = observer(driver), changes = Counter()
        target.start { _ in changes.add() }
        await fulfillment(of: [driver.installed], timeout: 1)
        target.cancel()
        driver.initial()
        try? await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(driver.cancellations, 5)
        XCTAssertEqual(changes.value, 0)
    }

    func testChangedSelectedPathInvalidatesSamePublicSnapshotOnly() async throws {
        let driver = Driver(), target = observer(driver), changes = Counter()
        target.start { _ in changes.add() }
        await fulfillment(of: [driver.installed], timeout: 1)
        driver.initial()
        _ = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1)
        let before = changes.value
        driver.send(.scoped(.wifi, path(7, "en0", v4: false, v6: true), changed: true))
        driver.send(.scoped(.cellular, path(8, "pdp_ip0"), changed: true))
        try? await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(changes.value, before + 1)
        target.cancel()
    }

    func testUnknownOwnedInterfaceCannotAdmitPath() async {
        let driver = Driver()
        let target = TunnelPhysicalPathObserver(boundary: .init(install: driver.install, ownedIndexes: { nil }))
        target.start { _ in }
        await fulfillment(of: [driver.installed], timeout: 1)
        driver.initial()
        do {
            _ = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 0.03)
            XCTFail("Unknown tunnel identity cannot authorize a physical path")
        } catch TunnelPhysicalPathObserver.Failure.unavailable {
        } catch { XCTFail("Unexpected error") }
        target.cancel()
    }

    func testUnknownInventoryRevokesPreviouslySelectedPath() async throws {
        let driver = Driver(), inventory = OwnedIndexes(), revocations = Counter()
        let target = TunnelPhysicalPathObserver(boundary: .init(install: driver.install, ownedIndexes: inventory.read))
        target.start { if $0 == nil { revocations.add() } }
        await fulfillment(of: [driver.installed], timeout: 1)
        driver.initial()
        _ = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1)
        inventory.makeUnknown()
        driver.send(.preference([99, 7, 8]))
        do {
            _ = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 0.03)
            XCTFail("Previously selected path cannot survive unknown tunnel identity")
        } catch TunnelPhysicalPathObserver.Failure.unavailable {
        } catch { XCTFail("Unexpected error") }
        XCTAssertEqual(revocations.value, 1)
        target.cancel()
    }

    func testOwnTunnelPreferenceChangesDoNotRefreshUnchangedPhysicalPath() async throws {
        let driver = Driver(), changes = Counter(), target = observer(driver)
        target.start { _ in changes.add() }
        await fulfillment(of: [driver.installed], timeout: 1)
        driver.initial()
        _ = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1)
        let before = changes.value
        driver.send(.preference([7, 99, 8]))
        try? await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(changes.value, before)
        target.cancel()
    }

    func testExplicitOwnedInterfaceDoesNotNeedFallback() async throws {
        let driver = Driver()
        let target = TunnelPhysicalPathObserver(boundary: .init(install: driver.install, ownedIndexes: { nil }),
            excludedInterfaceIndex: { 99 })
        target.start { _ in }
        await fulfillment(of: [driver.installed], timeout: 1)
        driver.initial()
        let selected = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1)
        XCTAssertEqual(selected.interfaceIndex, 7)
        target.cancel()
    }

    func testSnapshotBeforeStartFailsWithoutInstallingOSBoundary() async {
        let driver = Driver(), target = observer(driver)
        do { _ = try await target.initialSnapshot(deadline: ProcessInfo.processInfo.systemUptime + 1); XCTFail("Not started") }
        catch TunnelPhysicalPathObserver.Failure.notStarted {
        } catch { XCTFail("Unexpected error") }
        XCTAssertEqual(driver.cancellations, 0)
        target.cancel()
    }
}
