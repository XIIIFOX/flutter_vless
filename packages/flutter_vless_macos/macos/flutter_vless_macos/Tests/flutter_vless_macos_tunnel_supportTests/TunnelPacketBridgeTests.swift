import XCTest
import Darwin
@testable import flutter_vless_macos_tunnel_support

final class TunnelPacketBridgeTests: XCTestCase {
    private func packet(_ version: UInt8 = 4, count: Int = 60) -> Data {
        var bytes = Data(repeating: 0, count: count)
        bytes[0] = version == 4 ? 0x45 : 0x60
        return bytes
    }

    func testDarwinFramingAndInvalidPackets() throws {
        for (version, family) in [(UInt8(4), AF_INET), (UInt8(6), AF_INET6)] {
            let data = packet(version)
            let frame = try XCTUnwrap(TunnelPacketBridge.encode(data, family: family, mtu: 1500))
            XCTAssertEqual(Array(frame.prefix(4)), [0, 0, 0, UInt8(family)])
            let decoded = try XCTUnwrap(TunnelPacketBridge.decode(frame, mtu: 1500))
            XCTAssertEqual(decoded.data, data)
            XCTAssertEqual(decoded.family, family)
        }
        XCTAssertNil(TunnelPacketBridge.encode(packet(), family: AF_INET6, mtu: 1500))
        XCTAssertNil(TunnelPacketBridge.encode(packet(count: 1501), family: AF_INET, mtu: 1500))
        XCTAssertNil(TunnelPacketBridge.encode(Data([0x45]), family: AF_INET, mtu: 1500))
        XCTAssertNil(TunnelPacketBridge.decode(Data([0, 0, 0, 99]) + packet(), mtu: 1500))
        XCTAssertNil(TunnelPacketBridge.decode(Data([0, 0, 0, UInt8(AF_INET)]) + packet(6), mtu: 1500))
    }

    func testSocketpairPreservesPacketBoundariesInBothDirections() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Bridge failed") }
        defer { bridge.shutdown() }
        bridge.start()
        flow.deliver([packet(), packet(6)], [AF_INET, AF_INET6])
        for family in [AF_INET, AF_INET6] {
            let frame = try read(bridge.workerDescriptor)
            XCTAssertEqual(TunnelPacketBridge.decode(frame, mtu: 1500)?.family, family)
            XCTAssertEqual(frame.withUnsafeBytes { send(bridge.workerDescriptor, $0.baseAddress, $0.count, 0) }, frame.count)
        }
        XCTAssertTrue(flow.waitForWrites(2))
        XCTAssertEqual(flow.written.map(\.0), [packet(), packet(6)])
        XCTAssertEqual(flow.written.map(\.1), [AF_INET, AF_INET6])
    }

    func testWorkerRecoveryKeepsOneReaderAndDropsOldGeneration() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Bridge failed") }
        defer { bridge.shutdown() }
        bridge.start()
        XCTAssertEqual(flow.readCount, 1)
        bridge.pause()
        bridge.start()
        XCTAssertEqual(flow.readCount, 1, "Cannot add another read while the previous callback is outstanding")
        flow.deliver([packet()], [AF_INET])
        XCTAssertTrue(flow.waitForReadCount(2))
        var pfd = pollfd(fd: bridge.workerDescriptor, events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&pfd, 1, 0), 0, "Old-generation packet must be discarded")
        flow.deliver([packet(6)], [AF_INET6])
        XCTAssertEqual(TunnelPacketBridge.decode(try read(bridge.workerDescriptor), mtu: 1500)?.family, AF_INET6)
    }

    func testShutdownIsIdempotentAndLateCallbackDoesNotRearmRead() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Bridge failed") }
        bridge.start()
        bridge.shutdown()
        bridge.shutdown()
        flow.deliver([packet()], [AF_INET])
        bridge.pause() // synchronizes the late callback
        XCTAssertEqual(flow.readCount, 1)
        XCTAssertEqual(fcntl(bridge.workerDescriptor, F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
    }

    func testMalformedAndOversizedWorkerDatagramsAreDropped() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Bridge failed") }
        defer { bridge.shutdown() }
        bridge.start()
        for frame in [Data([0, 0]), Data(repeating: 0, count: 1505),
                      Data([0, 0, 0, UInt8(AF_INET6)]) + packet(),
                      TunnelPacketBridge.encode(packet(), family: AF_INET, mtu: 1500)!] {
            _ = frame.withUnsafeBytes { send(bridge.workerDescriptor, $0.baseAddress, $0.count, 0) }
        }
        XCTAssertTrue(flow.waitForWrites(1))
        bridge.pause()
        XCTAssertEqual(flow.written.count, 1)
    }

    func testBurstSurvivesBackpressureWithoutLossOrReordering() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Bridge failed") }
        defer { bridge.shutdown() }
        bridge.start()
        let packets = (0..<1024).map { index -> Data in
            var data = packet(count: 1500)
            data[20] = UInt8(index >> 8)
            data[21] = UInt8(index & 255)
            return data
        }
        flow.deliver(packets, Array(repeating: AF_INET, count: packets.count))
        // Let the producer fill the socket before the native worker can read.
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(flow.readCount, 1, "Read the next batch only after the current batch drains")
        var received: [Data] = []
        while received.count < packets.count {
            var pfd = pollfd(fd: bridge.workerDescriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&pfd, 1, 500) == 1 else { break }
            let frame = try read(bridge.workerDescriptor)
            received.append(try XCTUnwrap(TunnelPacketBridge.decode(frame, mtu: 1500)).data)
        }
        XCTAssertEqual(received.count, packets.count)
        XCTAssertTrue(received == packets, "Every packet must arrive intact and in order")
        XCTAssertTrue(flow.waitForReadCount(2))
    }

    func testBackpressureDoesNotBlockStop() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Backpressure must not fail the bridge") }
        defer { bridge.shutdown() }
        bridge.start()
        let start = Date()
        flow.deliver(Array(repeating: packet(count: 1500), count: 2000), Array(repeating: AF_INET, count: 2000))
        bridge.pause()
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
    }

    func testRecoveryDiscardsBackpressuredBatchAndItsRetry() throws {
        let flow = TestPacketFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { XCTFail("Bridge failed") }
        defer { bridge.shutdown() }
        bridge.start()
        flow.deliver(Array(repeating: packet(count: 1500), count: 1024), Array(repeating: AF_INET, count: 1024))
        Thread.sleep(forTimeInterval: 0.02)
        XCTAssertEqual(flow.readCount, 1)
        bridge.pause()
        bridge.start()
        XCTAssertTrue(flow.waitForReadCount(2))
        flow.deliver([packet(6)], [AF_INET6])
        XCTAssertEqual(TunnelPacketBridge.decode(try read(bridge.workerDescriptor), mtu: 1500)?.data, packet(6))
        XCTAssertTrue(flow.waitForReadCount(3))
        var pfd = pollfd(fd: bridge.workerDescriptor, events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&pfd, 1, 30), 0, "A retry from the old worker must not forward its queued packets")
    }

    func testOversizedBatchStopsForwardingAtMemoryAndPacketLimits() throws {
        for (count, packetSize) in [(4097, 60), (3000, 1500)] {
            let flow = TestPacketFlow()
            let failed = expectation(description: "bounded batch rejected")
            let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { failed.fulfill() }
            bridge.start()
            flow.deliver(Array(repeating: packet(count: packetSize), count: count), Array(repeating: AF_INET, count: count))
            wait(for: [failed], timeout: 2)
            XCTAssertEqual(flow.readCount, 1)
            var pfd = pollfd(fd: bridge.workerDescriptor, events: Int16(POLLIN), revents: 0)
            XCTAssertEqual(poll(&pfd, 1, 0), 0)
            bridge.shutdown()
        }
    }

    func testRejectedPacketFlowWriteStopsForwarding() throws {
        let flow = TestPacketFlow()
        flow.acceptWrites = false
        let failed = expectation(description: "bridge failure")
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) { failed.fulfill() }
        defer { bridge.shutdown() }
        bridge.start()
        let frame = TunnelPacketBridge.encode(packet(), family: AF_INET, mtu: 1500)!
        _ = frame.withUnsafeBytes { send(bridge.workerDescriptor, $0.baseAddress, $0.count, 0) }
        wait(for: [failed], timeout: 2)
        flow.deliver([packet()], [AF_INET])
        bridge.pause()
        XCTAssertEqual(flow.readCount, 1)
    }

    private func read(_ fd: Int32) throws -> Data {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, 2000) == 1 else { throw POSIXError(.ETIMEDOUT) }
        var data = [UInt8](repeating: 0, count: 1600)
        let count = recv(fd, &data, data.count, 0)
        guard count > 0 else { throw POSIXError(.EIO) }
        return Data(data.prefix(count))
    }
}

private final class TestPacketFlow: TunnelPacketFlow {
    private let condition = NSCondition()
    private var completion: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var reads = 0
    private var writes: [(Data, Int32)] = []
    var acceptWrites = true
    var readCount: Int { condition.lock(); defer { condition.unlock() }; return reads }
    var written: [(Data, Int32)] { condition.lock(); defer { condition.unlock() }; return writes }

    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        condition.lock()
        XCTAssertNil(completion, "Only one outstanding packet read is allowed")
        completion = completionHandler
        reads += 1
        condition.broadcast()
        condition.unlock()
    }

    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        condition.lock()
        writes.append(contentsOf: zip(packets, protocols).map { ($0, $1.int32Value) })
        condition.broadcast()
        condition.unlock()
        return acceptWrites
    }

    func deliver(_ packets: [Data], _ protocols: [Int32]) {
        condition.lock()
        let callback = completion
        completion = nil
        condition.unlock()
        XCTAssertNotNil(callback)
        callback?(packets, protocols.map { NSNumber(value: $0) })
    }

    func waitForWrites(_ count: Int) -> Bool { wait { writes.count >= count } }
    func waitForReadCount(_ count: Int) -> Bool { wait { reads >= count } }
    private func wait(_ predicate: () -> Bool) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(2)
        while !predicate() { if !condition.wait(until: deadline) { return predicate() } }
        return true
    }
}
