import Foundation
import NetworkExtension
import Darwin

protocol TunnelPacketFlow: AnyObject {
    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}

extension NEPacketTunnelFlow: TunnelPacketFlow {}

/// Adapt Apple's public packet API to HEV's Darwin datagram framing. Both
/// socketpair descriptors belong to this bridge; no private KVC or fd scanning.
/// Keep one bridge across worker recovery so only one packetFlow read is pending.
final class TunnelPacketBridge: @unchecked Sendable {
    let workerDescriptor: Int32
    private let bridgeDescriptor: Int32
    private let flow: TunnelPacketFlow
    private let mtu: Int
    private let failure: () -> Void
    private let queue = DispatchQueue(label: "dev.tfox.flutter-vless.packet-bridge", qos: .userInitiated)
    private var source: DispatchSourceRead?
    private var active = false
    private var closed = false
    private var readPending = false
    private var generation = 0
    private var pendingFrames: [Data] = []
    private var pendingIndex = 0
    private var pendingBytes = 0
    private var retry: DispatchWorkItem?
    private var forwardedToWorker: UInt64 = 0
    private var forwardedToFlow: UInt64 = 0
    private var backpressureWaits: UInt64 = 0
    private var peakPendingBytes = 0
    private static let maxPendingBytes = 4 * 1024 * 1024
    private static let maxPendingPackets = 4096

    init(flow: TunnelPacketFlow, mtu: Int, failure: @escaping () -> Void) throws {
        self.flow = flow
        self.mtu = mtu
        self.failure = failure
        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &descriptors) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        for fd in descriptors {
            guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0,
                  fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
                let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                descriptors.forEach { Darwin.close($0) }
                throw error
            }
            var enabled: Int32 = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled)))
            // Darwin's default local datagram receive buffer holds only about
            // two MTU-sized packets. Reserve space for bursts in both directions
            // without changing host-wide socket settings.
            for option in [SO_SNDBUF, SO_RCVBUF] {
                var configured = false
                for capacity in [512, 256, 128, 64] {
                    var bytes = Int32(capacity * 1024)
                    if setsockopt(fd, SOL_SOCKET, option, &bytes, socklen_t(MemoryLayout.size(ofValue: bytes))) == 0 {
                        configured = true
                        break
                    }
                }
                guard configured else {
                    let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENOBUFS)
                    descriptors.forEach { Darwin.close($0) }
                    throw error
                }
            }
        }
        bridgeDescriptor = descriptors[0]
        workerDescriptor = descriptors[1]
        let source = DispatchSource.makeReadSource(fileDescriptor: bridgeDescriptor, queue: queue)
        source.setEventHandler { [weak self] in self?.receiveFromWorker() }
        // Dispatch must finish using this descriptor before it can be reused.
        let ownedDescriptor = bridgeDescriptor
        source.setCancelHandler { Darwin.close(ownedDescriptor) }
        self.source = source
        source.activate()
    }

    deinit {
        // The native worker retains the bridge until HEV exits. Shutdown must
        // never close a descriptor still being used by that worker.
        source?.cancel()
        if !closed { Darwin.close(workerDescriptor) }
    }

    /// Call only after the previous HEV worker has exited.
    func start() {
        queue.sync {
            guard !closed else { return }
            clearPendingFrames()
            drain(bridgeDescriptor)
            drain(workerDescriptor)
            generation += 1
            active = true
            readFromFlow()
        }
    }

    func pause() {
        queue.sync {
            active = false
            generation += 1
            clearPendingFrames()
        }
    }

    /// Call only after HEV has exited. Repeated shutdown is harmless.
    func shutdown() {
        queue.sync {
            guard !closed else { return }
            active = false
            closed = true
            generation += 1
            clearPendingFrames()
            source?.cancel()
            source = nil
            Darwin.close(workerDescriptor)
        }
    }

    private func readFromFlow() {
        guard active, !closed, !readPending, pendingFrames.isEmpty else { return }
        readPending = true
        let readGeneration = generation
        flow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.queue.async {
                self.readPending = false
                guard self.active, !self.closed else { return }
                if self.generation == readGeneration {
                    guard packets.count == protocols.count,
                          packets.count <= Self.maxPendingPackets else { self.fail(); return }
                    for (packet, proto) in zip(packets, protocols) {
                        guard let frame = Self.encode(packet, family: proto.int32Value, mtu: self.mtu) else { continue }
                        guard self.pendingBytes + frame.count <= Self.maxPendingBytes else { self.fail(); return }
                        self.pendingFrames.append(frame)
                        self.pendingBytes += frame.count
                    }
                    self.peakPendingBytes = max(self.peakPendingBytes, self.pendingBytes)
                }
                self.flushPendingFrames()
            }
        }
    }

    private func flushPendingFrames() {
        guard active, !closed else { return }
        // Yield between large batches so stop and downlink cannot be starved.
        for _ in 0..<256 {
            guard pendingIndex < pendingFrames.count else {
                clearPendingFrames()
                readFromFlow()
                return
            }
            let frame = pendingFrames[pendingIndex]
            let written = frame.withUnsafeBytes { send(bridgeDescriptor, $0.baseAddress, $0.count, 0) }
            if written < 0 {
                if errno == EINTR { continue }
                guard errno == EAGAIN || errno == ENOBUFS else { fail(); return }
                backpressureWaits += 1
                // AF_UNIX datagram write readiness may stay signalled while the
                // peer receive buffer is full. A bounded retry avoids spinning.
                scheduleFlush(after: .milliseconds(1))
                return
            }
            guard written == frame.count else { fail(); return }
            pendingIndex += 1
            pendingBytes -= frame.count
            forwardedToWorker += 1
        }
        scheduleFlush(after: .nanoseconds(0))
    }

    private func scheduleFlush(after delay: DispatchTimeInterval) {
        guard retry == nil else { return }
        let expectedGeneration = generation
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.generation == expectedGeneration else { return }
            self.retry = nil
            self.flushPendingFrames()
        }
        retry = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func clearPendingFrames() {
        retry?.cancel()
        retry = nil
        pendingFrames.removeAll(keepingCapacity: false)
        pendingIndex = 0
        pendingBytes = 0
    }

    struct Statistics {
        let upPackets: UInt64
        let downPackets: UInt64
        let backpressureWaits: UInt64
        let queuedBytes: Int
        let peakQueuedBytes: Int
        let receiveBufferBytes: Int32
    }

    func statistics() -> Statistics {
        queue.sync {
            var receiveBytes: Int32 = 0
            var length = socklen_t(MemoryLayout.size(ofValue: receiveBytes))
            if !closed { _ = getsockopt(workerDescriptor, SOL_SOCKET, SO_RCVBUF, &receiveBytes, &length) }
            return Statistics(upPackets: forwardedToWorker, downPackets: forwardedToFlow,
                              backpressureWaits: backpressureWaits, queuedBytes: pendingBytes,
                              peakQueuedBytes: peakPendingBytes, receiveBufferBytes: receiveBytes)
        }
    }

    private func receiveFromWorker() {
        guard !closed else { return }
        var buffer = [UInt8](repeating: 0, count: mtu + 5)
        var packets: [Data] = []
        var protocols: [NSNumber] = []
        for _ in 0..<256 {
            let count = recv(bridgeDescriptor, &buffer, buffer.count, 0)
            if count < 0 {
                if errno != EAGAIN && errno != EINTR { fail() }
                break
            }
            guard active, let packet = Self.decode(Data(buffer.prefix(count)), mtu: mtu) else { continue }
            packets.append(packet.data)
            protocols.append(NSNumber(value: packet.family))
        }
        if active && !packets.isEmpty {
            if flow.writePackets(packets, withProtocols: protocols) {
                forwardedToFlow += UInt64(packets.count)
            } else { fail() }
        }
    }

    private func fail() {
        guard active else { return }
        active = false
        generation += 1
        clearPendingFrames()
        failure()
    }

    private func drain(_ fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: mtu + 5)
        while recv(fd, &buffer, buffer.count, 0) >= 0 {}
    }

    static func encode(_ packet: Data, family: Int32, mtu: Int) -> Data? {
        guard valid(packet, family: family, mtu: mtu) else { return nil }
        var header = UInt32(family).bigEndian
        var frame = withUnsafeBytes(of: &header) { Data($0) }
        frame.append(packet)
        return frame
    }

    static func decode(_ frame: Data, mtu: Int) -> (data: Data, family: Int32)? {
        guard frame.count >= 4, frame.count <= mtu + 4 else { return nil }
        let family = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard family == UInt32(AF_INET) || family == UInt32(AF_INET6) else { return nil }
        let packet = Data(frame.dropFirst(4))
        guard valid(packet, family: Int32(family), mtu: mtu) else { return nil }
        return (packet, Int32(family))
    }

    private static func valid(_ packet: Data, family: Int32, mtu: Int) -> Bool {
        guard packet.count <= mtu, let first = packet.first else { return false }
        switch family {
        case AF_INET: return packet.count >= 20 && first >> 4 == 4
        case AF_INET6: return packet.count >= 40 && first >> 4 == 6
        default: return false
        }
    }
}
