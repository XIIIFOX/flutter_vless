import Foundation
import Darwin
import HevSocks5Tunnel

// Synthetic TCP packets pass through the production bridge and shipped HEV.
// Bulk traffic stays on loopback; no VPN, remote server or OS route changes.
private final class ProbeFlow: TunnelPacketFlow {
    private let condition = NSCondition()
    private var callback: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var packets: [Data] = []
    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        condition.lock(); callback = completionHandler; condition.broadcast(); condition.unlock()
    }
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        condition.lock()
        self.packets.append(contentsOf: zip(packets, protocols).filter { $1.int32Value == AF_INET }.map { $0.0 })
        condition.broadcast(); condition.unlock()
        return true
    }
    func send(_ data: Data) throws {
        try send([data])
    }
    func send(_ batch: [Data]) throws {
        condition.lock()
        let deadline = Date().addingTimeInterval(5)
        while callback == nil {
            if !condition.wait(until: deadline) { condition.unlock(); throw POSIXError(.ETIMEDOUT) }
        }
        let callback = self.callback; self.callback = nil; condition.unlock()
        callback?(batch, Array(repeating: NSNumber(value: AF_INET), count: batch.count))
    }
    func receive(where matches: (Data) -> Bool) throws -> Data {
        condition.lock(); defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(5)
        while true {
            if let index = packets.firstIndex(where: matches) { return packets.remove(at: index) }
            guard condition.wait(until: deadline) else { throw POSIXError(.ETIMEDOUT) }
        }
    }
}

@main struct PacketBridgeProbe {
    static func main() throws {
        let listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard listener >= 0 else { throw POSIXError(.EIO) }
        defer { close(listener) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(listener, 1) == 0 else { throw POSIXError(.EIO) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) }
        }
        let port = UInt16(bigEndian: address.sin_port)
        let transferred = DispatchSemaphore(value: 0)
        let payload = Data("bridge-fixture".utf8)
        let bulk = Data((0..<(8 * 1024 * 1024)).map { UInt8($0 % 251) })
        DispatchQueue.global().async {
            let client = accept(listener, nil, nil)
            guard client >= 0 else { return }
            defer { close(client) }
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
            _ = setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
            var enabled: Int32 = 1
            _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled)))
            guard let greeting = read(client, 2), greeting[0] == 5,
                  read(client, Int(greeting[1])) != nil else { return }
            guard write(client, Data([5, 0])), let request = read(client, 4), request[0] == 5, request[1] == 1 else { return }
            let hostLength: Int
            switch request[3] {
            case 1: hostLength = 4
            case 3: guard let count = read(client, 1) else { return }; hostLength = Int(count[0])
            case 4: hostLength = 16
            default: return
            }
            guard read(client, hostLength + 2) != nil,
                  write(client, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])),
                  let received = read(client, payload.count), received == payload,
                  write(client, bulk),
                  let uploaded = read(client, bulk.count), uploaded == bulk else { return }
            transferred.signal()
        }
        let flow = ProbeFlow()
        let bridge = try TunnelPacketBridge(flow: flow, mtu: 1500) {
            fputs("FAIL packet bridge\n", stderr); exit(1)
        }
        let config = """
        tunnel:
          mtu: 1500
          ipv4: 198.18.0.1
        socks5:
          address: 127.0.0.1
          port: \(port)
          udp: udp
        misc:
          log-level: error
        """
        let done = DispatchSemaphore(value: 0)
        bridge.start()
        DispatchQueue.global().async {
            let code = config.withCString { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: config.utf8.count) {
                    hev_socks5_tunnel_main_from_str($0, UInt32(config.utf8.count), bridge.workerDescriptor)
                }
            }
            guard code == 0 else { fputs("FAIL HEV exit\n", stderr); exit(1) }
            done.signal()
        }
        do {
            try flow.send(tcp(sequence: 1000, ack: 0, flags: 2))
            let synack = try flow.receive { $0.count >= 40 && $0[9] == 6 && $0[33] & 0x12 == 0x12 }
            let serverSequence = synack[24..<28].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            try flow.send(tcp(sequence: 1001, ack: serverSequence &+ 1, flags: 16))
            try flow.send(tcp(sequence: 1001, ack: serverSequence &+ 1, flags: 24, payload: payload))
            var ack = serverSequence &+ 1
            var receivedBytes = 0
            var nextSequence = UInt32(1001 + payload.count)
            let downloadStart = Date()
            while receivedBytes < bulk.count {
                guard Date().timeIntervalSince(downloadStart) < 20 else { throw POSIXError(.ETIMEDOUT) }
                let packet = try flow.receive { tcpPayload($0) != nil }
                let (sequence, content) = tcpPayload(packet)!
                // Cumulative ACKs also let HEV retransmit any lost datagrams.
                if sequence == ack {
                    guard receivedBytes + content.count <= bulk.count,
                          content == bulk.subdata(in: receivedBytes..<(receivedBytes + content.count)) else {
                        throw POSIXError(.EBADMSG)
                    }
                    receivedBytes += content.count
                    ack &+= UInt32(content.count)
                }
                try flow.send(tcp(sequence: nextSequence, ack: ack, flags: 16))
            }
            let downloadSeconds = Date().timeIntervalSince(downloadStart)
            let uploadStart = Date()
            var sentBytes = 0
            while sentBytes < bulk.count {
                var batch: [Data] = []
                for _ in 0..<32 where sentBytes < bulk.count {
                    let count = min(1460, bulk.count - sentBytes)
                    batch.append(tcp(sequence: nextSequence, ack: ack, flags: 24,
                                     payload: bulk.subdata(in: sentBytes..<(sentBytes + count))))
                    nextSequence &+= UInt32(count)
                    sentBytes += count
                }
                try flow.send(batch)
                _ = try flow.receive { packet in
                    packet.count >= 40 && packet[9] == 6 && packet[33] & 16 != 0 &&
                    packet[28..<32].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } == nextSequence
                }
            }
            guard transferred.wait(timeout: .now() + 5) == .success else { throw POSIXError(.ETIMEDOUT) }
            let uploadSeconds = Date().timeIntervalSince(uploadStart)
            print(String(format: "PASS bulk integrity: 8 MiB download %.3fs (%.1f Mbit/s), 8 MiB upload %.3fs (%.1f Mbit/s)",
                         downloadSeconds, Double(bulk.count * 8) / downloadSeconds / 1_000_000,
                         uploadSeconds, Double(bulk.count * 8) / uploadSeconds / 1_000_000))
            print("Packet bridge: \(bridge.statistics())")
        } catch {
            var upPackets = 0, upBytes = 0, downPackets = 0, downBytes = 0
            hev_socks5_tunnel_stats(&upPackets, &upBytes, &downPackets, &downBytes)
            fputs("FAIL native TCP bulk transfer: \(error); HEV packets up=\(upPackets) down=\(downPackets)\n", stderr)
            exit(1)
        }
        bridge.pause()
        DispatchQueue.global().async { hev_socks5_tunnel_quit() }
        guard done.wait(timeout: .now() + 5) == .success else {
            fputs("FAIL HEV shutdown\n", stderr); exit(1)
        }
        bridge.shutdown()
        print("PASS shipped HEV: packetFlow -> owned datagram bridge -> HEV TCP -> loopback SOCKS -> packetFlow; clean shutdown")
    }

    private static func tcpPayload(_ packet: Data) -> (UInt32, Data)? {
        guard packet.count >= 40, packet[9] == 6 else { return nil }
        let offset = Int(packet[0] & 15) * 4
        guard offset >= 20, packet.count >= offset + 20 else { return nil }
        let payloadOffset = offset + Int(packet[offset + 12] >> 4) * 4
        guard payloadOffset >= offset + 20, payloadOffset < packet.count else { return nil }
        let sequence = packet[(offset + 4)..<(offset + 8)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return (sequence, Data(packet.dropFirst(payloadOffset)))
    }

    private static func tcp(sequence: UInt32, ack: UInt32, flags: UInt8, payload: Data = Data()) -> Data {
        let source: [UInt8] = [198, 18, 0, 2]
        let target: [UInt8] = [192, 0, 2, 1]
        func bytes(_ value: UInt32) -> [UInt8] { [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) } }
        var tcp: [UInt8] = [0xc0, 0, 0, 80] + bytes(sequence) + bytes(ack) + [0x50, flags, 0xff, 0xff, 0, 0, 0, 0] + payload
        let tcpLength = tcp.count
        let pseudo = source + target + [0, 6, UInt8(tcpLength >> 8), UInt8(tcpLength & 255)]
        let tcpChecksum = checksum(pseudo + tcp)
        tcp[16] = UInt8(tcpChecksum >> 8); tcp[17] = UInt8(tcpChecksum & 255)
        let length = 20 + tcpLength
        var ip: [UInt8] = [0x45, 0, UInt8(length >> 8), UInt8(length & 255), 0, 1, 0, 0, 64, 6, 0, 0] + source + target
        let ipChecksum = checksum(ip)
        ip[10] = UInt8(ipChecksum >> 8); ip[11] = UInt8(ipChecksum & 255)
        return Data(ip + tcp)
    }
    private static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        for i in stride(from: 0, to: bytes.count, by: 2) {
            sum += UInt32(bytes[i]) << 8
            if i + 1 < bytes.count { sum += UInt32(bytes[i + 1]) }
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return UInt16(truncatingIfNeeded: ~sum)
    }
    private static func read(_ fd: Int32, _ count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let n = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress!.advanced(by: offset), count - offset, 0) }
            guard n > 0 else { return nil }
            offset += n
        }
        return Data(bytes)
    }
    private static func write(_ fd: Int32, _ data: Data) -> Bool {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset, 0) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return false }
            offset += count
        }
        return true
    }
}
