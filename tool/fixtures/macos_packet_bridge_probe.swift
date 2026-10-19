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
        guard packets.count == protocols.count, zip(packets, protocols).allSatisfy({ packet, family in
            guard let first = packet.first else { return false }
            return (first >> 4 == 4 && family.int32Value == AF_INET) ||
                   (first >> 4 == 6 && family.int32Value == AF_INET6)
        }) else { condition.unlock(); return false }
        self.packets.append(contentsOf: packets)
        condition.broadcast(); condition.unlock()
        return true
    }
    func send(_ data: Data, family: Int32 = AF_INET) throws {
        try send([data], family: family)
    }
    func send(_ batch: [Data], family: Int32 = AF_INET) throws {
        condition.lock()
        let deadline = Date().addingTimeInterval(5)
        while callback == nil {
            if !condition.wait(until: deadline) { condition.unlock(); throw POSIXError(.ETIMEDOUT) }
        }
        let callback = self.callback; self.callback = nil; condition.unlock()
        callback?(batch, Array(repeating: NSNumber(value: family), count: batch.count))
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

#if !PACKET_BRIDGE_IOS_APPLICATION
@main
#endif
struct PacketBridgeProbe {
    static func main() throws {
        setbuf(stdout, nil)
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
        guard bound == 0, listen(listener, 3) == 0 else { throw POSIXError(.EIO) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) }
        }
        let port = UInt16(bigEndian: address.sin_port)
        let relay = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard relay >= 0 else { throw POSIXError(.EIO) }
        defer { close(relay) }
        let relayBound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(relay, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard relayBound == 0 else { throw POSIXError(.EIO) }
        var relayTimeout = timeval(tv_sec: 5, tv_usec: 0)
        guard setsockopt(relay, SOL_SOCKET, SO_RCVTIMEO, &relayTimeout, socklen_t(MemoryLayout.size(ofValue: relayTimeout))) == 0 else { throw POSIXError(.EIO) }
        let transferred = DispatchSemaphore(value: 0)
        let ipv6TCPTransferred = DispatchSemaphore(value: 0)
        let ipv6UDPTransferred = DispatchSemaphore(value: 0)
        let associationClosed = DispatchSemaphore(value: 0)
        let stubDone = DispatchSemaphore(value: 0)
        let tcp6Payload = Data(("bridge-ipv6-tcp-" + UUID().uuidString).utf8)
        let udp6Payload = Data(("bridge-ipv6-udp-" + UUID().uuidString).utf8)
        let tcp6Reply = Data("accepted-".utf8) + tcp6Payload
        let udp6Reply = Data("accepted-".utf8) + udp6Payload
        let payload = Data("bridge-fixture".utf8)
        let bulk = Data((0..<(8 * 1024 * 1024)).map { UInt8($0 % 251) })
        DispatchQueue.global().async {
            defer { stubDone.signal() }
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

            let tcp6 = accept(listener, nil, nil)
            guard tcp6 >= 0 else { return }
            defer { close(tcp6) }
            guard configure(tcp6), handshake(tcp6, command: 1, target: ipv6Target, port: ipv6Port),
                  write(tcp6, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])),
                  read(tcp6, tcp6Payload.count) == tcp6Payload,
                  write(tcp6, tcp6Reply) else { return }
            ipv6TCPTransferred.signal()

            let control = accept(listener, nil, nil)
            guard control >= 0 else { return }
            defer { close(control) }
            // UDP ASSOCIATE describes the client relay socket, not the payload
            // target. Its zero tuple is intentionally distinct from ATYP4 below.
            guard configure(control), handshake(control, command: 3),
                  write(control, Data([5, 0, 0, 1, 127, 0, 0, 1, UInt8(port >> 8), UInt8(port & 255)])) else { return }
            var packet = [UInt8](repeating: 0, count: 2048)
            var peer = sockaddr_storage()
            var peerLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let count = withUnsafeMutablePointer(to: &peer) { peer in
                peer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(relay, &packet, packet.count, 0, $0, &peerLength)
                }
            }
            let header = Data([0, 0, 0, 4] + ipv6Target + [UInt8(ipv6Port >> 8), UInt8(ipv6Port & 255)])
            guard count == header.count + udp6Payload.count,
                  Data(packet.prefix(count)) == header + udp6Payload,
                  peer.ss_family == sa_family_t(AF_INET) else { return }
            let response = header + udp6Reply
            let sent = response.withUnsafeBytes { bytes in
                withUnsafePointer(to: &peer) { peer in
                    peer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(relay, bytes.baseAddress, bytes.count, 0, $0, peerLength)
                    }
                }
            }
            guard sent == response.count else { return }
            ipv6UDPTransferred.signal()
            var byte: UInt8 = 0
            guard recv(control, &byte, 1, 0) == 0 else { return }
            associationClosed.signal()
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
            guard code == 0 else { fputs("FAIL HEV exit code=\(code)\n", stderr); exit(1) }
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

            try flow.send(ipv6TCP(sequence: 4000, ack: 0, flags: 2), family: AF_INET6)
            let synack6 = try flow.receive { packet in
                guard let tcp = ipv6Transport(packet, protocol: 6), tcp.count >= 20 else { return false }
                return tcp[0..<4] == Data([UInt8(ipv6Port >> 8), UInt8(ipv6Port & 255), 0xc0, 1]) && tcp[13] & 0x12 == 0x12
            }
            guard let syn6 = ipv6Transport(synack6, protocol: 6) else { throw POSIXError(.EBADMSG) }
            let seq6 = syn6[4..<8].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            try flow.send(ipv6TCP(sequence: 4001, ack: seq6 &+ 1, flags: 16), family: AF_INET6)
            try flow.send(ipv6TCP(sequence: 4001, ack: seq6 &+ 1, flags: 24, payload: tcp6Payload), family: AF_INET6)
            let returnedTCP = try flow.receive { packet in
                guard let tcp = ipv6Transport(packet, protocol: 6), tcp.count >= 20 else { return false }
                let offset = Int(tcp[12] >> 4) * 4
                return offset >= 20 && offset <= tcp.count && Data(tcp.dropFirst(offset)) == tcp6Reply
            }
            guard let tcp6 = ipv6Transport(returnedTCP, protocol: 6), tcp6[0..<4] == Data([UInt8(ipv6Port >> 8), UInt8(ipv6Port & 255), 0xc0, 1]),
                  tcp6[4..<8].reduce(UInt32(0), { ($0 << 8) | UInt32($1) }) == seq6 &+ 1,
                  ipv6TCPTransferred.wait(timeout: .now() + 5) == .success else { throw POSIXError(.EBADMSG) }
            try flow.send(ipv6TCP(sequence: UInt32(4001 + tcp6Payload.count), ack: seq6 &+ 1 &+ UInt32(tcp6Reply.count), flags: 16), family: AF_INET6)
            print("PASS shipped HEV: IPv6 TCP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow")

            try flow.send(ipv6UDP(payload: udp6Payload), family: AF_INET6)
            let returnedUDP = try flow.receive { packet in
                guard let udp = ipv6Transport(packet, protocol: 17), udp.count >= 8 else { return false }
                return Data(udp.dropFirst(8)) == udp6Reply
            }
            guard let udp6 = ipv6Transport(returnedUDP, protocol: 17),
                  udp6[0..<4] == Data([UInt8(ipv6Port >> 8), UInt8(ipv6Port & 255), 0xc0, 2]),
                  Int(udp6[4]) * 256 + Int(udp6[5]) == udp6.count,
                  ipv6UDPTransferred.wait(timeout: .now() + 5) == .success else { throw POSIXError(.EBADMSG) }
            print("PASS shipped HEV: IPv6 UDP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow")
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
        guard associationClosed.wait(timeout: .now() + 5) == .success,
              stubDone.wait(timeout: .now() + 5) == .success else { throw POSIXError(.ETIMEDOUT) }
        print("PASS shipped HEV: packetFlow -> owned datagram bridge -> HEV TCP -> loopback SOCKS -> packetFlow; clean shutdown")
    }

    private static let ipv6Source: [UInt8] = [0xfd, 0, 1, 0x98, 0, 0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    private static let ipv6Target: [UInt8] = [0x20, 1, 0x0d, 0xb8, 0, 0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42]
    private static let ipv6Port: UInt16 = 45678

    private static func configure(_ fd: Int32) -> Bool {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        var enabled: Int32 = 1
        return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 &&
               setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 &&
               setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0
    }

    private static func handshake(_ fd: Int32, command: UInt8, target: [UInt8]? = nil, port: UInt16 = 0) -> Bool {
        guard let greeting = read(fd, 2), greeting[0] == 5,
              let methods = read(fd, Int(greeting[1])), methods.contains(0),
              write(fd, Data([5, 0])), let request = read(fd, 4),
              request[0] == 5, request[1] == command, request[2] == 0 else { return false }
        if let target {
            return request[3] == 4 && read(fd, 18) == Data(target + [UInt8(port >> 8), UInt8(port & 255)])
        }
        // HEV UDP ASSOCIATE uses an unspecified IPv4 or IPv6 client tuple.
        let count = request[3] == 1 ? 6 : request[3] == 4 ? 18 : 0
        return count > 0 && read(fd, count) == Data(repeating: 0, count: count)
    }

    private static func bytes(_ value: UInt32) -> [UInt8] {
        [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) }
    }

    private static func ipv6Packet(_ transport: [UInt8], protocol number: UInt8) -> Data {
        Data([0x60, 0, 0, 0, UInt8(transport.count >> 8), UInt8(transport.count & 255), number, 64] +
             ipv6Source + ipv6Target + transport)
    }

    private static func ipv6TCP(sequence: UInt32, ack: UInt32, flags: UInt8, payload: Data = Data()) -> Data {
        var tcp: [UInt8] = [0xc0, 1, UInt8(ipv6Port >> 8), UInt8(ipv6Port & 255)] + bytes(sequence) + bytes(ack) +
            [0x50, flags, 0xff, 0xff, 0, 0, 0, 0] + payload
        let sum = checksum(ipv6Source + ipv6Target + bytes(UInt32(tcp.count)) + [0, 0, 0, 6] + tcp)
        tcp[16] = UInt8(sum >> 8); tcp[17] = UInt8(sum & 255)
        return ipv6Packet(tcp, protocol: 6)
    }

    private static func ipv6UDP(payload: Data) -> Data {
        let length = payload.count + 8
        var udp = [UInt8(0xc0), 2, UInt8(ipv6Port >> 8), UInt8(ipv6Port & 255), UInt8(length >> 8), UInt8(length & 255), 0, 0] + payload
        let calculated = checksum(ipv6Source + ipv6Target + bytes(UInt32(length)) + [0, 0, 0, 17] + udp)
        let sum: UInt16 = calculated == 0 ? 0xffff : calculated
        udp[6] = UInt8(sum >> 8); udp[7] = UInt8(sum & 255)
        return ipv6Packet(udp, protocol: 17)
    }

    /// Only the exact reverse flow with a valid mandatory IPv6 transport checksum
    /// is evidence. An unrelated v4 packet, address, port or corrupt reply cannot pass.
    private static func ipv6Transport(_ packet: Data, protocol number: UInt8) -> Data? {
        guard packet.count >= 48, packet[0] >> 4 == 6, packet[6] == number,
              packet[8..<24] == Data(ipv6Target), packet[24..<40] == Data(ipv6Source),
              Int(packet[4]) * 256 + Int(packet[5]) == packet.count - 40 else { return nil }
        let transport = Array(packet.dropFirst(40))
        if number == 17 && (transport.count < 8 || (transport[6] == 0 && transport[7] == 0)) { return nil }
        guard checksum(ipv6Target + ipv6Source + bytes(UInt32(transport.count)) + [0, 0, 0, number] + transport) == 0 else { return nil }
        return Data(transport)
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
