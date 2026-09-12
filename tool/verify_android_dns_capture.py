#!/usr/bin/env python3
"""Verify the emulator physical-interface pcap from ProtectedSystemDnsTest.

Reports only controlled fixture DNS names, never ordinary device traffic.
Requires both observed proxy payloads and zero matching UDP/TCP-53 packets.
This is scoped to plaintext system-DNS leaks for the reserved test names.
"""
import argparse
import collections
import json
import struct

MARKER = b"\x09dns-audit\x07invalid\x00"
PROXY_PORTS = {18280: "http", 18281: "socks", 18282: "vless"}


def packets(path):
    with open(path, "rb") as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("Missing pcap header")
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(header[:4])
        if endian is None:
            raise ValueError("Expected classic pcap from emulator network capture")
        link = struct.unpack(endian + "I", header[20:24])[0]
        if link not in (1, 101, 113):
            raise ValueError("Unsupported pcap data-link type")
        while True:
            record = capture.read(16)
            if not record:
                return
            if len(record) != 16:
                raise ValueError("Truncated pcap record")
            _, _, size, original_size = struct.unpack(endian + "IIII", record)
            if size != original_size:
                raise ValueError("Truncated packet capture cannot establish absence of DNS leaks")
            data = capture.read(size)
            if len(data) != size:
                raise ValueError("Truncated pcap payload")
            offset = 14 if link == 1 else 16 if link == 113 else 0
            if link == 1:
                kind = int.from_bytes(data[12:14], "big")
                while kind in (0x8100, 0x88a8):
                    kind = int.from_bytes(data[offset + 2:offset + 4], "big")
                    offset += 4
            yield data[offset:]


def transport(data):
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        offset = (data[0] & 15) * 4
        if (int.from_bytes(data[6:8], "big") & 0x1fff) != 0:
            return None
        protocol, source, destination = data[9], data[12:16], data[16:20]
        data = data[:int.from_bytes(data[2:4], "big")]
    elif version == 6:
        if len(data) < 40:
            return None
        protocol, source, destination, offset = data[6], data[8:24], data[24:40], 40
        while protocol in (0, 43, 60, 44):
            if offset + 8 > len(data):
                return None
            if protocol == 44:
                if (int.from_bytes(data[offset + 2:offset + 4], "big") & 0xfff8) != 0:
                    return None
                size = 8
            else:
                size = (data[offset + 1] + 1) * 8
            protocol, offset = data[offset], offset + size
    else:
        return None
    if protocol not in (6, 17) or offset + 8 > len(data):
        return None
    source_port, destination_port = struct.unpack("!HH", data[offset:offset + 4])
    if protocol == 17:
        return (protocol, source, destination, source_port, destination_port), None, data[offset + 8:]
    if offset + 20 > len(data):
        return None
    sequence = int.from_bytes(data[offset + 4:offset + 8], "big")
    payload = offset + (data[offset + 12] >> 4) * 4
    return (protocol, source, destination, source_port, destination_port), sequence, data[payload:]


def contiguous_stream(segments):
    output, end, gaps = b"", None, 0
    for sequence, payload in sorted(segments.items()):
        if end is None:
            output, end = payload, sequence + len(payload)
        elif sequence > end:
            output += b"\xff" + payload  # gaps must not synthesize a DNS name
            end = sequence + len(payload)
            gaps += 1
        elif sequence + len(payload) > end:
            output += payload[end - sequence:]
            end = sequence + len(payload)
    return output, gaps


def verify(path):
    streams = collections.defaultdict(dict)
    leaks = 0
    count = 0
    proxy_observations = collections.Counter()
    direct_dns_stream_gaps = 0
    for packet in packets(path):
        count += 1
        parsed = transport(packet)
        if parsed is None:
            continue
        key, sequence, payload = parsed
        protocol, _, _, _, destination_port = key
        if destination_port != 53 and destination_port not in PROXY_PORTS:
            continue
        if protocol == 17 and destination_port == 53:
            leaks += payload.count(MARKER)
        elif protocol == 6 and payload:
            if len(payload) > len(streams[key].get(sequence, b"")):
                streams[key][sequence] = payload
    for key, segments in streams.items():
        stream, gaps = contiguous_stream(segments)
        matches = stream.count(MARKER)
        if key[-1] == 53:
            leaks += matches
            direct_dns_stream_gaps += gaps
        elif key[-1] in PROXY_PORTS:
            proxy_observations[PROXY_PORTS[key[-1]]] += matches
    result = {"physical_packets": count, "controlled_direct_dns_queries": leaks,
              "direct_dns_stream_gaps": direct_dns_stream_gaps,
              "controlled_proxy_dns_queries": dict(proxy_observations),
              "passed": leaks == 0 and direct_dns_stream_gaps == 0 and all(proxy_observations[name] > 0 for name in PROXY_PORTS.values())}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    args = parser.parse_args()
    result = verify(args.capture)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
