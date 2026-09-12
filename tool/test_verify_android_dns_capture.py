import os
import struct
import tempfile
import unittest

from verify_android_dns_capture import MARKER, verify


def packet(port, payload, tcp=True, sequence=1):
    ip = bytearray(20)
    ip[0], ip[8], ip[9] = 0x45, 64, 6 if tcp else 17
    ip[12:16], ip[16:20] = bytes([10, 0, 2, 15]), bytes([1, 1, 1, 1])
    transport = bytearray(20 if tcp else 8)
    transport[:4] = struct.pack("!HH", 40000, port)
    if tcp:
        transport[4:8], transport[12] = struct.pack("!I", sequence), 0x50
    else:
        transport[4:6] = struct.pack("!H", 8 + len(payload))
    ip[2:4] = struct.pack("!H", len(ip) + len(transport) + len(payload))
    return bytes(ip + transport) + payload


class CaptureVerifierTest(unittest.TestCase):
    def capture(self, extra=(), proxies=True):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
            file.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
            packets = ([packet(port, MARKER) for port in (18280, 18281, 18282)] if proxies else []) + list(extra)
            for data in packets:
                file.write(struct.pack("<IIII", 0, 0, len(data), len(data)) + data)
        try:
            return verify(path)
        finally:
            os.unlink(path)

    def test_requires_all_proxy_observations(self):
        self.assertTrue(self.capture()["passed"])
        self.assertFalse(self.capture(proxies=False)["passed"])

    def test_rejects_direct_udp(self):
        result = self.capture([packet(53, MARKER, tcp=False)])
        self.assertFalse(result["passed"])
        self.assertEqual(1, result["controlled_direct_dns_queries"])

    def test_reassembles_split_out_of_order_tcp_and_deduplicates_retransmission(self):
        fragments = [packet(53, MARKER[5:], sequence=6), packet(53, MARKER[:5]), packet(53, MARKER[:5])]
        result = self.capture(fragments)
        self.assertFalse(result["passed"])
        self.assertEqual(1, result["controlled_direct_dns_queries"])

    def test_does_not_invent_name_across_missing_tcp_bytes(self):
        result = self.capture([packet(53, MARKER[:5]), packet(53, MARKER[5:], sequence=10)])
        self.assertFalse(result["passed"])
        self.assertEqual(0, result["controlled_direct_dns_queries"])
        self.assertEqual(1, result["direct_dns_stream_gaps"])


if __name__ == "__main__":
    unittest.main()
