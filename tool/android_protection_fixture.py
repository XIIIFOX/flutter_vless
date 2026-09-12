#!/usr/bin/env python3
"""Loopback-only SOCKS fixture for native Android UID/FD regression tests.

It never connects to a requested destination. The emulator accesses the host
loopback as 10.0.2.2; all host-UID requests target unroutable documentation IPs.
"""
import socket
import socketserver
import threading
import select
import struct
import ipaddress
import argparse

RELAY_READINESS = False

MARKER = b"flutter-vless-protected-host"

def exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data

class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(30)
        try:
            version, count = exact(sock, 2)
            assert version == 5
            exact(sock, count)
            sock.sendall(b"\x05\x00")
            version, command, _, atyp = exact(sock, 4)
            size = {1: 4, 4: 16}.get(atyp)
            if atyp == 3:
                size = exact(sock, 1)[0]
            raw_address = exact(sock, size)
            port = int.from_bytes(exact(sock, 2), "big")
            destination = raw_address.decode() if atyp == 3 else str(ipaddress.ip_address(raw_address))
            sock.sendall(b"\x05\x00\x00\x01\x0a\x00\x02\x02" + (18082).to_bytes(2, "big"))
            if command == 3:
                while sock.recv(1024):
                    pass
            elif command == 1:
                if RELAY_READINESS and port == 53:
                    query = exact(sock, int.from_bytes(exact(sock, 2), "big"))
                    answer = dns_answer(query)
                    sock.sendall(len(answer).to_bytes(2, "big") + answer)
                    return
                if RELAY_READINESS and destination != "192.0.2.99" and not (destination in ("10.0.2.2", "proxy-site.invalid") and port == 18083):
                    with socket.create_connection((destination, port), 10) as upstream:
                        while True:
                            readable, _, _ = select.select([sock, upstream], [], [], 20)
                            if not readable:
                                return
                            for source in readable:
                                chunk = source.recv(16384)
                                if not chunk:
                                    return
                                (upstream if source is sock else sock).sendall(chunk)
                    return
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 8192:
                    chunk = sock.recv(1024)
                    if not chunk:
                        return
                    data += chunk
                sock.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(MARKER)).encode() + b"\r\n\r\n" + MARKER)
                print("TCP proxied host request", flush=True)
        except (EOFError, OSError):
            pass

def dns_answer(query):
    offset = 12
    labels = []
    while query[offset]:
        size = query[offset]
        labels.append(query[offset + 1:offset + 1 + size].decode("ascii"))
        offset += size + 1
    offset += 1
    kind, cls = struct.unpack("!HH", query[offset:offset + 4])
    question = query[12:offset + 4]
    values = []
    if kind in (1, 28):
        family = socket.AF_INET if kind == 1 else socket.AF_INET6
        try:
            values = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(".".join(labels), None, family, socket.SOCK_STREAM)))
        except OSError:
            pass
    answers = b""
    for value in values:
        packed = ipaddress.ip_address(value).packed
        answers += b"\xc0\x0c" + struct.pack("!HHIH", kind, cls, 30, len(packed)) + packed
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, len(values), 0, 0) + question + answers


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 18082))
        while True:
            data, peer = sock.recvfrom(65535)
            if data[:3] == b"\0\0\0":
                if RELAY_READINESS:
                    size = {1: 4, 4: 16}.get(data[3])
                    offset = 4
                    if data[3] == 3:
                        size = data[4]
                        offset = 5
                    header_length = offset + size + 2
                    if int.from_bytes(data[header_length - 2:header_length], "big") == 53:
                        data = data[:header_length] + dns_answer(data[header_length:])
                sock.sendto(data, peer)
                print("UDP proxied host request", flush=True)

class DirectProbe(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            self.request.recv(1024)
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\nConnection: close\r\n\r\nflutter-vless-direct-bypass")
        except OSError:
            pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-readiness", action="store_true", help="Relay non-sentinel readiness traffic through host networking (host VPN stays enabled)")
    RELAY_READINESS = parser.parse_args().relay_readiness
    threading.Thread(target=udp, daemon=True).start()
    direct = Server(("127.0.0.1", 18083), DirectProbe)
    threading.Thread(target=direct.serve_forever, daemon=True).start()
    with Server(("127.0.0.1", 18080), Socks) as server:
        print("Native SOCKS fixture ready: TCP 18080 / UDP 18082", flush=True)
        server.serve_forever()
