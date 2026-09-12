#!/usr/bin/env python3
"""Loopback-only SOCKS fixture for native Android UID/FD regression tests.

It never connects to a requested destination. The emulator accesses the host
loopback as 10.0.2.2; all host-UID requests target unroutable documentation IPs.
"""
import socket
import socketserver
import threading

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
            exact(sock, size + 2)
            sock.sendall(b"\x05\x00\x00\x01\x0a\x00\x02\x02" + (18082).to_bytes(2, "big"))
            if command == 3:
                while sock.recv(1024):
                    pass
            elif command == 1:
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

def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 18082))
        while True:
            data, peer = sock.recvfrom(65535)
            if data[:3] == b"\0\0\0":
                sock.sendto(data, peer)
                print("UDP proxied host request", flush=True)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    threading.Thread(target=udp, daemon=True).start()
    with Server(("127.0.0.1", 18080), Socks) as server:
        print("Native SOCKS fixture ready: TCP 18080 / UDP 18082", flush=True)
        server.serve_forever()
