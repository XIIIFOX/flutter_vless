#!/usr/bin/env python3
"""Controlled loopback HTTP/SOCKS/VLESS upstreams for Android system-DNS tests.

The emulator accesses these listeners as 10.0.2.2. Reserved audit names never
leave this process. Only ordinary readiness traffic uses host networking, so
the computer's existing VPN remains in effect. JSONL records prove which proxy
transport handled each controlled DNS query; they are not a packet capture.
"""
import argparse
import ipaddress
import json
import select
import socket
import socketserver
import struct
import threading
import uuid
import time
from urllib.parse import urlsplit, parse_qs

SUFFIX = ".dns-audit.invalid"
ANSWER = "203.0.113.42"
VLESS_ID = uuid.UUID("2bddfbd9-7d82-4698-9d39-1b8136b856de").bytes
EVENTS = []
LOCK = threading.Lock()
EVENT_FILE = None
HTTP_STAGE_COUNT = 0
HTTP_STAGE_LIMIT = 256


def event(**value):
    value["host_epoch_seconds"] = time.time()
    with LOCK:
        EVENTS.append(value)
        line = json.dumps(value, sort_keys=True)
        print(line, flush=True)
        if EVENT_FILE:
            with open(EVENT_FILE, "a", encoding="utf-8") as output:
                output.write(line + "\n")


def http_stage(transport, stage, **details):
    """Bounded, content-free observations; never changes a relay outcome."""
    global HTTP_STAGE_COUNT
    if transport != "http":
        return
    with LOCK:
        if HTTP_STAGE_COUNT >= HTTP_STAGE_LIMIT:
            return
        HTTP_STAGE_COUNT += 1
    try:
        event(event="proxy-stage", transport="http", stage=stage, **details)
    except OSError:
        pass  # A diagnostic output failure must not replace the original I/O failure.


def http_error(transport, stage, error, **details):
    http_stage(transport, stage, error_class=type(error).__name__,
               errno=error.errno if isinstance(error, OSError) and isinstance(error.errno, int) else 0,
               **details)


def exact(sock, count):
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise EOFError()
        result += chunk
    return result


def address(sock, kind, kinds):
    if kind == kinds[0]:
        return str(ipaddress.ip_address(exact(sock, 4)))
    if kind == kinds[1]:
        return exact(sock, exact(sock, 1)[0]).decode("ascii")
    if kind == kinds[2]:
        return str(ipaddress.ip_address(exact(sock, 16)))
    raise ValueError("Unknown address type")


def dns_answer(query, transport):
    if len(query) < 17 or query[4:6] != b"\x00\x01":
        raise ValueError("Invalid DNS question")
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        if size > 63 or offset + size >= len(query):
            raise ValueError("Invalid DNS name")
        labels.append(query[offset + 1:offset + 1 + size].decode("ascii"))
        offset += size + 1
    offset += 1
    kind, cls = struct.unpack("!HH", query[offset:offset + 4])
    name = ".".join(labels).lower()
    question = query[12:offset + 4]
    controlled = name.endswith(SUFFIX)
    if controlled:
        dropped = name.startswith("drop-")
        event(event="dns", transport=transport, qname=name, qtype=kind,
              destination="1.1.1.1:53", network="tcp", dropped=dropped)
        if dropped:
            return None
        values = [ANSWER] if kind == 1 else ["2001:db8::42"] if kind == 28 else []
    else:
        values = []
        if kind in (1, 28):
            try:
                family = socket.AF_INET if kind == 1 else socket.AF_INET6
                values = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)))
            except OSError:
                pass
    answers = b""
    for value in values:
        packed = ipaddress.ip_address(value).packed
        answers += b"\xc0\x0c" + struct.pack("!HHIH", kind, cls, 0, len(packed)) + packed
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, len(values), 0, 0) + question + answers


def native_question(query):
    """Only bounded ordinary fixture questions; never delegates to OS DNS."""
    if not 17 <= len(query) <= 4096:
        raise ValueError('Invalid native DNS size')
    _, flags, questions, answers, authority, additional = struct.unpack('!HHHHHH', query[:12])
    if flags & 0xf800 or questions != 1 or answers or authority or additional > 1:
        raise ValueError('Invalid native DNS header')
    offset, labels = 12, []
    while True:
        if offset >= len(query):
            raise ValueError('Truncated native DNS name')
        size = query[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size >= len(query):
            raise ValueError('Invalid native DNS label')
        label = query[offset:offset + size].decode('ascii')
        if not label or any(not (c.isalnum() or c == '-') for c in label):
            raise ValueError('Invalid native DNS label')
        labels.append(label)
        offset += size
    if offset + 4 > len(query):
        raise ValueError('Truncated native DNS question')
    kind, cls = struct.unpack('!HH', query[offset:offset + 4])
    if cls != 1:
        raise ValueError('Invalid native DNS class')
    return '.'.join(labels).lower(), kind, query[12:offset + 4]


def native_answer(query, transport, port):
    name, kind, question = native_question(query)
    controlled = name.endswith(SUFFIX)
    event(event='dns', transport=transport, qname=name, qtype=kind,
          destination=f'10.0.2.2:{port}', network='tcp', dropped=False)
    code = 0 if controlled and kind in (1, 28) else 5
    answers = b''
    if controlled and kind == 1:
        packed = ipaddress.ip_address('10.0.2.2').packed
        answers = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(packed)) + packed
    return query[:2] + struct.pack('!HHHHH', 0x8180 | code, 1, int(bool(answers)), 0, 0) + question + answers


class NativeTCP(socketserver.BaseRequestHandler):
    """Raw numeric upstream for the opt-in composed native-entry tests only."""
    def handle(self):
        sock = self.request
        sock.settimeout(10)
        try:
            while True:
                size = int.from_bytes(exact(sock, 2), 'big')
                if not 17 <= size <= 4096:
                    raise ValueError('Invalid native TCP frame')
                query = exact(sock, size)
                name, kind, _ = native_question(query)
                if name.startswith('stall-') and name.endswith(SUFFIX):
                    details = dict(transport=self.server.transport, qname=name)
                    event(event='dns', qtype=kind, destination=f'10.0.2.2:{self.server.server_address[1]}', network='tcp', dropped=True, **details)
                    event(event='native-stall-start', **details)
                    try:
                        ended = sock.recv(1)
                        event(event='native-stall-eof' if ended == b'' else 'native-stall-data', **details)
                    except TimeoutError:
                        event(event='native-stall-timeout', **details)
                    return
                answer = native_answer(query, self.server.transport, self.server.server_address[1])
                sock.sendall(len(answer).to_bytes(2, 'big') + answer)
        except (EOFError, OSError, ValueError, UnicodeError):
            pass


def tunnel(sock, destination, port, transport):
    if port == 53:
        if destination != "1.1.1.1":
            event(event="unexpected-dns-destination", transport=transport, destination=destination)
            raise ValueError("System DNS was not rewritten to its configured upstream")
        while True:
            query = exact(sock, int.from_bytes(exact(sock, 2), "big"))
            answer = dns_answer(query, transport)
            if answer is None:
                return
            sock.sendall(len(answer).to_bytes(2, "big") + answer)
    destination_class = "status" if destination == "10.0.2.2" and port == 18283 else "other"
    # Only the fixture's status port is special-cased; readiness travels through host VPN.
    if destination == "10.0.2.2" and port == 18283:
        destination = "127.0.0.1"
    phase = "connect"
    client_bytes = upstream_bytes = 0
    http_stage(transport, "connect-attempt", destination_class=destination_class)
    try:
        with socket.create_connection((destination, port), 10) as upstream:
            phase = "relay"
            http_stage(transport, "connect-success", destination_class=destination_class)
            while True:
                readable, _, _ = select.select([sock, upstream], [], [], 20)
                if not readable:
                    http_stage(transport, "relay-idle", destination_class=destination_class,
                               client_bytes=client_bytes, upstream_bytes=upstream_bytes)
                    return
                for source in readable:
                    chunk = source.recv(16384)
                    if not chunk:
                        http_stage(transport, "relay-eof", destination_class=destination_class,
                                   side="client" if source is sock else "upstream",
                                   client_bytes=client_bytes, upstream_bytes=upstream_bytes)
                        return
                    (upstream if source is sock else sock).sendall(chunk)
                    if source is sock:
                        client_bytes += len(chunk)
                    else:
                        upstream_bytes += len(chunk)
    except (EOFError, OSError, ValueError, IndexError) as error:
        http_error(transport, phase + "-error", error, destination_class=destination_class,
                   client_bytes=client_bytes, upstream_bytes=upstream_bytes)
        raise


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(30)
        transport = self.server.transport
        entered_tunnel = False
        http_stage(transport, "accepted")
        try:
            if transport == "http":
                headers = b""
                while not headers.endswith(b"\r\n\r\n") and len(headers) < 16384:
                    headers += exact(sock, 1)
                first = headers.split(b"\r\n", 1)[0].decode("ascii")
                method, target, _ = first.split(" ", 2)
                if method != "CONNECT":
                    raise ValueError("HTTP fixture requires CONNECT")
                destination, port = target.rsplit(":", 1)
                destination, port = destination.strip("[]"), int(port)
                sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            elif transport == "socks":
                version, count = exact(sock, 2)
                if version != 5 or 0 not in exact(sock, count):
                    raise ValueError("Invalid SOCKS greeting")
                sock.sendall(b"\x05\x00")
                version, command, reserved, kind = exact(sock, 4)
                if (version, command, reserved) != (5, 1, 0):
                    raise ValueError("DNS fixture requires TCP SOCKS CONNECT")
                destination = address(sock, kind, (1, 3, 4))
                port = int.from_bytes(exact(sock, 2), "big")
                sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            else:
                version = exact(sock, 1)
                if version != b"\0" or exact(sock, 16) != VLESS_ID:
                    raise ValueError("Invalid VLESS client")
                exact(sock, exact(sock, 1)[0])  # request addons
                if exact(sock, 1) != b"\1":
                    raise ValueError("DNS fixture requires TCP VLESS command")
                port = int.from_bytes(exact(sock, 2), "big")
                destination = address(sock, exact(sock, 1)[0], (1, 2, 3))
                sock.sendall(b"\0\0")
            entered_tunnel = True
            tunnel(sock, destination, port, transport)
        except (EOFError, OSError, ValueError, IndexError) as error:
            if not entered_tunnel:
                http_error(transport, "handshake-error", error)
            pass


class Status(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        request = b""
        # Consume all headers before closing. Closing with unread request bytes
        # can reset an otherwise successful response on the VPN's TCP relay.
        while b"\r\n\r\n" not in request:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            request += chunk
            if len(request) > 16384:
                return
        preview_run = None
        try:
            path = request.split(b" ", 2)[1].decode("ascii")
            parsed = urlsplit(path)
            query = parse_qs(parsed.query)
            phase, run = query.get("phase", [None])[0], query.get("run", [None])[0]
            if parsed.path == '/native-preview' and run and run.isalnum() and len(run) == 12:
                preview_run = run
            if phase in ("ready", "stop-requested", "recovery-start", "recovery-ready") and run and run.isalnum() and len(run) == 12:
                event(event="lifecycle", phase=phase, run=run)
        except (IndexError, UnicodeError):
            pass
        with LOCK:
            value = EVENTS
            if preview_run:
                records = [record for record in EVENTS if record.get('qname', '').endswith('-' + preview_run + SUFFIX)]
                value = {'run': preview_run, 'queries': records}
                for transport in ('native-default', 'native-caller'):
                    value[transport.replace('-', '_')] = sum(record.get('event') == 'dns' and record.get('transport') == transport for record in records)
                for name in ('native-stall-start', 'native-stall-eof', 'native-stall-timeout'):
                    value[name.replace('-', '_')] = sum(record.get('event') == name for record in records)
            payload = json.dumps(value).encode()
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global EVENT_FILE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", help="Write controlled DNS observations as JSONL")
    parser.add_argument('--native-preview', action='store_true', help='Add numeric scoped-entry TCP fixture resolvers')
    arguments = parser.parse_args()
    EVENT_FILE = arguments.events
    servers = []
    try:
        for port, transport in [(18280, "http"), (18281, "socks"), (18282, "vless"), (18283, "status")]:
            server = Server(("127.0.0.1", port), Status if transport == "status" else Handler)
            server.transport = transport
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        if arguments.native_preview:
            for port, transport in [(18284, 'native-default'), (18285, 'native-caller')]:
                server = Server(('127.0.0.1', port), NativeTCP)
                server.transport = transport
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
        event(event="fixture-ready", ports={"http": 18280, "socks": 18281, "vless": 18282, "status": 18283})
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
