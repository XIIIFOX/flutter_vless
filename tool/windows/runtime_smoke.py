"""Exercise real Windows services with synthetic local network fixtures.

Full VPN mode is restricted to a disposable GitHub Windows runner. It sends
ordinary TCP to a documentation IP; HTTP sniffing selects a domain rule and
Xray delivers to a local underlay HTTP server or a loopback SOCKS server. No server secrets.
"""
import argparse
from contextlib import contextmanager, ExitStack
import base64
import hashlib
import http.client
import json
import ntpath
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import struct
import sys
from functools import lru_cache
import threading
import time
import tempfile
import uuid
from xml.etree import ElementTree
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORTS = {"inbound": 18580, "direct": 18581, "proxy": 18582, "extra": 18583, "routing_proxy": 18584}
DNS_QUERIES = []
PROBE = None
REAL_DNS = False
IPV6_PAYLOAD_TARGET = "2001:db8:85::7"
IPV6_TUN_SOURCE = "fd00:198:18::2"
IPV6_PAYLOAD_PORT = 45678
FAKEDNS_NAME = "fakedns-payload.invalid"
FAKEDNS_PORT = 45679


class IPv6PayloadState:
    """One-shot synthetic markers; no forwarding or physical IPv6 sockets."""
    def __init__(self):
        self.lock = threading.Lock()
        self.drained = threading.Condition(self.lock)
        self.expected = {}
        self.observed = {}
        self.controls = {}
        self.errors = []
        self.closed = False

    def arm(self, transport):
        assert transport in ("tcp", "udp")
        with self.lock:
            assert not self.closed and transport not in self.expected, "IPv6 marker already outstanding"
            payload = ("ipv6-payload-" + transport + "-" + uuid.uuid4().hex).encode("ascii")
            self.expected[transport] = payload
            return payload

    def accept(self, transport, kind, address, port, payload, source=None):
        with self.lock:
            active = source is None or any(peer == source for peer in self.controls.values())
            expected = self.expected.get(transport)
            if self.closed or not active or kind != 4 or address != socket.inet_pton(socket.AF_INET6, IPV6_PAYLOAD_TARGET) \
                    or port != IPV6_PAYLOAD_PORT or expected is None or payload != expected:
                self.errors.append("unexpected IPv6 proxy target or marker")
                return None
            del self.expected[transport]
            self.observed[transport] = payload
            return b"accepted-" + payload

    def control_open(self, sock, source):
        with self.lock:
            if self.closed:
                return False
            self.controls[sock] = source
            return True

    def control_close(self, sock):
        with self.drained:
            self.controls.pop(sock, None)
            self.drained.notify_all()

    def require_observed(self, transport, payload):
        with self.lock:
            assert not self.errors and self.observed.get(transport) == payload, "IPv6 proxy did not observe the exact one-shot target/marker"

    def close(self):
        with self.lock:
            self.closed = True
            controls = list(self.controls)
        for control in controls:
            try:
                control.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            control.close()
        deadline = time.monotonic() + 3
        with self.drained:
            while self.controls:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "IPv6 SOCKS control did not drain after close"
                self.drained.wait(remaining)

    def require_clean(self):
        with self.lock:
            assert not self.errors and not self.expected and not self.controls, "IPv6 proxy has rejected, outstanding or undrained work"


class IPv6PayloadDatagram(socketserver.BaseRequestHandler):
    def handle(self):
        packet, relay = self.request
        state = self.server.ipv6_payload
        # RFC1928 UDP: RSV=0, FRAG=0, ATYP=IPv6, exact target and payload.
        if len(packet) < 22 or packet[:4] != b"\0\0\0\x04":
            state.accept("udp", 0, b"", 0, b"", self.client_address[0])
            return
        reply = state.accept("udp", packet[3], packet[4:20], int.from_bytes(packet[20:22], "big"),
                             packet[22:], self.client_address[0])
        if reply is not None:
            relay.sendto(packet[:22] + reply, self.client_address)


class DatagramServer(socketserver.ThreadingUDPServer):
    daemon_threads = True


class FakeDnsPayloadState:
    """Dedicated observer: exact recovered domain and one-shot opaque bytes."""
    def __init__(self):
        self.lock = threading.Lock()
        self.drained = threading.Condition(self.lock)
        self.expected, self.controls = {}, {}
        self.observed, self.errors = [], []
        self.closed = False

    def arm(self, transport):
        with self.lock:
            assert transport in ("tcp", "udp") and not self.closed and transport not in self.expected
            payload = ("fakedns-payload-" + transport + "-" + uuid.uuid4().hex).encode("ascii")
            self.expected[transport] = payload
            return payload

    def accept(self, transport, kind, address, port, payload, source=None):
        with self.lock:
            active = transport == "tcp" or source in self.controls.values()
            if self.closed or not active or kind != 3 or address != FAKEDNS_NAME.encode("ascii") \
                    or port != FAKEDNS_PORT or self.expected.get(transport) != payload:
                self.errors.append("unexpected FakeDNS domain or nonce")
                return None
            del self.expected[transport]
            self.observed.append((transport, payload))
            return b"accepted-" + payload

    def control_open(self, sock, source):
        with self.lock:
            if self.closed: return False
            self.controls[sock] = source
            return True

    def control_close(self, sock):
        with self.drained:
            self.controls.pop(sock, None)
            self.drained.notify_all()

    def require_observed(self, transport, payload):
        with self.lock:
            assert not self.errors and self.observed.count((transport, payload)) == 1, "Exact FakeDNS domain and nonce not observed"

    def require_drained(self):
        deadline = time.monotonic() + 3
        with self.drained:
            while self.controls:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "FakeDNS Stop retained a SOCKS association"
                self.drained.wait(remaining)

    def close(self):
        with self.lock:
            self.closed = True
            controls = list(self.controls)
        for control in controls:
            try: control.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            control.close()
        deadline = time.monotonic() + 3
        with self.drained:
            while self.controls:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "FakeDNS SOCKS association did not drain"
                self.drained.wait(remaining)

    def require_clean(self):
        with self.lock:
            assert not self.errors and not self.expected and not self.controls, "FakeDNS observer retained failed/outstanding work"
            assert [kind for kind, _ in self.observed].count("tcp") == 2 \
                and [kind for kind, _ in self.observed].count("udp") == 2, "FakeDNS restart payload count changed"


class FakeDnsPayloadDatagram(socketserver.BaseRequestHandler):
    def handle(self):
        packet, relay = self.request
        state = self.server.fake_dns_payload
        end = 7 + packet[4] if len(packet) >= 5 else 0
        if packet[:4] != b"\0\0\0\x03" or end < 8 or len(packet) < end:
            state.accept("udp", 0, b"", 0, b"", self.client_address[0])
            return
        reply = state.accept("udp", 3, packet[5:end - 2], int.from_bytes(packet[end - 2:end], "big"),
                             packet[end:], self.client_address[0])
        if reply is not None:
            relay.sendto(packet[:end] + reply, self.client_address)


def ipv6_payload_request(state, udp):
    transport = "udp" if udp else "tcp"
    payload = state.arm(transport)
    expected = b"accepted-" + payload
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(4)
        sock.connect((IPV6_PAYLOAD_TARGET, IPV6_PAYLOAD_PORT))
        assert sock.getsockname()[0] == IPV6_TUN_SOURCE, "IPv6 payload did not select the owned tunnel address"
        sock.sendall(payload)
        reply = sock.recv(256) if udp else exact(sock, len(expected))
        assert reply == expected, "IPv6 payload marker reply changed"
    state.require_observed(transport, payload)
    return "IPv6 " + transport.upper() + " bytes via exact IPv4 SOCKS target and nonce"


def dns_question(query):
    offset = 12
    labels = []
    while offset < len(query) and query[offset]:
        size = query[offset]
        if size > 63 or offset + size + 1 > len(query):
            raise ValueError("Malformed fixture DNS question")
        labels.append(query[offset + 1:offset + size + 1].decode("ascii"))
        offset += size + 1
    if offset + 5 > len(query):
        raise ValueError("Truncated fixture DNS question")
    return ".".join(labels).lower(), offset + 5


def real_dns_response(query):
    # The ordinary socket is captured by TUN and forwarded by Xray's explicit
    # external-direct outbound. No physical DNS exception or host resolver is
    # used: the numeric HTTPS endpoint also avoids recursive name resolution.
    connection = http.client.HTTPSConnection("1.1.1.1", timeout=5,
                                             context=ssl.create_default_context())
    try:
        connection.request("POST", "/dns-query", body=query, headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        response = connection.getresponse()
        body = response.read(65536)
        if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/dns-message":
            raise ValueError("Controlled DoH request failed")
        if not 12 <= len(body) <= 65535 or body[:2] != query[:2] or not body[2] & 0x80:
            raise ValueError("Invalid controlled DoH response")
        return body
    finally:
        connection.close()


def dns_response(query):
    name, offset = dns_question(query)
    DNS_QUERIES.append(query[12:offset].hex())
    # Keep synthetic answers scoped to the test names. The runner itself must
    # retain working DNS/HTTPS while its traffic is captured by the VPN.
    if REAL_DNS and name != "invalid" and not name.endswith(".invalid"):
        return real_dns_response(query)
    return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:offset] + \
        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc6\x33\x64\x07"


def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("connection closed")
        data += part
    return data


def diagnostic_error_class(error):
    return type(error).__name__[:48]


def publish_rejection(path, document):
    # The C++ consumer reads/removes immediately after exists(). Publish only
    # after the sibling writer is closed, including on Windows sharing rules.
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    primary = None
    try:
        try:
            stream = os.fdopen(descriptor, "w", encoding="utf-8")
        except BaseException:
            try: os.close(descriptor)
            except OSError: pass
            raise
        with stream:
            stream.write(json.dumps(document))
        os.replace(temporary, path)
    except BaseException as error:
        primary = error
        raise
    finally:
        try: temporary.unlink(missing_ok=True)
        except OSError:
            if primary is None: raise


def replacement_failure(state, stage, process_exit, replacement_marker, asset_marker):
    # Evidence is captured before the existing finally stops the child. Retain
    # only fixed labels, booleans and the numeric exit status, never raw state/log.
    record = dict(stage=stage, before_stop=True,
                  process_exit=process_exit if type(process_exit) is int and -(1 << 31) <= process_exit < (1 << 32) else None,
                  replacement_marker=replacement_marker, asset_marker=asset_marker)
    try:
        with state.open("rb") as stream: data = stream.read(4097)
        value = json.loads(data) if len(data) <= 4096 else None
        record["state"] = ({name: value[name] for name in ("running", "protecting")}
                           if isinstance(value, dict) and all(type(value.get(name)) is bool for name in ("running", "protecting"))
                           else {"status": "invalid"})
    except (OSError, ValueError, RecursionError):
        record["state"] = {"status": "unavailable"}
    encoded = json.dumps(record, sort_keys=True)
    error = RuntimeError("Invalid replacement did not preserve the live session")
    try: Path(str(state) + ".rejection.evidence.log").write_text(encoded + "\n", encoding="utf-8")
    except OSError: pass
    if hasattr(error, "add_note"): error.add_note("REPLACEMENT_EVIDENCE " + encoded)
    return error


def await_rejected_replacement(process, log, state, require_asset):
    deadline = time.monotonic() + 25
    while True:
        current_log = log.read_text(errors="replace")
        replacement = "REJECTED_REPLACEMENT_PRESERVED=1" in current_log
        asset = "REJECTED_ASSET_ROOT_PRESERVED=1" in current_log
        if replacement and (not require_asset or asset): return
        code = process.poll()
        if code is not None or time.monotonic() >= deadline:
            raise replacement_failure(state, "CHILD_EXIT" if code is not None else "TIMEOUT", code, replacement, asset)
        time.sleep(0.1)


class DirectOrigin(ThreadingHTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        if hasattr(self, "direct_only_lock"):
            with self.direct_only_lock:
                owner = self.direct_only_active
                if owner is not None:
                    if len(self.direct_only_pending) < 64:
                        self.direct_only_pending[connection] = owner
                    self.direct_only_evidence[owner]["accepts"] += 1
        return connection, address


def direct_origin_event(handler, event, value=1):
    owner = getattr(handler, "direct_only_owner", None)
    if owner is not None:
        with handler.server.direct_only_lock:
            handler.server.direct_only_evidence[owner][event] += value


def save_direct_evidence(path, record, error=None):
    # Only fixed labels, booleans, byte counts and exception classes; no body,
    # raw native output, profile contents or exception messages are retained.
    encoded = json.dumps(record, sort_keys=True)
    if len(encoded) > 8192:
        encoded = json.dumps({"diagnostic": "bounded evidence overflow"})
    try:
        path.write_text(encoded + "\n", encoding="utf-8")
    except OSError:
        encoded = json.dumps({"diagnostic": "evidence write failed"})
    if error is not None and hasattr(error, "add_note"):
        error.add_note("DIRECT_ONLY_EVIDENCE " + encoded)


def direct_failure_evidence(label, stage, process, state, origin, requests):
    try:
        with state.open("rb") as stream:
            data = stream.read(4097)
        value = json.loads(data) if len(data) <= 4096 else None
        state_value = ({name: value[name] for name in ("running", "protecting")}
                       if isinstance(value, dict) and all(type(value.get(name)) is bool for name in ("running", "protecting"))
                       else {"status": "invalid"})
    except (OSError, ValueError) as error:
        state_value = {"status": diagnostic_error_class(error)}
    with origin.direct_only_lock:
        observed = dict(origin.direct_only_evidence[label])
    return dict(case=label, stage=stage, before_stop=True, process_exit=process.poll(),
                state=state_value, requests=requests, origin=observed)


class Direct(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.direct_only_owner = None
        if hasattr(server, "direct_only_lock"):
            with server.direct_only_lock:
                self.direct_only_owner = server.direct_only_pending.pop(request, None)
        super().__init__(request, client_address, server)

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def do_GET(self):
        if hasattr(self.server, "direct_only_lock"):
            with self.server.direct_only_lock:
                self.server.direct_only_observed.append(self.headers.get("Host"))
        kind = {"direct-only.invalid": "allowed", "blocked.invalid": "blocked"}.get(self.headers.get("Host"), "other")
        direct_origin_event(self, "get_" + kind)
        body = b"DIRECT-FIXTURE"
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            direct_origin_event(self, "headers_completed")
            written = self.wfile.write(body)
            direct_origin_event(self, "body_bytes", written if isinstance(written, int) else 0)
        except BaseException as error:
            direct_origin_event(self, "errors")
            owner = getattr(self, "direct_only_owner", None)
            if owner is not None:
                with self.server.direct_only_lock:
                    self.server.direct_only_evidence[owner]["last_error_class"] = diagnostic_error_class(error)
            raise

    def log_message(self, *_):
        pass


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            _, count = exact(sock, 2)
            exact(sock, count)
            sock.sendall(b"\x05\x00")
            _, command, _, kind = exact(sock, 4)
            count = exact(sock, 1)[0] if kind == 3 else {1: 4, 4: 16}[kind]
            address = exact(sock, count)
            port = int.from_bytes(exact(sock, 2), "big")
            fake_dns_state = getattr(self.server, "fake_dns_payload", None)
            payload_state = getattr(self.server, "ipv6_payload", None) or fake_dns_state
            if command == 3 and payload_state is not None:
                # The relay is the same numeric IPv4 address and port as this
                # TCP server. A closed transport pin need not admit an unknown
                # ephemeral UDP port or resolve a relay hostname.
                if kind != 1 or address != bytes(4) or port != 0 \
                        or not payload_state.control_open(sock, self.client_address[0]):
                    return
                try:
                    relay_host, relay_port = self.server.server_address
                    sock.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(relay_host) + relay_port.to_bytes(2, "big"))
                    sock.settimeout(1)
                    while True:
                        try:
                            if not sock.recv(1):
                                break
                            payload_state.accept("udp", 0, b"", 0, b"", self.client_address[0])
                            break
                        except socket.timeout:
                            with payload_state.lock:
                                if payload_state.closed:
                                    break
                finally:
                    payload_state.control_close(sock)
                return
            if command != 1:
                return
            sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            if fake_dns_state is not None:
                payload = exact(sock, len(b"fakedns-payload-tcp-") + 32)
                reply = fake_dns_state.accept("tcp", kind, address, port, payload)
                if reply is not None: sock.sendall(reply)
                return
            if kind == 4 and payload_state is not None:
                payload = exact(sock, len(b"ipv6-payload-tcp-") + 32)
                reply = payload_state.accept("tcp", kind, address, port, payload)
                if reply is not None:
                    sock.sendall(reply)
                return
            if port == 53:
                query = exact(sock, int.from_bytes(exact(sock, 2), "big"))
                response = dns_response(query)
                sock.sendall(len(response).to_bytes(2, "big") + response)
                return
            data = b""
            while b"\r\n\r\n" not in data:
                part = sock.recv(4096)
                if not part or len(data) > 65536:
                    return
                data += part
            body = b"PROXY-FIXTURE"
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                         str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except (EOFError, OSError, KeyError, ValueError, http.client.HTTPException):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DirectDns(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            query = exact(self.request, int.from_bytes(exact(self.request, 2), "big"))
            _, end = dns_question(query)
            with self.server.questions_lock:
                self.server.questions.append(query[12:end].hex())
            answer = dns_response(query)
            self.request.sendall(len(answer).to_bytes(2, "big") + answer)
        except (OSError, EOFError, ValueError):
            pass


def direct_only_config(index, address, dns_port):
    fixtures = Path(__file__).resolve().parents[2] / "tool/fixtures/compatibility"
    assert index in (0, 1, 2) and 1 <= dns_port <= 65535
    if index == 2:
        profile = json.loads((fixtures / "selector-traffic.json").read_text(encoding="utf-8"))
    else:
        corpus = json.loads((fixtures / "direct-only.json").read_text(encoding="utf-8"))
        assert len(corpus) == 2
        profile = corpus[index]["config"]
    socket.inet_aton(address)  # The controlled fixture endpoint is numeric, never an OS lookup.
    profile["dns"]["hosts"]["direct-only.invalid"] = address
    profile["dns"]["servers"] = [f"tcp://{address}:{dns_port}"]
    direct = next(outbound for outbound in profile["outbounds"] if outbound["protocol"] in ("freedom", "direct"))
    direct["settings"]["redirect"] = address + ":0"  # Preserve HTTP and resolver ports.
    assert all(outbound["protocol"] in ("freedom", "direct", "blackhole", "block") for outbound in profile["outbounds"])
    return profile


def direct_only_dns(server, tcp):
    name = uuid.uuid4().hex + ".invalid"
    question = b"\x20" + name[:32].encode() + b"\x07invalid\x00\x00\x01\x00\x01"
    query = b"\x12\x34\x01\x00\x00\x01" + bytes(6) + question
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(5); sock.connect(("10.0.85.53", 53))
        assert sock.getsockname()[0] == "10.0.85.2", "Direct-only DNS bypassed the TUN"
        sock.sendall((len(query).to_bytes(2, "big") if tcp else b"") + query)
        answer = exact(sock, int.from_bytes(exact(sock, 2), "big")) if tcp else sock.recv(4096)
    assert answer[:2] == query[:2] and answer[3] & 15 == 0 and answer[12:12 + len(question)] == question \
        and answer.endswith(b"\xc6\x33\x64\x07"), "Direct-only DNS reply changed"
    with server.questions_lock:
        assert question.hex() in server.questions, "Direct-only DNS did not reach the numeric TCP resolver"


def request(host, vpn, loopback=False, proxy_port=None, diagnostic=None):
    data = b""
    read_end = "not_read"
    try:
        destination = ("127.0.0.1", PORTS["direct"]) if loopback else (("203.0.113.10", PORTS["direct"]) if vpn else ("127.0.0.1", proxy_port or PORTS["inbound"]))
        with socket.create_connection(destination, timeout=4) as sock:
            sock.settimeout(4)
            if vpn:
                assert sock.getsockname()[0] == ("127.0.0.1" if loopback else "10.0.85.2"), "Unexpected client interface"
            encoded = host.encode()
            if not vpn and not loopback:
                sock.sendall(b"\x05\x01\x00")
                assert exact(sock, 2) == b"\x05\x00"
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded +
                             PORTS["direct"].to_bytes(2, "big"))
                head = exact(sock, 4)
                assert head[1] == 0, head
                count = exact(sock, 1)[0] if head[3] == 3 else {1: 4, 4: 16}[head[3]]
                exact(sock, count + 2)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + encoded + b"\r\nConnection: close\r\n\r\n")
            read_end = "reading"
            while True:
                part = sock.recv(4096)
                if not part:
                    read_end = "eof"
                    break
                data += part
            if b"\r\n\r\n" not in data:
                raise RuntimeError("connection ended without an HTTP response")
            return data.split(b"\r\n\r\n", 1)[1].decode()
    except BaseException as error:
        if read_end == "reading":
            read_end = "error"
        if diagnostic is not None:
            diagnostic["error_class"] = diagnostic_error_class(error)
        raise
    finally:
        if diagnostic is not None:
            diagnostic.update(response_bytes=len(data), header_present=b"\r\n\r\n" in data, read_end=read_end)


def external_http(address, vpn=False):
    # Direct baseline and in-tunnel request use the same address and HTTP Host.
    # This detects a freedom outbound looping back into the TUN default route.
    with socket.create_connection((address, 443), timeout=4) as connection, \
            ssl.create_default_context().wrap_socket(connection, server_hostname="api.ipify.org") as sock:
        sock.settimeout(4)
        if vpn:
            assert sock.getsockname()[0] == "10.0.85.2", "External HTTPS bypassed the TUN"
        sock.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        data = sock.recv(4096)
        if not data.startswith(b"HTTP/1.1 200") and not data.startswith(b"HTTP/1.0 200"):
            raise RuntimeError("public HTTP control did not return 200")
        return "HTTP 200"


def config(reverse, external_address=None, direct_address="127.0.0.1", caller_api_port=None, asset_fixture=None, ipv6_payload=False):
    profile = {
        "log": {"loglevel": "warning", "access": "none"},
        "dns": {"hosts": {h: direct_address for h in ("2ip.ru", "2ip.io", "myip.com")},
                "servers": ["localhost"]},
        "inbounds": [{"port": PORTS["inbound"], "protocol": "socks", "tag": "socks-in",
                      "listen": "127.0.0.1", "settings": {"auth": "noauth", "udp": True},
                      "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                                   "routeOnly": False}}],
        "outbounds": [{"protocol": "socks", "tag": "proxy",
                       "settings": {"servers": [{"address": direct_address, "port": PORTS["proxy"]}]}},
                      {"protocol": "freedom", "tag": "direct", "settings": {
                          "domainStrategy": "UseIP", "redirect": f"{direct_address}:{PORTS['direct']}"}}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "domain": ["domain:myip.com"] if reverse else ["domain:ru", "domain:io"],
             "outboundTag": "direct"}]}}
    profile["routing"]["rules"].append({"type": "field", "domain":
        ["full:2ip.ru", "full:2ip.io"] if reverse else ["full:myip.com"], "outboundTag": "proxy"})
    if external_address:
        profile["inbounds"].append({"port": PORTS["extra"], "protocol": "socks", "listen": "127.0.0.1", "tag": "socks-direct",
                                    "settings": {"auth": "noauth", "udp": True}})
        profile["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["socks-direct"], "outboundTag": "direct"})
        profile["outbounds"].append({"protocol": "freedom", "tag": "external-direct"})
        profile["dns"]["hosts"]["api.ipify.org"] = external_address
        profile["routing"]["rules"].append(
            {"type": "field", "domain": ["full:api.ipify.org"], "outboundTag": "external-direct"})
        profile["routing"]["rules"].append(
            {"type": "field", "network": "tcp,udp", "outboundTag": "external-direct"})
    # A dormant imported rule must not acquire the managed VPN input's traffic.
    profile["outbounds"].append({"protocol": "blackhole", "tag": "fixture-blocked"})
    profile["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["flutter-vless-tun"],
                                            "outboundTag": "fixture-blocked"})
    if ipv6_payload:
        profile["dns"]["hosts"]["ipv6-payload.invalid"] = IPV6_PAYLOAD_TARGET
        profile["routing"]["rules"].insert(1, {"type": "field", "ip": [IPV6_PAYLOAD_TARGET + "/128"],
                                                "network": "tcp,udp", "outboundTag": "proxy"})
    if caller_api_port is not None:
        assert type(caller_api_port) is int and 1 <= caller_api_port <= 65535, "Invalid fixture API port"
        profile["api"] = {"tag": "caller-api", "listen": f"127.0.0.1:{caller_api_port}",
                          "services": ["StatsService", "HandlerService"]}
        profile["stats"] = {}
        profile["policy"] = {"system": {key: False for key in (
            "statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink")}}
    if asset_fixture is not None:
        profile["dns"]["hosts"][asset_fixture["domain"]] = direct_address
        profile["routing"]["rules"][:0] = [
            {"type": "field", "domain": [f"ext:{asset_fixture['file']}:{asset_fixture['code']}"], "outboundTag": "direct"},
            {"type": "field", "domain": ["full:" + asset_fixture["domain"]], "outboundTag": "fixture-blocked"}]
    return profile


def create_asset_root(directory):
    source = Path(__file__).resolve().parents[2] / "tool/fixtures/compatibility/asset-files.json"
    fixture = json.loads(source.read_text(encoding="utf-8"))
    assert fixture["file"] == "caller-geosite.dat" and fixture["code"] == "CALLER" \
        and fixture["domain"] == "files-fixture.invalid", "Unexpected asset fixture manifest"
    data = base64.b64decode(fixture["base64"], validate=True)
    assert hashlib.sha256(data).hexdigest() == fixture["sha256"], "Asset fixture digest mismatch"
    owner = tempfile.TemporaryDirectory(prefix="caller-assets-", dir=directory)
    try:
        (Path(owner.name) / fixture["file"]).write_bytes(data)
    except BaseException:
        owner.cleanup()
        raise
    return owner, fixture


def check_caller_api(directory, port, wine_bottle=None):
    # Only the fixture's own numeric port and verified bundled runtime are used;
    # never discover a stats-query endpoint from imported configuration JSON.
    assert type(port) is int and 1 <= port <= 65535, "Invalid fixture API port"
    executable = directory / "xray.exe"
    if not executable.is_file():
        executable = directory / "xray" / "xray.exe"
    assert executable.is_file(), "Verified fixture Xray runtime is missing"
    command = (["/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
                "--bottle", wine_bottle] if wine_bottle else [])
    command += [str(executable), "api", "statsquery", f"-server=127.0.0.1:{port}", "-timeout=2"]
    try:
        completed = subprocess.run(command, cwd=directory, capture_output=True,
                                   encoding="utf-8", errors="strict", timeout=3)
    except subprocess.TimeoutExpired:
        raise AssertionError("Caller API stats query exceeded its deadline") from None
    assert completed.returncode == 0, "Caller StatsService query failed"
    assert len(completed.stdout) <= 65536, "Caller StatsService reply exceeded fixture limit"

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate StatsService response field")
            result[key] = value
        return result

    reply = json.loads(completed.stdout, object_pairs_hook=unique_object)
    # Pinned Core omits a nil repeated field; an explicit empty list is valid
    # too. Reject other shapes as well as any counter enabled by adaptation.
    assert type(reply) is dict and (reply == {} or reply == {"stat": []}), "Caller disabled counters were changed or API reply is invalid"


def check_metrics_listener(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/debug/vars", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(262145)
        assert response.status == 200 and len(body) <= 262144, "Caller metrics listener did not serve bounded HTTP JSON"
        assert isinstance(json.loads(body).get("stats"), dict), "Caller metrics response is missing statistics"
    finally:
        connection.close()


def protected_dns(tcp):
    name = f"{uuid.uuid4().hex}.invalid"
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00\x00\x01\x00\x01"
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    before = len(DNS_QUERIES)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        sock.connect(("10.0.85.53", 53))
        assert sock.getsockname()[0] == "10.0.85.2", "DNS did not select the TUN"
        sock.sendall((len(query).to_bytes(2, "big") if tcp else b"") + query)
        response = exact(sock, int.from_bytes(exact(sock, 2), "big")) if tcp else sock.recv(4096)
    assert response[:2] == query[:2] and response[-4:] == b"\xc6\x33\x64\x07"
    assert len(DNS_QUERIES) > before and question.hex() in DNS_QUERIES
    return "DNS reply through selected proxy"


def ipv6_payload_dns(tcp):
    question = b"\x0cipv6-payload\x07invalid\x00\x00\x1c\x00\x01"
    query = b"\x85\x28\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(("10.0.85.53", 53))
        assert sock.getsockname()[0] == "10.0.85.2", "AAAA query did not select the protected DNS adapter"
        sock.sendall((len(query).to_bytes(2, "big") if tcp else b"") + query)
        reply = exact(sock, int.from_bytes(exact(sock, 2), "big")) if tcp else sock.recv(4096)
    assert reply[:2] == query[:2] and reply[2] & 0x80 and reply[3] & 15 == 0 \
        and int.from_bytes(reply[6:8], "big") == 1, "Caller AAAA lookup returned no successful answer"
    assert reply[12:12 + len(question)] == question \
        and reply.endswith(socket.inet_pton(socket.AF_INET6, IPV6_PAYLOAD_TARGET)), "Caller static IPv6 DNS answer changed"
    return "AAAA caller static host through protected " + ("TCP" if tcp else "UDP") + " DNS"


def fakedns_answer(query, response):
    name = query[12:-4]
    assert len(response) >= 12 and response[:2] == query[:2] and response[2] & 0xfa == 0x80 \
        and response[3] & 15 == 0 and response[4:12] == b"\0\1\0\1\0\0\0\0", "FakeDNS A reply header changed"
    assert response[12:len(query)] == query[12:], "FakeDNS A question changed"
    answer = response[len(query):]
    if answer.startswith(b"\xc0\x0c"): answer = answer[2:]
    else:
        assert answer.startswith(name), "FakeDNS answer name changed"
        answer = answer[len(name):]
    assert len(answer) == 14 and answer[:4] == b"\0\1\0\1" and answer[8:10] == b"\0\4", "FakeDNS A record changed"
    packed = answer[10:]
    assert packed[0] == 198 and packed[1] in (18, 19), "FakeDNS answer is outside the default pool"
    return socket.inet_ntoa(packed)


def fakedns_query(tcp):
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in FAKEDNS_NAME.split("."))
    query = b"\x85\x53\x01\0\0\1\0\0\0\0\0\0" + labels + b"\0\0\1\0\1"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(("10.0.85.53", 53))
        assert sock.getsockname()[0] == "10.0.85.2", "FakeDNS query did not select the TUN"
        sock.sendall((len(query).to_bytes(2, "big") if tcp else b"") + query)
        if tcp:
            size = int.from_bytes(exact(sock, 2), "big")
            assert 12 <= size <= 4096, "FakeDNS response length is invalid"
            response = exact(sock, size)
        else: response = sock.recv(4096)
    return fakedns_answer(query, response)


def fakedns_payload_request(state, address, udp):
    packed = socket.inet_aton(address)
    assert packed[0] == 198 and packed[1] in (18, 19), "Payload target is not the returned FakeDNS pool address"
    transport = "udp" if udp else "tcp"
    payload = state.arm(transport)
    expected = b"accepted-" + payload
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(4)
        sock.connect((address, FAKEDNS_PORT))
        assert sock.getsockname()[0] == "10.0.85.2", "FakeDNS payload did not select the TUN"
        sock.sendall(payload)
        reply = sock.recv(256) if udp else exact(sock, len(expected))
        assert reply == expected, "FakeDNS opaque payload reply changed"
    state.require_observed(transport, payload)
    return "Opaque " + transport.upper() + " bytes and recovered SOCKS domain"


def relayed_dns():
    # An uncached question sent straight to the protected resolver verifies
    # that real runner names are not replaced with the synthetic test address.
    name = "api.github.com"
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00\x00\x01\x00\x01"
    query = b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    before = len(DNS_QUERIES)
    with socket.create_connection(("10.0.85.53", 53), timeout=6) as sock:
        assert sock.getsockname()[0] == "10.0.85.2", "Real DNS bypassed the TUN"
        sock.sendall(len(query).to_bytes(2, "big") + query)
        response = exact(sock, int.from_bytes(exact(sock, 2), "big"))
    assert response[:2] == query[:2] and response[3] & 15 == 0
    assert int.from_bytes(response[6:8], "big") > 0 and b"\xc6\x33\x64\x07" not in response
    assert len(DNS_QUERIES) > before and question.hex() in DNS_QUERIES
    return "Real DNS through protected proxy and verified HTTPS relay"


def system_dns():
    name = f"{uuid.uuid4().hex}.invalid."
    before = len(DNS_QUERIES)
    answer = subprocess.check_output([sys.executable, "-c",
        "import socket,sys; print(socket.gethostbyname(sys.argv[1]))", name],
        text=True, timeout=25).strip()
    assert answer == "198.51.100.7" and len(DNS_QUERIES) > before
    return "Windows resolver used the protected DNS proxy"


@lru_cache
def source_interface(source):
    # Discover the actual interface, including localized/renamed adapters.
    return int(native(PROBE, "source-interface", source))


def pin_interface(sock, source, ipv6=False):
    index = source_interface(source)
    # IP_UNICAST_IF expects network byte order; IPV6_UNICAST_IF uses host order.
    sock.setsockopt(socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP, 31,
                    index if ipv6 else struct.pack("!I", index))
    sock.bind((source, 0))


def physical_denied(address, source, port, udp=False, probe=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        pin_interface(sock, source)
        try:
            sock.connect((address, port))
            if udp:
                sock.send(b"private-dns-block-control")
        except OSError as error:
            # Require an explicit Windows access-denied verdict, not a timeout.
            assert getattr(error, "winerror", None) == 10013, f"Unproven block: {error}"
            return "WSAEACCES"
        if udp:
            # A successful UDP send only queues a datagram. Require a kernel
            # block event for this exact flow, caused by our own WFP filter.
            source_port = sock.getsockname()[1]
            owned = {int(value) for value in native(probe, "policy-ids").split()}
            command = f"""
$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=5157; StartTime=(Get-Date).AddMinutes(-1)}} -ErrorAction SilentlyContinue
foreach ($event in $events) {{
  $values = @{{}}
  ([xml]$event.ToXml()).Event.EventData.Data | ForEach-Object {{ $values[$_.Name] = $_.'#text' }}
  if ([long]$values.ProcessID -eq {os.getpid()} -and [int]$values.SourcePort -eq {source_port} -and $values.DestAddress -eq '{address}' -and [int]$values.DestPort -eq {port} -and [int]$values.Protocol -eq 17) {{ $values.FilterRTID }}
}}
"""
            for _ in range(5):
                output = subprocess.check_output(["powershell", "-NoProfile", "-Command", command],
                    text=True, timeout=15)
                matching = {int(value) for value in output.split()}
                if matching & owned:
                    return "Windows event 5157: exact UDP flow blocked by owned WFP filter"
                time.sleep(0.2)
            raise AssertionError("No owned WFP block event for the physical DNS control")
    raise AssertionError("Physical-interface traffic was permitted")


def native(probe, *args):
    completed = subprocess.run([str(probe), *map(str, args)], cwd=probe.parent,
                               capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, f"Native {args[0]} failed: {completed.stdout} {completed.stderr}"
    return completed.stdout.strip()


def await_state(path, running, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = json.loads(path.read_text())
            if state["running"] == running and state["protecting"]:
                return state
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.2)
    raise AssertionError(f"Protected readiness did not become {running}")


def read_traffic_state(path):
    # The probe publishes only numeric counters and readiness. Do not retain
    # unknown fields or include a partially written state in diagnostics.
    try:
        with path.open("rb") as source:
            data = source.read(4097)
        if len(data) > 4096:
            return None
        state = json.loads(data)
        if not isinstance(state, dict):
            return None
        for field in ("running", "protecting", "upload_available", "download_available"):
            if type(state.get(field)) is not bool:
                return None
        for field in ("tick", "upload", "download"):
            value = state.get(field)
            if type(value) is not int or not (0 <= value <= 9223372036854775807):
                return None
        if state["tick"] == 0:
            return None
        return {field: state[field] for field in ("running", "protecting", "tick", "upload", "download",
                                                  "upload_available", "download_available")}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None


def traffic_counter_evidence(path, stage, before, latest, enabled, protecting):
    evidence = dict(stage=stage, enabled=enabled, expected_protecting=protecting, before=before, latest=latest)
    try:
        # Both snapshots have a fixed numeric/boolean schema, bounded above.
        encoded = json.dumps(evidence, separators=(",", ":")).encode("ascii")
        assert len(encoded) <= 4096
        Path(str(path) + ".traffic.evidence.log").write_bytes(encoded)
    except OSError:
        pass


def await_traffic_baseline(path, protecting):
    deadline = time.monotonic() + 5
    latest = None
    while time.monotonic() < deadline:
        latest = read_traffic_state(path)
        if latest is not None and latest["running"] and latest["protecting"] == protecting \
                and latest["upload_available"] and latest["download_available"]:
            return latest
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.1, remaining))
    traffic_counter_evidence(path, "owned_traffic_baseline", None, latest, True, protecting)
    raise AssertionError("Owned traffic counter baseline did not become available")


def await_traffic_counters(path, before, enabled, protecting):
    # Observe a new sample after the existing HTTP payloads, without starting
    # another session or retrying a request. A positive startup health counter
    # cannot satisfy an available direction's required increase.
    if enabled and (before is None or not before["running"] or before["protecting"] != protecting
                    or not before["upload_available"] or not before["download_available"]):
        raise AssertionError("Owned traffic counter baseline is unavailable")
    deadline = time.monotonic() + 5
    latest = None
    while time.monotonic() < deadline:
        latest = read_traffic_state(path)
        if latest is not None and latest["running"] and latest["protecting"] == protecting \
                and latest["tick"] > (before["tick"] if before is not None else 0):
            if enabled:
                valid = all(latest[direction + "_available"] and latest[direction] > before[direction]
                            for direction in ("upload", "download"))
            else:
                valid = all(not latest[direction + "_available"] and latest[direction] == 0
                            for direction in ("upload", "download"))
            if valid:
                return latest
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.1, remaining))
    traffic_counter_evidence(path, "owned_traffic_counters", before, latest, enabled, protecting)
    raise AssertionError("Owned traffic counter sample did not satisfy the payload gate")


def kill_worker(pid, name):
    # Match this probe's child PID and image, never arbitrary user processes.
    command = f"$p = Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {pid} -and $_.Name -eq '{name}' }}; if (!$p) {{ throw 'Owned worker absent' }}; $p | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
    subprocess.run(["powershell", "-NoProfile", "-Command", command], check=True, timeout=15,
                   stdout=subprocess.DEVNULL)


def start_adapter(probe, directory, subnet):
    stop = directory / f"adapter-{subnet}.stop"
    stop.unlink(missing_ok=True)
    log_path = directory / f"adapter-{subnet}.log"
    log = log_path.open("w")
    process = subprocess.Popen([str(probe), "adapter", f"FlutterVlessValidation{subnet}", str(subnet), str(stop)],
                               cwd=directory, stdout=log, stderr=log)
    log.close()
    deadline = time.monotonic() + 60
    while "ADAPTER_READY=" not in log_path.read_text(errors="replace"):
        if process.poll() is not None or time.monotonic() >= deadline:
            stop.touch()
            process.wait(timeout=10)
            raise AssertionError("Synthetic dual-stack adapter did not become ready")
        time.sleep(0.2)
    return process, stop


def adapter_datagram(directory, subnet, ipv6, denied):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = f"fd00:85:{subnet}::1" if ipv6 else f"100.64.{subnet}.1"
    target = f"fd00:85:{subnet}::2" if ipv6 else f"100.64.{subnet}.2"
    token = uuid.uuid4().hex
    verdict = "send accepted"
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        pin_interface(sock, source, ipv6)
        try:
            sock.connect((target, 45000))
            sock.send(("wfp-adapter-control-" + token).encode())
        except OSError as error:
            assert denied and getattr(error, "winerror", None) == 10013, f"Unproven adapter verdict: {error}"
            verdict = "WSAEACCES"
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        observed = token in (directory / f"adapter-{subnet}.log").read_text(errors="replace")
        if observed:
            break
        time.sleep(0.05)
    assert observed != denied, f"Adapter packet evidence disagrees with expected block: observed={observed}, {verdict}"
    if denied:
        # TCP supplies a synchronous WFP verdict as an independent control.
        with socket.socket(family, socket.SOCK_STREAM) as tcp:
            tcp.settimeout(3)
            pin_interface(tcp, source, ipv6)
            try:
                tcp.connect((target, 45000))
            except OSError as error:
                assert getattr(error, "winerror", None) == 10013, f"Unproven TCP block: {error}"
            else:
                raise AssertionError("Adapter TCP bypassed WFP")
    return f"{verdict}; control packet {'absent' if denied else 'observed'} at adapter"


def direct_only_gate(probe, directory, address, dns, origin, results):
    origin.direct_only_observed = []
    origin.direct_only_evidence, origin.direct_only_pending, origin.direct_only_active = {}, {}, None
    origin.direct_only_lock = threading.Lock()  # Publish after every observer field exists.
    for index, shape in enumerate(("freedom-default", "block-default", "selector-round-robin")):
        label = "vpn-direct-only-" + shape
        with origin.direct_only_lock:
            origin.direct_only_active = label
            origin.direct_only_evidence[label] = dict(accepts=0, get_allowed=0, get_blocked=0, get_other=0,
                headers_completed=0, body_bytes=0, errors=0, last_error_class=None)
        profile, stop, state, guard_stop = [directory / (label + suffix) for suffix in (".json", ".stop", ".state.json", ".guard-stop")]
        for stale in (stop, state, guard_stop):
            stale.unlink(missing_ok=True)
        profile.write_text(json.dumps(direct_only_config(index, address, dns.server_address[1])))
        log_path = directory / (label + ".log")
        with log_path.open("w") as log:
            process = subprocess.Popen([str(probe), "run-vpn", str(profile), "120", str(stop), str(state)],
                                       cwd=directory, stdout=log, stderr=log)
            guard = None
            stage, requests = "startup", []
            def observed_request(host):
                detail = {"stage": stage}
                try:
                    return request(host, True, diagnostic=detail)
                finally:
                    requests.append(detail)
            try:
                guard = subprocess.Popen([str(probe), "guard", str(process.pid), "120", str(guard_stop)],
                                         cwd=directory, stdout=log, stderr=log)
                deadline = time.monotonic() + 65
                while "START_RETURN=1" not in log_path.read_text(errors="replace"):
                    assert process.poll() is None and time.monotonic() < deadline, "Direct-only VPN did not become ready"
                    time.sleep(0.1)
                stage = "positive_before"
                assert observed_request("direct-only.invalid") == "DIRECT-FIXTURE", "Direct-only HTTP bytes failed"
                stage = "blocked"
                try:
                    observed_request("blocked.invalid")
                except (OSError, EOFError, RuntimeError):
                    pass
                else:
                    raise AssertionError("Direct-only caller domain block was bypassed")
                stage = "positive_after"
                assert observed_request("direct-only.invalid") == "DIRECT-FIXTURE", "Direct-only HTTP did not survive the blocked request"
                with origin.direct_only_lock:
                    assert origin.direct_only_observed.count("direct-only.invalid") == 2 * (index + 1) \
                        and "blocked.invalid" not in origin.direct_only_observed, "Caller domain block reached the controlled origin"
                stage = "dns"
                for tcp in (False, True):
                    direct_only_dns(dns, tcp)
                results.append(dict(mode=label, check="no-proxy HTTP, caller domain block and numeric TCP root DNS via virtual TCP/UDP", passed=True))
                stage = "stop_cleanup"
                stop.touch()
                assert process.wait(timeout=25) == 0, "Direct-only VPN Stop failed"
                assert native(probe, "policy-count") == "0", "Direct-only Stop retained WFP filters"
                inventory = json.loads(subprocess.check_output(["powershell", "-NoProfile", "-Command",
                    "[pscustomobject]@{Routes=@(Get-NetRoute -InterfaceAlias flutter_vless_tun -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') }).Count; "
                    "IPv6Addresses=@(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'flutter_vless_tun' -and $_.IPAddress -eq 'fd00:198:18::2' }).Count} | ConvertTo-Json -Compress"], text=True, timeout=25))
                assert inventory == {"Routes": 0, "IPv6Addresses": 0}, "Direct-only Stop retained tunnel routes/address"
                results.append(dict(mode=label, check="explicit Stop removes owned WFP, capture routes and IPv6 address", passed=True))
            except BaseException as error:
                try:
                    evidence = direct_failure_evidence(label, stage, process, state, origin, requests)
                    save_direct_evidence(directory / (label + ".evidence.log"), evidence, error)
                except BaseException:
                    if hasattr(error, "add_note"):
                        error.add_note("DIRECT_ONLY_EVIDENCE capture failed")
                raise
            finally:
                try:
                    if process.poll() is None:
                        stop.touch()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait(timeout=5)
                    native(probe, "release-protection")
                finally:
                    guard_stop.touch()
                    if guard is not None:
                        try:
                            guard.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            guard.kill(); guard.wait(timeout=5)
        time.sleep(2)


def native_routing_config(address, dns_port):
    return {
        "inbounds": [{"tag": "caller-source", "protocol": "socks", "listen": "127.0.0.1", "port": PORTS["inbound"],
                      "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "first-blocked", "protocol": "blackhole"},
                      {"tag": "source-route", "protocol": "freedom", "settings": {"redirect": f"{address}:{PORTS['direct']}"}},
                      {"tag": "selected-default", "protocol": "socks", "settings": {"servers": [{"address": address, "port": PORTS["routing_proxy"]}]}},
                      {"tag": "dns-direct", "protocol": "freedom"}],
        "dns": {"tag": "caller-dns", "disableCache": True, "servers": [f"tcp://{address}:{dns_port}"]},
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["caller-dns"], "ip": [address + "/32"], "port": str(dns_port), "network": "tcp", "outboundTag": "dns-direct"},
            {"type": "field", "inboundTag": ["caller-source"], "domain": ["full:alias.invalid"], "outboundTag": "source-route"}]}}


def native_routing_proxy(address):
    server = Server((address, 0), Socks)
    server.daemon_threads = False  # server_close joins each bounded HTTP callback.
    PORTS["routing_proxy"] = server.server_address[1]
    return server


def fakedns_config(address, proxy_port, dns_port):
    return {"inbounds": [{"tag": "caller-fake-input", "protocol": "socks", "listen": "127.0.0.1", "port": PORTS["inbound"],
                          "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "routeOnly": False, "destOverride": ["tls"]}}],
            "outbounds": [{"tag": "caller-block", "protocol": "blackhole"},
                          {"tag": "fake-proxy", "protocol": "socks", "settings": {"servers": [{"address": address, "port": proxy_port}]}},
                          {"tag": "caller-direct", "protocol": "freedom"}],
            "dns": {"tag": "caller-fake-dns", "queryStrategy": "UseIPv4", "disableCache": True,
                    "servers": [{"address": "fakedns", "domains": ["full:" + FAKEDNS_NAME], "skipFallback": True}, f"tcp://{address}:{dns_port}"]},
            "routing": {"domainStrategy": "AsIs", "rules": [
                {"type": "field", "domain": ["full:" + FAKEDNS_NAME], "outboundTag": "fake-proxy"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "caller-direct"}]}}


def fakedns_gate(probe, directory, address, proxy_port, dns_port, payload_state, results):
    # One implicit default-pool profile, with a fresh engine on each restart.
    for cycle in range(2):
        label = "vpn-fakedns-" + str(cycle)
        profile, stop, state, guard_stop = [directory / (label + suffix) for suffix in (".json", ".stop", ".state.json", ".guard-stop")]
        for stale in (stop, state, guard_stop): stale.unlink(missing_ok=True)
        source = json.dumps(fakedns_config(address, proxy_port, dns_port)).encode("utf-8")
        profile.write_bytes(source)
        log_path = directory / (label + ".log")
        with log_path.open("w") as log:
            process = subprocess.Popen([str(probe), "run-vpn", str(profile), "120", str(stop), str(state)], cwd=directory, stdout=log, stderr=log)
            guard, primary = None, None
            try:
                guard = subprocess.Popen([str(probe), "guard", str(process.pid), "120", str(guard_stop)], cwd=directory, stdout=log, stderr=log)
                deadline = time.monotonic() + 65
                while "START_RETURN=1" not in log_path.read_text(errors="replace"):
                    assert process.poll() is None and time.monotonic() < deadline, "FakeDNS VPN did not become ready"
                    time.sleep(0.1)
                udp_ip, tcp_ip = fakedns_query(False), fakedns_query(True)
                assert udp_ip == tcp_ip, "FakeDNS TCP/UDP did not share the same engine mapping"
                results.append(dict(mode=label, check="FakeDNS A TCP/UDP use default pool", passed=True))
                for udp in (False, True):
                    actual = fakedns_payload_request(payload_state, udp_ip, udp)
                    results.append(dict(mode=label, check="FakeDNS opaque UDP restored domain" if udp else "FakeDNS opaque TCP restored domain", actual=actual, passed=True))
                assert await_state(state, True, timeout=5)["protecting"], "FakeDNS displaced the readiness probe or protection"
                assert profile.read_bytes() == source, "FakeDNS runtime changed the caller profile"
                stop.touch()
                assert process.wait(timeout=25) == 0, "FakeDNS Stop failed"
                payload_state.require_drained()
                assert native(probe, "policy-count") == "0", "FakeDNS Stop retained WFP filters"
                inventory = json.loads(subprocess.check_output(["powershell", "-NoProfile", "-Command",
                    "[pscustomobject]@{Routes=@(Get-NetRoute -InterfaceAlias flutter_vless_tun -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') }).Count; "
                    "IPv6Addresses=@(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'flutter_vless_tun' -and $_.IPAddress -eq 'fd00:198:18::2' }).Count} | ConvertTo-Json -Compress"], text=True, timeout=25))
                assert inventory == {"Routes": 0, "IPv6Addresses": 0}, "FakeDNS Stop retained tunnel routes/address"
                results.append(dict(mode=label, check="FakeDNS restart Stop removes protection and owned routes", passed=True))
            except BaseException as error:
                primary = error
                raise
            finally:
                cleanup_error = None
                def cleanup(operation):
                    nonlocal cleanup_error
                    try: operation()
                    except BaseException as error:
                        if cleanup_error is None: cleanup_error = error
                def stop_process():
                    if process.poll() is None:
                        stop.touch()
                        try: process.wait(timeout=15)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                def stop_guard():
                    guard_stop.touch()
                    if guard is not None:
                        try: guard.wait(timeout=10)
                        except subprocess.TimeoutExpired: guard.kill(); guard.wait(timeout=5)
                cleanup(stop_process)
                cleanup(lambda: native(probe, "release-protection"))
                cleanup(stop_guard)
                if cleanup_error is not None:
                    if primary is None: raise cleanup_error
                    if hasattr(primary, "add_note"): primary.add_note("FAKEDNS_CLEANUP_FAILED")
        time.sleep(2)
    return 2


@contextmanager
def occupied_private_ports():
    # Only the separate optional-routing scenario holds these owned listeners.
    # The real VPN admission must choose different private SOCKS/API ports.
    with ExitStack() as owned:
        for port in (10807, 10086):
            listener = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
        yield


def native_routing_gate(probe, directory, address, dns, origin, results):
    # This is a separate opt-in profile. The preceding ordinary-input isolation
    # assertions remain untouched and do not run with an aliased adapter.
    with origin.direct_only_lock:
        origin.direct_only_active = None
    for cycle in range(2):
        label = "vpn-native-routing-" + str(cycle)
        profile, stop, state, guard_stop = [directory / (label + suffix) for suffix in (".json", ".stop", ".state.json", ".guard-stop")]
        for stale in (stop, state, guard_stop, Path(str(state) + ".reject-routing")):
            stale.unlink(missing_ok=True)
        profile.write_text(json.dumps(native_routing_config(address, dns.server_address[1])))
        log_path = directory / (label + ".log")
        with log_path.open("w") as log:
            process = subprocess.Popen([str(probe), "run-vpn-routing", str(profile), "240", str(stop), str(state)],
                                       cwd=directory, stdout=log, stderr=log)
            guard = None
            primary = None
            try:
                guard = subprocess.Popen([str(probe), "guard", str(process.pid), "240", str(guard_stop)], cwd=directory, stdout=log, stderr=log)
                deadline = time.monotonic() + 65
                while "START_RETURN=1" not in log_path.read_text(errors="replace"):
                    assert process.poll() is None and time.monotonic() < deadline, "Native routing VPN did not become ready"
                    time.sleep(0.1)
                def payloads():
                    assert request("alias.invalid", True) == "DIRECT-FIXTURE", "Source-inbound alias did not match its caller rule"
                    assert request("fallback.invalid", True) == "PROXY-FIXTURE", "Explicit non-first default did not receive unmatched traffic"
                traffic_before = await_traffic_baseline(state, True)
                payloads()
                results.append(dict(mode=label, check="native source alias and explicit non-first fallback", passed=True))
                counters = await_traffic_counters(state, traffic_before, True, True)
                results.append(dict(mode=label, check="owned traffic counter sample", actual=counters, passed=True))
                for tcp in (False, True):
                    direct_only_dns(dns, tcp)
                results.append(dict(mode=label, check="private DNS and readiness probe survive source alias", passed=True))
                if cycle == 0:
                    Path(str(state) + ".reject-routing").touch()
                    deadline = time.monotonic() + 25
                    while "REJECTED_ROUTING_PRESERVED=1" not in log_path.read_text(errors="replace"):
                        assert process.poll() is None and time.monotonic() < deadline, "Invalid routing selection replaced live workers"
                        time.sleep(0.1)
                    payloads()
                    results.append(dict(mode=label, check="invalid routing candidate preserves both caller paths", passed=True))
                    kill_worker(process.pid, "xray.exe")
                    await_state(state, False); await_state(state, True, timeout=60)
                    payloads()
                    direct_only_dns(dns, True)
                    results.append(dict(mode=label, check="native routing selection and private guards survive worker recovery", passed=True))
                stop.touch()
                assert process.wait(timeout=25) == 0, "Native routing Stop failed"
                assert native(probe, "policy-count") == "0", "Native routing Stop retained WFP filters"
                inventory = json.loads(subprocess.check_output(["powershell", "-NoProfile", "-Command",
                    "[pscustomobject]@{Routes=@(Get-NetRoute -InterfaceAlias flutter_vless_tun -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') }).Count; "
                    "IPv6Addresses=@(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'flutter_vless_tun' -and $_.IPAddress -eq 'fd00:198:18::2' }).Count} | ConvertTo-Json -Compress"], text=True, timeout=25))
                assert inventory == {"Routes": 0, "IPv6Addresses": 0}, "Native routing Stop retained routes/address"
                results.append(dict(mode=label, check="native routing Stop removes WFP routes and owned address", passed=True))
            except BaseException as error:
                primary = error
                raise
            finally:
                cleanup_error = None
                def cleanup(operation):
                    nonlocal cleanup_error
                    try: operation()
                    except BaseException as error:
                        if cleanup_error is None: cleanup_error = error
                def stop_process():
                    if process.poll() is None:
                        stop.touch()
                        try: process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait(timeout=5)
                def stop_guard():
                    guard_stop.touch()
                    if guard is not None:
                        try: guard.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            guard.kill(); guard.wait(timeout=5)
                cleanup(stop_process)
                cleanup(lambda: native(probe, "release-protection"))
                cleanup(stop_guard)
                if cleanup_error is not None:
                    if primary is None: raise cleanup_error
                    if hasattr(primary, "add_note"): primary.add_note("NATIVE_ROUTING_CLEANUP_FAILED")
        time.sleep(2)
    print("WINDOWS_NATIVE_ROUTING_TRAFFIC_PASS=2", flush=True)




def numeric_ipv6_packets(text):
    rows=[]
    for line in text.splitlines():
        if line.startswith("IPV6_SCOPE_PACKET="):
            fields=line.partition("=")[2].split(",")
            assert len(fields)==5
            row=tuple(map(int,fields))
            assert row[0] in (6,17) and row[1] in (2,3) and row[2] in (18443,18444) and 1<=row[3]<=65535 and 0<=row[4]<=255
            rows.append(row)
    return rows


def numeric_ipv6_observation(rows,spec,source_port,sender,begin):
    label,remote,port,protocol=spec
    matching=[row for row in rows[begin:] if row[:4]==(protocol,int(remote.rsplit(":",1)[1]),port,source_port)]
    return dict(case=label,remote=remote,port=port,protocol=protocol,sourcePort=source_port,senderPID=sender,
                syn_packets=sum(bool(row[4]&2) for row in matching) if protocol==6 else 0,
                udp_packets=len(matching) if protocol==17 else 0)


def numeric_ipv6_refusal(event, spec, core_pid, owned, after_record):
    # Exact current-attempt event, not a recent unrelated Security record.
    _, remote, port, protocol = spec
    return (type(event) is dict and event.get("ProcessID") == core_pid
            and event.get("remote") == remote and event.get("port") == port and event.get("protocol") == protocol
            and type(event.get("RecordId")) is int and event["RecordId"] > after_record
            and type(event.get("SourcePort")) is int and 0 < event["SourcePort"] <= 65535
            and event.get("FilterRTID") in owned)


def numeric_ipv6_core_identity(rows, parent):
    # Native Launch quotes every token. Select the ordinary run worker, never
    # its same-image API/preflight children. Commands/config paths stay private.
    assert type(rows) is list and len(rows) <= 64 and type(parent) is int and parent > 0, "Core run worker identity invalid"
    selected = []
    for row in rows:
        if type(row) is not dict or type(row.get("ParentProcessId")) is not int or row["ParentProcessId"] != parent:
            continue
        pid, image, command = row.get("ProcessId"), row.get("ExecutablePath"), row.get("CommandLine")
        if type(pid) is not int or pid <= 0 or type(image) is not str or not image or type(command) is not str or len(command) > 32768:
            continue
        match = re.fullmatch(r'"([^"\x00-\x1f]+)" "run" "-config" "([^"\x00-\x1f]+)"', command)
        if match and ntpath.normcase(ntpath.normpath(match[1])) == ntpath.normcase(ntpath.normpath(image)):
            selected.append(dict(ProcessId=pid, ExecutablePath=image))
    assert len(selected) == 1, "Core run worker identity missing or ambiguous"
    return selected[0]


def numeric_ipv6_security_records(data, refusals=False):
    # wevtutil /uni:true emits XML bytes, without provider message rendering.
    assert type(data) is bytes and 0 < len(data) <= 2 * 1024 * 1024, "Security XML size invalid"
    assert b"<!DOCTYPE" not in data.replace(b"\0", b"").upper(), "Security XML DTD refused"
    root = ElementTree.fromstring(data)
    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    assert root.tag == "Events" and len(root) <= 256, "Security XML envelope invalid"
    rows, seen = [], set()

    def number(text, hexadecimal=False):
        pattern = r"(?:[0-9]+|0x[0-9a-fA-F]+)" if hexadecimal else r"[0-9]+"
        assert type(text) is str and re.fullmatch(pattern, text), "Security XML number invalid"
        value = int(text, 16 if text.startswith("0x") else 10)
        assert 0 <= value < 2 ** 64, "Security XML number outside range"
        return value

    for event in root:
        assert event.tag == namespace + "Event", "Security XML event invalid"
        systems = event.findall(namespace + "System")
        assert len(systems) == 1, "Security XML system invalid"
        records = systems[0].findall(namespace + "EventRecordID")
        assert len(records) == 1, "Security XML record missing or duplicated"
        record = number(records[0].text)
        assert record > 0 and record not in seen, "Security XML record invalid"
        seen.add(record)
        row = dict(RecordId=record)
        if refusals:
            kinds = systems[0].findall(namespace + "EventID")
            assert len(kinds) == 1 and number(kinds[0].text) == 5157, "Security XML kind invalid"
            containers = event.findall(namespace + "EventData")
            assert len(containers) == 1, "Security XML data invalid"
            values = {}
            for item in containers[0]:
                name = item.get("Name")
                assert item.tag == namespace + "Data" and name and name not in values, "Security XML fields invalid"
                values[name] = item.text
            required = {"ProcessID", "SourcePort", "FilterRTID", "DestAddress", "DestPort", "Protocol"}
            assert required <= values.keys(), "Security XML fields missing"
            assert values["DestAddress"], "Security XML destination missing"
            row.update(ProcessID=number(values["ProcessID"], True), SourcePort=number(values["SourcePort"]),
                       FilterRTID=number(values["FilterRTID"], True), remote=values["DestAddress"],
                       port=number(values["DestPort"]), protocol=number(values["Protocol"]))
        rows.append(row)
    if not refusals:
        assert len(rows) == 1, "Security baseline missing or ambiguous"
    return rows


def numeric_ipv6_security_events(timeout, after_record=None):
    # Finite reverse XML query; no PowerShell/Get-WinEvent provider startup.
    command = [str(Path(os.environ["SystemRoot"]) / "System32" / "wevtutil.exe"), "qe", "Security",
               "/rd:true", "/f:xml", "/e:Events", "/uni:true"]
    if after_record is None:
        command.append("/c:1")
    else:
        assert type(after_record) is int and 0 < after_record < 2 ** 64
        command += ["/c:256", f"/q:*[System[EventID=5157 and EventRecordID>{after_record}]]"]
    # Spill bounded-count native output to an owned temporary file, then cap
    # the bytes admitted to the XML parser. subprocess.run reaps on timeout.
    with tempfile.TemporaryFile() as output:
        subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL, check=True, timeout=timeout)
        if after_record is not None and output.tell() == 0:
            return []  # No event is never evidence; the caller keeps waiting.
        assert 0 < output.tell() <= 2 * 1024 * 1024, "Security XML size invalid"
        output.seek(0)
        return numeric_ipv6_security_records(output.read(2 * 1024 * 1024 + 1), after_record is not None)


def numeric_ipv6_gate(probe, directory, results, variant="routing"):
    # Existing cases have already closed their adapters in main's finally.
    # This fresh adapter epoch has one codec/nonce, no retry and no public peer.
    assert os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true"
    nonce = uuid.uuid4().hex
    case = directory / ("numeric-ipv6-" + nonce)
    case.mkdir(exist_ok=False)
    source_interface.cache_clear()  # old owned adapter2 is closed; never reuse its index
    build_path = directory / "numeric-ipv6-build-results.json"
    from verify_numeric_ipv6_qualification import load_json, source_vector
    build = load_json(build_path)
    repository = Path(__file__).resolve().parents[2]
    assert build["version"] == 1 and build["head"] == os.environ["GITHUB_SHA"] and build["run_id"] == os.environ["GITHUB_RUN_ID"]
    assert hashlib.sha256(probe.read_bytes()).hexdigest() == build["runtime_probe_sha256"]
    assert build["source_sha256"] == source_vector(repository)
    assert variant in ("official", "routing")
    assert hashlib.sha256((directory / "xray.exe").read_bytes()).hexdigest() == build["core_binaries_sha256"][variant]
    proof = dict(version=1, binary_variant=variant, run_id=build["run_id"], head=build["head"], source_sha256=build["source_sha256"],
                 build_receipt_sha256=hashlib.sha256(build_path.read_bytes()).hexdigest(), nonce=nonce, peer_nonce="",
                 scope={}, positive=dict(controlled_packets=dict(baseline=[], protected=[])), denied=[],
                 cleanup=dict(service_exit0=False, policy_filters=-1, capture_routes=-1, owned_adapter_absent=False,
                              owned_helpers_remaining=-1), passed=False, skipped=False)
    specs = [("wrong_address", "fd00:85:2::3", 18443, 6), ("wrong_port", "fd00:85:2::2", 18444, 6),
             ("udp", "fd00:85:2::2", 18443, 17), ("wrong_image", "fd00:85:2::2", 18443, 6)]
    peer_stop, arm = case / "peer.stop", case / "peer.arm"
    stop, state, guard_stop = case / "service.stop", case / "service.state.json", case / "guard.stop"
    peer_log, service_log = case / "peer.log", case / "service.log"
    peer, service, guard = None, None, None
    alias = "FlutterVlessNumericIPv6-" + nonce[:8]
    luid = None
    deadline = time.monotonic() + 60
    cleanup_errors = []

    def limit(seconds=15):
        remaining = deadline - time.monotonic()
        assert remaining > 0, "Numeric IPv6 work cutoff reached"
        return min(seconds, remaining)

    def native_call(*args):
        result = subprocess.run([str(probe), *map(str, args)], cwd=directory, capture_output=True, text=True, timeout=limit(3))
        assert result.returncode == 0, "Numeric IPv6 native metadata command failed"
        return result.stdout.strip()

    def ps(script):
        return subprocess.check_output(["powershell", "-NoProfile", "-Command", "$ErrorActionPreference='Stop'; " + script],
                                       text=True, timeout=limit(10))

    def packets():
        return numeric_ipv6_packets(peer_log.read_text(errors="replace"))

    def observation(spec,source_port,sender,begin):
        return numeric_ipv6_observation(packets(),spec,source_port,sender,begin)

    def baseline(spec):
        _, remote, port, protocol = spec
        begin = len(packets())
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM if protocol == 17 else socket.SOCK_STREAM) as sender:
            sender.settimeout(limit(0.5)); pin_interface(sender, "fd00:85:2::1", True)
            source_port = sender.getsockname()[1]
            if protocol == 17:
                sender.sendto(("numeric-scope-udp-" + nonce).encode("ascii"), (remote, port))
            else:
                try: sender.connect((remote, port))
                except (TimeoutError, ConnectionRefusedError): pass
        observe_until = time.monotonic() + limit(2)
        while True:
            row = observation(spec, source_port, os.getpid(), begin)
            if row["syn_packets"] + row["udp_packets"] > 0: return row
            assert time.monotonic() < observe_until and peer.poll() is None, "Controlled pre-policy sender/observer failed"
            time.sleep(0.02)

    def security_record_id():
        return numeric_ipv6_security_events(limit(3))[0]["RecordId"]

    def core_block(spec, core_pid, begin, after_record):
        label, remote, port, protocol = spec
        owned = set(proof["scope"]["owned_filter_ids"])
        scan_until = time.monotonic() + limit(5)
        while True:
            assert peer.poll() is None and service.poll() is None, "Owned sender/observer exited before deny proof"
            for event in numeric_ipv6_security_events(limit(3), after_record):
                if numeric_ipv6_refusal(event, spec, core_pid, owned, after_record):
                    row = observation(spec, event["SourcePort"], core_pid, begin)
                    assert row["syn_packets"] + row["udp_packets"] == 0, "Denied tuple reached the raw observer"
                    return row, dict(kind="owned_filter_event_5157", ProcessID=event["ProcessID"], SourcePort=event["SourcePort"],
                                     FilterRTID=event["FilterRTID"], RecordId=event["RecordId"], AfterRecordId=after_record)
            assert time.monotonic() < scan_until, "No exact same-Core owned-filter refusal"
            time.sleep(0.1)

    try:
        with peer_log.open("x") as log:
            peer = subprocess.Popen([str(probe), "adapter-v6-peer", alias, "2", str(peer_stop), nonce, str(arm)],
                                    cwd=directory, stdout=log, stderr=log)
        while "ADAPTER_READY=" not in peer_log.read_text(errors="replace"):
            assert peer.poll() is None and time.monotonic() < deadline, "Owned non-loopback adapter setup failed"
            time.sleep(0.1)
        text = peer_log.read_text()
        luid = int(next(line.partition("=")[2] for line in text.splitlines() if line.startswith("ADAPTER_READY=")))
        assert "IPV6_PEER_OWNERSHIP=source-owned,remote-unassigned,default-owned" in text
        assert int(native_call("underlay-v6")) == luid
        proof["positive"]["controlled_packets"]["baseline"] = [baseline(spec) for spec in specs]
        # CREATE_NEW and exact nonce arm only the designated protected exchange.
        with arm.open("x") as marker: marker.write(nonce)
        profile = dict(inbounds=[], outbounds=[
            dict(tag="proxy", protocol="socks", settings=dict(servers=[dict(address="fd00:85:2::2", port=18443,
                 users=[dict(user="scope-user", **{"pass": "scope-password"})])]), streamSettings=dict(network="tcp")),
            dict(tag="fixture-block", protocol="blackhole")],
            routing=dict(rules=[dict(type="field", ip=["198.18.0.77/32"], port="18080", network="tcp", outboundTag="proxy")]),
            dns=dict(servers=["1.1.1.1"], queryStrategy="UseIPv4"))
        for spec, logical in zip(specs[:3], (78, 79, 80)):
            label, remote, port, protocol = spec
            profile["outbounds"].append(dict(tag=label, protocol="freedom", settings=dict(redirect=f"[{remote}]:{port}")))
            profile["routing"]["rules"].append(dict(type="field", ip=[f"198.18.0.{logical}/32"], network="udp" if protocol == 17 else "tcp", outboundTag=label))
        # Only the designated application may consume the one-stream peer.
        # Keep captured guest background/DNS traffic out of this synthetic peer.
        profile["routing"]["rules"].append(dict(type="field", network="tcp,udp", outboundTag="fixture-block"))
        path = case / "source.json"; path.write_text(json.dumps(profile))
        deadline = time.monotonic() + 80  # manual Stop wrapper target, not OFF guarantee
        with service_log.open("x") as log:
            service = subprocess.Popen([str(probe), "run-vpn-no-reconnect", str(path), "90", str(stop), str(state)],
                                       cwd=directory, stdout=log, stderr=log)
            guard = subprocess.Popen([str(probe), "guard", str(service.pid), "90", str(guard_stop)],
                                     cwd=directory, stdout=log, stderr=log)
        ready_until = time.monotonic() + limit(45)
        while "START_RETURN=1" not in service_log.read_text(errors="replace"):
            assert service.poll() is None and time.monotonic() < ready_until, "Numeric IPv6 service did not become ready"
            time.sleep(0.1)
        core = numeric_ipv6_core_identity(json.loads(ps(f"ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {service.pid} -and $_.Name -eq 'xray.exe' }} | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine) -Compress")), service.pid)
        core_pid = int(core["ProcessId"])
        core_hash = hashlib.sha256(Path(core["ExecutablePath"]).read_bytes()).hexdigest()
        assert core_hash == hashlib.sha256((directory / "xray.exe").read_bytes()).hexdigest()
        owned_ids = sorted({int(value) for value in native_call("policy-ids").split()})
        assert owned_ids
        proof["scope"] = dict(remote="fd00:85:2::2", port=18443, protocol=6, LUID=luid, CorePID=core_pid, ServicePID=service.pid, CoreParentPID=service.pid,
                              Core_image=core["ExecutablePath"], Core_image_sha256=core_hash,
                              controllerPID=os.getpid(), owned_filter_ids=owned_ids)
        request = ("numeric-ipv6-" + nonce + "\n").encode("ascii")
        response = b"accepted-" + request
        with socket.create_connection(("198.18.0.77", 18080), timeout=limit(4)) as application:
            assert application.getsockname()[0] == "10.0.85.2", "Challenge bypassed VPN capture"
            # Start the real stream before observing its downstream connection.
            # Withhold the nonce until the owned TCP tuple has been sampled.
            prefix_bytes = len(b"numeric-ipv6-")
            application.settimeout(limit(3))
            application.sendall(request[:prefix_bytes])
            established_until = time.monotonic() + limit(3)
            while "IPV6_TCP_PEER_READY=" not in peer_log.read_text():
                assert peer.poll() is None and time.monotonic() < established_until, "Owned SOCKS handshake did not complete"
                time.sleep(0.02)
            owner = json.loads(ps(f"$c=@(Get-NetTCPConnection -OwningProcess {core_pid} -RemoteAddress 'fd00:85:2::2' -RemotePort 18443 -State Established); if($c.Count -ne 1){{throw 'Core TCP tuple ambiguous'}}; $c | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress"))
            proof["positive"]["tcp_owner"] = dict(PID=int(owner["OwningProcess"]), local_address=owner["LocalAddress"],
                local_port=int(owner["LocalPort"]), remote_address=owner["RemoteAddress"], remote_port=int(owner["RemotePort"]))
            application.settimeout(limit(3)); application.sendall(request[prefix_bytes:])
            assert exact(application, len(response)) == response and application.recv(1) == b"", "Owned nonce response/FIN failed"
            proof["positive"]["source"] = application.getsockname()[0]
            proof["positive"]["response_exact"] = True
        complete_until = time.monotonic() + limit(3)
        while "IPV6_TCP_PEER_COMPLETE=" not in peer_log.read_text():
            assert peer.poll() is None and time.monotonic() < complete_until, "Peer final ACK/FIN did not drain"
            time.sleep(0.02)
        final = next(line.partition("=")[2] for line in peer_log.read_text().splitlines() if line.startswith("IPV6_TCP_PEER_COMPLETE="))
        fields = final.split(","); assert len(fields) == 7
        proof["peer_nonce"] = fields[0]
        proof["positive"]["peer"] = dict(syn_count=int(fields[1]), authentication_count=int(fields[2]), connect_count=int(fields[3]),
            challenge_count=int(fields[4]), client_port=int(fields[5]), error=int(fields[6]), complete=True)
        assert proof["peer_nonce"] == nonce and all(int(v) == 1 for v in fields[1:5]) and fields[6] == "0"
        assert int(fields[5]) == proof["positive"]["tcp_owner"]["local_port"]
        for spec, logical in zip(specs[:3], (78, 79, 80)):
            begin = len(packets())
            after_record = security_record_id()  # captured BEFORE this one sender attempt
            if spec[3] == 17:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.sendto(("denied-" + nonce).encode(), (f"198.18.0.{logical}", 18080))
            else:
                try:
                    with socket.create_connection((f"198.18.0.{logical}", 18080), timeout=limit(2)) as sender:
                        sender.settimeout(limit(2)); sender.sendall(("denied-" + nonce).encode()); sender.recv(1)
                except (TimeoutError, ConnectionError): pass
            row, kernel = core_block(spec, core_pid, begin, after_record)
            proof["positive"]["controlled_packets"]["protected"].append(row)
            proof["denied"].append(dict(case=spec[0], SenderPID=core_pid, CorePID=core_pid, sender_attempted=True,
                protocol=spec[3], remote=spec[1], port=spec[2], observer_baseline_positive=True, matching_packets_after=0, kernel=kernel))
        spec = specs[3]; begin = len(packets())
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sender:
            pin_interface(sender, "fd00:85:2::1", True); sender.settimeout(limit(2)); source_port = sender.getsockname()[1]
            try: sender.connect((spec[1], spec[2]))
            except OSError as error: assert getattr(error, "winerror", None) == 10013, "Wrong-image block lacks WSAEACCES"
            else: raise AssertionError("Wrong-image matched allowed Core tuple")
        row = observation(spec, source_port, os.getpid(), begin)
        assert row["syn_packets"] == 0 and peer.poll() is None
        proof["positive"]["controlled_packets"]["protected"].append(row)
        proof["denied"].append(dict(case=spec[0], SenderPID=os.getpid(), CorePID=None, sender_attempted=True,
            protocol=6, remote=spec[1], port=spec[2], observer_baseline_positive=True, matching_packets_after=0,
            kernel=dict(kind="WSAEACCES", ProcessID=os.getpid(), SourcePort=source_port, FilterRTID=None, RecordId=None, AfterRecordId=None)))
        proof["passed"] = True
    finally:
        primary = sys.exc_info()[1]
        if service is not None:
            stop.touch()  # always request actual service Stop before any guard disposal
            try:
                code = service.wait(timeout=15)
                proof["cleanup"]["service_exit0"] = code == 0
            except subprocess.TimeoutExpired:
                cleanup_errors.append("service_stop_timeout")
                try: service.kill(); service.wait(timeout=5)
                except BaseException: cleanup_errors.append("service_reap")
            except BaseException: cleanup_errors.append("service_stop")
            try:
                count = int(subprocess.check_output(["powershell", "-NoProfile", "-Command",
                    f"@(Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {service.pid} -and $_.Name -in @('xray.exe','tun2socks.exe') }}).Count"], text=True, timeout=10).strip())
                assert count == 0, "Owned workers survived Stop"
                native(probe, "release-protection")
                proof["cleanup"]["policy_filters"] = int(native(probe, "policy-count"))
            except BaseException: cleanup_errors.append("service_or_policy_cleanup")
        if guard is not None and proof["cleanup"]["service_exit0"] and proof["cleanup"]["policy_filters"] == 0:
            guard_stop.touch()
            try: guard.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cleanup_errors.append("guard_reap")
                try: guard.kill(); guard.wait(timeout=5)
                except BaseException: cleanup_errors.append("guard_reap_failed")
            except BaseException: cleanup_errors.append("guard_wait")
        elif guard is not None:
            # Manual Stop unqualified: retain independent guard until its own
            # deadline, never cancel it just because the owner was terminated.
            try: guard.wait(timeout=100)
            except subprocess.TimeoutExpired:
                cleanup_errors.append("guard_deadline")
                try: guard.kill(); guard.wait(timeout=5)
                except BaseException: cleanup_errors.append("guard_reap_failed")
            except BaseException: cleanup_errors.append("guard_wait")
        if peer is not None:
            peer_stop.touch()
            try:
                peer_code = peer.wait(timeout=10)
                if peer_code != 0: cleanup_errors.append("peer_exit")
            except subprocess.TimeoutExpired:
                cleanup_errors.append("peer_reap")
                try: peer.kill(); peer.wait(timeout=5)
                except BaseException: cleanup_errors.append("peer_reap_failed")
            except BaseException: cleanup_errors.append("peer_wait")
        if peer is not None:
            try:
                # The exact LUID was published immediately after owned creation,
                # even if readiness failed. No broad route/adapter cleanup.
                if luid is None:
                    created = [int(line.partition("=")[2]) for line in peer_log.read_text().splitlines()
                               if line.startswith("PEER_ADAPTER_CREATED=")]
                    assert len(created) <= 1
                    if created: luid = created[0]
                if luid is not None: native(probe, "cleanup-peer-default", luid, alias)
            except BaseException: cleanup_errors.append("peer_default_cleanup")
        try:
            remaining = json.loads(subprocess.check_output(["powershell", "-NoProfile", "-Command",
                "$ErrorActionPreference='Stop'; [pscustomobject]@{Capture=@(Get-NetRoute -InterfaceAlias flutter_vless_tun -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')}).Count; "
                f"Peer=@(Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue).Count}} | ConvertTo-Json -Compress"], text=True, timeout=10))
            proof["cleanup"]["capture_routes"] = int(remaining["Capture"])
            proof["cleanup"]["owned_adapter_absent"] = remaining["Peer"] == 0
            proof["cleanup"]["owned_helpers_remaining"] = sum(p.poll() is None for p in (peer, service, guard) if p is not None)
        except BaseException: cleanup_errors.append("cleanup_inventory")
        source_interface.cache_clear()
        clean = not cleanup_errors and proof["cleanup"] == dict(service_exit0=True, policy_filters=0, capture_routes=0,
                                                               owned_adapter_absent=True, owned_helpers_remaining=0)
        proof["passed"] = proof["passed"] and clean and primary is None
        (directory / "numeric-ipv6-results.json").write_text(json.dumps(proof, indent=2))
        results.append(dict(mode="numeric-ipv6-outer-tcp", check="finite numeric IPv6 TCP peer and scoped WFP", passed=proof["passed"]))
        (directory / "vpn-results.json").write_text(json.dumps(results, indent=2))
        if primary is None and not proof["passed"]: raise AssertionError("Numeric IPv6 cleanup/proof incomplete")
    print("WINDOWS_NUMERIC_IPV6_OUTER_TCP_PASS=1", flush=True)
    print("WINDOWS_NUMERIC_IPV6_SCOPE_DENY_PASS=4", flush=True)


def main():
    global PROBE, REAL_DNS
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--vpn", action="store_true")
    parser.add_argument("--numeric-ipv6-only", action="store_true")
    parser.add_argument("--numeric-ipv6-variant", choices=("official", "routing"), default="routing")
    parser.add_argument("--native-routing", action="store_true", help="Append the separate native-routing profile; requires --vpn and an optional factory binary")
    parser.add_argument("--wine-bottle", help="CrossOver bottle for proxy-only tests on macOS")
    args = parser.parse_args()
    if args.native_routing and not args.vpn:
        raise SystemExit("Native routing acceptance requires the disposable VPN runner")
    if args.vpn and (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"):
        raise SystemExit("Full VPN tests require a disposable GitHub Windows runner")
    if args.numeric_ipv6_only and not args.vpn:
        raise SystemExit("Numeric IPv6 acceptance requires the disposable VPN runner")
    REAL_DNS = args.vpn
    directory = args.directory.resolve()
    probe = directory / "runtime_probe.exe"
    PROBE = probe
    if args.numeric_ipv6_only:
        isolated_results=[]
        numeric_ipv6_gate(probe,directory,isolated_results,args.numeric_ipv6_variant)
        return
    servers = []
    started_servers = []
    adapters = []
    asset_roots = []
    ipv6_payload = None
    fake_dns_payload = None
    fake_dns_cycles = 0
    results = []
    external_address = None
    direct_address = "127.0.0.1"
    try:
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            PORTS["inbound"] = candidate.getsockname()[1]
        if args.vpn:
            external_address = socket.gethostbyname("api.ipify.org")
            baseline = external_http(external_address)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((external_address, 443))
                direct_address = route.getsockname()[0]
            results.append(dict(check="external direct baseline", actual=baseline, passed=True))
        if args.vpn:
            driver = subprocess.run([str(probe), "wintun"], cwd=directory,
                                    capture_output=True, text=True, timeout=30)
            (directory / "wintun.log").write_text(driver.stdout + driver.stderr)
            assert driver.returncode == 0, "Wintun adapter creation failed"
            adapters.append(start_adapter(probe, directory, 2))
            for ipv6 in (False, True):
                actual = adapter_datagram(directory, 2, ipv6, False)
                results.append(dict(check="IPv6 adapter baseline" if ipv6 else "IPv4 adapter baseline", actual=actual, passed=True))
        # A VPN freedom socket is pinned to the underlay; use a local target
        # on that interface, not a loopback-only target on another interface.
        servers.append(DirectOrigin((direct_address, 0), Direct))
        servers.append(Server((direct_address, 0), Socks))
        servers[0].daemon_threads = False  # Join bounded HTTP callbacks before final direct-only observations.
        PORTS["direct"] = servers[0].server_address[1]
        PORTS["proxy"] = servers[1].server_address[1]
        if args.vpn:
            ipv6_payload = IPv6PayloadState()
            servers[1].ipv6_payload = ipv6_payload
            # UDP and TCP intentionally share the same fixed numeric IPv4
            # relay endpoint, keeping Xray's exact transport pin closed.
            relay = DatagramServer((direct_address, PORTS["proxy"]), IPv6PayloadDatagram)
            servers.append(relay)
            relay.socket.settimeout(1)
            relay.ipv6_payload = ipv6_payload
            assert relay.server_address == servers[1].server_address, "IPv6 proxy UDP relay changed endpoint"
            servers.append(ThreadingHTTPServer(("127.0.0.1", PORTS["direct"]), Direct))
            direct_dns = Server((direct_address, 0), DirectDns)
            servers.append(direct_dns)
            direct_dns.daemon_threads = False  # server_close joins the bounded, owned DNS callbacks.
            direct_dns.questions, direct_dns.questions_lock = [], threading.Lock()
            fake_dns_payload = FakeDnsPayloadState()
            fake_proxy = Server((direct_address, 0), Socks)
            servers.append(fake_proxy)
            fake_proxy.daemon_threads = False
            fake_proxy.fake_dns_payload = fake_dns_payload
            fake_relay = DatagramServer(fake_proxy.server_address, FakeDnsPayloadDatagram)
            servers.append(fake_relay)
            fake_relay.daemon_threads = False
            fake_relay.fake_dns_payload = fake_dns_payload
            if args.native_routing:
                # The selected default accepts ordinary traffic. It must not
                # share the prior IPv6 scenario's strict one-shot nonce state.
                servers.append(native_routing_proxy(direct_address))
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            started_servers.append(server)
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            PORTS["extra"] = candidate.getsockname()[1]
        cases = [(False, "stop"), (True, "stop")]
        if args.vpn:
            cases.extend([(False, "crash"), (False, "shutdown"), (False, "no-reconnect")])
        for reverse, ending in cases:
            label = ("vpn" if args.vpn else "proxy") + ("-reverse" if reverse else "") + ("-" + ending if ending != "stop" else "")
            profile = directory / (label + ".json")
            caller_api_port = None
            assets = None
            asset_fixture = None
            if reverse and ending == "stop":
                with socket.socket() as candidate:
                    candidate.bind(("127.0.0.1", 0))
                    caller_api_port = candidate.getsockname()[1]
                owner, asset_fixture = create_asset_root(directory)
                asset_roots.append(owner)
                assets = Path(owner.name)
            uses_ipv6_payload = args.vpn and not reverse and ending == "stop"
            prepared = config(reverse, external_address, direct_address, caller_api_port, asset_fixture, uses_ipv6_payload)
            # Exercise both the managed VPN SOCKS candidate and the private
            # stats API candidate, before either Core listener exists in the OS.
            metrics_port = (10086 if reverse else 10807) if args.vpn else 10085
            prepared["Metric\u017f"] = {"tag": "caller-metrics", "Li\u017ften": f"127.0.0.1:+{metrics_port}"}
            imported_ports = {entry["port"] for entry in prepared["inbounds"]}
            if caller_api_port is not None:
                imported_ports.add(caller_api_port)
            managed_port = next(port for port in range(10807, 65536) if port not in imported_ports | {metrics_port})
            if not args.vpn:
                with socket.socket() as candidate:
                    candidate.bind(("127.0.0.1", 0))
                    secondary_port = candidate.getsockname()[1]
                prepared["inbounds"].append({"listen": "127.0.0.1", "port": secondary_port,
                    "protocol": "socks", "tag": "socks-direct", "settings": {"auth": "noauth"}})
                prepared["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["socks-direct"], "outboundTag": "direct"})
            profile.write_text(json.dumps(prepared))
            stop_file = directory / (label + ".stop")
            stop_file.unlink(missing_ok=True)
            state_file = directory / (label + ".state.json")
            state_file.unlink(missing_ok=True)
            guard_stop = directory / (label + ".guard-stop")
            guard_stop.unlink(missing_ok=True)
            guard = None
            with (directory / (label + ".log")).open("w") as log:
                windows_path = lambda path: "Z:" + str(path).replace("/", "\\") if args.wine_bottle else str(path)
                command = (["/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
                            "--bottle", args.wine_bottle] if args.wine_bottle else [])
                command += [str(probe), ("run-vpn-no-reconnect" if ending == "no-reconnect" else "run-vpn") if args.vpn else "run-proxy", windows_path(profile), "240", windows_path(stop_file), windows_path(state_file)]
                if assets is not None:
                    command.append(windows_path(assets))
                process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=log)
                if args.vpn:
                    guard = subprocess.Popen([str(probe), "guard", str(process.pid), "240", str(guard_stop)],
                                             cwd=directory, stdout=log, stderr=log)
                try:
                    if args.vpn:
                        deadline = time.monotonic() + 65
                        while "START_RETURN=1" not in (directory / (label + ".log")).read_text(errors="replace"):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("VPN network setup did not become ready")
                            time.sleep(0.25)
                        routes = subprocess.check_output([
                            "powershell", "-NoProfile", "-Command",
                            "Get-NetRoute -InterfaceAlias flutter_vless_tun | Select-Object DestinationPrefix,NextHop,RouteMetric | ConvertTo-Json"], text=True, timeout=25)
                        (directory / (label + "-routes-during.log")).write_text(routes)
                        installed = json.loads(routes)
                        assert {r["DestinationPrefix"] for r in installed} >= {"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}
                        time.sleep(1)
                        assert int(native(probe, "policy-count")) >= 10
                        results.append(dict(mode=label, check="native WFP filters installed", passed=True))
                        if len(adapters) == 1:
                            adapters.append(start_adapter(probe, directory, 3))
                    else:
                        deadline = time.monotonic() + 25
                        while "START_RETURN=1" not in (directory / (label + ".log")).read_text(errors="replace"):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("Proxy did not report forwarding readiness")
                            time.sleep(0.1)
                    check_metrics_listener(metrics_port)
                    results.append(dict(mode=label, check="caller metrics HTTP survives private listener allocation", passed=True))
                    # Submit a Core-invalid replacement to the same live manager.
                    # The real routing requests below must still use its original
                    # workers, with WFP retained in VPN mode.
                    rejection = Path(str(state_file) + ".reject")
                    invalid = json.loads(json.dumps(prepared))
                    invalid["outbounds"][0]["protocol"] = "private-preflight-canary"
                    publish_rejection(rejection, invalid)
                    await_rejected_replacement(process, directory / (label + ".log"), state_file, assets is not None)
                    results.append(dict(mode=label, check="Core-invalid replacement preserves live workers", passed=True))
                    if assets is not None:
                        results.append(dict(mode=label, check="invalid asset root preserves live workers", passed=True))
                    traffic_before = (read_traffic_state(state_file) if reverse else await_traffic_baseline(state_file, args.vpn)) if ending == "stop" else None
                    for host in ("2ip.ru", "2ip.io", "myip.com"):
                        expected = "DIRECT-FIXTURE" if ((host == "myip.com") == reverse) else "PROXY-FIXTURE"
                        try:
                            actual = request(host, args.vpn)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        row = dict(mode=label, host=host, expected=expected, actual=actual, passed=actual == expected)
                        results.append(row)
                        print(json.dumps(row), flush=True)
                    if ending == "stop":
                        counters = await_traffic_counters(state_file, traffic_before, not reverse, args.vpn)
                        results.append(dict(mode=label, check="owned traffic counter sample", actual=counters, passed=True))
                    if asset_fixture is not None:
                        actual = request(asset_fixture["domain"], args.vpn)
                        results.append(dict(mode=label, check="explicit custom asset root routes ext GeoSite before blocking fallback",
                                            actual=actual, passed=actual == "DIRECT-FIXTURE"))
                        assert actual == "DIRECT-FIXTURE", "Custom GeoSite asset did not select its routing rule"
                    if caller_api_port is not None:
                        assert all(row["passed"] for row in results if row.get("mode") == label and "host" in row), "Caller API case has no successful routing proof"
                        check_caller_api(directory, caller_api_port, args.wine_bottle)
                        results.append(dict(mode=label, check="caller StatsService survives invalid replacement and routed HTTP with disabled counters", passed=True))
                    if not args.vpn:
                        for host in ("2ip.ru", "myip.com"):
                            actual = request(host, False, proxy_port=secondary_port)
                            results.append(dict(mode=label, check="secondary direct inbound", host=host,
                                                actual=actual, passed=actual == "DIRECT-FIXTURE"))
                    if args.vpn:
                        for subnet in (2, 3):
                            for ipv6 in (False, True):
                                actual = adapter_datagram(directory, subnet, ipv6, True)
                                results.append(dict(mode=label, check=f"{'new' if subnet == 3 else 'existing'} adapter {'IPv6' if ipv6 else 'IPv4'} blocked", actual=actual, passed=True))
                        with socket.create_connection(("127.0.0.1", managed_port), timeout=3) as denied:
                            denied.sendall(b"\x05\x01\x00")
                            assert exact(denied, 2) == b"\x05\xff", "Managed VPN SOCKS accepted noauth"
                        with socket.create_connection(("127.0.0.1", managed_port), timeout=3) as denied:
                            denied.sendall(b"\x05\x01\x02")
                            assert exact(denied, 2) == b"\x05\x02"
                            denied.sendall(b"\x01\x05wrong\x05wrong")
                            response = exact(denied, 2)
                            # RFC 1929 permits any nonzero failure code; Xray
                            # 26.7.28 uses FF, followed by a closed connection.
                            assert response[0] == 1 and response[1] != 0, "Managed VPN SOCKS accepted incorrect credentials"
                            try:
                                assert denied.recv(1) == b"", "Rejected SOCKS session remained open"
                            except ConnectionResetError:
                                pass
                        results.append(dict(mode=label, check="native SOCKS rejects noauth and incorrect credentials", passed=True))
                        for host in ("2ip.ru", "myip.com"):
                            expected = "DIRECT-FIXTURE" if ((host == "myip.com") == reverse) else "PROXY-FIXTURE"
                            actual = request(host, False)
                            results.append(dict(mode=label, check="imported SOCKS listener retains explicit noauth", host=host, actual=actual, passed=actual == expected))
                            actual = request(host, False, proxy_port=PORTS["extra"])
                            results.append(dict(mode=label, check="socks-direct inbound routing preserved", host=host, actual=actual, passed=actual == "DIRECT-FIXTURE"))
                        for udp in (False, True):
                            actual = physical_denied(external_address if not udp else "1.1.1.1", direct_address, 53 if udp else 443, udp, probe)
                            results.append(dict(mode=label, check="physical DNS denied" if udp else "physical TCP denied", actual=actual, passed=True))
                        for tcp in (False, True):
                            actual = protected_dns(tcp)
                            results.append(dict(mode=label, check="protected TCP DNS" if tcp else "protected UDP DNS", actual=actual, passed=True))
                        if uses_ipv6_payload:
                            for udp in (False, True):
                                actual = ipv6_payload_request(ipv6_payload, udp)
                                results.append(dict(mode=label, check="IPv6 UDP payload via IPv4 proxy" if udp else "IPv6 TCP payload via IPv4 proxy", actual=actual, passed=True))
                            for tcp in (False, True):
                                results.append(dict(mode=label, check="caller AAAA TCP DNS" if tcp else "caller AAAA UDP DNS",
                                                    actual=ipv6_payload_dns(tcp), passed=True))
                        results.append(dict(mode=label, check="real runner DNS through VPN", actual=relayed_dns(), passed=True))
                        try:
                            actual = request("localhost", True, loopback=True)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        results.append(dict(mode=label, check="ordinary loopback bypass", actual=actual,
                                            passed=actual == "DIRECT-FIXTURE"))
                        try:
                            actual = external_http(external_address, vpn=True)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        row = dict(mode=label, check="external direct through VPN", actual=actual,
                                   passed=actual == "HTTP 200")
                        results.append(row)
                        print(json.dumps(row), flush=True)
                        if not reverse and ending == "stop":
                            results.append(dict(mode=label, check="ordinary Windows DNS resolver", actual=system_dns(), passed=True))
                            # A new localized adapter name invalidates an Xray
                            # binding even though the local TUN probe still works.
                            # This disposable VM keeps its addresses and routes.
                            index = source_interface(direct_address)
                            subprocess.run(["powershell", "-NoProfile", "-Command",
                                f"Get-NetAdapter | Where-Object {{ $_.ifIndex -eq {index} }} | Rename-NetAdapter -NewName 'Vless Underlay Ω' -ErrorAction Stop"],
                                check=True, timeout=45, stdout=subprocess.DEVNULL)
                            await_state(state_file, False)
                            actual = physical_denied(external_address, direct_address, 443)
                            results.append(dict(mode=label, check="underlay rename remains protected", actual=actual, passed=True))
                            await_state(state_file, True, timeout=60)
                            assert request("myip.com", True) == "PROXY-FIXTURE"
                            assert system_dns()
                            for udp in (False, True):
                                results.append(dict(mode=label, check="IPv6 payload survives underlay rename",
                                                    actual=ipv6_payload_request(ipv6_payload, udp), passed=True))
                            results.append(dict(mode=label, check="Unicode underlay rename recovers routing and system DNS", passed=True))
                            for worker in ("xray.exe", "tun2socks.exe"):
                                kill_worker(process.pid, worker)
                                await_state(state_file, False)
                                actual = physical_denied(external_address, direct_address, 443)
                                results.append(dict(mode=label, check=worker + " failure remains blocked", actual=actual, passed=True))
                                await_state(state_file, True, timeout=60)
                                assert request("myip.com", True) == "PROXY-FIXTURE"
                                results.append(dict(mode=label, check=worker + " forwarding recovers", passed=True))
                                for udp in (False, True):
                                    results.append(dict(mode=label, check=worker + " IPv6 payload recovers",
                                                        actual=ipv6_payload_request(ipv6_payload, udp), passed=True))
                    if args.vpn and ending == "no-reconnect":
                        kill_worker(process.pid, "xray.exe")
                        await_state(state_file, False)
                        time.sleep(2)
                        state = await_state(state_file, False)
                        assert not state["running"] and state["protecting"]
                        remaining_workers = subprocess.check_output(["powershell", "-NoProfile", "-Command",
                            f"@(Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {process.pid} -and $_.Name -eq 'xray.exe' }}).Count"], text=True, timeout=25)
                        assert remaining_workers.strip() == "0", "Disabled recovery restarted Xray"
                        actual = physical_denied(external_address, direct_address, 443)
                        results.append(dict(mode=label, check="disabled Auto Reconnect retains WFP and leaves failed workers stopped", actual=actual, passed=True))
                    if ending == "crash":
                        process.kill()
                    elif ending == "shutdown":
                        stop_file.write_text("shutdown")
                    else:
                        stop_file.touch()
                    code = process.wait(timeout=25)
                    if args.vpn:
                        if ending in ("crash", "shutdown"):
                            assert int(native(probe, "policy-count")) >= 10
                            actual = physical_denied(external_address, direct_address, 443)
                            results.append(dict(mode=label, check="application exit retains native WFP block", actual=actual, passed=True))
                            native(probe, "release-protection")
                        assert native(probe, "policy-count") == "0"
                        remaining = subprocess.check_output([
                            "powershell", "-NoProfile", "-Command",
                            "[pscustomobject]@{Routes=@(Get-NetRoute -InterfaceAlias flutter_vless_tun -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') }).Count; "
                            "IPv6Addresses=@(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'flutter_vless_tun' -and $_.IPAddress -eq 'fd00:198:18::2' }).Count} | ConvertTo-Json -Compress"], text=True, timeout=25)
                        inventory = json.loads(remaining)
                        results.append(dict(mode=label, check="capture routes removed by service", passed=inventory["Routes"] == 0))
                        results.append(dict(mode=label, check="owned IPv6 address removed by service", passed=inventory["IPv6Addresses"] == 0))
                        assert external_http(external_address) == baseline
                        results.append(dict(mode=label, check="explicit stop restores ordinary HTTPS", passed=True))
                        if not reverse and ending == "stop":
                            for subnet in (2, 3):
                                for ipv6 in (False, True):
                                    actual = adapter_datagram(directory, subnet, ipv6, False)
                                    results.append(dict(mode=label, check=f"adapter {subnet} {'IPv6' if ipv6 else 'IPv4'} restored", actual=actual, passed=True))
                    results.append(dict(mode=label, check="requested termination", passed=ending == "crash" or code == 0, exit_code=code))
                finally:
                    if process.poll() is None:
                        stop_file.touch()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    if args.vpn:
                        # Do not rely on a later Actions step: WFP also covers
                        # the runner agent, so restore connectivity locally.
                        native(probe, "release-protection")
                        guard_stop.touch()
                        if guard:
                            guard.wait(timeout=10)
            # Stop removes the Wintun adapter; allow the next creation to settle.
            time.sleep(2)
        if args.vpn:
            direct_only_gate(probe, directory, direct_address, direct_dns, servers[0], results)
            if args.native_routing:
                with occupied_private_ports():
                    native_routing_gate(probe, directory, direct_address, direct_dns, servers[0], results)
                print("WINDOWS_PRIVATE_PORT_OCCUPIED_RUNTIME_PASS=2", flush=True)
            fake_dns_cycles = fakedns_gate(probe, directory, direct_address, fake_proxy.server_address[1],
                                          direct_dns.server_address[1], fake_dns_payload, results)
    finally:
        primary = sys.exc_info()[1]
        server_cleanup_error = None
        for process, stop in adapters:
            stop.touch()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if ipv6_payload is not None:
            try:
                ipv6_payload.close()
            except (AssertionError, OSError):
                results.append(dict(check="IPv6 SOCKS control cleanup", passed=False))
        if fake_dns_payload is not None:
            try: fake_dns_payload.close()
            except (AssertionError, OSError): results.append(dict(check="FakeDNS SOCKS control cleanup", passed=False))
        for server in servers:
            # BaseServer.shutdown waits for serve_forever; calling it on a
            # constructed owner whose worker never started waits forever.
            if server in started_servers:
                try: server.shutdown()
                except BaseException as error:
                    if server_cleanup_error is None: server_cleanup_error = error
            try: server.server_close()
            except BaseException as error:
                if server_cleanup_error is None: server_cleanup_error = error
        if server_cleanup_error is not None:
            results.append(dict(check="owned server shutdown and close", passed=False))
        if servers and hasattr(servers[0], "direct_only_lock"):
            with servers[0].direct_only_lock:
                clean = servers[0].direct_only_observed.count("direct-only.invalid") == 6 \
                    and "blocked.invalid" not in servers[0].direct_only_observed
            results.append(dict(check="direct-only origin counts after owned callbacks drain", passed=clean))
            with servers[0].direct_only_lock:
                evidence = {name: dict(value) for name, value in servers[0].direct_only_evidence.items()}
            save_direct_evidence(directory / "direct-only-origin.evidence.log", dict(after_drain=True, cases=evidence))
        if ipv6_payload is not None:
            try:
                ipv6_payload.require_clean()
            except AssertionError:
                results.append(dict(check="IPv6 proxy target and nonce ownership", passed=False))
        if fake_dns_payload is not None:
            clean = True
            try: fake_dns_payload.require_clean()
            except AssertionError: clean = False
            results.append(dict(check="FakeDNS exact domain and nonce ownership after joined drain", passed=clean))
        for owner in asset_roots:
            try:
                owner.cleanup()
            except OSError:
                results.append(dict(check="owned asset directory cleanup", passed=False))
        (directory / ("vpn-results.json" if args.vpn else "proxy-results.json")).write_text(json.dumps(results, indent=2))
        if server_cleanup_error is not None and primary is None:
            raise server_cleanup_error
    if not results or not all(row["passed"] for row in results):
        raise SystemExit(1)
    if args.vpn:
        numeric_ipv6_gate(probe,directory,results,"routing")
    counter_gates = sum(row.get("check") == "owned traffic counter sample" for row in results)
    assert counter_gates == 2 + (2 if args.native_routing else 0), "Owned traffic counter gate count changed"
    print("WINDOWS_TRAFFIC_COUNTER_RUNTIME_PASS=" + str(counter_gates), flush=True)
    if args.vpn:
        assert fake_dns_cycles == 2, "FakeDNS restart gate count changed"
        print("WINDOWS_FAKEDNS_RUNTIME_PASS=2", flush=True)


if __name__ == "__main__":
    main()
