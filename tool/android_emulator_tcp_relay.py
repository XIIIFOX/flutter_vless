#!/usr/bin/env python3
"""Bounded emulator CONNECT gateway; never changes host VPN, routes, DNS or proxy.

Pass -http-proxy 127.0.0.1:PORT to the owned Android emulator only. UDP is
unaffected. Explicit --emulator-public-tcp permits numeric public TCP 80/443;
hostnames need a private pre-resolved --allowlist. Optional Darwin --peer-policy
binds only exact public IPv4:443 peers to an existing interface, before connect.
Policies contain no VPN credentials. Tunnel payloads and destinations are not
logged. A separate owner must still guard emulator/VPN session lifetimes.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import sys
import threading
import time


class RelayFailure(Exception):
    def __init__(self, status, category):
        self.status = status
        self.category = category


def authority(value):
    if not isinstance(value, str) or not value or len(value) > 300 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise RelayFailure(400, 'bad_authority')
    if any(c in value for c in '/?#@%\\'):
        raise RelayFailure(400, 'bad_authority')
    if value.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\]:([0-9]+)', value)
        if not match:
            raise RelayFailure(400, 'bad_authority')
        host, port = match.groups()
        try:
            host = ipaddress.IPv6Address(host).compressed
        except ValueError:
            raise RelayFailure(400, 'bad_authority') from None
    else:
        if value.count(':') != 1:
            raise RelayFailure(400, 'bad_authority')
        host, port = value.split(':')
        host = host.lower()
        if len(host) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
            raise RelayFailure(400, 'bad_authority')
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise RelayFailure(400, 'bad_authority')
        if re.fullmatch(r'[0-9.]+', host):
            try:
                host = ipaddress.IPv4Address(host).compressed
            except ValueError:
                raise RelayFailure(400, 'bad_authority') from None
    if not port.isascii() or not port.isdecimal() or len(port) > 5 or str(int(port)) != port or not 1 <= int(port) <= 65535:
        raise RelayFailure(400, 'bad_authority')
    return host, int(port)


def parse_header(raw):
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        raise RelayFailure(400, 'bad_headers') from None
    if not text.endswith('\r\n\r\n') or re.search(r'(?<!\r)\n|\r(?!\n)', text):
        raise RelayFailure(400, 'bad_headers')
    lines = text[:-4].split('\r\n')
    if not lines or len(lines) > 33:
        raise RelayFailure(400, 'bad_headers')
    parts = lines[0].split(' ')
    if len(parts) != 3 or parts[0] != 'CONNECT' or parts[2] not in ('HTTP/1.0', 'HTTP/1.1'):
        raise RelayFailure(405, 'not_connect')
    target = authority(parts[1])
    seen = set()
    for line in lines[1:]:
        if not line or line[0].isspace() or ':' not in line:
            raise RelayFailure(400, 'bad_headers')
        name, value = line.split(':', 1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(ord(c) < 32 and c != '\t' or ord(c) > 126 for c in value):
            raise RelayFailure(400, 'bad_headers')
        name = name.lower()
        if name in seen:
            raise RelayFailure(400, 'duplicate_header')
        seen.add(name)
        if name in ('authorization', 'proxy-authorization', 'transfer-encoding'):
            raise RelayFailure(400, 'unsupported_header')
        if name == 'content-length' and value.strip() != '0':
            raise RelayFailure(400, 'unsupported_body')
        if name == 'host' and authority(value.strip()) != target:
            raise RelayFailure(400, 'host_mismatch')
    return target


class Policy:
    def __init__(self, document, *, test_loopback=False, allow_public_numeric=False):
        rows = document.get('destinations') if isinstance(document, dict) else None
        if not isinstance(rows, list) or not (0 if allow_public_numeric else 1) <= len(rows) <= 256:
            raise ValueError('Invalid destination list')
        self.endpoints = {}
        self.test_loopback = test_loopback
        self.allow_public_numeric = allow_public_numeric
        if test_loopback and allow_public_numeric:
            raise ValueError('Loopback tests cannot enable public forwarding')
        for row in rows:
            if not isinstance(row, dict) or set(row) != {'host', 'ports', 'addresses'}:
                raise ValueError('Invalid destination record')
            ports, addresses = row['ports'], row['addresses']
            if not isinstance(ports, list) or not 1 <= len(ports) <= 2 or not isinstance(addresses, list) or not 1 <= len(addresses) <= 8:
                raise ValueError('Invalid destination bounds')
            parsed = []
            if not isinstance(row['host'],str):
                raise ValueError('Invalid hostname')
            for value in addresses:
                if not isinstance(value,str):
                    raise ValueError('Invalid numeric address')
                address = ipaddress.ip_address(value)
                if not test_loopback and (not address.is_global or address.is_multicast or getattr(address, 'ipv4_mapped', None) is not None):
                    raise ValueError('Forbidden address')
                if test_loopback and not address.is_loopback:
                    raise ValueError('Tests may use loopback only')
                parsed.append(address)
            for port in ports:
                if type(port) is not int or not 1 <= port <= 65535 or not test_loopback and port not in (80, 443):
                    raise ValueError('Forbidden port')
                host = row['host']
                wrapped = f'[{host}]' if ':' in host else host
                key = authority(f'{wrapped}:{port}')
                if key in self.endpoints:
                    raise ValueError('Duplicate authority')
                try:
                    numeric = ipaddress.ip_address(key[0])
                except ValueError:
                    numeric = None
                if numeric is not None and any(address != numeric for address in parsed):
                    raise ValueError('Numeric authority must retain its address')
                self.endpoints[key] = tuple((socket.AF_INET6 if address.version == 6 else socket.AF_INET,
                                             (address.compressed, port, 0, 0) if address.version == 6 else (address.compressed, port)) for address in parsed)

    @classmethod
    def from_file(cls, path, *, allow_public_numeric=False):
        document, digest = read_private_json(path, with_digest=True)
        policy = cls(document, allow_public_numeric=allow_public_numeric)
        policy.source_sha256 = digest
        return policy

    def lookup(self, key):
        if key in self.endpoints:
            return self.endpoints[key]
        if self.allow_public_numeric and key[1] in (80, 443):
            try:
                address = ipaddress.ip_address(key[0])
            except ValueError:
                address = None
            if address is not None and address.is_global and not address.is_multicast and getattr(address, 'ipv4_mapped', None) is None:
                endpoint = (address.compressed, key[1], 0, 0) if address.version == 6 else (address.compressed, key[1])
                return ((socket.AF_INET6 if address.version == 6 else socket.AF_INET, endpoint),)
        raise RelayFailure(403, 'not_allowed')


def read_private_json(path, *, with_digest=False):
    """Read an owned, non-symlink regular 0600 policy without a path reopen race."""
    if not hasattr(os, 'getuid'):
        raise ValueError('Private policy files require POSIX owner/mode support')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 128 * 1024:
            raise ValueError('Policy must be an owned regular 0600 file')
        with os.fdopen(descriptor, 'rb') as source:
            descriptor = None
            raw = source.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError('Policy exceeds size bound')
        document = json.loads(raw)
        return (document, hashlib.sha256(raw).hexdigest()) if with_digest else document
    finally:
        if descriptor is not None:
            os.close(descriptor)


class PeerBindings:
    """Exact Darwin per-socket IPv4:443 binding; no fallback after bind failure.

    Private policy: {"peers":[{"address":"PUBLIC_IPV4","port":443,
                                "interface":"en0"}]}
    Interface indexes are resolved and rechecked without DNS. Numeric option 25
    is Darwin's IP_BOUND_IF; it is never used on another operating system.
    """
    def __init__(self, document, *, platform=sys.platform, interface_index=socket.if_nametoindex):
        rows = document.get('peers') if isinstance(document, dict) else None
        if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
            raise ValueError('Invalid peer binding list')
        if platform != 'darwin':
            raise ValueError('Peer interface binding requires Darwin')
        self.endpoints = {}
        self.interface_index = interface_index
        for row in rows:
            if not isinstance(row, dict) or set(row) != {'address', 'port', 'interface'}:
                raise ValueError('Invalid peer binding record')
            if not isinstance(row['address'], str):
                raise ValueError('Peer must be numeric public IPv4')
            try:
                address = ipaddress.IPv4Address(row['address'])
            except (ValueError, TypeError):
                raise ValueError('Peer must be numeric public IPv4') from None
            if not address.is_global or address.is_multicast or type(row['port']) is not int or row['port'] != 443:
                raise ValueError('Peer binding requires public IPv4:443')
            name = row['interface']
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', name):
                raise ValueError('Invalid interface name')
            index = interface_index(name)
            if type(index) is not int or not 1 <= index <= 0xffffffff:
                raise ValueError('Invalid interface index')
            key = (address.compressed, 443)
            if key in self.endpoints:
                raise ValueError('Duplicate peer binding')
            self.endpoints[key] = (name, index)

    @classmethod
    def from_file(cls, path):
        document, digest = read_private_json(path, with_digest=True)
        bindings = cls(document)
        bindings.source_sha256 = digest
        return bindings

    def apply(self, upstream, family, address):
        selected = self.endpoints.get((address[0], address[1])) if family == socket.AF_INET else None
        if selected is None:
            return False
        name, index = selected
        try:
            if self.interface_index(name) != index:
                raise OSError(errno.ENXIO, 'Interface identity changed')
            upstream.setsockopt(socket.IPPROTO_IP, 25, index)
            if upstream.getsockopt(socket.IPPROTO_IP, 25) != index:
                raise OSError(errno.ENXIO, 'Interface bind not confirmed')
        except OSError:
            raise RelayFailure(502, 'peer_interface_bind_failed') from None
        return True


@dataclass(frozen=True)
class Limits:
    header_seconds: float = 3
    connect_seconds: float = 5
    idle_seconds: float = 30
    tunnel_seconds: float = 120
    server_seconds: float = 1200
    max_connections: int = 16
    max_header_bytes: int = 16384
    max_buffer_bytes: int = 262144

    def __post_init__(self):
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 < value <= 600 for value in
               (self.header_seconds, self.connect_seconds, self.idle_seconds, self.tunnel_seconds)):
            raise ValueError('Invalid time bounds')
        if isinstance(self.server_seconds, bool) or not isinstance(self.server_seconds, (int, float)) or not 0 < self.server_seconds <= 1800:
            raise ValueError('Invalid server lifetime')
        if not 1 <= self.max_connections <= 32 or not 128 <= self.max_header_bytes <= 32768 or not 4096 <= self.max_buffer_bytes <= 1024 * 1024:
            raise ValueError('Invalid resource bounds')


class ConnectRelay:
    def __init__(self, policy, limits=Limits(), *, listen_port=0, peer_bindings=None, _socket_factory=socket.socket):
        if type(listen_port) is not int or not 0 <= listen_port <= 65535:
            raise ValueError('Invalid loopback listen port')
        self.policy, self.limits = policy, limits
        self.peer_bindings = peer_bindings
        self._socket_factory = _socket_factory
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._workers = set()
        self._sockets = set()
        self._counts = {}
        self._unexpected = []
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(('127.0.0.1', listen_port))
            self._listener.listen(limits.max_connections)
            self._listener.settimeout(.1)
        except BaseException:
            self._listener.close()
            raise
        self.port = self._listener.getsockname()[1]
        self._accept_thread = threading.Thread(target=self._accept, name='private-connect-accept', daemon=False)
        self._started = False

    def _count(self, category, amount=1):
        with self._lock:
            self._counts[category] = self._counts.get(category, 0) + amount

    def snapshot(self):
        with self._lock:
            return {'counts': dict(self._counts), 'active_workers': len(self._workers),
                    'tracked_sockets': len(self._sockets), 'unexpected_worker_exceptions': list(self._unexpected),
                    'stopping': self._stopping.is_set()}

    def start(self):
        if self._started:
            raise RuntimeError('Relay already started')
        self._started = True
        self._accept_thread.start()
        return self

    def _accept(self):
        try:
            while not self._stopping.is_set():
                try:
                    client, _ = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                client.setblocking(False)
                with self._lock:
                    busy = len(self._workers) >= self.limits.max_connections
                    if not busy and not self._stopping.is_set():
                        worker = threading.Thread(target=self._worker, args=(client, time.monotonic()), name='private-connect-worker', daemon=False)
                        self._workers.add(worker)
                        self._sockets.add(client)
                    else:
                        worker = None
                if worker is None:
                    self._count('busy')
                    try:
                        self._send(client, b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n', time.monotonic()+.2)
                    except (OSError, RelayFailure):
                        pass
                    client.close()
                else:
                    self._count('accepted')
                    worker.start()
        except Exception as error:
            self._unexpected_error(error)

    def _unexpected_error(self, error):
        with self._lock:
            self._unexpected.append({'type':type(error).__name__, 'errno':error.errno if isinstance(error,OSError) else None})
        self.request_stop()

    def _wait(self, read, write, deadline):
        if self._stopping.is_set():
            raise RelayFailure(503, 'cancelled')
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise RelayFailure(408, 'deadline')
        try:
            return select.select(read, write, [], min(.1, remaining))[:2]
        except (ValueError, OSError):
            if self._stopping.is_set():
                raise RelayFailure(503, 'cancelled') from None
            raise

    def _send(self, destination, data, deadline):
        pending = memoryview(data)
        while pending:
            _, writable = self._wait([], [destination], deadline)
            if not writable:
                continue
            try:
                count = destination.send(pending)
            except BlockingIOError:
                continue
            if count <= 0:
                raise OSError(errno.ECONNRESET, 'Socket closed')
            pending = pending[count:]

    def _header(self, client, deadline):
        data = bytearray()
        while True:
            if self._stopping.is_set():
                raise RelayFailure(503, 'cancelled')
            if time.monotonic() >= deadline:
                raise RelayFailure(408, 'header_deadline')
            end = data.find(b'\r\n\r\n')
            if end >= 0:
                if end+4 > self.limits.max_header_bytes:
                    raise RelayFailure(400, 'header_too_large')
                target = parse_header(bytes(data[:end+4]))
                if time.monotonic() >= deadline:
                    raise RelayFailure(408, 'header_deadline')
                return target, bytes(data[end+4:])
            if len(data) > self.limits.max_header_bytes:
                raise RelayFailure(400, 'header_too_large')
            # An incomplete final CR is valid until the next read; other bare
            # CR/LF bytes are malformed. Binary bytes AFTER CRLFCRLF are opaque.
            if re.search(rb'(?<!\r)\n|\r(?!\n|$)', data):
                raise RelayFailure(400, 'bad_headers')
            readable, _ = self._wait([client], [], deadline)
            if not readable:
                continue
            try:
                chunk = client.recv(4096)
            except BlockingIOError:
                continue
            if not chunk:
                raise RelayFailure(400, 'header_eof')
            data.extend(chunk)

    def _dial(self, endpoints, deadline):
        pending_errors = (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EINTR)
        expected_errors = (errno.ECONNREFUSED,errno.ECONNRESET,errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ETIMEDOUT,errno.ENETDOWN,errno.EADDRNOTAVAIL)
        for family, address in endpoints:
            if self._stopping.is_set():
                raise RelayFailure(503, 'cancelled')
            if time.monotonic() >= deadline:
                raise RelayFailure(502, 'connect_deadline')
            upstream = self._socket_factory(family, socket.SOCK_STREAM)
            upstream.setblocking(False)
            with self._lock:
                self._sockets.add(upstream)
            connected = False
            try:
                if self.peer_bindings is not None and self.peer_bindings.apply(upstream, family, address):
                    self._count('selected_peer_interface_bound')
                error = upstream.connect_ex(address)  # Numeric-only: no resolver thread.
                while error in pending_errors:
                    try:
                        _, writable = self._wait([], [upstream], deadline)
                    except RelayFailure as failure:
                        if failure.category == 'deadline':
                            raise RelayFailure(502, 'connect_deadline') from None
                        raise
                    if writable:
                        error = upstream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error == 0:
                    if time.monotonic() >= deadline:
                        raise RelayFailure(502, 'connect_deadline')
                    connected = True
                    return upstream
                if error not in expected_errors:
                    raise OSError(error, 'Unexpected connect failure')
                self._count('connect_errno_'+str(error))
            except OSError as error:
                if error.errno not in expected_errors:
                    raise
                self._count('connect_errno_'+str(error.errno))
            finally:
                if not connected:
                    with self._lock:
                        self._sockets.discard(upstream)
                    upstream.close()
        raise RelayFailure(502, 'connect_failed')

    def _transfer(self, client, upstream, first, deadline):
        buffers = {upstream: bytearray(first), client: bytearray()}
        sources = {client: upstream, upstream: client}
        reading = {client: True, upstream: True}
        shutdown = {client: False, upstream: False}
        activity = time.monotonic()
        while True:
            for source, destination in sources.items():
                if not reading[source] and not buffers[destination] and not shutdown[destination]:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError as error:
                        if error.errno not in (errno.ENOTCONN, errno.EPIPE, errno.ECONNRESET):
                            raise
                    shutdown[destination] = True
            if not any(reading.values()) and not any(buffers.values()):
                return
            now = time.monotonic()
            if now >= deadline:
                raise RelayFailure(408, 'tunnel_lifetime')
            if now-activity >= self.limits.idle_seconds:
                raise RelayFailure(408, 'idle_deadline')
            rlist = [s for s, d in sources.items() if reading[s] and len(buffers[d]) < self.limits.max_buffer_bytes]
            wlist = [s for s in sources if buffers[s]]
            readable, writable = self._wait(rlist, wlist, min(deadline, activity+self.limits.idle_seconds))
            for destination in writable:
                try:
                    count = destination.send(buffers[destination])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise OSError(errno.ECONNRESET, 'Socket closed')
                del buffers[destination][:count]
                activity = time.monotonic()
                self._count('tunnel_bytes', count)
            for source in readable:
                destination = sources[source]
                try:
                    chunk = source.recv(min(65536, self.limits.max_buffer_bytes-len(buffers[destination])))
                except BlockingIOError:
                    continue
                if chunk:
                    buffers[destination].extend(chunk)
                    activity = time.monotonic()
                else:
                    reading[source] = False

    def _worker(self, client, accepted):
        upstream, reply_started = None, False
        try:
            target, first = self._header(client, min(accepted+self.limits.header_seconds, accepted+self.limits.tunnel_seconds))
            endpoints = self.policy.lookup(target)
            upstream = self._dial(endpoints, min(time.monotonic()+self.limits.connect_seconds, accepted+self.limits.tunnel_seconds))
            reply_started = True
            self._send(client, b'HTTP/1.1 200 Connection Established\r\n\r\n', min(time.monotonic()+1, accepted+self.limits.tunnel_seconds))
            self._count('established')
            self._transfer(client, upstream, first, accepted+self.limits.tunnel_seconds)
            self._count('completed')
        except RelayFailure as failure:
            self._count(failure.category)
            if not reply_started and not self._stopping.is_set():
                try:
                    reply = f'HTTP/1.1 {failure.status} Relay Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'.encode('ascii')
                    self._send(client, reply, time.monotonic()+1)
                except (OSError, RelayFailure):
                    pass
        except OSError as error:
            if error.errno in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN, errno.ECONNABORTED) or self._stopping.is_set():
                self._count('socket_closed')
            else:
                self._unexpected_error(error)
        except Exception as error:
            self._unexpected_error(error)
        finally:
            for sock in (upstream, client):
                if sock is not None:
                    with self._lock:
                        self._sockets.discard(sock)
                    sock.close()
            with self._lock:
                self._workers.discard(threading.current_thread())

    def request_stop(self):
        self._stopping.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            active = list(self._sockets)
        # Workers own close(); shutdown only wakes them, avoiding descriptor reuse.
        for sock in active:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.request_stop()
        if self._started and threading.current_thread() != self._accept_thread:
            self._accept_thread.join(timeout=2)
        deadline = time.monotonic()+3
        while True:
            with self._lock:
                workers = list(self._workers)
            if not workers:
                break
            for worker in workers:
                if worker != threading.current_thread():
                    worker.join(timeout=max(0, deadline-time.monotonic()))
            if time.monotonic() >= deadline:
                raise RuntimeError('Relay worker shutdown failed')
        snapshot = self.snapshot()
        if self._accept_thread.is_alive() or snapshot['tracked_sockets']:
            raise RuntimeError('Relay socket shutdown failed')
        return snapshot


def write_json(path, value):
    path = Path(path)
    with path.open('x') as output:
        os.chmod(path, 0o600)
        json.dump(value, output, indent=2)
        output.write('\n')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allowlist', help='Owned 0600 pre-resolved hostname/numeric policy')
    parser.add_argument('--emulator-public-tcp', action='store_true', help='Explicitly allow public numeric TCP 80/443, without DNS')
    parser.add_argument('--peer-policy', help='Owned 0600 exact public IPv4:443/interface policy; Darwin only')
    parser.add_argument('--port', type=int, default=0, help='Owned loopback listener port; 0 chooses an ephemeral port')
    parser.add_argument('--ready', required=True)
    parser.add_argument('--result', required=True)
    parser.add_argument('--stop-file', required=True)
    parser.add_argument('--server-seconds', type=float, default=1200)
    args = parser.parse_args()
    if any(Path(p).exists() or Path(p).is_symlink() for p in (args.ready, args.result, args.stop_file)):
        parser.error('Ready/result/stop paths must be fresh')
    if not args.allowlist and not args.emulator_public_tcp:
        parser.error('An allowlist or explicit emulator-public-tcp mode is required')
    policy = Policy.from_file(args.allowlist, allow_public_numeric=args.emulator_public_tcp) if args.allowlist else Policy({'destinations': []}, allow_public_numeric=True)
    bindings = PeerBindings.from_file(args.peer_policy) if args.peer_policy else None
    limits = Limits(server_seconds=args.server_seconds)
    relay = ConnectRelay(policy, limits, listen_port=args.port, peer_bindings=bindings)
    requested = [False]
    for signum in (signal.SIGTERM, signal.SIGINT):
        # Avoid acquiring locks/socket shutdown from an asynchronous handler.
        signal.signal(signum, lambda *_: requested.__setitem__(0, True))
    try:
        relay.start()
        write_json(args.ready, {'PID': os.getpid(), 'bind': '127.0.0.1', 'port': relay.port,
                   'allowlist_SHA256': policy.source_sha256 if args.allowlist else None,
                   'peer_policy_SHA256': bindings.source_sha256 if bindings else None,
                   'peer_bindings': len(bindings.endpoints) if bindings else 0,
                   'emulator_public_numeric_TCP_80_443': args.emulator_public_tcp,
                   'host_network_configuration_changed': False,
                   'source_SHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'limits': asdict(limits), 'no_TLS_inspection': True, 'no_payload_or_credentials_logging': True})
        deadline = time.monotonic()+limits.server_seconds
        while not relay._stopping.wait(.1) and not requested[0] and time.monotonic() < deadline and not Path(args.stop_file).exists():
            pass
    finally:
        snapshot = relay.close()
        write_json(args.result, dict(snapshot, PID=os.getpid(), closed=True))
    return 0 if not snapshot['unexpected_worker_exceptions'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
