#!/usr/bin/env python3
"""Account-free, loopback-only S3 subset for XDRIVE acceptance.

Not a production S3 service. Objects remain in bounded memory and disappear at
shutdown. The server verifies SigV4 instead of accepting an Authorization prefix.
It never logs request headers, object bodies or credentials. Android may reach
this loopback listener through a task-owned adb reverse mapping.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import signal
import socket
from socketserver import TCPServer
import sys
import threading
import time
from urllib.parse import parse_qsl, quote, unquote, urlsplit
import xml.etree.ElementTree as ET

ACCESS = 'synthetic-xdrive-access'
SECRET = 'synthetic-xdrive-secret'
BUCKET = 'synthetic-xdrive-bucket'
REGION = 'us-east-1'
MAX_BODY = 1 << 20
MAX_TOTAL = 32 << 20
MAX_OBJECTS = 4096


def verify_signature(method, target, headers, body, access=ACCESS, secret=SECRET):
    """Independent request-side SigV4 verification, without a Core signer."""
    headers = {key.lower(): value for key, value in headers.items()}
    authorization = headers.get('authorization', '')
    if not authorization.startswith('AWS4-HMAC-SHA256 '):
        return False
    fields = {}
    for field in authorization[len('AWS4-HMAC-SHA256 '):].split(','):
        pair = field.strip().split('=', 1)
        if len(pair) != 2 or pair[0] in fields:
            return False
        fields[pair[0]] = pair[1]
    credential = fields.get('Credential', '').split('/')
    stamp = headers.get('x-amz-date', '')
    if len(credential) != 5 or credential != [access, stamp[:8], REGION, 's3', 'aws4_request'] or len(stamp) != 16:
        return False
    payload = hashlib.sha256(body).hexdigest()
    if headers.get('x-amz-content-sha256') != payload:
        return False
    names = fields.get('SignedHeaders', '').split(';')
    if not names or names != sorted(set(names)) or not {'host', 'x-amz-date'}.issubset(names):
        return False
    if any(not name or name != name.lower() or name not in headers for name in names):
        return False
    if headers.get('x-amz-security-token') and 'x-amz-security-token' not in names:
        return False
    url = urlsplit(target)
    query = '&'.join(f'{quote(key, safe="-_.~")}={quote(value, safe="-_.~")}'
                     for key, value in sorted(parse_qsl(url.query, keep_blank_values=True)))
    canonical_headers = ''.join(name + ':' + ' '.join(headers[name].split()) + '\n' for name in names)
    canonical = '\n'.join([method, url.path or '/', query, canonical_headers, ';'.join(names), payload])
    text = '\n'.join(['AWS4-HMAC-SHA256', stamp, '/'.join(credential[1:]), hashlib.sha256(canonical.encode()).hexdigest()])
    key = ('AWS4' + secret).encode()
    for part in credential[1:]:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, text.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(fields.get('Signature', ''), expected)


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, port=0, folder='acceptance'):
        if not folder or '\\' in folder or any(part in ('', '.', '..') for part in folder.split('/')) or any(ord(c) < 32 or ord(c) == 127 for c in folder):
            raise ValueError('Fixture folder must be a relative nonempty prefix')
        self.folder = folder
        self.control = secrets.token_hex(24)
        self.lock = threading.Lock()
        self.connection_lock = threading.Lock()
        self.connections = set()
        self.closing = False
        self.objects = {}
        self.total_bytes = 0
        self.counts = {'requests': 0, 'PUT': 0, 'GET': 0, 'DELETE': 0, 'LIST': 0,
                       'signature_failures': 0, 'request_failures': 0,
                       'put_bytes': 0, 'get_bytes': 0, 'handler_failures': 0,
                       'client_disconnects': 0, 'incomplete_requests': 0}
        super().__init__(('127.0.0.1', port), FixtureHandler)

    @property
    def endpoint(self):
        return f'http://127.0.0.1:{self.server_port}'

    def server_bind(self):
        # HTTPServer normally performs getfqdn() during construction. This
        # numeric loopback fixture has no hostname to resolve and must not wait
        # on host DNS before any test request can be admitted.
        TCPServer.server_bind(self)
        self.server_name = '127.0.0.1'
        self.server_port = self.server_address[1]

    def snapshot(self):
        with self.lock:
            result = {**self.counts, 'objects': len(self.objects), 'stored_bytes': self.total_bytes}
        with self.connection_lock:
            result['active_connections'] = len(self.connections)
        return result

    def get_request(self):
        connection, address = super().get_request()
        # Admission and ownership precede worker creation. A concurrent shutdown
        # therefore sees even a socket whose handler has not started yet.
        with self.connection_lock:
            if self.closing:
                connection.close()
                raise OSError('S3 fixture admission is closed')
            self.connections.add(connection)
        return connection, address

    def process_request_thread(self, request, client_address):
        threading.current_thread().name = 'owned-s3-handler-' + str(threading.get_ident())
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.discard(request)

    def server_close(self):
        with self.connection_lock:
            self.closing = True
            owned = list(self.connections)
        # A relative socket timeout cannot retire a steady trickle. Shut down
        # every accepted socket before ThreadingMixIn joins its owned workers.
        for connection in owned:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        super().server_close()

    def handle_error(self, request, client_address):
        with self.lock:
            # Closing a Core owner can cancel an already accepted HTTP request.
            # Keep that observable without classifying peer retirement as an
            # API/protocol failure or printing the request's private contents.
            error = sys.exc_info()[1]
            key = 'client_disconnects' if isinstance(error, (BrokenPipeError, ConnectionResetError, TimeoutError)) or self.closing and isinstance(error, OSError) else 'handler_failures'
            self.counts[key] += 1


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *args):
        pass

    def send_body(self, status, body=b'', content_type='application/octet-stream'):
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def reject(self, status, code):
        with self.server.lock:
            self.server.counts['request_failures'] += 1
        body = ET.Element('Error')
        ET.SubElement(body, 'Code').text = code
        self.send_body(status, ET.tostring(body), 'application/xml')

    def request(self):
        if self.path == '/__fixture__/state' and self.command == 'GET':
            if not hmac.compare_digest(self.headers.get('X-Fixture-Control', ''), self.server.control):
                self.send_body(403)
            else:
                self.send_body(200, json.dumps(self.server.snapshot()).encode(), 'application/json')
            return
        with self.server.lock:
            self.server.counts['requests'] += 1
        if self.headers.get('Transfer-Encoding') or any(len(self.headers.get_all(name, [])) != 1 for name in ['Host', 'Authorization', 'X-Amz-Date', 'X-Amz-Content-Sha256']):
            self.reject(400, 'InvalidRequest')
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.reject(413, 'EntityTooLarge')
            return
        body = self.rfile.read(length)
        if len(body) != length:
            with self.server.lock:
                self.server.counts['incomplete_requests'] += 1
            self.send_body(400, b'<Error><Code>IncompleteBody</Code></Error>', 'application/xml')
            return
        if not verify_signature(self.command, self.path, dict(self.headers), body):
            with self.server.lock:
                self.server.counts['signature_failures'] += 1
            self.reject(403, 'SignatureDoesNotMatch')
            return
        target = urlsplit(self.path)
        base = '/' + BUCKET + '/'
        if not target.path.startswith(base):
            self.reject(404, 'NoSuchBucket')
            return
        key = unquote(target.path[len(base):], errors='strict')
        query = dict(parse_qsl(target.query, keep_blank_values=True))
        if self.command == 'GET' and query.get('list-type') == '2':
            self.list_objects(query)
            return
        if not key.startswith(self.server.folder + '/') or any(part in ('', '.', '..') for part in key.split('/')) or any(ord(c) < 32 for c in key):
            self.reject(400, 'InvalidObjectName')
            return
        with self.server.lock:
            if self.command == 'PUT':
                old = len(self.server.objects.get(key, b''))
                if self.server.total_bytes - old + len(body) > MAX_TOTAL or key not in self.server.objects and len(self.server.objects) >= MAX_OBJECTS:
                    status, payload = 507, b'<Error><Code>FixtureCapacity</Code></Error>'
                else:
                    self.server.objects[key] = body
                    self.server.total_bytes += len(body) - old
                    self.server.counts['PUT'] += 1
                    self.server.counts['put_bytes'] += len(body)
                    status, payload = 200, b''
            elif self.command == 'GET':
                self.server.counts['GET'] += 1
                if key in self.server.objects:
                    status, payload = 200, self.server.objects[key]
                    self.server.counts['get_bytes'] += len(payload)
                else:
                    status, payload = 404, b'<Error><Code>NoSuchKey</Code></Error>'
            elif self.command == 'DELETE':
                self.server.total_bytes -= len(self.server.objects.pop(key, b''))
                self.server.counts['DELETE'] += 1
                status, payload = 204, b''
            else:
                status, payload = 405, b''
        self.send_body(status, payload)

    def list_objects(self, query):
        prefix, delimiter = query.get('prefix', ''), query.get('delimiter', '')
        if not prefix.startswith(self.server.folder + '/') or delimiter not in ('', '/'):
            self.reject(400, 'InvalidPrefix')
            return
        try:
            maximum = int(query.get('max-keys', '1000'))
            start = int(query.get('continuation-token', '0'))
            assert 1 <= maximum <= 1000 and start >= 0
        except (ValueError, AssertionError):
            self.reject(400, 'InvalidPagination')
            return
        with self.server.lock:
            self.server.counts['LIST'] += 1
            entries = set()
            for key in self.server.objects:
                if key.startswith(prefix):
                    tail = key[len(prefix):]
                    if delimiter and delimiter in tail:
                        entries.add(('CommonPrefixes', prefix + tail.split(delimiter, 1)[0] + delimiter))
                    else:
                        entries.add(('Contents', key))
        entries = sorted(entries, key=lambda entry: entry[1])
        page = ET.Element('ListBucketResult')
        ET.SubElement(page, 'IsTruncated').text = 'true' if start + maximum < len(entries) else 'false'
        for kind, key in entries[start:start + maximum]:
            ET.SubElement(ET.SubElement(page, kind), 'Key' if kind == 'Contents' else 'Prefix').text = key
        if start + maximum < len(entries):
            ET.SubElement(page, 'NextContinuationToken').text = str(start + maximum)
        self.send_body(200, ET.tostring(page), 'application/xml')

    do_GET = request
    do_PUT = request
    do_DELETE = request


@contextmanager
def running_server(port=0, folder='acceptance'):
    server = FixtureServer(port=port, folder=folder)
    worker = threading.Thread(target=server.serve_forever, name='owned-s3-fixture')
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(3)
        if worker.is_alive():
            raise RuntimeError('Owned S3 fixture did not terminate')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir', type=Path, required=True)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--folder', default='acceptance')
    parser.add_argument('--seconds', type=int, default=180)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or not 1 <= args.seconds <= 1800:
        parser.error('Invalid port or bounded fixture lifetime')
    args.case_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.case_dir.chmod(0o700)
    ready, final = args.case_dir / 'ready.json', args.case_dir / 'final.json'
    if ready.exists() or final.exists():
        parser.error('Existing fixture evidence must be retained; choose a fresh case directory')
    stop = threading.Event()
    def terminate(_number, _frame):
        stop.set()
    previous = {sig: signal.signal(sig, terminate) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with running_server(args.port, args.folder) as server:
            info = {'endpoint': server.endpoint, 'folder': server.folder, 'bucket': BUCKET, 'region': REGION,
                    'access_key': ACCESS, 'secret_key': SECRET, 'control_token': server.control,
                    'pid': os.getpid(), 'started_monotonic_ns': time.monotonic_ns(), 'scope': 'synthetic_loopback_only'}
            with ready.open('x') as stream:
                json.dump(info, stream, indent=2)
            ready.chmod(0o600)
            print('READY: loopback S3 fixture; synthetic credentials are in the private readiness file', flush=True)
            stop.wait(args.seconds)
        snapshot = server.snapshot()
        with final.open('x') as stream:
            json.dump({'counts': snapshot, 'owned_server_closed': True}, stream, indent=2)
        final.chmod(0o600)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    main()
