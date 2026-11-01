#!/usr/bin/env python3
"""Real HTTP contract tests for the account-free S3 fixture; no Core or VPN."""
import hashlib
import hmac
import http.client
import errno
from contextlib import contextmanager
import importlib.util
import faulthandler
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest import mock
from urllib.parse import quote, urlsplit
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('s3_fixture', Path(__file__).with_name('xdrive_s3_fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


@contextmanager
def owned_thread_error_guard(test):
    """Join callers before exit; fail on owned worker errors without messages."""
    original = threading.excepthook
    failures = []

    def observe(args):
        if args.thread.name.startswith('owned-s3-'):
            if len(failures) < 16:
                failures.append(args.exc_type.__name__)
        else:
            original(args)

    threading.excepthook = observe
    try:
        yield
    finally:
        threading.excepthook = original
        test.assertEqual(failures, [], 'Owned fixture thread exception')


def sign(method, path, host, body=b'', secret=fixture.SECRET):
    headers = {'Host': host, 'X-Amz-Date': '20261101T000000Z', 'X-Amz-Content-Sha256': hashlib.sha256(body).hexdigest()}
    canonical_headers = f'host:{host}\nx-amz-content-sha256:{headers["X-Amz-Content-Sha256"]}\nx-amz-date:{headers["X-Amz-Date"]}\n'
    names = 'host;x-amz-content-sha256;x-amz-date'
    url = urlsplit(path)
    canonical = '\n'.join([method, url.path, url.query, canonical_headers, names, headers['X-Amz-Content-Sha256']])
    scope = '20261101/us-east-1/s3/aws4_request'
    text = '\n'.join(['AWS4-HMAC-SHA256', headers['X-Amz-Date'], scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ('AWS4' + secret).encode()
    for part in scope.split('/'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, text.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = f'AWS4-HMAC-SHA256 Credential={fixture.ACCESS}/{scope}, SignedHeaders={names}, Signature={signature}'
    return headers


class S3FixtureContract(unittest.TestCase):
    def test_owned_thread_failure_guard_rejects_hidden_errors_and_restores_hook(self):
        original = threading.excepthook

        def fail():
            raise RuntimeError('private background exception canary')

        with self.assertRaises(AssertionError) as rejected:
            with owned_thread_error_guard(self):
                worker = threading.Thread(target=fail, name='owned-s3-guard-negative-control')
                worker.start()
                worker.join(1)
                self.assertFalse(worker.is_alive())
        self.assertIs(threading.excepthook, original)
        self.assertIn('RuntimeError', str(rejected.exception))
        self.assertNotIn('private background exception canary', str(rejected.exception))
        delegated = []
        with mock.patch.object(threading, 'excepthook', side_effect=lambda args: delegated.append(args.exc_type)) as prior:
            with owned_thread_error_guard(self):
                worker = threading.Thread(target=fail, name='unrelated-guard-negative-control')
                worker.start()
                worker.join(1)
                self.assertFalse(worker.is_alive())
            self.assertIs(threading.excepthook, prior)
        self.assertEqual(delegated, [RuntimeError])
        self.assertIs(threading.excepthook, original)

    def test_closing_admitted_http_worker_only_accepts_closed_descriptor_errors(self):
        cases = [('permission', lambda: PermissionError(errno.EACCES, 'private closing exception canary'), True),
                 ('unexpected-os', lambda: OSError(errno.EIO, 'private closing exception canary'), True),
                 ('closed-descriptor', lambda: OSError(errno.EBADF, 'private closing exception canary'), False),
                 ('not-a-socket', lambda: OSError(errno.ENOTSOCK, 'private closing exception canary'), False)]
        if hasattr(errno, 'WSAENOTSOCK') and errno.WSAENOTSOCK != errno.ENOTSOCK:
            cases.append(('winsock-not-a-socket', lambda: OSError(errno.WSAENOTSOCK, 'private closing exception canary'), False))
        for name, make_error, fatal in cases:
            with self.subTest(case=name):
                entered, release = threading.Event(), threading.Event()
                loop_stopped, stop_ack = threading.Event(), threading.Event()
                errors = []
                original_loop = fixture.FixtureServer.serve_forever

                def observed_loop(server, *args, **kwargs):
                    try:
                        return original_loop(server, *args, **kwargs)
                    finally:
                        loop_stopped.set()

                class ClosingReply(fixture.FixtureHandler):
                    def send_body(self, status, *args, **kwargs):
                        if status == 404:
                            entered.set()
                            if not release.wait(3):
                                raise RuntimeError('Owned closing worker was not released')
                            raise make_error()
                        return super().send_body(status, *args, **kwargs)

                with mock.patch.object(fixture.FixtureServer, 'serve_forever', observed_loop), \
                        owned_thread_error_guard(self), fixture.running_server() as server:
                    server.RequestHandlerClass = ClosingReply

                    def admitted_client():
                        try:
                            self.request(server, 'GET', '/' + fixture.BUCKET + '/acceptance/closing')
                        except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError):
                            return
                        except Exception as error:
                            errors.append(type(error).__name__)
                        else:
                            errors.append('UnexpectedHTTPResponse')

                    def orderly_close():
                        if not loop_stopped.is_set():
                            server.shutdown()
                        if not loop_stopped.wait(2):
                            raise RuntimeError('Owned server loop did not stop before socket close')
                        stop_ack.set()
                        server.server_close()

                    client = threading.Thread(target=admitted_client, name='owned-s3-closing-client')
                    closer = threading.Thread(target=orderly_close, name='owned-s3-closing-server')
                    client.start()
                    try:
                        self.assertTrue(entered.wait(1), 'Signed request did not reach its real response worker')
                        closer.start()
                        # shutdown can need serve_forever's 0.5s poll. Observe
                        # that phase separately before timing close admission.
                        self.assertTrue(stop_ack.wait(2), 'Owned serve loop did not acknowledge shutdown')
                        until = time.monotonic() + 1
                        while not server.closing and time.monotonic() < until:
                            time.sleep(.01)
                        self.assertTrue(server.closing, 'Real server_close did not close admission')
                        release.set()
                    finally:
                        release.set()
                        if closer.ident is not None:
                            closer.join(3)
                        client.join(3)
                    self.assertFalse(closer.is_alive(), 'Owned server_close worker survived')
                    self.assertFalse(client.is_alive(), 'Owned admitted HTTP client survived')
                    self.assertEqual(errors, [])
                    counts = server.snapshot()
                    self.assertEqual((counts['handler_failures'], counts['client_disconnects']), (1, 0) if fatal else (0, 1))
                    self.assertEqual(counts['active_connections'], 0)
                    self.assertEqual(sum(counts['handler_exception_types'].values()), 1)
                    self.assertNotIn('private closing exception canary', str(counts))

    def test_aborted_http_worker_is_peer_retirement_without_hiding_auth_or_protocol_errors(self):
        class AbortReply(fixture.FixtureHandler):
            def send_body(self, status, *args, **kwargs):
                if status == 404 and self.path.endswith('/abort'):
                    raise ConnectionAbortedError(errno.ECONNABORTED, 'private worker exception canary')
                return super().send_body(status, *args, **kwargs)

        with fixture.running_server() as server:
            server.RequestHandlerClass = AbortReply
            path = '/' + fixture.BUCKET + '/acceptance/abort'
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request(server, 'GET', path)
            counts = server.snapshot()
            self.assertEqual((counts['handler_failures'], counts['client_disconnects']), (0, 1))
            self.assertEqual(counts['handler_exception_types'], {f'ConnectionAbortedError(errno={errno.ECONNABORTED})': 1})
            self.assertEqual(self.request(server, 'PUT', path, b'body',
                lambda h: h.update(Authorization='AWS4-HMAC-SHA256 forged'))[0], 403)
            self.assertEqual(self.request(server, 'GET', '/' + fixture.BUCKET + '/foreign/invalid')[0], 400)
            counts = server.snapshot()
            self.assertEqual((counts['signature_failures'], counts['request_failures'], counts['handler_failures']), (1, 2, 0))
            self.assertNotIn('private worker exception canary', str(counts))
        self.assertEqual(server.snapshot()['active_connections'], 0)

    def test_unexpected_http_worker_errors_remain_fatal_with_sanitized_diagnostics(self):
        class FailingReply(fixture.FixtureHandler):
            def send_body(self, status, *args, **kwargs):
                if status == 404:
                    if self.path.endswith('/permission'):
                        raise PermissionError(errno.EACCES, 'private worker exception canary')
                    raise RuntimeError('private worker exception canary')
                return super().send_body(status, *args, **kwargs)

        with fixture.running_server() as server:
            server.RequestHandlerClass = FailingReply
            for suffix in ('unexpected', 'permission'):
                with self.assertRaises(http.client.RemoteDisconnected):
                    self.request(server, 'GET', '/' + fixture.BUCKET + '/acceptance/' + suffix)
            counts = server.snapshot()
            self.assertEqual((counts['handler_failures'], counts['client_disconnects']), (2, 0))
            self.assertEqual(counts['handler_exception_types'], {'RuntimeError': 1, f'PermissionError(errno={errno.EACCES})': 1})
            self.assertNotIn('private worker exception canary', str(counts))
        self.assertEqual(server.snapshot()['active_connections'], 0)

    def test_numeric_loopback_fixture_performs_no_hostname_lookup(self):
        with mock.patch.object(socket, 'getfqdn', side_effect=AssertionError('Numeric loopback fixture attempted system DNS')):
            with fixture.running_server() as server:
                self.assertEqual(server.server_name, '127.0.0.1')

    def test_aws_reference_vector_and_tampering(self):
        # Official AWS GET Object reference; these are public documentation keys.
        access = 'AKIAIOSFODNN7EXAMPLE'
        secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        headers = {'Host': 'examplebucket.s3.amazonaws.com', 'Range': 'bytes=0-9', 'X-Amz-Date': '20130524T000000Z',
                   'X-Amz-Content-Sha256': hashlib.sha256(b'').hexdigest(),
                   'Authorization': 'AWS4-HMAC-SHA256 Credential=' + access + '/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'}
        self.assertTrue(fixture.verify_signature('GET', '/test.txt', headers, b'', access, secret))
        for name, value in [('Host', 'changed.invalid'), ('Range', 'bytes=1-9'), ('X-Amz-Date', '20130525T000000Z')]:
            self.assertFalse(fixture.verify_signature('GET', '/test.txt', {**headers, name: value}, b'', access, secret))
        for method, target, body in [('PUT', '/test.txt', b''), ('GET', '/other.txt', b''), ('GET', '/test.txt?extra=1', b''), ('GET', '/test.txt', b'wrong')]:
            self.assertFalse(fixture.verify_signature(method, target, headers, body, access, secret))

    def request(self, server, method, path, body=b'', alter=None):
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        headers = sign(method, path, f'127.0.0.1:{server.server_port}', body)
        if alter:
            alter(headers)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_full_crud_unicode_and_delimiter_listing(self):
        with fixture.running_server() as server:
            prefix = '/' + fixture.BUCKET + '/'
            data = b'\x00\x01binary\xff' * 100
            key = 'acceptance/streams/session/c2s/файл +%&'
            path = prefix + quote(key, safe='/')
            self.assertEqual(self.request(server, 'PUT', path, data)[0], 200)
            self.assertEqual(self.request(server, 'GET', path), (200, data))
            status, body = self.request(server, 'GET', prefix + '?delimiter=%2F&list-type=2&max-keys=1000&prefix=acceptance%2Fstreams%2F')
            self.assertEqual(status, 200)
            xml = ET.fromstring(body)
            self.assertEqual([element.text for element in xml.findall('CommonPrefixes/Prefix')], ['acceptance/streams/session/'])
            self.assertEqual(xml.findall('Contents'), [])
            status, body = self.request(server, 'GET', prefix + '?delimiter=%2F&list-type=2&max-keys=1000&prefix=acceptance%2Fstreams%2Fsession%2Fc2s%2F')
            self.assertEqual(status, 200)
            self.assertEqual([element.text for element in ET.fromstring(body).findall('Contents/Key')], [key])
            self.assertEqual(self.request(server, 'DELETE', path)[0], 204)
            self.assertEqual(self.request(server, 'GET', path)[0], 404)
            counts = server.snapshot()
            self.assertEqual((counts['PUT'], counts['DELETE'], counts['LIST']), (1, 1, 2))
            self.assertEqual((counts['objects'], counts['stored_bytes'], counts['signature_failures']), (0, 0, 0))

    def test_authentication_refusal_does_not_store_a_body(self):
        with fixture.running_server() as server:
            path = '/' + fixture.BUCKET + '/acceptance/object'
            self.assertEqual(self.request(server, 'PUT', path, b'body', lambda h: h.update(Authorization='AWS4-HMAC-SHA256 forged'))[0], 403)
            counts = server.snapshot()
            self.assertEqual((counts['objects'], counts['signature_failures']), (0, 1))

    def test_prefix_boundary_and_delete_idempotence(self):
        with fixture.running_server() as server:
            prefix = '/' + fixture.BUCKET + '/'
            self.assertEqual(self.request(server, 'PUT', prefix + 'foreign/object', b'x')[0], 400)
            self.assertEqual(self.request(server, 'GET', prefix + '?list-type=2&prefix=foreign%2F')[0], 400)
            self.assertEqual(self.request(server, 'PUT', prefix + 'acceptance/%2e%2e/object', b'x')[0], 400)
            self.assertEqual(self.request(server, 'DELETE', prefix + 'acceptance/missing')[0], 204)

    def test_listing_pages_do_not_skip_or_repeat_objects(self):
        with fixture.running_server() as server:
            prefix = '/' + fixture.BUCKET + '/'
            for key in ['a', 'b', 'c']:
                self.assertEqual(self.request(server, 'PUT', prefix + 'acceptance/' + key, key.encode())[0], 200)
            query = '?list-type=2&max-keys=2&prefix=acceptance%2F'
            status, body = self.request(server, 'GET', prefix + query)
            self.assertEqual(status, 200)
            first = ET.fromstring(body)
            self.assertEqual(first.findtext('IsTruncated'), 'true')
            self.assertEqual(first.findtext('NextContinuationToken'), '2')
            status, body = self.request(server, 'GET', prefix + '?continuation-token=2&list-type=2&max-keys=2&prefix=acceptance%2F')
            self.assertEqual(status, 200)
            second = ET.fromstring(body)
            self.assertEqual(second.findtext('IsTruncated'), 'false')
            self.assertEqual([e.text for page in [first, second] for e in page.findall('Contents/Key')], ['acceptance/a', 'acceptance/b', 'acceptance/c'])

    def test_capacity_refuses_before_mutating_existing_object(self):
        old = fixture.MAX_TOTAL
        fixture.MAX_TOTAL = 4
        try:
            with fixture.running_server() as server:
                path = '/' + fixture.BUCKET + '/acceptance/object'
                self.assertEqual(self.request(server, 'PUT', path, b'good')[0], 200)
                self.assertEqual(self.request(server, 'PUT', path, b'too-long')[0], 507)
                self.assertEqual(self.request(server, 'GET', path), (200, b'good'))
        finally:
            fixture.MAX_TOTAL = old

    def test_listener_and_owned_threads_close_without_leaving_objects_on_disk(self):
        with fixture.running_server() as server:
            port = server.server_port
            self.assertEqual(server.server_address[0], '127.0.0.1')
        self.assertFalse(any(t.name == 'owned-s3-fixture' and t.is_alive() for t in threading.enumerate()))
        with self.assertRaises(OSError):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
            try:
                connection.connect()
            finally:
                connection.close()

    def test_shutdown_closes_an_owned_trickling_incomplete_body(self):
        stop = threading.Event()
        peer, worker = None, None
        started = None
        try:
            with fixture.running_server() as server:
                peer = socket.create_connection(('127.0.0.1', server.server_port), timeout=1)
                # A steady byte stream defeats a timeout that restarts on each
                # recv. Stop the negative control after four seconds so even
                # the old implementation can fail and retire its fixture.
                peer.sendall((f'PUT /{fixture.BUCKET}/acceptance/partial HTTP/1.1\r\n'
                              f'Host: 127.0.0.1:{server.server_port}\r\n'
                              'Authorization: AWS4-HMAC-SHA256 incomplete\r\n'
                              'X-Amz-Date: 20261101T000000Z\r\n'
                              'X-Amz-Content-Sha256: incomplete\r\n'
                              'Content-Length: 100000\r\n\r\nx').encode())
                def trickle():
                    until = time.monotonic() + 4
                    while not stop.wait(.05) and time.monotonic() < until:
                        try:
                            peer.sendall(b'x')
                        except OSError:
                            return
                worker = threading.Thread(target=trickle, name='owned-s3-trickling-peer')
                worker.start()
                until = time.monotonic() + 1
                while server.snapshot()['requests'] != 1 and time.monotonic() < until:
                    time.sleep(.01)
                self.assertEqual(server.snapshot()['requests'], 1, 'Incomplete body never reached its owned HTTP handler')
                started = time.monotonic()
            elapsed = time.monotonic() - started
            peer.settimeout(1)
            try:
                while peer.recv(1024):
                    pass
            except (ConnectionResetError, ConnectionAbortedError):
                # Winsock can report WSAECONNABORTED (10053) when the owned
                # server shuts down a partial request. A typed reset/abort is
                # closure; a timeout or arbitrary message remains a failure.
                pass
            self.assertLess(elapsed, 2.5, 'Server shutdown renewed its body timeout while the owned peer trickled')
            self.assertEqual(server.snapshot()['active_connections'], 0)
            self.assertEqual(server.snapshot()['handler_failures'], 0)
            self.assertFalse(any(t.name.startswith('owned-s3-handler-') and t.is_alive() for t in threading.enumerate()))
        finally:
            stop.set()
            if peer is not None:
                peer.close()
            if worker is not None:
                worker.join(2)
                self.assertFalse(worker.is_alive(), 'Owned trickling peer survived fixture cleanup')


if __name__ == '__main__':
    faulthandler.dump_traceback_later(12)
    try:
        unittest.main(verbosity=2)
    finally:
        faulthandler.cancel_dump_traceback_later()
