"""Controlled native-upstream fixture tests; no Xray or OS DNS execution."""
import contextlib
import json
import socket
import struct
import threading
import time
import unittest
from unittest import mock

import android_dns_fixture as fixture


def question(name, kind=1):
    labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.'))
    return struct.pack('!HHHHHH', 0x6d42, 0x0100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('!HH', kind, 1)


class NativeFixtureTests(unittest.TestCase):
    def setUp(self):
        with fixture.LOCK:
            self.before = list(fixture.EVENTS)
            fixture.EVENTS.clear()

    def tearDown(self):
        with fixture.LOCK:
            fixture.EVENTS[:] = self.before

    @contextlib.contextmanager
    def server(self, handler, transport='native-default'):
        server = fixture.Server(('127.0.0.1', 0), handler)
        server.transport = transport
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)
            self.assertFalse(worker.is_alive())

    def connect(self, server):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(server.server_address)
        return client

    def test_numeric_answers_never_call_platform_dns(self):
        for name, kind, count, code in [
            ('default-123456789abc.dns-audit.invalid', 1, 1, 0),
            ('caller-123456789abc.dns-audit.invalid', 28, 0, 0),
            ('default-123456789abc.dns-audit.invalid', 16, 0, 5),
            ('unrelated.external.invalid', 1, 0, 5),
        ]:
            with self.subTest(name=name, kind=kind), mock.patch.object(fixture.socket, 'getaddrinfo', side_effect=AssertionError('OS DNS forbidden')):
                query = question(name, kind)
                answer = fixture.native_answer(query, 'native-default', 18284)
                self.assertEqual(answer[:2], query[:2])
                self.assertEqual(answer[3] & 15, code)
                self.assertEqual(int.from_bytes(answer[6:8], 'big'), count)
                if count:
                    self.assertEqual(answer[-4:], socket.inet_aton('10.0.2.2'))

    def test_malformed_frames_are_bounded_and_refused(self):
        good = question('default-123456789abc.dns-audit.invalid')
        cases = [b'', good[:16], b'x' * 4097,
                 good[:4] + b'\0\2' + good[6:],
                 good[:12] + b'\xc0\x0c' + struct.pack('!HH', 1, 1),
                 good[:-1], good[:2] + b'\x81\x00' + good[4:]]
        for query in cases:
            with self.subTest(size=len(query)), self.assertRaises((ValueError, UnicodeError)):
                fixture.native_question(query)

    def test_actual_tcp_reads_fragmented_length_and_query(self):
        with self.server(fixture.NativeTCP) as server, self.connect(server) as client, \
                mock.patch.object(fixture.socket, 'getaddrinfo', side_effect=AssertionError('OS DNS forbidden')):
            query = question('default-123456789abc.dns-audit.invalid')
            frame = len(query).to_bytes(2, 'big') + query
            client.sendall(frame[:1])
            client.sendall(frame[1:8])
            client.sendall(frame[8:])
            size = int.from_bytes(fixture.exact(client, 2), 'big')
            answer = fixture.exact(client, size)
            self.assertEqual(answer[-4:], socket.inet_aton('10.0.2.2'))
        self.assertEqual([row['transport'] for row in fixture.EVENTS], ['native-default'])

    def test_stalled_socket_records_real_eof_not_timeout(self):
        with self.server(fixture.NativeTCP) as server:
            with self.connect(server) as client:
                query = question('stall-123456789abc.dns-audit.invalid')
                client.sendall(len(query).to_bytes(2, 'big') + query)
                deadline = time.monotonic() + 2
                while not any(row['event'] == 'native-stall-start' for row in fixture.EVENTS):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.005)
            deadline = time.monotonic() + 2
            while not any(row['event'] == 'native-stall-eof' for row in fixture.EVENTS):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.005)
        self.assertFalse(any(row['event'] == 'native-stall-timeout' for row in fixture.EVENTS))

    def test_status_is_run_scoped_and_legacy_status_stays_array(self):
        for run, transport in [('123456789abc', 'native-default'), ('123456789abc', 'native-caller'), ('987654321abc', 'native-default')]:
            fixture.native_answer(question(f'default-{run}.dns-audit.invalid'), transport, 18284)
        with self.server(fixture.Status) as server:
            def fetch(path):
                with self.connect(server) as client:
                    client.sendall(f'GET {path} HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n'.encode())
                    data = b''
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    return json.loads(data.split(b'\r\n\r\n', 1)[1])
            result = fetch('/native-preview?run=123456789abc')
            self.assertEqual(result['native_default'], 1)
            self.assertEqual(result['native_caller'], 1)
            self.assertEqual(result['native_stall_eof'], 0)
            self.assertEqual(len(result['queries']), 2)
            self.assertIsInstance(fetch('/'), list)


if __name__ == '__main__':
    unittest.main()
