"""Pure HTTP fixture failure-path controls; never creates a socket or server."""
import errno
import io
import json
from types import SimpleNamespace
import unittest
from unittest import mock

import android_dns_fixture as fixture


class FakeSocket:
    def __init__(self, incoming=b""):
        self.incoming = io.BytesIO(incoming)
        self.sent = bytearray()

    def settimeout(self, _seconds):
        pass

    def recv(self, count):
        return self.incoming.read(count)

    def sendall(self, value):
        self.sent.extend(value)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


class HttpFixtureDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.records = []
        self.events = mock.patch.object(fixture, "event", side_effect=lambda **value: self.records.append(value))
        self.events.start()
        self.addCleanup(self.events.stop)
        self.no_socket = mock.patch.object(fixture.socket, "socket", side_effect=AssertionError("Pure controls must not open sockets"))
        self.no_socket.start()
        self.addCleanup(self.no_socket.stop)
        self.counter = mock.patch.object(fixture, "HTTP_STAGE_COUNT", 0)
        self.counter.start()
        self.addCleanup(self.counter.stop)

    def handle(self, client, transport="http"):
        handler = object.__new__(fixture.Handler)
        handler.request = client
        handler.server = SimpleNamespace(transport=transport)
        handler.handle()

    def stages(self):
        return [record["stage"] for record in self.records if record.get("event") == "proxy-stage"]

    def test_connect_refusal_has_safe_stage_without_repeating_or_exposing_error(self):
        client = FakeSocket(b"CONNECT 10.0.2.2:18283 HTTP/1.1\r\nHost: hidden-value\r\n\r\n")
        with mock.patch.object(fixture.socket, "create_connection", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "hidden-error")) as connect:
            self.handle(client)
        self.assertEqual(1, connect.call_count)
        self.assertEqual(b"HTTP/1.1 200 Connection Established\r\n\r\n", bytes(client.sent))
        self.assertEqual(["accepted", "connect-attempt", "connect-error"], self.stages())
        failed = self.records[-1]
        self.assertEqual("status", failed["destination_class"])
        self.assertEqual("ConnectionRefusedError", failed["error_class"])
        self.assertEqual(errno.ECONNREFUSED, failed["errno"])
        self.assertNotIn("hidden", json.dumps(self.records))
        self.assertNotIn("10.0.2.2", json.dumps(self.records))

    def test_client_eof_records_forwarded_byte_counts_and_keeps_relay_bytes(self):
        payload = b"private-payload"
        client = FakeSocket(b"CONNECT 10.0.2.2:18283 HTTP/1.1\r\n\r\n" + payload)
        upstream = FakeSocket()
        with mock.patch.object(fixture.socket, "create_connection", return_value=upstream) as connect, mock.patch.object(fixture.select, "select", side_effect=[([client], [], []), ([client], [], [])]):
            self.handle(client)
        self.assertEqual(1, connect.call_count)
        self.assertEqual(payload, bytes(upstream.sent))
        self.assertEqual(["accepted", "connect-attempt", "connect-success", "relay-eof"], self.stages())
        self.assertEqual("client", self.records[-1]["side"])
        self.assertEqual(len(payload), self.records[-1]["client_bytes"])
        self.assertEqual(0, self.records[-1]["upstream_bytes"])
        self.assertNotIn(payload.decode(), json.dumps(self.records))

    def test_upstream_eof_preserves_response_and_reports_its_direction(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]"
        client = FakeSocket(b"CONNECT 10.0.2.2:18283 HTTP/1.1\r\n\r\n")
        upstream = FakeSocket(response)
        with mock.patch.object(fixture.socket, "create_connection", return_value=upstream), mock.patch.object(fixture.select, "select", side_effect=[([upstream], [], []), ([upstream], [], [])]):
            self.handle(client)
        self.assertEqual(b"HTTP/1.1 200 Connection Established\r\n\r\n" + response, bytes(client.sent))
        self.assertEqual(["accepted", "connect-attempt", "connect-success", "relay-eof"], self.stages())
        self.assertEqual("relay-eof", self.records[-1]["stage"])
        self.assertEqual("upstream", self.records[-1]["side"])
        self.assertEqual(0, self.records[-1]["client_bytes"])
        self.assertEqual(len(response), self.records[-1]["upstream_bytes"])

    def test_incomplete_connect_reports_handshake_eof_without_upstream_attempt(self):
        with mock.patch.object(fixture.socket, "create_connection") as connect:
            self.handle(FakeSocket(b"CONNECT incomplete"))
        connect.assert_not_called()
        self.assertEqual(["accepted", "handshake-error"], self.stages())
        self.assertEqual("EOFError", self.records[-1]["error_class"])

    def test_non_http_path_does_not_add_diagnostic_or_change_its_failure(self):
        # Existing SOCKS no-auth CONNECT to the controlled status endpoint.
        client = FakeSocket(b"\x05\x01\x00\x05\x01\x00\x01\x0a\x00\x02\x02" + (18283).to_bytes(2, "big"))
        with mock.patch.object(fixture.socket, "create_connection", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "ignored")) as connect:
            self.handle(client, "socks")
        self.assertEqual(1, connect.call_count)
        self.assertEqual(b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", bytes(client.sent))
        self.assertEqual([], self.records)

    def test_relay_error_reports_class_and_completed_bytes_without_error_text(self):
        client = FakeSocket(b"CONNECT 10.0.2.2:18283 HTTP/1.1\r\n\r\nprivate-body")
        upstream = FakeSocket()
        with mock.patch.object(upstream, "sendall", side_effect=BrokenPipeError(errno.EPIPE, "private-error")), mock.patch.object(fixture.socket, "create_connection", return_value=upstream), mock.patch.object(fixture.select, "select", return_value=([client], [], [])):
            self.handle(client)
        self.assertEqual("relay-error", self.records[-1]["stage"])
        self.assertEqual("BrokenPipeError", self.records[-1]["error_class"])
        self.assertEqual(errno.EPIPE, self.records[-1]["errno"])
        self.assertEqual(0, self.records[-1]["client_bytes"])
        self.assertNotIn("private", json.dumps(self.records))

    def test_diagnostics_are_bounded_independently_of_protocol_work(self):
        with mock.patch.object(fixture, "HTTP_STAGE_LIMIT", 3):
            for _ in range(10):
                fixture.http_stage("http", "accepted")
        self.assertEqual(3, len(self.records))
        self.assertEqual(3, fixture.HTTP_STAGE_COUNT)

    def test_diagnostic_write_failure_does_not_replace_original_connect_failure(self):
        original = ConnectionRefusedError(errno.ECONNREFUSED, "original-private-message")
        with mock.patch.object(fixture, "event", side_effect=BrokenPipeError(errno.EPIPE, "diagnostic-private-message")), mock.patch.object(fixture.socket, "create_connection", side_effect=original):
            with self.assertRaises(ConnectionRefusedError) as caught:
                fixture.tunnel(FakeSocket(), "10.0.2.2", 18283, "http")
        self.assertIs(original, caught.exception)


if __name__ == "__main__":
    unittest.main()
