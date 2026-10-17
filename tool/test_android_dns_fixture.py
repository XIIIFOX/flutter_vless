import json
import socket
import threading
import time
import unittest
from android_dns_fixture import Server, Status


class StatusFixtureTest(unittest.TestCase):
    def test_fragmented_headers_complete_without_connection_reset(self):
        server = Server(('127.0.0.1', 0), Status)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=2) as client:
                client.sendall(b'GET /?phase=ready&run=123456789abc HTTP/1.1\r\n')
                time.sleep(.05)
                client.sendall(b'Host: fixture.test\r\nConnection: close\r\n\r\n')
                response = b''
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            headers, body = response.split(b'\r\n\r\n', 1)
            self.assertIn(b'200 OK', headers)
            self.assertTrue(any(event.get('run') == '123456789abc' for event in json.loads(body)))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


if __name__ == '__main__':
    unittest.main()
