import json
import socket
import threading
import unittest

from android_protection_fixture import DirectProbe, Server, DIRECT_EVENTS, DIRECT_LOCK


class DirectOriginTest(unittest.TestCase):
    def test_fresh_browser_marker_and_exact_host_path_record(self):
        server = Server(('127.0.0.1', 0), DirectProbe)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            def request(path, fragmented=False, method='GET'):
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall((method + ' ' + path + ' HTTP/1.1\r\n').encode())
                    if fragmented:
                        client.sendall(b'Host: fresh.dns-')
                        client.settimeout(.02)
                        with self.assertRaises(socket.timeout):
                            client.recv(1)
                        client.settimeout(2)
                        client.sendall(b'audit.invalid:18083\r\n')
                    else:
                        client.sendall(b'Host: fresh.dns-audit.invalid:18083\r\n')
                    client.sendall(b'Connection: close\r\n\r\n')
                    parts = []
                    while chunk := client.recv(8192):
                        parts.append(chunk)
                header, body = b''.join(parts).split(b'\r\n\r\n', 1)
                self.assertIn(b'Cache-Control: no-store', header)
                length = len(body) if method == 'GET' else len(b'flutter-vless-direct-bypass')
                self.assertIn(b'Content-Length: ' + str(length).encode(), header)
                return body
            with DIRECT_LOCK:
                DIRECT_EVENTS.clear()
            run = '123456789abc'
            path = '/native-tun?run=' + run
            self.assertIn(('NATIVE_TUN_BROWSER_' + run).encode(), request(path, True))
            rows = json.loads(request('/native-tun-events?run=' + run))
            self.assertEqual(rows, [dict(event='native-tun-http', host='fresh.dns-audit.invalid:18083', path=path, run=run)])
            self.assertEqual(json.loads(request('/native-tun-events?run=abcdef123456')), [])
            self.assertEqual(request('/ordinary-readiness'), b'flutter-vless-direct-bypass')
            self.assertEqual(request('/ordinary-readiness', method='HEAD'), b'')
            self.assertEqual(request('/native-tun?run=' + run, method='HEAD'), b'')
            self.assertEqual(len(json.loads(request('/native-tun-events?run=' + run))), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
            self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
