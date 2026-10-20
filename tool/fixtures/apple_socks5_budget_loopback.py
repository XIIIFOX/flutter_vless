#!/usr/bin/env python3
"""Four CI-only loopback cases for actual Darwin budget I/O. No Core/SDK."""
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time


def exact(connection, count):
    data = bytearray()
    while len(data) < count:
        value = connection.recv(count - len(data))
        if not value:
            raise AssertionError('incomplete synthetic frame')
        data.extend(value)
    return bytes(data)


class OwnedServer:
    def __init__(self, kind, nonce):
        self.kind, self.nonce, self.failure, self.connection = kind, nonce, None, None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.settimeout(2)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, name='owned-budget-' + kind)

    def serve(self):
        try:
            connection, peer = self.listener.accept()
            self.connection = connection
            connection.settimeout(1.5)
            assert peer[0] == '127.0.0.1'
            assert exact(connection, 3) == b'\x05\x01\x02'
            if self.kind == 'drip':
                connection.sendall(b'\x05')
                time.sleep(0.5)
                assert connection.recv(1) == b''  # deadline closed the owned FD, no authentication retry
                return
            if self.kind == 'downgrade':
                connection.sendall(b'\x05\x00')
                assert connection.recv(1) == b''  # configured credentials never fall back
                return
            connection.sendall(b'\x05\x02')
            assert exact(connection, 2) == b'\x01\x0b'
            assert exact(connection, 11) == b'budget-user'
            assert exact(connection, 1) == b'\x0f'
            assert exact(connection, 15) == b'budget-password'
            connection.sendall(b'\x01\x00')
            assert exact(connection, 5) == b'\x05\x01\x00\x03\x0d'
            assert exact(connection, 13) == b'probe.invalid'
            assert exact(connection, 2) == (18083).to_bytes(2, 'big')
            connection.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
            if self.kind == 'positive':
                assert exact(connection, 32) == self.nonce.encode('ascii')
                connection.sendall(b'reply:' + self.nonce.encode('ascii'))
            assert connection.recv(1) == b''  # client cancellation or completed positive closes FD
        except BaseException as error:
            self.failure = type(error).__name__
        finally:
            if self.connection is not None:
                self.connection.close()

    def close(self):
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        self.listener.close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), 'owned server did not exit'


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('CI_ONLY: real loopback budget fixture was not run')
    assert len(sys.argv) == 2
    binary = Path(sys.argv[1]).resolve()
    for kind in ('positive', 'drip', 'cancel', 'downgrade'):
        nonce = secrets.token_hex(16)
        server = OwnedServer(kind, nonce)
        server.thread.start()
        try:
            result = subprocess.run([str(binary), kind, str(server.port), nonce], capture_output=True, text=True, timeout=4)
            assert result.returncode == 0, 'budget loopback client failed: ' + kind
            assert result.stdout.splitlines() == ['APPLE_SOCKS5_BUDGET_LOOPBACK_CASE_PASS=' + kind]
            server.thread.join(timeout=2)
            assert not server.thread.is_alive() and server.failure is None, 'budget loopback server failed: ' + kind
        finally:
            server.close()
    print('APPLE_SOCKS5_BUDGET_LOOPBACK_PASS=4')


if __name__ == '__main__':
    main()
