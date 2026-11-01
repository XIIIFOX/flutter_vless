#!/usr/bin/env python3
"""Actual shared Swift delay sockets against owned, slow loopback peers.

No Core, native SDK, system VPN, public network or credentials are used.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
from pathlib import Path
import socket
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/apple_delay_deadline'
PLATFORMS = {
    'ios': ROOT / 'ios/flutter_vless/Sources/flutter_vless_privacy',
    'macos': ROOT / 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy',
}
CASES = ('http-connect', 'socks-connect', 'http-response', 'tls-record')


def exact(connection, length):
    result = b''
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise EOFError('owned client closed')
        result += part
    return result


def header(connection):
    result = b''
    while not result.endswith(b'\r\n\r\n'):
        result += exact(connection, 1)
        assert len(result) < 8192
    return result


def run_case(binary, case):
    stop, drained, observed = threading.Event(), threading.Event(), threading.Event()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(2)
    failures = []

    def serve():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(2)
                if case == 'http-connect':
                    assert header(connection).startswith(b'CONNECT deadline.invalid:80 ')
                    observed.set()
                    for byte in b'HTTP/1.1 200 Connection Established\r\n\r\n':
                        connection.sendall(bytes([byte]))
                        if stop.wait(.6):
                            return
                else:
                    assert exact(connection, 3) == b'\x05\x01\x02'
                    connection.sendall(b'\x05\x02')
                    assert exact(connection, 1) == b'\x01'
                    assert exact(connection, exact(connection, 1)[0]) == b'deadline-user'
                    assert exact(connection, exact(connection, 1)[0]) == b'deadline-password'
                    connection.sendall(b'\x01\x00')
                    assert exact(connection, 4) == b'\x05\x01\x00\x03'
                    assert exact(connection, exact(connection, 1)[0]) == b'deadline.invalid'
                    exact(connection, 2)
                    observed.set()
                    reply = b'\x05\x00\x00\x04' + b'\x00' * 18
                    if case == 'socks-connect':
                        for byte in reply:
                            connection.sendall(bytes([byte]))
                            if stop.wait(.6):
                                return
                    else:
                        connection.sendall(reply)
                        if case == 'http-response':
                            assert header(connection).startswith(b'GET / HTTP/1.1\r\n')
                            if stop.wait(9):
                                return
                            connection.sendall(b'HTTP/1.1 ')
                        else:
                            assert connection.recv(4096), 'TLS ClientHello absent'
                            if stop.wait(7):
                                return
                            connection.sendall(b'\x16')
                        # Partial input arrived shortly before the total limit.
                        # A fresh eight-second recv timeout would exceed it.
                        connection.settimeout(12)
                        while connection.recv(1024):
                            pass
        except (EOFError, BrokenPipeError, ConnectionResetError):
            pass  # Expected bounded client retirement.
        except Exception as error:
            failures.append(repr(error))
        finally:
            drained.set()

    worker = threading.Thread(target=serve, name='owned-delay-' + case)
    worker.start()
    mode = 'http' if case == 'http-connect' else 'socks'
    scheme = 'https' if case == 'tls-record' else 'http'
    started = time.monotonic()
    child = subprocess.Popen([str(binary), mode, str(listener.getsockname()[1]),
                              scheme + '://deadline.invalid/'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        try:
            stdout, stderr = child.communicate(timeout=12.5)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.terminate()
            stdout, stderr = child.communicate(timeout=2)
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        listener.close()
        worker.join(2.5)
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=2)
    result = {'case': case, 'elapsed_seconds': elapsed, 'exit': child.returncode,
              'child_timeout': timed_out, 'peer_observed': observed.is_set(),
              'worker_drained': drained.is_set() and not worker.is_alive(),
              'result': stdout.decode().strip(), 'errors': failures}
    (binary.parent / (case + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    assert observed.is_set() and not failures, result
    assert not timed_out and child.returncode == 0 and elapsed < 11.5, result
    # Reaching a peer then failing immediately is not a deadline pass. Connect
    # owns an eight-second phase; response/TLS consumes the shared ten seconds.
    assert elapsed >= (7 if case.endswith('connect') else 9), result
    assert result['worker_drained'] and stdout.strip() == b'DELAY_RESULT=-1', result
    print('PASS', binary.parent.name, json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=list(PLATFORMS))
    parser.add_argument('--case', choices=CASES)
    args = parser.parse_args()
    selected = {args.platform: PLATFORMS[args.platform]} if args.platform else PLATFORMS
    for platform, source in selected.items():
        folder = OUT / platform
        folder.mkdir(parents=True, exist_ok=True)
        main_source = folder / 'main.swift'
        main_source.write_text('''import Foundation
let credentials = try LocalProxyCredentials(username: "deadline-user", password: "deadline-password")
let group = DispatchGroup()
group.enter()
LocalProxyDelayClient.measure(url: URL(string: CommandLine.arguments[3])!,
  port: Int(CommandLine.arguments[2])!, credentials: credentials, proxyProtocol: CommandLine.arguments[1]) {
    print("DELAY_RESULT=\\($0)"); group.leave()
}
if group.wait(timeout: .now() + 12) != .success { print("DELAY_WORKER_EXCEEDED_TOTAL_DEADLINE"); exit(2) }
''')
        files = ['LocalProxyAccessPolicy.swift', 'XrayServiceTags.swift', 'LocalProxyIOBudget.swift',
                 'LocalSOCKS5Client.swift', 'LocalHTTPProxyClient.swift', 'LocalProxyDelayClient.swift']
        binary = folder / 'probe'
        with (folder / 'compiler.log').open('w') as compiler_log:
            subprocess.run(['xcrun', 'swiftc', '-O', *[str(source / name) for name in files],
                            str(main_source), '-o', str(binary)], check=True, timeout=90,
                           stdout=subprocess.DEVNULL, stderr=compiler_log)
        cases = [args.case] if args.case else CASES
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda case: run_case(binary, case), cases))
        report = {'platform': platform, 'scope': 'owned_loopback_no_vpn_or_core',
                  'results': results, 'source_sha256': {
                      str((source / name).relative_to(ROOT)): hashlib.sha256((source / name).read_bytes()).hexdigest()
                      for name in files},
                  'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
