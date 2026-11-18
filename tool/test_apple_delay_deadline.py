#!/usr/bin/env python3
"""Actual Apple delay sockets and provider reply deadlines.

Uses owned loopback peers and synthetic provider callbacks without a system VPN.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
from pathlib import Path
import re
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
SOCKET_CASES = ('http-connect', 'socks-connect', 'http-response', 'tls-record')
PROVIDER_CASES = ('provider-slow', 'provider-late', 'provider-default', 'provider-error')
CASES = SOCKET_CASES + PROVIDER_CASES

PROVIDER_FIXTURE = r'''
import OSLog

typealias FlutterResult = (Any?) -> Void
struct FlutterMethodCall { let arguments: Any? }
struct FlutterError { let code: String; let message: String; let details: Any? }
enum NativeLogPrivacy { static func operationError(_ error: Error) -> Error { error } }
let pluginLog = Logger(subsystem: "flutter-vless-fixture", category: "provider-delay")

enum ProviderStatus { case connected, reasserting }
struct FixtureProviderManager { let connection: Any }
struct FixtureProxyOnlyRunner {
    let isRunning = false
    func measureConnectedDelay(url: String) async -> Int { fatalError("unexpected proxy-only request") }
}

final class NETunnelProviderSession {
    let status = ProviderStatus.connected
    let replies = DispatchGroup()
    let expectedMessage: String
    let delay: TimeInterval

    init(message: String, delay: TimeInterval) {
        self.expectedMessage = message
        self.delay = delay
    }

    func sendProviderMessage(_ data: Data, responseHandler: @escaping (Data?) -> Void) throws {
        precondition(String(decoding: data, as: UTF8.self) == expectedMessage)
        if delay < 0 { throw NSError(domain: "fixture", code: 23) }
        replies.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            Thread.sleep(forTimeInterval: self.delay)
            responseHandler(Data("173".utf8))
            responseHandler(Data("174".utf8))
            self.replies.leave()
        }
    }
}

struct FixtureTimeoutQueue {
    let queue: DispatchQueue
    static func global(qos: DispatchQoS.QoSClass) -> Self { .init(queue: .global(qos: qos)) }
    func asyncAfter(deadline: DispatchTime, execute: @escaping @Sendable () -> Void) {
        // Force the late provider callback to reach the host before its timer
        // callback even though the monotonic deadline has already passed.
        let schedulingDelay: TimeInterval = CommandLine.arguments[1] == "provider-late" ? 2 : 0
        queue.asyncAfter(deadline: deadline + schedulingDelay, execute: execute)
    }
}

final class ProviderHost {
    let manager: FixtureProviderManager?
    let proxyOnlyRunner = FixtureProxyOnlyRunner()
    var packetTunnelManager: ProviderHost? { self }

    init(session: NETunnelProviderSession) {
        manager = FixtureProviderManager(connection: session)
    }

    func measureDelay(url: String, result: @escaping FlutterResult) {
        getConnectedServerDelay(call: FlutterMethodCall(arguments: ["url": url]), result: result)
    }
}

func exerciseProvider(_ scenario: String) {
    let sdkError = scenario == "provider-error"
    let ordinary = scenario == "provider-default" || sdkError
    let late = scenario == "provider-late"
    let url = "https://deadline.invalid/"
    let replyDelays: [String: TimeInterval] = [
        "provider-slow": 10.3, "provider-late": 11.7,
        "provider-default": 3.6, "provider-error": -1,
    ]
    let session = NETunnelProviderSession(message: ordinary ? "xray_runtime_state" : "xray_delay" + url,
                                          delay: replyDelays[scenario]!)
    let host = ProviderHost(session: session)
    let result = DispatchGroup()
    let started = ProcessInfo.processInfo.systemUptime
    result.enter()
    func finish(_ value: Int) {
        let elapsed = ProcessInfo.processInfo.systemUptime - started
        print("PROVIDER_RESULT=\(value) ELAPSED=\(elapsed)")
        result.leave()
    }
    if ordinary {
        Task {
            do {
                _ = try await host.sendProviderMessage(data: Data("xray_runtime_state".utf8))
                finish(0)
            } catch {
                let failure = error as NSError
                finish(failure.domain == (sdkError ? "fixture" : "VPN") ? failure.code : 0)
            }
        }
    } else {
        host.measureDelay(url: url) { finish(($0 as? Int) ?? 0) }
    }
    let watchdog = DispatchTime.now() + 14
    precondition(result.wait(timeout: watchdog) == .success, "missing provider result")
    precondition(session.replies.wait(timeout: watchdog) == .success, "missing provider callbacks")
    // Keep the successful delay request alive beyond its scheduled timeout so
    // CheckedContinuation also detects a second completion from that direction.
    if sdkError || (!ordinary && !late) {
        let keepAlive = sdkError ? 3.6 : 12.5
        let remaining = keepAlive - (ProcessInfo.processInfo.systemUptime - started)
        if remaining > 0 { Thread.sleep(forTimeInterval: remaining) }
    }
}
'''


def provider_methods(source):
    methods = []
    for signature in ('private func getConnectedServerDelay', 'func sendProviderMessage'):
        match = re.search(rf'^    {signature}\([^\n]*\n.*?^    }}$', source, re.M | re.S)
        assert match, signature
        method = match.group()
        if signature == 'func sendProviderMessage':
            assert method.count('DispatchQueue.global') == 1
            method = method.replace('DispatchQueue.global', 'FixtureTimeoutQueue.global')
        methods.append(method)
    return 'extension ProviderHost {\n' + '\n'.join(methods) + '\n}'


def run_provider_case(binary, case):
    child = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=15)
    matches = re.findall(r'^PROVIDER_RESULT=(-?\d+) ELAPSED=([\d.eE+-]+)$', child.stdout, re.M)
    assert child.returncode == 0 and len(matches) == 1, (case, child.stdout, child.stderr)
    (value, elapsed), = matches
    expected, lower, upper = {
        'provider-slow': (173, 10.1, 11.5),
        'provider-late': (-1, 11.5, 13),
        'provider-default': (3, 2.8, 4.5),
        'provider-error': (23, 0, 2),
    }[case]
    result = {'case': case, 'elapsed_seconds': float(elapsed), 'result': int(value)}
    assert result['result'] == expected and lower <= result['elapsed_seconds'] <= upper, result
    print('PASS', binary.parent.name, json.dumps(result), flush=True)
    return result


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
        plugin = source.with_name(source.name.removesuffix('_privacy'))
        methods = provider_methods((plugin / 'FlutterVlessPlugin.swift').read_text())
        main_source.write_text('import Foundation\n' + PROVIDER_FIXTURE + methods + '''
if CommandLine.arguments[1].hasPrefix("provider-") {
    exerciseProvider(CommandLine.arguments[1])
    exit(0)
}
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
        sources = [source / name for name in files] + [plugin / 'NativeOperationQueue.swift']
        binary = folder / 'probe'
        with (folder / 'compiler.log').open('w') as compiler_log:
            subprocess.run(['xcrun', 'swiftc', '-O', *map(str, sources),
                            str(main_source), '-o', str(binary)], check=True, timeout=90,
                           stdout=subprocess.DEVNULL, stderr=compiler_log)
        cases = [args.case] if args.case else CASES
        with ThreadPoolExecutor(max_workers=len(cases)) as pool:
            jobs = [pool.submit(run_provider_case if case in PROVIDER_CASES else run_case, binary, case)
                    for case in cases]
            results = [job.result() for job in jobs]
        report = {'platform': platform, 'scope': 'owned_loopback_no_vpn_or_core',
                  'results': results, 'source_sha256': {
                      str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in [*sources, plugin / 'FlutterVlessPlugin.swift']},
                  'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
