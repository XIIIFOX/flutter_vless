#!/usr/bin/env python3
"""Measure first verified HTTP over synthetic Xray peers without system VPN settings."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from typing import NamedTuple
import uuid

VERSION = '26.11.9'
LOOPBACK = '127.0.0.1'
SNI = 'protocol-fixture.invalid'
DESTINATION = '198.51.100.17'
TIMEOUT = 8


class Case(NamedTuple):
    name: str
    protocol: str
    network: str
    alpn: list
    stream: dict
    socket_type: int


CASES = (
    Case('vless-raw-tls', 'vless', 'raw', ['http/1.1'], {}, socket.SOCK_STREAM),
    Case('vless-raw-reality-vision', 'vless', 'raw', [], {}, socket.SOCK_STREAM),
    Case('vless-websocket-tls', 'vless', 'ws', ['http/1.1'],
         {'wsSettings': {'path': '/fixture'}}, socket.SOCK_STREAM),
    Case('vless-grpc-tls', 'vless', 'grpc', ['h2'],
         {'grpcSettings': {'serviceName': 'fixture'}}, socket.SOCK_STREAM),
    Case('vless-httpupgrade-tls', 'vless', 'httpupgrade', ['http/1.1'],
         {'httpupgradeSettings': {'path': '/fixture'}}, socket.SOCK_STREAM),
    Case('vless-xhttp-h2-tls', 'vless', 'xhttp', ['h2'],
         {'xhttpSettings': {'path': '/fixture', 'mode': 'stream-one'}}, socket.SOCK_STREAM),
    Case('vless-xhttp-h3-tls', 'vless', 'xhttp', ['h3'],
         {'xhttpSettings': {'path': '/fixture', 'mode': 'packet-up'}}, socket.SOCK_DGRAM),
    Case('vmess-aead-raw', 'vmess', 'raw', [], {}, socket.SOCK_STREAM),
    Case('trojan-raw-tls', 'trojan', 'raw', ['http/1.1'], {}, socket.SOCK_STREAM),
    Case('shadowsocks-aead', 'shadowsocks', 'raw', [], {}, socket.SOCK_STREAM),
    Case('shadowsocks-2022', 'shadowsocks', 'raw', [], {}, socket.SOCK_STREAM),
    Case('hysteria2', 'hysteria', 'hysteria', ['h3'],
         {'hysteriaSettings': {'version': 2}}, socket.SOCK_DGRAM),
    Case('wireguard-userspace', 'wireguard', 'raw', [], {}, socket.SOCK_DGRAM),
)


def child_env():
    return {
        key: value for key, value in os.environ.items()
        if not key.lower().startswith(('xray', 'flutter_vless_'))
        and key.upper() not in {'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                                'NO_PROXY', 'SSLKEYLOGFILE', 'GODEBUG', 'GOTRACEBACK'}
    }


def command(core, *arguments):
    result = subprocess.run([str(core), *arguments], env=child_env(),
                            capture_output=True, timeout=TIMEOUT, check=True)
    return result.stdout.decode('utf-8')


def certificate(core, server_name=SNI, authority=False):
    flags = ['-domain', server_name, '-name', server_name, '-expire', '1h']
    if authority:
        flags.append('-ca')
    cert = json.loads(command(core, 'tls', 'cert', *flags))
    leaf = ssl.PEM_cert_to_DER_cert('\n'.join(cert['certificate']))
    return cert, hashlib.sha256(leaf).hexdigest()


def keys(core, kind):
    fields = dict(line.split(': ', 1) for line in command(core, kind).splitlines() if ': ' in line)
    return fields['PrivateKey'], fields['Password (PublicKey)']


def unused_port(kind, avoid):
    for _ in range(32):
        with socket.socket(socket.AF_INET, kind) as probe:
            probe.bind((LOOPBACK, 0))
            port = probe.getsockname()[1]
        if port not in avoid:
            avoid.add(port)
            return port
    raise RuntimeError('Could not reserve a distinct fixture port')


def transport(network, settings, tls, alpn):
    stream = {'network': network}
    stream.update(settings)
    if tls:
        stream.update(security='tls', tlsSettings={**tls, 'alpn': alpn})
    return stream


def peers(core, case, server_port, client_port, origin_port, cert, pin, reality_port=None, wrong_pin=False):
    protocol = case.protocol
    identity = str(uuid.uuid4())
    password = secrets.token_urlsafe(16)
    client = {'address': LOOPBACK, 'port': server_port}
    server = {}
    if protocol in {'vless', 'vmess'}:
        server['clients'] = [{'id': identity}]
        client['id'] = identity
        if protocol == 'vless':
            server['decryption'] = client['encryption'] = 'none'
        else:
            client['security'] = 'auto'
    elif protocol == 'trojan':
        server['clients'] = [{'password': password}]
        client['password'] = password
    elif protocol == 'shadowsocks':
        method = 'chacha20-ietf-poly1305'
        if case.name == 'shadowsocks-2022':
            method = '2022-blake3-aes-128-gcm'
            password = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
        server.update(method=method, password=password, network='tcp')
        client.update(method=method, password=password)
    elif protocol == 'hysteria':
        server.update(version=2, clients=[{'auth': password}])
        client['version'] = 2
    elif protocol == 'wireguard':
        private_server, public_server = keys(core, 'wg')
        private_client, public_client = keys(core, 'wg')
        server = {'secretKey': private_server, 'address': ['192.0.2.1/32'],
                  'noKernelTun': True, 'peers': [{'publicKey': public_client, 'allowedIPs': ['192.0.2.2/32']}]}
        client = {'secretKey': private_client, 'address': ['192.0.2.2/32'],
                  'noKernelTun': True, 'peers': [{
                      'publicKey': public_server, 'endpoint': f'{LOOPBACK}:{server_port}',
                      'allowedIPs': [f'{DESTINATION}/32']}]}
    else:
        raise ValueError('Unhandled synthetic protocol')
    server_tls = {'certificates': [cert]} if case.alpn else None
    client_tls = {'serverName': SNI, 'disableSystemRoot': True,
                  'pinnedPeerCertSha256': '0' * 64 if wrong_pin else pin} if case.alpn else None
    server_stream = transport(case.network, case.stream, server_tls, case.alpn)
    client_stream = transport(case.network, case.stream, client_tls, case.alpn)
    if protocol == 'hysteria':
        client_stream['hysteriaSettings'] = {'version': 2, 'auth': password}
    if reality_port is not None:
        private_key, public_key = keys(core, 'x25519')
        short_id = secrets.token_hex(8)
        server['clients'][0]['flow'] = client['flow'] = 'xtls-rprx-vision'
        server_stream.update(security='reality', realitySettings={
            'target': f'{LOOPBACK}:{reality_port}', 'serverNames': [SNI],
            'privateKey': private_key, 'shortIds': [short_id],
        })
        client_stream.update(security='reality', realitySettings={
            'fingerprint': 'chrome', 'serverName': SNI, 'password': public_key, 'shortId': short_id,
        })
    return (
        {'log': {'loglevel': 'warning'}, 'inbounds': [{
            'listen': LOOPBACK, 'port': server_port, 'protocol': protocol, 'settings': server,
            'streamSettings': server_stream}],
         'outbounds': [{'protocol': 'freedom', 'settings': {
             'redirect': f'{LOOPBACK}:{origin_port}',
             'finalRules': [
                 {'action': 'allow', 'ip': [f'{LOOPBACK}/32'], 'port': str(origin_port), 'network': 'tcp'},
                 {'action': 'block', 'delay': 0},
             ]}}]},
        {'log': {'loglevel': 'warning'}, 'inbounds': [{
            'listen': LOOPBACK, 'port': client_port, 'protocol': 'http'}],
         'outbounds': [{'protocol': protocol, 'settings': client, 'streamSettings': client_stream}]},
    )


@contextmanager
def core_process(core, directory, name, config):
    path = directory / f'{name}.json'
    path.write_text(json.dumps(config), encoding='utf-8')
    log = directory / f'{name}.log'
    result = {}
    with log.open('wb') as output:
        began = time.perf_counter()
        process = subprocess.Popen([str(core), 'run', '-config', str(path)], cwd=directory,
                                   env=child_env(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + TIMEOUT
            while f'Xray {VERSION} started' not in log.read_text(encoding='utf-8', errors='replace'):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f'{name} Core did not become ready: {log.read_text(errors="replace")[-3000:]}')
                time.sleep(0.01)
            result['ready_ms'] = round((time.perf_counter() - began)*1000, 2)
            yield process, began, result
        finally:
            stopping = time.perf_counter()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                raise RuntimeError(f'{name} Core did not stop on time') from None
            result['stop_ms'] = round((time.perf_counter() - stopping)*1000, 2)


@contextmanager
def origin(tls_context=None):
    nonce = secrets.token_hex(16).encode('ascii')
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/fixture':
                self.send_error(404)
                return
            hits.append(self.path)
            self.send_response(200)
            self.send_header('Content-Length', str(len(nonce)))
            self.end_headers()
            self.wfile.write(nonce)

        def log_message(self, *args):
            pass

    class Listener(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(1)
            if tls_context is not None:
                try:
                    connection = tls_context.wrap_socket(connection, server_side=True)
                except OSError:
                    connection.close()
                    raise
            return connection, address

    with Listener((LOOPBACK, 0), Handler) as listener:
        worker = threading.Thread(target=listener.serve_forever, kwargs={'poll_interval': 0.02})
        worker.start()
        try:
            yield listener.server_port, nonce, hits
        finally:
            listener.shutdown()
            worker.join(timeout=3)
            assert not worker.is_alive()


def measure(core, directory, case, cert, pin, wrong_pin=False):
    with ExitStack() as stack:
        origin_port, nonce, hits = stack.enter_context(origin())
        used = {origin_port}
        reality_port = None
        if case.name == 'vless-raw-reality-vision':
            reality_port = unused_port(socket.SOCK_STREAM, used)
            target = {'log': {'loglevel': 'warning'},
                      'inbounds': [{'listen': LOOPBACK, 'port': reality_port, 'protocol': 'http',
                                    'streamSettings': transport('raw', {}, {'certificates': [cert]}, ['h2'])}],
                      'outbounds': [{'protocol': 'blackhole'}]}
            stack.enter_context(core_process(core, directory, 'reality-target', target))
        server_port = unused_port(case.socket_type, used)
        client_port = unused_port(socket.SOCK_STREAM, used)
        server, client = peers(core, case, server_port, client_port, origin_port, cert, pin, reality_port, wrong_pin)
        with core_process(core, directory, 'server', server) as (server_proc, _, server_result):
            with core_process(core, directory, 'client', client) as (client_proc, began, client_result):
                if server_proc.poll() is not None or client_proc.poll() is not None:
                    raise RuntimeError('A controlled protocol Core exited early')
                conn = HTTPConnection(LOOPBACK, client_port, timeout=4)
                try:
                    conn.request('GET', f'http://{DESTINATION}:18080/fixture', headers={'Connection': 'close'})
                    response = conn.getresponse()
                    verified = response.status == 200 and response.read(len(nonce)+1) == nonce
                except (OSError, HTTPException):
                    verified = False
                finally:
                    conn.close()
                elapsed = round((time.perf_counter() - began)*1000, 2)
                if (wrong_pin and (verified or hits)) or (not wrong_pin and (not verified or hits != ['/fixture'])):
                    details = '\n'.join((directory / f'{role}.log').read_text(errors='replace')[-1500:] for role in ('server', 'client'))
                    raise RuntimeError(f'{case.name} did not match expected HTTP path: {details}')
        return {'case': case.name, 'first_http_ms': elapsed if verified else None,
                'client_ready_ms': client_result['ready_ms'], 'client_stop_ms': client_result['stop_ms'],
                'server_stop_ms': server_result['stop_ms'], 'verified_http': verified}


def check_managed_ws_bootstrap(core, directory, cert, pin):
    """Require app HTTPS over the same managed pin before counting readiness."""
    logical = 'upstream.fixture.invalid'
    ws_host = 'websocket.fixture.invalid'
    app_host = 'https-app.fixture.invalid'
    loop, scope, leaf, denied = ('flutter-vless-bootstrap-' + tag
                                 for tag in ('loop', 'input', 'pin', 'denied'))
    app_cert, _ = certificate(core, app_host, authority=True)
    app_pem = '\n'.join(app_cert['certificate']) + '\n'
    cert_path, key_path = directory / 'app.crt', directory / 'app.key'
    # Xray labels this PKCS#8 EC fixture key as RSA. OpenSSL needs its real type.
    key_pem = ['-----BEGIN PRIVATE KEY-----', *app_cert['key'][1:-1], '-----END PRIVATE KEY-----']
    cert_path.write_bytes(app_pem.encode('ascii'))
    key_path.write_bytes(('\n'.join(key_pem) + '\n').encode('ascii'))
    origin_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    origin_tls.load_cert_chain(cert_path, key_path)
    app_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    app_tls.load_verify_locations(cadata=app_pem)
    case = next(case for case in CASES if case.name == 'vless-websocket-tls')

    with origin(origin_tls) as (origin_port, nonce, hits):
        used = {origin_port}
        server_port = unused_port(socket.SOCK_STREAM, used)
        app_port = unused_port(socket.SOCK_STREAM, used)
        server, authored = peers(core, case, server_port, app_port, origin_port, cert, pin)
        server_stream = server['inbounds'][0]['streamSettings']
        server_stream['tlsSettings']['rejectUnknownSni'] = True
        server_stream['wsSettings']['host'] = ws_host
        authored['dns'] = {'queryStrategy': 'UseIPv4', 'hosts': {logical: LOOPBACK}}
        proxy = authored['outbounds'][0]
        proxy['settings']['address'] = logical
        proxy['streamSettings']['wsSettings'] = {'headers': {'Host': ws_host}, 'path': '/fixture'}

        managed = deepcopy(authored)
        managed['log']['loglevel'] = 'info'
        managed_stream = managed['outbounds'][0]['streamSettings']
        managed_stream['sockopt'] = {'domainStrategy': 'AsIs', 'dialerProxy': loop}
        managed['outbounds'].extend([
            {'tag': loop, 'protocol': 'loopback', 'settings': {'inboundTag': scope}},
            {'tag': leaf, 'protocol': 'freedom', 'settings': {
                'redirect': f'{LOOPBACK}:0',
                # The synthetic peer uses loopback, which Freedom blocks by default.
                'finalRules': [
                    {'action': 'allow', 'ip': [f'{LOOPBACK}/32'],
                     'port': str(server_port), 'network': 'tcp'},
                    {'action': 'block', 'delay': 0},
                ]}, 'streamSettings': {'sockopt': {'domainStrategy': 'AsIs'}}},
            {'tag': denied, 'protocol': 'blackhole'},
        ])
        managed['routing'] = {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'inboundTag': [scope], 'domain': [f'full:{logical}'],
             'port': str(server_port), 'outboundTag': leaf},
            {'type': 'field', 'inboundTag': [scope], 'outboundTag': denied},
        ]}
        assert managed['dns'] == authored['dns']
        assert managed['outbounds'][0]['settings'] == proxy['settings']
        for identity in ('tlsSettings', 'wsSettings'):
            assert managed_stream[identity] == proxy['streamSettings'][identity]

        def app_probe(allow_failure=False):
            conn = HTTPSConnection(LOOPBACK, app_port, timeout=2, context=app_tls)
            conn.set_tunnel(app_host, 18080)
            try:
                conn.request('GET', '/fixture', headers={'Connection': 'close'})
                response = conn.getresponse()
                return response.status == 200 and response.read(len(nonce) + 1) == nonce
            except (OSError, HTTPException):
                if not allow_failure:
                    raise
                return False
            finally:
                conn.close()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stall, ExitStack() as accepted:
            stall.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stall.bind((LOOPBACK, server_port))
            stall.listen()
            stall.settimeout(2)
            with core_process(core, directory, 'managed-ws-client', managed), ThreadPoolExecutor(1) as worker:
                pending = worker.submit(app_probe, True)
                connection, _ = stall.accept()
                # Let the owned client exit before closing the accepted TCP
                # socket, so the listening port can be used by the real peer.
                accepted.enter_context(connection)
                connection.settimeout(2)
                with connection.makefile('rb') as tls_wire:
                    assert tls_wire.read(3).startswith(b'\x16\x03'), 'The fixed pin did not receive a TLS ClientHello'
                    assert not pending.result(timeout=3) and not hits, 'A stalled upstream was reported as usable'

        with core_process(core, directory, 'managed-ws-server', server):
            with core_process(core, directory, 'managed-ws-client', managed):
                assert app_probe() and hits == ['/fixture'], 'The unchanged managed pin did not carry verified HTTPS'
        log = (directory / 'managed-ws-client.log').read_text(encoding='utf-8', errors='replace')
        assert f'[{scope} -> {leaf}]' in log, 'App HTTPS did not use the managed fixed pin'
    print('MANAGED_WS_TLS_BOOTSTRAP_PASS=2', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--repetitions', type=int, choices=range(1, 6), default=1)
    parser.add_argument('--case', choices=[case.name for case in CASES])
    args = parser.parse_args()
    core = args.core.resolve(strict=True)
    if not command(core, 'version').startswith(f'Xray {VERSION} '):
        parser.error(f'Requires Xray {VERSION}')
    cert, pin = certificate(core)
    selected = [case for case in CASES if args.case in (None, case.name)]
    with tempfile.TemporaryDirectory(prefix='vless-protocol-runtime-') as temporary:
        directory = Path(temporary)
        for case in selected:
            for _ in range(args.repetitions):
                print(json.dumps(measure(core, directory, case, cert, pin)), flush=True)
        if args.case in (None, 'vless-raw-tls'):
            measure(core, directory, CASES[0], cert, pin, wrong_pin=True)
            print('WRONG_TLS_PIN_REJECTED', flush=True)
        if args.case in (None, 'vless-websocket-tls'):
            check_managed_ws_bootstrap(core, directory, cert, pin)
    print(f'PROTOCOL_RUNTIME_MATRIX_PASS={len(selected)}', flush=True)


if __name__ == '__main__':
    main()
