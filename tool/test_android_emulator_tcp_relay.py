import errno
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import os
import sys

from android_emulator_tcp_relay import ConnectRelay, Limits, Policy, PeerBindings, RelayFailure, authority, parse_header, read_private_json


def header(port):
    return f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n'.encode()


def read_header(sock):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    if b'\r\n\r\n' not in data:
        return bytes(data), b''
    first, rest = bytes(data).split(b'\r\n\r\n', 1)
    return first+b'\r\n\r\n', rest


def read_all(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length-len(data))
        if not chunk:
            raise EOFError('Incomplete owned loopback payload')
        data.extend(chunk)
    return bytes(data)


class Origin:
    def __init__(self, handler):
        self.handler = handler
        self.stop = threading.Event()
        self.errors = []
        self.clients = set()
        self.lock = threading.Lock()
        self.workers = []
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(8)
        self.server.settimeout(.05)
        self.thread = threading.Thread(target=self.accept, name='test-connect-origin', daemon=False)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set(): self.errors.append(type(error).__name__)
                break
            with self.lock: self.clients.add(connection)
            worker = threading.Thread(target=self.run, args=(connection,), name='test-connect-origin-worker', daemon=False)
            self.workers.append(worker)
            worker.start()

    def run(self, connection):
        try:
            connection.settimeout(2)
            self.handler(connection)
        except OSError as error:
            if not self.stop.is_set() and error.errno not in (errno.ECONNRESET, errno.EPIPE):
                self.errors.append(type(error).__name__)
        except Exception as error:
            self.errors.append(type(error).__name__)
        finally:
            with self.lock: self.clients.discard(connection)
            connection.close()

    def close(self):
        self.stop.set()
        self.server.close()
        with self.lock: clients = list(self.clients)
        for client in clients:
            try: client.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        self.thread.join(2)
        for worker in self.workers: worker.join(2)
        if self.thread.is_alive() or any(w.is_alive() for w in self.workers):
            raise AssertionError('Origin worker leaked')
        if self.errors: raise AssertionError(self.errors)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.relays, self.origins, self.clients = [], [], []
        self.thread_errors=[]
        self.previous_excepthook=threading.excepthook
        def owned_exception(args):
            if args.thread.name.startswith(('private-connect-','test-connect-')):
                self.thread_errors.append({'type':args.exc_type.__name__,'thread':args.thread.name})
            else:self.previous_excepthook(args)
        threading.excepthook=owned_exception

    def tearDown(self):
        errors=[]
        try:
            for client in self.clients:client.close()
            for relay in self.relays:
                try:
                    result = relay.close()
                    self.assertEqual(result['active_workers'], 0)
                    self.assertEqual(result['tracked_sockets'], 0)
                    self.assertEqual(result['unexpected_worker_exceptions'], [])
                except Exception as error:errors.append(repr(error))
            for origin in self.origins:
                try:origin.close()
                except Exception as error:errors.append(repr(error))
            self.assertEqual(errors,[])
            self.assertEqual(self.thread_errors,[])
        finally:threading.excepthook=self.previous_excepthook

    def origin(self, handler):
        value = Origin(handler); self.origins.append(value); return value

    def relay(self, port, **limits):
        policy = Policy({'destinations': [{'host': '127.0.0.1', 'ports': [port], 'addresses': ['127.0.0.1']}]}, test_loopback=True)
        value = ConnectRelay(policy, Limits(**limits)).start(); self.relays.append(value); return value

    def client(self, relay):
        value = socket.create_connection(('127.0.0.1', relay.port), timeout=2)
        value.settimeout(2); self.clients.append(value); return value

    def wait_idle(self, relay):
        deadline = time.monotonic()+2
        while relay.snapshot()['active_workers'] and time.monotonic() < deadline: time.sleep(.01)
        self.assertEqual(relay.snapshot()['active_workers'], 0)

    def test_strict_authority_headers_and_allowlist(self):
        self.assertEqual(authority('EXAMPLE.COM:443'), ('example.com', 443))
        self.assertEqual(authority('[::1]:443'), ('::1', 443))
        for bad in ['example.com', 'example.com:0443', 'a:0', 'a:65536', 'user@a:443',
                    'a:443/path', 'a:443\r\nX:y', 'a%00:443', '[::1%lo0]:443', '::1:443']:
            with self.subTest(bad=repr(bad)), self.assertRaises(RelayFailure): authority(bad)
        for bad in [b'CONNECT a:443 HTTP/1.1\n\n', b'CONNECT a:443 HTTP/1.1\r\n X: y\r\n\r\n',
                    b'CONNECT a:443 HTTP/1.1\r\nHost: b:443\r\n\r\n',
                    b'CONNECT a:443 HTTP/1.1\r\nContent-Length: 9\r\n\r\n',
                    b'CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: private-canary\r\n\r\n']:
            with self.subTest(bad=repr(bad)), self.assertRaises(RelayFailure): parse_header(bad)
        with self.assertRaises(ValueError): Policy({'destinations': [{'host':'127.0.0.1','ports':[443],'addresses':['127.0.0.1']}]})
        policy = Policy({'destinations': [{'host':'example.com','ports':[443],'addresses':['93.184.216.34']}]})
        with self.assertRaises(RelayFailure): policy.lookup(('other.example', 443))

    def test_binary_first_payload_and_half_close_preserve_exact_bytes(self):
        payload = bytes(range(256))*300 + b'\x00\r\n\r\n\xffTAIL'
        seen = []
        def echo_after_eof(connection):
            data = read_all(connection); seen.append(data); connection.sendall(b'owned-reply:'+data)
        origin = self.origin(echo_after_eof); relay = self.relay(origin.port); client = self.client(relay)
        # The first opaque bytes arrive in the SAME write as CONNECT headers.
        client.sendall(header(origin.port)+payload); client.shutdown(socket.SHUT_WR)
        response, buffered = read_header(client)
        self.assertTrue(response.startswith(b'HTTP/1.1 200 '))
        self.assertEqual(buffered+read_all(client), b'owned-reply:'+payload)
        self.assertEqual(seen, [payload]); self.wait_idle(relay)

    def test_unavailable_owned_upstream_returns_502_and_never_200(self):
        reserved = socket.socket(); reserved.bind(('127.0.0.1',0)); self.addCleanup(reserved.close)
        # Keep the exact target port owned but not listening. Darwin may drop
        # these SYNs instead of rejecting them, so bound the real dial too.
        relay = self.relay(reserved.getsockname()[1],connect_seconds=.2); client = self.client(relay)
        client.sendall(header(reserved.getsockname()[1])); response = read_all(client)
        self.assertTrue(response.startswith(b'HTTP/1.1 502 ')); self.assertNotIn(b'200', response)
        self.wait_idle(relay)

    def test_header_limit_and_real_silent_header_deadline(self):
        reserved = socket.socket(); reserved.bind(('127.0.0.1',0)); self.addCleanup(reserved.close)
        relay = self.relay(reserved.getsockname()[1], header_seconds=.2, max_header_bytes=128)
        client = self.client(relay); client.sendall(b'CONNECT a:443 HTTP/1.1\r\nX: '+b'a'*150)
        self.assertTrue(read_all(client).startswith(b'HTTP/1.1 400 ')); self.wait_idle(relay)
        silent = self.client(relay); started = time.monotonic(); response=read_all(silent)
        self.assertTrue(response.startswith(b'HTTP/1.1 408 ')); self.assertGreater(time.monotonic()-started,.15)
        self.assertLess(time.monotonic()-started,1.5); self.wait_idle(relay)

    def test_concurrency_rejection_has_no_extra_worker(self):
        reserved = socket.socket(); reserved.bind(('127.0.0.1',0)); self.addCleanup(reserved.close)
        relay = self.relay(reserved.getsockname()[1], max_connections=1)
        first=self.client(relay);first.sendall(b'CONNECT ')
        deadline=time.monotonic()+1
        while relay.snapshot()['active_workers']!=1 and time.monotonic()<deadline:time.sleep(.01)
        second=self.client(relay);response=read_all(second)
        self.assertTrue(response.startswith(b'HTTP/1.1 503 '));self.assertEqual(relay.snapshot()['active_workers'],1)
        first.close();self.wait_idle(relay)

    def test_shutdown_cancels_transfer_without_injecting_http_after_200(self):
        received=threading.Event()
        def sink(connection):
            if connection.recv(1):received.set()
            read_all(connection)
        origin=self.origin(sink);relay=self.relay(origin.port);client=self.client(relay)
        client.sendall(header(origin.port));response,tail=read_header(client);self.assertIn(b' 200 ',response)
        client.sendall(b'x');self.assertTrue(received.wait(1))
        started=time.monotonic();final=relay.close();self.assertLess(time.monotonic()-started,.8)
        self.assertEqual(tail+read_all(client),b'');self.assertEqual(final['active_workers'],0)

    def test_steady_trickle_cannot_extend_absolute_tunnel_lifetime(self):
        def echo(connection):
            while True:
                data=connection.recv(1024)
                if not data:return
                connection.sendall(data)
        origin=self.origin(echo);relay=self.relay(origin.port,idle_seconds=.18,tunnel_seconds=.35)
        client=self.client(relay);started=time.monotonic();client.sendall(header(origin.port));response,_=read_header(client);self.assertIn(b' 200 ',response)
        count=0
        while True:
            try:
                client.sendall(b'x');data=client.recv(1)
            except OSError:break
            if not data:break
            self.assertEqual(data,b'x');count+=1;time.sleep(.035)
        self.assertGreater(count,3);self.assertGreater(time.monotonic()-started,.28);self.assertLess(time.monotonic()-started,1.5)
        self.wait_idle(relay)

    def test_connect_deadline_and_cancel_with_real_pollable_pending_socket(self):
        # OS boundary fault: a real socket descriptor remains EINPROGRESS.
        # No DNS or public connection is used, and the production dial loop runs.
        created=[]
        class Pending:
            def __init__(self,*_):
                self.left,self.right=socket.socketpair();self.closed=False;created.append(self)
            def fileno(self):return self.left.fileno()
            def setblocking(self,value):self.left.setblocking(value)
            def connect_ex(self,address):return errno.EINPROGRESS
            def getsockopt(self,*_):return errno.EINPROGRESS
            def shutdown(self,how):self.left.shutdown(how)
            def close(self):self.left.close();self.right.close();self.closed=True
        policy=Policy({'destinations':[{'host':'127.0.0.1','ports':[443],'addresses':['127.0.0.1']}]},test_loopback=True)
        relay=ConnectRelay(policy,Limits(connect_seconds=.2),_socket_factory=Pending).start();self.relays.append(relay)
        client=self.client(relay);started=time.monotonic();client.sendall(header(443));response=read_all(client)
        self.assertTrue(response.startswith(b'HTTP/1.1 502 '));self.assertNotIn(b'200',response)
        self.assertGreater(time.monotonic()-started,.15);self.assertLess(time.monotonic()-started,1.5)
        self.wait_idle(relay);self.assertTrue(all(x.closed for x in created))
        client2=self.client(relay);client2.sendall(header(443));deadline=time.monotonic()+1
        while len(created)<2 and time.monotonic()<deadline:time.sleep(.005)
        self.assertEqual(len(created),2);started=time.monotonic();relay.close();self.assertLess(time.monotonic()-started,.8)
        self.assertNotIn(b'200',read_all(client2));self.assertTrue(created[-1].closed)

    def test_actual_tls_clienthello_buffered_with_connect_is_opaque_and_trusted(self):
        with tempfile.TemporaryDirectory(prefix='owned-connect-tls-') as temporary:
            folder=Path(temporary);config=folder/'openssl.cnf';cert=folder/'cert.pem';key=folder/'key.pem'
            config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n')
            run=subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert)],capture_output=True,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr.decode()[-300:])
            server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(cert,key)
            payload=b'owned TLS byte-boundary\x00\xff'*20;seen=[]
            def tls_origin(raw):
                with server.wrap_socket(raw,server_side=True) as secured:
                    data=bytearray()
                    while len(data)<len(payload):
                        chunk=secured.recv(len(payload)-len(data))
                        if not chunk:raise EOFError('Incomplete owned TLS payload')
                        data.extend(chunk)
                    seen.append(bytes(data));secured.sendall(b'OK:'+data)
            origin=self.origin(tls_origin);relay=self.relay(origin.port);client=self.client(relay)
            context=ssl.create_default_context(cafile=str(cert));incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
            secured=context.wrap_bio(incoming,outgoing,server_hostname='localhost')
            with self.assertRaises(ssl.SSLWantReadError):secured.do_handshake()
            hello=outgoing.read();self.assertGreater(len(hello),100)
            client.sendall(header(origin.port)+hello);response,tail=read_header(client);self.assertIn(b' 200 ',response)
            if tail:incoming.write(tail)
            deadline=time.monotonic()+2
            while True:
                self.assertLess(time.monotonic(),deadline)
                try:secured.do_handshake();break
                except ssl.SSLWantReadError:
                    if outgoing.pending:client.sendall(outgoing.read())
                    data=client.recv(65536);self.assertTrue(data);incoming.write(data)
            if outgoing.pending:client.sendall(outgoing.read())
            self.assertTrue(secured.getpeercert());secured.write(payload);client.sendall(outgoing.read());reply=bytearray()
            while len(reply)<len(payload)+3:
                try:reply.extend(secured.read(65536))
                except ssl.SSLWantReadError:
                    data=client.recv(65536);self.assertTrue(data);incoming.write(data)
            self.assertEqual(bytes(reply),b'OK:'+payload);self.assertEqual(seen,[payload]);client.close();self.wait_idle(relay)

    def test_late_success_after_connect_deadline_is_not_admitted(self):
        class Late:
            def __init__(self,*_):self.left,self.right=socket.socketpair()
            def setblocking(self,value):self.left.setblocking(value)
            def connect_ex(self,_):time.sleep(.12);return 0
            def shutdown(self,how):self.left.shutdown(how)
            def close(self):self.left.close();self.right.close()
        policy=Policy({'destinations':[{'host':'127.0.0.1','ports':[443],'addresses':['127.0.0.1']}]},test_loopback=True)
        relay=ConnectRelay(policy,Limits(connect_seconds=.05),_socket_factory=Late).start();self.relays.append(relay)
        client=self.client(relay);client.sendall(header(443));response=read_all(client)
        self.assertTrue(response.startswith(b'HTTP/1.1 502 '));self.assertNotIn(b' 200 ',response)
        self.wait_idle(relay);self.assertEqual(relay.snapshot()['counts'].get('connect_deadline'),1)

    def test_header_completion_after_deadline_is_not_admitted(self):
        left,right=socket.socketpair();self.addCleanup(left.close);self.addCleanup(right.close)
        left.setblocking(False);right.sendall(header(443))
        class DelayedRead:
            def fileno(self):return left.fileno()
            def recv(self,count):time.sleep(.10);return left.recv(count)
        policy=Policy({'destinations':[{'host':'127.0.0.1','ports':[443],'addresses':['127.0.0.1']}]},test_loopback=True)
        relay=ConnectRelay(policy);self.relays.append(relay)
        with self.assertRaises(RelayFailure) as failure:relay._header(DelayedRead(),time.monotonic()+.04)
        self.assertEqual(failure.exception.status,408)

    def test_bad_descriptor_is_a_visible_unexpected_fault_not_a_quiet_network_failure(self):
        class Bad:
            def __init__(self,*_):self.left,self.right=socket.socketpair()
            def setblocking(self,value):self.left.setblocking(value)
            def connect_ex(self,_):return errno.EBADF
            def shutdown(self,how):self.left.shutdown(how)
            def close(self):self.left.close();self.right.close()
        policy=Policy({'destinations':[{'host':'127.0.0.1','ports':[443],'addresses':['127.0.0.1']}]},test_loopback=True)
        relay=ConnectRelay(policy,_socket_factory=Bad).start()
        try:
            client=self.client(relay);client.sendall(header(443));response=read_all(client)
            self.assertNotIn(b' 200 ',response);self.assertNotIn(b' 502 ',response)
            self.wait_idle(relay)
            self.assertEqual(relay.snapshot()['unexpected_worker_exceptions'],[{'type':'OSError','errno':errno.EBADF}])
            self.assertTrue(relay.snapshot()['stopping'])
        finally:
            final=relay.close();self.assertEqual(final['active_workers'],0);self.assertEqual(final['tracked_sockets'],0)

    @unittest.skipUnless(os.name == 'posix', 'Private policy owner/mode contract requires POSIX')
    def test_cli_ephemeral_only_ready_stop_and_worker_drain(self):
        with tempfile.TemporaryDirectory(prefix='owned-connect-cli-') as temporary:
            folder=Path(temporary);policy=folder/'policy.json';ready=folder/'ready.json';result=folder/'result.json';stop=folder/'stop'
            policy.write_text(json.dumps({'destinations':[{'host':'example.invalid','ports':[443],'addresses':['93.184.216.34']}]}));policy.chmod(0o600)
            process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('android_emulator_tcp_relay.py')),'--allowlist',str(policy),'--ready',str(ready),'--result',str(result),'--stop-file',str(stop),'--server-seconds','2'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                deadline=time.monotonic()+1
                while not ready.exists() and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(ready.exists());data=json.loads(ready.read_text());self.assertEqual(data['bind'],'127.0.0.1');self.assertEqual(data['PID'],process.pid)
                client=socket.create_connection(('127.0.0.1',data['port']),timeout=1);client.settimeout(1)
                try:
                    client.sendall(b'CONNECT ')
                    stop.touch(mode=0o600)
                    output,error=process.communicate(timeout=2)
                    self.assertEqual(process.returncode,0,error.decode());self.assertEqual(output,b'')
                    final=json.loads(result.read_text());self.assertEqual(final['active_workers'],0);self.assertEqual(final['tracked_sockets'],0);self.assertEqual(final['unexpected_worker_exceptions'],[])
                    self.assertEqual(ready.stat().st_mode & 0o777,0o600);self.assertEqual(result.stat().st_mode & 0o777,0o600)
                finally:client.close()
            finally:
                if process.poll() is None:
                    process.terminate();process.communicate(timeout=2)


    def test_numeric_emulator_mode_is_explicit_public_only_and_has_no_dns(self):
        strict = Policy({'destinations': [{'host':'example.com','ports':[443],'addresses':['93.184.216.34']}]})
        with self.assertRaises(RelayFailure): strict.lookup(('8.8.8.8', 443))
        emulator = Policy({'destinations': []}, allow_public_numeric=True)
        self.assertEqual(emulator.lookup(('8.8.8.8',443)), ((socket.AF_INET,('8.8.8.8',443)),))
        self.assertEqual(emulator.lookup(('2606:4700:4700::1111',80)), ((socket.AF_INET6,('2606:4700:4700::1111',80,0,0)),))
        for host, port in [('example.com',443),('127.0.0.1',443),('10.0.0.1',443),('169.254.169.254',80),
                           ('100.64.0.1',443),('192.0.2.1',443),('224.0.0.1',443),('::1',443),('fe80::1',443),
                           ('::ffff:127.0.0.1',443),('::ffff:8.8.8.8',443),('8.8.8.8',22)]:
            with self.subTest(host=host,port=port),self.assertRaises(RelayFailure):emulator.lookup((host,port))
        for address in ['127.0.0.1','10.0.0.1','169.254.169.254','224.0.0.1','192.0.2.1','::ffff:8.8.8.8']:
            with self.subTest(address=address),self.assertRaises(ValueError):
                Policy({'destinations':[{'host':'example.com','ports':[443],'addresses':[address]}]})

    def test_peer_policy_rejects_widening_invalid_platform_and_interface(self):
        row={'address':'8.8.8.8','port':443,'interface':'en0'}
        def make(value, **kwargs):
            return PeerBindings({'peers':[value]},platform='darwin',interface_index=lambda _:7,**kwargs)
        self.assertEqual(make(row).endpoints,{('8.8.8.8',443):('en0',7)})
        with self.assertRaises(ValueError):PeerBindings({'peers':[row]},platform='linux',interface_index=lambda _:7)
        for changes in [{'address':'peer.example'},{'address':'::ffff:8.8.8.8'},{'address':'127.0.0.1'},
                        {'address':'192.0.2.1'},{'address':134744072},{'port':80},{'port':True},
                        {'interface':'en0;other'},{'interface':'*'},{'interface':''},{'extra':'ignored'}]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):make(dict(row,**changes))
        with self.assertRaises(ValueError):PeerBindings({'peers':[row,row]},platform='darwin',interface_index=lambda _:7)
        for index in (0,-1,True,2**32):
            with self.subTest(index=index),self.assertRaises(ValueError):
                PeerBindings({'peers':[row]},platform='darwin',interface_index=lambda _:index)

    def peer_relay(self, origin, *, address='8.8.8.8', port=443, bind_error=None, readback=7, index=None, alternatives=False):
        # Every actual socket connects ONLY to the owned loopback Origin. The
        # wrapper spies on the OS boundary before redirecting that synthetic dial.
        events=[];created=[]
        class Spy:
            def __init__(self,*_):
                self.sock=socket.socket();self.bound=None;self.closed=False;created.append(self)
            def fileno(self):return self.sock.fileno()
            def setblocking(self,value):self.sock.setblocking(value)
            def setsockopt(self,level,option,value):
                events.append(('bind',level,option,value))
                if bind_error:raise OSError(bind_error,'injected bind rejection')
                self.bound=value
            def getsockopt(self,level,option):
                if option==25:return readback
                return self.sock.getsockopt(level,option)
            def connect_ex(self,target):
                events.append(('dial',target))
                return self.sock.connect_ex(('127.0.0.1',origin.port))
            def recv(self,*args):return self.sock.recv(*args)
            def send(self,*args):return self.sock.send(*args)
            def shutdown(self,*args):return self.sock.shutdown(*args)
            def close(self):self.sock.close();self.closed=True
        bindings=PeerBindings({'peers':[{'address':'8.8.8.8','port':443,'interface':'en0'}]},platform='darwin',interface_index=index or (lambda _:7))
        policy=Policy({'destinations':[{'host':'peer.example','ports':[port],'addresses':[address]+(['1.1.1.1'] if alternatives else [])}]})
        relay=ConnectRelay(policy,peer_bindings=bindings,_socket_factory=Spy).start();self.relays.append(relay)
        client=self.client(relay);client.sendall(f'CONNECT peer.example:{port} HTTP/1.1\r\nHost: peer.example:{port}\r\n\r\n'.encode().replace(b'\\r\\n',b'\r\n'))
        return relay,client,events,created

    def test_peer_binding_precedes_real_loopback_payload_and_only_selected_peer(self):
        seen=[]
        def echo(connection):
            payload=read_exact(connection,len(b'owned-interface-test'));seen.append(payload);connection.sendall(b'reply:'+payload)
        origin=self.origin(echo)
        for address,port,expected_bound in [('8.8.8.8',443,True),('1.1.1.1',443,False),('8.8.8.8',80,False)]:
            with self.subTest(address=address,port=port):
                relay,client,events,created=self.peer_relay(origin,address=address,port=port)
                response,_=read_header(client);self.assertIn(b' 200 ',response)
                client.sendall(b'owned-interface-test');self.assertEqual(read_exact(client,len(b'reply:owned-interface-test')),b'reply:owned-interface-test')
                client.shutdown(socket.SHUT_WR);read_all(client);self.wait_idle(relay)
                self.assertEqual([event[0] for event in events],['bind','dial'] if expected_bound else ['dial'])
                if expected_bound:self.assertEqual(events[0],('bind',socket.IPPROTO_IP,25,7))
                self.assertTrue(all(value.closed for value in created))
        self.assertEqual(seen,[b'owned-interface-test']*3)

    def test_binding_failure_readback_and_changed_interface_never_dial_or_retry(self):
        admitted=[]
        origin=self.origin(lambda connection:admitted.append(connection.recv(1)))
        for kwargs in [{'bind_error':errno.EPERM},{'readback':0},
                       {'index':iter([7,9]).__next__}]:
            # Interface resolver takes a name; the third case changes its index
            # between policy admission and the worker's pre-connect check.
            if 'index' in kwargs:
                values=iter([7,9]);kwargs['index']=lambda _:next(values)
            with self.subTest(kwargs=tuple(kwargs)):
                relay,client,events,created=self.peer_relay(origin,alternatives=True,**kwargs)
                response=read_all(client);self.assertTrue(response.startswith(b'HTTP/1.1 502 '));self.assertNotIn(b' 200 ',response)
                self.wait_idle(relay);self.assertFalse(any(event[0]=='dial' for event in events))
                self.assertEqual(len(created),1);self.assertTrue(created[0].closed)
                self.assertEqual(relay.snapshot()['counts'].get('peer_interface_bind_failed'),1)
                self.assertEqual(relay.snapshot()['unexpected_worker_exceptions'],[])
        self.assertEqual(admitted,[])

    @unittest.skipUnless(os.name == 'posix', 'Private policy/FIFO contract requires POSIX')
    def test_owned_private_policy_input_and_explicit_listener_port_bounds(self):
        with tempfile.TemporaryDirectory(prefix='owned-relay-policy-') as temporary:
            folder=Path(temporary);policy=folder/'policy.json';policy.write_text('{"destinations":[]}');policy.chmod(0o644)
            with self.assertRaises(ValueError):read_private_json(policy)
            policy.chmod(0o600);self.assertEqual(read_private_json(policy),{'destinations':[]})
            fifo=folder/'policy.fifo';os.mkfifo(fifo,0o600)
            code='import sys\nfrom android_emulator_tcp_relay import read_private_json\ntry: read_private_json(sys.argv[1])\nexcept ValueError: sys.exit(0)\nsys.exit(1)'
            child=subprocess.run([sys.executable,'-c',code,str(fifo)],cwd=Path(__file__).resolve().parent,capture_output=True,timeout=2)
            self.assertEqual(child.returncode,0,child.stderr.decode())
            link=folder/'link.json';link.symlink_to(policy)
            with self.assertRaises((OSError,ValueError)):read_private_json(link)
            loaded=Policy.from_file(policy,allow_public_numeric=True)
            import hashlib
            self.assertEqual(loaded.source_sha256,hashlib.sha256(policy.read_bytes()).hexdigest())
        for invalid in (-1,65536,True):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):ConnectRelay(Policy({'destinations':[]},allow_public_numeric=True),listen_port=invalid)
        owned=socket.socket();owned.bind(('127.0.0.1',0));self.addCleanup(owned.close)
        with self.assertRaises(OSError):ConnectRelay(Policy({'destinations':[]},allow_public_numeric=True),listen_port=owned.getsockname()[1])
        for duration in (1200,1800):self.assertEqual(Limits(server_seconds=duration).server_seconds,duration)
        for duration in (1800.01,0,True,float('inf'),float('nan')):
            with self.subTest(duration=duration),self.assertRaises(ValueError):Limits(server_seconds=duration)


    def test_cli_explicit_public_mode_expires_without_stop_and_closes_owned_worker(self):
        with tempfile.TemporaryDirectory(prefix='owned-relay-deadline-') as temporary:
            folder=Path(temporary);ready=folder/'ready.json';result=folder/'result.json';stop=folder/'stop'
            started=time.monotonic()
            process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('android_emulator_tcp_relay.py')),
                '--emulator-public-tcp','--ready',str(ready),'--result',str(result),'--stop-file',str(stop),
                '--server-seconds','.25'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            client=None
            try:
                deadline=time.monotonic()+1
                while not ready.exists() and time.monotonic()<deadline:time.sleep(.005)
                data=json.loads(ready.read_text());self.assertTrue(data['emulator_public_numeric_TCP_80_443'])
                self.assertEqual(data['bind'],'127.0.0.1');self.assertEqual(data['peer_bindings'],0)
                self.assertFalse(data['host_network_configuration_changed']);self.assertEqual(data['limits']['server_seconds'],.25)
                client=socket.create_connection(('127.0.0.1',data['port']),timeout=1);client.settimeout(1)
                client.sendall(b'CONNECT ')
                output,error=process.communicate(timeout=2)
                self.assertEqual(process.returncode,0,error.decode());self.assertEqual(output,b'')
                self.assertGreater(time.monotonic()-started,.20);self.assertLess(time.monotonic()-started,1.5)
                self.assertFalse(stop.exists());final=json.loads(result.read_text())
                self.assertTrue(final['closed']);self.assertEqual(final['active_workers'],0)
                self.assertEqual(final['tracked_sockets'],0);self.assertEqual(final['unexpected_worker_exceptions'],[])
            finally:
                if client is not None:client.close()
                if process.poll() is None:process.terminate();process.communicate(timeout=2)


if __name__=='__main__':
    unittest.main(verbosity=2)
