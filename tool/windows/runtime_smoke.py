"""Exercise real Windows services with synthetic local network fixtures.

Full VPN mode is restricted to a disposable GitHub Windows runner. It sends
ordinary TCP to a documentation IP; HTTP sniffing selects a domain rule and
Xray delivers to a local underlay HTTP server or a loopback SOCKS server. No server secrets.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import struct
import sys
from functools import lru_cache
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORTS = {"inbound": 18580, "direct": 18581, "proxy": 18582, "extra": 18583}
DNS_QUERIES = []
PROBE = None
REAL_DNS = False


def dns_question(query):
    offset = 12
    labels = []
    while offset < len(query) and query[offset]:
        size = query[offset]
        if size > 63 or offset + size + 1 > len(query):
            raise ValueError("Malformed fixture DNS question")
        labels.append(query[offset + 1:offset + size + 1].decode("ascii"))
        offset += size + 1
    if offset + 5 > len(query):
        raise ValueError("Truncated fixture DNS question")
    return ".".join(labels).lower(), offset + 5


def real_dns_response(query):
    # The ordinary socket is captured by TUN and forwarded by Xray's explicit
    # external-direct outbound. No physical DNS exception or host resolver is
    # used: the numeric HTTPS endpoint also avoids recursive name resolution.
    connection = http.client.HTTPSConnection("1.1.1.1", timeout=5,
                                             context=ssl.create_default_context())
    try:
        connection.request("POST", "/dns-query", body=query, headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        response = connection.getresponse()
        body = response.read(65536)
        if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/dns-message":
            raise ValueError("Controlled DoH request failed")
        if not 12 <= len(body) <= 65535 or body[:2] != query[:2] or not body[2] & 0x80:
            raise ValueError("Invalid controlled DoH response")
        return body
    finally:
        connection.close()


def dns_response(query):
    name, offset = dns_question(query)
    DNS_QUERIES.append(query[12:offset].hex())
    # Keep synthetic answers scoped to the test names. The runner itself must
    # retain working DNS/HTTPS while its traffic is captured by the VPN.
    if REAL_DNS and name != "invalid" and not name.endswith(".invalid"):
        return real_dns_response(query)
    return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:offset] + \
        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc6\x33\x64\x07"


def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("connection closed")
        data += part
    return data


class Direct(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"DIRECT-FIXTURE"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            _, count = exact(sock, 2)
            exact(sock, count)
            sock.sendall(b"\x05\x00")
            _, command, _, kind = exact(sock, 4)
            count = exact(sock, 1)[0] if kind == 3 else {1: 4, 4: 16}[kind]
            exact(sock, count)
            port = int.from_bytes(exact(sock, 2), "big")
            if command != 1:
                return
            sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            if port == 53:
                query = exact(sock, int.from_bytes(exact(sock, 2), "big"))
                response = dns_response(query)
                sock.sendall(len(response).to_bytes(2, "big") + response)
                return
            data = b""
            while b"\r\n\r\n" not in data:
                part = sock.recv(4096)
                if not part or len(data) > 65536:
                    return
                data += part
            body = b"PROXY-FIXTURE"
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                         str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except (EOFError, OSError, KeyError, ValueError, http.client.HTTPException):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def request(host, vpn, loopback=False, proxy_port=None):
    destination = ("127.0.0.1", PORTS["direct"]) if loopback else (("203.0.113.10", PORTS["direct"]) if vpn else ("127.0.0.1", proxy_port or PORTS["inbound"]))
    with socket.create_connection(destination, timeout=4) as sock:
        sock.settimeout(4)
        if vpn:
            assert sock.getsockname()[0] == ("127.0.0.1" if loopback else "10.0.85.2"), "Unexpected client interface"
        encoded = host.encode()
        if not vpn and not loopback:
            sock.sendall(b"\x05\x01\x00")
            assert exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded +
                         PORTS["direct"].to_bytes(2, "big"))
            head = exact(sock, 4)
            assert head[1] == 0, head
            count = exact(sock, 1)[0] if head[3] == 3 else {1: 4, 4: 16}[head[3]]
            exact(sock, count + 2)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: " + encoded + b"\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            part = sock.recv(4096)
            if not part:
                break
            data += part
        if b"\r\n\r\n" not in data:
            raise RuntimeError("connection ended without an HTTP response")
        return data.split(b"\r\n\r\n", 1)[1].decode()


def external_http(address, vpn=False):
    # Direct baseline and in-tunnel request use the same address and HTTP Host.
    # This detects a freedom outbound looping back into the TUN default route.
    with socket.create_connection((address, 443), timeout=4) as connection, \
            ssl.create_default_context().wrap_socket(connection, server_hostname="api.ipify.org") as sock:
        sock.settimeout(4)
        if vpn:
            assert sock.getsockname()[0] == "10.0.85.2", "External HTTPS bypassed the TUN"
        sock.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        data = sock.recv(4096)
        if not data.startswith(b"HTTP/1.1 200") and not data.startswith(b"HTTP/1.0 200"):
            raise RuntimeError("public HTTP control did not return 200")
        return "HTTP 200"


def config(reverse, external_address=None, direct_address="127.0.0.1", caller_api_port=None):
    profile = {
        "log": {"loglevel": "warning", "access": "none"},
        "dns": {"hosts": {h: direct_address for h in ("2ip.ru", "2ip.io", "myip.com")},
                "servers": ["localhost"]},
        "inbounds": [{"port": PORTS["inbound"], "protocol": "socks", "tag": "socks-in",
                      "listen": "127.0.0.1", "settings": {"auth": "noauth", "udp": True},
                      "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                                   "routeOnly": False}}],
        "outbounds": [{"protocol": "socks", "tag": "proxy",
                       "settings": {"servers": [{"address": direct_address, "port": PORTS["proxy"]}]}},
                      {"protocol": "freedom", "tag": "direct", "settings": {
                          "domainStrategy": "UseIP", "redirect": f"{direct_address}:{PORTS['direct']}"}}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "domain": ["domain:myip.com"] if reverse else ["domain:ru", "domain:io"],
             "outboundTag": "direct"}]}}
    profile["routing"]["rules"].append({"type": "field", "domain":
        ["full:2ip.ru", "full:2ip.io"] if reverse else ["full:myip.com"], "outboundTag": "proxy"})
    if external_address:
        profile["inbounds"].append({"port": PORTS["extra"], "protocol": "socks", "listen": "127.0.0.1", "tag": "socks-direct",
                                    "settings": {"auth": "noauth", "udp": True}})
        profile["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["socks-direct"], "outboundTag": "direct"})
        profile["outbounds"].append({"protocol": "freedom", "tag": "external-direct"})
        profile["dns"]["hosts"]["api.ipify.org"] = external_address
        profile["routing"]["rules"].append(
            {"type": "field", "domain": ["full:api.ipify.org"], "outboundTag": "external-direct"})
        profile["routing"]["rules"].append(
            {"type": "field", "network": "tcp,udp", "outboundTag": "external-direct"})
    # A dormant imported rule must not acquire the managed VPN input's traffic.
    profile["outbounds"].append({"protocol": "blackhole", "tag": "fixture-blocked"})
    profile["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["flutter-vless-tun"],
                                            "outboundTag": "fixture-blocked"})
    if caller_api_port is not None:
        assert type(caller_api_port) is int and 1 <= caller_api_port <= 65535, "Invalid fixture API port"
        profile["api"] = {"tag": "caller-api", "listen": f"127.0.0.1:{caller_api_port}",
                          "services": ["StatsService", "HandlerService"]}
        profile["stats"] = {}
        profile["policy"] = {"system": {key: False for key in (
            "statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink")}}
    return profile


def check_caller_api(directory, port, wine_bottle=None):
    # Only the fixture's own numeric port and verified bundled runtime are used;
    # never discover a stats-query endpoint from imported configuration JSON.
    assert type(port) is int and 1 <= port <= 65535, "Invalid fixture API port"
    executable = directory / "xray.exe"
    if not executable.is_file():
        executable = directory / "xray" / "xray.exe"
    assert executable.is_file(), "Verified fixture Xray runtime is missing"
    command = (["/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
                "--bottle", wine_bottle] if wine_bottle else [])
    command += [str(executable), "api", "statsquery", f"-server=127.0.0.1:{port}", "-timeout=2"]
    try:
        completed = subprocess.run(command, cwd=directory, capture_output=True,
                                   encoding="utf-8", errors="strict", timeout=3)
    except subprocess.TimeoutExpired:
        raise AssertionError("Caller API stats query exceeded its deadline") from None
    assert completed.returncode == 0, "Caller StatsService query failed"
    assert len(completed.stdout) <= 65536, "Caller StatsService reply exceeded fixture limit"

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate StatsService response field")
            result[key] = value
        return result

    reply = json.loads(completed.stdout, object_pairs_hook=unique_object)
    # Pinned Core omits a nil repeated field; an explicit empty list is valid
    # too. Reject other shapes as well as any counter enabled by adaptation.
    assert type(reply) is dict and (reply == {} or reply == {"stat": []}), "Caller disabled counters were changed or API reply is invalid"


def check_metrics_listener(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/debug/vars", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(262145)
        assert response.status == 200 and len(body) <= 262144, "Caller metrics listener did not serve bounded HTTP JSON"
        assert isinstance(json.loads(body).get("stats"), dict), "Caller metrics response is missing statistics"
    finally:
        connection.close()


def protected_dns(tcp):
    name = f"{uuid.uuid4().hex}.invalid"
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00\x00\x01\x00\x01"
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    before = len(DNS_QUERIES)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        sock.connect(("198.18.0.2", 53))
        assert sock.getsockname()[0] == "10.0.85.2", "DNS did not select the TUN"
        sock.sendall((len(query).to_bytes(2, "big") if tcp else b"") + query)
        response = exact(sock, int.from_bytes(exact(sock, 2), "big")) if tcp else sock.recv(4096)
    assert response[:2] == query[:2] and response[-4:] == b"\xc6\x33\x64\x07"
    assert len(DNS_QUERIES) > before and question.hex() in DNS_QUERIES
    return "DNS reply through selected proxy"


def relayed_dns():
    # An uncached question sent straight to the protected resolver verifies
    # that real runner names are not replaced with the synthetic test address.
    name = "api.github.com"
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00\x00\x01\x00\x01"
    query = b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    before = len(DNS_QUERIES)
    with socket.create_connection(("198.18.0.2", 53), timeout=6) as sock:
        assert sock.getsockname()[0] == "10.0.85.2", "Real DNS bypassed the TUN"
        sock.sendall(len(query).to_bytes(2, "big") + query)
        response = exact(sock, int.from_bytes(exact(sock, 2), "big"))
    assert response[:2] == query[:2] and response[3] & 15 == 0
    assert int.from_bytes(response[6:8], "big") > 0 and b"\xc6\x33\x64\x07" not in response
    assert len(DNS_QUERIES) > before and question.hex() in DNS_QUERIES
    return "Real DNS through protected proxy and verified HTTPS relay"


def system_dns():
    name = f"{uuid.uuid4().hex}.invalid."
    before = len(DNS_QUERIES)
    answer = subprocess.check_output([sys.executable, "-c",
        "import socket,sys; print(socket.gethostbyname(sys.argv[1]))", name],
        text=True, timeout=25).strip()
    assert answer == "198.51.100.7" and len(DNS_QUERIES) > before
    return "Windows resolver used the protected DNS proxy"


@lru_cache
def source_interface(source):
    # Discover the actual interface, including localized/renamed adapters.
    return int(native(PROBE, "source-interface", source))


def pin_interface(sock, source, ipv6=False):
    index = source_interface(source)
    # IP_UNICAST_IF expects network byte order; IPV6_UNICAST_IF uses host order.
    sock.setsockopt(socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP, 31,
                    index if ipv6 else struct.pack("!I", index))
    sock.bind((source, 0))


def physical_denied(address, source, port, udp=False, probe=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        pin_interface(sock, source)
        try:
            sock.connect((address, port))
            if udp:
                sock.send(b"private-dns-block-control")
        except OSError as error:
            # Require an explicit Windows access-denied verdict, not a timeout.
            assert getattr(error, "winerror", None) == 10013, f"Unproven block: {error}"
            return "WSAEACCES"
        if udp:
            # A successful UDP send only queues a datagram. Require a kernel
            # block event for this exact flow, caused by our own WFP filter.
            source_port = sock.getsockname()[1]
            owned = {int(value) for value in native(probe, "policy-ids").split()}
            command = f"""
$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=5157; StartTime=(Get-Date).AddMinutes(-1)}} -ErrorAction SilentlyContinue
foreach ($event in $events) {{
  $values = @{{}}
  ([xml]$event.ToXml()).Event.EventData.Data | ForEach-Object {{ $values[$_.Name] = $_.'#text' }}
  if ([long]$values.ProcessID -eq {os.getpid()} -and [int]$values.SourcePort -eq {source_port} -and $values.DestAddress -eq '{address}' -and [int]$values.DestPort -eq {port} -and [int]$values.Protocol -eq 17) {{ $values.FilterRTID }}
}}
"""
            for _ in range(5):
                output = subprocess.check_output(["powershell", "-NoProfile", "-Command", command],
                    text=True, timeout=15)
                matching = {int(value) for value in output.split()}
                if matching & owned:
                    return "Windows event 5157: exact UDP flow blocked by owned WFP filter"
                time.sleep(0.2)
            raise AssertionError("No owned WFP block event for the physical DNS control")
    raise AssertionError("Physical-interface traffic was permitted")


def native(probe, *args):
    completed = subprocess.run([str(probe), *map(str, args)], cwd=probe.parent,
                               capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, f"Native {args[0]} failed: {completed.stdout} {completed.stderr}"
    return completed.stdout.strip()


def await_state(path, running, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = json.loads(path.read_text())
            if state["running"] == running and state["protecting"]:
                return state
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.2)
    raise AssertionError(f"Protected readiness did not become {running}")


def kill_worker(pid, name):
    # Match this probe's child PID and image, never arbitrary user processes.
    command = f"$p = Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {pid} -and $_.Name -eq '{name}' }}; if (!$p) {{ throw 'Owned worker absent' }}; $p | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
    subprocess.run(["powershell", "-NoProfile", "-Command", command], check=True, timeout=15,
                   stdout=subprocess.DEVNULL)


def start_adapter(probe, directory, subnet):
    stop = directory / f"adapter-{subnet}.stop"
    stop.unlink(missing_ok=True)
    log_path = directory / f"adapter-{subnet}.log"
    log = log_path.open("w")
    process = subprocess.Popen([str(probe), "adapter", f"FlutterVlessValidation{subnet}", str(subnet), str(stop)],
                               cwd=directory, stdout=log, stderr=log)
    log.close()
    deadline = time.monotonic() + 60
    while "ADAPTER_READY=" not in log_path.read_text(errors="replace"):
        if process.poll() is not None or time.monotonic() >= deadline:
            stop.touch()
            process.wait(timeout=10)
            raise AssertionError("Synthetic dual-stack adapter did not become ready")
        time.sleep(0.2)
    return process, stop


def adapter_datagram(directory, subnet, ipv6, denied):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = f"fd00:85:{subnet}::1" if ipv6 else f"100.64.{subnet}.1"
    target = f"fd00:85:{subnet}::2" if ipv6 else f"100.64.{subnet}.2"
    token = uuid.uuid4().hex
    verdict = "send accepted"
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        pin_interface(sock, source, ipv6)
        try:
            sock.connect((target, 45000))
            sock.send(("wfp-adapter-control-" + token).encode())
        except OSError as error:
            assert denied and getattr(error, "winerror", None) == 10013, f"Unproven adapter verdict: {error}"
            verdict = "WSAEACCES"
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        observed = token in (directory / f"adapter-{subnet}.log").read_text(errors="replace")
        if observed:
            break
        time.sleep(0.05)
    assert observed != denied, f"Adapter packet evidence disagrees with expected block: observed={observed}, {verdict}"
    if denied:
        # TCP supplies a synchronous WFP verdict as an independent control.
        with socket.socket(family, socket.SOCK_STREAM) as tcp:
            tcp.settimeout(3)
            pin_interface(tcp, source, ipv6)
            try:
                tcp.connect((target, 45000))
            except OSError as error:
                assert getattr(error, "winerror", None) == 10013, f"Unproven TCP block: {error}"
            else:
                raise AssertionError("Adapter TCP bypassed WFP")
    return f"{verdict}; control packet {'absent' if denied else 'observed'} at adapter"


def main():
    global PROBE, REAL_DNS
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--vpn", action="store_true")
    parser.add_argument("--wine-bottle", help="CrossOver bottle for proxy-only tests on macOS")
    args = parser.parse_args()
    if args.vpn and (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"):
        raise SystemExit("Full VPN tests require a disposable GitHub Windows runner")
    REAL_DNS = args.vpn
    directory = args.directory.resolve()
    probe = directory / "runtime_probe.exe"
    PROBE = probe
    servers = []
    adapters = []
    results = []
    external_address = None
    direct_address = "127.0.0.1"
    try:
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            PORTS["inbound"] = candidate.getsockname()[1]
        if args.vpn:
            external_address = socket.gethostbyname("api.ipify.org")
            baseline = external_http(external_address)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((external_address, 443))
                direct_address = route.getsockname()[0]
            results.append(dict(check="external direct baseline", actual=baseline, passed=True))
        if args.vpn:
            driver = subprocess.run([str(probe), "wintun"], cwd=directory,
                                    capture_output=True, text=True, timeout=30)
            (directory / "wintun.log").write_text(driver.stdout + driver.stderr)
            assert driver.returncode == 0, "Wintun adapter creation failed"
            adapters.append(start_adapter(probe, directory, 2))
            for ipv6 in (False, True):
                actual = adapter_datagram(directory, 2, ipv6, False)
                results.append(dict(check="IPv6 adapter baseline" if ipv6 else "IPv4 adapter baseline", actual=actual, passed=True))
        # A VPN freedom socket is pinned to the underlay; use a local target
        # on that interface, not a loopback-only target on another interface.
        servers = [ThreadingHTTPServer((direct_address, 0), Direct),
                   Server((direct_address, 0), Socks)]
        PORTS["direct"] = servers[0].server_address[1]
        PORTS["proxy"] = servers[1].server_address[1]
        if args.vpn:
            servers.append(ThreadingHTTPServer(("127.0.0.1", PORTS["direct"]), Direct))
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            PORTS["extra"] = candidate.getsockname()[1]
        cases = [(False, "stop"), (True, "stop")]
        if args.vpn:
            cases.extend([(False, "crash"), (False, "shutdown"), (False, "no-reconnect")])
        for reverse, ending in cases:
            label = ("vpn" if args.vpn else "proxy") + ("-reverse" if reverse else "") + ("-" + ending if ending != "stop" else "")
            profile = directory / (label + ".json")
            caller_api_port = None
            if reverse and ending == "stop":
                with socket.socket() as candidate:
                    candidate.bind(("127.0.0.1", 0))
                    caller_api_port = candidate.getsockname()[1]
            prepared = config(reverse, external_address, direct_address, caller_api_port)
            # Exercise both the managed VPN SOCKS candidate and the private
            # stats API candidate, before either Core listener exists in the OS.
            metrics_port = (10086 if reverse else 10807) if args.vpn else 10085
            prepared["Metric\u017f"] = {"tag": "caller-metrics", "Li\u017ften": f"127.0.0.1:+{metrics_port}"}
            imported_ports = {entry["port"] for entry in prepared["inbounds"]}
            if caller_api_port is not None:
                imported_ports.add(caller_api_port)
            managed_port = next(port for port in range(10807, 65536) if port not in imported_ports | {metrics_port})
            if not args.vpn:
                with socket.socket() as candidate:
                    candidate.bind(("127.0.0.1", 0))
                    secondary_port = candidate.getsockname()[1]
                prepared["inbounds"].append({"listen": "127.0.0.1", "port": secondary_port,
                    "protocol": "socks", "tag": "socks-direct", "settings": {"auth": "noauth"}})
                prepared["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["socks-direct"], "outboundTag": "direct"})
            profile.write_text(json.dumps(prepared))
            stop_file = directory / (label + ".stop")
            stop_file.unlink(missing_ok=True)
            state_file = directory / (label + ".state.json")
            state_file.unlink(missing_ok=True)
            guard_stop = directory / (label + ".guard-stop")
            guard_stop.unlink(missing_ok=True)
            guard = None
            with (directory / (label + ".log")).open("w") as log:
                windows_path = lambda path: "Z:" + str(path).replace("/", "\\") if args.wine_bottle else str(path)
                command = (["/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
                            "--bottle", args.wine_bottle] if args.wine_bottle else [])
                command += [str(probe), ("run-vpn-no-reconnect" if ending == "no-reconnect" else "run-vpn") if args.vpn else "run-proxy", windows_path(profile), "240", windows_path(stop_file), windows_path(state_file)]
                process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=log)
                if args.vpn:
                    guard = subprocess.Popen([str(probe), "guard", str(process.pid), "240", str(guard_stop)],
                                             cwd=directory, stdout=log, stderr=log)
                try:
                    if args.vpn:
                        deadline = time.monotonic() + 65
                        while "START_RETURN=1" not in (directory / (label + ".log")).read_text(errors="replace"):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("VPN network setup did not become ready")
                            time.sleep(0.25)
                        routes = subprocess.check_output([
                            "powershell", "-NoProfile", "-Command",
                            "Get-NetRoute -InterfaceAlias flutter_vless_tun | Select-Object DestinationPrefix,NextHop,RouteMetric | ConvertTo-Json"], text=True, timeout=25)
                        (directory / (label + "-routes-during.log")).write_text(routes)
                        installed = json.loads(routes)
                        assert {r["DestinationPrefix"] for r in installed} >= {"0.0.0.0/1", "128.0.0.0/1"}
                        time.sleep(1)
                        assert int(native(probe, "policy-count")) >= 10
                        results.append(dict(mode=label, check="native WFP filters installed", passed=True))
                        if len(adapters) == 1:
                            adapters.append(start_adapter(probe, directory, 3))
                    else:
                        deadline = time.monotonic() + 25
                        while "START_RETURN=1" not in (directory / (label + ".log")).read_text(errors="replace"):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("Proxy did not report forwarding readiness")
                            time.sleep(0.1)
                    check_metrics_listener(metrics_port)
                    results.append(dict(mode=label, check="caller metrics HTTP survives private listener allocation", passed=True))
                    # Submit a Core-invalid replacement to the same live manager.
                    # The real routing requests below must still use its original
                    # workers, with WFP retained in VPN mode.
                    rejection = Path(str(state_file) + ".reject")
                    invalid = json.loads(json.dumps(prepared))
                    invalid["outbounds"][0]["protocol"] = "private-preflight-canary"
                    rejection.write_text(json.dumps(invalid))
                    deadline = time.monotonic() + 25
                    while "REJECTED_REPLACEMENT_PRESERVED=1" not in (directory / (label + ".log")).read_text(errors="replace"):
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("Invalid replacement did not preserve the live session")
                        time.sleep(0.1)
                    results.append(dict(mode=label, check="Core-invalid replacement preserves live workers", passed=True))
                    for host in ("2ip.ru", "2ip.io", "myip.com"):
                        expected = "DIRECT-FIXTURE" if ((host == "myip.com") == reverse) else "PROXY-FIXTURE"
                        try:
                            actual = request(host, args.vpn)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        row = dict(mode=label, host=host, expected=expected, actual=actual, passed=actual == expected)
                        results.append(row)
                        print(json.dumps(row), flush=True)
                    if caller_api_port is not None:
                        assert all(row["passed"] for row in results if row.get("mode") == label and "host" in row), "Caller API case has no successful routing proof"
                        check_caller_api(directory, caller_api_port, args.wine_bottle)
                        results.append(dict(mode=label, check="caller StatsService survives invalid replacement and routed HTTP with disabled counters", passed=True))
                    if not args.vpn:
                        for host in ("2ip.ru", "myip.com"):
                            actual = request(host, False, proxy_port=secondary_port)
                            results.append(dict(mode=label, check="secondary direct inbound", host=host,
                                                actual=actual, passed=actual == "DIRECT-FIXTURE"))
                    if args.vpn:
                        for subnet in (2, 3):
                            for ipv6 in (False, True):
                                actual = adapter_datagram(directory, subnet, ipv6, True)
                                results.append(dict(mode=label, check=f"{'new' if subnet == 3 else 'existing'} adapter {'IPv6' if ipv6 else 'IPv4'} blocked", actual=actual, passed=True))
                        with socket.create_connection(("127.0.0.1", managed_port), timeout=3) as denied:
                            denied.sendall(b"\x05\x01\x00")
                            assert exact(denied, 2) == b"\x05\xff", "Managed VPN SOCKS accepted noauth"
                        with socket.create_connection(("127.0.0.1", managed_port), timeout=3) as denied:
                            denied.sendall(b"\x05\x01\x02")
                            assert exact(denied, 2) == b"\x05\x02"
                            denied.sendall(b"\x01\x05wrong\x05wrong")
                            response = exact(denied, 2)
                            # RFC 1929 permits any nonzero failure code; Xray
                            # 26.7.28 uses FF, followed by a closed connection.
                            assert response[0] == 1 and response[1] != 0, "Managed VPN SOCKS accepted incorrect credentials"
                            try:
                                assert denied.recv(1) == b"", "Rejected SOCKS session remained open"
                            except ConnectionResetError:
                                pass
                        results.append(dict(mode=label, check="native SOCKS rejects noauth and incorrect credentials", passed=True))
                        for host in ("2ip.ru", "myip.com"):
                            expected = "DIRECT-FIXTURE" if ((host == "myip.com") == reverse) else "PROXY-FIXTURE"
                            actual = request(host, False)
                            results.append(dict(mode=label, check="imported SOCKS listener retains explicit noauth", host=host, actual=actual, passed=actual == expected))
                            actual = request(host, False, proxy_port=PORTS["extra"])
                            results.append(dict(mode=label, check="socks-direct inbound routing preserved", host=host, actual=actual, passed=actual == "DIRECT-FIXTURE"))
                        for udp in (False, True):
                            actual = physical_denied(external_address if not udp else "1.1.1.1", direct_address, 53 if udp else 443, udp, probe)
                            results.append(dict(mode=label, check="physical DNS denied" if udp else "physical TCP denied", actual=actual, passed=True))
                        for tcp in (False, True):
                            actual = protected_dns(tcp)
                            results.append(dict(mode=label, check="protected TCP DNS" if tcp else "protected UDP DNS", actual=actual, passed=True))
                        results.append(dict(mode=label, check="real runner DNS through VPN", actual=relayed_dns(), passed=True))
                        try:
                            actual = request("localhost", True, loopback=True)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        results.append(dict(mode=label, check="ordinary loopback bypass", actual=actual,
                                            passed=actual == "DIRECT-FIXTURE"))
                        try:
                            actual = external_http(external_address, vpn=True)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        row = dict(mode=label, check="external direct through VPN", actual=actual,
                                   passed=actual == "HTTP 200")
                        results.append(row)
                        print(json.dumps(row), flush=True)
                        if not reverse and ending == "stop":
                            results.append(dict(mode=label, check="ordinary Windows DNS resolver", actual=system_dns(), passed=True))
                            # A new localized adapter name invalidates an Xray
                            # binding even though the local TUN probe still works.
                            # This disposable VM keeps its addresses and routes.
                            index = source_interface(direct_address)
                            subprocess.run(["powershell", "-NoProfile", "-Command",
                                f"Get-NetAdapter | Where-Object {{ $_.ifIndex -eq {index} }} | Rename-NetAdapter -NewName 'Vless Underlay Ω' -ErrorAction Stop"],
                                check=True, timeout=45, stdout=subprocess.DEVNULL)
                            await_state(state_file, False)
                            actual = physical_denied(external_address, direct_address, 443)
                            results.append(dict(mode=label, check="underlay rename remains protected", actual=actual, passed=True))
                            await_state(state_file, True, timeout=60)
                            assert request("myip.com", True) == "PROXY-FIXTURE"
                            assert system_dns()
                            results.append(dict(mode=label, check="Unicode underlay rename recovers routing and system DNS", passed=True))
                            for worker in ("xray.exe", "tun2socks.exe"):
                                kill_worker(process.pid, worker)
                                await_state(state_file, False)
                                actual = physical_denied(external_address, direct_address, 443)
                                results.append(dict(mode=label, check=worker + " failure remains blocked", actual=actual, passed=True))
                                await_state(state_file, True, timeout=60)
                                assert request("myip.com", True) == "PROXY-FIXTURE"
                                results.append(dict(mode=label, check=worker + " forwarding recovers", passed=True))
                    if args.vpn and ending == "no-reconnect":
                        kill_worker(process.pid, "xray.exe")
                        await_state(state_file, False)
                        time.sleep(2)
                        state = await_state(state_file, False)
                        assert not state["running"] and state["protecting"]
                        remaining_workers = subprocess.check_output(["powershell", "-NoProfile", "-Command",
                            f"@(Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {process.pid} -and $_.Name -eq 'xray.exe' }}).Count"], text=True, timeout=25)
                        assert remaining_workers.strip() == "0", "Disabled recovery restarted Xray"
                        actual = physical_denied(external_address, direct_address, 443)
                        results.append(dict(mode=label, check="disabled Auto Reconnect retains WFP and leaves failed workers stopped", actual=actual, passed=True))
                    if ending == "crash":
                        process.kill()
                    elif ending == "shutdown":
                        stop_file.write_text("shutdown")
                    else:
                        stop_file.touch()
                    code = process.wait(timeout=25)
                    if args.vpn:
                        if ending in ("crash", "shutdown"):
                            assert int(native(probe, "policy-count")) >= 10
                            actual = physical_denied(external_address, direct_address, 443)
                            results.append(dict(mode=label, check="application exit retains native WFP block", actual=actual, passed=True))
                            native(probe, "release-protection")
                        assert native(probe, "policy-count") == "0"
                        remaining = subprocess.check_output([
                            "powershell", "-NoProfile", "-Command",
                            "@(Get-NetRoute -InterfaceAlias flutter_vless_tun -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }).Count"], text=True, timeout=25)
                        results.append(dict(mode=label, check="capture routes removed by service", passed=remaining.strip() == "0"))
                        assert external_http(external_address) == baseline
                        results.append(dict(mode=label, check="explicit stop restores ordinary HTTPS", passed=True))
                        if not reverse and ending == "stop":
                            for subnet in (2, 3):
                                for ipv6 in (False, True):
                                    actual = adapter_datagram(directory, subnet, ipv6, False)
                                    results.append(dict(mode=label, check=f"adapter {subnet} {'IPv6' if ipv6 else 'IPv4'} restored", actual=actual, passed=True))
                    results.append(dict(mode=label, check="requested termination", passed=ending == "crash" or code == 0, exit_code=code))
                finally:
                    if process.poll() is None:
                        stop_file.touch()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    if args.vpn:
                        # Do not rely on a later Actions step: WFP also covers
                        # the runner agent, so restore connectivity locally.
                        native(probe, "release-protection")
                        guard_stop.touch()
                        if guard:
                            guard.wait(timeout=10)
            # Stop removes the Wintun adapter; allow the next creation to settle.
            time.sleep(2)
    finally:
        for process, stop in adapters:
            stop.touch()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for server in servers:
            server.shutdown()
            server.server_close()
        (directory / ("vpn-results.json" if args.vpn else "proxy-results.json")).write_text(json.dumps(results, indent=2))
    if not results or not all(row["passed"] for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
