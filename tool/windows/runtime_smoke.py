"""Exercise real Windows services with synthetic, loopback-only proxy fixtures.

Full VPN mode is restricted to a disposable GitHub Windows runner. It sends
ordinary TCP to a documentation IP; HTTP sniffing selects a domain rule and
Xray delivers to one of two distinguishable local servers. No server secrets.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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
            exact(sock, count + 2)
            if command != 1:
                return
            sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            data = b""
            while b"\r\n\r\n" not in data:
                part = sock.recv(4096)
                if not part or len(data) > 65536:
                    return
                data += part
            body = b"PROXY-FIXTURE"
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                         str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except (EOFError, OSError, KeyError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def request(host, vpn):
    destination = ("203.0.113.10", 18581) if vpn else ("127.0.0.1", 18580)
    with socket.create_connection(destination, timeout=4) as sock:
        sock.settimeout(4)
        encoded = host.encode()
        if not vpn:
            sock.sendall(b"\x05\x01\x00")
            assert exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded +
                         (18581).to_bytes(2, "big"))
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
        return data.split(b"\r\n\r\n", 1)[1].decode()


def external_http(address):
    # Direct baseline and in-tunnel request use the same address and HTTP Host.
    # This detects a freedom outbound looping back into the TUN default route.
    with socket.create_connection((address, 443), timeout=4) as connection, \
            ssl.create_default_context().wrap_socket(connection, server_hostname="api.ipify.org") as sock:
        sock.settimeout(4)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        data = sock.recv(4096)
        if not data.startswith(b"HTTP/1.1 200") and not data.startswith(b"HTTP/1.0 200"):
            raise RuntimeError("public HTTP control did not return 200")
        return "HTTP 200"


def config(reverse, external_address=None):
    profile = {
        "log": {"loglevel": "warning"},
        "dns": {"hosts": {h: "127.0.0.1" for h in ("2ip.ru", "2ip.io", "myip.com")},
                "servers": ["localhost"]},
        "inbounds": [{"port": 18580, "protocol": "socks", "tag": "socks-in",
                      "listen": "127.0.0.1", "settings": {"auth": "noauth", "udp": True},
                      "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                                   "routeOnly": False}}],
        "outbounds": [{"protocol": "socks", "tag": "proxy",
                       "settings": {"servers": [{"address": "127.0.0.1", "port": 18582}]}},
                      {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIP"}}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "domain": ["domain:myip.com"] if reverse else ["domain:ru", "domain:io"],
             "outboundTag": "direct"}]}}
    if external_address:
        profile["dns"]["hosts"]["api.ipify.org"] = external_address
        profile["routing"]["rules"].append(
            {"type": "field", "domain": ["full:api.ipify.org"], "outboundTag": "direct"})
    return profile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--vpn", action="store_true")
    args = parser.parse_args()
    if args.vpn and (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"):
        raise SystemExit("Full VPN tests require a disposable GitHub Windows runner")
    directory = args.directory.resolve()
    probe = directory / "runtime_probe.exe"
    servers = [ThreadingHTTPServer(("127.0.0.1", 18581), Direct), Server(("127.0.0.1", 18582), Socks)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    results = []
    external_address = None
    try:
        if args.vpn:
            external_address = socket.gethostbyname("api.ipify.org")
            baseline = external_http(external_address)
            results.append(dict(check="external direct baseline", actual=baseline, passed=True))
        if args.vpn:
            driver = subprocess.run([str(probe), "wintun"], cwd=directory,
                                    capture_output=True, text=True, timeout=30)
            (directory / "wintun.log").write_text(driver.stdout + driver.stderr)
            assert driver.returncode == 0, "Wintun adapter creation failed"
        for reverse in (False, True):
            label = ("vpn" if args.vpn else "proxy") + ("-reverse" if reverse else "")
            profile = directory / (label + ".json")
            profile.write_text(json.dumps(config(reverse, external_address)))
            with (directory / (label + ".log")).open("w") as log:
                process = subprocess.Popen([str(probe), "run-vpn" if args.vpn else "run-proxy",
                                            str(profile), "22"], cwd=directory, stdout=log, stderr=log)
                try:
                    time.sleep(7 if args.vpn else 3)
                    for host in ("2ip.ru", "2ip.io", "myip.com"):
                        expected = "DIRECT-FIXTURE" if ((host == "myip.com") == reverse) else "PROXY-FIXTURE"
                        try:
                            actual = request(host, args.vpn)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        row = dict(mode=label, host=host, expected=expected, actual=actual, passed=actual == expected)
                        results.append(row)
                        print(json.dumps(row), flush=True)
                    if args.vpn:
                        try:
                            actual = external_http(external_address)
                        except Exception as error:
                            actual = type(error).__name__ + ": " + str(error)
                        row = dict(mode=label, check="external direct through VPN", actual=actual,
                                   passed=actual == "HTTP 200")
                        results.append(row)
                        print(json.dumps(row), flush=True)
                    code = process.wait(timeout=35)
                    results.append(dict(mode=label, check="clean shutdown", passed=code == 0, exit_code=code))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            # Stop removes the Wintun adapter; allow the next creation to settle.
            time.sleep(2)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        (directory / ("vpn-results.json" if args.vpn else "proxy-results.json")).write_text(json.dumps(results, indent=2))
    if not results or not all(row["passed"] for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
