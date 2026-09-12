"""Exercise production Swift socket/TLS helpers without configuring a host VPN."""
import base64
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import threading

output = Path(sys.argv[1])
expected_user = b"transport-user"
expected_password = b"transport-password"


def exact(connection, count):
    data = b""
    while len(data) < count:
        received = connection.recv(count - len(data))
        if not received:
            raise EOFError("peer closed")
        data += received
    return data


def headers(connection):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += exact(connection, 1)
        assert len(data) <= 16384
    return data


def run_case(mode, behavior, *, tls=False, trusted_public=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(12)
    errors = []
    observations = []

    def serve():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(10)
                if mode == "socks":
                    assert exact(connection, 3) == b"\x05\x01\x02", "Client must offer only RFC1929"
                    if behavior == "noauth-selection":
                        connection.sendall(b"\x05\x00")
                        assert connection.recv(1) == b"", "Downgrade must close without CONNECT"
                        observations.append("rejected")
                        return
                    connection.sendall(b"\x05\x02")
                    assert exact(connection, 1) == b"\x01"
                    assert exact(connection, exact(connection, 1)[0]) == expected_user
                    assert exact(connection, exact(connection, 1)[0]) == expected_password
                    if behavior == "wrong-password":
                        connection.sendall(b"\x01\x01")
                        assert connection.recv(1) == b"", "Authentication failure must close without fallback"
                        observations.append("rejected")
                        return
                    connection.sendall(b"\x01\x00")
                    assert exact(connection, 4) == b"\x05\x01\x00\x03"
                    host = exact(connection, exact(connection, 1)[0]).decode()
                    exact(connection, 2)
                    assert host == ("www.gstatic.com" if trusted_public else "probe.invalid")
                    connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                else:
                    request = headers(connection)
                    assert request.startswith(b"CONNECT probe.invalid:")
                    token = base64.b64encode(expected_user + b":" + expected_password)
                    assert b"Proxy-Authorization: Basic " + token + b"\r\n" in request
                    if behavior == "wrong-password":
                        connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        assert connection.recv(1) == b""
                        observations.append("rejected")
                        return
                    connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if trusted_public:
                    with socket.create_connection(("www.gstatic.com", 443), 8) as remote:
                        while True:
                            ready, _, _ = select.select([connection, remote], [], [], 12)
                            assert ready, "TLS relay timed out"
                            for source in ready:
                                data = source.recv(8192)
                                if not data:
                                    observations.append("trusted TLS relay")
                                    return
                                (remote if source is connection else connection).sendall(data)
                elif tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(output / "cert.pem", output / "key.pem")
                    try:
                        with context.wrap_socket(connection, server_side=True) as secured:
                            assert not secured.recv(4096), "HTTP bytes must not reach an untrusted TLS peer"
                    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                        pass
                    observations.append("TLS rejected before HTTP")
                else:
                    request = headers(connection)
                    assert request.startswith(b"GET /response?query=1 HTTP/1.1\r\n")
                    assert b"Proxy-Authorization" not in request
                    assert expected_password not in request and expected_user not in request
                    # Fragment the first status line; production client must accumulate it.
                    connection.sendall(b"HTTP/1.1 ")
                    connection.sendall(b"204 No Content\r\nConnection: close\r\n\r\n")
                    observations.append("origin has no proxy credentials")
        except Exception as error:
            errors.append(f"{type(error).__name__}: {error}")

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    hostname = "www.gstatic.com" if trusted_public else "probe.invalid"
    url = f"{'https' if tls else 'http'}://{hostname}/response?query=1"
    if trusted_public:
        url = "https://www.gstatic.com/generate_204"
    result = subprocess.run([str(output / "probe"), mode, str(listener.getsockname()[1]), url],
                            capture_output=True, text=True, timeout=22)
    worker.join(12)
    listener.close()
    assert not worker.is_alive(), "Fixture did not finish"
    assert not errors, errors
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("DELAY_RESULT="), result.stdout
    delay = int(result.stdout.strip().split("=", 1)[1])
    expected_success = behavior == "success" and (not tls or trusted_public)
    assert (delay > 0) == expected_success, (mode, behavior, tls, delay)
    assert observations
    print(f"PASS: {mode}/{behavior}/{'TLS' if tls else 'HTTP'}")


run_case("socks", "noauth-selection")
run_case("socks", "wrong-password")
run_case("http", "wrong-password")
for protocol in ["socks", "http"]:
    run_case(protocol, "success")
    run_case(protocol, "success", tls=True)
if os.environ.get("TEST_REAL_HTTPS") == "1":
    run_case("socks", "success", tls=True, trusted_public=True)
print("PASS: strict authentication, real HTTP response, scoped proxy credentials and TLS certificate rejection")
