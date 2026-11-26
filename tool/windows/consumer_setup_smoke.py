"""Run the freshly built Flutter consumer on a disposable Windows runner."""

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from . import runtime_smoke as fixtures


HOSTS = ("2ip.ru", "myip.com")
HTTPS_HOST = "api.ipify.org"
CAPTURE_ROUTES = {"0.0.0.0/1", "128.0.0.0/1", "10.0.85.53/32", "::/1", "8000::/1"}


def system_proxy(settings=None):
    """Read or restore the four WinINet options used by the plugin."""
    class Value(ctypes.Union):
        _fields_ = [("number", wintypes.DWORD), ("text", ctypes.c_void_p),
                    ("time", wintypes.FILETIME)]

    class Option(ctypes.Structure):
        _fields_ = [("name", wintypes.DWORD), ("value", Value)]

    class OptionList(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("connection", wintypes.LPWSTR),
                    ("count", wintypes.DWORD), ("error", wintypes.DWORD),
                    ("options", ctypes.POINTER(Option))]

    options = (Option * 4)()
    for item, key in zip(options, (1, 2, 3, 4)):
        item.name = key
    option_list = OptionList(ctypes.sizeof(OptionList), None, len(options), 0, options)
    wininet = ctypes.WinDLL("wininet", use_last_error=True)
    if settings is not None:
        options[0].value.number = settings[0]
        strings = [ctypes.create_unicode_buffer(text) for text in settings[1:]]
        for item, buffer in zip(options[1:], strings):
            item.value.text = ctypes.cast(buffer, ctypes.c_void_p)
        if not wininet.InternetSetOptionW(None, 75, ctypes.byref(option_list), option_list.size):
            raise ctypes.WinError(ctypes.get_last_error())
        for notification in (39, 37):  # SETTINGS_CHANGED and REFRESH
            wininet.InternetSetOptionW(None, notification, None, 0)
        return

    size = wintypes.DWORD(option_list.size)
    free = ctypes.WinDLL("kernel32").GlobalFree
    free.argtypes = (ctypes.c_void_p,)
    free.restype = ctypes.c_void_p
    try:
        if not wininet.InternetQueryOptionW(None, 75, ctypes.byref(option_list), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (options[0].value.number, *(
            ctypes.wstring_at(option.value.text) if option.value.text else ""
            for option in options[1:]))
    finally:
        for option in options[1:]:
            if option.value.text:
                free(option.value.text)


def powershell(command):
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        check=True, capture_output=True, encoding="utf-8", timeout=15,
    ).stdout.strip()


def capture_routes():
    return CAPTURE_ROUTES.intersection(powershell(
        "$routes = @(Get-NetRoute -InterfaceAlias 'flutter_vless_tun' "
        "-ErrorAction SilentlyContinue); $routes.DestinationPrefix"
    ).splitlines())


def remove_test_routes():
    prefixes = ",".join(f"'{route}'" for route in sorted(CAPTURE_ROUTES))
    powershell("Get-NetRoute -InterfaceAlias 'flutter_vless_tun' "
               "-ErrorAction SilentlyContinue | "
               f"Where-Object {{ $_.DestinationPrefix -in @({prefixes}) }} | "
               "Remove-NetRoute -Confirm:$false -ErrorAction Stop")


@contextmanager
def route_fixtures(address):
    with fixtures.DirectOrigin((address, 0), fixtures.Direct) as direct, \
            fixtures.Server((address, 0), fixtures.Socks) as proxy:
        fixtures.PORTS["direct"] = direct.server_address[1]
        fixtures.PORTS["proxy"] = proxy.server_address[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            fixtures.PORTS["inbound"] = sock.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as extra:
                extra.bind(("127.0.0.1", 0))
                fixtures.PORTS["extra"] = extra.getsockname()[1]
        servers = (direct, proxy)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()
        try:
            yield
        finally:
            for server in servers:
                server.shutdown()
            for thread in threads:
                thread.join(timeout=3)


def read_receipt(path):
    if not path.is_file():
        return None
    data = path.read_bytes()
    assert len(data) < 16 * 1024, "Consumer receipt exceeded its size limit"
    return json.loads(data)


def wait_receipt(path, final, process, phase, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = read_receipt(path)
        if receipt is not None:
            return receipt
        failure = read_receipt(final)
        if failure is not None or process.poll() is not None:
            raise AssertionError(f"Consumer exited before {phase}: {failure}")
        time.sleep(0.1)
    raise AssertionError(f"Consumer did not report {phase} within {timeout} seconds")


def disconnected(probe, gateway, proxy):
    assert int(fixtures.native(probe, "policy-count")) == 0, "Plugin WFP filters remain after Stop"
    assert not capture_routes(), "Plugin capture routes remain after Stop"
    assert not powershell(
        "$addresses = @(Get-NetIPAddress -InterfaceAlias 'flutter_vless_tun' "
        "-IPAddress 'fd00:198:18::2' -ErrorAction SilentlyContinue); $addresses.IPAddress"
    ), "Plugin IPv6 tunnel address remains after Stop"
    assert fixtures.native(probe, "gateway") == gateway, "Default IPv4 gateway was not restored"
    # Query the same WinINet values Windows clients use, not the user registry
    # cache or process proxy environment.
    assert system_proxy() == proxy, "WinINet proxy settings were not restored"


def test_case(bundle, mode, directory, probe, public_ip, underlay, baseline, reverse):
    receipt = directory / "final.json"
    active = directory / "live.json"
    proceed = directory / "continue"
    restored = directory / "restored.json"
    finish = directory / "finish"
    guard_stop = directory / "guard-stop"
    plan_file = directory / "plan.json"
    direction = "reverse" if reverse else "original"
    routes = [
        dict(host=host, address=fixtures.PROFILE_TUN_TARGET, port=fixtures.PORTS["direct"],
             expected_body="DIRECT-FIXTURE" if (host == "myip.com") == reverse else "PROXY-FIXTURE")
        for host in HOSTS
    ]
    task = dict(mode=mode, config=fixtures.config(reverse, public_ip, underlay),
                socks_port=fixtures.PORTS["inbound"], routes=routes,
                https=dict(host=HTTPS_HOST, address=public_ip, path="/"),
                receipt=str(receipt), active_receipt=str(active), restored_receipt=str(restored),
                finish=str(finish), **{"continue": str(proceed)})
    plan_file.write_text(json.dumps(task), encoding="utf-8")
    process = guard = None
    normal_stop = False
    with (directory / "app.log").open("wb") as app_log:
        try:
            process = subprocess.Popen(
                [str(bundle / "vless_setup_probe.exe")], cwd=bundle,
                env=dict(os.environ, FLUTTER_VLESS_CONSUMER_PLAN=str(plan_file)),
                stdout=app_log, stderr=app_log,
            )
            guard = subprocess.Popen(
                [str(probe), "guard", str(process.pid), "150", str(guard_stop)],
                cwd=probe.parent, stdout=app_log, stderr=app_log,
            )
            during = wait_receipt(active, receipt, process, "live HTTPS and routing", 90)
            assert during["mode"] == mode
            count = int(fixtures.native(probe, "policy-count"))
            proxy_settings = system_proxy()
            if mode == "vpn":
                assert count >= 10 and CAPTURE_ROUTES == capture_routes(), "Expected Wintun routes and WFP protection"
                assert proxy_settings == baseline[1], "VPN changed WinINet proxy settings"
                # Dart's Socket.address can report the dialed address. Windows
                # socket probes confirm the local address via getsockname.
                assert fixtures.external_http(public_ip, vpn=True, verify_body=True) == "HTTP 200"
                for route in routes:
                    assert fixtures.request(route["host"], vpn=True) == route["expected_body"]
                fixtures.protected_dns(tcp=False)
            else:
                assert not count and not capture_routes(), "Proxy mode installed VPN routes or protection"
                assert proxy_settings[0] & 2 and proxy_settings[1] == f"socks=localhost:{task['socks_port']}", \
                    "Proxy mode did not install the owned WinINet SOCKS endpoint"
            proceed.touch()
            final = wait_receipt(restored, receipt, process, "Stop and restored HTTPS", 35)
            assert final["success"] is True and final["mode"] == mode, \
                f"Consumer failed its connection or Stop checks: {final}"
            assert final["routes"] == [
                dict(host=route["host"], expected=route["expected_body"],
                     actual=route["expected_body"])
                for route in routes
            ], "Consumer did not prove both exact routes"
            assert final["baseline_https_status"] == final["active_https_status"] \
                == final["post_stop_https_status"] == 200
            if mode == "vpn":
                assert final["administrator"] is True
            times = {key: final[key] for key in
                     ("start_to_connected_ms", "start_to_first_https_ms", "stop_ms")}
            assert all(type(ms) is int and ms >= 0 for ms in times.values())
            assert times["start_to_first_https_ms"] >= times["start_to_connected_ms"]
            disconnected(probe, *baseline)
            assert fixtures.external_http(public_ip, verify_body=True) == "HTTP 200"
            finish.touch()
            assert process.wait(timeout=10) == 0, "Consumer exited with an error after Stop"
            normal_stop = True
            result = dict(mode=mode, routing=direction, **times, routes=final["routes"],
                          active_https=200, restored_https=200)
            if mode == "vpn":
                stages = final["startup_stages_ms"]
                assert stages and all(type(ms) is int and ms >= 0 for ms in stages.values())
                result["startup_stages_ms"] = stages
            print("WINDOWS_CONSUMER_LIVE " + json.dumps(result), flush=True)
            if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                with Path(summary).open("a", encoding="utf-8") as file:
                    print(f"- {mode} ({direction}): CONNECTED {times['start_to_connected_ms']} ms, "
                          f"first verified HTTPS {times['start_to_first_https_ms']} ms, "
                          f"Stop {times['stop_ms']} ms. Routing and network restoration passed.", file=file)
                    if mode == "vpn":
                        print("  - Startup stages: " + ", ".join(f"{stage} {ms} ms" for stage, ms in stages.items()), file=file)
        finally:
            proceeded = process is not None
            if proceeded and process.poll() is None:
                proceed.touch()
                finish.touch()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            if proceeded and not normal_stop:
                # Emergency cleanup occurs only after stopping this owned app.
                # It cannot turn a failed normal Stop into a passing test.
                fixtures.native(probe, "release-protection")
                if capture_routes():
                    remove_test_routes()
                if system_proxy() != baseline[1]:
                    system_proxy(baseline[1])
            if guard is not None:
                guard_stop.touch()
                assert guard.wait(timeout=10) == 0, "Runner network watchdog failed"


def exercise_consumer(bundle, mode, directory, probe):
    assert os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" \
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Disposable Windows runner required"
    assert ctypes.windll.shell32.IsUserAnAdmin(), "Windows runner token is not elevated"
    assert probe.is_file(), "Native network observer missing"
    # Reply synthetically only for the isolated DNS fixture. The runner needs
    # normal DNS while its own network traffic is captured by the VPN.
    fixtures.REAL_DNS = True
    public_ip = socket.gethostbyname(HTTPS_HOST)
    assert fixtures.external_http(public_ip, verify_body=True) == "HTTP 200"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as routing:
        routing.connect((public_ip, 443))
        underlay = routing.getsockname()[0]
    baseline = (fixtures.native(probe, "gateway"), system_proxy())
    disconnected(probe, *baseline)
    with route_fixtures(underlay):
        for reverse in (False, True):
            case_directory = directory / ("reverse" if reverse else "original")
            case_directory.mkdir(parents=True)
            test_case(bundle, mode, case_directory, probe, public_ip, underlay, baseline, reverse)
