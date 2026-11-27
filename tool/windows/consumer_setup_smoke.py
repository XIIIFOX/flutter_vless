"""Run the freshly built Flutter consumer on a disposable Windows runner."""

from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time

from . import runtime_smoke as fixtures


HOSTS = ("2ip.ru", "myip.com")
HTTPS_HOST = "api.ipify.org"
CAPTURE_ROUTES = {"0.0.0.0/1", "128.0.0.0/1", "10.0.85.53/32", "::/1", "8000::/1"}
IPV6_CONTROL_SUBNET = 3
SETUPAPI_READ_LIMIT = 256 * 1024
SETUPAPI_TIMESTAMP = r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3}"
SETUPAPI_HEADER = re.compile(r">>>\s+\[([^\r\n]+)\]")
SETUPAPI_START = re.compile(
    rf">>>\s+(?:Section start ({SETUPAPI_TIMESTAMP})|({SETUPAPI_TIMESTAMP}):? Section start)"
)
SETUPAPI_END = re.compile(
    rf"<<<\s+(?:Section end ({SETUPAPI_TIMESTAMP})|\[({SETUPAPI_TIMESTAMP}):? Section end\])"
)
SETUPAPI_EXIT = re.compile(r"<<<\s+\[Exit(?: status(?:: .*|\(0x[0-9a-f]+\)))?\]", re.IGNORECASE)


def wintun_setupapi_sections(log_delta):
    """Keep completed Wintun staging and installation durations only."""
    sections = []
    stage = start = end = None
    for line in log_delta.splitlines():
        line = line.rstrip()
        if header := SETUPAPI_HEADER.fullmatch(line):
            stage = start = end = None
            title, _, target = header[1].partition(" - ")
            title = title.lower().partition(" (")[0]
            target = target.lower().strip('"')
            inf_name = re.split(r"[\\/]", target)[-1]
            if title in ("setupcopyoeminf", "driver package import", "setup import driver package") \
                    and inf_name == "wintun.inf":
                stage = "driver_stage"
            elif title == "device install" and target.startswith(("swd\\wintun\\", "root\\wintun\\")):
                stage = "device_install"
        elif stage is not None:
            if stamp := SETUPAPI_START.fullmatch(line):
                start = stamp[1] or stamp[2]
            elif stamp := SETUPAPI_END.fullmatch(line):
                end = stamp[1] or stamp[2]
            elif SETUPAPI_EXIT.fullmatch(line):
                if start and end:
                    try:
                        elapsed = datetime.fromisoformat(end.replace("/", "-")) - \
                                  datetime.fromisoformat(start.replace("/", "-"))
                    except ValueError:
                        pass
                    else:
                        if elapsed.days >= 0:
                            sections.append(dict(stage=stage, elapsed_ms=elapsed // timedelta(milliseconds=1)))
                stage = start = end = None
    return sections


def setupapi_baseline():
    if system_root := os.environ.get("SystemRoot"):
        path = Path(system_root) / "inf" / "setupapi.dev.log"
        try:
            return path, path.stat()
        except OSError:
            pass
    return None


def setupapi_wintun_delta(baseline):
    if baseline is None:
        return dict(status="unavailable", sections=[])
    path, before = baseline
    try:
        with path.open("rb") as log:
            after = os.fstat(log.fileno())
            offset = before.st_size
            if not os.path.samestat(before, after) or after.st_size < offset:
                return dict(status="log_replaced", sections=[])
            encoding = {b"\xff\xfe": "utf-16-le", b"\xfe\xff": "utf-16-be"}.get(log.read(2), "utf-8")
            log.seek(offset)
            delta = log.read(min(after.st_size - offset, SETUPAPI_READ_LIMIT))
    except OSError:
        return dict(status="unavailable", sections=[])
    sections = wintun_setupapi_sections(delta.decode(encoding, errors="replace").removeprefix("\ufeff"))
    truncated = after.st_size - offset > len(delta)
    status = "truncated" if truncated else "observed" if sections else "no_wintun_sections"
    return dict(status=status, sections=sections)


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


def powershell(command, *, timeout=15):
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        check=True, capture_output=True, encoding="utf-8", timeout=timeout,
    ).stdout.strip()


def wintun_authenticode_status(dll):
    sdk_bins = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits" / "10" / "bin"
    candidates = sorted(sdk_bins.glob("10.*/x64/signtool.exe"), reverse=True)
    assert candidates, "Windows SDK SignTool is required to verify Wintun Authenticode"
    result = subprocess.run(
        [str(candidates[0]), "verify", "/pa", str(dll)],
        capture_output=True, timeout=45,
    )
    return "Valid" if result.returncode == 0 else f"SignTool exit {result.returncode}"


def wintun_driver_inventory():
    """Query Windows' staged OEM driver packages without touching devices."""
    return powershell(
        "$ProgressPreference = 'SilentlyContinue'; "
        "Get-WindowsDriver -Online -ErrorAction Stop | Where-Object { "
        "[IO.Path]::GetFileName($_.OriginalFileName) -eq 'wintun.inf' } | "
        'ForEach-Object { "$($_.Driver)|$($_.Version)" } | Sort-Object', timeout=45,
    ).splitlines()


def wintun_setup_network(probe):
    assert not powershell(
        "Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { "
        "$_.Name -eq 'flutter_vless_tun' -or $_.InterfaceDescription -like '*Wintun*' } | "
        "Select-Object -ExpandProperty Name"
    ), "Windows setup left a Wintun adapter present"
    routes = powershell(
        "Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { "
        "$_.DestinationPrefix -in @('0.0.0.0/0', '::/0', '0.0.0.0/1', '128.0.0.0/1', "
        "'::/1', '8000::/1', '10.0.85.53/32') } | ForEach-Object { "
        '"$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)" } | Sort-Object'
    )
    assert int(fixtures.native(probe, "policy-count")) == 0, "Windows setup left plugin WFP filters"
    return routes, system_proxy()


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
def route_fixtures(address, vpn):
    with ExitStack() as stack:
        direct = stack.enter_context(fixtures.DirectOrigin((address, 0), fixtures.Direct))
        ipv6_payload = None
        if vpn:
            proxy, relay = fixtures.socks_datagram_pair(address, fixtures.IPv6PayloadDatagram)
            stack.enter_context(proxy)
            stack.enter_context(relay)
            ipv6_payload = fixtures.IPv6PayloadState()
            proxy.ipv6_payload = relay.ipv6_payload = ipv6_payload
            relay.socket.settimeout(1)
            servers = (direct, proxy, relay)
        else:
            proxy = stack.enter_context(fixtures.Server((address, 0), fixtures.Socks))
            servers = (direct, proxy)
        fixtures.PORTS["direct"] = direct.server_address[1]
        fixtures.PORTS["proxy"] = proxy.server_address[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            fixtures.PORTS["inbound"] = sock.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as extra:
                extra.bind(("127.0.0.1", 0))
                fixtures.PORTS["extra"] = extra.getsockname()[1]
        started = []
        try:
            for server in servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                started.append((server, thread))
            yield ipv6_payload
        finally:
            try:
                if ipv6_payload is not None:
                    ipv6_payload.close()
            finally:
                for server, thread in started:
                    server.shutdown()
                    thread.join(timeout=3)
        if ipv6_payload is not None:
            ipv6_payload.require_clean()


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
        "$ipv4 = @(Get-NetIPAddress -InterfaceAlias 'flutter_vless_tun' "
        "-AddressFamily IPv4 -IPAddress '10.0.85.2' -ErrorAction SilentlyContinue); "
        f"$ipv6 = @({fixtures.tunnel_ipv6_rows()}); $ipv4.IPAddress; $ipv6.IPAddress"
    ), "Plugin tunnel addresses remain after Stop"
    assert fixtures.native(probe, "gateway") == gateway, "Default IPv4 gateway was not restored"
    # Query the same WinINet values Windows clients use, not the user registry
    # cache or process proxy environment.
    assert system_proxy() == proxy, "WinINet proxy settings were not restored"


def physical_dns_servers(underlay):
    index = fixtures.source_interface(underlay)
    servers = powershell(
        f"(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4 "
        "-ErrorAction Stop).ServerAddresses"
    ).splitlines()
    assert servers, "The Windows underlay has no DNS resolver"
    for server in servers:
        socket.inet_pton(socket.AF_INET, server)
    return tuple(servers)


def query_restored_dns(servers):
    addresses = ",".join(f"'{server}'" for server in servers)
    answer = powershell(
        f"(Resolve-DnsName -Name 'api.github.com.' -Type A -Server @({addresses}) "
        "-DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop).IPAddress"
    )
    assert answer, "Restored physical DNS returned no IPv4 answer"
    for address in answer.splitlines():
        socket.inet_pton(socket.AF_INET, address)


@contextmanager
def ipv6_underlay_control(bundle, directory, probe):
    directory.mkdir()
    adapter_probe = directory / probe.name
    # Native DLL lookup is rooted at the executable, not its working directory.
    # Use only the same verified Wintun image already in this disposable build.
    shutil.copyfile(probe, adapter_probe)
    shutil.copyfile(bundle / "xray" / "wintun.dll", directory / "wintun.dll")
    try:
        process, stop = fixtures.start_adapter(adapter_probe, directory, IPV6_CONTROL_SUBNET)
        try:
            yield directory
        finally:
            stop.touch()
            try:
                assert process.wait(timeout=10) == 0, "IPv6 underlay control did not stop cleanly"
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise
    finally:
        fixtures.source_interface.cache_clear()


def test_case(bundle, mode, directory, probe, public_ip, underlay, baseline, reverse, ipv6_payload,
              *, address_loss=None, ipv6_underlay=None, wintun_benchmark=None):
    receipt = directory / "final.json"
    active = directory / "live.json"
    proceed = directory / "continue"
    fail_closed = directory / "fail-closed.json" if address_loss else None
    restored = directory / "restored.json"
    finish = directory / "finish"
    guard_stop = directory / "guard-stop"
    plan_file = directory / "plan.json"
    gateway, proxy, dns_servers = baseline
    direction = "reverse" if reverse else "original"
    measure_wintun_install = mode == "vpn" and address_loss != "IPv6"
    routes = [
        dict(host=host, address=fixtures.PROFILE_TUN_TARGET, port=fixtures.PORTS["direct"],
             expected_body="DIRECT-FIXTURE" if (host == "myip.com") == reverse else "PROXY-FIXTURE")
        for host in HOSTS
    ]
    task = dict(mode=mode, config=fixtures.config(reverse, public_ip, underlay,
                                                  ipv6_payload=ipv6_payload is not None),
                socks_port=fixtures.PORTS["inbound"], routes=routes,
                https=dict(host=HTTPS_HOST, address=public_ip, path="/"),
                receipt=str(receipt), active_receipt=str(active), restored_receipt=str(restored),
                finish=str(finish), **{"continue": str(proceed)})
    if fail_closed is not None:
        task["fail_closed_receipt"] = str(fail_closed)
        task["address_loss"] = address_loss
    plan_file.write_text(json.dumps(task), encoding="utf-8")
    process = guard = None
    normal_stop = False
    network_checks = None
    ipv6_control = None
    if ipv6_underlay is not None:
        ipv6_control = dict(baseline_udp=fixtures.adapter_datagram(
            ipv6_underlay, IPV6_CONTROL_SUBNET, ipv6=True, denied=False))
    with (directory / "app.log").open("wb") as app_log:
        try:
            installation_baseline = setupapi_baseline() if measure_wintun_install else None
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
                assert ipv6_payload is not None, "IPv6 payload fixture is unavailable"
                assert count >= 10 and CAPTURE_ROUTES == capture_routes(), "Expected Wintun routes and WFP protection"
                assert proxy_settings == proxy, "VPN changed WinINet proxy settings"
                assert powershell("(Get-NetIPInterface -InterfaceAlias 'flutter_vless_tun' "
                                  "-AddressFamily IPv4 -ErrorAction Stop).Dhcp") == "Disabled", \
                    "Wintun IPv4 unexpectedly uses DHCP"
                assert not powershell("$routes = @(Get-NetRoute -InterfaceAlias 'flutter_vless_tun' "
                                      "-DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue); "
                                      "$routes.DestinationPrefix"), "Wintun installed a default gateway"
                assert powershell("(Get-DnsClientServerAddress -InterfaceAlias 'flutter_vless_tun' "
                                  "-AddressFamily IPv4 -ErrorAction Stop).ServerAddresses") == "10.0.85.53", \
                    "Wintun IPv4 DNS differs from the protected resolver"
                # Dart's Socket.address can report the dialed address. Windows
                # socket probes confirm the local address via getsockname.
                assert fixtures.external_http(public_ip, vpn=True, verify_body=True) == "HTTP 200"
                for route in routes:
                    assert fixtures.request(route["host"], vpn=True) == route["expected_body"]
                ipv6_source = fixtures.tunnel_ipv6_address()
                network_checks = dict(
                    ipv6_tcp=fixtures.ipv6_payload_request(ipv6_payload, udp=False, source=ipv6_source),
                    ipv6_udp=fixtures.ipv6_payload_request(ipv6_payload, udp=True, source=ipv6_source),
                    ipv6_aaaa_udp=fixtures.ipv6_payload_dns(tcp=False),
                    ipv6_aaaa_tcp=fixtures.ipv6_payload_dns(tcp=True),
                    protected_dns_udp=fixtures.protected_dns(tcp=False),
                    protected_dns_tcp=fixtures.protected_dns(tcp=True),
                    system_dns=fixtures.system_dns(),
                    real_dns=fixtures.relayed_dns(),
                    physical_tcp=fixtures.physical_denied(public_ip, underlay, 443),
                    physical_dns_udp=fixtures.physical_denied("1.1.1.1", underlay, 53, True, probe),
                )
                if ipv6_control is not None:
                    ipv6_control.update(active_udp=fixtures.adapter_datagram(
                        ipv6_underlay, IPV6_CONTROL_SUBNET, ipv6=True, denied=True), active_tcp="WSAEACCES")
                if fail_closed is not None:
                    target, prefix_length = {"IPv4": ("10.0.85.2", 24),
                                             "IPv6": (ipv6_source, 64)}[address_loss]
                    # Remove only the exact manually provisioned Wintun address.
                    powershell("$address = @(Get-NetIPAddress -InterfaceAlias 'flutter_vless_tun' "
                               f"-AddressFamily {address_loss} -IPAddress '{target}' -PrefixLength {prefix_length} "
                               "-PrefixOrigin Manual -AddressState Preferred -PolicyStore ActiveStore "
                               "-ErrorAction Stop); if ($address.Count -ne 1) { throw 'Expected one owned tunnel address' }; "
                               "Remove-NetIPAddress -InputObject $address -Confirm:$false -ErrorAction Stop")
                    protected = wait_receipt(fail_closed, receipt, process, f"protected status after {address_loss} loss", 12)
                    assert protected == {"status": "CONNECTING", "address_family": address_loss}
                    assert int(fixtures.native(probe, "policy-count")) >= 10, f"WFP protection disappeared after {address_loss} loss"
                    network_checks.update(
                        address_loss_family=address_loss,
                        address_loss_status=protected["status"],
                        address_loss_physical_tcp=fixtures.physical_denied(public_ip, underlay, 443),
                        address_loss_physical_dns_udp=fixtures.physical_denied("1.1.1.1", underlay, 53, True, probe),
                    )
                    if ipv6_control is not None:
                        ipv6_control.update(after_loss_udp=fixtures.adapter_datagram(
                            ipv6_underlay, IPV6_CONTROL_SUBNET, ipv6=True, denied=True), after_loss_tcp="WSAEACCES")
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
                assert final["invalid_replacement_rejected"] is True
            times = {key: final[key] for key in
                     ("start_to_connected_ms", "start_to_first_https_ms", "stop_ms")}
            assert all(type(ms) is int and ms >= 0 for ms in times.values())
            assert times["start_to_first_https_ms"] >= times["start_to_connected_ms"]
            disconnected(probe, gateway, proxy)
            assert fixtures.external_http(public_ip, verify_body=True) == "HTTP 200"
            if network_checks is not None:
                assert physical_dns_servers(underlay) == dns_servers, "Physical DNS servers changed after Stop"
                query_restored_dns(dns_servers)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(4)
                    fixtures.pin_interface(sock, underlay)
                    sock.connect((public_ip, 443))
                network_checks.update(restored_dns=True, restored_physical_tcp=True)
                if ipv6_control is not None:
                    ipv6_control["restored_udp"] = fixtures.adapter_datagram(
                        ipv6_underlay, IPV6_CONTROL_SUBNET, ipv6=True, denied=False)
                    network_checks["ipv6_underlay_control"] = ipv6_control
            finish.touch()
            assert process.wait(timeout=10) == 0, "Consumer exited with an error after Stop"
            normal_stop = True
            result = dict(mode=mode, routing=direction, **times, routes=final["routes"],
                          active_https=200, restored_https=200)
            if mode == "vpn":
                stages = final["startup_stages_ms"]
                assert "ipv6_address" in stages and all(type(ms) is int and ms >= 0 for ms in stages.values())
                result["startup_stages_ms"] = stages
                result["ipv4_setup"] = final["ipv4_setup"]
                result["ipv4_dad_fallback"] = final["ipv4_dad_fallback"]
                result["ipv6_setup"] = final["ipv6_setup"]
                result["dns_setup"] = final["dns_setup"]
                result["invalid_replacement_rejected"] = True
                result["network_checks"] = network_checks
            if measure_wintun_install:
                setupapi = setupapi_wintun_delta(installation_baseline)
                result["setupapi_wintun"] = setupapi
                if wintun_benchmark:
                    result["wintun_benchmark"] = wintun_benchmark
                    assert setupapi["status"] in ("observed", "no_wintun_sections"), setupapi
                    staged_while_connecting = any(row["stage"] == "driver_stage" for row in setupapi["sections"])
                    assert staged_while_connecting == (wintun_benchmark == "control" and not reverse), \
                        "Wintun was installed during the wrong VPN startup"
            event = "WINDOWS_CONSUMER_IPV6_LOSS" if address_loss == "IPv6" else "WINDOWS_CONSUMER_LIVE"
            print(event + " " + json.dumps(result), flush=True)
            if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                with Path(summary).open("a", encoding="utf-8") as file:
                    if address_loss == "IPv6":
                        print("- Additional VPN session: IPv6 loss and Stop restoration passed.", file=file)
                    else:
                        print(f"- {mode} ({direction}): CONNECTED {times['start_to_connected_ms']} ms, "
                              f"first verified HTTPS {times['start_to_first_https_ms']} ms, "
                              f"Stop {times['stop_ms']} ms. Routing and network restoration passed.", file=file)
                    if mode == "vpn":
                        if address_loss != "IPv6":
                            print("  - Startup stages: " + ", ".join(f"{stage} {ms} ms" for stage, ms in stages.items()), file=file)
                        if measure_wintun_install:
                            sections = ", ".join(f"{row['stage']} {row['elapsed_ms']} ms" for row in setupapi["sections"])
                            print(f"  - Wintun SetupAPI: {setupapi['status']} ({sections or 'no completed sections'}).", file=file)
                        print("  - Protected DNS, physical-interface leak controls, and restored DNS passed.", file=file)
                        print("  - IPv6 TCP/UDP through Wintun and protected AAAA replies passed.", file=file)
                        if fail_closed is not None:
                            print(f"  - {address_loss} loss retained WFP protection until explicit Stop.", file=file)
                        if ipv6_control is not None:
                            print("  - Non-tunnel IPv6 TCP and UDP stayed blocked until Stop. UDP delivery restored.", file=file)
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
                if system_proxy() != proxy:
                    system_proxy(proxy)
            if guard is not None:
                guard_stop.touch()
                assert guard.wait(timeout=10) == 0, "Runner network watchdog failed"


def exercise_consumer(bundle, mode, directory, probe, *, wintun_benchmark=None):
    assert os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" \
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Disposable Windows runner required"
    assert ctypes.windll.shell32.IsUserAnAdmin(), "Windows runner token is not elevated"
    assert probe.is_file(), "Native network observer missing"
    # Reply synthetically only for the isolated DNS fixture. The runner needs
    # normal DNS while its own network traffic is captured by the VPN.
    fixtures.REAL_DNS = True
    fixtures.PROBE = probe
    public_ip = socket.gethostbyname(HTTPS_HOST)
    assert fixtures.external_http(public_ip, verify_body=True) == "HTTP 200"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as routing:
        routing.connect((public_ip, 443))
        underlay = routing.getsockname()[0]
    gateway, proxy = fixtures.native(probe, "gateway"), system_proxy()
    disconnected(probe, gateway, proxy)
    dns_servers = physical_dns_servers(underlay) if mode == "vpn" else None
    if dns_servers:
        query_restored_dns(dns_servers)
    baseline = (gateway, proxy, dns_servers)
    with route_fixtures(underlay, vpn=mode == "vpn") as ipv6_payload:
        for reverse in (False, True):
            case_directory = directory / ("reverse" if reverse else "original")
            case_directory.mkdir(parents=True)
            test_case(bundle, mode, case_directory, probe, public_ip, underlay, baseline, reverse, ipv6_payload,
                      address_loss="IPv4" if mode == "vpn" and reverse else None,
                      wintun_benchmark=wintun_benchmark)
        if mode == "vpn":
            case_directory = directory / "ipv6-loss"
            case_directory.mkdir(parents=True)
            with ipv6_underlay_control(bundle, case_directory / "underlay", probe) as ipv6_underlay:
                test_case(bundle, mode, case_directory, probe, public_ip, underlay, baseline, True, ipv6_payload,
                          address_loss="IPv6", ipv6_underlay=ipv6_underlay)
