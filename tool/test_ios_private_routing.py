#!/usr/bin/env python3
"""Opt-in real-server routing checks. Profile files and IPs are never published.

Usage: SIMULATOR_UDID=... python3 tool/test_ios_private_routing.py private1.json private2.json
Requires the supplied two-loopback-SOCKS profile shape (primary + direct tag).
Native policy/runner code is compiled from the current tree; host VPN is untouched.
"""
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
UDID = os.environ["SIMULATOR_UDID"]
BUNDLE = "dev.tfox.private-routing-probe"
PORT, DIRECT_PORT = 25080, 25081
DIRECT_URL, PROXY_URL = "https://api.ipify.org", "https://api4.ipify.org"
profiles = [json.loads(Path(name).read_text()) for name in sys.argv[1:]]
if not profiles:
    raise SystemExit("Pass private profile JSON paths; do not commit their contents.")
for port in (PORT, DIRECT_PORT):
    with socket.socket() as control:
        control.bind(("127.0.0.1", port))
output = ROOT / "build/private-routing-results.json"
summary = {"passed": False, "platform": "ios-simulator", "host_vpn_changed": False, "profiles": []}

def execute(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)

with tempfile.TemporaryDirectory(prefix="flutter-vless-private-routing-") as directory:
    work = Path(directory)
    app = work / "Probe.app"
    app.mkdir()
    modules = work / "modules"
    modules.mkdir()
    source = (ROOT / "ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift").read_text()
    head = source[:source.index("public class FlutterVlessPlugin:")].replace("import Flutter\n", "")
    asset = source[source.index("private func configureXrayAssetLocation"):source.index("final class PacketTunnelManager:")]
    (work / "main.swift").write_text(head + asset + (ROOT / "tool/fixtures/ios_private_routing_probe.swift").read_text())
    sdk = execute(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"]).stdout.decode().strip()
    common = ["-O", "-target", os.uname().machine + "-apple-ios15.0-simulator", "-sdk", sdk]
    for module, object_name in [("flutter_vless_privacy", "privacy"), ("flutter_vless_tunnel_support", "support")]:
        execute(["xcrun", "swiftc", *common, "-parse-as-library", "-I", str(modules), "-module-name", module,
                 "-emit-module", "-emit-object", "-whole-module-optimization", "-emit-module-path", str(modules / (module + ".swiftmodule")),
                 *map(str, (ROOT / "ios/flutter_vless/Sources" / module).glob("*.swift")), "-o", str(modules / (object_name + ".o"))])
    execute(["xcrun", "swiftc", *common, "-I", str(modules), "-F", str(ROOT / "ios/XRay.xcframework/ios-arm64_x86_64-simulator"),
             "-framework", "XRay", "-framework", "UIKit", "-lresolv", str(work / "main.swift"),
             str(ROOT / "ios/flutter_vless/Sources/flutter_vless/BoundedNativeLogStore.swift"), str(modules / "privacy.o"),
             str(modules / "support.o"), "-o", str(app / "Probe")])
    info = {"CFBundleIdentifier": BUNDLE, "CFBundleExecutable": "Probe", "CFBundleName": "Routing Probe",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
            "MinimumOSVersion": "15.0", "LSRequiresIPhoneOS": True, "UIDeviceFamily": [1, 2]}
    process = None
    log = None

    def stop():
        global process, log
        subprocess.run(["xcrun", "simctl", "terminate", UDID, BUNDLE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if process is not None:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process = None
        if log is not None:
            log.close()
            log = None
        subprocess.run(["xcrun", "simctl", "uninstall", UDID, BUNDLE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start(profile, mode):
        global process, log
        stop()
        (app / "profile.json").write_text(json.dumps(profile))
        (app / "profile.json").chmod(0o600)
        with (app / "Info.plist").open("wb") as stream:
            plistlib.dump(dict(info, RoutingMode=mode), stream)
        execute(["codesign", "--force", "--sign", "-", str(app)])
        execute(["xcrun", "simctl", "install", UDID, str(app)])
        log = (work / "runtime.log").open("wb")
        process = subprocess.Popen(["xcrun", "simctl", "launch", "--console", UDID, BUNDLE], stdout=log, stderr=log)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            text = (work / "runtime.log").read_text(errors="replace")
            if "ROUTING_READY" in text:
                if mode == "original":
                    assert "ROUTING_ORIGINAL_VPN_REJECT_PASS" in text
                return
            if process.poll() is not None:
                raise RuntimeError("Private native probe stopped before readiness (native details withheld)")
            time.sleep(.1)
        raise RuntimeError("Private native probe readiness timed out")

    def observed_ip(url, port, authenticated=False):
        args = ["curl", "--silent", "--show-error", "--fail", "--max-time", "30", "--noproxy", "", "--proxy",
                f"socks5h://127.0.0.1:{port}", "--http1.1", "--ipv4"]
        if authenticated:
            args += ["--proxy-user", "routing-fixture-user:routing-fixture-password"]
        response = execute([*args, url]).stdout.decode().strip()
        return ipaddress.ip_address(response)

    def counters():
        time.sleep(.25)
        matches = re.findall(r"ROUTING_COUNTERS=(\d+),(\d+)", (work / "runtime.log").read_text(errors="replace"))
        assert matches, "Missing real native routing counters"
        return tuple(map(int, matches[-1]))

    try:
        for index, original in enumerate(profiles, 1):
            profile = json.loads(json.dumps(original))
            assert len(profile["inbounds"]) == 2
            profile["inbounds"][0]["port"] = PORT
            profile["inbounds"][1]["port"] = DIRECT_PORT
            profile.setdefault("stats", {})
            profile.setdefault("policy", {}).setdefault("system", {}).update(
                statsOutboundUplink=True, statsOutboundDownlink=True)
            start(profile, "original")
            before = counters()
            direct = observed_ip(DIRECT_URL, DIRECT_PORT)
            after_direct = counters()
            assert after_direct[0] > before[0], "Direct listener did not transfer through direct outbound"
            proxy = observed_ip(DIRECT_URL, PORT)
            after_proxy = counters()
            assert after_proxy[1] > after_direct[1], "Primary listener did not transfer through proxy outbound"
            assert after_proxy[0] == after_direct[0], "Primary listener also transferred through direct outbound"
            # The Mac's existing VPN may use the same exit as the tested server.
            # Native per-outbound counters distinguish routing even in that case.
            proxy_other_domain = observed_ip(PROXY_URL, PORT)
            print(f"PASS profile {index}: original proxyOnly inbound routing and VPN rejection", flush=True)
            profile["inbounds"] = profile["inbounds"][:1]
            profile["routing"]["rules"] = [
                {"type": "field", "domain": ["full:api.ipify.org"], "outboundTag": "direct"},
                {"type": "field", "domain": ["full:api4.ipify.org"], "outboundTag": "proxy"}]
            for generation in range(2):
                start(profile, "vpn")
                before = counters()
                routed_direct = observed_ip(DIRECT_URL, PORT, True)
                after_direct = counters()
                assert after_direct[0] > before[0], "Direct domain did not increase the native direct counter"
                routed_proxy = observed_ip(PROXY_URL, PORT, True)
                after_proxy = counters()
                assert after_proxy[1] > after_direct[1], "Proxy domain did not increase the native proxy counter"
                assert after_proxy[0] == after_direct[0], "Proxy domain also produced direct traffic"
                # Exit pools may rotate addresses between connections. Egress
                # equality is recorded below; path acceptance uses native counters.
                print(f"PASS profile {index}: protected domain routing, runtime generation {generation}", flush=True)
            summary["profiles"].append({"index": index, "original_proxy_only_routing": True,
                "original_vpn_rejected": True, "distinct_egress": direct != proxy, "protected_domain_routing_generations": 2,
                "native_outbound_counter_routing": True, "direct_baseline_matches": routed_direct == direct,
                "proxy_same_domain_baseline_matches": routed_proxy == proxy_other_domain})
        summary["passed"] = True
    finally:
        stop()
        output.write_text(json.dumps(summary, indent=2) + "\n")
print("PASS: private iOS routing; sanitized report: " + str(output))
