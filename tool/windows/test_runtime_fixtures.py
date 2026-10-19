"""Fixture isolation checks run without Windows APIs or network access."""
import unittest
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import runtime_smoke as runtime


def question(name):
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return header + labels + b"\0\0\x01\0\x01"


class RuntimeFixtureTest(unittest.TestCase):
    def test_explicit_asset_root_contains_only_verified_custom_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, fixture = runtime.create_asset_root(Path(directory))
            root = Path(owner.name)
            try:
                self.assertTrue(root.is_absolute())
                self.assertEqual([fixture["file"]], [path.name for path in root.iterdir()])
                data = (root / fixture["file"]).read_bytes()
                self.assertEqual(base64.b64decode(fixture["base64"], validate=True), data)
                self.assertEqual(fixture["sha256"], hashlib.sha256(data).hexdigest())
                self.assertIn(b"files-fixture.invalid", data)
                self.assertFalse((root / "geoip.dat").exists())
                self.assertFalse((root / "geosite.dat").exists())
            finally:
                owner.cleanup()
            self.assertFalse(root.exists())

    def test_ext_asset_route_precedes_explicit_block_without_changing_api(self):
        fixture = {"file": "caller-geosite.dat", "code": "CALLER", "domain": "files-fixture.invalid"}
        for external in (None, "203.0.113.1"):
            profile = runtime.config(True, external, "192.0.2.10", 19086, fixture)
            self.assertEqual({"type": "field", "domain": ["ext:caller-geosite.dat:CALLER"], "outboundTag": "direct"}, profile["routing"]["rules"][0])
            self.assertEqual({"type": "field", "domain": ["full:files-fixture.invalid"], "outboundTag": "fixture-blocked"}, profile["routing"]["rules"][1])
            self.assertEqual("192.0.2.10", profile["dns"]["hosts"]["files-fixture.invalid"])
            self.assertEqual(runtime.config(True, external, "192.0.2.10", 19086)["api"], profile["api"])
            self.assertTrue(all(value is False for value in profile["policy"]["system"].values()))
            if external:
                self.assertEqual("external-direct", profile["routing"]["rules"][-1]["outboundTag"])

    def test_invalid_asset_manifest_is_refused_before_creating_a_root(self):
        source = {"file": "caller-geosite.dat", "code": "CALLER", "domain": "files-fixture.invalid", "base64": "YQ==", "sha256": "0" * 64}
        for change in ({}, {"file": "../foreign.dat"}, {"base64": "invalid%%"}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, \
                    patch.object(runtime.Path, "read_text", return_value=json.dumps(dict(source, **change))):
                with self.assertRaises((AssertionError, ValueError)):
                    runtime.create_asset_root(Path(directory))
                self.assertEqual([], list(Path(directory).iterdir()))

    def test_caller_api_case_is_optional_and_retains_disabled_counters(self):
        ordinary = runtime.config(False)
        for key in ("api", "stats", "policy"):
            self.assertNotIn(key, ordinary)
        profile = runtime.config(True, caller_api_port=19086)
        self.assertEqual({"tag": "caller-api", "listen": "127.0.0.1:19086",
                          "services": ["StatsService", "HandlerService"]}, profile["api"])
        self.assertEqual({}, profile["stats"])
        self.assertEqual({"system": {key: False for key in (
            "statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink")}}, profile["policy"])
        self.assertEqual(runtime.config(True)["routing"], profile["routing"])

    def test_caller_api_query_uses_known_runtime_and_fixture_port_only(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for nested in (False, True):
                executable = directory / "xray" / "xray.exe" if nested else directory / "xray.exe"
                executable.parent.mkdir(exist_ok=True)
                executable.touch()
                for reply in ("{}", '{"stat": []}'):
                    with self.subTest(nested=nested, reply=reply), patch.object(runtime.subprocess, "run") as run:
                        run.return_value = subprocess.CompletedProcess([], 0, reply, "")
                        runtime.check_caller_api(directory, 19086)
                        self.assertEqual([str(executable), "api", "statsquery", "-server=127.0.0.1:19086", "-timeout=2"], run.call_args.args[0])
                        self.assertEqual(3, run.call_args.kwargs["timeout"])
                        self.assertEqual(directory, run.call_args.kwargs["cwd"])
                        self.assertEqual("utf-8", run.call_args.kwargs["encoding"])
                with patch.object(runtime.subprocess, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], 0, "{}", "")
                    runtime.check_caller_api(directory, 19086, "owned-fixture-bottle")
                    self.assertEqual(["/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine", "--bottle", "owned-fixture-bottle"], run.call_args.args[0][:3])
                executable.unlink()

    def test_caller_api_query_rejects_failure_or_nonempty_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); (directory / "xray.exe").touch()
            for code, stdout in ((1, "{}"), (0, ""), (0, "[]"), (0, '{"stat": null}'),
                                 (0, '{"stat": [{"name": "inbound>>>caller>>>traffic>>>uplink", "value": "12"}]}'),
                                 (0, '{"foreign": []}'), (0, '{"stat":[1],"stat":[]}'), (0, " " * 65537)):
                with self.subTest(code=code, stdout=stdout[:80]), patch.object(runtime.subprocess, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], code, stdout, "")
                    with self.assertRaises((AssertionError, ValueError)):
                        runtime.check_caller_api(directory, 19086)
                    self.assertEqual(1, run.call_count)
            with patch.object(runtime.subprocess, "run", side_effect=subprocess.TimeoutExpired("known", 3)) as run:
                with self.assertRaises(AssertionError):
                    runtime.check_caller_api(directory, 19086)
                self.assertEqual(1, run.call_count)

    def test_caller_api_query_refuses_unqualified_port_or_missing_binary(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(runtime.subprocess, "run") as run:
            for port in (0, 65536, True, "127.0.0.1:19086", "19086"):
                with self.subTest(port=port), self.assertRaises((AssertionError, ValueError)):
                    runtime.check_caller_api(Path(temp), port)
            with self.assertRaises((AssertionError, ValueError)):
                runtime.check_caller_api(Path(temp), 19086)
            run.assert_not_called()

    def test_full_vpn_guard_still_precedes_any_socket_or_child(self):
        for name, environment in (("posix", {"GITHUB_ACTIONS": "true"}), ("nt", {})):
            with self.subTest(name=name), patch.object(runtime, "os", SimpleNamespace(name=name, environ=environment)), \
                    patch.object(runtime.sys, "argv", ["runtime_smoke.py", "--directory", "unused", "--vpn"]), \
                    patch.object(runtime.socket, "socket") as socket, patch.object(runtime.subprocess, "Popen") as child:
                with self.assertRaisesRegex(SystemExit, "disposable GitHub Windows runner"):
                    runtime.main()
                socket.assert_not_called()
                child.assert_not_called()

    def test_synthetic_dns_is_scoped_and_other_names_use_encrypted_relay(self):
        with patch.object(runtime, "REAL_DNS", True), \
                patch.object(runtime, "real_dns_response", return_value=b"relay") as relay:
            self.assertTrue(runtime.dns_response(question("controlled.invalid")).endswith(bytes([198, 51, 100, 7])))
            relay.assert_not_called()
            self.assertEqual(b"relay", runtime.dns_response(question("api.github.com")))
            relay.assert_called_once()

    def test_domain_controls_remain_explicit_before_external_traffic(self):
        for reverse in (False, True):
            rules = runtime.config(reverse, "203.0.113.1")["routing"]["rules"]
            self.assertEqual("external-direct", rules[-1]["outboundTag"])
            self.assertEqual("tcp,udp", rules[-1]["network"])
            self.assertEqual({"type": "field", "inboundTag": ["flutter-vless-tun"],
                              "outboundTag": "fixture-blocked"}, rules[0])
            self.assertEqual("direct", rules[2]["outboundTag"])
            self.assertEqual("proxy", rules[3]["outboundTag"])
            self.assertEqual(["full:2ip.ru", "full:2ip.io"] if reverse else ["full:myip.com"], rules[3]["domain"])

    def test_proxy_only_fixture_keeps_original_default_outbound(self):
        profile = runtime.config(False)
        self.assertEqual("proxy", profile["outbounds"][0]["tag"])
        self.assertFalse(any(outbound["tag"] == "external-direct" for outbound in profile["outbounds"]))
        with patch.object(runtime, "REAL_DNS", False), patch.object(runtime, "real_dns_response") as relay:
            self.assertTrue(runtime.dns_response(question("example.com")).endswith(bytes([198, 51, 100, 7])))
            relay.assert_not_called()

    def test_encrypted_relay_checks_certificate_endpoint_status_and_dns_reply(self):
        query = question("example.com")
        reply = b"\x12\x34\x81\x80" + bytes(8)
        with patch.object(runtime.http.client, "HTTPSConnection") as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "application/dns-message"
            response.read.return_value = reply
            self.assertEqual(reply, runtime.real_dns_response(query))
            self.assertEqual("1.1.1.1", factory.call_args.args[0])
            self.assertTrue(factory.call_args.kwargs["context"].check_hostname)
            self.assertEqual(query, factory.return_value.request.call_args.kwargs["body"])
            response.status = 403
            with self.assertRaises(ValueError):
                runtime.real_dns_response(query)
            response.status = 200
            response.read.return_value = b"\0\0" + reply[2:]
            with self.assertRaises(ValueError):
                runtime.real_dns_response(query)


if __name__ == "__main__":
    unittest.main()
