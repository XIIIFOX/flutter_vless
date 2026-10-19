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
from unittest.mock import Mock

import runtime_smoke as runtime


def question(name):
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return header + labels + b"\0\0\x01\0\x01"


class RuntimeFixtureTest(unittest.TestCase):
    def test_direct_only_profiles_preserve_default_order_and_dns_tag_route(self):
        corpus_path = Path(runtime.__file__).resolve().parents[2] / "tool/fixtures/compatibility/direct-only.json"
        original = corpus_path.read_bytes()
        for index in (0, 1):
            source = json.loads(original)[index]["config"]
            actual = runtime.direct_only_config(index, "192.0.2.10", 15353)
            self.assertEqual(source["routing"], actual["routing"])
            self.assertEqual([o["protocol"] for o in source["outbounds"]], [o["protocol"] for o in actual["outbounds"]])
            self.assertEqual([o["tag"] for o in source["outbounds"]], [o["tag"] for o in actual["outbounds"]])
            self.assertEqual(["tcp://192.0.2.10:15353"], actual["dns"]["servers"])
            self.assertEqual(source["dns"]["queryStrategy"], actual["dns"]["queryStrategy"])
            direct = next(o for o in actual["outbounds"] if o["tag"] == "direct")
            self.assertEqual("192.0.2.10:0", direct["settings"]["redirect"])
        self.assertEqual(original, corpus_path.read_bytes())

    def test_selector_profile_preserves_round_robin_prefix_and_finds_direct_by_role(self):
        path = Path(runtime.__file__).resolve().parents[2] / "tool/fixtures/compatibility/selector-traffic.json"
        encoded = path.read_bytes(); source = json.loads(encoded)
        actual = runtime.direct_only_config(2, "192.0.2.10", 15353)
        self.assertEqual(source["routing"], actual["routing"])
        self.assertEqual("flutter-vless-caller-direct", actual["outbounds"][0]["tag"])
        self.assertEqual("192.0.2.10:0", actual["outbounds"][0]["settings"]["redirect"])
        self.assertEqual(source["outbounds"][1], actual["outbounds"][1])
        self.assertEqual(["flutter-vless"], actual["routing"]["balancers"][0]["selector"])
        self.assertEqual(["tcp://192.0.2.10:15353"], actual["dns"]["servers"])
        self.assertEqual(encoded, path.read_bytes())

    def test_direct_tcp_dns_fixture_observes_and_frames_exact_question(self):
        query = question("remote.invalid")
        stream = bytearray(len(query).to_bytes(2, "big") + query)
        client = Mock()
        def recv(count):
            result = bytes(stream[:count]); del stream[:count]; return result
        client.recv.side_effect = recv
        server = SimpleNamespace(questions=[], questions_lock=runtime.threading.Lock())
        runtime.DirectDns(client, ("192.0.2.10", 50000), server)
        answer = client.sendall.call_args.args[0]
        self.assertEqual(len(answer) - 2, int.from_bytes(answer[:2], "big"))
        self.assertEqual(query[:2], answer[2:4])
        self.assertEqual([query[12:].hex()], server.questions)
        self.assertTrue(answer.endswith(b"\xc6\x33\x64\x07"))

    def test_direct_only_virtual_dns_requires_tun_source_reply_and_resolver_observation(self):
        for tcp in (False, True):
            for defect in (None, "source", "reply", "unobserved"):
                with self.subTest(tcp=tcp, defect=defect):
                    client = Mock(); client.__enter__ = Mock(return_value=client); client.__exit__ = Mock(return_value=False)
                    client.getsockname.return_value = ("192.0.2.10" if defect == "source" else "10.0.85.2", 50000)
                    server = SimpleNamespace(questions=[], questions_lock=runtime.threading.Lock())
                    response = bytearray()
                    def send(data):
                        query = data[2:] if tcp else data
                        if defect != "unobserved": server.questions.append(query[12:].hex())
                        answer = runtime.dns_response(query)
                        if defect == "reply": answer = answer[:-4] + bytes(4)
                        response.extend((len(answer).to_bytes(2, "big") if tcp else b"") + answer)
                    def recv(count):
                        result = bytes(response[:count]); del response[:count]; return result
                    client.sendall.side_effect = send; client.recv.side_effect = recv
                    with patch.object(runtime.socket, "socket", return_value=client):
                        if defect is None: runtime.direct_only_dns(server, tcp)
                        else:
                            with self.assertRaises(AssertionError): runtime.direct_only_dns(server, tcp)
                    client.connect.assert_called_once_with(("198.18.0.2", 53))

    def test_direct_only_origin_observes_denied_host_before_sending_bytes(self):
        handler = runtime.Direct.__new__(runtime.Direct)
        handler.server = SimpleNamespace(direct_only_observed=[], direct_only_lock=runtime.threading.Lock())
        handler.headers = {"Host": "blocked.invalid"}
        handler.send_response = Mock(); handler.send_header = Mock(); handler.end_headers = Mock(); handler.wfile = Mock()
        handler.do_GET()
        self.assertEqual(["blocked.invalid"], handler.server.direct_only_observed)
        handler.wfile.write.assert_called_once_with(b"DIRECT-FIXTURE")

    def test_direct_only_gate_timeout_does_not_hide_origin_delivery_and_drains_owned_children(self):
        for delivered in (False, True):
            with self.subTest(delivered=delivered), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); origin = SimpleNamespace(); children = []
                def launch(command, **kwargs):
                    child = Mock(pid=200 + len(children)); child.poll.return_value = None
                    def wait(timeout): child.poll.return_value = 0; return 0
                    child.wait.side_effect = wait; children.append(child)
                    if command[1] == "run-vpn":
                        kwargs["stdout"].write("START_RETURN=1\n"); kwargs["stdout"].flush()
                    return child
                def http(host, vpn):
                    self.assertTrue(vpn)
                    if host == "blocked.invalid":
                        if delivered: origin.direct_only_observed.append(host)
                        raise runtime.socket.timeout("controlled missing response")
                    origin.direct_only_observed.append(host)
                    return "DIRECT-FIXTURE"
                with patch.object(runtime.subprocess, "Popen", side_effect=launch), \
                     patch.object(runtime.subprocess, "check_output", return_value='{"Routes":0,"IPv6Addresses":0}'), \
                     patch.object(runtime, "native", return_value="0") as native, \
                     patch.object(runtime, "request", side_effect=http), \
                     patch.object(runtime, "direct_only_dns"), patch.object(runtime.time, "sleep"):
                    if delivered:
                        with self.assertRaisesRegex(AssertionError, "controlled origin"):
                            runtime.direct_only_gate(directory / "runtime_probe.exe", directory, "192.0.2.10",
                                                     SimpleNamespace(server_address=("192.0.2.10", 15353)), origin, [])
                    else:
                        rows = []
                        runtime.direct_only_gate(directory / "runtime_probe.exe", directory, "192.0.2.10",
                                                 SimpleNamespace(server_address=("192.0.2.10", 15353)), origin, rows)
                        self.assertEqual(6, len(rows)); self.assertTrue(all(row["passed"] for row in rows))
                        self.assertEqual({"vpn-direct-only-freedom-default", "vpn-direct-only-block-default", "vpn-direct-only-selector-round-robin"}, {row["mode"] for row in rows})
                        self.assertEqual(6, origin.direct_only_observed.count("direct-only.invalid"))
                    self.assertEqual(2 if delivered else 6, len(children))
                    for child in children: child.wait.assert_called(); child.kill.assert_not_called()
                    self.assertTrue(any(call.args[1] == "release-protection" for call in native.call_args_list))

    def test_ipv6_profile_keeps_numeric_ipv4_proxy_and_exact_payload_route(self):
        ordinary = runtime.config(False, "203.0.113.1", "192.0.2.10")
        profile = runtime.config(False, "203.0.113.1", "192.0.2.10", ipv6_payload=True)
        self.assertEqual(ordinary["outbounds"], profile["outbounds"])
        self.assertEqual("192.0.2.10", profile["outbounds"][0]["settings"]["servers"][0]["address"])
        self.assertEqual(ordinary["routing"]["rules"][0], profile["routing"]["rules"][0])
        self.assertEqual({"type": "field", "ip": [runtime.IPV6_PAYLOAD_TARGET + "/128"],
                          "network": "tcp,udp", "outboundTag": "proxy"}, profile["routing"]["rules"][1])
        self.assertEqual(runtime.IPV6_PAYLOAD_TARGET, profile["dns"]["hosts"]["ipv6-payload.invalid"])
        self.assertEqual(ordinary["routing"]["rules"][1:], profile["routing"]["rules"][2:])

    def test_ipv6_marker_state_requires_exact_destination_and_one_shot_nonce(self):
        address = runtime.socket.inet_pton(runtime.socket.AF_INET6, runtime.IPV6_PAYLOAD_TARGET)
        for transport in ("tcp", "udp"):
            for changed in ("kind", "address", "port", "nonce", "no-association"):
                if transport == "tcp" and changed == "no-association":
                    continue
                with self.subTest(transport=transport, changed=changed):
                    state = runtime.IPv6PayloadState()
                    payload = state.arm(transport)
                    control = object()
                    if transport == "udp" and changed != "no-association":
                        self.assertTrue(state.control_open(control, "192.0.2.10"))
                    reply = state.accept(transport, 1 if changed == "kind" else 4,
                                         bytes(16) if changed == "address" else address,
                                         1 if changed == "port" else runtime.IPV6_PAYLOAD_PORT,
                                         b"foreign-marker" if changed == "nonce" else payload,
                                         "192.0.2.10" if transport == "udp" else None)
                    self.assertIsNone(reply)
                    with self.assertRaises(AssertionError):
                        state.require_observed(transport, payload)
                    state.control_close(control)
                    state.close()
        state = runtime.IPv6PayloadState()
        payload = state.arm("tcp")
        self.assertEqual(b"accepted-" + payload, state.accept("tcp", 4, address, runtime.IPV6_PAYLOAD_PORT, payload))
        state.require_observed("tcp", payload)
        self.assertIsNone(state.accept("tcp", 4, address, runtime.IPV6_PAYLOAD_PORT, payload))

    def test_ipv6_socks_tcp_verifies_captured_atyp_target_and_bytes(self):
        state = runtime.IPv6PayloadState()
        payload = state.arm("tcp")
        address = runtime.socket.inet_pton(runtime.socket.AF_INET6, runtime.IPV6_PAYLOAD_TARGET)
        stream = bytearray(b"\x05\x01\x00\x05\x01\x00\x04" + address
                           + runtime.IPV6_PAYLOAD_PORT.to_bytes(2, "big") + payload)
        client = Mock()
        def recv(count):
            result = bytes(stream[:count]); del stream[:count]; return result
        client.recv.side_effect = recv
        server = SimpleNamespace(ipv6_payload=state, server_address=("192.0.2.10", 18582))
        runtime.Socks(client, ("192.0.2.10", 50000), server)
        self.assertEqual(b"accepted-" + payload, client.sendall.call_args.args[0])
        self.assertEqual(bytearray(), stream)
        state.require_observed("tcp", payload)
        state.close(); state.require_clean()

    def test_ipv6_socks_udp_association_replies_with_same_numeric_ipv4_endpoint(self):
        state = runtime.IPv6PayloadState()
        stream = bytearray(b"\x05\x01\x00\x05\x03\x00\x01" + bytes(6))
        client = Mock()
        def recv(count):
            result = bytes(stream[:count]); del stream[:count]; return result
        client.recv.side_effect = recv
        server = SimpleNamespace(ipv6_payload=state, server_address=("192.0.2.10", 18582))
        runtime.Socks(client, ("192.0.2.10", 50000), server)
        self.assertEqual(b"\x05\x00\x00\x01\xc0\x00\x02\x0a" + (18582).to_bytes(2, "big"), client.sendall.call_args.args[0])
        self.assertFalse(state.controls)
        state.close(); state.require_clean()

    def test_ipv6_datagram_requires_live_association_and_exact_unfragmented_header(self):
        for changed in (None, "fragment", "ipv4", "target", "port", "nonce", "no-association"):
            with self.subTest(changed=changed):
                state = runtime.IPv6PayloadState()
                payload = state.arm("udp")
                control = object()
                if changed != "no-association":
                    state.control_open(control, "192.0.2.10")
                address = runtime.socket.inet_pton(runtime.socket.AF_INET6, runtime.IPV6_PAYLOAD_TARGET)
                prefix = b"\0\0" + (b"\1" if changed == "fragment" else b"\0") + (b"\1" if changed == "ipv4" else b"\4")
                packet = prefix + (bytes(16) if changed == "target" else address) \
                    + (1 if changed == "port" else runtime.IPV6_PAYLOAD_PORT).to_bytes(2, "big") \
                    + (b"foreign" if changed == "nonce" else payload)
                relay = Mock()
                runtime.IPv6PayloadDatagram((packet, relay), ("192.0.2.10", 50001), SimpleNamespace(ipv6_payload=state))
                if changed is None:
                    relay.sendto.assert_called_once_with(packet[:22] + b"accepted-" + payload, ("192.0.2.10", 50001))
                    state.require_observed("udp", payload)
                else:
                    relay.sendto.assert_not_called()
                    self.assertTrue(state.errors)
                state.control_close(control)
                state.close()

    def test_ipv6_state_close_interrupts_only_owned_controls_and_revokes_admission(self):
        state = runtime.IPv6PayloadState()
        owned = Mock()
        owned.close.side_effect = lambda: state.control_close(owned)
        self.assertTrue(state.control_open(owned, "192.0.2.10"))
        state.close()
        owned.shutdown.assert_called_once_with(runtime.socket.SHUT_RDWR)
        owned.close.assert_called_once()
        self.assertFalse(state.control_open(object(), "192.0.2.10"))
        with self.assertRaises(AssertionError):
            state.arm("tcp")
        state.require_clean()

    def test_ipv6_client_requires_owned_tun_source_and_independent_proxy_observation(self):
        for udp in (False, True):
            for changed in (None, "source", "reply", "no-observation"):
                with self.subTest(udp=udp, changed=changed):
                    state = runtime.IPv6PayloadState()
                    client = Mock()
                    client.__enter__ = Mock(return_value=client)
                    client.__exit__ = Mock(return_value=False)
                    client.getsockname.return_value = ("::1" if changed == "source" else runtime.IPV6_TUN_SOURCE, 50000, 0, 0)
                    response = bytearray()
                    def send(payload):
                        if changed != "no-observation":
                            address = runtime.socket.inet_pton(runtime.socket.AF_INET6, runtime.IPV6_PAYLOAD_TARGET)
                            state.accept("udp" if udp else "tcp", 4, address, runtime.IPV6_PAYLOAD_PORT, payload)
                        response.extend(bytes(len(b"accepted-" + payload)) if changed == "reply" else b"accepted-" + payload)
                    def recv(count):
                        reply = bytes(response[:count]); del response[:count]; return reply
                    client.sendall.side_effect = send
                    client.recv.side_effect = recv
                    # UDP state normally has the independently authenticated
                    # TCP association; this fake client only tests publication.
                    with patch.object(runtime.socket, "socket", return_value=client) as factory:
                        if changed is None:
                            self.assertIn("IPv6", runtime.ipv6_payload_request(state, udp))
                        else:
                            with self.assertRaises(AssertionError):
                                runtime.ipv6_payload_request(state, udp)
                    factory.assert_called_once_with(runtime.socket.AF_INET6,
                                                    runtime.socket.SOCK_DGRAM if udp else runtime.socket.SOCK_STREAM)
                    client.connect.assert_called_once_with((runtime.IPV6_PAYLOAD_TARGET, runtime.IPV6_PAYLOAD_PORT))

    def test_ipv6_aaaa_probe_requires_protected_source_and_exact_caller_answer(self):
        for tcp in (False, True):
            for changed in (None, "source", "empty", "question", "address"):
                with self.subTest(tcp=tcp, changed=changed):
                    client = Mock()
                    client.__enter__ = Mock(return_value=client)
                    client.__exit__ = Mock(return_value=False)
                    client.getsockname.return_value = ("192.0.2.10" if changed == "source" else "10.0.85.2", 50000)
                    response = bytearray()
                    def send(data):
                        query = data[2:] if tcp else data
                        self.assertEqual(("ipv6-payload.invalid", len(query)), runtime.dns_question(query))
                        self.assertEqual(b"\x00\x1c\x00\x01", query[-4:])
                        question_bytes = bytes(len(query) - 12) if changed == "question" else query[12:]
                        answer = query[:2] + b"\x81\x80\x00\x01" + (bytes(2) if changed == "empty" else b"\x00\x01") \
                            + bytes(4) + question_bytes + b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x10" \
                            + (bytes(16) if changed == "address" else runtime.socket.inet_pton(runtime.socket.AF_INET6, runtime.IPV6_PAYLOAD_TARGET))
                        response.extend((len(answer).to_bytes(2, "big") if tcp else b"") + answer)
                    def recv(count):
                        reply = bytes(response[:count]); del response[:count]; return reply
                    client.sendall.side_effect = send
                    client.recv.side_effect = recv
                    with patch.object(runtime.socket, "socket", return_value=client) as factory:
                        if changed is None:
                            self.assertIn("AAAA", runtime.ipv6_payload_dns(tcp))
                        else:
                            with self.assertRaises(AssertionError):
                                runtime.ipv6_payload_dns(tcp)
                    factory.assert_called_once_with(runtime.socket.AF_INET,
                                                    runtime.socket.SOCK_STREAM if tcp else runtime.socket.SOCK_DGRAM)
                    client.connect.assert_called_once_with(("198.18.0.2", 53))

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
