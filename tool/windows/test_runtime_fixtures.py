"""Fixture isolation checks run without Windows APIs or network access."""
import unittest
import ast
import base64
import hashlib
import json
import io
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
    def test_actual_rejection_publisher_is_invisible_until_closed_and_complete(self):
        # Execute the actual main() publication expression, with a synchronous
        # reader interleaved after open and each partial write (no child/thread).
        main = next(node for node in ast.parse(Path(runtime.__file__).read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and (
                     isinstance(node.value.func, ast.Attribute)
                     and isinstance(node.value.func.value, ast.Name)
                     and node.value.func.value.id == "rejection" and node.value.func.attr == "write_text"
                     or isinstance(node.value.func, ast.Name) and node.value.func.id == "publish_rejection")]
        self.assertEqual(1, len(calls), "Actual command publication boundary changed")
        command = compile(ast.fix_missing_locations(ast.Module(body=calls, type_ignores=[])), "<actual-publisher>", "exec")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "state.json.reject"
            document = {"outbounds": [{"protocol": "synthetic-invalid"}], "canary": "private-test-value"}
            expected = json.dumps(document).encode()
            observations = []; writers = []
            original_open, original_fdopen, original_replace = Path.open, runtime.os.fdopen, runtime.os.replace
            def observe(): observations.append(target.read_bytes() if target.exists() else None)
            class InterleavedWriter:
                def __init__(self, stream): self.stream = stream; writers.append(stream); observe()
                def __enter__(self): self.stream.__enter__(); return self
                def __exit__(self, *args): return self.stream.__exit__(*args)
                def __getattr__(self, name): return getattr(self.stream, name)
                def write(self, text):
                    split = max(1, len(text) // 2)
                    self.stream.write(text[:split]); self.stream.flush(); observe()
                    self.stream.write(text[split:]); self.stream.flush(); observe()
                    return len(text)
            def opened(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                mode = kwargs.get("mode", args[0] if args else "r")
                return InterleavedWriter(stream) if "w" in mode else stream
            def fdopened(*args, **kwargs): return InterleavedWriter(original_fdopen(*args, **kwargs))
            def replaced(source, destination):
                self.assertTrue(writers and all(writer.closed for writer in writers))
                self.assertEqual(target.parent, Path(source).parent)
                self.assertEqual(target, Path(destination)); observe()
                return original_replace(source, destination)
            with patch.object(Path, "open", opened), patch.object(runtime.os, "fdopen", fdopened), \
                 patch.object(runtime.os, "replace", replaced):
                exec(command, {"rejection": target, "invalid": document, "json": json,
                               "publish_rejection": getattr(runtime, "publish_rejection", None)})
            self.assertGreaterEqual(len(observations), 3)
            self.assertTrue(all(value is None for value in observations),
                            "Reader observed a published empty/partial/open command")
            self.assertEqual(expected, target.read_bytes())
            self.assertEqual([target], list(target.parent.iterdir()))

    def test_rejection_publication_failures_close_writer_remove_temp_and_keep_original(self):
        for stage in ("write", "replace"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / "state.json.reject"; target.write_text("previous-complete-command")
                primary = OSError("synthetic publication failure"); writers = []
                original = runtime.os.fdopen
                def opened(*args, **kwargs):
                    stream = original(*args, **kwargs); writers.append(stream)
                    if stage == "write":
                        class FailedWriter:
                            def __enter__(self): return self
                            def __exit__(self, *args): return stream.__exit__(*args)
                            def write(self, text): stream.write(text[:1]); raise primary
                        return FailedWriter()
                    return stream
                with patch.object(runtime.os, "fdopen", opened), \
                     patch.object(runtime.os, "replace", side_effect=primary) as replace:
                    with self.assertRaises(OSError) as raised: runtime.publish_rejection(target, {"synthetic": "value"})
                self.assertIs(primary, raised.exception)
                self.assertTrue(writers and all(stream.closed for stream in writers))
                self.assertEqual("previous-complete-command", target.read_text())
                self.assertEqual([target], list(target.parent.iterdir()))
                self.assertEqual(0 if stage == "write" else 1, replace.call_count)

    def test_rejection_waiter_retains_numeric_child_exit_before_cleanup_without_raw_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"; log = Path(temporary) / "runtime.log"
            state.write_text(json.dumps({"running": True, "protecting": True, "secret": "private-state-canary"}))
            log.write_text("START_RETURN=1\nprivate-log-canary\n")
            process = Mock(); process.poll.return_value = 3221226505
            with self.assertRaises(RuntimeError) as raised:
                runtime.await_rejected_replacement(process, log, state, False)
            self.assertEqual("Invalid replacement did not preserve the live session", str(raised.exception))
            saved = Path(str(state) + ".rejection.evidence.log").read_text()
            record = json.loads(saved)
            self.assertEqual("CHILD_EXIT", record["stage"]); self.assertTrue(record["before_stop"])
            self.assertEqual(3221226505, record["process_exit"])
            self.assertEqual({"running": True, "protecting": True}, record["state"])
            self.assertFalse(record["replacement_marker"] or record["asset_marker"])
            self.assertLess(len(saved), 512)
            self.assertNotIn("canary", saved + str(getattr(raised.exception, "__notes__", [])))
            process.poll.assert_called_once(); process.kill.assert_not_called(); process.wait.assert_not_called()

    def test_rejection_waiter_keeps_exact_markers_deadline_and_fixed_failure_on_bad_state(self):
        for asset in (False, True):
            with self.subTest(asset=asset), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary) / "state.json"; log = Path(temporary) / "runtime.log"
                log.write_text("REJECTED_REPLACEMENT_PRESERVED=1\n")
                process = Mock(); process.poll.return_value = None
                if not asset:
                    runtime.await_rejected_replacement(process, log, state, False)
                    process.poll.assert_not_called()
                else:
                    # Required asset marker remains absent: do not accept the
                    # replacement marker alone or widen the existing25s budget.
                    state.write_text("private-state-canary" * 4097)
                    with patch.object(runtime.time, "monotonic", side_effect=[10, 35]), \
                         patch.object(runtime.time, "sleep") as sleep:
                        with self.assertRaises(RuntimeError): runtime.await_rejected_replacement(process, log, state, True)
                    record = json.loads(Path(str(state) + ".rejection.evidence.log").read_text())
                    self.assertEqual("TIMEOUT", record["stage"]); self.assertIsNone(record["process_exit"])
                    self.assertTrue(record["replacement_marker"]); self.assertFalse(record["asset_marker"])
                    self.assertEqual({"status": "invalid"}, record["state"]); sleep.assert_not_called()
                    log.write_text("REJECTED_REPLACEMENT_PRESERVED=1\nREJECTED_ASSET_ROOT_PRESERVED=1\n")
                    runtime.await_rejected_replacement(process, log, state, True)

    def test_occupied_private_ports_close_exact_owners_on_success_and_failure(self):
        for failure_stage in (None, "second_bind", "body"):
            with self.subTest(failure_stage=failure_stage):
                owners = [Mock(), Mock()]
                for owner in owners:
                    owner.__enter__ = Mock(return_value=owner)
                    owner.__exit__ = Mock(return_value=False)
                failure = RuntimeError("synthetic controlled failure")
                if failure_stage == "second_bind": owners[1].bind.side_effect = failure
                with patch.object(runtime.socket, "socket", side_effect=owners), \
                     patch.object(runtime.socket, "SO_EXCLUSIVEADDRUSE", 123, create=True):
                    if failure_stage:
                        with self.assertRaises(RuntimeError) as raised:
                            with runtime.occupied_private_ports():
                                if failure_stage == "body": raise failure
                        self.assertIs(failure, raised.exception)
                    else:
                        with runtime.occupied_private_ports(): pass
                for owner, port in zip(owners, (10807, 10086)):
                    owner.bind.assert_called_once_with(("127.0.0.1", port))
                    owner.setsockopt.assert_called_once_with(runtime.socket.SOL_SOCKET, 123, 1)
                    owner.__exit__.assert_called_once()
                if failure_stage != "second_bind":
                    for owner in owners: owner.listen.assert_called_once_with(1)

    def test_native_routing_proxy_does_not_feed_previous_ipv6_nonce_observer(self):
        state = runtime.IPv6PayloadState()
        # This is a valid ordinary HTTP payload to an IPv6 target, not the
        # prior scenario's one-shot IPv6 marker protocol.
        stream = bytearray(b"\x05\x01\x00\x05\x01\x00\x04" +
            runtime.socket.inet_pton(runtime.socket.AF_INET6, "2001:db8::123") +
            (80).to_bytes(2, "big") + b"GET /ordinary-http HTTP/1.1\r\nHost: fallback.invalid\r\n\r\n")
        client = Mock()
        def recv(count):
            value = bytes(stream[:count]); del stream[:count]; return value
        client.recv.side_effect = recv
        previous = SimpleNamespace(ipv6_payload=state, server_address=("192.0.2.10", runtime.PORTS["proxy"]))
        separate_port = runtime.PORTS.get("routing_proxy", runtime.PORTS["proxy"] + 1)
        separate = SimpleNamespace(server_address=("192.0.2.10", separate_port))
        selected = runtime.native_routing_config("192.0.2.10", 15353)["outbounds"][2]["settings"]["servers"][0]["port"]
        server = {previous.server_address[1]: previous, separate_port: separate}[selected]
        runtime.Socks(client, ("192.0.2.10", 50000), server)
        state.close(); state.require_clean()
        self.assertTrue(client.sendall.call_args.args[0].endswith(b"PROXY-FIXTURE"))
        self.assertEqual(separate_port, selected)

    def test_native_routing_dedicated_origin_is_joined_and_uses_its_bound_port(self):
        owner = SimpleNamespace(server_address=("192.0.2.10", 19422), daemon_threads=True)
        with patch.object(runtime, "Server", return_value=owner) as constructor, patch.dict(runtime.PORTS):
            self.assertIs(owner, runtime.native_routing_proxy("192.0.2.10"))
            constructor.assert_called_once_with(("192.0.2.10", 0), runtime.Socks)
            self.assertFalse(owner.daemon_threads)
            self.assertFalse(hasattr(owner, "ipv6_payload"))
            actual = runtime.native_routing_config("192.0.2.10", 15353)
            self.assertEqual(19422, actual["outbounds"][2]["settings"]["servers"][0]["port"])
            self.assertNotEqual(runtime.PORTS["proxy"], runtime.PORTS["routing_proxy"])

    def test_native_routing_profile_requires_source_alias_and_non_first_default(self):
        profile = runtime.native_routing_config("192.0.2.10", 15353)
        self.assertEqual("blackhole", profile["outbounds"][0]["protocol"])
        self.assertEqual("selected-default", profile["outbounds"][2]["tag"])
        self.assertEqual("caller-source", profile["inbounds"][0]["tag"])
        self.assertEqual(f"192.0.2.10:{runtime.PORTS['direct']}", profile["outbounds"][1]["settings"]["redirect"])
        self.assertEqual(["tcp://192.0.2.10:15353"], profile["dns"]["servers"])
        rules = profile["routing"]["rules"]
        self.assertEqual(["caller-dns"], rules[0]["inboundTag"])
        self.assertEqual(["caller-source"], rules[1]["inboundTag"])
        self.assertEqual(["full:alias.invalid"], rules[1]["domain"])
        self.assertFalse(any(rule.get("outboundTag") == "selected-default" for rule in rules))

    def test_native_routing_gate_proves_payload_rejection_recovery_and_drains(self):
        for defect in (None, "alias", "fallback", "exit", "cleanup"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); children = []; payloads = []
                origin = SimpleNamespace(direct_only_lock=runtime.threading.Lock(), direct_only_active="prior")
                def launch(command, **kwargs):
                    child = Mock(pid=400 + len(children)); child.poll.return_value = None
                    def wait(timeout):
                        child.poll.return_value = 0
                        return 9 if defect == "exit" and command[1] == "run-vpn-routing" else 0
                    child.wait.side_effect = wait; children.append(child)
                    if command[1] == "run-vpn-routing":
                        kwargs["stdout"].write("START_RETURN=1\nREJECTED_ROUTING_PRESERVED=1\n")
                        kwargs["stdout"].flush()
                    return child
                def request(host, vpn):
                    self.assertTrue(vpn); payloads.append(host)
                    if defect == "alias" and host == "alias.invalid": return "PROXY-FIXTURE"
                    if defect == "fallback" and host == "fallback.invalid": return "DIRECT-FIXTURE"
                    return "DIRECT-FIXTURE" if host == "alias.invalid" else "PROXY-FIXTURE"
                with patch.object(runtime.subprocess, "Popen", side_effect=launch), \
                     patch.object(runtime.subprocess, "check_output", return_value=json.dumps({"Routes": 1 if defect == "cleanup" else 0, "IPv6Addresses": 0})), \
                     patch.object(runtime, "native", return_value="0") as native, \
                     patch.object(runtime, "request", side_effect=request), \
                     patch.object(runtime, "direct_only_dns") as dns, \
                     patch.object(runtime, "kill_worker") as kill, \
                     patch.object(runtime, "await_state") as state, \
                     patch.object(runtime.time, "sleep"), patch("builtins.print") as printed:
                    rows = []
                    args = (directory / "runtime_probe.exe", directory, "192.0.2.10",
                            SimpleNamespace(server_address=("192.0.2.10", 15353)), origin, rows)
                    if defect is None:
                        runtime.native_routing_gate(*args)
                        self.assertEqual(8, len(rows)); self.assertTrue(all(row["passed"] for row in rows))
                        self.assertEqual(["alias.invalid", "fallback.invalid"] * 4, payloads)
                        self.assertEqual(5, dns.call_count)
                        kill.assert_called_once_with(400, "xray.exe")
                        self.assertEqual([False, True], [call.args[1] for call in state.call_args_list])
                        self.assertTrue((directory / "vpn-native-routing-0.state.json.reject-routing").exists())
                        printed.assert_called_once_with("WINDOWS_NATIVE_ROUTING_TRAFFIC_PASS=2", flush=True)
                    else:
                        with self.assertRaises(AssertionError): runtime.native_routing_gate(*args)
                        printed.assert_not_called()
                    self.assertIsNone(origin.direct_only_active)
                    self.assertEqual(4 if defect is None else 2, len(children))
                    for child in children: child.wait.assert_called(); child.kill.assert_not_called()
                    self.assertTrue(any(call.args[1] == "release-protection" for call in native.call_args_list))

    def test_native_routing_gate_failure_preserves_error_and_reaps_forced_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); children = []
            origin = SimpleNamespace(direct_only_lock=runtime.threading.Lock(), direct_only_active=None)
            failure = RuntimeError("synthetic payload failure")
            def launch(command, **kwargs):
                child = Mock(pid=500 + len(children)); child.poll.return_value = None
                child.wait.side_effect = [subprocess.TimeoutExpired(command, 1), 0]
                children.append(child)
                if command[1] == "run-vpn-routing":
                    kwargs["stdout"].write("START_RETURN=1\n"); kwargs["stdout"].flush()
                return child
            with patch.object(runtime.subprocess, "Popen", side_effect=launch), \
                 patch.object(runtime, "native", side_effect=OSError("synthetic cleanup failure")), \
                 patch.object(runtime, "request", side_effect=failure), patch("builtins.print") as printed:
                with self.assertRaises(RuntimeError) as raised:
                    runtime.native_routing_gate(directory / "runtime_probe.exe", directory, "192.0.2.10",
                        SimpleNamespace(server_address=("192.0.2.10", 15353)), origin, [])
            self.assertIs(failure, raised.exception)
            self.assertEqual(2, len(children))
            for child in children:
                child.kill.assert_called_once(); self.assertEqual(2, child.wait.call_count)
            printed.assert_not_called()

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
                def http(host, vpn, **diagnostic):
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

    def test_http_diagnostics_preserve_eof_reset_and_response_bytes(self):
        for outcome in ("complete", "eof", "reset"):
            with self.subTest(outcome=outcome):
                client = Mock(); client.__enter__ = Mock(return_value=client); client.__exit__ = Mock(return_value=False)
                client.getsockname.return_value = ("10.0.85.2", 50000)
                response = b"HTTP/1.0 200 OK\r\nContent-Length: 14\r\n\r\nDIRECT-FIXTURE"
                failure = ConnectionResetError("synthetic-private-message")
                client.recv.side_effect = [response, b""] if outcome == "complete" else [b""] if outcome == "eof" else failure
                detail = {}
                with patch.object(runtime.socket, "create_connection", return_value=client):
                    if outcome == "complete": self.assertEqual("DIRECT-FIXTURE", runtime.request("direct-only.invalid", True, diagnostic=detail))
                    elif outcome == "eof":
                        with self.assertRaisesRegex(RuntimeError, "without an HTTP response"):
                            runtime.request("direct-only.invalid", True, diagnostic=detail)
                    else:
                        with self.assertRaises(ConnectionResetError) as raised:
                            runtime.request("direct-only.invalid", True, diagnostic=detail)
                        self.assertIs(failure, raised.exception)
                self.assertEqual(len(response) if outcome == "complete" else 0, detail["response_bytes"])
                self.assertEqual(outcome == "complete", detail["header_present"])
                self.assertEqual("error" if outcome == "reset" else "eof", detail["read_end"])
                self.assertNotIn("synthetic-private-message", json.dumps(detail))
                client.settimeout.assert_called_once_with(4)

    def test_origin_diagnostics_keep_accept_case_across_late_handler_and_record_write_error(self):
        server = runtime.DirectOrigin.__new__(runtime.DirectOrigin)
        server.direct_only_lock = runtime.threading.Lock()
        server.direct_only_pending = {}; server.direct_only_observed = []
        def counters():
            return dict(accepts=0, get_allowed=0, get_blocked=0, get_other=0, headers_completed=0,
                        body_bytes=0, errors=0, last_error_class=None)
        server.direct_only_evidence = {"first": counters(), "second": counters()}
        server.direct_only_active = "first"; connection = object()
        with patch.object(runtime.ThreadingHTTPServer, "get_request", return_value=(connection, ("192.0.2.10", 50000))):
            self.assertEqual(connection, server.get_request()[0])
        server.direct_only_active = "second"
        handler = runtime.Direct.__new__(runtime.Direct)
        with patch.object(runtime.BaseHTTPRequestHandler, "__init__", return_value=None):
            handler.__init__(connection, ("192.0.2.10", 50000), server)
        handler.server = server; handler.headers = {"Host": "direct-only.invalid"}
        handler.send_response = Mock(); handler.send_header = Mock(); handler.end_headers = Mock(); handler.wfile = io.BytesIO()
        handler.do_GET()
        self.assertEqual(1, server.direct_only_evidence["first"]["accepts"])
        self.assertEqual(1, server.direct_only_evidence["first"]["get_allowed"])
        self.assertEqual(14, server.direct_only_evidence["first"]["body_bytes"])
        self.assertEqual(0, server.direct_only_evidence["second"]["get_allowed"])
        failure = BrokenPipeError("synthetic-private-write")
        handler.end_headers.side_effect = failure
        with self.assertRaises(BrokenPipeError) as raised: handler.do_GET()
        self.assertIs(failure, raised.exception)
        self.assertEqual(1, server.direct_only_evidence["first"]["errors"])
        self.assertEqual("BrokenPipeError", server.direct_only_evidence["first"]["last_error_class"])
        self.assertNotIn("synthetic-private-write", json.dumps(server.direct_only_evidence))

    def test_direct_only_failure_evidence_precedes_stop_and_keeps_original_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); origin = SimpleNamespace(); children = []; calls = []
            class FixtureFailure(RuntimeError):
                def add_note(self, note):
                    self.__notes__ = getattr(self, "__notes__", []) + [note]
            failure = FixtureFailure("synthetic-private-original")
            def launch(command, **kwargs):
                child = Mock(pid=300 + len(children)); child.poll.return_value = None
                def wait(timeout): child.poll.return_value = 0; return 0
                child.wait.side_effect = wait; children.append(child)
                if command[1] == "run-vpn":
                    kwargs["stdout"].write("START_RETURN=1\n"); kwargs["stdout"].flush()
                    Path(command[5]).write_text('{"running":true,"protecting":true,"ignored":"private-state"}')
                return child
            def request(host, vpn, diagnostic=None):
                calls.append(host)
                diagnostic.update(response_bytes=0, header_present=False, read_end="eof")
                if len(calls) == 3: raise failure
                if host == "blocked.invalid": raise EOFError("synthetic blocked")
                origin.direct_only_observed.append(host)
                return "DIRECT-FIXTURE"
            with patch.object(runtime.subprocess, "Popen", side_effect=launch), \
                 patch.object(runtime, "request", side_effect=request), patch.object(runtime, "native", return_value="0"), \
                 patch.object(runtime.time, "sleep"):
                with self.assertRaises(RuntimeError) as raised:
                    runtime.direct_only_gate(directory / "runtime_probe.exe", directory, "192.0.2.10",
                        SimpleNamespace(server_address=("192.0.2.10", 15353)), origin, [])
            self.assertIs(failure, raised.exception)
            self.assertEqual(["direct-only.invalid", "blocked.invalid", "direct-only.invalid"], calls)
            evidence = json.loads((directory / "vpn-direct-only-freedom-default.evidence.log").read_text())
            self.assertEqual("positive_after", evidence["stage"])
            self.assertTrue(evidence["before_stop"]); self.assertIsNone(evidence["process_exit"])
            self.assertEqual({"running": True, "protecting": True}, evidence["state"])
            self.assertEqual(3, len(evidence["requests"]))
            self.assertNotIn("private", json.dumps(evidence))
            self.assertTrue(any("DIRECT_ONLY_EVIDENCE" in note for note in failure.__notes__))
            for child in children: child.wait.assert_called(); child.kill.assert_not_called()
            with patch.object(Path, "write_text", side_effect=OSError("private-write-error")):
                runtime.save_direct_evidence(directory / "unused.log", {}, failure)
            self.assertNotIn("private-write-error", failure.__notes__[-1])

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
