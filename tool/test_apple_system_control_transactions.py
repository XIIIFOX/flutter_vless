#!/usr/bin/env python3
"""Whole Apple system-control methods with memory-only settings/auth/VPN fakes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = (
    "ios/flutter_vless/Sources/flutter_vless_privacy",
    "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy",
)
FIXTURES = ("tool/fixtures/apple_system_control_transaction_sdk.swift",
            "tool/fixtures/apple_system_control_transactions.swift")
EXPECTED = "DESIRED_FAILURES=0;CONTROLS_PASS=12;CASES=36;REAL_AUTH_SETTINGS_OR_VPN_ACTIONS=0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(source):
    # Keep the complete production enum/serialiser. Only the OS boundaries and
    # access levels for internal fake types change; no copied policy decisions.
    assert source.count("import NetworkExtension\n") == source.count("import WidgetKit\n") == 1
    assert "public enum VlessSystemControl" in source and "private actor OperationSerialiser" in source
    result = source.replace("import NetworkExtension\n", "").replace("import WidgetKit\n", "")
    result = result.replace("public ", "").replace("UserDefaults(", "InertDefaults(")
    assert "NetworkExtension" not in result and "WidgetKit" not in result
    assert "UserDefaults(" not in result
    return result


def process_inventory():
    text = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,pgid=,uid=,command='], text=True, timeout=5)
    rows = []
    for line in text.splitlines():
        fields = line.strip().split(None, 4)
        if len(fields) != 5 or not all(value.isdigit() for value in fields[:4]):
            raise ValueError('process-inventory-unknown')
        rows.append(dict(zip(('pid', 'ppid', 'pgid', 'uid'), map(int, fields[:4])), command=fields[4]))
    return rows


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


class OwnedGroup:
    def __init__(self, child, *, exclusive_output, expected_uid=None, parent_pgid=None):
        # Callers use start_new_session=True; all compiler descendants inherit it.
        self.child, self.pgid = child, child.pid
        self.expected_uid = os.getuid() if expected_uid is None else expected_uid
        self.parent_pgid = os.getpgrp() if parent_pgid is None else parent_pgid
        self.output = str(Path(exclusive_output))
        self.report = {'owned_pgid': self.pgid, 'expected_sid': self.pgid,
                       'group_empty': False, 'child_reaped': False, 'signals': []}

    def drain(self, *, inventory=process_inventory, get_sid=os.getsid, exists=group_exists,
              send=os.killpg, now=time.monotonic, sleep=time.sleep):
        try:
            if self.pgid <= 1 or self.pgid == self.parent_pgid:
                raise ValueError('refuse-parent-or-invalid-group')

            def observe():
                self.child.poll()  # reap our direct leader even after normal exit
                members = []
                for row in inventory():
                    if row['pgid'] != self.pgid:
                        continue
                    if row['uid'] != self.expected_uid:
                        raise ValueError('owned-group-UID-proof-failed')
                    try:
                        sid = get_sid(row['pid'])
                    except ProcessLookupError:
                        continue
                    if sid != self.pgid:
                        raise ValueError('owned-session-proof-failed')
                    members.append(row['pid'])
                present = exists(self.pgid)
                if present and not members:
                    raise ValueError('group-present-with-unobserved-members')
                self.report['last_member_pids'] = members
                return members, present

            members, present = observe()
            if members or present:
                for sig, duration in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
                    members, present = observe()  # qualify identity before signals
                    if not members and not present:
                        break
                    try:
                        send(self.pgid, sig)
                    except ProcessLookupError:
                        continue  # all members may exit between observation/signal
                    self.report['signals'].append(int(sig))
                    end = now()+duration
                    while True:
                        members, present = observe()
                        if not members and not present:
                            break
                        remaining = end-now()
                        if remaining <= 0:
                            break
                        sleep(min(.05, remaining))
                members, present = observe()
                if members or present:
                    raise ValueError('owned-group-not-empty-after-bounded-drain')
            self.child.wait(timeout=2)
            self.report['child_reaped'] = True
            rows = inventory()
            if any(row['pgid'] == self.pgid for row in rows) or exists(self.pgid):
                raise ValueError('owned-group-reappeared-or-unqualified')
            # Observe escaped compilers, but never signal outside the owned group.
            compiler_names = ('xcodebuild', 'swift-frontend', 'swiftc', 'clang', 'clang++', 'ld')
            escaped = [row['pid'] for row in rows if self.output in row['command'] and
                       Path(row['command'].split(None, 1)[0]).name in compiler_names]
            self.report['outside_group_compiler_pids'] = escaped
            if escaped:
                raise ValueError('exclusive-output-compiler-outside-owned-group')
            self.report['group_empty'] = True
        except BaseException as error:
            self.report['fixed_error_type'] = type(error).__name__
            self.report['fixed_error'] = str(error) if isinstance(error, ValueError) else 'inventory-or-cleanup-failed'
            try:
                self.child.wait(timeout=2)
                self.report['child_reaped'] = True
            except BaseException:
                self.report['child_reaped'] = False
        return self.report


def run_bounded(command, directory, name, timeout):
    # Handlers record cancellation without raising between spawn and owner
    # publication. Compiler children exec with normal signal semantics.
    cancelled = []
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    def interrupt(number, _frame):
        cancelled.append(number)
    process = None
    cleanup = None
    try:
        for number in previous:
            signal.signal(number, interrupt)
        log = directory / (name + ".log")
        with log.open("xb") as output:
            log.chmod(0o600)
            process = subprocess.Popen(command, cwd=directory, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            owner = OwnedGroup(process, exclusive_output=directory)
            try:
                deadline = time.monotonic() + timeout
                while True:
                    if cancelled:
                        raise InterruptedError("inert-test-cancelled")
                    if log.stat().st_size > 2 * 1024 * 1024:
                        raise ValueError("inert-test-log-limit")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("inert-test-deadline")
                    try:
                        code = process.wait(timeout=min(.25, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                cleanup = owner.drain()
                write(directory / (name + "-cleanup.json"), cleanup)
                assert cleanup["group_empty"] and cleanup["child_reaped"], "Owned inert compiler/test cleanup not qualified"
        return code
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def write(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2); output.write("\n")
    path.chmod(0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--generate-only", action="store_true")
    args = parser.parse_args(argv)
    repository = args.repository.resolve(strict=True)
    sources = [repository/base/name for base in SOURCE_DIRS
               for name in ("VlessNativeOptions.swift", "VlessSystemControl.swift")]
    sources += [repository/name for name in FIXTURES]
    for path in sources:
        assert path.is_file() and not path.is_symlink(), "Expected regular fixture/source"
    before = {str(path.relative_to(repository)): digest(path) for path in sources}
    for name in ("VlessNativeOptions.swift", "VlessSystemControl.swift"):
        assert (repository/SOURCE_DIRS[0]/name).read_bytes() == (repository/SOURCE_DIRS[1]/name).read_bytes(), "Apple source mirrors differ: " + name
    build = repository/"build"
    build.mkdir(exist_ok=True)
    assert not build.is_symlink(), "Refuse linked output parent"
    if args.output_dir is None:
        output = Path(tempfile.mkdtemp(prefix="apple-system-control-transactions-", dir=build))
    else:
        output = args.output_dir.resolve()
        assert output.is_relative_to(build.resolve()) and not output.exists(), "Fresh build output required"
        output.mkdir(mode=0o700, parents=True)
    output.chmod(0o700)
    generated = output/"Control.swift"
    generated.write_text(extract((repository/SOURCE_DIRS[0]/"VlessSystemControl.swift").read_text()))
    generated.chmod(0o600)
    record = {"schema": 1, "state": "GENERATED_NOT_EXECUTED", "source_sha256": before,
              "both_mirrors_checked": True, "shared_whole_method_fixture_runs": 0,
              "generated_sha256": digest(generated), "fake_only": True,
              "Core_SDK_network_preferences_auth_or_device_actions": False}
    try:
        if not args.generate_only:
            command = ["xcrun", "swiftc", "-O", "-parse-as-library", "-module-cache-path", str(output/"module-cache"),
                       str(repository/SOURCE_DIRS[0]/"VlessNativeOptions.swift"),
                       str(repository/FIXTURES[0]), str(generated), str(repository/FIXTURES[1]), "-o", str(output/"probe")]
            code = run_bounded(command, output, "compile", 100)
            record["compile_exit"] = code
            assert code == 0, "Inert system-control fixture did not compile; see " + str(output/"compile.log")
            code = run_bounded([str(output/"probe")], output, "runtime", 25)
            record["runtime_exit"] = code
            text = (output/"runtime.log").read_text()
            print(text, end="", flush=True)
            assert code == 0 and text.splitlines().count(EXPECTED) == 1, "System-control transaction regression; see runtime.log"
            record.update(state="PASSED", shared_whole_method_fixture_runs=1, cases_passed=36, controls_passed=12)
    except BaseException as error:
        record.update(state="FAILED", failure_type=type(error).__name__)
        raise
    finally:
        record["source_unchanged"] = all(digest(repository/name) == checksum for name, checksum in before.items())
        record["outputs_sha256"] = {path.name: digest(path) for path in output.iterdir()
                                    if path.is_file() and path.suffix in (".log", ".json")}
        write(output/"result.json", record)
        assert record["source_unchanged"], "Fixture/source changed during test"
    print("APPLE_SYSTEM_CONTROL_TRANSACTION_OUTPUT=" + str(output), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
