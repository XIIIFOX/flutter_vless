#!/usr/bin/env python3
"""Run the three mandatory Android CI gates and retain every ordinary failure."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CANCEL_GRACE_SECONDS = 30


class _WaitFailed(Exception):
    def __init__(self, returncode):
        self.returncode = returncode


def _save(path, report):
    data = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    if len(data) > 4096:
        raise ValueError("gate-report-size")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".android-ci-gates-", delete=False) as output:
            temporary = Path(output.name)
            output.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class _Cancellation:
    def __init__(self):
        self.signum = None
        self.process = None

    def forward(self, number):
        if self.process is not None:
            try:
                os.killpg(self.process.pid, number)
            except ProcessLookupError:
                pass

    def receive(self, number, _frame=None):
        if self.signum is None:
            self.signum = number


@contextmanager
def _handlers(state):
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, state.receive)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _execute(command, environment, state):
    if state.signum is not None:
        return None
    process = subprocess.Popen(command, cwd=ROOT, env=environment, start_new_session=True)
    state.process = process
    try:
        forwarded = False
        while True:
            cancelling = state.signum is not None
            if cancelling and not forwarded:
                # All three existing harnesses unwind on INT; the UID Python
                # harness has no TERM handler. Keep the parent's signal for
                # our exit status while allowing its finally cleanup to run.
                state.forward(signal.SIGINT)
                forwarded = True
            try:
                return process.wait(timeout=CANCEL_GRACE_SECONDS if cancelling else 0.25)
            except subprocess.TimeoutExpired:
                if cancelling:
                    state.forward(signal.SIGKILL)
                    return process.wait()
            except KeyboardInterrupt:
                state.receive(signal.SIGINT)
    except OSError:
        # The command already belongs to us; a wait error cannot turn it into
        # an untracked background gate before the next mandatory gate starts.
        state.forward(signal.SIGKILL)
        raise _WaitFailed(process.wait()) from None
    finally:
        state.process = None


def run_gates(serial, routing_preview, output, *, environment=None):
    environment = dict(os.environ if environment is None else environment)
    if environment.get("CI") != "true" or environment.get("GITHUB_ACTIONS") != "true":
        raise ValueError("github-ci-required")
    if re.fullmatch(r"emulator-[0-9]{1,5}", serial) is None:
        raise ValueError("dedicated-emulator-required")
    environment["ANDROID_SERIAL"] = serial
    commands = [
        ("native", [str(ROOT / "tool/test_android_security_emulator.sh"), "--no-capture", "--native-routing-preview", str(routing_preview)]),
        ("flutter", [sys.executable, str(ROOT / "tool/test_android_flutter_smoke.py"), "--serial", serial]),
        ("separate_uid", [sys.executable, str(ROOT / "tool/test_android_separate_uid.py"), "--serial", serial,
                          "--output", str(ROOT / "build/android-separate-uid-results.json")]),
    ]
    report = {"schema": 1, "serial": serial, "success": False, "exit_code": 1,
              "gates": [{"name": name, "status": "not_run", "exit_code": None} for name, _ in commands]}
    output = Path(output)
    _save(output, report)
    state = _Cancellation()
    with _handlers(state):
        for gate, (_, command) in zip(report["gates"], commands):
            if state.signum is not None:
                break
            gate["status"] = "running"
            _save(output, report)
            try:
                code = _execute(command, environment, state)
                gate["exit_code"] = code
                if state.signum is None and code in (-signal.SIGINT, -signal.SIGTERM, 130, 143):
                    state.signum = -code if code < 0 else code - 128
                gate["status"] = "interrupted" if state.signum else ("passed" if code == 0 else "failed")
            except _WaitFailed as error:
                gate.update(status="wait_failed", exit_code=error.returncode)
            except OSError:
                gate.update(status="launch_failed", exit_code=None)
            _save(output, report)
            if state.signum is not None:
                break
        report["success"] = all(gate["status"] == "passed" for gate in report["gates"])
        report["exit_code"] = 128 + state.signum if state.signum else (0 if report["success"] else 1)
        _save(output, report)
    return report["exit_code"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--native-routing-preview", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "build/android-ci-gates/result.json")
    args = parser.parse_args(argv)
    try:
        return run_gates(args.serial, args.native_routing_preview, args.output)
    except (OSError, ValueError):
        print("ANDROID_CI_GATES_ERROR=setup-or-report", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
