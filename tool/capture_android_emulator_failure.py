#!/usr/bin/env python3
"""Bounded, read-only crash context for the disposable Android test APK."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time


TEST_PACKAGE = "com.github.tfox.flutter_vless.test"
CAPTURE_TIMEOUT_SECONDS = 10
MAX_CONTEXT_BYTES = 512 * 1024


def _signal_group(pid, sig):
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass


def _close_owned_group(process):
    """Always clean the private PGID, including after its leader has exited."""
    cleanup = {"leader_reaped": False, "pipe_closed": False, "error": None}
    def attempt(action):
        try:
            action()
        except (Exception, KeyboardInterrupt) as error:
            if cleanup["error"] is None:
                cleanup["error"] = type(error).__name__
    try:
        attempt(lambda: _signal_group(process.pid, signal.SIGTERM))
        attempt(lambda: time.sleep(0.2))
    finally:
        # Never skip escalation because setup, output, TERM or a signal failed.
        deadline = time.monotonic() + 1
        while True:
            try:
                _signal_group(process.pid, signal.SIGKILL)
                break
            except KeyboardInterrupt:
                if time.monotonic() >= deadline:
                    cleanup["error"] = cleanup["error"] or "KeyboardInterrupt"
                    break
            except OSError as error:
                cleanup["error"] = cleanup["error"] or type(error).__name__
                break
        attempt(process.stdout.close)
        cleanup["pipe_closed"] = process.stdout.closed
        while not cleanup["leader_reaped"] and time.monotonic() < deadline:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                cleanup["leader_reaped"] = True
            except KeyboardInterrupt:
                continue  # Preserve the same deadline through repeated interrupts.
            except (subprocess.TimeoutExpired, OSError) as error:
                if cleanup["error"] is None:
                    cleanup["error"] = type(error).__name__
                break
    return cleanup


def capture(command, path, *, timeout=CAPTURE_TIMEOUT_SECONDS,
            max_bytes=MAX_CONTEXT_BYTES, cancelled=None):
    """Drain bounded output without retaining unlimited subprocess data in memory."""
    started = time.monotonic()
    result = {"command": command, "file": path.name, "timeout_seconds": timeout,
              "max_bytes": max_bytes, "returncode": None, "timed_out": False,
              "truncated": False, "bytes_written": 0, "cancelled": False,
              "cleanup": None}
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb", buffering=0) as output:
        process = None
        selector = None
        try:
            result["cancelled"] = bool(cancelled and cancelled())
            if result["cancelled"]:
                return dict(result, elapsed_seconds=round(time.monotonic() - started, 3))
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            deadline = started + timeout
            # Setup belongs inside the post-spawn finally too. A failed
            # selector/register must not abandon an independent process group.
            os.set_blocking(process.stdout.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            eof = False
            while True:
                result["cancelled"] = bool(cancelled and cancelled())
                if result["cancelled"]:
                    break
                if time.monotonic() >= deadline:
                    result["timed_out"] = True
                    break
                if eof and process.poll() is not None:
                    break
                if not selector.get_map():
                    time.sleep(0.05)
                    continue
                for key, _ in selector.select(0.05):
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        eof = True
                        continue
                    remaining = max_bytes - result["bytes_written"]
                    if remaining:
                        written = output.write(chunk[:remaining])
                        result["bytes_written"] += written or 0
                        if written != min(len(chunk), remaining):
                            raise OSError("incomplete-context-write")
                    result["truncated"] |= len(chunk) > remaining
        except Exception as error:
            result["error"] = type(error).__name__
        finally:
            # Even selector.close failures cannot bypass exact-child cleanup.
            try:
                if selector is not None:
                    selector.close()
            except (Exception, KeyboardInterrupt) as error:
                result.setdefault("error", type(error).__name__)
            finally:
                if process is not None:
                    result["cleanup"] = _close_owned_group(process)
                    result["returncode"] = process.returncode
                    if not (result["cleanup"]["leader_reaped"] and result["cleanup"]["pipe_closed"]
                            and result["cleanup"]["error"] is None):
                        result.setdefault("error", "cleanup-failed")
        try:
            result["cancelled"] |= bool(cancelled and cancelled())
        except Exception as error:
            result.setdefault("error", type(error).__name__)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def collect(adb, serial, package, output, phase, *, timeout=CAPTURE_TIMEOUT_SECONDS,
            max_bytes=MAX_CONTEXT_BYTES, cancelled=None):
    if not re.fullmatch(r"emulator-[0-9]+", serial) or package != TEST_PACKAGE:
        raise ValueError("Failure context is restricted to the dedicated emulator test APK")
    commands = (
        ("crash", ["logcat", "-b", "crash", "-d", "-t", "400"]),
        ("logcat", ["logcat", "-b", "main", "-b", "system", "-d", "-t", "1000"]),
        ("exit-info", ["shell", "dumpsys", "activity", "exit-info", package]),
    )
    report = {"version": 1, "phase": phase, "serial": serial, "package": package,
              "captures": []}
    for name, arguments in commands:
        try:
            result = capture([str(adb), "-s", serial, *arguments],
                             output / f"failure-context-{name}.log",
                             timeout=timeout, max_bytes=max_bytes, cancelled=cancelled)
        except OSError as error:
            # A single output/launch failure must not prevent later evidence or cleanup.
            result = {"error": type(error).__name__, "returncode": None,
                      "timed_out": False, "timeout_seconds": timeout,
                      "max_bytes": max_bytes}
        report["captures"].append({"name": name, **result})
    report["cancelled"] = bool(cancelled and cancelled()) or any(item.get("cancelled") for item in report["captures"])
    report["complete"] = not report["cancelled"] and all(item.get("returncode") == 0 and not item["timed_out"]
                             and "error" not in item for item in report["captures"])
    metadata = output / "failure-context.json"
    with os.fdopen(os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    return report


@contextmanager
def cancellation_handlers(state):
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    def receive(number, _frame):
        if not state:
            state.append(number)
    try:
        for number in previous:
            signal.signal(number, receive)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", required=True)
    arguments = parser.parse_args()
    state = []
    with cancellation_handlers(state):
        report = collect(arguments.adb, arguments.serial, arguments.package,
                         arguments.output, arguments.phase, cancelled=lambda: bool(state))
        # Raw context stays only in the private run directory, never console output.
        return 128 + state[0] if state else 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
