#!/usr/bin/env python3
"""Bounded, read-only crash context for the disposable Android test APK."""

import argparse
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


def capture(command, path, *, timeout=CAPTURE_TIMEOUT_SECONDS,
            max_bytes=MAX_CONTEXT_BYTES):
    """Drain bounded output without retaining unlimited subprocess data in memory."""
    started = time.monotonic()
    result = {"command": command, "file": path.name, "timeout_seconds": timeout,
              "max_bytes": max_bytes, "returncode": None, "timed_out": False,
              "truncated": False, "bytes_written": 0}
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            result["error"] = type(error).__name__
        else:
            deadline = started + timeout
            kill_deadline = None
            close_deadline = None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                try:
                    while selector.get_map():
                        now = time.monotonic()
                        if not result["timed_out"] and now >= deadline:
                            result["timed_out"] = True
                            _signal_group(process.pid, signal.SIGTERM)
                            kill_deadline = now + 0.3
                        if kill_deadline is not None and now >= kill_deadline:
                            # The parent may have exited while a child kept the
                            # output pipe open. The group belongs only to this capture.
                            _signal_group(process.pid, signal.SIGKILL)
                            kill_deadline = None
                            close_deadline = now + 0.5
                        if close_deadline is not None and now >= close_deadline:
                            break
                        for key, _ in selector.select(0.05):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            remaining = max_bytes - result["bytes_written"]
                            output.write(chunk[:remaining])
                            result["bytes_written"] += min(len(chunk), remaining)
                            result["truncated"] |= len(chunk) > remaining
                finally:
                    process.stdout.close()
                    if result["timed_out"] and process.poll() is None:
                        _signal_group(process.pid, signal.SIGKILL)
                    try:
                        process.wait(timeout=1 if result["timed_out"] else
                                     max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        result["timed_out"] = True
                        _signal_group(process.pid, signal.SIGKILL)
                        process.wait(timeout=1)
                    result["returncode"] = process.returncode
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def collect(adb, serial, package, output, phase, *, timeout=CAPTURE_TIMEOUT_SECONDS,
            max_bytes=MAX_CONTEXT_BYTES):
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
                             timeout=timeout, max_bytes=max_bytes)
        except OSError as error:
            # A single output/launch failure must not prevent later evidence or cleanup.
            result = {"error": type(error).__name__, "returncode": None,
                      "timed_out": False, "timeout_seconds": timeout,
                      "max_bytes": max_bytes}
        report["captures"].append({"name": name, **result})
    report["complete"] = all(item.get("returncode") == 0 and not item["timed_out"]
                             and "error" not in item for item in report["captures"])
    metadata = output / "failure-context.json"
    with os.fdopen(os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", required=True)
    arguments = parser.parse_args()
    report = collect(arguments.adb, arguments.serial, arguments.package,
                     arguments.output, arguments.phase)
    # Raw context stays only in the private run directory, never console output.
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
