#!/usr/bin/env python3
"""Preserve startup evidence; retry only a pre-entry Flutter DDS failure."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DDS_FAILURE = 'Failed to start Dart Development Service'
TEST_ENTRY = 'ANDROID_XRAY_SMOKE_TEST_ENTRY'
MAX_CONTEXT_BYTES = 64 * 1024
EXAMPLE_PACKAGE = 'com.example.flutter_vless_example'


def write_private(path, text):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags, 0o600), 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(text.encode('utf-8') if isinstance(text, str) else text)


def collect_failure_context(serial, output, attempt, run=subprocess.run):
    """Read the dedicated emulator only; never clear logs or restart the app."""
    commands = {
        'crash': ['logcat', '-d', '-b', 'crash', '-t', '200', '-v', 'threadtime'],
        'logcat': ['logcat', '-d', '-b', 'main', '-b', 'system', '-t', '400', '-v', 'threadtime'],
        'exit-info': ['shell', 'dumpsys', 'activity', 'exit-info', EXAMPLE_PACKAGE],
    }
    metadata = {}
    for name, arguments in commands.items():
        try:
            result = run(['adb', '-s', serial, *arguments], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, timeout=10)
            raw = result.stdout or b''
            metadata[name] = {'returncode': result.returncode}
        except subprocess.TimeoutExpired as error:
            raw = error.stdout or b''
            metadata[name] = {'error': 'timeout'}
        except OSError as error:
            # A missing/disconnected ADB must not replace the original failure.
            raw = b''
            metadata[name] = {'error': type(error).__name__}
        if isinstance(raw, str):
            raw = raw.encode('utf-8', errors='replace')
        metadata[name]['truncated'] = len(raw) > MAX_CONTEXT_BYTES
        write_private(output / f'flutter-smoke-{attempt}-{name}.log',
                      raw[-MAX_CONTEXT_BYTES:])
    write_private(output / f'flutter-smoke-{attempt}-context.json',
                  json.dumps(metadata, indent=2) + '\n')


def run_smoke(serial, output, run=subprocess.run, pause=time.sleep,
              collect=collect_failure_context):
    if not serial.startswith('emulator-'):
        raise ValueError('Smoke acceptance requires an explicitly selected emulator.')
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    command = ['flutter', 'test', 'integration_test/android_xray_runtime_smoke_test.dart', '-d', serial]
    for attempt in range(1, 3):
        result = run(command, cwd=ROOT / 'example', stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True)
        text = result.stdout or ''
        write_private(output / f'flutter-smoke-{attempt}.log', text)
        print(text, end='', flush=True)
        if result.returncode == 0:
            return 0
        try:
            collect(serial, output, attempt)
        except (OSError, subprocess.SubprocessError) as error:
            print(f'Could not preserve emulator context ({type(error).__name__}).', flush=True)
        # Entry precedes binding/plugin initialization. The version marker alone
        # was too late to establish that native initialization had not run.
        # VM disappearance remains a failure until its captured cause is known;
        # an app/engine crash can produce the same Flutter tool exception.
        before_tests = TEST_ENTRY not in text and 'ANDROID_XRAY_CORE_VERSION=' not in text
        if attempt == 2 or DDS_FAILURE not in text or not before_tests:
            return result.returncode
        print('Flutter DDS failed before tests; retrying startup once.', flush=True)
        pause(2)
    return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/android-flutter-smoke')
    args = parser.parse_args()
    sys.exit(run_smoke(args.serial, args.output))
