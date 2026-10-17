#!/usr/bin/env python3
"""Retry only a Flutter DDS startup failure before the native smoke tests run."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DDS_FAILURE = 'Failed to start Dart Development Service'


def run_smoke(serial, output, run=subprocess.run, pause=time.sleep):
    output.mkdir(parents=True, exist_ok=True)
    command = ['flutter', 'test', 'integration_test/android_xray_runtime_smoke_test.dart', '-d', serial]
    for attempt in range(1, 3):
        result = run(command, cwd=ROOT / 'example', stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True)
        text = result.stdout or ''
        (output / f'flutter-smoke-{attempt}.log').write_text(text)
        print(text, end='', flush=True)
        if result.returncode == 0:
            return 0
        # The version marker is emitted by the first test. Never retry a test
        # assertion/runtime failure after that point, or any other tool error.
        before_tests = 'ANDROID_XRAY_CORE_VERSION=' not in text
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
