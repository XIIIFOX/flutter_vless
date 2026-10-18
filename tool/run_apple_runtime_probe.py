#!/usr/bin/env python3
"""Bound a single owned Apple probe; stdout/stderr remain available to tee."""
import argparse
import math
import signal
import subprocess
import sys

IOS_BUNDLE = 'dev.tfox.security-runtime-probe'
STOP_SECONDS = 5


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def stop_owned(process):
    # A live, unreaped Popen child identifies our process. Never search by name,
    # kill a process group, or signal a PID taken from an old artifact.
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=STOP_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=STOP_SECONDS)


def terminate_ios_probe(simulator, run=subprocess.run):
    # The caller installed and launched this fixed test bundle in its disposable
    # simulator. The simctl console process is not the application's own PID.
    try:
        result = run(['xcrun', 'simctl', 'terminate', simulator, IOS_BUNDLE],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     timeout=10, check=False)
        print(f'PROBE_CLEANUP=ios-bundle;status={result.returncode}', flush=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f'PROBE_CLEANUP=ios-bundle;error={type(error).__name__}', flush=True)


def run_probe(command, timeout, simulator=None, cleanup_ios=terminate_ios_probe):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Probe timeout must be positive and finite')
    if simulator is not None and command != ['xcrun', 'simctl', 'launch', '--console', simulator, IOS_BUNDLE]:
        raise ValueError('Simulator cleanup requires the exact owned probe launch command')
    process = subprocess.Popen(command)
    previous = {}
    needs_ios_cleanup = True
    def interrupt(signum, _frame):
        raise Interrupted(signum)
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, interrupt)
        print(f'PROBE_PROCESS_STARTED=owned-child;pid={process.pid}', flush=True)
        try:
            code = process.wait(timeout=timeout)
            needs_ios_cleanup = code != 0
            print(f'PROBE_PROCESS_EXIT=status-{code if code >= 0 else 128 - code}', flush=True)
            return code if code >= 0 else 128 - code
        except subprocess.TimeoutExpired:
            print('PROBE_TIMEOUT=runtime', flush=True)
            return 124
        except Interrupted as error:
            print(f'PROBE_INTERRUPTED=signal-{error.signum}', flush=True)
            return 128 + error.signum
    finally:
        # Bound cleanup even if the outer CI ceiling interrupts this helper.
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            try:
                if simulator is not None and needs_ios_cleanup:
                    cleanup_ios(simulator)
            finally:
                stop_owned(process)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f'PROBE_CLEANUP=owned-child;error={type(error).__name__}', flush=True)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--ios-simulator')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('A probe command is required')
    try:
        return run_probe(command, arguments.timeout, arguments.ios_simulator)
    except (OSError, ValueError) as error:
        print(f'PROBE_LAUNCH_FAILED={type(error).__name__}', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
