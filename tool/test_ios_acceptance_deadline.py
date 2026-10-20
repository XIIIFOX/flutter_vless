#!/usr/bin/env python3
"""Compile only extracted acceptance-deadline functions with fake NE/timers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def run(command, output, seconds=45):
    def exists(group):
        try: os.killpg(group, 0); return True
        except ProcessLookupError: return False
    with output.open('xb') as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=seconds)
        finally:
            for signum in (signal.SIGTERM, signal.SIGKILL):
                if not exists(child.pid): break
                try: os.killpg(child.pid, signum)
                except ProcessLookupError: break
                limit = time.monotonic() + 3
                while exists(child.pid) and time.monotonic() < limit: time.sleep(.025)
            child.wait(timeout=3)
    if exists(child.pid): raise RuntimeError('owned-fixture-group-remains')
    if code: raise RuntimeError('pure-fixture-command-failed: ' + output.name)


def generate(root):
    source = (root/'example/ios/XrayTunnel/PacketTunnelProvider.swift').read_text()
    marker = '    #if FLUTTER_VLESS_ACCEPTANCE_SESSION_DEADLINE\n'
    if source.count(marker) != 1: raise AssertionError('actual acceptance deadline hook missing')
    begin = source.index(marker); depth = 0; end = begin
    for line in source[begin:].splitlines(keepends=True):
        if line.strip().startswith('#if '): depth += 1
        elif line.strip() == '#endif': depth -= 1
        end += len(line)
        if depth == 0: break
    block = source[begin:end]
    assert source.rfind('    #if FLUTTER_VLESS_ACCEPTANCE_TESTING\n', 0, begin) >= 0
    assert source.count('try beginAcceptanceSessionDeadline(configuration: configuration, options: options)') == 1
    start = source[source.index('override func startTunnel'):source.index('override func stopTunnel')]
    assert start.index('try beginAcceptanceSessionDeadline(') < start.index('await ')
    assert source.count('let stoppedEpoch = revokeAcceptanceSessionDeadline()') == 1
    assert 'saveToPreferences' not in block and 'startVPNTunnel' not in block
    assert block.count('.now() + 110') == 1 and block.count('.now() + 5') == 1
    block = block.replace('DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 110, execute: work)',
                          'DeadlineClock.schedule(110, work)')
    block = block.replace('DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5, execute: fallback)',
                          'DeadlineClock.schedule(5, fallback)')
    assert 'asyncAfter' not in block
    block = block.replace('    private ', '    ')  # Test access only; actual bodies remain unchanged.
    fixture = (root/'tool/fixtures/ios_acceptance_deadline.swift').read_text()
    assert fixture.count('// ACTUAL_DEADLINE_SOURCE') == 1
    admission = (root/'ios/flutter_vless/Sources/flutter_vless_tunnel_support/TunnelSessionAdmission.swift').read_text()
    return admission + '\n' + fixture.replace('// ACTUAL_DEADLINE_SOURCE', block)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    contents = generate(args.root)
    args.output.mkdir(parents=True, exist_ok=False)
    probe = args.output/'Probe.swift'; probe.write_text(contents)
    outcomes = {}
    for mode, flags in [('normal', []), ('acceptance', ['-D', 'FLUTTER_VLESS_ACCEPTANCE_TESTING']),
                        ('deadline', ['-D', 'FLUTTER_VLESS_ACCEPTANCE_TESTING', '-D', 'FLUTTER_VLESS_ACCEPTANCE_SESSION_DEADLINE'])]:
        binary = args.output/mode
        run(['xcrun', 'swiftc', '-parse-as-library', *flags, str(probe), '-o', str(binary)], args.output/(mode+'-compile.log'))
        run([str(binary)], args.output/(mode+'.log'), 10)
        marker = b'FLVLESS_ACCEPTANCE_SESSION_DEADLINE_110S_V1'
        assert (marker in binary.read_bytes()) == (mode == 'deadline')
        outcomes[mode] = (args.output/(mode+'.log')).read_text().strip()
    result = {'fake_NetworkExtension_preferences_and_timers_only': True, 'outcomes': outcomes,
              'probe_sha256': hashlib.sha256(probe.read_bytes()).hexdigest(), 'owned_process_groups_remaining': []}
    (args.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
