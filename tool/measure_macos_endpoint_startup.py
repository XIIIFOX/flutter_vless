#!/usr/bin/env python3
"""Compare real-clock production DNS startup on a controlled driver in Actions.

This measures DNS preparation, not a signed NetworkExtension or Internet access.
Both revisions execute the same XCTest and retain separate logs and source hashes.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '9d18a5fa8c894f35ab02a4819751b7640842182e'
PACKAGE = 'packages/flutter_vless_macos/macos/flutter_vless_macos'
TEST = PACKAGE + '/Tests/flutter_vless_macos_tunnel_supportTests/TunnelEndpointStartupTimingTests.swift'
PREFIX = 'FLVLESS_ENDPOINT_STARTUP_TIMING '
CASES = {'terminal_unavailable_fallback': 3, 'no_record_late_aaaa': 1,
         'silence_fallback': 1, 'private_name_no_fallback': 1,
         'ipv6_only_no_ipv4_fallback': 1, 'stop_cancel': 1, 'path_cancel': 1}
MANIFEST = '''// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "EndpointTiming", platforms: [.macOS("13.0")], targets: [
    .target(name: "flutter_vless_macos_privacy"),
    .target(name: "flutter_vless_macos_tunnel_support", dependencies: ["flutter_vless_macos_privacy"]),
    .testTarget(name: "flutter_vless_macos_tunnel_supportTests", dependencies: ["flutter_vless_macos_tunnel_support"])
])
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_run(argv, log, timeout, env=None):
    """Kill only this command's process group when its wall-clock bound expires."""
    with log.open('xb') as stream:
        process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    else:
        raise ValueError('Command left a background process in its owned group')
    if code:
        raise ValueError(f'Command failed ({code}); inspect {log.name}')


def parse_metrics(text, mode):
    rows = [json.loads(line.split(PREFIX, 1)[1]) for line in text.splitlines() if PREFIX in line]
    expected = {(case, sample) for case, count in CASES.items() for sample in range(count)}
    actual = set()
    for row in rows:
        key = (row.get('case'), row.get('sample'))
        if type(row.get('sample')) is not int or key not in expected or key in actual:
            raise ValueError('Missing, duplicate or unknown timing sample')
        actual.add(key)
        elapsed = row.get('elapsed_ms')
        if row.get('schema') != 1 or row.get('mode') != mode or row.get('dns_only') is not True \
                or row.get('live_ne_vpn') is not False or type(elapsed) not in (int, float) \
                or not math.isfinite(elapsed) or not 0 <= elapsed < 3500:
            raise ValueError('Invalid timing scope, clock value or deadline')
        if any(type(row.get(k)) is not int for k in ('registered_refs', 'closed_refs', 'fallback_calls')) \
                or row.get('registered_refs') != 2 or row.get('closed_refs') != 2:
            raise ValueError('DNS references were not drained')
        fallback = 1 if key[0] in ('terminal_unavailable_fallback', 'silence_fallback') else 0
        if row.get('fallback_calls') != fallback:
            raise ValueError('DNS fallback privacy/family/cancellation fence changed')
        families = {'terminal_unavailable_fallback': ['ipv4'], 'silence_fallback': ['ipv4'],
                    'no_record_late_aaaa': ['ipv6']}.get(key[0], [])
        if row.get('candidate_families') != families:
            raise ValueError('DNS address-family selection changed')
    if actual != expected:
        raise ValueError('Incomplete timing evidence')
    return rows


def compare(baseline, candidate):
    def times(rows, case):
        return [r['elapsed_ms'] for r in rows if r['case'] == case]
    before = times(baseline, 'terminal_unavailable_fallback')
    after = times(candidate, 'terminal_unavailable_fallback')
    gain = statistics.median(before) - statistics.median(after)
    if statistics.median(before) < 1800 or max(after) >= 900 or gain < 1000:
        raise ValueError('Terminal DNS timing did not improve within the 900ms budget')
    for rows in (baseline, candidate):
        if times(rows, 'no_record_late_aaaa')[0] < 1700 or times(rows, 'silence_fallback')[0] < 1800:
            raise ValueError('Late AAAA or silent DNS collection was shortened')
        for case in ('stop_cancel', 'path_cancel'):
            if times(rows, case)[0] >= 500:
                raise ValueError('Cancellation exceeded 500ms')
    return {'terminal_before_median_ms': statistics.median(before),
            'terminal_after_median_ms': statistics.median(after),
            'terminal_after_max_ms': max(after), 'terminal_gain_ms': gain,
            'candidate_budget_ms': 900, 'cancellation_budget_ms': 500,
            'late_AAAA_and_silence_full_window_retained': True}


def provider_metrics(text, ready):
    prefix = 'APPLE_PROVIDER_STARTUP_METRIC '
    rows = [json.loads(line.split(prefix, 1)[1]) for line in text.splitlines() if prefix in line]
    expected = {'first-ready-' + p for p in ('encrypted', 'literal', 'sealed-system')}
    if len(rows) != 3 or {r.get('scenario') for r in rows} != expected:
        raise ValueError('Incomplete provider startup timing evidence')
    for row in rows:
        if row.get('realNetworkExtension') is not False or row.get('controlledBoundaries') != 'NE-Core-HEV-DNS':
            raise ValueError('Provider timing scope mislabelled')
        if ready:
            total, final = row.get('startToReadyMs'), row.get('finalForceToReadyMs')
            if row.get('outcome') != 'ready' or row.get('passed') is not True \
                    or any(type(t) not in (int, float) or not math.isfinite(t) for t in (total, final)) \
                    or not 0 <= final < 900 or total < final:
                raise ValueError('Provider did not reach current-generation readiness within budget')
        elif row.get('outcome') != 'noReady' or row.get('passed') is not False \
                or row.get('startToReadyMs') is not None or row.get('finalForceToReadyMs') is not None:
            raise ValueError('Previous provider must reproduce noReady without fabricated timing')
    return rows


def prepare(output, revision):
    directory = output / revision
    directory.mkdir(parents=True)
    hashes = {}
    for module in ('flutter_vless_macos_privacy', 'flutter_vless_macos_tunnel_support'):
        prefix = PACKAGE + '/Sources/' + module
        if revision == 'baseline':
            paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', BASELINE, '--', prefix], cwd=ROOT, text=True).splitlines()
        else:
            paths = [str(p.relative_to(ROOT)) for p in sorted((ROOT / prefix).glob('*.swift'))]
        for name in paths:
            if not name.endswith('.swift') or Path(name).name == 'FlutterVlessPacketTunnelProvider.swift':
                continue
            data = subprocess.check_output(['git', 'show', BASELINE + ':' + name], cwd=ROOT) \
                if revision == 'baseline' else (ROOT / name).read_bytes()
            target = directory / 'Sources' / module / Path(name).name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            hashes[name] = digest(data)
    test = directory / 'Tests/flutter_vless_macos_tunnel_supportTests' / Path(TEST).name
    test.parent.mkdir(parents=True)
    test.write_bytes((ROOT / TEST).read_bytes())
    (directory / 'Package.swift').write_text(MANIFEST)
    return directory, hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'build/macos-endpoint-startup-timing')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, mode=0o700)
    packages = {mode: prepare(output, mode) for mode in ('baseline', 'candidate')}
    result = {'schema': 1, 'success': False, 'dns_only': True, 'live_ne_vpn': False,
              'baseline_ref': BASELINE, 'candidate_ref': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'test_sha256': digest((ROOT / TEST).read_bytes()),
              'production_sha256': {mode: item[1] for mode, item in packages.items()}, 'metrics': {}}
    if args.prepare_only:
        result['prepared_only'] = True
    else:
        try:
            result['provider_policy_metrics'] = {}
            result['provider_policy_source_sha256'] = {}
            for platform, name in [('ios', 'example/ios/XrayTunnel/PacketTunnelProvider.swift'),
                                   ('macos', PACKAGE + '/Sources/flutter_vless_macos_tunnel_support/FlutterVlessPacketTunnelProvider.swift')]:
                result['provider_policy_source_sha256'][name] = digest((ROOT / name).read_bytes())
                for mode, directory in [('candidate', 'apple-cold-start-current'), ('baseline', 'apple-cold-start-negative')]:
                    result['provider_policy_metrics'][platform + '-' + mode] = provider_metrics(
                        (ROOT / 'build' / directory / (platform + '.log')).read_text(), ready=mode == 'candidate')
            for mode, (package, _) in packages.items():
                bounded_run(['swift', 'build', '--build-tests', '--package-path', str(package)], output / (mode + '-build.log'), 300)
                environment = dict(os.environ, FLVLESS_TIMING_MODE=mode)
                log = output / (mode + '-run.log')
                bounded_run(['swift', 'test', '--skip-build', '--package-path', str(package), '--filter', 'TunnelEndpointStartupTimingTests'], log, 45, environment)
                result['metrics'][mode] = parse_metrics(log.read_text(), mode)
            result['comparison'] = compare(result['metrics']['baseline'], result['metrics']['candidate'])
            result['log_sha256'] = {mode + '-run.log': digest((output / (mode + '-run.log')).read_bytes()) for mode in packages}
            result['success'] = True
            if os.environ.get('GITHUB_STEP_SUMMARY'):
                summary = ['Controlled DNS startup; this is not a live system VPN measurement.', '',
                           '| Scenario | Before (ms) | After (ms) |', '|---|---:|---:|']
                for case in CASES:
                    values = [statistics.median(r['elapsed_ms'] for r in result['metrics'][mode] if r['case'] == case)
                              for mode in ('baseline', 'candidate')]
                    summary.append(f'| {case} | {values[0]:.1f} | {values[1]:.1f} |')
                summary += ['', 'Controlled provider readiness (inert NE/Core/HEV boundaries):', '',
                            '| Platform / profile | Start → ready (ms) | Final path change → ready (ms) |',
                            '|---|---:|---:|']
                for platform in ('ios', 'macos'):
                    for row in result['provider_policy_metrics'][platform + '-candidate']:
                        summary.append(f"| {platform} / {row['scenario']} | {row['startToReadyMs']:.1f} | {row['finalForceToReadyMs']:.1f} |")
                with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as stream:
                    stream.write('\n'.join(summary) + '\n')
        except BaseException as error:
            result['error_type'] = type(error).__name__
            raise
        finally:
            (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.prepare_only:
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result.get(key) for key in ('success', 'prepared_only', 'dns_only', 'live_ne_vpn', 'comparison')}))


if __name__ == '__main__':
    main()
