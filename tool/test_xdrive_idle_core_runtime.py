#!/usr/bin/env python3
"""Observe idle XDRIVE workers through actual Core.Close, in remote CI only."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import test_native_dns_context_runtime as supervisor

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tool/fixtures/xdrive_idle_core_runtime_test.go'
COPIER = ROOT / 'third_party/xray-vpn-routing/apply.py'
MANIFEST = json.loads((ROOT / 'third_party/xray-native-dns/pin-manifest.json').read_text())
TEST = 'TestAcceptanceXdriveActualCoreCloseDrainsIdleWorker'
ASSERTION = 'idle WAL worker survived actual Core.Close; caller/feature contexts preserved'


def runtime_authorized(environment):
    return all(environment.get(key, '').lower() == 'true' for key in ('CI', 'GITHUB_ACTIONS'))


def reproduced_failure(results, output):
    if not results:
        return False
    row = results[-1]
    return (row.get('name') == 'idle-runtime' and row.get('exit_code') == 1
            and row.get('process_exit_code') == 1 and row.get('timed_out') is False
            and row.get('output_closed') is True and row.get('output_eof') is True
            and row.get('output_errors') == [] and ASSERTION in output
            and f'--- FAIL: {TEST}' in output)


def snapshot(paths):
    return {str(path.relative_to(ROOT)).replace(os.sep, '/'): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-runtime', action='store_true')
    parser.add_argument('--go', default='go')
    parser.add_argument('--evidence', type=Path, default=ROOT / 'build/xdrive_idle_core_runtime')
    args = parser.parse_args(argv)
    # Guard before creating files, resolving a toolchain or invoking any Core.
    if not args.run_runtime or not runtime_authorized(os.environ):
        parser.error('Actual Core diagnostic requires --run-runtime and remote GitHub Actions')
    evidence = args.evidence.absolute()
    if evidence.exists() or evidence.is_symlink():
        parser.error('Evidence directory must be new; earlier outcomes are never replaced')
    evidence.mkdir(parents=True)
    supervisor.EVIDENCE = evidence
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
    source_inputs = sorted(set([Path(__file__).resolve(), FIXTURE, COPIER,
                               ROOT / 'third_party/xray-vpn-routing/pin-manifest.json',
                               ROOT / 'tool/test_native_dns_context_runtime.py']
                              + list((ROOT / 'third_party/xray-native-dns').glob('*.py'))
                              + list((ROOT / 'third_party/xray-native-dns/overlay').rglob('*.go'))))
    before = snapshot(source_inputs)
    results = []
    report = {'success': False, 'published': False, 'runtime_requested': True,
              'core_commit': MANIFEST['core_commit'], 'results': results,
              'source_sha256': before, 'observation': 'real Core/dispatcher/SOCKS with observing-only transport alias',
              'scope': 'one idle WAL reader, synthetic local S3, no cloud account or OS VPN',
              'production_source_modified': False}
    source = None
    try:
        downloaded = subprocess.run([args.go, 'mod', 'download', '-json',
                                     f"{MANIFEST['module']}@{MANIFEST['module_version']}"],
                                    cwd=ROOT / 'third_party/xray-mobile', env=environment,
                                    text=True, capture_output=True, check=True, timeout=180)
        metadata = json.loads(downloaded.stdout)
        if metadata.get('Version') != MANIFEST['module_version'] or metadata.get('Sum') != MANIFEST['module_sum']:
            raise RuntimeError('Pinned Core version/checksum mismatch')
        source = Path(metadata['Dir']).resolve()
        spec = importlib.util.spec_from_file_location('idle_ordinary_copier', COPIER)
        copier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(copier)
        copied = copier.copy_and_apply(source, evidence / 'Core', go=args.go, routing=True)
        target = copied / 'transport/internet/xdrive/native_idle_core_runtime_test.go'
        shutil.copyfile(FIXTURE, target)
        report['copied_production_source_sha256'] = {
            str(p.relative_to(copied)).replace(os.sep, '/'): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(copied.rglob('*.go')) if not p.name.endswith('_test.go')}
        binary = evidence / ('idle.test.exe' if os.name == 'nt' else 'idle.test')
        supervisor.checked('idle-compile', [args.go, 'test', '-mod=readonly', '-c', '-o', str(binary),
                                           './transport/internet/xdrive'],
                           cwd=copied, environment=environment, seconds=300, results=results)
        supervisor.checked('idle-runtime', [str(binary), '-test.run=^' + TEST + '$', '-test.v', '-test.timeout=15s'],
                           cwd=copied, environment=environment, seconds=20, results=results)
        report['success'] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    finally:
        log = evidence / 'idle-runtime.log'
        report['idle_worker_survival_reproduced'] = reproduced_failure(results, log.read_text() if log.exists() else '')
        report['source_snapshot_unchanged'] = snapshot(source_inputs) == before
        if source is not None:
            report['module_cache_source_unchanged'] = all(
                hashlib.sha256((source / path).read_bytes()).hexdigest() == digest
                for path, digest in MANIFEST['upstream_sha256'].items())
        (evidence / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['success'] and report['source_snapshot_unchanged'] and report.get('module_cache_source_unchanged') else 1


if __name__ == '__main__':
    raise SystemExit(main())
