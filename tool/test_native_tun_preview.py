#!/usr/bin/env python3
"""Test private policy/UDP/FD ownership without starting an engine or TUN."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess

import build_android_tun_preview as builder


def logged(command, path, cwd, environment):
    with path.open('w') as output:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=180)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=15)
            raise
    if status:
        raise RuntimeError('Forwarder verification failed; see ' + path.name)
    return path.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    root = builder.ROOT
    output = root / 'build/native_tun_preview'
    if output.exists() or output.is_symlink():
        parser.error('Use a fresh evidence directory; existing evidence is preserved')
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
    manifest = json.loads((builder.CAPABILITY / 'pin-manifest.json').read_text())
    metadata = json.loads(builder.common.owned([go, 'mod', 'download', '-json', manifest['module'] + '@' + manifest['module_version']],
                                              cwd=root / 'third_party/xray-mobile', environment=env, seconds=180, capture=True))
    if metadata.get('Version') != manifest['module_version'] or metadata.get('Sum') != manifest['module_sum']:
        raise RuntimeError('Pinned forwarder version/checksum differs')
    spec = importlib.util.spec_from_file_location('forwarder_test_copy', builder.CAPABILITY / 'apply.py')
    copier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copier)
    output.mkdir(parents=True)
    source, work = Path(metadata['Dir']), output / 'Source'
    initial = builder.input_hashes()
    report = {'success': False, 'engine_executed': False, 'tun_opened': False,
              'fixture_scope': 'synthetic SOCKS loopback; Linux SCM_RIGHTS with a non-TUN descriptor',
              'forwarder_commit': manifest['commit'], 'input_sha256': initial, 'phases': []}
    try:
        copier.copy_and_apply(source, work, go)
        for name, package in [('proxy', 'proxy'), ('policy', 'main/nativepreview')]:
            command = [go, 'test', '-race', '-json', '-run', '^TestNative', '-count=1', '-timeout=30s', './' + package]
            text = logged(command, output / (name + '.jsonl'), work, env)
            events = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
            passed = [row['Test'] for row in events if row.get('Action') == 'pass' and 'Test' in row]
            if not passed or any(row.get('Action') == 'fail' for row in events):
                raise RuntimeError('Selected forwarder tests did not pass')
            required = {'TestNativeUDPClientLoopbackBoundAuthenticatedAndControlEOF',
                        'TestNativeUDPClientLoopbackDropsForeignFirstResponse',
                        'TestNativeUDPClientLoopbackRejectedReplyReleasesSockets',
                        'TestNativeUDPClientLoopbackStalledHandshakeBoundedAndDrained'} if name == 'proxy' else {'TestNativePrivateForwarderPolicy'}
            if name == 'policy' and platform.system() == 'Linux':
                required |= {'TestNativePrivateFDHandoffOwnershipWithoutTUN', 'TestNativePrivateFDRejectsRealNonTUNWithoutEngine',
                             'TestNativePrivateFDCancelAcceptedReadBeforePeerEOF'}
            if not required.issubset(passed):
                raise RuntimeError('A required forwarder control did not report PASS')
            report['phases'].append({'name': name, 'passed_tests': passed})
        if platform.system() != 'Linux':
            cross = dict(env, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
            logged([go, 'test', '-c', '-o', str(output / 'linux-fd.test'), './main/nativepreview'],
                   output / 'linux-fd-compile.log', work, cross)
            report['phases'].append({'name': 'linux-fd-compile', 'executed': False})
        report['source_snapshot_unchanged'] = initial == builder.input_hashes()
        report['module_cache_targeted_sources_unchanged'] = all(
            hashlib.sha256((source / path).read_bytes()).hexdigest() == digest for path, digest in manifest['upstream_sha256'].items())
        report['success'] = report['source_snapshot_unchanged'] and report['module_cache_targeted_sources_unchanged']
        if not report['success']:
            raise RuntimeError('Forwarder source snapshot changed')
    finally:
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
