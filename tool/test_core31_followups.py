#!/usr/bin/env python3
"""Focused Core31 source-runtime acceptance, executable only in CI.

Without --run-runtime this runs the Python harness tests only: no Go command,
module download, Core preparation or native execution is performed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROUTING = ROOT / 'third_party/xray-vpn-routing'
CLASSIC = ROOT / 'third_party/xray-native-dns'
MOBILE = ROOT / 'third_party/xray-mobile'
TAG = 'flutter_vless_core31_followups'
PIN = {
    'core_commit': 'a4a3dff5b20c2faae567b742c172c7b95e75c083',
    'module': 'github.com/xtls/xray-core',
    'module_version': 'v1.260327.1-0.20261031132019-a4a3dff5b20c',
    'module_sum': 'h1:XijTasBJ2fImHZo1GoAgSfHuDqloQGYHEADLy9CgrJ8=',
}


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# This process/output owner is already independently exercised on all three OSs.
common = load_module(ROOT / 'tool/test_native_dns_context_runtime.py', 'core31_process_owner')


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Source input must be a real regular file: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_authorized(environment=None, system=None):
    return common.runtime_authorized(environment, system)


def child_environment(source):
    environment = {key: value for key, value in source.items()
                   if not key.upper().startswith(('XRAY.', 'XRAY_'))}
    environment.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly')
    environment['xray.browser.dialer'] = ''
    environment['XRAY_BROWSER_DIALER'] = ''
    return environment


def validate_pin(manifest, module_text, sum_text):
    if any(manifest.get(key) != value for key, value in PIN.items()):
        raise ValueError('This focused acceptance requires the exact Core31 pin')
    requirement = re.compile(r'^\s*(?:require\s+)?' + re.escape(PIN['module'])
                             + r'\s+' + re.escape(PIN['module_version']) + r'\s*(?://[^\n]*)?$', re.M)
    if not requirement.search(module_text) or '{} {} {}'.format(
            PIN['module'], PIN['module_version'], PIN['module_sum']) not in sum_text.splitlines():
        raise ValueError('Mobile module Version/Sum differs from the exact Core31 pin')


def validate_metadata(metadata):
    if metadata.get('Error') or any(metadata.get(key) != PIN[field] for key, field in
                                   [('Path', 'module'), ('Version', 'module_version'), ('Sum', 'module_sum')]):
        raise ValueError('Downloaded Core Path/Version/Sum differs from Core31')
    source = Path(metadata.get('Dir', ''))
    if not source.is_absolute() or source.is_symlink() or not source.is_dir():
        raise ValueError('Downloaded Core directory must be an existing absolute real directory')
    return source.resolve()


def tree_snapshot(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Source tree must be a real directory')
    return {path.relative_to(root).as_posix(): digest(path)
            for path in sorted(root.rglob('*')) if path.is_symlink() or path.is_file()}


def verify_tree(root, expected):
    if tree_snapshot(root) != expected:
        raise ValueError('Source tree changed during acceptance: ' + str(root))


def copy_fixture(source, core, relative):
    expected = digest(source)
    target = core / relative
    if target.exists() or target.is_symlink():
        if digest(target) != expected:
            raise ValueError('Prepared fixture collision: ' + relative)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    if digest(target) != expected:
        raise ValueError('Fixture copy differs from source: ' + relative)


def fixture_pairs():
    overlay = CLASSIC / 'overlay'
    return [
        (overlay / 'app/geodata/native_geodata_gzip_test.go', 'app/geodata/native_geodata_gzip_test.go'),
        (overlay / 'transport/internet/splithttp/native_core31_xhttp_test.go', 'transport/internet/splithttp/native_core31_xhttp_test.go'),
        (overlay / 'transport/internet/splithttp/native_core31_xhttp_admission_test.go', 'transport/internet/splithttp/native_core31_xhttp_admission_test.go'),
        (overlay / 'proxy/http/native_core31_continue_test.go', 'proxy/http/native_core31_continue_test.go'),
        (ROOT / 'tool/fixtures/core31/native_core31_wfp_windows_test.go', 'proxy/tun/native_core31_wfp_windows_test.go'),
    ]


def source_snapshot():
    paths = {Path(__file__).resolve(), ROOT / 'tool/test_core31_followups_runner.py',
             ROOT / 'tool/test_native_dns_context_runtime.py', MOBILE / 'go.mod', MOBILE / 'go.sum'}
    for folder in (CLASSIC, ROUTING):
        paths.update(folder.glob('*.py'))
        paths.add(folder / 'pin-manifest.json')
        paths.update((folder / 'overlay').rglob('*.go'))
    paths.update(source for source, _ in fixture_pairs())
    paths.update(path for path in (ROOT / 'example/configs/core31').rglob('*') if path.is_file() or path.is_symlink())
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(paths)}


GEO_CONTENT_MODES = ['gzip_without_gz_extension', 'raw_with_gz_extension', 'corrupt_header',
                     'truncated_header', 'truncated_trailer', 'corrupt_checksum',
                     'empty_decoded_body', 'corrupt_second_member']
GEO_TESTS = ['TestNativeGeoDataGzipContentsAndCorruptPreservation', 'TestNativeGeoDataGzipDecodedLimit',
             'TestNativeGeoDataGzipBatchStagingAndCommit', 'TestNativeGeoDataGzipCloseCancelsActiveCompressedDownload']
QUIC_TEST = 'TestNativeVPNRoutingRuntimeQUICInitial'
QUIC_MODES = ['whole', 'frames-out-of-order', 'coalesced-initials', 'separate-datagrams',
              'gap-repaired', 'gap-in-sni', 'gap-in-name-length', 'empty-sni', 'wrong-sni',
              'truncated-packet', 'bad-authentication']
HTTP_TEST = 'TestCore31HTTPContinueUpload'
HTTP_MODES = ['short_continue', 'fragmented_continue', 'rejected_expectation', 'truncated_interim', 'cancelled_origin']
XHTTP_TESTS = ['TestCore31XHTTPOptions', 'TestCore31XHTTPH2ParamsWire', 'TestCore31XHTTPInvalidH2ParamsAdmission']
WFP_TEST = 'TestNativeCore31WFPPortsAndCleanup'


def groups(system):
    quic = [QUIC_TEST] + [QUIC_TEST+'/decoder/'+mode for mode in QUIC_MODES]
    for default in ['direct', 'proxy']:
        for sniff in ['true', 'false']:
            parent = QUIC_TEST+'/route/default-'+default+'/sniff-'+sniff
            quic.extend([parent, *(parent+'/'+mode for mode in QUIC_MODES)])
    return [
        {'name': 'geodat', 'package': 'app/geodata', 'core': 'ordinary', 'seconds': 90,
         'tests': GEO_TESTS, 'passes': GEO_TESTS
         + [GEO_TESTS[0]+'/'+mode for mode in GEO_CONTENT_MODES]
         + [GEO_TESTS[1]+'/'+mode for mode in ['exact_256MiB', 'over_256MiB']]},
        {'name': 'xhttp', 'package': 'transport/internet/splithttp', 'core': 'ordinary', 'seconds': 70,
         'tests': XHTTP_TESTS[:2], 'passes': XHTTP_TESTS[:2]
         + [XHTTP_TESTS[0]+'/'+mode+'/'+method for mode in ['packet-up', 'stream-up', 'stream-one'] for method in ['POST', 'OPTIONS']]
         + [XHTTP_TESTS[1]+'/'+mode for mode in ['baseline', 'custom']]},
        {'name': 'xhttp-admission', 'package': 'transport/internet/splithttp', 'core': 'ordinary', 'seconds': 15,
         'tests': XHTTP_TESTS[2:], 'passes': XHTTP_TESTS[2:]},
        {'name': 'http-continue', 'package': 'proxy/http', 'core': 'ordinary', 'seconds': 30,
         'tests': [HTTP_TEST], 'passes': [HTTP_TEST, *(HTTP_TEST+'/'+mode for mode in HTTP_MODES)]},
        {'name': 'quic', 'package': 'app/dispatcher', 'core': 'routing', 'seconds': 90,
         'tests': [QUIC_TEST], 'passes': quic},
        {'name': 'windows-core-tun-wfp', 'package': 'proxy/tun', 'core': 'ordinary', 'seconds': 60,
         'tests': [WFP_TEST], 'passes': [WFP_TEST], 'applicable': system == 'Windows'},
    ]


def marker_patterns(name):
    if name == 'geodat':
        return [('native_geodata_gzip_test.go', 'GEODAT_GZIP_CONTENT_PASS mode='+mode) for mode in GEO_CONTENT_MODES] + [
            ('native_geodata_gzip_test.go', r'GEODAT_GZIP_LIMIT_PASS mode=exact_256MiB decoded=268435456 wire=\d+'),
            ('native_geodata_gzip_test.go', r'GEODAT_GZIP_LIMIT_PASS mode=over_256MiB decoded=268435457 wire=\d+'),
            ('native_geodata_gzip_test.go', 'GEODAT_GZIP_TRANSACTION_PASS'),
            ('native_geodata_gzip_test.go', 'GEODAT_GZIP_CANCEL_PASS')]
    if name == 'quic':
        return [('native_routing_quic_runtime_test.go', 'CORE31_QUIC_INITIAL_PASS decoder=11 directions=2 sniff-controls=2 exact-datagrams=true')]
    if name == 'xhttp':
        return [('native_core31_xhttp_test.go', 'CORE31_XHTTP_OPTIONS_PASS mode='+mode+' method='+method+' bytes=4096')
                for mode in ['packet-up', 'stream-up', 'stream-one'] for method in ['POST', 'OPTIONS']] + [
            ('native_core31_xhttp_test.go', 'CORE31_XHTTP_H2_PARAMS_PASS mode='+mode+' settings=true preflight=true wrong_path=true')
            for mode in ['baseline', 'custom']]
    if name == 'xhttp-admission':
        return [
            ('native_core31_xhttp_admission_test.go', r'CORE31_XHTTP_H2_REJECT_PASS stage=(?:build|start) listener_reusable=true valid_settings=true')]
    if name == 'http-continue':
        return [('native_core31_continue_test.go', 'CORE31_HTTP_CONTINUE_PASS mode='+mode+' interim=100 final=200 bytes=65536')
                for mode in ['short_continue', 'fragmented_continue']] + [
            ('native_core31_continue_test.go', 'CORE31_HTTP_CONTINUE_PASS mode=rejected_expectation body_sent=false status=417'),
            ('native_core31_continue_test.go', 'CORE31_HTTP_CONTINUE_PASS mode=truncated_interim body_sent=false status=503'),
            ('native_core31_continue_test.go', 'CORE31_HTTP_CONTINUE_PASS mode=cancelled_origin body_sent=false deadline=true')]
    if name == 'windows-core-tun-wfp':
        return [('native_core31_wfp_windows_test.go', 'CORE31_WFP_PHASE_PASS mode='+mode+' cases=8')
                for mode in ['before', 'outside-TUN-blocked', 'after-close', 'through-TUN-interface-permitted', 'final-recovery']] + [
            ('native_core31_wfp_windows_test.go', 'CORE31_WFP_SELF_EXEMPT_PASS'),
            ('native_core31_wfp_windows_test.go', 'CORE31_WFP_CLEANUP_PASS filters_delta=0 ports=4')]
    raise ValueError('Unknown group')


def test_pattern(names):
    if not names or len(names) != len(set(names)):
        raise ValueError('Selected tests must be nonempty and unique')
    return '^('+'|'.join(re.escape(name) for name in names)+')$'


def qualify(output, group):
    if not output or re.search(r'^\s*--- (?:FAIL|SKIP):', output, re.M) or not re.search(r'\nPASS\r?\n?\Z', output):
        raise ValueError('Runtime evidence empty, failed, skipped or not fully drained')
    passes = re.findall(r'^\s*--- PASS: ([^\s]+) \([^\r\n]*\)\r?$', output, re.M)
    if Counter(passes) != Counter(group['passes']):
        raise ValueError('Exact selected runtime test/subtest PASS set missing, duplicated or unexpected')
    patterns = marker_patterns(group['name'])
    seen = []
    for line in output.splitlines():
        if not re.search(r'(?:GEODAT_GZIP|CORE31_(?:QUIC|XHTTP|HTTP_CONTINUE|WFP))', line):
            continue
        matches = [index for index, (source, marker) in enumerate(patterns)
                   if re.fullmatch(r'\s+'+re.escape(source)+r':\d+: '+marker, line)]
        if len(matches) != 1:
            raise ValueError('Unexpected/spoofed runtime marker source or fields')
        seen.extend(matches)
    if Counter(seen) != Counter(range(len(patterns))):
        raise ValueError('Exact runtime controls missing or duplicated')
    return {'selected_tests': group['tests'], 'test_and_subtest_PASS_count': len(passes),
            'strict_control_marker_count': len(patterns), 'no_skips': True, 'final_PASS': True}


def verify_phase(result):
    if result.get('exit_code') != 0 or result.get('process_exit_code') != 0 or result.get('timed_out') \
            or not result.get('output_closed') or not result.get('output_eof') or result.get('output_errors') != []:
        raise ValueError('Runtime phase lacked successful child exit and complete owned output')


def run_units():
    module = load_module(ROOT / 'tool/test_core31_followups_runner.py', 'core31_followup_unit_suite')
    return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module)).wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-runtime', action='store_true')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'build/core31_followups')
    parser.add_argument('--go', default='go')
    arguments = parser.parse_args(argv)
    if not arguments.run_runtime:
        return run_units()
    if not runtime_authorized():
        parser.error('Core runtime requires CI=true; Darwin also requires GITHUB_ACTIONS=true')
    evidence = arguments.output_dir.absolute()
    if evidence.exists() or evidence.is_symlink():
        parser.error('Evidence directory already exists; select a fresh owned output directory')
    evidence.mkdir(parents=True, mode=0o700)
    common.EVIDENCE = evidence
    environment = child_environment(os.environ)
    results = []
    report = {'scope': 'Five focused Core31 source-runtime follow-ups; no plugin publication or live Mac VPN',
              'published_runtime_bytes': False, 'core_pin': PIN, 'system': platform.system(),
              'results': results, 'groups': [], 'runtime_guard_passed': True}
    source = None
    source_before = None
    snapshot = None
    copies = {}
    try:
        snapshot = source_snapshot()
        report['root_source_sha256'] = snapshot
        module_text = (MOBILE / 'go.mod').read_text()
        sum_text = (MOBILE / 'go.sum').read_text()
        for manifest in [ROUTING / 'pin-manifest.json', CLASSIC / 'pin-manifest.json']:
            validate_pin(json.loads(manifest.read_text()), module_text, sum_text)
        common.checked('go-version', [arguments.go, 'version'], cwd=ROOT, environment=environment, seconds=15, results=results)
        report['go_version'] = (evidence / 'go-version.log').read_text().strip()
        common.checked('module-download', [arguments.go, 'mod', 'download', '-json', PIN['module']+'@'+PIN['module_version']],
                       cwd=MOBILE, environment=environment, seconds=180, results=results)
        source = validate_metadata(json.loads((evidence / 'module-download.log').read_text()))
        # Version/Sum metadata alone is insufficient for an already-expanded
        # cache tree. Let Go verify cached file contents against its module ZIP
        # before treating the disposable copies as authenticated pinned input.
        common.checked('module-cache-verify', [arguments.go, 'mod', 'verify'], cwd=MOBILE,
                       environment=environment, seconds=120, results=results)
        if (evidence / 'module-cache-verify.log').read_text().strip() != 'all modules verified':
            raise ValueError('Module cache content verification did not report complete success')
        source_before = tree_snapshot(source)
        report['module_cache_source_sha256'] = source_before
        common.checked('module-cache-path', [arguments.go, 'env', 'GOMODCACHE'], cwd=MOBILE,
                       environment=environment, seconds=15, results=results)
        cache = Path((evidence / 'module-cache-path.log').read_text().strip()).resolve()
        if not cache.is_dir() or not source.is_relative_to(cache):
            raise ValueError('Downloaded source is outside its reported module cache')
        applier = load_module(ROUTING / 'apply.py', 'core31_routing_applier')
        for kind, routing in [('ordinary', False), ('routing', True)]:
            core = evidence / ('Core-'+kind)
            applier.copy_and_apply_lifetimes(source, core, go=arguments.go, caches=[cache], routing=routing)
            if kind == 'ordinary':
                for original, target in fixture_pairs():
                    copy_fixture(original, core, target)
            else:
                relative = 'app/dispatcher/native_routing_quic_runtime_test.go'
                copy_fixture(ROUTING / 'overlay' / relative, core, relative)
                # Real authenticated SOCKS/UDP encoders are shared by this test.
                helper = 'app/dispatcher/native_routing_runtime_test.go'
                if digest(core / helper) != digest(ROUTING / 'overlay' / helper):
                    raise ValueError('QUIC helper differs from the exact routing fixture')
            copies[kind] = (core, tree_snapshot(core))
        report['composition_source_sha256'] = {kind: hashes for kind, (_, hashes) in copies.items()}
        for group in groups(platform.system()):
            entry = {'name': group['name'], 'scope': 'exact pinned protected '+group['core']+' Core source composition'}
            report['groups'].append(entry)
            if not group.get('applicable', True):
                entry.update(status='not-applicable', reason='Actual Core WFP installation requires Windows; no substitute pass')
                continue
            try:
                core = copies[group['core']][0]
                binary = evidence / (group['name']+('.test.exe' if os.name == 'nt' else '.test'))
                common.checked(group['name']+'-compile', [arguments.go, 'test', '-tags', TAG, '-c', '-o', str(binary), './'+group['package']],
                               cwd=core, environment=environment, seconds=300, results=results)
                verify_phase(results[-1])
                entry['test_binary_sha256'] = digest(binary)
                phase = group['name']+'-runtime'
                common.checked(phase, [str(binary), '-test.run', test_pattern(group['tests']), '-test.v', '-test.timeout='+str(group['seconds'])+'s'],
                               cwd=core, environment=environment, seconds=group['seconds']+15, results=results)
                verify_phase(results[-1])
                entry.update(qualify((evidence / (phase+'.log')).read_text(encoding='utf-8'), group))
                entry['status'] = 'passed'
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                # Preserve an independent RED (e.g. admission) and still obtain
                # other bounded groups' evidence. A RED can never yield an
                # overall pass and does not reuse a stale preceding group's log.
                entry.update(status='failed', error_type=type(error).__name__, error=str(error))
        if source_snapshot() != snapshot:
            raise ValueError('Root source snapshot changed during acceptance')
        verify_tree(source, source_before)
        for core, hashes in copies.values():
            verify_tree(core, hashes)
        if any(entry['status'] == 'failed' for entry in report['groups']):
            raise RuntimeError('One or more focused runtime groups failed; see their exact phase evidence')
        report.update(success=True, root_inputs_unchanged=True, module_cache_source_unchanged=True,
                      composition_sources_unchanged=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(success=False, error_type=type(error).__name__, error=str(error))
        print('Core31 follow-up acceptance failed: '+str(error), file=sys.stderr)
    finally:
        if snapshot is not None:
            try:
                report['root_inputs_unchanged'] = source_snapshot() == snapshot
            except (OSError, ValueError):
                report['root_inputs_unchanged'] = False
        if source is not None and source_before is not None:
            try:
                report['module_cache_source_unchanged'] = tree_snapshot(source) == source_before
            except (OSError, ValueError):
                report['module_cache_source_unchanged'] = False
        if not report.get('root_inputs_unchanged') or not report.get('module_cache_source_unchanged'):
            report['success'] = False
        (evidence / 'result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return 0 if report.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
