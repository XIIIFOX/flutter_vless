#!/usr/bin/env python3
"""Verify the optional routing overlay; execute real Core only when requested in CI."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY = ROOT / 'third_party/xray-vpn-routing'
MOBILE = ROOT / 'third_party/xray-mobile'
EVIDENCE = ROOT / 'build/native_vpn_routing'
PACKAGES = [('routing', 'features/routing'), ('dispatcher', 'app/dispatcher'),
            ('inbound', 'app/proxyman/inbound')]
RUNTIME_TEST = 'TestNativeVPNRoutingRuntime'


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Reuse the independently tested bounded process/output owner, not a second
# implementation. Its source is included in this runner's immutable snapshot.
common = load_module(ROOT / 'tool/test_native_dns_context_runtime.py', 'vpn_routing_process_owner')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child_environment(source):
    result = {key: value for key, value in source.items()
              if not key.upper().startswith(('XRAY.', 'XRAY_'))}
    result.update(GOTOOLCHAIN='local', GOWORK='off')
    result['xray.browser.dialer'] = ''
    result['XRAY_BROWSER_DIALER'] = ''
    return result


def runtime_authorized(environment=None):
    environment = os.environ if environment is None else environment
    return all(environment.get(key, '').lower() == 'true' for key in ('CI', 'GITHUB_ACTIONS'))


def source_snapshot():
    paths = [Path(__file__).resolve(), ROOT / 'tool/test_native_vpn_routing_runner.py',
             ROOT / 'tool/test_native_dns_context_runtime.py', CAPABILITY / 'apply.py',
             CAPABILITY / 'pin-manifest.json', MOBILE / 'go.mod', MOBILE / 'go.sum']
    paths.extend(sorted((CAPABILITY / 'overlay').rglob('*.go')))
    return {str(path.relative_to(ROOT)).replace(os.sep, '/'): digest(path) for path in paths}


def tree_snapshot(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Core source must be a real directory')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Core source symlinks are unsupported')
        if path.is_file():
            result[str(path.relative_to(root)).replace(os.sep, '/')] = digest(path)
    return result


def validate_mobile_pin(manifest, module_text, sum_text):
    module, version, checksum = (manifest[key] for key in ('module', 'module_version', 'module_sum'))
    requirement = re.compile(r'^\s*(?:require\s+)?' + re.escape(module) + r'\s+' + re.escape(version) + r'\s*(?://[^\n]*)?$', re.M)
    if not requirement.search(module_text) or f'{module} {version} {checksum}' not in sum_text.splitlines():
        raise ValueError('Routing overlay pin differs from the mobile Core module')


def validate_metadata(manifest, metadata):
    if metadata.get('Error') or any(metadata.get(key) != manifest[field] for key, field in
                                  [('Path', 'module'), ('Version', 'module_version'), ('Sum', 'module_sum')]):
        raise ValueError('Downloaded Core Version/Sum differs from the pinned mobile module')
    source = Path(metadata['Dir']).resolve()
    if not source.is_dir():
        raise ValueError('Pinned Core source directory is unavailable')
    return source


def selected_tests(overlay, package, *, runtime=False):
    names = []
    for path in sorted((overlay / package).glob('*_test.go')):
        names.extend(re.findall(r'^func\s+(Test(?:NativeRouting|NativeVPNRouting)[A-Za-z0-9_]*)\s*\(', path.read_text(), re.M))
    if len(names) != len(set(names)):
        raise ValueError('Duplicate selected routing test names')
    if runtime:
        if RUNTIME_TEST not in names:
            raise ValueError('Requested runtime fixture is absent')
        return [RUNTIME_TEST]
    names = sorted(name for name in names if not name.startswith(RUNTIME_TEST))
    if not names:
        raise ValueError('No selected pure routing tests in ' + package)
    return names


def test_pattern(names):
    return '^(' + '|'.join(re.escape(name) for name in names) + ')$'


def checked(name, command, *, environment, cwd, seconds, results):
    common.EVIDENCE = EVIDENCE
    common.checked(name, command, environment=environment, cwd=cwd, seconds=seconds, results=results)


def require_pass(name, selected, results):
    text = (EVIDENCE / (name + '.log')).read_text(encoding='utf-8')
    for test in selected:
        common.require_selected_test_pass(text, test)
    results[-1].update(selected_test_pass=True, selected_tests=selected)


class Interrupted(BaseException):
    def __init__(self, number):
        self.number = number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go', help='Existing Go 1.27+ binary; never installs a toolchain')
    parser.add_argument('--run-runtime', action='store_true')
    arguments = parser.parse_args(argv)
    if arguments.run_runtime and not runtime_authorized():
        parser.error('Actual Core requires CI=true and GITHUB_ACTIONS=true')
    core = EVIDENCE / 'Core'
    if core.exists() or core.is_symlink() or (EVIDENCE / 'result.json').exists():
        parser.error('Evidence/Core already exists; use a fresh checkout/evidence directory')
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    results = []
    report = {'published': False, 'runtime_requested': arguments.run_runtime, 'results': results,
              'success': False}
    source = None
    source_before = None
    copied_before = None
    snapshot = None
    previous_handlers = {}

    def interrupt(number, frame):
        # Do not interrupt the bounded child cleanup on a second signal.
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        raise Interrupted(number)

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.signal(sig, interrupt)
        snapshot = source_snapshot()
        report['source_sha256'] = snapshot
        manifest = json.loads((CAPABILITY / 'pin-manifest.json').read_text())
        report.update(capability=manifest['capability'], core_commit=manifest['core_commit'])
        validate_mobile_pin(manifest, (MOBILE / 'go.mod').read_text(), (MOBILE / 'go.sum').read_text())
        selections = {name: selected_tests(CAPABILITY / 'overlay', package) for name, package in PACKAGES}
        if arguments.run_runtime:
            selected_tests(CAPABILITY / 'overlay', 'app/dispatcher', runtime=True)
        environment = child_environment(os.environ)
        go = Path(shutil.which(arguments.go) or arguments.go).resolve()
        gofmt = go.with_name('gofmt.exe' if os.name == 'nt' else 'gofmt')
        if not go.is_file() or not gofmt.is_file():
            raise ValueError('Existing Go/gofmt toolchain is unavailable')
        report['go_binary'] = str(go)
        checked('runner-guards', [sys.executable, str(ROOT / 'tool/test_native_vpn_routing_runner.py')],
                cwd=ROOT, environment=environment, seconds=30, results=results)
        checked('core-pin', [str(go), 'mod', 'download', '-json', manifest['module'] + '@' + manifest['module_version']],
                cwd=MOBILE, environment=environment, seconds=180, results=results)
        metadata = json.loads((EVIDENCE / 'core-pin.log').read_text(encoding='utf-8'))
        source = validate_metadata(manifest, metadata)
        source_before = tree_snapshot(source)
        report['module_source_before_sha256'] = source_before
        if any(source_before.get(path) != expected for path, expected in manifest['upstream_sha256'].items()):
            raise ValueError('Pinned source/cache hash mismatch before copying')
        checked('module-cache', [str(go), 'env', 'GOMODCACHE'], cwd=MOBILE,
                environment=environment, seconds=20, results=results)
        cache = Path((EVIDENCE / 'module-cache.log').read_text(encoding='utf-8').strip())
        if not cache.is_absolute():
            raise ValueError('Go module cache path must be absolute')
        applier = load_module(CAPABILITY / 'apply.py', 'native_vpn_routing_apply')
        applier.copy_and_apply(source, core, go=str(go), caches=[cache])
        overlay = CAPABILITY / 'overlay'
        for path in overlay.rglob('*.go'):
            relative = path.relative_to(overlay)
            if digest(core / relative) != digest(path):
                raise ValueError('Copied overlay differs from its source')
        targets = {path for path, _, _ in applier.patches()}
        if not targets.issubset(manifest['upstream_sha256']):
            raise ValueError('Patch target has no pinned upstream hash')
        targets.update(str(path.relative_to(overlay)).replace(os.sep, '/') for path in overlay.rglob('*.go'))
        copied_go = sorted(path for path in targets if path.endswith('.go'))
        checked('gofmt-copy', [str(gofmt), '-w', *[str(core / path) for path in copied_go]],
                cwd=core, environment=environment, seconds=30, results=results)
        report['copied_go_sha256'] = {path: digest(core / path) for path in copied_go}
        copied_before = tree_snapshot(core)
        report['copied_tree_sha256'] = hashlib.sha256(json.dumps(copied_before, sort_keys=True).encode()).hexdigest()
        report['copied_tree_file_count'] = len(copied_before)
        binaries = {}
        for name, package in PACKAGES:
            binary = EVIDENCE / (name + ('.test.exe' if os.name == 'nt' else '.test'))
            checked(name + '-compile', [str(go), 'test', '-mod=readonly', '-c', '-o', str(binary), './' + package],
                    cwd=core, environment=environment, seconds=300, results=results)
            binaries[name] = binary
            checked(name + '-pure', [str(binary), '-test.run', test_pattern(selections[name]), '-test.v', '-test.timeout=30s'],
                    cwd=core, environment=environment, seconds=45, results=results)
            require_pass(name + '-pure', selections[name], results)
        if arguments.run_runtime:
            checked('runtime', [str(binaries['dispatcher']), '-test.run', '^' + RUNTIME_TEST + '$', '-test.v', '-test.timeout=75s'],
                    cwd=core, environment=environment, seconds=90, results=results)
            require_pass('runtime', [RUNTIME_TEST], results)
        if source_snapshot() != snapshot:
            raise ValueError('Routing overlay/runner inputs changed during verification')
        report['source_snapshot_unchanged'] = True
        if any(digest(core / path) != expected for path, expected in report['copied_go_sha256'].items()):
            raise ValueError('Copied patched source changed during verification')
        report['copied_source_unchanged'] = True
        report['success'] = True
    except Interrupted as error:
        report.update(error='Interrupted', signal=error.number)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        report['error'] = str(error)
        print('Native VPN routing verification failed: ' + str(error), file=sys.stderr)
    finally:
        if source is not None and source_before is not None:
            try:
                report['module_cache_source_unchanged'] = tree_snapshot(source) == source_before
            except (OSError, ValueError):
                report['module_cache_source_unchanged'] = False
            if not report['module_cache_source_unchanged']:
                report['success'] = False
                report.setdefault('error', 'Core source/cache changed during verification')
        if snapshot is not None:
            try:
                report['source_snapshot_unchanged'] = source_snapshot() == snapshot
            except (OSError, ValueError):
                report['source_snapshot_unchanged'] = False
            if not report['source_snapshot_unchanged']:
                report['success'] = False
                report.setdefault('error', 'Routing input source changed during verification')
        if copied_before is not None:
            try:
                report['copied_source_unchanged'] = tree_snapshot(core) == copied_before
            except (OSError, ValueError):
                report['copied_source_unchanged'] = False
            if not report['copied_source_unchanged']:
                report['success'] = False
                report.setdefault('error', 'Copied Core source changed during verification')
        try:
            (EVIDENCE / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
    return 0 if report['success'] else 128 + report['signal'] if 'signal' in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
