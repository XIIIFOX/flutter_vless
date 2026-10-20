#!/usr/bin/env python3
"""Prepare only Classic DNS lifetime support in a copied Apple build module."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ('app/dns/dns.go', 'app/dns/nameserver_udp.go', 'transport/internet/udp/dispatcher.go')
HELPERS = ('native_classic_lifetime.go', 'native_classic_lifetime_test.go')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(path):
    if not path.is_dir() or path.is_symlink():
        raise ValueError('Core source must be a real directory')
    entries = sorted(path.rglob('*'))
    if any(entry.is_symlink() for entry in entries):
        raise ValueError('Core source symlinks are unsupported')
    return {str(entry.relative_to(path)): digest(entry) for entry in entries if entry.is_file()}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest():
    return json.loads((ROOT / 'third_party/xray-native-dns/pin-manifest.json').read_text())


def applier():
    return load(ROOT / 'third_party/xray-vpn-routing/apply.py', 'ordinary_apple_classic_applier')


def run(go, arguments, mobile, timeout):
    return subprocess.run([go, *arguments], cwd=mobile, env=dict(os.environ, GOWORK='off'),
                          capture_output=True, text=True, check=True, timeout=timeout).stdout


def metadata(go, arguments, mobile, timeout=60):
    value = json.loads(run(go, arguments, mobile, timeout))
    if not isinstance(value, dict) or value.get('Error'):
        raise ValueError('Core metadata unavailable')
    return value


def reference_hashes(source, parent):
    # A routing replacement may contain other intentional overlay files. Only
    # compare the three exact Classic upstream edits and its two helper files.
    with tempfile.TemporaryDirectory(prefix='classic-reference-', dir=parent) as directory:
        reference = Path(directory)
        for relative in UPSTREAM:
            target = reference / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)

        def replace(relative, before, after):
            path = reference / relative
            text = path.read_text()
            if text.count(before) != 1:
                raise ValueError('Pinned Classic reference mismatch')
            path.write_text(text.replace(before, after))

        patch = load(ROOT / 'third_party/xray-native-dns/classic_lifetime_patch.py', 'ordinary_classic_reference')
        patch.apply(reference, replace)
        return {relative: digest(reference / relative) for relative in UPSTREAM}


def prepare(mobile, destination, go):
    mobile, destination = mobile.resolve(), destination.resolve()
    if mobile == ROOT / 'third_party/xray-mobile' or not (mobile / 'go.mod').is_file():
        raise ValueError('A copied build module is required')
    pin, copier = manifest(), applier()
    module, version, checksum = (pin[key] for key in ('module', 'module_version', 'module_sum'))
    selected = metadata(go, ['list', '-m', '-json', module], mobile)
    if selected.get('Path') != module or selected.get('Version') != version:
        raise ValueError('Unpinned Core version')
    downloaded = metadata(go, ['mod', 'download', '-json', module + '@' + version], mobile, 180)
    if any(downloaded.get(key) != value for key, value in [('Path', module), ('Version', version), ('Sum', checksum)]):
        raise ValueError('Core pin/checksum mismatch')
    source = Path(downloaded['Dir'])
    if source.is_symlink():
        raise ValueError('Core source symlink is unsupported')
    source = source.resolve()
    before = tree(source)
    for relative in UPSTREAM:
        if before.get(relative) != pin['upstream_sha256'][relative]:
            raise ValueError('Pinned Classic upstream mismatch')
    inputs = [Path(__file__).resolve(), ROOT / 'third_party/xray-vpn-routing/apply.py',
              ROOT / 'third_party/xray-vpn-routing/pin-manifest.json', *copier.classic_input_paths()]
    input_hashes = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
    replacement = selected.get('Replace')
    if replacement is not None:
        if not isinstance(replacement, dict) or not replacement.get('Dir'):
            raise ValueError('Unsupported existing Core replacement')
        effective = Path(replacement['Dir'])
        if effective.is_symlink():
            raise ValueError('Core replacement symlink is unsupported')
        effective = effective.resolve()
        cache = Path(run(go, ['env', 'GOMODCACHE'], mobile, 30).strip()).resolve()
        if effective == cache or cache in effective.parents or effective == source:
            raise ValueError('Replacement must be a copied Core')
        existing = tree(effective)
        expected = reference_hashes(source, mobile.parent)
        for relative, value in expected.items():
            if existing.get(relative) != value:
                raise ValueError('Existing Core lacks exact Classic patch')
        for name in HELPERS:
            helper = ROOT / 'third_party/xray-native-dns/overlay/app/dns' / name
            if existing.get('app/dns/' + name) != digest(helper):
                raise ValueError('Existing Core lacks exact Classic helper')
        mode = 'validated-existing-replacement'
    else:
        effective = copier.copy_and_apply_classic(source, destination, go=go)
        existing = tree(effective)
        run(go, ['mod', 'edit', '-replace=' + module + '=' + str(effective)], mobile, 30)
        mode = 'new-classic-copy'
    final = metadata(go, ['list', '-m', '-json', module], mobile)
    final_replacement = final.get('Replace')
    if final.get('Path') != module or final.get('Version') != version or not isinstance(final_replacement, dict) \
            or not final_replacement.get('Dir') or Path(final_replacement['Dir']).resolve() != effective:
        raise ValueError('Build lost the checked Core replacement')
    if tree(source) != before or tree(effective) != existing or any(digest(ROOT / name) != value for name, value in input_hashes.items()):
        raise ValueError('Core source or patch inputs changed')
    report = {'stage': 'pre-build-preparation', 'mode': mode, 'module': module, 'version': version, 'sum': checksum,
              'scope': 'Classic DNS lifetime only; no full native-DNS context overlay',
              'replacement': str(effective), 'source_sha256': input_hashes,
              'upstream_cache_unchanged': True, 'replacement_unchanged_after_prepare': True,
              'core_copy_sha256': existing, 'runtime_executed': False}
    (mobile.parent / 'classic-core-inputs.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mobile', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--go', default='go')
    arguments = parser.parse_args()
    try:
        prepare(arguments.mobile, arguments.destination, arguments.go)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('Classic DNS build preparation failed')
    print('APPLE_CLASSIC_DNS_PREPARED=1')


if __name__ == '__main__':
    main()
