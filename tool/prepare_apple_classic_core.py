#!/usr/bin/env python3
"""Prepare Classic DNS and XHTTP H3 lifetime fixes in a copied Apple build module."""
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
UPSTREAM = ('app/dns/dns.go', 'app/dns/nameserver_udp.go', 'transport/internet/udp/dispatcher.go',
            'transport/internet/splithttp/dialer.go', 'transport/internet/sockopt_darwin.go')
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
    # compare the three Classic upstream edits, H3 dial edit and two helpers.
    with tempfile.TemporaryDirectory(prefix='classic-reference-', dir=parent) as directory:
        reference = Path(directory)
        for relative in UPSTREAM:
            target = reference / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)

        def replace(relative, before, after):
            if relative not in UPSTREAM:
                raise ValueError('Lifetime reference attempted an unrelated edit')
            path = reference / relative
            text = path.read_text()
            if text.count(before) != 1:
                raise ValueError('Pinned lifetime reference mismatch')
            path.write_text(text.replace(before, after))

        patch = load(ROOT / 'third_party/xray-native-dns/classic_lifetime_patch.py', 'ordinary_classic_reference')
        patch.apply(reference, replace)
        h3 = load(ROOT / 'third_party/xray-native-dns/h3_lifetime_patch.py', 'ordinary_h3_reference')
        h3.apply(reference, replace)
        binding = load(ROOT / 'third_party/xray-native-dns/darwin_interface_bind_patch.py', 'ordinary_darwin_binding_reference')
        binding.apply(reference, replace)
        return {relative: digest(reference / relative) for relative in UPSTREAM}


def prepare(mobile, destination, go, *, routing=False):
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
            raise ValueError('Pinned lifetime upstream mismatch')
    inputs = [Path(__file__).resolve(), ROOT / 'third_party/xray-vpn-routing/apply.py',
              ROOT / 'third_party/xray-vpn-routing/pin-manifest.json', *copier.lifetime_input_paths()]
    if routing:
        inputs += sorted((ROOT / 'third_party/xray-vpn-routing/overlay').rglob('*.go'))
    input_hashes = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
    replacement = selected.get('Replace')
    if replacement is not None:
        if routing:
            raise ValueError('Routing release preparation requires a fresh Core copy')
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
                raise ValueError('Existing Core lacks exact lifetime patch')
        for name in HELPERS:
            helper = ROOT / 'third_party/xray-native-dns/overlay/app/dns' / name
            if existing.get('app/dns/' + name) != digest(helper):
                raise ValueError('Existing Core lacks exact Classic helper')
        mode = 'validated-existing-replacement'
    else:
        effective = (copier.copy_and_apply(source, destination, go=go) if routing
                     else copier.copy_and_apply_lifetimes(source, destination, go=go))
        existing = tree(effective)
        run(go, ['mod', 'edit', '-replace=' + module + '=' + str(effective)], mobile, 30)
        mode = 'new-lifetime-copy'
    final = metadata(go, ['list', '-m', '-json', module], mobile)
    final_replacement = final.get('Replace')
    if final.get('Path') != module or final.get('Version') != version or not isinstance(final_replacement, dict) \
            or not final_replacement.get('Dir') or Path(final_replacement['Dir']).resolve() != effective:
        raise ValueError('Build lost the checked Core replacement')
    if tree(source) != before or tree(effective) != existing or any(digest(ROOT / name) != value for name, value in input_hashes.items()):
        raise ValueError('Core source or patch inputs changed')
    report = {'success': False, 'stage': 'pre-build-preparation', 'mode': mode, 'module': module, 'version': version, 'sum': checksum,
              'scope': 'Classic DNS/XHTTP H3 lifetime and mandatory Darwin interface binding; no full native-DNS context overlay',
              'routing_capability_expected': 1 if routing else 0,
              'core_commit': pin.get('core_commit'), 'core_source': str(source),
              'module_cache_before_sha256': before,
              'h3_lifetime_applied': True, 'lifetime_patch_scope': ['classic_dns', 'xhttp_h3_dial'],
              'h3_lifetime_patch_sha256': digest(ROOT / 'third_party/xray-native-dns/h3_lifetime_patch.py'),
              'darwin_interface_binding_source_applied': True,
              'darwin_interface_binding_patch_sha256': digest(ROOT / 'third_party/xray-native-dns/darwin_interface_bind_patch.py'),
              'darwin_interface_binding_capability_expected': 1,
              'replacement': str(effective), 'source_sha256': input_hashes,
              'upstream_cache_unchanged': True, 'replacement_unchanged_after_prepare': True,
              'core_copy_sha256': existing, 'runtime_executed': False}
    (mobile.parent / 'classic-core-inputs.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def verify(mobile, go):
    """Post-compiler check of the same copied Core and all producer inputs."""
    mobile = mobile.resolve()
    path = mobile.parent / 'classic-core-inputs.json'
    report = json.loads(path.read_text())
    pin = manifest()
    if any(report.get(key) != pin[pin_key] for key, pin_key in
           [('module', 'module'), ('version', 'module_version'), ('sum', 'module_sum'), ('core_commit', 'core_commit')]):
        raise ValueError('Prepared Core pin changed')
    selected = metadata(go, ['list', '-m', '-json', report['module']], mobile)
    if selected.get('Path') != report['module'] or selected.get('Version') != report['version'] \
            or Path(selected.get('Replace', {}).get('Dir', '')).resolve() != Path(report['replacement']).resolve():
        raise ValueError('Build lost the checked Core replacement')
    if tree(Path(report['core_source'])) != report['module_cache_before_sha256'] \
            or tree(Path(report['replacement'])) != report['core_copy_sha256'] \
            or any(digest(ROOT / name) != checksum for name, checksum in report['source_sha256'].items()):
        raise ValueError('Core source or patch inputs changed during build')
    version = run(go, ['env', 'GOVERSION'], mobile, 30).strip()
    import re
    match = re.fullmatch(r'go(\d+)\.(\d+)\.(\d+)', version)
    if not match or tuple(map(int, match.groups())) < (1, 27, 3):
        raise ValueError('Go 1.27.3 or newer is required for root CA filtering')
    goroot = Path(run(go, ['env', 'GOROOT'], mobile, 30).strip()).resolve()
    scratch = goroot / 'src/net/http/internal/http2/transport.go'
    if 'const max = 128 << 10 // H2BUF patch (flutter_vless issue #23)' not in scratch.read_text():
        raise ValueError('Canonical release requires the 128 KiB H2BUF patch')
    report.update(success=True, stage='post-build-verified', go_version=version,
                  root_ca_filter_toolchain_minimum='go1.27.3', h2buf_cap_kib=128,
                  h2buf_source_sha256=digest(scratch), module_cache_source_unchanged=True,
                  core_copy_unchanged=True, runtime_executed=False, published=False)
    path.write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mobile', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--vpn-routing', action='store_true')
    parser.add_argument('--verify', action='store_true')
    arguments = parser.parse_args()
    try:
        if arguments.verify:
            verify(arguments.mobile, arguments.go)
        else:
            if arguments.destination is None:
                parser.error('--destination is required for preparation')
            prepare(arguments.mobile, arguments.destination, arguments.go, routing=arguments.vpn_routing)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('Classic DNS/XHTTP H3 build preparation failed')
    print('APPLE_CLASSIC_DNS_PREPARED=1')
    print('APPLE_XHTTP_H3_PREPARED=1')


if __name__ == '__main__':
    main()
