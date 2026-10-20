#!/usr/bin/env python3
"""Test native DNS preparation; run checked, lifetime-patched Core only in CI."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'build/native_dns_preservation'
WINDOWS = ROOT / 'packages/flutter_vless_windows/windows'
MOBILE = ROOT / 'third_party/xray-mobile'
CAPABILITY = ROOT / 'third_party/xray-native-dns'
CLASSIC_PATCH = CAPABILITY / 'classic_lifetime_patch.py'
CLASSIC_OVERLAY = CAPABILITY / 'overlay/app/dns'
SWIFT = ROOT / 'packages/flutter_vless_macos/macos/flutter_vless_macos'
SELECTED_TEST = 'TestNativeDNSPreservation'
PROTOCOL_TEST = 'TestNativeProtocolPreparation'
MATERIAL_TEST = 'TestNativeDoHMaterialOnly'

spec = importlib.util.spec_from_file_location('dns_preservation_checked', ROOT / 'tool/test_native_dns_context_runtime.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child_environment(source):
    # distro/all registers a browser-dialer listener during package init when
    # configured by environment. Keep file-only Build tests independent from
    # caller runtime settings without changing the parent's environment.
    result = {key: value for key, value in source.items()
              if not key.upper().startswith(('XRAY.', 'XRAY_'))}
    result.update(GOTOOLCHAIN='local', GOWORK='off')
    result['xray.browser.dialer'] = ''
    result['XRAY_BROWSER_DIALER'] = ''
    return result


def prepare_classic_core(source, destination, manifest, *, patch_apply=None, overlay=CLASSIC_OVERLAY):
    """Apply only Classic DNS lifetime edits in a checked, private Core copy."""
    source, destination = Path(source), Path(destination)
    resolved, origin = destination.resolve(), source.resolve()
    if source.is_symlink() or not source.is_dir() or destination.exists() or destination.is_symlink():
        raise ValueError('Classic DNS patch requires a real source and new destination')
    if resolved == origin or origin in resolved.parents or any(
            resolved.parts[index:index + 2] == ('pkg', 'mod') for index in range(len(resolved.parts) - 1)):
        raise ValueError('Classic DNS patch destination must be outside source and module caches')
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('Core source symlinks are unsupported')
    allowed = {'app/dns/dns.go', 'app/dns/nameserver_udp.go', 'transport/internet/udp/dispatcher.go'}
    expected = manifest['upstream_sha256']
    if not allowed.issubset(expected) or any(
            Path(name).is_absolute() or '..' in Path(name).parts for name in expected):
        raise ValueError('Classic DNS upstream guards are incomplete')
    if any(digest(source / name) != value for name, value in expected.items()):
        raise ValueError('Pinned Core source mismatch before Classic DNS patch')
    helpers = sorted(Path(overlay).glob('native_classic_*.go'))
    if not {'native_classic_lifetime.go', 'native_classic_lifetime_test.go'}.issubset(path.name for path in helpers) \
            or any(path.is_symlink() for path in helpers):
        raise ValueError('Classic DNS lifetime helper sources are missing or unsafe')
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    destination.chmod(destination.stat().st_mode | 0o700)
    for path in destination.rglob('*'):
        path.chmod(path.stat().st_mode | (0o700 if path.is_dir() else 0o200))

    def replace(name, before, after):
        if name not in allowed:
            raise ValueError('Classic DNS patch attempted an unrelated Core edit')
        path = destination / name
        text = path.read_text()
        if text.count(before) != 1:
            raise ValueError('Classic DNS pinned replacement boundary changed: ' + name)
        path.write_text(text.replace(before, after))

    if patch_apply is None:
        spec = importlib.util.spec_from_file_location('classic_dns_lifetime_patch', CLASSIC_PATCH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        patch_apply = module.apply
    patch_apply(destination, replace)
    added = {}
    for helper in helpers:
        target = destination / 'app/dns' / helper.name
        if target.exists() or target.is_symlink():
            raise ValueError('Classic DNS helper would overwrite a Core file')
        shutil.copyfile(helper, target)
        added['app/dns/' + helper.name] = digest(target)
    if any(digest(source / name) != value for name, value in expected.items()):
        raise ValueError('Original Core source changed during Classic DNS preparation')
    return {'kind': 'classic-udp-lifetime-only', 'source_unchanged': True,
            'changed_upstream': {name: digest(destination / name) for name in allowed
                                 if digest(destination / name) != expected[name]},
            'added_files': added}


def source_snapshot():
    paths = [Path(__file__).resolve(), ROOT / 'tool/test_native_dns_preservation_runner.py', ROOT / 'tool/test_native_dns_context_runtime.py',
             ROOT / 'third_party/xray-native-dns/pin-manifest.json', MOBILE / 'go.mod', MOBILE / 'go.sum',
             WINDOWS / 'xray_config.h', WINDOWS / 'desktop_security_test.cpp',
             WINDOWS / 'xray_config_test.cpp', WINDOWS / 'asset_location.h', WINDOWS / 'preparation_report.h',
             WINDOWS / 'third_party/nlohmann/json.hpp']
    paths.append(CLASSIC_PATCH)
    paths.extend(sorted(CLASSIC_OVERLAY.glob('native_classic_*.go')))
    paths.append(ROOT / 'tool/fixtures/compatibility/protocols.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/inactive-tls.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/full-config.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/traffic-counters.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/fakedns.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/direct-only.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/dns-default-tags.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/dns-data-maps.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/transport-data-maps.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/routing-attrs.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/selector-prefixes.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/selector-traffic.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/listen-addresses.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/port-env.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/schema-fields.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/opaque-fields.json')
    paths.append(ROOT / 'tool/generate_core_env_case.go')
    paths.append(ROOT / 'tool/generate_core_env_case_test.go')
    paths.append(ROOT / 'tool/fixtures/compatibility/endpoint-addresses.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/dns-addresses.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/dns-mapped-addresses.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/dns-ipv6-servers.json')
    paths.extend(ROOT / path for path in ['tool/test_native_dns_ipv6_preparation.py',
        'tool/fixtures/dns_ipv6_preparer.cpp', 'tool/fixtures/dns_ipv6_preparer.swift'])
    paths.append(ROOT / 'tool/fixtures/compatibility/transport-none.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/logical-addresses.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/asset-files.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/certificate-paths.json')
    paths.append(ROOT / 'tool/fixtures/compatibility/ipv6-payload.json')
    fixture = MOBILE / 'native_dns_preservation'
    sources = sorted(fixture.rglob('*.go'))
    if not sources:
        raise RuntimeError('Ordinary Core DNS acceptance source is missing')
    paths.extend(sources)
    if platform.system() == 'Darwin':
        paths.append(ROOT / 'tool/fixtures/native_dns_preparer.swift')
        paths.append(ROOT / 'tool/test_apple_address_binding.sh')
        paths.append(ROOT / 'tool/fixtures/apple_address_binding.swift')
        paths.extend(sorted((SWIFT / 'Sources').rglob('*.swift')))
        paths.extend(sorted((SWIFT / 'Tests').rglob('*.swift')))
    return {str(path.relative_to(ROOT)).replace(os.sep, '/'): digest(path) for path in paths}


def require_transport_data_runtime(output, preparers):
    markers = re.findall(r'^\s+xhttp_runtime_test\.go:\d+: XHTTP_TRANSPORT_DATA_MAPS_PASS chained=(true|false)\r?$',
                         output, re.MULTILINE)
    independent = re.findall(r'^\s+xhttp_runtime_test\.go:\d+: XHTTP_INDEPENDENT_DOWNLOAD_PASS\r?$', output, re.MULTILINE)
    if preparers not in (1, 2) or any(markers.count(mode) != preparers for mode in ('true', 'false')) or len(independent) != preparers:
        raise RuntimeError('Exact XHTTP transport dictionary runtime markers missing or duplicated')


def require_inactive_tls_runtime(output, preparers):
    markers = re.findall(r'^[ \t]+xhttp_runtime_test\.go:\d+: XHTTP_DORMANT_ECH_PASS mode=([^\r\n]+)\r?$',
                         output, re.MULTILINE)
    if preparers not in (1, 2) or len(markers) != 3 * preparers or any(markers.count(mode) != preparers
            for mode in ('direct', 'chained', 'independent')):
        raise RuntimeError('Exact dormant ECH transport runtime markers missing or duplicated')


def require_ipv6_dns_runtime(output, preparers):
    markers = re.findall(r'^\s+dns_ipv6_servers_test\.go:\d+: DNS_IPV6_UPSTREAM_RUNTIME_PASS transport=(udp|tcp) strategy=(UseIP|UseIPv4)\r?$',
                         output, re.MULTILINE)
    if preparers not in (1, 2) or any(markers.count((transport, strategy)) != preparers
            for transport in ('udp', 'tcp') for strategy in ('UseIP', 'UseIPv4')):
        raise RuntimeError('Exact IPv6 DNS carrier runtime markers missing or duplicated')


def require_ipv4_dns_runtime(output, preparers):
    markers = re.findall(r'^\s+dns_ipv6_servers_test\.go:\d+: DNS_IPV4_UPSTREAM_RUNTIME_PASS transport=udp strategy=(UseIP|UseIPv4)\r?$',
                         output, re.MULTILINE)
    if preparers not in (1, 2) or any(markers.count(strategy) != preparers
                                     for strategy in ('UseIP', 'UseIPv4')):
        raise RuntimeError('Exact IPv4 Classic DNS lifetime control markers missing or duplicated')


def cmd_path(path):
    # Generated batch source only contains trusted checkout/tool paths. Quotes
    # and line separators cannot be represented as a Windows path argument.
    value = str(path)
    if any(character in value for character in '"\r\n'):
        raise ValueError('Unsupported build path')
    return '"' + value.replace('%', '%%') + '"'


def msvc_script(exporter, config_test, environment):
    vswhere = Path(environment.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    script = [
        '@echo off', 'setlocal DisableDelayedExpansion',
        'set "NATIVE_DNS_VC_FOUND="',
        'if not exist ' + cmd_path(vswhere) + ' exit /b 1',
        'for /f "usebackq tokens=*" %%I in (`' + cmd_path(vswhere) + ' -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (',
        '  call "%%I\\VC\\Auxiliary\\Build\\vcvars64.bat"', '  if errorlevel 1 exit /b 1',
        '  set "NATIVE_DNS_VC_FOUND=1"', ')', 'if not defined NATIVE_DNS_VC_FOUND exit /b 1',
        'where cl >nul 2>nul', 'if errorlevel 1 exit /b 1',
    ]
    for source, binary in [('desktop_security_test.cpp', exporter), ('xray_config_test.cpp', config_test)]:
        script.extend(['cl /nologo /std:c++17 /EHsc /utf-8 /W4 /WX /DNOMINMAX '
                       + cmd_path(WINDOWS / source) + ' /Fe:' + cmd_path(binary)
                       + ' /Fo:' + cmd_path(binary.with_suffix('.obj')), 'if errorlevel 1 exit /b 1'])
    script.extend(['exit /b 0', ''])
    return '\r\n'.join(script)


def apple_commands(directory):
    """Standalone production JSON preparer; no Core objects/libraries linked."""
    privacy = sorted((SWIFT / 'Sources/flutter_vless_macos_privacy').glob('*.swift'))
    support = [path for path in sorted((SWIFT / 'Sources/flutter_vless_macos_tunnel_support').glob('*.swift'))
               if path.name != 'FlutterVlessPacketTunnelProvider.swift']
    base = ['xcrun', 'swiftc', '-O', '-target', platform.machine() + '-apple-macos13.0']
    binary = directory / 'apple-dns-preparer'
    commands = [
        ('apple-privacy-compile', base + ['-parse-as-library', '-module-name', 'flutter_vless_macos_privacy',
            '-emit-module', '-emit-object', '-whole-module-optimization', '-emit-module-path',
            str(directory / 'flutter_vless_macos_privacy.swiftmodule')] + list(map(str, privacy)) + ['-o', str(directory / 'privacy.o')]),
        ('apple-support-compile', base + ['-parse-as-library', '-I', str(directory), '-module-name', 'flutter_vless_macos_tunnel_support',
            '-emit-module', '-emit-object', '-whole-module-optimization', '-emit-module-path',
            str(directory / 'flutter_vless_macos_tunnel_support.swiftmodule')] + list(map(str, support)) + ['-o', str(directory / 'support.o')]),
        ('apple-preparer-link', base + ['-I', str(directory), str(ROOT / 'tool/fixtures/native_dns_preparer.swift'),
            str(directory / 'privacy.o'), str(directory / 'support.o'), '-o', str(binary)]),
    ]
    return binary, commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-runtime', action='store_true')
    parser.add_argument('--go', default='go')
    arguments = parser.parse_args()
    # This precedes any child process, compilation, evidence or Swift package.
    if arguments.run_runtime and not common.runtime_authorized():
        parser.error('Runtime execution requires CI=true; Darwin also requires GITHUB_ACTIONS=true')
    if EVIDENCE.exists() or EVIDENCE.is_symlink():
        parser.error('build/native_dns_preservation already exists; preserve earlier evidence before a fresh run')
    EVIDENCE.mkdir(parents=True)
    common.EVIDENCE = EVIDENCE
    results = []
    report = {'runtime_requested': arguments.run_runtime, 'core_overlay_applied': False,
              'native_dns_context_overlay_applied': False,
              'go_binary': str(Path(shutil.which(arguments.go) or arguments.go).resolve()), 'results': results}
    environment = child_environment(os.environ)
    core_source = None
    manifest = common.MANIFEST
    try:
        report['source_sha256'] = source_snapshot()
        checked = lambda name, command, seconds=60, cwd=ROOT, env=environment: common.checked(
            name, command, cwd=cwd, environment=env, seconds=seconds, results=results)
        checked('runner-guards', [sys.executable, str(ROOT / 'tool/test_native_dns_preservation_runner.py')], 40)
        checked('environment-case-generator-pure', [arguments.go, 'test',
                str(ROOT / 'tool/generate_core_env_case.go'), str(ROOT / 'tool/generate_core_env_case_test.go')], 30)
        checked('environment-case-generated', [arguments.go, 'run', str(ROOT / 'tool/generate_core_env_case.go'), '-check'], 30)
        exporter = EVIDENCE / ('dns-preparer.exe' if os.name == 'nt' else 'dns-preparer')
        config_test = EVIDENCE / ('config-pure.exe' if os.name == 'nt' else 'config-pure')
        if os.name == 'nt':
            batch = EVIDENCE / 'compile-preparers.cmd'
            batch.write_text(msvc_script(exporter, config_test, environment), encoding='utf-8', newline='')
            checked('cpp-compile', ['cmd.exe', '/d', '/c', str(batch)], 120)
        else:
            compiler = shlex.split(environment.get('CXX', 'c++'))
            if not compiler:
                raise RuntimeError('C++ compiler is missing')
            for name, binary in [('desktop_security_test.cpp', exporter), ('xray_config_test.cpp', config_test)]:
                checked(binary.stem + '-compile', compiler + ['-std=c++17', '-Wall', '-Wextra', '-Werror', str(WINDOWS / name), '-o', str(binary)], 120)
        checked('desktop-dns-pure', [str(exporter)], 30)
        checked('config-pure', [str(config_test)], 30)
        runtime_environment = dict(environment, NATIVE_DNS_PREPARER=str(exporter.resolve()))
        report['native_preparer_sha256'] = digest(exporter)
        if platform.system() == 'Darwin':
            apple, commands = apple_commands(EVIDENCE)
            for name, command in commands:
                checked(name, command, 180)
            runtime_environment['NATIVE_DNS_PREPARER_APPLE'] = str(apple.resolve())
            report['apple_preparer_sha256'] = digest(apple)
        checked('core-pin', [arguments.go, 'list', '-m', '-json', manifest['module']], 60, MOBILE)
        metadata = json.loads((EVIDENCE / 'core-pin.log').read_text(encoding='utf-8'))
        if metadata.get('Version') != manifest['module_version'] or metadata.get('Sum') != manifest['module_sum']:
            raise RuntimeError('Ordinary Core module pin/checksum mismatch')
        core_source = Path(metadata['Dir']).resolve()
        report['core_module_version'] = metadata['Version']
        report['core_module_sum'] = metadata['Sum']
        if any(digest(core_source / path) != expected for path, expected in manifest['upstream_sha256'].items()):
            raise RuntimeError('Ordinary Core source cache does not match pin')
        module_flags = []
        if arguments.run_runtime:
            classic_core = EVIDENCE / 'ClassicCore'
            report['classic_lifetime_patch'] = prepare_classic_core(core_source, classic_core, manifest)
            report['core_overlay_applied'] = True
            modfile = EVIDENCE / 'classic-lifetime.mod'
            shutil.copyfile(MOBILE / 'go.mod', modfile)
            shutil.copyfile(MOBILE / 'go.sum', modfile.with_suffix('.sum'))
            checked('classic-lifetime-modfile', [arguments.go, 'mod', 'edit', '-modfile=' + str(modfile),
                    '-replace=' + manifest['module'] + '=' + str(classic_core)], 30, MOBILE)
            module_flags = ['-modfile=' + str(modfile)]
        binary = EVIDENCE / ('acceptance.test.exe' if os.name == 'nt' else 'acceptance.test')
        checked('acceptance-compile', [arguments.go, 'test', *module_flags, '-c', '-o', str(binary), './native_dns_preservation'], 300, MOBILE)
        report['acceptance_sha256'] = digest(binary)
        # Decode/build, file-only preparers, a static-host matcher and an inert
        # selector manager: no Core instance, listener, resolver or engine.
        pure_tests = [PROTOCOL_TEST, 'TestProtocolCorpusBuilds', MATERIAL_TEST, 'TestNativeSelectorPrefixAllocation',
                      'TestNativeCertificatePaths', 'TestNativeRoutingContextTailCatchall',
                      'TestNativeRoutingContextLoopbackDNS', 'TestNativeRoutingContextCandidate',
                      'TestRoutingAttrsBuilds', 'TestNativeRoutingAttrsPreservation', 'TestPortEnvironmentAliases',
                      'TestSchemaFieldsPreparation', 'TestOpaqueFieldsPreparation']
        checked('protocol-preparation-pure', [str(binary), '-test.run', '^(' + '|'.join(pure_tests) + ')$',
                '-test.v', '-test.timeout=60s'], 75, MOBILE, runtime_environment)
        output = (EVIDENCE / 'protocol-preparation-pure.log').read_text(encoding='utf-8')
        for name in pure_tests:
            common.require_selected_test_pass(output, name)
        results[-1]['selected_test_pass'] = True
        results[-1]['selected_tests'] = pure_tests
        if arguments.run_runtime:
            checked('actual-core-dns', [str(binary), '-test.run', '^' + SELECTED_TEST + '$', '-test.v', '-test.timeout=120s'],
                    140, MOBILE, runtime_environment)
            output = (EVIDENCE / 'actual-core-dns.log').read_text(encoding='utf-8')
            common.require_selected_test_pass(output, SELECTED_TEST)
            preparers = 1 + bool(runtime_environment.get('NATIVE_DNS_PREPARER_APPLE'))
            require_transport_data_runtime(output, preparers)
            require_inactive_tls_runtime(output, preparers)
            require_ipv6_dns_runtime(output, preparers)
            require_ipv4_dns_runtime(output, preparers)
            results[-1]['selected_test_pass'] = True
            results[-1]['selected_tests'] = [SELECTED_TEST]
            results[-1]['transport_data_runtime_modes_per_preparer'] = 2
            results[-1]['transport_data_runtime_preparers'] = preparers
            results[-1]['independent_download_runtime_modes_per_preparer'] = 1
            results[-1]['inactive_tls_runtime_modes_per_preparer'] = 3
            results[-1]['ipv6_dns_runtime_modes_per_preparer'] = 4
            results[-1]['ipv4_dns_lifetime_modes_per_preparer'] = 2
        if source_snapshot() != report['source_sha256']:
            raise RuntimeError('Production preparer/acceptance source changed during verification')
        report['source_snapshot_unchanged'] = True
        report['success'] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['success'] = False
        report['error'] = str(error)
        print('Native DNS preservation check failed: ' + str(error), file=sys.stderr)
    finally:
        if core_source is not None:
            try:
                report['module_cache_targeted_sources_unchanged'] = all(
                    digest(core_source / path) == expected for path, expected in manifest['upstream_sha256'].items())
            except OSError:
                report['module_cache_targeted_sources_unchanged'] = False
            if not report['module_cache_targeted_sources_unchanged']:
                report['success'] = False
                report['error'] = 'Ordinary Core source cache changed during verification'
        (EVIDENCE / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0 if report.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
