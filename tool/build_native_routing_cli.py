#!/usr/bin/env python3
"""Compile an unpublished optional desktop CLI; never execute the binary."""
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
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MOBILE = ROOT / 'third_party/xray-mobile'
CAPABILITY = ROOT / 'third_party/xray-vpn-routing'
spec = importlib.util.spec_from_file_location('desktop_routing_cli_helpers', ROOT / 'tool/test_native_routing_cli.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
core_runner = cli.core_runner
TAGS = cli.CLI_TAG + ',' + cli.FACTORY_TAG


def inputs():
    result = cli.inputs()
    paths = [Path(__file__).resolve(), ROOT / 'tool/test_build_native_routing_cli.py',
             CAPABILITY / 'apply.py', CAPABILITY / 'pin-manifest.json', MOBILE / 'go.mod', MOBILE / 'go.sum']
    paths += sorted((CAPABILITY / 'overlay').rglob('*.go')) + sorted(MOBILE.glob('*.go'))
    if MOBILE.is_symlink() or (MOBILE / 'nativecli').is_symlink():
        raise ValueError('Mobile source symlinks are unsupported')
    paths += [path for path in sorted((MOBILE / 'nativecli').rglob('*')) if path.is_file() or path.is_symlink()]
    for path in paths:
        if path.is_symlink():
            raise ValueError('Builder input symlinks are unsupported')
        key = str(path.relative_to(ROOT)).replace(os.sep, '/') if path.is_relative_to(ROOT) else str(path)
        result[key] = core_runner.digest(path)
    return result


def copy_mobile(destination):
    core_runner.tree_snapshot(MOBILE / 'nativecli')
    files = [MOBILE / 'go.mod', MOBILE / 'go.sum', *sorted(MOBILE.glob('*.go'))]
    if MOBILE.is_symlink() or any(path.is_symlink() for path in files):
        raise ValueError('Mobile source symlinks are unsupported')
    destination.mkdir()
    for path in files:
        shutil.copyfile(path, destination / path.name)
    shutil.copytree(MOBILE / 'nativecli', destination / 'nativecli')


def validate_output(output, source, cache):
    if output.exists() or output.is_symlink():
        raise ValueError('Output directory must be new')
    resolved = output.resolve()
    for parent in (source, cache, MOBILE, CAPABILITY):
        if resolved == parent.resolve() or parent.resolve() in resolved.parents:
            raise ValueError('Build output must be outside source and module cache directories')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New disposable output directory')
    parser.add_argument('--go', default='go', help='Existing Go 1.27+; no toolchain installation')
    parser.add_argument('--goos', choices=('darwin', 'linux', 'windows'))
    parser.add_argument('--goarch', choices=('amd64', 'arm64', '386'))
    args = parser.parse_args(argv)
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('Output directory must be new; previous artifacts are preserved')
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    if not Path(go).is_file():
        parser.error('Existing Go toolchain is unavailable')
    report = {'success': False, 'runtime_executed': False, 'binary_executed': False, 'published': False,
              'production_enabled': False, 'host_qualified': False, 'routing_capability_expected': 1,
              'tags': TAGS, 'go_binary': go, 'results': []}
    before = source = source_before = core = mobile = core_initial = mobile_initial = core_ready = mobile_ready = None
    admitted = False
    stage = None
    handlers = {}

    def interrupted(number, frame):
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        raise core_runner.Interrupted(number)

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        before = inputs()
        report['input_sha256'] = before
        manifest = json.loads((CAPABILITY / 'pin-manifest.json').read_text())
        core_runner.validate_mobile_pin(manifest, (MOBILE / 'go.mod').read_text(), (MOBILE / 'go.sum').read_text())
        report.update(capability=manifest['capability'], core_commit=manifest['core_commit'],
                      core_module=manifest['module'], core_version=manifest['module_version'], module_sum=manifest['module_sum'])
        environment = core_runner.child_environment(os.environ)
        environment.update(GOFLAGS='', GOTOOLCHAIN='local', GOWORK='off')
        for key in ('GOOS', 'GOARCH', 'GOEXPERIMENT', 'GOARM', 'GOARM64', 'GOAMD64', 'GOMIPS', 'GOMIPS64', 'GOPPC64', 'GOWASM'):
            environment.pop(key, None)
        # Metadata is collected before admitting the requested output path. A
        # bad path inside the cache therefore cannot leave logs in that cache.
        stage = tempfile.TemporaryDirectory(prefix='native-routing-build-')
        evidence = Path(stage.name)

        def run(name, command, *, cwd=MOBILE, seconds=120, env=None):
            cli.EVIDENCE = evidence
            cli.checked(name, command, cwd=cwd, environment=environment if env is None else env,
                        seconds=seconds, results=report['results'])

        run('toolchain', [go, 'env', '-json', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH', 'GOMODCACHE'], seconds=20)
        toolchain = json.loads((evidence / 'toolchain.log').read_text(encoding='utf-8'))
        version = re.fullmatch(r'go1\.(\d+)(?:\.\d+)?(?:[a-zA-Z][a-zA-Z0-9.-]*)?', toolchain.get('GOVERSION', ''))
        if version is None or int(version.group(1)) < 27:
            raise ValueError('An installed Go 1.27+ toolchain is required')
        goos, goarch = args.goos or toolchain['GOHOSTOS'], args.goarch or toolchain['GOHOSTARCH']
        if goos not in ('darwin', 'linux', 'windows') or goarch not in ('amd64', 'arm64', '386') or (goos == 'darwin' and goarch == '386'):
            raise ValueError('Unsupported desktop target pair')
        cache = Path(toolchain['GOMODCACHE'])
        if not cache.is_absolute():
            raise ValueError('Go module cache must be absolute')
        report.update(go_version=toolchain['GOVERSION'], goos=goos, goarch=goarch, cgo_enabled=False)
        run('core-pin', [go, 'mod', 'download', '-json', manifest['module'] + '@' + manifest['module_version']], seconds=180)
        metadata = json.loads((evidence / 'core-pin.log').read_text(encoding='utf-8'))
        source = core_runner.validate_metadata(manifest, metadata)
        source_before = core_runner.tree_snapshot(source)
        if any(source_before.get(path) != expected for path, expected in manifest['upstream_sha256'].items()):
            raise ValueError('Pinned source/cache preimage differs from the manifest')
        report['module_source_sha256'] = source_before
        validate_output(output, source, cache)
        output.mkdir(parents=True)
        admitted = True
        for log in evidence.iterdir():
            shutil.copyfile(log, output / log.name)
        evidence = output
        applier = core_runner.load_module(CAPABILITY / 'apply.py', 'desktop_routing_applier')
        core = applier.copy_and_apply(source, output / 'Core', go=go, caches=[cache])
        report['classic_dns_lifetime_applied'] = True
        mobile = output / 'Mobile'
        copy_mobile(mobile)
        core_initial, mobile_initial = core_runner.tree_snapshot(core), core_runner.tree_snapshot(mobile)
        run('select-copied-mobile', [go, 'mod', 'edit', '-require=' + cli.MODULE + '@v0.0.0', '-replace=' + cli.MODULE + '=' + str(mobile)], cwd=core, seconds=20)
        run('select-copied-core', [go, 'mod', 'edit', '-replace=' + manifest['module'] + '=' + str(core)], cwd=mobile, seconds=20)
        build_environment = dict(environment, CGO_ENABLED='0', GOOS=goos, GOARCH=goarch)
        run('readonly-graph', [go, 'list', '-mod=readonly', '-tags=' + TAGS, '-deps', './main'], cwd=core, env=build_environment, seconds=180)
        for name, directory, module, replacement, selected_version in [
            ('verify-mobile-selection', core, cli.MODULE, mobile, 'v0.0.0'),
            ('verify-core-selection', mobile, manifest['module'], core, manifest['module_version']),
        ]:
            run(name, [go, 'list', '-mod=readonly', '-m', '-json', module], cwd=directory, env=build_environment, seconds=20)
            selected = json.loads((output / (name + '.log')).read_text(encoding='utf-8'))
            if selected.get('Path') != module or selected.get('Version') != selected_version or Path(selected.get('Replace', {}).get('Dir', '')).resolve() != replacement.resolve():
                raise ValueError('CLI module graph lost its intended local replacement')
        core_ready, mobile_ready = core_runner.tree_snapshot(core), core_runner.tree_snapshot(mobile)
        if cli.non_module_sources(core_ready) != cli.non_module_sources(core_initial) or cli.non_module_sources(mobile_ready) != cli.non_module_sources(mobile_initial):
            raise ValueError('Module wiring changed non-module source files')
        report['core_copy_sha256'], report['mobile_copy_sha256'] = core_ready, mobile_ready
        report['intended_module_sha256'] = {name: {path: snapshot.get(path) for path in ('go.mod', 'go.sum')}
                                            for name, snapshot in [('core_before', core_initial), ('core_after', core_ready), ('mobile_before', mobile_initial), ('mobile_after', mobile_ready)]}
        artifact = output / ('xray.exe' if goos == 'windows' else 'xray')
        run('cli-build', [go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-tags=' + TAGS,
                          '-ldflags=-s -w -buildid=', '-o', str(artifact), './main'], cwd=core, env=build_environment, seconds=600)
        if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size == 0:
            raise ValueError('Compiler did not produce a regular nonempty artifact')
        report.update(artifact=str(artifact), artifact_sha256=core_runner.digest(artifact), artifact_bytes=artifact.stat().st_size, success=True)
    except core_runner.Interrupted as error:
        report.update(error='Interrupted', signal=error.number)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        report['error'] = str(error)
        print('Native routing CLI build failed: ' + str(error), file=sys.stderr)
    finally:
        checks = [('source_snapshot_unchanged', lambda: inputs() == before, before is not None),
                  ('module_cache_source_unchanged', lambda: core_runner.tree_snapshot(source) == source_before, source_before is not None),
                  ('core_non_module_sources_unchanged', lambda: cli.non_module_sources(core_runner.tree_snapshot(core)) == cli.non_module_sources(core_initial), core_initial is not None),
                  ('mobile_non_module_sources_unchanged', lambda: cli.non_module_sources(core_runner.tree_snapshot(mobile)) == cli.non_module_sources(mobile_initial), mobile_initial is not None),
                  ('core_copy_unchanged', lambda: core_runner.tree_snapshot(core) == core_ready, core_ready is not None),
                  ('mobile_copy_unchanged', lambda: core_runner.tree_snapshot(mobile) == mobile_ready, mobile_ready is not None)]
        for key, check, applicable in checks:
            if applicable:
                try:
                    report[key] = check()
                except (OSError, ValueError):
                    report[key] = False
                if not report[key]:
                    report['success'] = False
                    report.setdefault('error', key + ' failed')
        try:
            if admitted:
                (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        finally:
            if stage is not None:
                stage.cleanup()
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return 0 if report['success'] else 128 + report['signal'] if 'signal' in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
