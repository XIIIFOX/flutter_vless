#!/usr/bin/env python3
"""Build both additive CLI modes and execute only version/capabilities/Check.

This verifier never selects Core's run/-test or native-routing run commands.
Its prerequisite is an independently verified optional Core source receipt.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys

ROOT = Path(__file__).resolve().parents[1]
MOBILE = ROOT / 'third_party/xray-mobile'
EVIDENCE = ROOT / 'build/native_routing_cli'
MODULE = 'github.com/EbrahimTahernejad/xray-mobile'
CLI_TAG = 'flutter_vless_vpn_routing_cli'
FACTORY_TAG = 'flutter_vless_vpn_routing'
MANAGED_TAG = 'flutter_vless_managed_service_lifetimes'
MAIN_TESTS = ['TestNativeRoutingCLIStockLogger', 'TestNativeRoutingCLIRegisteredOnce',
              'TestNativeRoutingCLIParentInputLifecycle', 'TestNativeRoutingCLIParentInputRefusal',
              'TestNativeRoutingCLIParentInputGrammar', 'TestNativeRoutingCLIParentInputOrdinaryForeground']
NATIVE_TESTS = ['TestNativeCLIGrammarAndCapabilityBeforeRead', 'TestNativeCLICheckAndInputFailures',
                'TestNativeCLIRunOwnsSameBytesAndStop', 'TestNativeCLIRunRefusesBeforeStartAndOwnsCancellation',
                'TestNativeCLIRunWaitsForCancellation']

spec = importlib.util.spec_from_file_location('routing_cli_factory_prerequisite', ROOT / 'tool/test_native_routing_factory.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)
core_runner = factory.core_runner


def inputs():
    result = core_runner.source_snapshot()
    paths = [Path(__file__).resolve(), ROOT / 'tool/test_native_routing_cli_runner.py',
             ROOT / 'tool/test_native_routing_factory.py', MOBILE / 'go.mod', MOBILE / 'go.sum']
    paths += sorted(MOBILE.glob('*.go'))
    lifetime_copier = core_runner.load_module(ROOT / 'third_party/xray-vpn-routing/apply.py', 'cli_lifetime_inputs')
    paths += lifetime_copier.lifetime_input_paths()
    if (MOBILE / 'nativecli').is_symlink():
        raise ValueError('Mobile CLI source symlinks are unsupported')
    paths += [path for path in sorted((MOBILE / 'nativecli').rglob('*')) if path.is_file() or path.is_symlink()]
    if any(path.is_symlink() for path in paths):
        raise ValueError('CLI input symlinks are unsupported')
    result.update({str(path.relative_to(ROOT)).replace(os.sep, '/'): core_runner.digest(path) for path in paths})
    return result


def validate_phase(phase, expected):
    if (phase.get('exit_code') != expected or phase.get('process_exit_code') != expected or
            phase.get('output_closed') is not True or phase.get('output_eof') is not True or
            phase.get('timed_out') is not False or phase.get('output_errors') != []):
        raise ValueError('CLI phase did not reach its expected exit with complete output')


def checked(name, command, *, cwd, environment, seconds, results, expected=0):
    core_runner.EVIDENCE = EVIDENCE
    failure = None
    before = len(results)
    try:
        core_runner.checked(name, command, cwd=cwd, environment=environment, seconds=seconds, results=results)
    except RuntimeError as error:
        failure = error
    if len(results) != before + 1 or results[-1].get('name') != name:
        if failure:
            raise failure
        raise ValueError('CLI phase has no owned-process receipt')
    try:
        validate_phase(results[-1], expected)
    except ValueError:
        if failure:
            raise failure
        raise
    results[-1].update(expected_exit_code=expected, expected_exit_matched=True)


def safe_cli_args(args):
    if args in (['version'], ['native-routing', 'capabilities']):
        return args
    if len(args) == 6 and args[:3] == ['native-routing', 'check', '--config'] and args[4] == '--spec':
        return args
    raise ValueError('Only stock version, native capabilities and native Check may execute')


def require_status(name, expected):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate CLI output field')
            result[key] = value
        return result
    value = json.loads((EVIDENCE / (name + '.log')).read_text(encoding='utf-8'), object_pairs_hook=unique)
    if value != expected:
        raise ValueError('CLI output differs from its fixed status contract')


def copy_inputs(source):
    # The prerequisite remains immutable. Even its already-patched go.mod is
    # never edited: dependency wiring belongs only to these second copies.
    core_runner.tree_snapshot(source)
    if MOBILE.is_symlink() or (MOBILE / 'nativecli').is_symlink():
        raise ValueError('Mobile sources must be real directories')
    files = [MOBILE / 'go.mod', MOBILE / 'go.sum', *sorted(MOBILE.glob('*.go'))]
    if any(path.is_symlink() for path in files):
        raise ValueError('Mobile source symlinks are unsupported')
    core_runner.tree_snapshot(MOBILE / 'nativecli')
    core, mobile = EVIDENCE / 'Core', EVIDENCE / 'Mobile'
    if core.resolve() == source.resolve() or source.resolve() in core.resolve().parents:
        raise ValueError('Disposable Core must be outside the prerequisite source')
    if core.exists() or core.is_symlink() or mobile.exists() or mobile.is_symlink():
        raise ValueError('CLI copied module directories must be new')
    shutil.copytree(source, core)
    mobile.mkdir()
    for path in files:
        shutil.copyfile(path, mobile / path.name)
    shutil.copytree(MOBILE / 'nativecli', mobile / 'nativecli')
    return core, mobile


def non_module_sources(snapshot):
    return {path: digest for path, digest in snapshot.items() if path not in ('go.mod', 'go.sum')}


def tidy_required(text):
    # Do not turn import cycles, missing modules or compiler errors into a
    # general graph-rewrite fallback. Only Go's exact readonly refusal qualifies.
    return text.strip() == 'go: updates to go.mod needed; to update it:\n\tgo mod tidy'


def synthetic_pair():
    config = json.dumps({'log': {'loglevel': 'none'}, 'inbounds': [
        {'tag': 'native-routing-fixture', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
         'settings': {'auth': 'password', 'accounts': [{'user': 'synthetic-native-user', 'pass': 'synthetic-native-password'}], 'udp': True}}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}]}, separators=(',', ':')).encode() + b'\n'
    spec = {'version': 1, 'source_sha256': hashlib.sha256(config).hexdigest(), 'managed_inbound_index': 0,
            'managed_inbound_tag': 'native-routing-fixture', 'auth_user': 'synthetic-native-user'}
    documents = [('config.json', config), ('spec.json', json.dumps(spec).encode())]
    spec['source_sha256'] = '0' * 64
    documents.append(('stale-spec.json', json.dumps(spec).encode()))
    paths = []
    for name, data in documents:
        path = EVIDENCE / name
        with path.open('xb') as file:
            file.write(data)
        path.chmod(0o600)
        paths.append(path)
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--core-evidence', type=Path, default=ROOT / 'build/native_vpn_routing')
    args = parser.parse_args(argv)
    if EVIDENCE.exists() or EVIDENCE.is_symlink():
        parser.error('CLI evidence already exists; retain it and use a fresh directory')
    EVIDENCE.mkdir(parents=True)
    report = {'success': False, 'runtime_requested': False, 'runtime_executed': False, 'published': False, 'results': []}
    before = source = source_before = cache = cache_before = None
    core = mobile = core_initial = mobile_initial = core_ready = mobile_ready = None
    handlers = {}

    def interrupted(number, frame):
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        raise core_runner.Interrupted(number)

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        before = inputs()
        report['source_sha256'] = before
        source, receipt = factory.checked_core(args.core_evidence.resolve())
        source_before = core_runner.tree_snapshot(source)
        report['core_receipt_source_sha256'] = receipt['source_sha256']
        report['core_evidence'] = str(args.core_evidence.resolve())
        report['core_receipt_sha256'] = core_runner.digest(args.core_evidence / 'result.json')
        report['prerequisite_core_tree_sha256'] = factory.tree_hash(source)
        manifest = json.loads((ROOT / 'third_party/xray-vpn-routing/pin-manifest.json').read_text())
        report['core_commit'] = manifest['core_commit']
        metadata = json.loads((args.core_evidence / 'core-pin.log').read_text(encoding='utf-8'))
        cache = core_runner.validate_metadata(manifest, metadata)
        cache_before = core_runner.tree_snapshot(cache)
        if cache_before != receipt['module_source_before_sha256']:
            raise ValueError('Original module cache differs from the verified prerequisite')
        go = str(Path(shutil.which(args.go) or args.go).resolve())
        if not Path(go).is_file():
            raise ValueError('Existing Go toolchain is unavailable')
        report['go_binary'] = go
        environment = core_runner.child_environment(os.environ)
        environment.pop('GOFLAGS', None)
        core, mobile = copy_inputs(source)
        core_initial, mobile_initial = core_runner.tree_snapshot(core), core_runner.tree_snapshot(mobile)

        def run(name, command, *, cwd=core, seconds=120, expected=0):
            checked(name, command, cwd=cwd, environment=environment, seconds=seconds, results=report['results'], expected=expected)

        run('runner-guards', [sys.executable, str(ROOT / 'tool/test_native_routing_cli_runner.py')], cwd=ROOT, seconds=30)
        run('select-copied-mobile', [go, 'mod', 'edit', '-require=' + MODULE + '@v0.0.0', '-replace=' + MODULE + '=' + str(mobile)], seconds=20)
        run('select-copied-core', [go, 'mod', 'edit', '-replace=' + manifest['module'] + '=' + str(core)], cwd=mobile, seconds=20)
        tags = CLI_TAG + ',' + FACTORY_TAG + ',' + MANAGED_TAG

        def graph(name, directory, target):
            command = [go, 'list', '-mod=readonly', '-tags=' + tags, '-deps', target]
            try:
                run(name + '-readonly', command, cwd=directory, seconds=180)
            except RuntimeError:
                text = (EVIDENCE / (name + '-readonly.log')).read_text(encoding='utf-8')
                if not tidy_required(text):
                    raise
                validate_phase(report['results'][-1], 1)
                report['results'][-1].update(module_update_required=True, expected_exit_code=1, expected_exit_matched=True)
                run(name + '-tidy-copy', [go, 'mod', 'tidy'], cwd=directory, seconds=180)
                run(name + '-readonly-final', command, cwd=directory, seconds=180)

        graph('core-graph', core, './main')
        graph('mobile-graph', mobile, './nativecli')
        for name, directory, module, replacement, version in [
            ('verify-mobile-selection', core, MODULE, mobile, 'v0.0.0'),
            ('verify-core-selection', mobile, manifest['module'], core, manifest['module_version']),
        ]:
            run(name, [go, 'list', '-mod=readonly', '-m', '-json', module], cwd=directory, seconds=20)
            selected = json.loads((EVIDENCE / (name + '.log')).read_text(encoding='utf-8'))
            if selected.get('Path') != module or selected.get('Version') != version or Path(selected.get('Replace', {}).get('Dir', '')).resolve() != replacement.resolve():
                raise ValueError('CLI module graph lost its intended local replacement')
        core_ready, mobile_ready = core_runner.tree_snapshot(core), core_runner.tree_snapshot(mobile)
        if non_module_sources(core_ready) != non_module_sources(core_initial) or non_module_sources(mobile_ready) != non_module_sources(mobile_initial):
            raise ValueError('Dependency resolution changed non-module sources')
        report['intended_module_sha256'] = {name: {path: snapshot.get(path) for path in ('go.mod', 'go.sum')}
                                            for name, snapshot in [('core_before', core_initial), ('core_after', core_ready), ('mobile_before', mobile_initial), ('mobile_after', mobile_ready)]}
        report['disposable_source_tree_sha256'] = {name: hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
                                                   for name, snapshot in [('core', core_ready), ('mobile', mobile_ready)]}
        config, spec_path, stale = synthetic_pair()
        suffix = '.exe' if os.name == 'nt' else ''
        for optional in (False, True):
            mode = 'optional' if optional else 'ordinary'
            selected_tags = tags if optional else CLI_TAG + ',' + MANAGED_TAG
            binary = EVIDENCE / (mode + '-xray' + suffix)
            tests = EVIDENCE / (mode + '-main.test' + suffix)
            run(mode + '-build', [go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-tags=' + selected_tags, '-o', str(binary), './main'], seconds=300)
            run(mode + '-main-compile', [go, 'test', '-mod=readonly', '-c', '-tags=' + selected_tags, '-o', str(tests), './main'], seconds=300)
            run(mode + '-main-pure', [str(tests), '-test.run', core_runner.test_pattern(MAIN_TESTS), '-test.v', '-test.timeout=20s'], seconds=30)
            core_runner.require_pass(mode + '-main-pure', MAIN_TESTS, report['results'])
            run(mode + '-version', [str(binary), *safe_cli_args(['version'])], seconds=20)
            if not (EVIDENCE / (mode + '-version.log')).read_text(encoding='utf-8').startswith('Xray 26.10.29'):
                raise ValueError('Stock version does not identify the pinned Core release')
            code, capability = (0, 1) if optional else (32, 0)
            run(mode + '-capabilities', [str(binary), *safe_cli_args(['native-routing', 'capabilities'])], seconds=20, expected=code)
            require_status(mode + '-capabilities', {'stage': 'capabilities', 'code': code, 'capability': capability})
            for label, path, expected in [('check', spec_path, code), ('stale', stale, 17 if optional else 32)]:
                name = mode + '-' + label
                command = safe_cli_args(['native-routing', 'check', '--config', str(config), '--spec', str(path)])
                run(name, [str(binary), *command], seconds=30, expected=expected)
                require_status(name, {'stage': 'check', 'code': expected} if optional else {'stage': 'capabilities', 'code': 32, 'capability': 0})
            report.setdefault('artifacts_sha256', {})[binary.name] = core_runner.digest(binary)
        fake_tests = EVIDENCE / ('nativecli.test' + suffix)
        run('nativecli-compile', [go, 'test', '-mod=readonly', '-c', '-o', str(fake_tests), './nativecli'], cwd=mobile, seconds=300)
        run('nativecli-pure', [str(fake_tests), '-test.run', core_runner.test_pattern(NATIVE_TESTS), '-test.v', '-test.timeout=20s'], cwd=mobile, seconds=30)
        core_runner.require_pass('nativecli-pure', NATIVE_TESTS, report['results'])
        report['success'] = True
    except core_runner.Interrupted as error:
        report.update(error='Interrupted', signal=error.number)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        report['error'] = str(error)
        print('Native routing CLI verification failed: ' + str(error), file=sys.stderr)
    finally:
        checks = [('source_snapshot_unchanged', lambda: inputs() == before, before is not None),
                  ('prerequisite_core_unchanged', lambda: core_runner.tree_snapshot(source) == source_before, source_before is not None),
                  ('module_cache_source_unchanged', lambda: core_runner.tree_snapshot(cache) == cache_before, cache_before is not None),
                  ('core_non_module_sources_unchanged', lambda: non_module_sources(core_runner.tree_snapshot(core)) == non_module_sources(core_initial), core_initial is not None),
                  ('mobile_non_module_sources_unchanged', lambda: non_module_sources(core_runner.tree_snapshot(mobile)) == non_module_sources(mobile_initial), mobile_initial is not None),
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
        (EVIDENCE / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    return 0 if report['success'] else 128 + report['signal'] if 'signal' in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
