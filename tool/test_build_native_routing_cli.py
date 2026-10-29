#!/usr/bin/env python3
"""File-only tool mocks for the optional desktop routing CLI builder."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_routing_builder_subject', ROOT / 'tool/build_native_routing_cli.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class RoutingCLIBuilderTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.mobile = self.root / 'mobile'; self.mobile.mkdir()
        self.capability = self.root / 'capability'; self.capability.mkdir()
        self.cache = self.root / 'cache'; self.cache.mkdir()
        self.core = self.cache / 'core'; self.core.mkdir()
        self.go = self.root / 'go'; self.go.write_text('inert tool; never executed')
        self.output = self.root / 'build with spaces'
        self.version = 'v1.260327.1-0.20261029083850-0afec66085a8'
        self.module = 'github.com/xtls/xray-core'
        self.checksum = 'h1:synthetic-reviewed-sum='
        (self.mobile / 'go.mod').write_text('module ' + builder.cli.MODULE + '\ngo 1.27\nrequire ' + self.module + ' ' + self.version + '\n')
        (self.mobile / 'go.sum').write_text(self.module + ' ' + self.version + ' ' + self.checksum + '\n')
        (self.mobile / 'factory.go').write_text('package XRay\n')
        (self.mobile / 'nativecli').mkdir()
        (self.mobile / 'nativecli/cli.go').write_text('package nativecli\n')
        (self.core / 'go.mod').write_text('module ' + self.module + '\ngo 1.27\n')
        (self.core / 'fixture.go').write_text('package core\n')
        (self.capability / 'overlay/main').mkdir(parents=True)
        (self.capability / 'overlay/main/native_routing_cli.go').write_text('package main\n')
        (self.capability / 'apply.py').write_text('from pathlib import Path\nimport shutil\ndef copy_and_apply(source,destination,**kwargs):\n shutil.copytree(source,destination)\n overlay=Path(__file__).parent/"overlay"\n for path in overlay.rglob("*.go"):\n  target=Path(destination)/path.relative_to(overlay)\n  target.parent.mkdir(parents=True,exist_ok=True)\n  shutil.copyfile(path,target)\n return Path(destination)\n')
        self.manifest = {'module': self.module, 'module_version': self.version, 'module_sum': self.checksum,
                         'core_commit': '0afec66085a85191e9dd2a4a6646c7c9a94688d1', 'capability': 'native-vpn-routing-source-preview-v1',
                         'upstream_sha256': {name: hashlib.sha256((self.core / name).read_bytes()).hexdigest() for name in ('go.mod', 'fixture.go')}}
        (self.capability / 'pin-manifest.json').write_text(json.dumps(self.manifest))
        self.calls = []
        self.metadata_sum = self.checksum
        self.mutate = None
        self.fail_compile = False

    def fake_checked(self, name, command, **kwargs):
        self.calls.append((name, list(command), Path(kwargs['cwd']), dict(kwargs['environment'])))
        self.assertEqual(str(self.go.resolve()), command[0], 'Builder executed a non-Go binary')
        args = command[1:]
        text = ''
        if args[0] == 'env':
            text = json.dumps({'GOHOSTOS': 'darwin', 'GOHOSTARCH': 'arm64', 'GOVERSION': 'go1.27.0', 'GOMODCACHE': str(self.cache)})
        elif args[:2] == ['mod', 'download']:
            text = json.dumps({'Path': self.module, 'Version': self.version, 'Sum': self.metadata_sum, 'Dir': str(self.core)})
        elif args[:2] == ['mod', 'edit']:
            path = Path(kwargs['cwd']) / 'go.mod'
            with path.open('a') as file:
                for arg in args[2:]:
                    if arg.startswith('-replace='):
                        module, directory = arg.removeprefix('-replace=').split('=', 1)
                        file.write('\nreplace ' + module + ' => ' + directory + '\n')
                    elif arg.startswith('-require='):
                        module, version = arg.removeprefix('-require=').split('@')
                        file.write('\nrequire ' + module + ' ' + version + '\n')
                    else:
                        self.fail('Unexpected module edit')
        elif args[0] == 'list':
            if '-m' in args:
                module = args[-1]
                version = 'v0.0.0' if module == builder.cli.MODULE else self.version
                lines = (Path(kwargs['cwd']) / 'go.mod').read_text().splitlines()
                directory = next(line.split(' => ', 1)[1] for line in lines if line.startswith('replace ' + module + ' => '))
                text = json.dumps({'Path': module, 'Version': version, 'Replace': {'Dir': directory}})
            else:
                self.assertIn('-mod=readonly', args)
                text = self.module + '/main\n'
        elif args[0] == 'build':
            artifact = Path(args[args.index('-o') + 1])
            artifact.write_bytes(b'inert mock executable; never run')
            if self.mutate:
                self.mutate(artifact)
        else:
            self.fail('Unexpected compiler command: ' + repr(args))
        log = builder.cli.EVIDENCE / (name + '.log')
        log.write_text(text)
        failed = self.fail_compile and args[0] == 'build'
        kwargs['results'].append({'name': name, 'exit_code': int(failed), 'process_exit_code': int(failed), 'timed_out': False, 'output_closed': True, 'output_eof': True, 'output_errors': []})
        if failed:
            raise RuntimeError('synthetic compiler failure')

    def run_builder(self, extra=()):
        with patch.object(builder, 'MOBILE', self.mobile), patch.object(builder, 'CAPABILITY', self.capability), patch.object(builder.core_runner, 'checked', side_effect=self.fake_checked):
            return builder.main(['--output', str(self.output), '--go', str(self.go), *extra])

    def report(self):
        return json.loads((self.output / 'result.json').read_text())

    def test_default_build_fixed_tags_and_immutable_inputs(self):
        old_core, old_mobile = (self.core / 'go.mod').read_bytes(), (self.mobile / 'go.mod').read_bytes()
        self.assertEqual(self.run_builder(), 0)
        report = self.report()
        self.assertTrue(report['success'])
        self.assertFalse(report['runtime_executed'])
        self.assertFalse(report['published'])
        self.assertEqual(report['routing_capability_expected'], 1)
        self.assertEqual((report['goos'], report['goarch']), ('darwin', 'arm64'))
        self.assertEqual(Path(report['artifact']).name, 'xray')
        self.assertTrue(all(report[key] for key in ('source_snapshot_unchanged', 'module_cache_source_unchanged', 'core_copy_unchanged', 'mobile_copy_unchanged')))
        compile_call = next(call for call in self.calls if call[1][1] == 'build')
        self.assertIn('-trimpath', compile_call[1])
        self.assertIn('-tags=' + builder.TAGS, compile_call[1])
        self.assertEqual(compile_call[3]['CGO_ENABLED'], '0')
        self.assertEqual((self.core / 'go.mod').read_bytes(), old_core)
        self.assertEqual((self.mobile / 'go.mod').read_bytes(), old_mobile)
        self.assertEqual((self.output / 'Mobile/nativecli/cli.go').read_text(), 'package nativecli\n')
        self.assertTrue(all(call[1][1] in ('env', 'mod', 'list', 'build') for call in self.calls))
        self.assertFalse(any('tidy' in call[1] for call in self.calls))

    def test_windows_target_and_filename(self):
        self.assertEqual(self.run_builder(['--goos', 'windows', '--goarch', 'amd64']), 0)
        report = self.report()
        self.assertEqual((report['goos'], report['goarch']), ('windows', 'amd64'))
        self.assertEqual(Path(report['artifact']).name, 'xray.exe')
        self.assertTrue(report['classic_dns_lifetime_applied'])
        self.assertIs(report['h3_lifetime_applied'], True)
        self.assertEqual(report['lifetime_patch_scope'], ['classic_dns', 'xhttp_h3_dial'])
        key = 'third_party/xray-native-dns/h3_lifetime_patch.py'
        self.assertEqual(report['h3_lifetime_patch_sha256'], report['input_sha256'][key])
        self.assertIn('third_party/xray-native-dns/classic_lifetime_patch.py', report['input_sha256'])
        self.assertIn('third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime.go', report['input_sha256'])
        compile_call = next(call for call in self.calls if call[1][1] == 'build')
        self.assertEqual((compile_call[3]['GOOS'], compile_call[3]['GOARCH']), ('windows', 'amd64'))

    def test_unknown_tags_and_invalid_target_fail_before_work(self):
        for extra in (['--tags', 'arbitrary'], ['--goos', 'android'], ['--goarch', 'unqualified']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.run_builder(extra)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_replaced(self):
        self.output.mkdir(); (self.output / 'keep').write_text('previous')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.run_builder()
        self.assertEqual((self.output / 'keep').read_text(), 'previous')
        self.assertEqual(self.calls, [])

    def test_wrong_metadata_checksum_refused_before_copy_or_build(self):
        self.metadata_sum = 'foreign'
        self.assertEqual(self.run_builder(), 1)
        self.assertFalse(self.output.exists())
        self.assertFalse(any(call[1][1] == 'build' for call in self.calls))

    def test_upstream_preimage_mismatch_refused(self):
        (self.core / 'fixture.go').write_text('foreign source\n')
        self.assertEqual(self.run_builder(), 1)
        self.assertFalse(self.output.exists())

    def test_output_inside_module_cache_refused_before_creation(self):
        self.output = self.cache / 'new-output'
        self.assertEqual(self.run_builder(), 1)
        self.assertFalse(self.output.exists())

    def test_source_mutation_during_compile_cannot_have_success_receipt(self):
        self.mutate = lambda _: (self.mobile / 'factory.go').write_text('changed source\n')
        self.assertEqual(self.run_builder(), 1)
        self.assertFalse(self.report()['success'])
        self.assertFalse(self.report()['source_snapshot_unchanged'])

    def test_cache_mutation_during_compile_cannot_have_success_receipt(self):
        self.mutate = lambda _: (self.core / 'fixture.go').write_text('changed cache\n')
        self.assertEqual(self.run_builder(), 1)
        self.assertFalse(self.report()['success'])
        self.assertFalse(self.report()['module_cache_source_unchanged'])

    def test_copied_source_or_module_mutation_during_compile_is_refused(self):
        for relative in ('Core/fixture.go', 'Core/go.mod', 'Mobile/factory.go', 'Mobile/go.mod'):
            with self.subTest(relative=relative):
                self.output = self.root / relative.replace('/', '-')
                self.mutate = lambda _, relative=relative: (self.output / relative).write_text('changed copy\n')
                self.assertEqual(self.run_builder(), 1)
                self.assertFalse(self.report()['success'])

    def test_compile_failure_has_failed_receipt(self):
        self.fail_compile = True
        self.assertEqual(self.run_builder(), 1)
        self.assertFalse(self.report()['success'])

    def test_ambient_flags_cannot_add_tags_or_install_toolchain(self):
        with patch.dict(os.environ, GOFLAGS='-tags=foreign', GOTOOLCHAIN='auto', GOOS='foreign', GOARCH='foreign'):
            self.assertEqual(self.run_builder(), 0)
        for _, _, _, environment in self.calls:
            self.assertEqual(environment['GOTOOLCHAIN'], 'local')
            self.assertEqual(environment['GOWORK'], 'off')
            self.assertEqual(environment['GOFLAGS'], '')


if __name__ == '__main__':
    unittest.main()
