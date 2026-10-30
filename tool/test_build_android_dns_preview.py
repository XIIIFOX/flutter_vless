"""Inert producer controls: mock every command; never compile or run Core."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import build_android_dns_preview as builder


class AndroidDNSProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.capability = self.root/'third_party/xray-native-dns'
        (self.capability/'overlay/main').mkdir(parents=True)
        (self.capability/'overlay/main/fixture.go').write_text('package main\n')
        for name in ('classic_lifetime_patch.py', 'h3_lifetime_patch.py', 'darwin_interface_bind_patch.py'):
            (self.capability/name).write_text('inert patch input\n')
        self.protection = self.root/'packages/flutter_vless_android/android/xray-protect'
        self.protection.mkdir(parents=True)
        for name in ('apply.py', 'protect.go', 'main_android.go'):
            (self.protection/name).write_text('inert protection input\n')
        self.cache = self.root/'cache/Core'; self.cache.mkdir(parents=True)
        (self.cache/'go.mod').write_text('module fixture.core\n')
        self.h3_relative = 'transport/internet/splithttp/dialer.go'
        h3 = self.cache/self.h3_relative; h3.parent.mkdir(parents=True)
        h3.write_text('synthetic H3 source before mock compiler\n')
        self.manifest = {'module': 'fixture.core', 'module_version': 'v1.0.0', 'module_sum': 'h1:fixture=',
                         'core_commit': 'fixture-commit', 'upstream_sha256': {'go.mod': hashlib.sha256((self.cache/'go.mod').read_bytes()).hexdigest()}}
        (self.capability/'pin-manifest.json').write_text(json.dumps(self.manifest))
        (self.capability/'apply.py').write_text('''from pathlib import Path
import shutil
def module_cache_paths(go): return []
def validate_destination(source,output,caches):
 if output.exists(): raise ValueError('Existing output')
def copy_and_apply(source,destination,**kwargs):
 shutil.copytree(source,destination)
 for path in (Path(__file__).parent/'overlay').rglob('*.go'):
  target=destination/path.relative_to(Path(__file__).parent/'overlay')
  target.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(path,target)
 return destination
''')
        self.ndk = self.root/'ndk'
        compiler = self.ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin'
        compiler.mkdir(parents=True)
        for suffix in ('-clang', '-clang++'):
            (compiler/('x86_64-linux-android23'+suffix)).write_text('inert compiler marker')
        self.go = self.root/'go'; self.go.write_text('inert Go marker; not executable')
        self.output = self.root/'output'
        self.calls = []
        self.mutate = None
        self.fail_compile = False

    def owned(self, command, **options):
        self.calls.append((command, options))
        if command[1:3] == ['mod', 'download']:
            return json.dumps(dict(Path=self.manifest['module'], Version=self.manifest['module_version'],
                                   Sum=self.manifest['module_sum'], Dir=str(self.cache)))
        if command[1] == str(self.protection/'apply.py'):
            core = Path(command[2])
            for name, target in (('protect.go', 'common/androidprotect/protect.go'),
                                 ('main_android.go', 'main/flutter_vless_protect_android.go')):
                path = core/target; path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.protection/name, path)
            return ''
        self.assertEqual(command[1], 'build')
        Path(command[command.index('-o')+1]).write_bytes(b'inert ELF marker; never executed')
        if self.mutate:
            self.mutate()
        if self.fail_compile:
            raise RuntimeError('synthetic compiler failure')
        return ''

    def run_builder(self):
        args = ['builder', '--output', str(self.output), '--ndk', str(self.ndk), '--go', str(self.go)]
        with patch.object(builder, 'ROOT', self.root), patch.object(builder, 'CAPABILITY', self.capability), \
                patch.object(builder, 'PROTECTION', self.protection), patch.object(builder.platform, 'system', return_value='Linux'), \
                patch.object(builder, 'owned', side_effect=self.owned), patch.object(builder.os.sys, 'argv', args):
            return builder.main()

    def receipt(self):
        return json.loads((self.output/'result.json').read_text())

    def test_built_preview_binds_auto_discovered_h3_patch_and_applied_scope(self):
        self.assertEqual(self.run_builder(), 0)
        result = self.receipt()
        key = 'third_party/xray-native-dns/h3_lifetime_patch.py'
        self.assertTrue(result['success'])
        self.assertIs(result['h3_lifetime_applied'], True)
        self.assertIs(result['darwin_interface_binding_source_applied'],True)
        self.assertEqual(result['darwin_interface_binding_patch_sha256'],result['input_sha256']['third_party/xray-native-dns/darwin_interface_bind_patch.py'])
        self.assertIs(result['classic_dns_lifetime_applied'], True)
        self.assertEqual(result['lifetime_patch_scope'], ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'])
        self.assertEqual(result['h3_lifetime_patch_sha256'], result['input_sha256'][key])
        self.assertIs(result['runtime_executed'], False)
        self.assertIs(result['published'], False)
        self.assertIs(result['copied_h3_source_unchanged'], True)
        self.assertEqual(result['copied_h3_sha256'], hashlib.sha256((self.cache/self.h3_relative).read_bytes()).hexdigest())
        self.assertEqual(len(self.calls), 3)

    def test_copied_h3_mutation_refuses_success_and_is_recorded_on_compile_failure(self):
        for failed_compile in (False, True):
            with self.subTest(failed_compile=failed_compile):
                self.output = self.root/('failed-compile' if failed_compile else 'successful-compile')
                self.fail_compile = failed_compile
                self.mutate = lambda: (self.output/'Core'/self.h3_relative).write_text('copied H3 changed during mock compile')
                error = 'synthetic compiler failure' if failed_compile else 'Copied H3 source changed'
                with self.assertRaisesRegex(RuntimeError, error):
                    self.run_builder()
                self.assertIs(self.receipt()['success'], False)
                self.assertIs(self.receipt()['copied_h3_source_unchanged'], False)

    def test_changed_h3_input_cannot_produce_success_receipt(self):
        self.mutate = lambda: (self.capability/'h3_lifetime_patch.py').write_text('changed during mock compile')
        with self.assertRaisesRegex(RuntimeError, 'input snapshot changed'):
            self.run_builder()
        self.assertIs(self.receipt()['success'], False)
        self.assertIs(self.receipt()['source_snapshot_unchanged'], False)

    def test_failed_copy_never_claims_h3_applied_or_compiles(self):
        path = self.capability/'apply.py'
        path.write_text(path.read_text().replace(' shutil.copytree(source,destination)', " raise RuntimeError('synthetic copy failure')"))
        with self.assertRaisesRegex(RuntimeError, 'synthetic copy failure'):
            self.run_builder()
        self.assertIs(self.receipt()['success'], False)
        self.assertNotIn('h3_lifetime_applied', self.receipt())
        self.assertEqual(len(self.calls), 1)


if __name__ == '__main__':
    unittest.main()
