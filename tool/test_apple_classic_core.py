#!/usr/bin/env python3
"""File/mock producer checks only; never invokes Go, SDKs, Core or sockets."""
from pathlib import Path
import importlib.util
import hashlib
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_apple_classic_core', ROOT / 'tool/prepare_apple_classic_core.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class AppleClassicProducerTests(unittest.TestCase):
    def require_hook(self, relative):
        source = (ROOT / relative).read_text()
        hook = source.index('prepare_apple_classic_core.py') if 'prepare_apple_classic_core.py' in source else -1
        self.assertGreater(hook, 0, 'ordinary producer must prepare the Classic-only Core')
        self.assertLess(source.index('go get "github.com/xtls/xray-core@$XRAY_CORE_REF"'), hook)
        self.assertLess(hook, source.index('go mod tidy'))
        self.assertIn('--mobile "$PWD"', source)
        self.assertIn('--destination "$PWD/../Core-classic"', source)

    def test_legacy_ios_requires_classic_after_pin(self):
        self.require_hook('ios/build_xray_ios.sh')

    def test_legacy_macos_requires_classic_after_pin(self):
        self.require_hook('packages/flutter_vless_macos/macos/build_xray_macos.sh')


class AppleClassicPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.mobile, self.source, self.destination = self.base / 'mobile', self.base / 'cache/Core', self.base / 'Core'
        self.mobile.mkdir()
        (self.mobile / 'go.mod').write_text('synthetic copied module\n')
        for relative in helper.UPSTREAM:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original ' + relative)
        self.pin = {'module': 'synthetic.invalid/core', 'module_version': 'v1.0.0', 'module_sum': 'h1:synthetic',
                    'upstream_sha256': {name: helper.digest(self.source / name) for name in helper.UPSTREAM}}
        self.selected = {'Path': self.pin['module'], 'Version': self.pin['module_version']}
        self.downloaded = {'Path': self.pin['module'], 'Version': self.pin['module_version'],
                           'Sum': self.pin['module_sum'], 'Dir': str(self.source)}
        self.calls, self.copies, self.edits = [], [], []
        self.lose_replacement = False
        self.mutate_cache = False
        self.inputs = [ROOT / 'third_party/xray-native-dns/overlay/app/dns' / name for name in helper.HELPERS]
        copier = SimpleNamespace(copy_and_apply_classic=self.copy, classic_input_paths=lambda: self.inputs)
        patches = mock.patch.multiple(helper, manifest=lambda: self.pin, applier=lambda: copier,
                                      metadata=self.metadata, run=self.run_go, reference_hashes=self.reference)
        patches.start()
        self.addCleanup(patches.stop)

    def reference(self, source, parent):
        return {relative: hashlib.sha256(('patched ' + relative).encode()).hexdigest()
                for relative in helper.UPSTREAM}

    def make_copy(self, destination):
        shutil.copytree(self.source, destination)
        for relative in helper.UPSTREAM:
            (destination / relative).write_text('patched ' + relative)
        for name in helper.HELPERS:
            shutil.copyfile(ROOT / 'third_party/xray-native-dns/overlay/app/dns' / name,
                            destination / 'app/dns' / name)

    def copy(self, source, destination, **kwargs):
        self.copies.append((source, destination, kwargs))
        self.make_copy(destination)
        if self.mutate_cache:
            (source / helper.UPSTREAM[0]).write_text('unexpected mutation')
        return destination

    def metadata(self, go, arguments, mobile, timeout=60):
        self.calls.append((go, arguments, mobile, timeout))
        if arguments[:2] == ['list', '-m']:
            result = dict(self.selected)
            if self.lose_replacement and self.edits:
                result.pop('Replace', None)
            return result
        if arguments[:2] == ['mod', 'download']:
            return dict(self.downloaded)
        self.fail('unexpected Go metadata command')

    def run_go(self, go, arguments, mobile, timeout):
        if arguments == ['env', 'GOMODCACHE']:
            return str(self.source.parent)
        if arguments[:2] == ['mod', 'edit']:
            self.edits.append(arguments)
            self.selected['Replace'] = {'Dir': str(self.destination)}
            return ''
        self.fail('unexpected Go command')

    def prepare(self):
        return helper.prepare(self.mobile, self.destination, 'inert-go')

    def existing(self):
        self.make_copy(self.destination)
        self.selected['Replace'] = {'Dir': str(self.destination)}

    def test_new_copy_uses_only_checked_classic_copier(self):
        before = helper.tree(self.source)
        report = self.prepare()
        self.assertEqual(report['mode'], 'new-classic-copy')
        self.assertEqual(len(self.copies), 1)
        self.assertEqual(self.copies[0][2], {'go': 'inert-go'})
        self.assertEqual(len(self.edits), 1)
        self.assertEqual(before, helper.tree(self.source))
        self.assertFalse(report['runtime_executed'])
        self.assertEqual(report['source_sha256'].get('third_party/xray-vpn-routing/pin-manifest.json'),
                         helper.digest(ROOT / 'third_party/xray-vpn-routing/pin-manifest.json'))
        self.assertTrue((self.base / 'classic-core-inputs.json').is_file())

    def test_existing_routing_replacement_is_validated_and_preserved(self):
        self.existing()
        (self.destination / 'routing-owner.go').write_text('existing routing semantics')
        before = helper.tree(self.destination)
        report = self.prepare()
        self.assertEqual(report['mode'], 'validated-existing-replacement')
        self.assertEqual(self.copies, [])
        self.assertEqual(self.edits, [])
        self.assertEqual(before, helper.tree(self.destination))

    def test_unpinned_selected_version_refused_before_copy(self):
        self.selected['Version'] = 'v999.0.0'
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(self.copies, [])
        self.assertEqual(self.edits, [])

    def test_download_checksum_refused_before_copy(self):
        self.downloaded['Sum'] = 'wrong'
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(self.copies, [])

    def test_existing_unpatched_core_refused_without_mutation(self):
        self.existing()
        (self.destination / helper.UPSTREAM[0]).write_text('old unpatched Close')
        before = helper.tree(self.destination)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(before, helper.tree(self.destination))
        self.assertEqual(self.edits, [])

    def test_existing_helper_mismatch_refused(self):
        self.existing()
        (self.destination / 'app/dns' / helper.HELPERS[0]).write_text('wrong helper')
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(self.edits, [])

    def test_existing_cache_replacement_refused(self):
        self.selected['Replace'] = {'Dir': str(self.source)}
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(self.copies, [])

    def test_cache_mutation_cannot_produce_success(self):
        self.mutate_cache = True
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse((self.base / 'classic-core-inputs.json').exists())

    def test_lost_final_replacement_cannot_produce_success(self):
        self.lose_replacement = True
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse((self.base / 'classic-core-inputs.json').exists())

    def test_tracked_mobile_module_is_refused(self):
        with self.assertRaises(ValueError):
            helper.prepare(ROOT / 'third_party/xray-mobile', self.destination, 'inert-go')
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
