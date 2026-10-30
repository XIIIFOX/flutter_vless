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
        self.assertGreater(hook, 0, 'ordinary producer must prepare the checked lifetime Core')
        self.assertLess(source.index('go get "github.com/xtls/xray-core@$XRAY_CORE_REF"'), hook)
        self.assertLess(hook, source.index('go mod tidy'))
        self.assertIn('--mobile "$PWD"', source)
        self.assertIn('--destination "$PWD/../Core-classic"', source)
        self.assertIn('--vpn-routing', source)
        self.assertIn('-tags=flutter_vless_vpn_routing,flutter_vless_darwin_interface_binding', source)
        self.assertIn('flutter_vless_managed_service_lifetimes', source)
        self.assertIn('go1.27.3', source)
        self.assertIn('--verify', source)

    def test_legacy_ios_requires_classic_after_pin(self):
        self.require_hook('ios/build_xray_ios.sh')

    def test_legacy_macos_requires_classic_after_pin(self):
        self.require_hook('packages/flutter_vless_macos/macos/build_xray_macos.sh')


class AppleClassicPreparationTests(unittest.TestCase):
    H3 = 'transport/internet/splithttp/dialer.go'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.mobile, self.source, self.destination = self.base / 'mobile', self.base / 'cache/Core', self.base / 'Core'
        self.mobile.mkdir()
        (self.mobile / 'go.mod').write_text('synthetic copied module\n')
        self.upstream = tuple(dict.fromkeys([*helper.UPSTREAM, self.H3]))
        for relative in self.upstream:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original ' + relative)
        self.pin = {'module': 'synthetic.invalid/core', 'module_version': 'v1.0.0', 'module_sum': 'h1:synthetic', 'core_commit': '1'*40,
                    'upstream_sha256': {name: helper.digest(self.source / name) for name in self.upstream}}
        self.selected = {'Path': self.pin['module'], 'Version': self.pin['module_version']}
        self.downloaded = {'Path': self.pin['module'], 'Version': self.pin['module_version'],
                           'Sum': self.pin['module_sum'], 'Dir': str(self.source)}
        self.calls, self.copies, self.edits = [], [], []
        self.lose_replacement = False
        self.mutate_cache = False
        self.go_version = 'go1.27.3'
        self.goroot = self.base / 'private-goroot'
        self.scratch = self.goroot / 'src/net/http/internal/http2/transport.go'
        self.scratch.parent.mkdir(parents=True)
        self.scratch.write_text('const max = 128 << 10 // H2BUF patch (flutter_vless issue #23)\n')
        self.inputs = [ROOT / 'third_party/xray-native-dns/overlay/app/dns' / name for name in helper.HELPERS]
        self.inputs.append(ROOT / 'third_party/xray-native-dns/darwin_interface_bind_patch.py')
        self.inputs.append(ROOT / 'third_party/xray-native-dns/h3_lifetime_patch.py')
        self.managed_helpers = helper.applier().managed_service_helpers()
        self.inputs += [ROOT / 'third_party/xray-native-dns/xdrive_lifetime_patch.py',
                        ROOT / 'third_party/xray-native-dns/geodata_lifetime_patch.py',
                        *self.managed_helpers]
        copier = SimpleNamespace(copy_and_apply=self.copy, copy_and_apply_lifetimes=self.copy, lifetime_input_paths=lambda: self.inputs,
                                 managed_service_helpers=lambda: self.managed_helpers,
                                 copy_and_apply_classic=mock.Mock(side_effect=AssertionError('ordinary producer must include H3')),
                                 classic_input_paths=lambda: self.inputs[:-1])
        patches = mock.patch.multiple(helper, manifest=lambda: self.pin, applier=lambda: copier,
                                      metadata=self.metadata, run=self.run_go, reference_hashes=self.reference)
        patches.start()
        self.addCleanup(patches.stop)

    def reference(self, source, parent, routing=False):
        return {relative: hashlib.sha256(('patched ' + relative).encode()).hexdigest()
                for relative in self.upstream}

    def make_copy(self, destination):
        shutil.copytree(self.source, destination)
        for relative in self.upstream:
            (destination / relative).write_text('patched ' + relative)
        for name in helper.HELPERS:
            shutil.copyfile(ROOT / 'third_party/xray-native-dns/overlay/app/dns' / name,
                            destination / 'app/dns' / name)
        for source in self.managed_helpers:
            target = destination / source.relative_to(ROOT / 'third_party/xray-native-dns/overlay')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

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
        if arguments == ['env', 'GOVERSION']:
            return self.go_version
        if arguments == ['env', 'GOROOT']:
            return str(self.goroot)
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

    def test_existing_managed_helper_mismatch_refused_without_edit(self):
        self.existing()
        relative = 'transport/internet/xdrive/native_lifetime.go'
        (self.destination / relative).write_text('wrong managed-service owner')
        before = helper.tree(self.destination)
        with self.assertRaisesRegex(ValueError, 'managed-service helper'):
            self.prepare()
        self.assertEqual(before, helper.tree(self.destination))
        self.assertEqual(self.edits, [])

    def test_existing_geodata_without_exact_cancellation_patch_refused(self):
        self.existing()
        relative = 'app/geodata/geodata.go'
        (self.destination / relative).write_text('original ' + relative)
        before = helper.tree(self.destination)
        with self.assertRaisesRegex(ValueError, 'exact lifetime patch'):
            self.prepare()
        self.assertEqual(before, helper.tree(self.destination))
        self.assertEqual(self.edits, [])

    def test_new_copy_uses_checked_classic_and_h3_copier(self):
        before = helper.tree(self.source)
        report = self.prepare()
        self.assertEqual(report['mode'], 'new-lifetime-copy')
        self.assertEqual(len(self.copies), 1)
        self.assertEqual(self.copies[0][2], {'go': 'inert-go'})
        self.assertEqual(len(self.edits), 1)
        self.assertEqual(before, helper.tree(self.source))
        self.assertFalse(report['runtime_executed'])
        self.assertTrue(report['h3_lifetime_applied'])
        self.assertTrue(report['darwin_interface_binding_source_applied'])
        self.assertEqual(report['darwin_interface_binding_capability_expected'],1)
        self.assertEqual(report['lifetime_patch_scope'], ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'])
        self.assertEqual(report['h3_lifetime_patch_sha256'], helper.digest(ROOT / 'third_party/xray-native-dns/h3_lifetime_patch.py'))
        self.assertTrue(report['xdrive_lifetime_applied'])
        self.assertTrue(report['geodata_lifetime_applied'])
        self.assertEqual(report['managed_service_lifetime_capabilities_expected'], {'xdrive': 1, 'geodata': 1})
        self.assertIn('no full native-DNS context overlay', report['scope'])
        self.assertEqual(report['stage'], 'pre-build-preparation')
        self.assertEqual(report['source_sha256'].get('third_party/xray-vpn-routing/pin-manifest.json'),
                         helper.digest(ROOT / 'third_party/xray-vpn-routing/pin-manifest.json'))
        self.assertTrue((self.base / 'classic-core-inputs.json').is_file())

    def test_canonical_routing_prepares_exact_new_copy_and_binds_overlay_inputs(self):
        report = helper.prepare(self.mobile, self.destination, 'inert-go', routing=True)
        self.assertEqual(report['routing_capability_expected'], 1)
        self.assertEqual(report['core_commit'], self.pin['core_commit'])
        self.assertEqual(report['module_cache_before_sha256'], helper.tree(self.source))
        self.assertFalse(report['success'])
        self.assertTrue(any(name.startswith('third_party/xray-vpn-routing/overlay/') for name in report['source_sha256']))

    def test_routing_cannot_relabel_existing_ordinary_replacement(self):
        self.existing()
        with self.assertRaisesRegex(ValueError, 'fresh Core copy'):
            helper.prepare(self.mobile, self.destination, 'inert-go', routing=True)
        self.assertEqual(self.edits, [])
        self.assertEqual(self.copies, [])

    def test_postbuild_verifies_actual_copy_toolchain_and_h2buf(self):
        helper.prepare(self.mobile, self.destination, 'inert-go', routing=True)
        report = helper.verify(self.mobile, 'inert-go')
        self.assertTrue(report['success'])
        self.assertEqual(report['go_version'], 'go1.27.3')
        self.assertEqual(report['h2buf_cap_kib'], 128)
        self.assertTrue(report['module_cache_source_unchanged'] and report['core_copy_unchanged'])

    def test_postbuild_old_CA_toolchain_or_wrong_h2buf_cannot_succeed(self):
        helper.prepare(self.mobile, self.destination, 'inert-go', routing=True)
        self.go_version = 'go1.27.2'
        with self.assertRaisesRegex(ValueError, 'root CA filtering'):
            helper.verify(self.mobile, 'inert-go')
        self.go_version = 'go1.27.3'
        self.scratch.write_text('const max = 512 << 10')
        with self.assertRaisesRegex(ValueError, '128 KiB'):
            helper.verify(self.mobile, 'inert-go')

    def test_postbuild_Core_or_cache_mutation_cannot_succeed(self):
        helper.prepare(self.mobile, self.destination, 'inert-go', routing=True)
        for directory in (self.destination, self.source):
            target = directory / self.upstream[0]
            before = target.read_bytes()
            target.write_bytes(before+b' changed during compiler')
            with self.assertRaisesRegex(ValueError, 'changed during build'):
                helper.verify(self.mobile, 'inert-go')
            target.write_bytes(before)

    def test_h3_input_is_attested_in_ordinary_receipt(self):
        report = self.prepare()
        self.assertEqual(report['source_sha256']['third_party/xray-native-dns/h3_lifetime_patch.py'],
                         helper.digest(ROOT / 'third_party/xray-native-dns/h3_lifetime_patch.py'))

    def test_existing_classic_only_replacement_is_refused_before_edit(self):
        self.existing()
        (self.destination / self.H3).write_text('original ' + self.H3)
        before = helper.tree(self.destination)
        with self.assertRaisesRegex(ValueError, 'lifetime patch'):
            self.prepare()
        self.assertEqual(before, helper.tree(self.destination))
        self.assertEqual(self.edits, [])

    def test_existing_h3_patch_requires_exact_not_close_presence(self):
        self.existing()
        (self.destination / self.H3).write_text('different H3 close ordering')
        before = helper.tree(self.destination)
        with self.assertRaisesRegex(ValueError, 'lifetime patch'):
            self.prepare()
        self.assertEqual(before, helper.tree(self.destination))
        self.assertEqual(self.edits, [])

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
