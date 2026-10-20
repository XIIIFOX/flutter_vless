#!/usr/bin/env python3
"""File-only patch guards. No Go, Core, native sockets or network execution."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT/'third_party/xray-native-dns/darwin_interface_bind_patch.py'
spec = importlib.util.spec_from_file_location('darwin_bind_patch', ROOT/'third_party/xray-native-dns/darwin_interface_bind_patch.py')
patch = importlib.util.module_from_spec(spec); spec.loader.exec_module(patch)


class DarwinInterfaceBindPatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.path = self.root/patch.PATH
        self.path.parent.mkdir(parents=True)
        self.original = 'unrelated prefix\n'+patch.BEFORE+'\nunrelated suffix\n'
        self.path.write_text(self.original); self.calls=[]

    def replace(self, relative, before, after):
        self.assertEqual(relative, patch.PATH); self.calls.append(relative)
        source=self.path.read_text()
        if source.count(before)!=1: raise ValueError('unique replacement required')
        self.path.write_text(source.replace(before,after))

    def test_binding_precedes_every_ignored_outbound_TCP_option_return(self):
        patch.apply(self.root,self.replace); changed=self.path.read_text()
        function=changed[changed.index('func applyOutboundSocketOptions('):]
        self.assertIn('(err error)',function.split('\n',1)[0])
        self.assertLess(function.index('defer func()'),function.index('if isTCPSocket(network)'))
        self.assertLess(function.index('IPV6_BOUND_IF'),function.index('if isTCPSocket(network)'))
        self.assertLess(function.index('IP_BOUND_IF'),function.index('TCP_FASTOPEN'))
        self.assertEqual(function.count('NewBindError('),3)
        self.assertIn('const DarwinInterfaceBindingCapability = 1',changed)
        self.assertEqual(self.calls,[patch.PATH])

    def test_all_original_option_and_binding_bytes_are_preserved(self):
        original_tcp=patch.BEFORE.split('\n',1)[1].split('\tif config.Interface != "" {',1)[0].strip()
        patch.apply(self.root,self.replace); changed=self.path.read_text()
        self.assertIn(original_tcp,changed)
        self.assertEqual(changed.count('NewBindError(errors.New('),3)
        self.assertTrue(changed.startswith('unrelated prefix\n')); self.assertTrue(changed.endswith('\nunrelated suffix\n'))

    def test_unknown_duplicate_or_changed_boundary_refused_before_write(self):
        for value in ['unknown future implementation',patch.BEFORE+patch.BEFORE,
                      self.original.replace('return err','return altered',1)]:
            self.path.write_text(value)
            with self.assertRaisesRegex(ValueError,'boundary changed'):patch.apply(self.root,self.replace)
            self.assertEqual(self.path.read_text(),value);self.assertEqual(self.calls,[])

    def test_double_application_refused_without_second_change(self):
        patch.apply(self.root,self.replace);before=self.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'boundary changed'):patch.apply(self.root,self.replace)
        self.assertEqual(self.path.read_bytes(),before);self.assertEqual(len(self.calls),1)

    def test_sibling_and_cache_surrogate_remain_unchanged(self):
        sibling=self.path.with_name('system_dialer.go');sibling.write_text('untouched control')
        before=hashlib.sha256(sibling.read_bytes()).hexdigest();patch.apply(self.root,self.replace)
        self.assertEqual(hashlib.sha256(sibling.read_bytes()).hexdigest(),before)

    def test_symlink_or_missing_source_refused(self):
        target=self.path.with_name('external.go');self.path.rename(target);self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError,'real file'):patch.apply(self.root,self.replace)
        self.assertEqual(target.read_text(),self.original)
        self.path.unlink()
        with self.assertRaisesRegex(ValueError,'real file'):patch.apply(self.root,self.replace)
        self.assertEqual(self.calls,[])

    def test_guarded_callback_failure_propagates(self):
        def reject(*args):raise ValueError('owned guard refused')
        with self.assertRaisesRegex(ValueError,'owned guard refused'):patch.apply(self.root,reject)
        self.assertEqual(self.path.read_text(),self.original)



class DarwinBindingCompositionTests(unittest.TestCase):
    def fixture(self):
        import json
        from unittest import mock
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);source=root/'source';native=root/'native';source.mkdir();native.mkdir()
        file=source/patch.PATH;file.parent.mkdir(parents=True);file.write_text(patch.BEFORE)
        (source/'guarded.go').write_text('unchanged routing source')
        (native/'darwin_interface_bind_patch.py').write_bytes(PATCH.read_bytes())
        pins={key:'fixture-'+key for key in ['module','module_version','module_sum','core_commit']}
        manifest={**pins,'upstream_sha256':{patch.PATH:hashlib.sha256(file.read_bytes()).hexdigest()}}
        (native/'pin-manifest.json').write_text(json.dumps(manifest))
        spec=importlib.util.spec_from_file_location('darwin_composition',ROOT/'third_party/xray-vpn-routing/apply.py')
        applier=importlib.util.module_from_spec(spec);spec.loader.exec_module(applier)
        controls=mock.patch.multiple(applier,CLASSIC=native,MANIFEST={**pins,'upstream_sha256':{}},
            patches=lambda:[],apply_classic_lifetime=lambda root:None,validate_h3_lifetime_source=lambda root:None,
            apply_h3_lifetime=lambda root:None)
        controls.start();self.addCleanup(controls.stop)
        return root,source,native,manifest,applier

    def test_ordinary_and_routing_patch_only_owned_copy_while_classic_only_stays_classic(self):
        root,source,native,manifest,applier=self.fixture();before=(source/patch.PATH).read_bytes()
        for name,copy in [('ordinary',applier.copy_and_apply_lifetimes),('routing',applier.copy_and_apply),('classic',applier.copy_and_apply_classic)]:
            result=copy(source,root/name,caches=[])
            self.assertEqual((result/patch.PATH).read_text(),patch.BEFORE if name=='classic' else patch.AFTER)
        self.assertEqual((source/patch.PATH).read_bytes(),before)

    def test_upstream_or_module_mismatch_refuses_before_destination(self):
        import json
        for kind in ['source','pin']:
            root,source,native,manifest,applier=self.fixture()
            if kind=='source':(source/patch.PATH).write_text('future source')
            else:
                manifest['module_sum']='foreign';(native/'pin-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):applier.copy_and_apply_lifetimes(source,root/'refused',caches=[])
            self.assertFalse((root/'refused').exists())

    def test_copy_rejects_binding_patch_symlink_before_destination(self):
        from unittest import mock
        root,source,native,manifest,applier=self.fixture();candidate=native/'darwin_interface_bind_patch.py'
        original=Path.is_symlink
        with mock.patch.object(Path,'is_symlink',lambda value:value==candidate or original(value)):
            with self.assertRaisesRegex(ValueError,'real files'):applier.copy_and_apply_lifetimes(source,root/'refused',caches=[])
        self.assertFalse((root/'refused').exists())

    def test_patch_callback_cannot_write_other_file(self):
        root,source,native,manifest,applier=self.fixture()
        (native/'darwin_interface_bind_patch.py').write_text("def apply(root,replace):\n replace('guarded.go','unchanged','mutated')\n")
        with self.assertRaisesRegex(ValueError,'unrelated edit'):applier.apply_darwin_interface(source)
        self.assertEqual((source/'guarded.go').read_text(),'unchanged routing source')


class DarwinBindingABIGuards(unittest.TestCase):
    def test_enabled_accessor_requires_actual_core_marker_while_stub_is_zero(self):
        enabled=(ROOT/'third_party/xray-mobile/darwin_interface_binding_enabled.go').read_text()
        disabled=(ROOT/'third_party/xray-mobile/darwin_interface_binding_disabled.go').read_text()
        self.assertIn('//go:build darwin && flutter_vless_darwin_interface_binding',enabled)
        self.assertIn('return int64(internet.DarwinInterfaceBindingCapability)',enabled)
        self.assertNotIn('return 1',enabled)
        self.assertIn('//go:build !darwin || !flutter_vless_darwin_interface_binding',disabled)
        self.assertIn('return 0',disabled)

    def test_old_apple_sdk_missing_symbol_is_weak_zero_and_not_constant_folded(self):
        for folder in ['ios/flutter_vless/Sources/flutter_vless_core_compat',
                       'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_core_compat']:
            source=(ROOT/folder/'FlutterVlessCoreCompat.m').read_text()
            self.assertIn('__attribute__((weak)) int64_t XRayDarwinInterfaceBindingCapability(void) { return 0; }',source)
            self.assertIn('int64_t (*volatile capability)(void) = XRayDarwinInterfaceBindingCapability;',source)
            self.assertIn('FLVlessCoreDarwinInterfaceBindingCapability(void)',(ROOT/folder/'include/FlutterVlessCoreCompat.h').read_text())

if __name__=='__main__':unittest.main()
