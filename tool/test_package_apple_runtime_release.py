#!/usr/bin/env python3
"""Synthetic files and mocked Git/lipo/nm only; no SDK or Core execution."""
import copy
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

import package_apple_runtime_release as builder


class CanonicalPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.head = 'a'*40
        self.core, self.copied = self.root/'cache/Core', self.root/'work/Core'
        for p in (self.core, self.copied):
            p.mkdir(parents=True); (p/'go.mod').write_text('inert pinned source')
        self.pin = {'module': 'fixture.invalid/core', 'module_version': 'v1.0.0',
                    'module_sum': 'h1:fixture', 'core_commit': 'b'*40}
        self.report = {'module': self.pin['module'], 'version': self.pin['module_version'],
                       'sum': self.pin['module_sum'], 'core_commit': self.pin['core_commit'],
                       'success': True, 'stage': 'post-build-verified', 'h3_lifetime_applied': True,
                       'darwin_interface_binding_source_applied': True, 'module_cache_source_unchanged': True,
                       'core_copy_unchanged': True, 'routing_capability_expected': 1,
                       'darwin_interface_binding_capability_expected': 1, 'runtime_executed': False,
                       'published': False, 'lifetime_patch_scope': ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'],
                       'go_version': 'go1.27.3', 'root_ca_filter_toolchain_minimum': 'go1.27.3',
                       'h2buf_cap_kib': 128, 'core_source': str(self.core), 'replacement': str(self.copied),
                       'module_cache_before_sha256': builder.tree(self.core),
                       'core_copy_sha256': builder.tree(self.copied)}
        names = ['tool/prepare_apple_classic_core.py', 'third_party/xray-vpn-routing/apply.py',
                 'third_party/xray-vpn-routing/pin-manifest.json',
                 'third_party/xray-native-dns/classic_lifetime_patch.py',
                 'third_party/xray-native-dns/h3_lifetime_patch.py',
                 'third_party/xray-native-dns/darwin_interface_bind_patch.py',
                 'third_party/xray-native-dns/pin-manifest.json',
                 'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime.go',
                 'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime_test.go']
        names += ['third_party/xray-native-dns/xdrive_lifetime_patch.py',
                  'third_party/xray-native-dns/geodata_lifetime_patch.py',
                  'third_party/xray-native-dns/overlay/main/native_services_cli.go',
                  'third_party/xray-native-dns/overlay/transport/internet/xdrive/native_lifetime.go',
                           'third_party/xray-native-dns/overlay/transport/internet/native_service_lifetime.go']
        extra = ['ios/build_xray_ios.sh', 'packages/flutter_vless_macos/macos/build_xray_macos.sh',
                 '.github/workflows/apple-runtime-build.yml', 'tool/package_apple_runtime_release.py',
                 'tool/package_apple_core_preview.py', 'third_party/xray-mobile/go.mod',
                 'third_party/xray-mobile/go.sum', 'third_party/xray-mobile/wrapper.go']
        for name in names+extra:
            p=self.root/name; p.parent.mkdir(parents=True, exist_ok=True);p.write_text('source '+name)
        (self.root/'third_party/xray-vpn-routing/pin-manifest.json').write_text(json.dumps(self.pin))
        self.report['source_sha256'] = {name: builder.digest(self.root/name) for name in names}
        self.report.update(xdrive_lifetime_applied=True, geodata_lifetime_applied=True,
                           managed_service_lifetime_capabilities_expected={'xdrive':2,'geodata':1},
                           xdrive_lifetime_patch_sha256=builder.digest(self.root/'third_party/xray-native-dns/xdrive_lifetime_patch.py'),
                           geodata_lifetime_patch_sha256=builder.digest(self.root/'third_party/xray-native-dns/geodata_lifetime_patch.py'))
        self.receipt = self.root/'producer.json'
        self.bad_symbol = None

    def framework(self, platform):
        path = self.root/(platform+'-XRay.xcframework');path.mkdir()
        libraries=[]
        variants=[('ios-arm64', ['arm64'], None), ('ios-arm64_x86_64-simulator', ['arm64','x86_64'], 'simulator')] \
            if platform=='ios' else [('macos-arm64_x86_64',['arm64','x86_64'],None)]
        for identifier,arches,variant in variants:
            library={'LibraryIdentifier':identifier,'SupportedPlatform':platform,
                     'SupportedArchitectures':arches,'LibraryPath':'XRay.framework' if platform=='ios' else 'libXRay.a'}
            if variant:library['SupportedPlatformVariant']=variant
            if platform=='macos':library['HeadersPath']='Headers'
            binary=path/identifier/library['LibraryPath']
            if platform=='ios':binary=binary/'XRay'
            binary.parent.mkdir(parents=True);binary.write_bytes(b'inert fixture archive')
            header=binary.parent/'Headers/XRay.objc.h' if platform=='ios' else path/identifier/'Headers/XRay.objc.h'
            header.parent.mkdir();header.write_text('\n'.join('int '+name+'(void);' for name in builder.EXPORTS))
            libraries.append(library)
        (path/'Info.plist').write_bytes(plistlib.dumps({'AvailableLibraries':libraries}))
        return path

    def output(self, command, root):
        if command==['git','rev-parse','HEAD']:return self.head+'\n'
        if command[:3]==['xcrun','lipo','-archs']:
            return 'arm64\n' if '/ios-arm64/' in command[-1] else 'arm64 x86_64\n'
        if command[:2]==['xcrun','nm']:
            return '\n'.join('---------------- (LTO,CODE) external _'+name for name in builder.EXPORTS if name!=self.bad_symbol)
        self.fail('Unexpected real-tool boundary')

    def run_package(self, platform, framework):
        self.receipt.write_text(json.dumps(self.report))
        def bind(repository, head, sources):
            self.assertEqual(head,self.head)
            for name,checksum in sources.items():self.assertEqual(builder.digest(repository/name),checksum)
        with patch.object(builder,'output',side_effect=self.output),patch.object(builder,'git_bindings',side_effect=bind):
            return builder.package(platform,framework,self.receipt,self.root/('packed-'+platform),self.head,self.root)

    def test_both_layouts_archive_exact_files_and_preserve_six_strong_exports(self):
        for platform in ('ios','macos'):
            with self.subTest(platform=platform):
                result=self.run_package(platform,self.framework(platform))
                self.assertFalse(result['published'])
                self.assertEqual(result['go_version'],'go1.27.3')
                self.assertEqual(len(result['strong_exports']),3 if platform=='ios' else 2)
                self.assertEqual(result['archive_sha256'],builder.digest(self.root/('packed-'+platform)/'XRay.xcframework.zip'))

    def test_old_CA_toolchain_wrong_capability_or_h2buf_refused(self):
        framework=self.framework('ios');original=copy.deepcopy(self.report)
        for key,value in [('go_version','go1.27.2'),('routing_capability_expected',0),
                          ('darwin_interface_binding_capability_expected',True),
                          ('managed_service_lifetime_capabilities_expected',{'xdrive':1,'geodata':1}),
                          ('h2buf_cap_kib',512),('success',False)]:
            self.report=copy.deepcopy(original);self.report[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_package('ios',framework)
        self.assertFalse((self.root/'packed-ios').exists())

    def test_missing_actual_strong_symbol_refused(self):
        self.bad_symbol='XRayDarwinInterfaceBindingCapability'
        with self.assertRaisesRegex(ValueError,'strong ABI missing'):
            self.run_package('ios',self.framework('ios'))

    def test_omitted_producer_source_cannot_be_hidden_in_receipt(self):
        del self.report['source_sha256']['third_party/xray-native-dns/h3_lifetime_patch.py']
        with self.assertRaisesRegex(ValueError,'source set differs'):
            self.run_package('ios',self.framework('ios'))

    def test_changed_copied_Core_or_symlink_framework_refused(self):
        (self.copied/'go.mod').write_text('changed during compiler')
        with self.assertRaisesRegex(ValueError,'source changed'):
            self.run_package('ios',self.framework('ios'))
        (self.copied/'go.mod').write_text('inert pinned source')
        framework=self.framework('macos');(framework/'linked').symlink_to(self.core/'go.mod')
        with self.assertRaisesRegex(ValueError,'links'):
            self.run_package('macos',framework)

    def test_wrong_architecture_metadata_refused(self):
        framework=self.framework('ios');info=plistlib.loads((framework/'Info.plist').read_bytes())
        info['AvailableLibraries'][1]['SupportedArchitectures']=['arm64']
        (framework/'Info.plist').write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(ValueError,'architecture metadata'):
            self.run_package('ios',framework)


if __name__=='__main__':unittest.main()
