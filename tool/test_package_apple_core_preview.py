"""Synthetic files and command doubles only; never builds or executes an SDK."""
import copy
import hashlib
import io
import json
from pathlib import Path
import plistlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import package_apple_core_preview as subject


class AppleSDKPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.preview, self.destination = self.root/'preview', self.root/'artifact'
        self.head = 'a'*40
        for name in [*subject.PACKAGING_INPUTS, *subject.PRODUCER_INPUTS, 'third_party/xray-mobile/runtime.go']:
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic source ' + name)
        self.pin = {'module': 'fixture.invalid/core', 'module_version': 'v1.0.0',
                    'module_sum': 'h1:fixture=', 'core_commit': 'b'*40}
        (self.root/'third_party/xray-vpn-routing/pin-manifest.json').write_text(json.dumps(self.pin))
        self.core, self.cache, self.mobile = self.root/'core', self.root/'cache', self.preview/'routing/mobile'
        for directory in (self.core, self.cache, self.mobile):
            directory.mkdir(parents=True)
            (directory/'go.mod').write_text('synthetic copied source')
        self.framework = self.preview/'XRay.xcframework'; self.framework.mkdir()
        libraries = []
        for identifier, architectures, variant in [('ios-arm64', ['arm64'], None),
                                                    ('ios-arm64_x86_64-simulator', ['arm64', 'x86_64'], 'simulator')]:
            binary = self.framework/identifier/'XRay.framework/XRay'
            binary.parent.mkdir(parents=True); binary.write_bytes(b'inert archive; never executed')
            header = binary.parent/'Headers/XRay.objc.h'; header.parent.mkdir()
            header.write_text('\n'.join('extern void ' + name + '(void);' for name in subject.EXPORTS))
            library = dict(LibraryIdentifier=identifier, LibraryPath='XRay.framework',
                           SupportedPlatform='ios', SupportedArchitectures=architectures)
            if variant: library['SupportedPlatformVariant'] = variant
            libraries.append(library)
        (self.framework/'Info.plist').write_bytes(plistlib.dumps({'AvailableLibraries': libraries}))
        bindings = {name: subject.digest(self.root/name) for name in [*subject.PRODUCER_INPUTS, 'third_party/xray-mobile/runtime.go']}
        self.producer = dict(success=True, source_unchanged=True, module_cache_source_unchanged=True,
                             copies_unchanged=True, classic_dns_lifetime_applied=True, h3_lifetime_applied=True,
                             xdrive_lifetime_applied=True, geodata_lifetime_applied=True,
                             darwin_interface_binding_source_applied=True, darwin_interface_binding_capability_expected=1,
                             darwin_interface_binding_tag='flutter_vless_darwin_interface_binding',
                             darwin_interface_binding_patch_sha256=bindings[subject.BINDING_PATCH],
                             published=False, runtime_executed=False, routing_capability_expected=1,
                             routing_tag='flutter_vless_vpn_routing', lifetime_patch_scope=['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'],
                             core=self.pin['module_version'], core_module=self.pin['module'], core_sum=self.pin['module_sum'],
                             core_commit=self.pin['core_commit'], source_sha256=bindings,
                             h3_lifetime_patch_sha256=bindings[subject.H3_PATCH], core_source=str(self.cache),
                             core_replacement=str(self.core), module_cache_before_sha256=subject.tree(self.cache),
                             core_copy_sha256=subject.tree(self.core), mobile_copy_sha256=subject.tree(self.mobile))
        self.producer.update(managed_service_lifetime_capabilities_expected={'xdrive':2,'geodata':1},
                             xdrive_lifetime_patch_sha256=bindings[subject.XDRIVE_PATCH],
                             geodata_lifetime_patch_sha256=bindings[subject.GEODATA_PATCH])
        self.summary = dict(platform='ios', core=self.pin['module_version'], preflightABI=1, published=False)
        self.write_receipts()
        self.blobs = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.commands = []
        self.bad_architecture = False
        self.bad_export = None
        self.lto_code = False

    def write_receipts(self):
        (self.preview/'routing-preview.json').write_text(json.dumps(self.producer))
        (self.preview/'preview.json').write_text(json.dumps(self.summary))

    def command(self, command, *, cwd, timeout):
        self.commands.append(command)
        self.assertEqual(cwd, self.root)
        self.assertEqual(timeout, 60)
        if command == ['git', 'rev-parse', 'HEAD']: return self.head.encode()
        if command[:2] == ['git', 'show']:
            head, name = command[2].split(':', 1); self.assertEqual(head, self.head)
            return self.blobs[name]
        if command[:3] == ['xcrun', 'lipo', '-archs']:
            if self.bad_architecture: return b'x86_64'
            return b'arm64 x86_64' if 'simulator' in command[-1] else b'arm64'
        if command[:2] == ['xcrun', 'nm']:
            definition = '---------------- (LTO,CODE)' if self.lto_code else '000000 (__TEXT,__text)'
            lines = [definition + ' external _' + name for name in subject.EXPORTS]
            if self.bad_export == 'weak': lines[0] = lines[0].replace('external', 'weak external')
            elif self.bad_export == 'missing': lines.pop()
            elif self.bad_export == 'duplicate': lines.append(lines[0])
            elif self.bad_export == 'absolute': lines[0] = lines[0].replace('(__TEXT,__text)', '(absolute)')
            elif self.bad_export == 'data': lines[0] = lines[0].replace('(__TEXT,__text)', '(__DATA,__data)')
            elif self.bad_export == 'prefixed': lines[0] = lines[0].replace('_XRayStartPrivate', '_prefix_XRayStartPrivate')
            elif self.bad_export == 'lto-data': lines[0] = lines[0].replace('(__TEXT,__text)', '(LTO,DATA)')
            elif self.bad_export == 'long-data': lines[0] = 'x'*10000 + lines[0].replace('(__TEXT,__text)', '(LTO,DATA)')
            return '\n'.join(lines).encode()
        self.fail('Unexpected actual command: ' + repr(command))

    def package(self):
        with patch.object(subject.subprocess, 'check_output', side_effect=self.command):
            return subject.package(self.preview, self.destination, self.head, self.root)

    def test_complete_dynamic_file_set_and_provenance_without_execution(self):
        result = self.package()
        self.assertTrue(result['success'])
        self.assertEqual(len(result['framework_sha256']), 5)
        self.assertEqual(len(result['strong_exports']), 3)
        self.assertTrue(all(len(exports) == 8 for exports in result['strong_exports'].values()))
        self.assertEqual(result['head'], self.head)
        self.assertFalse(result['runtime_executed'] or result['installed'] or result['published'])
        archive = self.destination/result['archive']
        self.assertEqual(subject.digest(archive), result['archive_sha256'])
        subject.verify_archive(archive, result['members_sha256'])
        self.assertEqual(set(p.name for p in self.destination.iterdir()), {'manifest.json', 'ios-sdk-preview.tar.gz'})
        self.assertFalse(any('go' == command[0] for command in self.commands))

    def test_real_lto_code_definition_shape_is_accepted(self):
        # The immutable verified SDK469 nm logs use this exact definition class
        # for all five function wrappers in each of the three architectures.
        self.lto_code = True
        result = self.package()
        self.assertTrue(result['success'])
        self.assertEqual(len(result['strong_exports']), 3)

    def test_export_refusal_has_bounded_actual_match_and_architecture(self):
        self.bad_export = 'long-data'
        with self.assertRaises(ValueError) as failure:
            self.package()
        message = str(failure.exception)
        self.assertIn('library=ios-arm64 arch=arm64 matches=1', message)
        self.assertIn('(LTO,DATA) external _XRayStartPrivate', message)
        self.assertLess(len(message), 1000)
        self.assertFalse(self.destination.exists())

    def test_missing_false_foreign_scope_pin_or_hash_refused(self):
        original = copy.deepcopy(self.producer)
        for key, value in [('success', False), ('h3_lifetime_applied', 1), ('published', 0),
                           ('runtime_executed', True), ('routing_capability_expected', True),
                           ('core_sum', 'foreign'), ('h3_lifetime_patch_sha256', 'c'*64),
                           ('darwin_interface_binding_source_applied', False),
                           ('darwin_interface_binding_capability_expected', True),
                           ('darwin_interface_binding_patch_sha256', '0'*64),
                           ('managed_service_lifetime_capabilities_expected', {'xdrive': 1, 'geodata': 1}),
                           ('lifetime_patch_scope', ['classic_dns'])]:
            with self.subTest(key=key):
                self.producer = copy.deepcopy(original); self.producer[key] = value; self.write_receipts()
                with self.assertRaises(ValueError): self.package()
                self.assertFalse(self.destination.exists())

    def test_checkout_and_git_blob_source_mutations_refused(self):
        source = self.root/'third_party/xray-mobile/runtime.go'
        original = source.read_bytes(); source.write_bytes(b'changed checkout')
        with self.assertRaisesRegex(ValueError, 'Checkout source'): self.package()
        source.write_bytes(original)
        self.blobs['third_party/xray-mobile/runtime.go'] = b'foreign Git source'
        with self.assertRaisesRegex(ValueError, 'Git source'): self.package()

    def test_omitted_or_unsafe_producer_input_refused(self):
        del self.producer['source_sha256']['third_party/xray-mobile/runtime.go']; self.write_receipts()
        with self.assertRaisesRegex(ValueError, 'input set'): self.package()
        for name in ('../escape', '/absolute', 'a/../escape', 'a\\escape'):
            with self.subTest(name=name), self.assertRaises(ValueError): subject.safe_name(name)

    def test_copied_core_mobile_and_cache_mutations_refused(self):
        for directory in (self.core, self.mobile, self.cache):
            path = directory/'go.mod'; original = path.read_bytes(); path.write_bytes(b'changed copied source')
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, 'source/copy changed'): self.package()
            path.write_bytes(original)

    def test_binary_architecture_and_strong_export_failures_refused(self):
        self.bad_architecture = True
        with self.assertRaisesRegex(ValueError, 'binary architectures'): self.package()
        self.bad_architecture = False
        for defect in ('weak', 'missing', 'duplicate', 'absolute', 'data', 'prefixed', 'lto-data'):
            self.bad_export = defect
            with self.subTest(defect=defect), self.assertRaisesRegex(ValueError, 'strong ABI'): self.package()
        self.assertFalse(self.destination.exists())

    def test_unsafe_library_identifier_and_framework_symlink_refused(self):
        path = self.framework/'Info.plist'; original = path.read_bytes(); info = plistlib.loads(original)
        for key, value in [('LibraryIdentifier', '../escape'), ('SupportedPlatform', 'macos'),
                           ('SupportedArchitectures', ['arm64', 'arm64']), ('SupportedPlatformVariant', 'simulator')]:
            with self.subTest(key=key):
                changed = copy.deepcopy(info); changed['AvailableLibraries'][0][key] = value
                path.write_bytes(plistlib.dumps(changed))
                with self.assertRaises(ValueError): self.package()
        path.write_bytes(original)
        (self.framework/'foreign-link').symlink_to(self.core/'go.mod')
        with self.assertRaisesRegex(ValueError, 'links'): self.package()

    def test_summary_abi_and_header_refusals(self):
        original = copy.deepcopy(self.summary)
        for key, value in [('platform', 'macos'), ('preflightABI', True), ('published', 0)]:
            with self.subTest(key=key):
                self.summary = dict(original, **{key: value}); self.write_receipts()
                with self.assertRaisesRegex(ValueError, 'platform/ABI'): self.package()
        self.summary = original; self.write_receipts()
        (self.framework/'ios-arm64/XRay.framework/Headers/XRay.objc.h').write_text('missing declarations')
        with self.assertRaisesRegex(ValueError, 'ABI header'): self.package()

    def test_existing_and_overlapping_outputs_refused_without_replacement(self):
        self.destination.mkdir(); (self.destination/'keep').write_text('untouched')
        with self.assertRaisesRegex(ValueError, 'new'): self.package()
        self.assertEqual((self.destination/'keep').read_text(), 'untouched')
        self.destination = self.preview/'new-package'
        with self.assertRaisesRegex(ValueError, 'overlaps'): self.package()
        self.assertFalse(self.destination.exists())

    def test_archive_rejects_unsafe_links_duplicates_extra_and_bad_bytes(self):
        archive = self.root/'malformed.tar.gz'
        for names, link, content in [(['../escape'], False, b'expected'), (['safe'], True, b''),
                                    (['safe', 'safe'], False, b'expected'), (['extra'], False, b'expected'),
                                    (['safe'], False, b'changed'), ([], False, b'')]:
            with self.subTest(names=names, link=link):
                with tarfile.open(archive, 'w:gz') as packed:
                    for name in names:
                        entry = tarfile.TarInfo(name)
                        if link: entry.type = tarfile.SYMTYPE; entry.linkname = '../escape'; packed.addfile(entry)
                        else: entry.size = len(content); packed.addfile(entry, io.BytesIO(content))
                with self.assertRaises(ValueError): subject.verify_archive(archive, {'safe': hashlib.sha256(b'expected').hexdigest()})


if __name__ == '__main__':
    unittest.main()
