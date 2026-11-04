"""Published Apple SDK file/selection controls; no SDK build or execution."""
import hashlib
import json
import shutil
import subprocess
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import install_published_apple_runtime as subject


class PublishedApple(unittest.TestCase):
    def test_verify_installed_main_calls_only_the_selected_platform(self):
        with patch.object(subject.sys, 'argv', ['installer', '--verify-installed', '--platform', 'macos']), \
                patch.object(subject.sys, 'platform', 'darwin'), \
                patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), \
                patch.object(subject, 'finish', return_value={'success': True}) as finish:
            subject.main()
        finish.assert_called_once_with(subject.ROOT, 'macos')

    def test_platform_selection_keeps_both_as_default_and_selects_exact_receipt(self):
        parser = subject.argument_parser()
        self.assertEqual(subject.selected_platforms(parser.parse_args([]).platform), ['ios', 'macos'])
        for platform in ['ios', 'macos']:
            args = parser.parse_args(['--verify-installed', '--platform', platform])
            self.assertTrue(args.verify_installed)
            self.assertEqual(subject.selected_platforms(args.platform), [platform])
        with self.assertRaises(ValueError): subject.selected_platforms('foreign')
        with self.assertRaises(SystemExit): parser.parse_args(['--platform', 'foreign'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.platform = 'ios'
        self.files = {'Info.plist': b'fixture metadata', 'ios-arm64/XRay.framework/XRay': b'public SDK bytes'}
        self.archive = self.root/'sdk.zip'
        with zipfile.ZipFile(self.archive, 'w') as packed:
            for name, data in self.files.items(): packed.writestr('XRay.xcframework/'+name, data)
        self.document = dict(success=True, platform='ios', head=subject.HEAD, release_version='26.10.31', runtime_revision=subject.REVISION,
                             core_commit=subject.CORE_COMMIT, archive='XRay.xcframework.zip', archive_sha256=subject.digest(self.archive),
                             routing_capability_expected=1, darwin_interface_binding_capability_expected=1,
                             framework_sha256={name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()},
                             source_sha256={name: 'a'*64 for name in
                                            ['synthetic-source.go', *subject.LIFETIME_SOURCE_SCOPES.values(), subject.DARWIN_BINDING_PATCH]},
                             xhttp_listener_cleanup_applied=True,
                             xhttp_listener_cleanup_patch_sha256='a'*64,
                             xhttp_listener_cleanup_source_sha256=subject.XHTTP_LISTENER_SOURCE_SHA256,
                             go_version='go1.27.3', root_ca_filter_toolchain_minimum='go1.27.3', h2buf_cap_kib=128)
        self.manifest = self.root/'manifest.json'; self.manifest.write_text(json.dumps(self.document))
        self.pins = {'zip': subject.digest(self.archive), 'manifest': subject.digest(self.manifest)}
        pins = patch.dict(subject.PINS, {'ios': self.pins}); pins.start(); self.addCleanup(pins.stop)
        package = self.root/subject.PATHS['ios']['package']; package.parent.mkdir(parents=True)
        package.write_text('let xrayReleaseTag = "xray-ios-v26.10.31-'+subject.REVISION+'"\nlet xrayChecksum = "'+self.pins['zip']+'"\n')

    def test_archive_and_full_file_set_are_verified_without_execution(self):
        result = subject.verify_archive('ios', self.archive, self.manifest)
        self.assertEqual(result, self.document)
        for path in [self.archive, self.manifest]:
            original = path.read_bytes(); path.write_bytes(original+b'x')
            with self.assertRaises(ValueError): subject.verify_archive('ios', self.archive, self.manifest)
            path.write_bytes(original)

    def test_signed_metadata_identity_and_binary_map_remain_required(self):
        for change in [{'head': 'b'*40}, {'platform': 'macos'}, {'release_version': '26.10.29'},
                       {'runtime_revision': 'r1'}, {'framework_sha256': {}}, {'routing_capability_expected': True},
                       {'xhttp_listener_cleanup_applied': False}, {'xhttp_listener_cleanup_applied': 1},
                       {'xhttp_listener_cleanup_patch_sha256': 'b'*64},
                       {'xhttp_listener_cleanup_source_sha256': 'a651b04643dde70653955a55501f4607d7ed6bb647ea3d39596fb63f7d734aaa'},
                       {'go_version': 'go1.27.2'}, {'h2buf_cap_kib': 512},
                       {'root_ca_filter_toolchain_minimum': 'go1.27.2'}]:
            self.manifest.write_text(json.dumps(dict(self.document, **change)))
            with patch.dict(self.pins, {'manifest': subject.digest(self.manifest)}), self.assertRaises(ValueError):
                subject.verify_archive('ios', self.archive, self.manifest)

    def test_all_qualified_lifetime_sources_and_separate_darwin_binding_remain_required(self):
        for missing in [*subject.LIFETIME_SOURCE_SCOPES.values(), subject.DARWIN_BINDING_PATCH]:
            sources = dict(self.document['source_sha256']); del sources[missing]
            self.manifest.write_text(json.dumps(dict(self.document, source_sha256=sources)))
            with patch.dict(self.pins, {'manifest': subject.digest(self.manifest)}), self.assertRaises(ValueError):
                subject.verify_archive('ios', self.archive, self.manifest)

    def test_old_vendored_cache_is_not_accepted_and_install_replaces_exactly(self):
        destination = self.root/subject.PATHS['ios']['framework']; destination.mkdir(parents=True)
        (destination/'old-binary').write_bytes(b'old cache')
        with self.assertRaises(ValueError): subject.verify_installed(self.root, 'ios', self.document)
        with patch.object(subject, 'git_bindings') as source_binding:
            result = subject.install(self.root, 'ios', self.archive, self.manifest)
        source_binding.assert_called_once_with(self.root, subject.HEAD, self.document['source_sha256'])
        self.assertEqual(subject.tree(destination), self.document['framework_sha256'])
        self.assertTrue(result['runtime_checks_pending'])
        self.assertTrue(result['xhttp_listener_cleanup_applied'])
        self.assertEqual(result['verified_derived_lifetime_scope'], list(subject.LIFETIME_SOURCE_SCOPES))
        self.assertFalse((destination/'old-binary').exists())

    def test_preferred_package_local_wrong_cache_is_refused_before_replacing_primary(self):
        cache = (self.root/subject.PATHS['ios']['package']).parent/'XRay.xcframework'; cache.mkdir()
        (cache/'wrong-binary').write_bytes(b'wrong preferred cache')
        destination = self.root/subject.PATHS['ios']['framework']; destination.mkdir()
        (destination/'retained').write_bytes(b'keep until admission')
        with patch.object(subject, 'git_bindings'), self.assertRaises(ValueError):
            subject.install(self.root, 'ios', self.archive, self.manifest)
        self.assertTrue((destination/'retained').exists())

    def test_spm_pin_mismatch_refuses_before_install(self):
        package = self.root/subject.PATHS['ios']['package']; package.write_text(package.read_text().replace('26.10.31', '26.10.29'))
        with patch.object(subject, 'git_bindings'), self.assertRaises(ValueError):
            subject.install(self.root, 'ios', self.archive, self.manifest)
        self.assertFalse((self.root/subject.PATHS['ios']['framework']).exists())

    def test_only_canonical_repository_alias_is_admitted(self):
        preferred = (self.root/subject.PATHS['ios']['package']).parent/'XRay.xcframework'
        preferred.symlink_to('../XRay.xcframework')
        with patch.object(subject, 'git_bindings'):
            subject.install(self.root, 'ios', self.archive, self.manifest)
        subject.verify_installed(self.root, 'ios', self.document)
        preferred.unlink(); preferred.symlink_to(self.root/'foreign-cache')
        with self.assertRaises(ValueError): subject.verify_installed(self.root, 'ios', self.document)

    def test_post_test_proof_requires_unchanged_sdk_actual_markers_and_no_duplicates(self):
        with patch.object(subject, 'git_bindings'):
            subject.install(self.root, 'ios', self.archive, self.manifest)
        output = self.root/'build/published_apple_runtime/ios'
        shutil.copyfile(self.archive, output/'XRay.xcframework.zip'); shutil.copyfile(self.manifest, output/'manifest.json')
        log = self.root/'build/ios_privacy_runtime_probe/runtime.log'; log.parent.mkdir()
        valid = '\n'.join(['RUNTIME=26.10.31', 'APPLE_GEODATA_LIFETIME_CAPABILITY_PASS=1', 'APPLE_XDRIVE_LIFETIME_CAPABILITY_PASS=2',
                           'APPLE_DARWIN_INTERFACE_BIND_CAPABILITY_PASS=1', 'APPLE_FAKEDNS_SDK_PASS=2', 'APPLE_DNS_DATA_MAPS_SDK_PASS=2',
                           'NATIVE_ROUTING_RUNTIME_PASS=0', 'NATIVE_ROUTING_RUNTIME_PASS=1', 'NATIVE_ROUTING_RUNTIME_DRAIN_PASS'])+'\n'
        for wrong in ['', valid.replace('26.10.31', '26.10.29'), valid.replace('CAPABILITY_PASS=2', 'CAPABILITY_PASS=1'),
                      valid+'RUNTIME=26.10.31\n']:
            log.write_text(wrong)
            with patch.object(subject, 'git_bindings'), self.assertRaises(ValueError): subject.finish(self.root, 'ios')
        log.write_text(valid)
        with patch.object(subject, 'git_bindings'): result = subject.finish(self.root, 'ios')
        self.assertFalse(result['runtime_checks_pending']); self.assertTrue(result['post_test_framework_unchanged'])
        (self.root/subject.PATHS['ios']['framework']/'Info.plist').write_bytes(b'changed after tests')
        with patch.object(subject, 'git_bindings'), self.assertRaises(ValueError): subject.finish(self.root, 'ios')


class Workflow(unittest.TestCase):
    def test_published_mode_preserves_runtime_suites_and_skips_all_sdk_rebuilds(self):
        text = (Path(__file__).resolve().parents[1]/'.github/workflows/ci.yml').read_text()
        self.assertIn('apple_runtime_source:', text); self.assertIn('options: [build, published]', text)
        ios = text.split('\n  ios:\n', 1)[1].split('\n  windows:\n', 1)[0]
        self.assertNotIn('REQUIRE_MANAGED_SERVICE_LIFETIMES:', ios.split('    steps:', 1)[0],
                         'Runtime-only capability policy must not leak into synthetic qualifier fixtures')
        steps = ios.split('\n      - ')
        for marker in ['name: Build unpublished iOS Core preview', 'name: Build unpublished macOS Core preview',
                       'name: Package the checked unpublished iOS SDK', 'name: Upload the checked unpublished iOS SDK']:
            selected = [step for step in steps if step.startswith(marker)]
            self.assertEqual(len(selected), 1, marker)
            self.assertIn("if: ${{ inputs.apple_runtime_source != 'published' }}", selected[0])
        for marker in ['name: Test real iOS Xray in simulator', 'name: Test macOS protection policies',
                       'name: Build example iOS app', 'name: Build example macOS app']:
            step = next(step for step in steps if step.startswith(marker))
            self.assertNotRegex(step, r'(?m)^        if: .*apple_runtime_source')
        for marker in ['name: Test real iOS Xray in simulator', 'name: Test macOS protection policies']:
            step = next(step for step in steps if step.startswith(marker))
            self.assertIn("REQUIRE_MANAGED_SERVICE_LIFETIMES: ${{ inputs.apple_runtime_source == 'published' && '1' || '0' }}", step)
        self.assertIn('REQUIRE_MANAGED_SERVICE_LIFETIMES:', ios)
        self.assertIn('tool/install_published_apple_runtime.py --verify-installed', ios)
        self.assertIn('build/published_apple_runtime/**/*.json', ios)
        install = next(step for step in steps if step.startswith('name: Install the checksum-pinned published Apple SDKs'))
        fetch = f'git fetch --no-tags --depth=1 origin {subject.HEAD}'
        self.assertIn(fetch, install)
        self.assertLess(install.index(fetch), install.index('python3 tool/install_published_apple_runtime.py'))

    def test_exact_producer_fetch_restores_source_validation_in_a_shallow_checkout(self):
        def git(directory, *arguments):
            return subprocess.run(['git', '-C', str(directory), *arguments], capture_output=True,
                                  text=True, check=True, timeout=10).stdout.strip()
        with tempfile.TemporaryDirectory(prefix='apple-published-shallow-') as temporary:
            root = Path(temporary); origin = root/'origin'; origin.mkdir()
            git(origin, 'init')
            (origin/'source.py').write_text('immutable producer source\n')
            git(origin, 'add', '.')
            git(origin, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'producer')
            producer = git(origin, 'rev-parse', 'HEAD')
            (origin/'unrelated-verifier.py').write_text('later verifier only\n')
            git(origin, 'add', '.')
            git(origin, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'consumer')
            checkout = root/'checkout'
            subprocess.run(['git', 'clone', '--depth=1', origin.as_uri(), str(checkout)],
                           capture_output=True, check=True, timeout=10)
            absent = subprocess.run(['git', '-C', str(checkout), 'show', producer+':source.py'],
                                    capture_output=True, check=False, timeout=10)
            self.assertNotEqual(absent.returncode, 0, 'Control must reproduce unavailable producer history')
            git(checkout, 'fetch', '--no-tags', '--depth=1', 'origin', producer)
            subject.git_bindings(checkout, producer, {'source.py': subject.digest(checkout/'source.py')})


if __name__ == '__main__': unittest.main()
