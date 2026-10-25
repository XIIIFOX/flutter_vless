"""Synthetic files/command doubles only: no Gradle, Go, Core or network."""
import ast
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

import build_android_runtime_preview as builder
import package_android_runtime_preview as package


HEAD = 'a' * 40


def elf(abi, tag=b'fresh H3 v26.10.21'):
    wide, machine = {'arm64-v8a': (True, 183), 'armeabi-v7a': (False, 40),
                     'x86': (False, 3), 'x86_64': (True, 62)}[abi]
    data = bytearray(160)
    data[:6] = b'\x7fELF' + bytes((2 if wide else 1, 1))
    struct.pack_into('<HH', data, 16, 3, machine)
    if wide:
        struct.pack_into('<QQ', data, 24, 4096, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<I', data, 64, 1)
        struct.pack_into('<Q', data, 112, 16384)
    else:
        struct.pack_into('<II', data, 24, 4096, 52)
        struct.pack_into('<HH', data, 42, 32, 1)
        struct.pack_into('<I', data, 52, 1)
        struct.pack_into('<I', data, 80, 16384)
    return bytes(data) + tag


class AndroidPreviewControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.preview = self.root / 'build/preview'
        self.project = self.preview / 'project'
        self.version = builder.preview_version(HEAD)
        for name in [*builder.WRAPPER_INPUTS, *package.PACKAGING_INPUTS, builder.H3,
                     *builder.ORDINARY_FILES,
                     'third_party/xray-mobile/fixture.go', 'third_party/xray-mobile/nativecli/main.go',
                     'third_party/xray-vpn-routing/overlay/app/fixture.go',
                     'packages/flutter_vless_android/android/xray-protect/apply.py',
                     'packages/flutter_vless_android/android/xray-protect/protect.go',
                     'packages/flutter_vless_android/android/build_xray.sh',
                     'third_party/xray-vpn-routing/pin-manifest.json',
                     'tool/package_android_runtime_preview.py', 'tool/test_android_runtime_preview.py',
                     '.github/workflows/android-runtime-preview.yml', 'tool/verify_android_dns_preview.py',
                     'tool/build_android_dns_preview.py']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic source: ' + name).encode())
        self.pin = {'module': 'fixture.core', 'module_version': 'v26.10.21', 'module_sum': 'h1:fixture',
                    'core_commit': 'fixture-commit'}
        (self.root / 'third_party/xray-vpn-routing/pin-manifest.json').write_text(json.dumps(self.pin))
        pins = {}
        for abi in builder.ABIS:
            for lib, data in [('libxray.so', elf(abi, b'old committed Core')),
                              ('libtun2socks.so', ('pinned HEV ' + abi).encode())]:
                name = f'jniLibs/{abi}/{lib}'
                self.write(self.root / builder.RUNTIME / 'src/main' / name, data)
                pins[name] = hashlib.sha256(data).hexdigest()
        for name in ('assets/geoip.dat', 'assets/geosite.dat'):
            self.write(self.root / builder.RUNTIME / 'src/main' / name, name.encode())
            pins[name] = hashlib.sha256(name.encode()).hexdigest()
        (self.root / builder.RUNTIME / 'runtime-inputs.sha256.json').write_text(json.dumps(pins))
        self.pins = pins
        for name in builder.PROJECT_FILES:
            self.write(self.project / name, (self.root / builder.RUNTIME / name).read_bytes())
        for name in pins:
            source = self.root / builder.RUNTIME / 'src/main' / name
            if name.endswith('/libxray.so'):
                data = elf(name.split('/')[1])
                self.write(self.preview / 'fresh-jni' / name.removeprefix('jniLibs/'), data)
            else:
                data = source.read_bytes()
            self.write(self.project / 'src/main' / name, data)
        self.cache = self.root / 'cache/Core'
        self.write(self.cache / 'pinned.go', b'original cache')
        self.core = self.root / 'build/security-android-classic.fixture/Core'
        self.write(self.core / builder.DIALER, b'patched H3 owned socket close')
        self.receipt_path = self.preview / 'fresh-jni/classic-preview-security-android-classic.fixture.json'
        self.receipt = {'success': True, 'source_unchanged': True, 'module_cache_source_unchanged': True,
                        'copies_unchanged': True, 'classic_dns_lifetime_applied': True, 'h3_lifetime_applied': True,
                        'darwin_interface_binding_source_applied': True,
                        'darwin_interface_binding_patch_sha256': builder.digest(self.root/'third_party/xray-native-dns/darwin_interface_bind_patch.py'),
                        'routing_capability_expected': 0, 'lifetime_patch_scope': ['classic_dns', 'xhttp_h3_dial'],
                        'runtime_executed': False, 'published': False, 'selected_abis': list(builder.ABIS),
                        'source_sha256': {name: builder.digest(self.root / name) for name in builder.ordinary_inputs(self.root)},
                        'h3_lifetime_patch_sha256': builder.digest(self.root / builder.H3),
                        'artifacts_sha256': {abi + '/libxray.so': builder.digest(self.preview / 'fresh-jni' / abi / 'libxray.so')
                                             for abi in builder.ABIS},
                        'core_copy_sha256': builder.tree(self.core), 'core_source': str(self.cache),
                        'module_cache_before_sha256': builder.tree(self.cache),
                        'core_module': self.pin['module'], 'core': self.pin['module_version'],
                        'core_sum': self.pin['module_sum'], 'core_commit': self.pin['core_commit']}
        self.receipt_path.write_text(json.dumps(self.receipt))
        self.repo = self.project / 'build/repo'
        base = self.repo / f'dev/tfox/fluttervless/xray-android/{self.version}'
        base.mkdir(parents=True)
        self.aar = base / f'xray-android-{self.version}.aar'
        (base / f'xray-android-{self.version}.pom').write_text(
            '<project><groupId>dev.tfox.fluttervless</groupId><artifactId>xray-android</artifactId>'
            '<version>' + self.version + '</version></project>')
        self.repack()
        inputs = {name: builder.digest(self.root / name) for name in builder.WRAPPER_INPUTS}
        inputs.update(self.receipt['source_sha256'])
        self.result = {'schema': 1, 'success': True, 'head': HEAD, 'version': self.version,
                       'release_candidate': False, 'Go_toolchain_version': 'go version go1.27.3 linux/amd64',
                       'source_sha256': inputs, 'pinned_HEV_geodata_sha256': {k: v for k, v in pins.items() if not k.endswith('/libxray.so')},
                       'runtime_executed': False, 'installed': False, 'published': False, 'results': [],
                       'core_build_receipt': self.receipt_path.relative_to(self.preview).as_posix(),
                       'core_build_receipt_sha256': builder.digest(self.receipt_path),
                       'copied_h3_sha256': builder.digest(self.core / builder.DIALER),
                       'aar': self.aar.relative_to(self.preview).as_posix(), 'aar_sha256': builder.digest(self.aar),
                       'maven_files_sha256': builder.tree(self.repo), 'source_unchanged': True,
                       'copied_source_unchanged': True, 'module_cache_source_unchanged': True,
                       'staged_runtime_unchanged': True, 'fresh_outputs_unchanged': True,
                       'staged_runtime_sha256': builder.tree(self.project / 'src/main')}
        self.save()

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def repack(self):
        with zipfile.ZipFile(self.aar, 'w') as archive:
            archive.writestr('AndroidManifest.xml', b'synthetic Android manifest')
            for path in sorted((self.project / 'src/main').rglob('*')):
                if path.is_file() and path.name != 'AndroidManifest.xml':
                    name = path.relative_to(self.project / 'src/main').as_posix().replace('jniLibs/', 'jni/', 1)
                    archive.writestr(name, path.read_bytes())

    def save(self):
        self.receipt_path.write_text(json.dumps(self.receipt))
        self.result.update(core_build_receipt_sha256=builder.digest(self.receipt_path),
                           aar_sha256=builder.digest(self.aar), maven_files_sha256=builder.tree(self.repo),
                           staged_runtime_sha256=builder.tree(self.project / 'src/main'))
        (self.preview / 'preview.json').write_text(json.dumps(self.result))

    def validate(self):
        with mock.patch.object(package, 'git_head', return_value=HEAD, create=True), \
                mock.patch.object(package, 'git_blob', side_effect=lambda root, head, name: (root / name).read_bytes(), create=True):
            return package.validate(self.preview, HEAD, self.root)

    def build_with_double(self, output, *, mutation=None, failure=None, release=False):
        commands = []
        self.build_commands = commands
        def checked(name, command, out, environment, results, **options):
            commands.append((name, command, dict(environment)))
            if failure == name:
                raise RuntimeError('synthetic owned child failed')
            results.append({'name': name, 'exit_code': 0})
            if name == 'ordinary-core-build':
                shutil.copytree(self.preview / 'fresh-jni', out / 'fresh-jni')
                if release:
                    path = next((out / 'fresh-jni').glob('routing-preview-*.json'))
                    value = json.loads(path.read_text())
                    value['output_directory'] = str(out / 'fresh-jni')
                    path.write_text(json.dumps(value))
            else:
                shutil.copytree(self.repo, out / 'project/build/repo')
            if mutation is not None:
                mutation(name, out)
        environment = {'CI': 'true', 'GITHUB_ACTIONS': 'true'}
        if release:
            environment.update(SIGNING_IN_MEMORY_KEY='synthetic-private-signing-key',
                               SIGNING_IN_MEMORY_KEY_PASSWORD='synthetic-signing-password')
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(builder.os, 'uname', return_value=mock.Mock(sysname='Linux')), \
                mock.patch.object(builder.subprocess, 'check_output', return_value='go version go1.27.3 linux/amd64\n'), \
                mock.patch.object(builder, 'git_head', return_value=HEAD), mock.patch.object(builder, 'checked', side_effect=checked):
            return builder.build(output, HEAD, self.root, release=release), commands

    def release_fixture(self):
        old_version = self.version
        self.version = '26.10.21-protect1'
        new_core = self.root / 'build/security-android-routing.fixture/Core'
        shutil.copytree(self.core, new_core)
        self.core = new_core
        mobile = new_core.parent / 'mobile'
        self.write(mobile / 'main.go', b'synthetic source-bound routing CLI')
        self.receipt_path.unlink()
        self.receipt_path = self.preview / 'fresh-jni/routing-preview-security-android-routing.fixture.json'
        self.receipt.update(routing_capability_expected=1,
                            routing_tags=['flutter_vless_vpn_routing_cli', 'flutter_vless_vpn_routing'],
                            core_copy_sha256=builder.tree(self.core), mobile_copy_sha256=builder.tree(mobile),
                            core_replacement=str(new_core), mobile_replacement=str(mobile),
                            output_directory=str(self.preview / 'fresh-jni'))
        old = self.repo / 'dev/tfox/fluttervless/xray-android' / old_version
        target = old.with_name(self.version)
        old.rename(target)
        for path in list(target.iterdir()):
            path.rename(path.with_name(path.name.replace(old_version, self.version)))
        self.aar = target / f'xray-android-{self.version}.aar'
        (target / f'xray-android-{self.version}.pom').write_text(
            '<project><groupId>dev.tfox.fluttervless</groupId><artifactId>xray-android</artifactId>'
            '<version>' + self.version + '</version></project>')
        for suffix in ('-sources.jar', '-javadoc.jar'):
            (target / ('xray-android-' + self.version + suffix)).write_bytes(b'synthetic archive')
        for suffix in ('.aar', '.pom', '-sources.jar', '-javadoc.jar'):
            (target / ('xray-android-' + self.version + suffix + '.asc')).write_bytes(
                b'-----BEGIN PGP SIGNATURE-----\nsynthetic presence only\n-----END PGP SIGNATURE-----\n')
        self.result.update(version=self.version, release_candidate=True,
                           copied_mobile_source_unchanged=True,
                           core_build_receipt=self.receipt_path.relative_to(self.preview).as_posix(),
                           aar=self.aar.relative_to(self.preview).as_posix())
        self.save()

    def validate_release(self):
        with mock.patch.object(package, 'git_head', return_value=HEAD), \
                mock.patch.object(package, 'git_blob', side_effect=lambda root, head, name: (root / name).read_bytes()):
            return package.validate(self.preview, HEAD, self.root, release=True)

    def test_final_release_requires_routing_and_signing_byte_provenance(self):
        self.release_fixture()
        checked = self.validate_release()
        self.assertEqual('26.10.21-protect1', checked['version'])
        self.assertEqual(1, checked['routing_capability_expected'])
        self.assertEqual(8, len(checked['signed_artifacts_sha256']))

    def test_final_release_rejects_unsigned_or_missing_signature(self):
        self.release_fixture()
        (self.aar.parent / (self.aar.name + '.asc')).unlink()
        self.save()
        with self.assertRaisesRegex(ValueError, 'signed|signature'):
            self.validate_release()

    def test_final_release_rejects_ordinary_capability_zero(self):
        self.release_fixture()
        self.receipt['routing_capability_expected'] = 0
        self.save()
        with self.assertRaisesRegex(ValueError, 'lifetime|capability'):
            self.validate_release()

    def test_final_release_rejects_stale_mobile_copy_and_old_Go(self):
        self.release_fixture()
        path = self.core.parent / 'mobile/main.go'
        path.write_bytes(b'drift after compiler')
        with self.assertRaisesRegex(ValueError, 'mobile|copied'):
            self.validate_release()
        path.write_bytes(b'synthetic source-bound routing CLI')
        self.result['Go_toolchain_version'] = 'go version go1.27.0 linux/amd64'
        self.save()
        with self.assertRaisesRegex(ValueError, 'Go|toolchain'):
            self.validate_release()

    def test_final_release_refuses_missing_signing_before_children_and_output(self):
        output = self.root / 'build/no-signing'
        with mock.patch.dict(os.environ, {'CI': 'true', 'GITHUB_ACTIONS': 'true'}, clear=True), \
                mock.patch.object(builder.os, 'uname', return_value=mock.Mock(sysname='Linux')), \
                mock.patch.object(builder, 'checked') as child, \
                self.assertRaisesRegex(ValueError, 'signing'):
            builder.build(output, HEAD, self.root, release=True)
        self.assertFalse(output.exists())
        child.assert_not_called()

    def test_final_release_refuses_foreign_output_receipt(self):
        self.release_fixture()
        self.receipt['output_directory'] = str(self.root / 'other-output')
        self.save()
        with self.assertRaisesRegex(ValueError, 'copy|tags'):
            self.validate_release()

    def test_final_release_builder_compiles_all_ABIs_before_signing_without_secret_receipt(self):
        self.release_fixture()
        result, commands = self.build_with_double(self.root / 'build/final-release', release=True)
        self.assertTrue(result['success'])
        self.assertEqual('1', commands[0][2]['XRAY_NATIVE_ROUTING'])
        self.assertNotIn('SIGNING_IN_MEMORY_KEY', commands[0][2])
        self.assertEqual('synthetic-private-signing-key', commands[1][2]['SIGNING_IN_MEMORY_KEY'])
        self.assertNotIn('synthetic-private-signing-key', json.dumps(result))
        self.assertEqual('26.10.21-protect1', result['version'])

    def test_final_release_central_bundle_roundtrip_and_corruption_rejected(self):
        self.release_fixture()
        output = self.root / 'build/release-artifact'
        with mock.patch.object(package, 'git_head', return_value=HEAD), \
                mock.patch.object(package, 'git_blob', side_effect=lambda root, head, name: (root / name).read_bytes()):
            manifest = package.package(self.preview, output, HEAD, self.root, release=True)
            self.assertEqual(40, len(manifest['central_bundle_members_sha256']))
            self.assertEqual(manifest, package.verify_release(self.preview, output, HEAD, self.root))
            bundle = output / manifest['central_bundle']
            with zipfile.ZipFile(bundle, 'a') as archive:
                archive.writestr('unexpected.txt', b'not published')
            with self.assertRaisesRegex(ValueError, 'bundle|artifact'):
                package.verify_release(self.preview, output, HEAD, self.root)

    def test_final_release_provenance_archive_mutation_is_rejected(self):
        self.release_fixture()
        output = self.root / 'build/provenance-artifact'
        with mock.patch.object(package, 'git_head', return_value=HEAD), \
                mock.patch.object(package, 'git_blob', side_effect=lambda root, head, name: (root / name).read_bytes()):
            manifest = package.package(self.preview, output, HEAD, self.root, release=True)
            (output / manifest['archive']).write_bytes(b'changed archive')
            with self.assertRaisesRegex(ValueError, 'provenance archive'):
                package.verify_release(self.preview, output, HEAD, self.root)

    def test_actual_publisher_status_parser_never_calls_uploaded_published(self):
        source = (Path(__file__).resolve().parent / 'publish_android_runtime_maven.sh').read_text()
        marker = 'state="$(DEPLOYMENT_ID="$DEPLOYMENT_ID" python3 - "$status_file" <<\'PY\'\n'
        body = source.split(marker, 1)[1].split('\nPY\n', 1)[0]
        for state, published in [('VALIDATING', False), ('PUBLISHING', False), ('FAILED', False), ('PUBLISHED', True)]:
            with self.subTest(state=state):
                path = self.root / 'publication-status.json'
                path.write_text(json.dumps({'deploymentState': state}))
                with mock.patch.dict(os.environ, {'DEPLOYMENT_ID': 'synthetic-deployment'}, clear=True), \
                        mock.patch.object(sys, 'argv', ['publisher-status', str(path)]), \
                        contextlib.redirect_stdout(io.StringIO()):
                    exec(compile(body, '<actual-publisher-status>', 'exec'), {})
                result = json.loads((self.root / 'central-deployment.json').read_text())
                self.assertEqual(published, result['published'])
                self.assertEqual('synthetic-deployment', result['deployment_id'])
        path.write_text('{"deploymentState":"UNKNOWN"}')
        with mock.patch.dict(os.environ, {'DEPLOYMENT_ID': 'synthetic-deployment'}, clear=True), \
                mock.patch.object(sys, 'argv', ['publisher-status', str(path)]), \
                self.assertRaises(SystemExit):
            exec(compile(body, '<actual-publisher-status>', 'exec'), {})

    def test_missing_H3_receipt_is_not_candidate_provenance(self):
        self.receipt['h3_lifetime_applied'] = False
        self.save()
        with self.assertRaisesRegex(ValueError, 'lifetime'):
            self.validate()

    def test_omitting_input_from_both_source_maps_is_rejected(self):
        name = 'packages/flutter_vless_android/android/build_xray.sh'
        del self.receipt['source_sha256'][name]
        del self.result['source_sha256'][name]
        self.save()
        with self.assertRaisesRegex(ValueError, 'sources|source provenance'):
            self.validate()

    def test_dynamic_input_vector_matches_actual_ordinary_producer(self):
        source = (Path(builder.__file__).resolve().parents[1] /
                  'packages/flutter_vless_android/android/build_xray.sh').read_text()
        block = source.split("<<'PYCLASSIC'", 1)[1].split('\nPYCLASSIC', 1)[0]
        vector = block[block.index('paths=[root/'):block.index('if any(p.is_symlink()')]
        # Execute only the existing file-enumeration assignments, never the
        # embedded module download, patcher, compiler, or executable.
        parsed = ast.parse(vector)
        self.assertTrue(all(isinstance(node, (ast.Assign, ast.AugAssign)) for node in parsed.body))
        namespace = {'root': self.root, 'mobile': self.root / 'third_party/xray-mobile',
                     'capability': self.root / 'third_party/xray-vpn-routing',
                     'protect': self.root / 'packages/flutter_vless_android/android/xray-protect'}
        exec(compile(parsed, '<ordinary-input-vector-only>', 'exec'), namespace)
        self.assertEqual(builder.ordinary_inputs(self.root),
                         sorted({p.relative_to(self.root).as_posix() for p in namespace['paths']}))

    def test_old_committed_Core_cannot_be_relabelled_with_new_receipts(self):
        for abi in builder.ABIS:
            data = (self.root / builder.RUNTIME / f'src/main/jniLibs/{abi}/libxray.so').read_bytes()
            self.write(self.preview / f'fresh-jni/{abi}/libxray.so', data)
            self.write(self.project / f'src/main/jniLibs/{abi}/libxray.so', data)
            self.receipt['artifacts_sha256'][abi + '/libxray.so'] = hashlib.sha256(data).hexdigest()
        self.repack()
        self.save()
        with self.assertRaisesRegex(ValueError, 'old runtime|Old Xray'):
            self.validate()

    def test_changed_copied_H3_is_not_covered_by_true_flags(self):
        (self.core / builder.DIALER).write_bytes(b'changed after compiler')
        with self.assertRaisesRegex(ValueError, 'copied source'):
            self.validate()

    def test_correct_new_all_ABI_candidate_is_accepted(self):
        checked = self.validate()
        self.assertEqual(checked['selected_abis'], list(builder.ABIS))
        self.assertEqual(set(checked['ELF_LOAD_alignments']), set(builder.ABIS))

    def test_actual_package_roundtrip_contains_only_candidate_repo_and_receipts(self):
        output = self.root / 'build/artifact'
        with mock.patch.object(package, 'git_head', return_value=HEAD), \
                mock.patch.object(package, 'git_blob', side_effect=lambda root, head, name: (root / name).read_bytes()):
            manifest = package.package(self.preview, output, HEAD, self.root)
        archive = output / manifest['archive']
        self.assertEqual(manifest['archive_sha256'], builder.digest(archive))
        self.assertFalse(manifest['runtime_executed'] or manifest['installed'] or manifest['published'])
        with tarfile.open(archive) as packed:
            found = {item.name: hashlib.sha256(packed.extractfile(item).read()).hexdigest() for item in packed}
        self.assertEqual(found, manifest['members_sha256'])
        self.assertEqual({name for name in found if not name.startswith('maven/')},
                         {'preview.json', 'core-build-receipt.json'})
        self.assertTrue(all('Core/' not in name and 'src/main/' not in name for name in found))

    def test_unexpected_AAR_runtime_member_refuses_even_with_updated_AAR_hash(self):
        with zipfile.ZipFile(self.aar, 'a') as archive:
            archive.writestr('jni/unreviewed-abi/libxray.so', b'unreviewed runtime')
        self.save()
        with self.assertRaisesRegex(ValueError, 'runtime members'):
            self.validate()

    def test_wrong_ELF_ABI_fails_even_if_all_hashes_are_updated(self):
        data = elf('x86_64')
        self.write(self.preview / 'fresh-jni/arm64-v8a/libxray.so', data)
        self.write(self.project / 'src/main/jniLibs/arm64-v8a/libxray.so', data)
        self.receipt['artifacts_sha256']['arm64-v8a/libxray.so'] = hashlib.sha256(data).hexdigest()
        self.repack()
        self.save()
        with self.assertRaisesRegex(ValueError, 'ABI|target'):
            self.validate()

    def test_old_Core_version_fails_even_if_fresh_hashes_are_updated(self):
        data = elf('arm64-v8a', b'freshly rebuilt but wrong v26.10.17')
        self.write(self.preview / 'fresh-jni/arm64-v8a/libxray.so', data)
        self.write(self.project / 'src/main/jniLibs/arm64-v8a/libxray.so', data)
        self.receipt['artifacts_sha256']['arm64-v8a/libxray.so'] = hashlib.sha256(data).hexdigest()
        self.repack()
        self.save()
        with self.assertRaisesRegex(ValueError, 'version marker'):
            self.validate()

    def test_pinned_HEV_mutation_is_rejected(self):
        self.write(self.project / 'src/main/jniLibs/arm64-v8a/libtun2socks.so', b'unreviewed HEV')
        self.repack()
        self.save()
        with self.assertRaisesRegex(ValueError, 'pinned|Pinned'):
            self.validate()

    def test_source_and_cache_drift_are_rejected(self):
        for kind in ('source', 'cache'):
            with self.subTest(kind=kind):
                path = self.root / builder.H3 if kind == 'source' else self.cache / 'pinned.go'
                before = path.read_bytes()
                path.write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    self.validate()
                path.write_bytes(before)

    def test_symlink_candidate_is_rejected(self):
        path = self.preview / 'fresh-jni/arm64-v8a/libxray.so'
        path.unlink()
        path.symlink_to(self.root / builder.RUNTIME / 'src/main/jniLibs/arm64-v8a/libxray.so')
        with self.assertRaisesRegex(ValueError, 'symlink|real'):
            self.validate()

    def test_local_build_refuses_before_commands_or_output(self):
        output = self.root / 'build/not-created'
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(builder, 'checked') as child, \
                mock.patch.object(builder, 'git_head') as head, self.assertRaisesRegex(ValueError, 'GitHub Actions'):
            builder.build(output, HEAD, self.root)
        child.assert_not_called()
        head.assert_not_called()
        self.assertFalse(output.exists())

    def test_actual_builder_selects_only_compilation_and_local_Maven(self):
        output = self.root / 'build/new-output'
        result, commands = self.build_with_double(output)
        self.assertTrue(result['success'])
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][2]['XRAY_NATIVE_ROUTING'], '0')
        self.assertTrue(all(commands[0][2][name] == '1' for name in ('XRAY_BUILD_ARM64', 'XRAY_BUILD_ARMV7', 'XRAY_BUILD_X86', 'XRAY_BUILD_X86_64')))
        self.assertIn('publishReleasePublicationToLocalBuildRepository', commands[1][1])
        self.assertFalse(result['runtime_executed'] or result['installed'] or result['published'])

    def test_actual_builder_refuses_drift_during_Gradle_and_records_it(self):
        for kind in ('Core', 'cache', 'staged', 'fresh'):
            with self.subTest(kind=kind):
                output = self.root / ('build/drift-' + kind)
                path = (self.core / builder.DIALER if kind == 'Core' else self.cache / 'pinned.go')
                original = path.read_bytes()
                def mutate(name, out):
                    if name == 'isolated-aar-build':
                        target = (out / 'project/src/main/jniLibs/x86/libxray.so' if kind == 'staged' else
                                  out / 'fresh-jni/x86/libxray.so' if kind == 'fresh' else path)
                        target.write_bytes(b'drift during isolated Gradle')
                try:
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        self.build_with_double(output, mutation=mutate)
                    result = json.loads((output / 'preview.json').read_text())
                    self.assertFalse(result['success'])
                    field = {'Core': 'copied_source_unchanged', 'cache': 'module_cache_source_unchanged',
                             'staged': 'staged_runtime_unchanged', 'fresh': 'fresh_outputs_unchanged'}[kind]
                    self.assertIs(result[field], False)
                finally:
                    path.write_bytes(original)

    def test_actual_builder_child_failure_stops_and_preserves_false_receipt(self):
        output = self.root / 'build/child-failure'
        with self.assertRaisesRegex(RuntimeError, 'synthetic owned child'):
            self.build_with_double(output, failure='ordinary-core-build')
        result = json.loads((output / 'preview.json').read_text())
        self.assertEqual(len(self.build_commands), 1)
        self.assertFalse(result['success'])
        self.assertIs(result['source_unchanged'], True)
        self.assertIs(result['copied_source_unchanged'], False)
        self.assertNotIn('aar', result)

    def test_actual_builder_primary_failure_is_not_masked_by_missing_copy(self):
        output = self.root / 'build/primary-failure'
        def mutate(name, out):
            if name == 'isolated-aar-build':
                shutil.rmtree(self.core)
                raise RuntimeError('primary synthetic Gradle failure')
        with self.assertRaisesRegex(RuntimeError, 'primary synthetic Gradle'):
            self.build_with_double(output, mutation=mutate)
        result = json.loads((output / 'preview.json').read_text())
        self.assertFalse(result['success'])
        self.assertIs(result['copied_source_unchanged'], False)


if __name__ == '__main__':
    unittest.main()
