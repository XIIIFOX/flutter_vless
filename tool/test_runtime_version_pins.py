#!/usr/bin/env python3
"""File-only checks for the active runtime producer and example consumers."""
import ast
import json
import re
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class RuntimeVersionPinsTest(unittest.TestCase):
    def setUp(self):
        # Read literals only: importing a producer must never become a build.
        nodes = ast.parse(self.read('tool/build_android_runtime_preview.py')).body
        literals = {node.targets[0].id: node.value.value for node in nodes
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Constant)}
        self.assertRegex(literals['CORE_TAG'], r'^v[0-9]+\.[0-9]+\.[0-9]+$')
        self.core = literals['CORE_TAG'][1:]
        self.runtime = literals['RELEASE_VERSION']
        apple = ast.parse(self.read('tool/package_apple_runtime_release.py'))
        manifests = [node.value for node in ast.walk(apple)
                     if isinstance(node, ast.Assign) and any(
                         isinstance(target, ast.Name) and target.id == 'manifest'
                         for target in node.targets) and isinstance(node.value, ast.Dict)]
        self.assertEqual(len(manifests), 1)
        apple_literals = {key.value: value.value
                          for key, value in zip(manifests[0].keys, manifests[0].values)
                          if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)}
        self.apple_core = apple_literals['release_version']
        self.apple_revision = apple_literals['runtime_revision']
        self.assertRegex(self.apple_revision, r'^r[1-9][0-9]*$')

    @staticmethod
    def read(name):
        return (ROOT / name).read_text(encoding='utf-8')

    def test_producer_release_version_matches_core_tag(self):
        self.assertRegex(self.runtime, '^' + re.escape(self.core) + r'-protect[1-9][0-9]*$')

    def assert_official_whitelist(self, text):
        allowed = re.findall(r'check\(version == null \|\| version == "([^"]+)"\)', text)
        self.assertEqual(allowed, [self.runtime], 'Official runtime whitelist differs from producer')

    def test_android_official_whitelist_matches_producer(self):
        self.assert_official_whitelist(self.read('example/android/settings.gradle.kts'))

    def test_stale_official_whitelist_is_rejected(self):
        current = self.read('example/android/settings.gradle.kts')
        stale = re.sub(r'version == "[^"]+"', 'version == "0.0.0-protect1"', current)
        self.assertNotEqual(stale, current, 'Fault control must change the actual guard')
        with self.assertRaisesRegex(AssertionError, 'Official runtime whitelist'):
            self.assert_official_whitelist(stale)

    def test_android_dependency_default_matches_producer(self):
        text = self.read('packages/flutter_vless_android/android/build.gradle')
        default = re.findall(r"findProperty\('flutterVlessXrayRuntimeVersion'\) \?: '([^']+)'", text)
        self.assertEqual(default, [self.runtime])

    def test_android_verification_pins_cover_exact_runtime(self):
        tree = ET.fromstring(self.read('example/android/gradle/verification-metadata.xml'))
        components = [node for node in tree.findall('./{*}components/{*}component')
                      if node.get('group') == 'dev.tfox.fluttervless'
                      and node.get('name') == 'xray-android']
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].get('version'), self.runtime)
        artifacts = components[0].findall('{*}artifact')
        self.assertEqual({node.get('name') for node in artifacts}, {
            'xray-android-' + self.runtime + suffix
            for suffix in ('.aar', '.pom', '-sources.jar', '-javadoc.jar')})
        self.assertEqual(len(artifacts), 4)
        for artifact in artifacts:
            hashes = artifact.findall('{*}sha256')
            self.assertEqual(len(hashes), 1)
            self.assertRegex(hashes[0].get('value', ''), r'^[0-9a-f]{64}$')

    def test_android_live_runtime_expectation_matches_core(self):
        text = self.read('example/integration_test/android_xray_runtime_smoke_test.dart')
        self.assertEqual(re.findall(r"expect\(version, startsWith\('Xray ([^']+) '\)\)", text), [self.core])
        self.assertEqual(re.findall(r"Android Xray runtime reports v([^']+)'", text), [self.core])

    def test_embedded_live_runtime_expectation_matches_core(self):
        text = self.read('example/integration_test/core_version_smoke_test.dart')
        self.assertEqual(re.findall(r"expect\(version, contains\('([^']+)'\)\)", text), [self.core])
        self.assertEqual(re.findall(r"Embedded Xray core reports v([^']+)'", text), [self.core])

    def test_windows_example_uses_same_official_release_and_checksum(self):
        guide = self.read('example/windows/README.md')
        workflow = self.read('.github/workflows/windows-runtime.yml')
        self.assertEqual(re.findall(r'github.com/XTLS/Xray-core/releases/tag/v([0-9.]+)', guide), [self.core])
        self.assertEqual(re.findall(r'github.com/XTLS/Xray-core/releases/download/v([0-9.]+)/Xray-windows-64.zip', workflow), [self.core])
        official_sha = re.findall(r"-ne '([0-9a-f]{64})'", workflow)
        self.assertEqual(len(official_sha), 1)
        self.assertEqual(re.findall(r'archive SHA-256: `([0-9a-f]{64})`', guide), official_sha)

    def test_apple_producer_release_matches_shared_core(self):
        self.assertEqual(self.apple_core, self.core)

    def assert_apple_pins(self, platform, package, podspec):
        """Check declared default consumers; public archive bytes are a separate gate."""
        tag = f'xray-{platform}-v{self.core}-{self.apple_revision}'
        url = f'https://github.com/XIIIFOX/flutter_vless/releases/download/{tag}/XRay.xcframework.zip'
        self.assertEqual(re.findall(r'let xrayReleaseTag = "([^"]+)"', package), [tag])
        checksums = re.findall(r'let xrayChecksum = "([0-9a-f]{64})"', package)
        self.assertEqual(len(checksums), 1)
        self.assertNotEqual(checksums[0], '0' * 64)
        self.assertEqual(re.findall(r'let xrayBinaryURL = [^\n]+\?\? "([^"]+)"', package),
                         [r'https://github.com/XIIIFOX/flutter_vless/releases/download/\(xrayReleaseTag)/XRay.xcframework.zip'])
        self.assertRegex(package, r'xrayBinaryChecksum = [^\n]+\?\? xrayChecksum')
        self.assertRegex(package, r'\.binaryTarget\(name: "XRay", url: xrayBinaryURL, checksum: xrayBinaryChecksum\)')
        if platform == 'ios':
            self.assertEqual(re.findall(r"xray_version = ENV\['FLUTTER_VLESS_XRAY_VERSION'\] \|\| '([^']+)'", podspec), ['v' + self.core])
            self.assertEqual(re.findall(r"xray_release_tag = ENV\['FLUTTER_VLESS_XRAY_RELEASE_TAG'\] \|\| '([^']+)'", podspec), [tag])
            self.assertEqual(re.findall(r'xray_url = [^\n]+\|\| "([^"]+)"', podspec),
                             ['https://github.com/XIIIFOX/flutter_vless/releases/download/#{xray_release_tag}/XRay.xcframework.zip'])
            pod_checksums = re.findall(r"xray_checksum = ENV\['FLUTTER_VLESS_XRAY_CHECKSUM'\] \|\| '([0-9a-f]{64})'", podspec)
        else:
            self.assertEqual(re.findall(r'DEFAULT_FRAMEWORK_URL="([^"]+)"', podspec), [url])
            pod_checksums = re.findall(r'FRAMEWORK_SHA256="\$\{FLUTTER_VLESS_MACOS_FRAMEWORK_SHA256:-([0-9a-f]{64})\}"', podspec)
        self.assertEqual(pod_checksums, checksums, 'SwiftPM and CocoaPods default archive checksums differ')

    def test_apple_default_consumers_match_producer_and_each_other(self):
        for platform, package, podspec in [
            ('ios', 'ios/flutter_vless/Package.swift', 'ios/flutter_vless.podspec'),
            ('macos', 'packages/flutter_vless_macos/macos/flutter_vless_macos/Package.swift',
             'packages/flutter_vless_macos/macos/flutter_vless_macos.podspec'),
        ]:
            with self.subTest(platform=platform):
                self.assert_apple_pins(platform, self.read(package), self.read(podspec))

    def test_apple_pin_contract_rejects_stale_version_checksum_and_unused_url(self):
        checksum = 'a' * 64
        for platform in ['ios', 'macos']:
            tag = f'xray-{platform}-v{self.core}-{self.apple_revision}'
            package = (f'let xrayReleaseTag = "{tag}"\nlet xrayChecksum = "{checksum}"\n'
                       r'let xrayBinaryURL = env["URL"] ?? "https://github.com/XIIIFOX/flutter_vless/releases/download/\(xrayReleaseTag)/XRay.xcframework.zip"' + '\n' +
                       'let xrayBinaryChecksum = env["CHECKSUM"] ?? xrayChecksum\n'
                       '.binaryTarget(name: "XRay", url: xrayBinaryURL, checksum: xrayBinaryChecksum)\n')
            if platform == 'ios':
                podspec = (f"xray_version = ENV['FLUTTER_VLESS_XRAY_VERSION'] || 'v{self.core}'\n"
                           f"xray_release_tag = ENV['FLUTTER_VLESS_XRAY_RELEASE_TAG'] || '{tag}'\n" +
                           'xray_url = ENV["URL"] || "https://github.com/XIIIFOX/flutter_vless/releases/download/#{xray_release_tag}/XRay.xcframework.zip"\n' +
                           f"xray_checksum = ENV['FLUTTER_VLESS_XRAY_CHECKSUM'] || '{checksum}'\n")
            else:
                podspec = (f'DEFAULT_FRAMEWORK_URL="https://github.com/XIIIFOX/flutter_vless/releases/download/{tag}/XRay.xcframework.zip"\n'
                           'FRAMEWORK_SHA256="${FLUTTER_VLESS_MACOS_FRAMEWORK_SHA256:-' + checksum + '}"\n')
            self.assert_apple_pins(platform, package, podspec)
            for stale in [package.replace(self.core, '26.10.29'), package.replace(self.core, self.core + '0'),
                          package.replace(checksum, 'b' * 64), package.replace(checksum, '0' * 64),
                          package.replace(r'\(xrayReleaseTag)', 'unused-release'),
                          package + f'let xrayReleaseTag = "{tag}"\n']:
                with self.subTest(platform=platform), self.assertRaises(AssertionError):
                    self.assert_apple_pins(platform, stale, podspec)
            for stale in [podspec.replace(self.core, '26.10.29'), podspec.replace(checksum, 'b' * 64)]:
                with self.subTest(platform=platform, consumer='podspec'), self.assertRaises(AssertionError):
                    self.assert_apple_pins(platform, package, stale)

    def assert_preview_commit(self, source, expected):
        self.assertRegex(expected, r'^[0-9a-f]{40}$')
        self.assertEqual(re.findall(r'\bconst val CORE_COMMIT = "([0-9a-f]{40})"', source), [expected],
                         'Android preview admission commit differs from its actual Core producer')

    def test_android_debug_preview_admission_matches_current_core(self):
        manifest = json.loads(self.read('third_party/xray-native-dns/pin-manifest.json'))
        for relative in [
            'nativeDnsPreview/kotlin/com/github/tfox/flutter_vless/xray/service/NativePreviewVpnSpec.kt',
            'nativeDnsPreviewTest/kotlin/com/github/tfox/flutter_vless/xray/service/NativePreviewRuntimeDeviceTest.kt',
        ]:
            with self.subTest(source=relative):
                self.assert_preview_commit(self.read('packages/flutter_vless_android/android/src/' + relative), manifest['core_commit'])

    def test_preview_commit_contract_rejects_stale_and_duplicate_admission(self):
        current = 'a' * 40
        source = f'const val CORE_COMMIT = "{current}"'
        self.assert_preview_commit(source, current)
        for stale in [source.replace(current, 'b' * 40), source + '\n' + source, source.replace('CORE_COMMIT', 'UNUSED_COMMIT')]:
            with self.subTest(source=stale), self.assertRaises(AssertionError):
                self.assert_preview_commit(stale, current)

    def test_selected_pub_versions_keep_plugin_and_native_build_numbers_separate(self):
        expected = {
            'pubspec.yaml': '1.1.7',
            'packages/flutter_vless_platform_interface/pubspec.yaml': '1.1.7',
            'packages/flutter_vless_android/pubspec.yaml': '1.1.7+1',
            'packages/flutter_vless_macos/pubspec.yaml': '1.1.7+1',
            'packages/flutter_vless_windows/pubspec.yaml': '1.1.7+1',
            'example/pubspec.yaml': '1.1.7+117',
        }
        for path, version in expected.items():
            with self.subTest(package=path):
                self.assertEqual(re.findall(r'^version:\s*([^\s]+)\s*$', self.read(path), re.M), [version])
                if path.startswith('packages/'):
                    changelog = path.replace('pubspec.yaml', 'CHANGELOG.md')
                    self.assertEqual(self.read(changelog).splitlines()[0], '## ' + version)
                    if version == '1.1.7+1':
                        # Keep the actual published predecessor beneath its new build.
                        headings = re.findall(r'^## ([^\n]+)$', self.read(changelog), re.M)
                        self.assertEqual(headings[:3], ['1.1.7+1', '1.1.7', '1.1.6'])

    def test_root_requires_new_implementation_builds_without_bumping_interface(self):
        source = self.read('pubspec.yaml')
        for implementation in ['android', 'macos', 'windows']:
            with self.subTest(package=implementation):
                # ^1.1.7 would still allow the already-published older wrapper.
                self.assertEqual(re.findall(
                    rf'^  flutter_vless_{implementation}:\s*([^\s]+)\s*$', source, re.M),
                    ['^1.1.7+1'])
                backend = self.read(f'packages/flutter_vless_{implementation}/pubspec.yaml')
                self.assertEqual(re.findall(
                    r'^  flutter_vless_platform_interface:\s*([^\s]+)\s*$', backend, re.M),
                    ['^1.1.7'])
        self.assertEqual(re.findall(
            r'^  flutter_vless_platform_interface:\s*([^\s]+)\s*$', source, re.M), ['^1.1.7'])


if __name__ == '__main__':
    unittest.main()
