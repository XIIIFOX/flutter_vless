#!/usr/bin/env python3
"""File-only checks for the active runtime producer and example consumers."""
import ast
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


if __name__ == '__main__':
    unittest.main()
