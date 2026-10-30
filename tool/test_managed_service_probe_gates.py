"""Exercise the actual Apple runtime-log qualifiers without executing an SDK."""
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
MARKERS = ['APPLE_GEODATA_LIFETIME_CAPABILITY_PASS=1', 'APPLE_XDRIVE_LIFETIME_CAPABILITY_PASS=2']


class ManagedRuntimeProbeGates(unittest.TestCase):
    def qualifier(self, platform, text, required=True):
        path = ROOT / f'tool/test_{platform}_privacy_runtime.sh'
        source = path.read_text()
        begin = source.index("if os.environ.get('REQUIRE_MANAGED_SERVICE_LIFETIMES') == '1':")
        end = source.index("if os.environ.get('REQUIRE_DARWIN_INTERFACE_BINDING')", begin)
        exec(compile(source[begin:end], str(path), 'exec'), {
            'os': SimpleNamespace(environ={'REQUIRE_MANAGED_SERVICE_LIFETIMES': '1' if required else '0'}),
            'text': text,
        })

    def test_both_actual_values_required_once_on_both_platforms(self):
        for platform in ('ios', 'macos'):
            with self.subTest(platform=platform):
                self.qualifier(platform, '\n'.join(MARKERS))
                for bad in ['', MARKERS[0], MARKERS[1], '\n'.join(MARKERS + [MARKERS[0]]), '\n'.join(MARKERS).replace('PASS=1', 'PASS=0')]:
                    with self.assertRaises(AssertionError):
                        self.qualifier(platform, bad)
                self.qualifier(platform, '', required=False)

    def test_published_r2_xdrive_one_and_unknown_values_are_rejected(self):
        for platform in ('ios', 'macos'):
            for old_or_unknown in ('0', '1', '3', '-1'):
                with self.subTest(platform=platform, xdrive=old_or_unknown):
                    with self.assertRaises(AssertionError):
                        self.qualifier(platform, MARKERS[0] + '\nAPPLE_XDRIVE_LIFETIME_CAPABILITY_PASS=' + old_or_unknown)

    def test_fakedns_shortcut_keeps_the_real_value_probe(self):
        for platform in ('ios', 'macos'):
            source = (ROOT / f'tool/test_{platform}_privacy_runtime.sh').read_text()
            begin = source.index("harness = harness[:begin] + r'''func runModes() async {")
            end = source.index("''' + harness[end:]", begin)
            self.assertIn('requireManagedServiceLifetimeCapabilities()', source[begin:end])
            self.assertLess(source.index("if os.environ.get('REQUIRE_MANAGED_SERVICE_LIFETIMES')"), source.rindex("if os.environ.get('APPLE_RUNTIME_PROBE_MODE') == 'fakedns-only':"))
        self.assertIn('SIMCTL_CHILD_REQUIRE_MANAGED_SERVICE_LIFETIMES="${REQUIRE_MANAGED_SERVICE_LIFETIMES:-0}"',
                      (ROOT / 'tool/test_ios_privacy_runtime.sh').read_text())

    def test_swift_probe_calls_exports_with_exact_geo_one_and_xdrive_two(self):
        source = (ROOT / 'tool/fixtures/ios_privacy_probe.swift').read_text()
        begin = source.index('func requireManagedServiceLifetimeCapabilities() {')
        end = source.index('\n}\n', begin)
        body = source[begin:end]
        self.assertIn('FLVlessCoreGeodataLifetimeCapability() == 1', body)
        self.assertIn('FLVlessCoreXdriveLifetimeCapability() == 2', body)
        for marker in MARKERS:
            self.assertEqual(body.count(marker), 1)


if __name__ == '__main__':
    unittest.main()
