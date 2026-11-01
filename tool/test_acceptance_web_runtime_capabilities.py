#!/usr/bin/env python3
"""SDK-free tests of the opted-in own-view snapshot capability metadata.

The Swift test executes the actual getter body against four independent stub
shim functions. It never imports, links or runs Xray, UIKit, Flutter or an app.
"""
import argparse
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--source', type=Path,
                    default=ROOT / 'example/ios/Runner/AcceptanceWebDiagnostics.swift')
options, remaining = parser.parse_known_args()
SOURCE = options.source.read_text()
CAPABILITIES = {
    'geodata_lifetime': 'FLVlessCoreGeodataLifetimeCapability',
    'xdrive_lifetime': 'FLVlessCoreXdriveLifetimeCapability',
    'vpn_routing': 'FLVlessCoreRoutingCapability',
    'darwin_interface_binding': 'FLVlessCoreDarwinInterfaceBindingCapability',
}


def body_after(marker):
    start = SOURCE.index(marker)
    opening = SOURCE.index('{', start)
    depth = 1
    for position in range(opening + 1, len(SOURCE)):
        depth += (SOURCE[position] == '{') - (SOURCE[position] == '}')
        if depth == 0:
            return SOURCE[opening + 1:position]
    raise AssertionError('Unterminated source block: ' + marker)


class SnapshotCapabilitiesTests(unittest.TestCase):
    def test_existing_qa_admission_and_zero_argument_snapshot(self):
        self.assertLess(SOURCE.index('#if FLUTTER_VLESS_ACCEPTANCE_TESTING'),
                        SOURCE.index('import flutter_vless_core_compat'))
        self.assertTrue(SOURCE.rstrip().endswith('#endif'))
        admitted = re.sub(r'\s+', '', body_after('private var admitted: Bool'))
        self.assertEqual(admitted,
                         'ProcessInfo.processInfo.arguments.contains('
                         '"--flutter-vless-acceptance-web-diagnostics")&&'
                         'Bundle.main.bundleIdentifier=="dev.tfox.flutterXrayExample"&&'
                         'UIApplication.shared.applicationState==.active&&'
                         'UIApplication.shared.isProtectedDataAvailable')
        self.assertRegex(SOURCE, r'case "snapshot" where call.arguments == nil '
                                r'\|\| call.arguments is NSNull:\s*'
                                r'self.snapshot\(result: result\)')
        self.assertEqual(re.findall(r'case "([^"]+)"', SOURCE),
                         ['available', 'navigate', 'openSafari', 'stop', 'snapshot',
                          'ownedManagerSafety'])

    def test_metadata_is_read_only_and_only_created_after_admission(self):
        snapshot = body_after('private func snapshot(result:')
        self.assertIn('guard admitted,', snapshot)
        save = body_after('private func save(image:')
        self.assertLess(save.index('guard admitted,'),
                        save.index('"runtime_capabilities": runtimeCapabilities()'))
        self.assertEqual(SOURCE.count('runtimeCapabilities()'), 2)
        getter = body_after('private func runtimeCapabilities() -> [String: Int]')
        calls = re.findall(r'\b(\w+)\s*\(', getter)
        self.assertEqual(set(calls), {'Int', *CAPABILITIES.values()})
        self.assertEqual(set(re.findall(r'"([^"]+)"\s*:', getter)), set(CAPABILITIES))

    def test_public_import_works_for_spm_and_pod_umbrella_and_fails_closed(self):
        imported = re.search(
            r'#if canImport\(flutter_vless_core_compat\)\n'
            r'import flutter_vless_core_compat\n#else\nimport flutter_vless\n#endif', SOURCE)
        self.assertIsNotNone(imported, 'QA must support both public module layouts')
        header = (ROOT / 'ios/flutter_vless/Sources/flutter_vless_core_compat/include/'
                  'FlutterVlessCoreCompat.h').read_text()
        declarations = []
        for symbol in CAPABILITIES.values():
            declaration = re.search(r'FOUNDATION_EXPORT\s+int64_t\s+' + re.escape(symbol)
                                    + r'\(void\);', header)
            self.assertIsNotNone(declaration, 'Public capability declaration required')
            declarations.append(declaration.group(0).replace('FOUNDATION_EXPORT', 'extern'))
        # CocoaPods exposes source headers in the named module by default.
        # Check that tracked contract even on a clean checkout without Pods.
        podspec = (ROOT / 'ios/flutter_vless.podspec').read_text()
        self.assertRegex(podspec, r"s\.name\s*=\s*'flutter_vless'")
        sources = re.search(r'^\s*s\.source_files\s*=([^\n]+)', podspec, re.MULTILINE)
        self.assertIsNotNone(sources, 'Tracked CocoaPods source declaration required')
        self.assertIn("'flutter_vless/Sources/flutter_vless_core_compat/**/*.{h,m}'",
                      sources.group(1))
        self.assertNotRegex(
            podspec,
            re.compile(r'^\s*s\.(?:module_name|private_header_files|exclude_files|public_header_files)\s*=',
                       re.MULTILINE),
            'A module or header-visibility override needs an explicit compatibility check')
        umbrella_path = (ROOT / 'example/ios/Pods/Target Support Files/flutter_vless/'
                         'flutter_vless-umbrella.h')
        if umbrella_path.exists():
            self.assertIn('#import "FlutterVlessCoreCompat.h"', umbrella_path.read_text())
        getter = body_after('private func runtimeCapabilities() -> [String: Int]')
        probe = ('#if FLUTTER_VLESS_ACCEPTANCE_TESTING\n' + imported.group(0)
                 + '\nprivate func runtimeCapabilities() -> [String: Int] {' + getter + '}\n'
                 + 'let values = runtimeCapabilities()\n'
                 + 'precondition(values == ["geodata_lifetime":1,"xdrive_lifetime":2,'
                   '"vpn_routing":1,"darwin_interface_binding":1])\n'
                 + 'print("QA_PUBLIC_MODULE_CAPS_PASS")\n#else\n'
                 + 'print("NORMAL_QA_EXCLUDED_PASS")\n#endif\n')
        with tempfile.TemporaryDirectory(prefix='flvless-public-modules-') as temporary:
            folder = Path(temporary)
            spm = folder / 'spm'
            headers = folder / 'pods/flutter_vless.framework/Headers'
            modules = headers.parent / 'Modules'
            for directory in (spm, headers, modules):
                directory.mkdir(parents=True, exist_ok=True)
            public_header = '#include <stdint.h>\n' + '\n'.join(declarations) + '\n'
            (spm / 'FlutterVlessCoreCompat.h').write_text(public_header)
            (headers / 'FlutterVlessCoreCompat.h').write_text(public_header)
            (headers / 'flutter_vless-umbrella.h').write_text('#import "FlutterVlessCoreCompat.h"\n')
            (spm / 'module.modulemap').write_text(
                'module flutter_vless_core_compat { header "FlutterVlessCoreCompat.h" export * }\n')
            (modules / 'module.modulemap').write_text(
                'framework module flutter_vless { umbrella header "flutter_vless-umbrella.h" export * }\n')
            shim = folder / 'shim.c'
            shim.write_text('#include <stdint.h>\n' + '\n'.join(
                f'int64_t {symbol}(void) {{ return {2 if key == "xdrive_lifetime" else 1}; }}'
                for key, symbol in CAPABILITIES.items()) + '\n')
            source = folder / 'probe.swift'
            source.write_text(probe)
            obj = folder / 'shim.o'
            built = subprocess.run(['clang', '-c', str(shim), '-o', str(obj)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr[-4000:])
            archived = subprocess.run(['ar', 'rcs', str(headers.parent / 'flutter_vless'), str(obj)],
                                      capture_output=True, text=True, timeout=15)
            self.assertEqual(archived.returncode, 0, archived.stderr[-4000:])
            cases = [('spm', ['-I', str(spm), str(obj)], True),
                     ('pods', ['-F', str(headers.parent.parent), '-framework', 'flutter_vless'], True),
                     ('missing', [], True), ('normal', [], False)]
            for name, arguments, enabled in cases:
                with self.subTest(module_layout=name):
                    binary = folder / ('probe-' + name)
                    command = ['swiftc', '-swift-version', '5', '-module-cache-path',
                               str(folder / ('modules-' + name))]
                    if enabled:
                        command += ['-D', 'FLUTTER_VLESS_ACCEPTANCE_TESTING']
                    result = subprocess.run(command + arguments + [str(source), '-o', str(binary)],
                                            capture_output=True, text=True, timeout=45)
                    if name == 'missing':
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('flutter_vless', result.stderr)
                        self.assertFalse(binary.exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                    self.assertEqual(result.stdout, 'QA_PUBLIC_MODULE_CAPS_PASS\n' if enabled
                                     else 'NORMAL_QA_EXCLUDED_PASS\n')

    def test_actual_swift_getter_preserves_all_independent_normalized_values(self):
        getter = body_after('private func runtimeCapabilities() -> [String: Int]')
        swift = ['var values: [String: Int64] = [:]',
                 'var calls: [String: Int] = [:]']
        for key, symbol in CAPABILITIES.items():
            swift.append(f'func {symbol}() -> Int64 {{ '
                         f'calls["{key}", default: 0] += 1; return values["{key}"]! }}')
        swift.append('private func runtimeCapabilities() -> [String: Int] {' + getter + '}')
        swift.append('for mask in 0..<16 {\n  calls = [:]\n  values = [:]')
        for index, key in enumerate(CAPABILITIES):
            accepted = 2 if key == 'xdrive_lifetime' else 1
            swift.append(f'  values["{key}"] = Int64(((mask >> {index}) & 1) * {accepted})')
        swift.append('  let actual = runtimeCapabilities()')
        swift.append('  precondition(actual.count == 4)')
        for key in CAPABILITIES:
            swift.append(f'  precondition(actual["{key}"] == Int(values["{key}"]!))')
            swift.append(f'  precondition(calls["{key}"] == 1)')
        swift.append('  precondition(calls.count == 4)\n}')
        swift.append('print("PASS: actual snapshot getter, 16 normalized states, four reads per state")')
        with tempfile.TemporaryDirectory(prefix='flvless-qa-caps-') as temporary:
            folder = Path(temporary)
            source = folder / 'probe.swift'
            binary = folder / 'probe'
            source.write_text('\n'.join(swift) + '\n')
            compiler = shutil.which('swiftc')
            self.assertIsNotNone(compiler, 'SDK-free Swift compiler required')
            compiled = subprocess.run([compiler, '-swift-version', '5',
                                       '-module-cache-path', str(folder / 'modules'),
                                       str(source), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=45)
            self.assertEqual(compiled.returncode, 0, compiled.stderr[-4000:])
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr[-4000:])
            self.assertEqual(result.stdout,
                             'PASS: actual snapshot getter, 16 normalized states, four reads per state\n')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining])
