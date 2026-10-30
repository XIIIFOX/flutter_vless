#!/usr/bin/env python3
"""File-only packaging controls; no Windows or Core executable is run."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import package_managed_runtime as subject


class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root/'runtime'; self.runtime.mkdir()
        self.output = self.root/'package'
        data = bytearray(128); data[:2] = b'MZ'; data[60:64] = (64).to_bytes(4, 'little'); data[64:70] = b'PE\x00\x00\x64\x86'
        (self.runtime/'xray.exe').write_bytes(data)
        for name in ('geoip.dat', 'geosite.dat'):
            source = self.root/'android_runtime/xray_android/src/main/assets'/name
            source.parent.mkdir(parents=True, exist_ok=True); source.write_bytes(b'full project data')
            (self.runtime/name).write_bytes(source.read_bytes())
        rows = [dict(host=host, actual=result, passed=True) for host in ('2ip.ru','2ip.io','myip.com') for result in ('DIRECT-FIXTURE','PROXY-FIXTURE')]
        rows += [dict(check='owned traffic counter sample', passed=True)]*2
        self.rows = self.runtime/'proxy-results.json'; self.rows.write_text(json.dumps(rows))
        for name in ('tool/windows/package_managed_runtime.py', 'tool/windows/test_package_managed_runtime.py',
                     '.github/workflows/windows-runtime.yml', 'tool/fixtures/xdrive-v26.10.29/LICENSE'):
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('source fixture')
        self.report = dict(success=True, source_snapshot_unchanged=True, module_cache_source_unchanged=True,
                           core_copy_unchanged=True, mobile_copy_unchanged=True, xdrive_lifetime_applied=True,
                           geodata_lifetime_applied=True, tags='flutter_vless_vpn_routing_cli,flutter_vless_vpn_routing,flutter_vless_managed_service_lifetimes',
                           goos='windows', goarch='amd64', artifact_sha256=subject.digest(self.runtime/'xray.exe'),
                           input_sha256={'fixture.py':'a'*64})
        self.producer = self.root/'producer.json'
        self.producer.write_text(json.dumps(self.report))
        self.capability = {'stage':'capabilities','code':0,'managed_service_lifetimes':3}

    def package(self):
        self.producer.write_text(json.dumps(self.report))
        with patch.object(subject, 'git_bindings') as binding, patch.object(subject, 'capabilities', return_value=self.capability) as probe:
            value = subject.package(self.runtime, self.producer, self.output, 'b'*40, self.root)
            self.assertEqual(binding.call_count, 2)
            probe.assert_called_once_with(self.runtime/'xray.exe')
            return value

    def test_exact_core_and_full_geodata_archive(self):
        value = self.package()
        self.assertTrue(value['success']); self.assertFalse(value['published'])
        self.assertEqual(value['runtime_revision'], '26.10.29-r2')
        with zipfile.ZipFile(self.output/value['archive']) as packed:
            self.assertEqual(set(packed.namelist()), {'xray.exe','geoip.dat','geosite.dat','LICENSE.xray-core'})
            for name in ('xray.exe','geoip.dat','geosite.dat'): self.assertEqual(packed.read(name), (self.runtime/name).read_bytes())

    def test_old_body_cannot_be_relabelled(self):
        (self.runtime/'xray.exe').write_bytes(b'old body')
        with self.assertRaisesRegex(ValueError, 'executable differs'): self.package()
        self.assertFalse(self.output.exists())

    def test_missing_managed_source_gate_refuses_before_packaging(self):
        self.report['xdrive_lifetime_applied'] = False
        with self.assertRaisesRegex(ValueError, 'Incomplete'): self.package()
        self.assertFalse(self.output.exists())

    def test_unqualified_routing_or_cleanup_refuses(self):
        self.rows.write_text('[{"passed":false}]')
        with self.assertRaisesRegex(ValueError, 'acceptance'): self.package()
        self.assertFalse(self.output.exists())

    def test_lite_or_mutated_geodata_is_not_packaged(self):
        (self.runtime/'geoip.dat').write_bytes(b'lite bundle')
        with self.assertRaisesRegex(ValueError, 'GeoDAT'): self.package()
        self.assertFalse(self.output.exists())

    def test_runtime_execution_is_never_available_on_this_host(self):
        with patch.object(subject.sys, 'platform', 'darwin'), patch.object(subject.subprocess, 'run', side_effect=AssertionError('must never run')):
            with self.assertRaisesRegex(ValueError, 'Windows CI'): subject.capabilities(self.runtime/'xray.exe')

    def test_capability_command_is_bounded_and_requires_both_services(self):
        from subprocess import CompletedProcess
        for payload in [b'{"stage":"capabilities","code":0,"managed_service_lifetimes":1}', b'{"stage":"capabilities","code":false,"managed_service_lifetimes":3}', b'{}', b'x'*4097]:
            with self.subTest(payload=payload[:50]), patch.object(subject.sys, 'platform', 'win32'), patch.object(subject.subprocess, 'run', return_value=CompletedProcess([],0,payload,b'')) as child:
                with self.assertRaises(ValueError): subject.capabilities(self.runtime/'xray.exe')
                self.assertEqual(child.call_args.kwargs['timeout'], 10)


if __name__ == '__main__': unittest.main()
