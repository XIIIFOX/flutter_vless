#!/usr/bin/env python3
"""File-only command mocks for the optional Apple routing framework builder."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION = json.loads((ROOT / 'third_party/xray-vpn-routing/pin-manifest.json').read_text())['module_version']
MODULE = 'github.com/xtls/xray-core'
CHECKSUM = 'h1:fixture-core-sum='

GO = r'''
import json,os,pathlib,sys
a=sys.argv[1:];p=pathlib.Path
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'go','args':a,'cwd':os.getcwd()})+'\n')
if a==['env','GOVERSION']: print(os.environ.get('MOCK_GO_VERSION','go1.27.3'))
elif a[:2]==['mod','download']:
 print(json.dumps({'Path':'github.com/xtls/xray-core','Version':os.environ['PIN_VERSION'],'Sum':os.environ.get('PIN_SUM','h1:fixture-core-sum='),'Dir':os.environ['FAKE_CORE']}))
elif a[:2]==['mod','edit']:
 target=next((x.split('=',1)[1] for x in a if x.startswith('-modfile=')),str(p.cwd()/'go.mod'))
 replacement=next(x.split('=',1)[1] for x in a if x.startswith('-replace='))
 module,directory=replacement.split('=',1)
 with open(target,'a') as f:f.write('\nreplace '+module+' => '+directory+'\n')
elif a and a[0]=='build':
 output=p(a[a.index('-o')+1]);output.parent.mkdir(parents=True,exist_ok=True)
 output.write_text(p(os.environ['MOCK_GOMOBILE']).read_text() if output.name=='gomobile' else '#!/bin/sh\nexit 0\n');output.chmod(0o755)
elif a[:2]==['list','-m']:
 if '-json' not in a: print(os.environ['PIN_VERSION'])
 else:
  data={'Path':'github.com/xtls/xray-core','Version':os.environ['PIN_VERSION']}
  for line in (p.cwd()/'go.mod').read_text().splitlines():
   if line.startswith('replace github.com/xtls/xray-core => '):data['Replace']={'Dir':line.split(' => ',1)[1]}
  print(json.dumps(data))
else:raise SystemExit('Unexpected mock go command')
'''

GOMOBILE = r'''
import json,os,pathlib,sys
a=sys.argv[1:];p=pathlib.Path
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'gomobile','args':a,'cwd':os.getcwd()})+'\n')
output=p(a[a.index('-o')+1]);fw=output/('macos-arm64_x86_64' if '-target=macos' in a else 'ios-arm64')/'XRay.framework'
(fw/'Headers').mkdir(parents=True);(fw/'XRay').write_text('inert archive')
names=['XRayCheckPrivate','XRayDarwinInterfaceBindingCapability','XRayXdriveLifetimeCapability','XRayGeodataLifetimeCapability']
if any(x.startswith('-tags=') and 'flutter_vless_vpn_routing' in x.split('=',1)[1].split(',') for x in a):names+=['XRayRoutingCapability','XRayCheckRoutingPrivate','XRayStartRoutingPrivate']
if os.environ.get('MISSING_SYMBOL'):names.remove('XRayStartRoutingPrivate')
(fw/'Headers'/'XRay.objc.h').write_text('\n'.join(names))
if os.environ.get('MUTATE_INPUT'):p(os.environ['MUTATE_INPUT']).write_text('changed during mock compile')
'''

XCODEBUILD = r'''
import pathlib,shutil,sys
a=sys.argv[1:];output=pathlib.Path(a[a.index('-output')+1]);output.mkdir(parents=True)
shutil.copytree(a[a.index('-headers')+1],output/'Headers')
'''


class ApplePreviewBuilderTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'tool').mkdir()
        self.script = self.root / 'tool/build_apple_core_preview.sh'
        shutil.copyfile(ROOT / 'tool/build_apple_core_preview.sh', self.script)
        self.mobile = self.root / 'third_party/xray-mobile'
        self.mobile.mkdir(parents=True)
        (self.mobile / 'go.mod').write_text('module fixture.mobile\n\ngo 1.27\nrequire '+MODULE+' '+VERSION+'\n')
        (self.mobile / 'go.sum').write_text(MODULE+' '+VERSION+' '+CHECKSUM+'\n')
        (self.mobile / 'main.go').write_text('package XRay\n')
        capability = self.root / 'third_party/xray-vpn-routing'
        (capability / 'overlay/core').mkdir(parents=True)
        (capability / 'overlay/core/routing.go').write_text('package core\n')
        (capability / 'pin-manifest.json').write_text(json.dumps({'module':MODULE,'module_version':VERSION,'module_sum':CHECKSUM,'core_commit':'92ccc939aaf4','capability':'fixture-routing'}))
        (capability / 'apply.py').write_text('import pathlib,shutil\ndef copy_and_apply(source,destination,**kwargs):\n if pathlib.Path(destination).exists(): raise ValueError("Destination must be new")\n return pathlib.Path(shutil.copytree(source,destination))\n')
        with (capability / 'apply.py').open('a') as out:
            out.write('def copy_and_apply_classic(source,destination,**kwargs):\n return copy_and_apply(source,destination,**kwargs)\n')
            out.write('def copy_and_apply_lifetimes(source,destination,**kwargs):\n assert kwargs.get("routing",False) is False\n result=copy_and_apply(source,destination,**kwargs)\n (result/"h3-applied").write_text("h3")\n return result\n')
        classic = self.root / 'third_party/xray-native-dns'
        (classic / 'overlay/app/dns').mkdir(parents=True)
        for name in ('classic_lifetime_patch.py', 'h3_lifetime_patch.py', 'darwin_interface_bind_patch.py', 'xdrive_lifetime_patch.py', 'geodata_lifetime_patch.py', 'pin-manifest.json', 'overlay/main/native_services_cli.go', 'overlay/transport/internet/xdrive/native_lifetime.go', 'overlay/app/dns/native_classic_lifetime.go', 'overlay/app/dns/native_classic_lifetime_test.go'):
            (classic / name).parent.mkdir(parents=True,exist_ok=True)
            (classic / name).write_text('shared-classic-fixture')
        self.core = self.root / 'module-cache/core'
        self.core.mkdir(parents=True)
        (self.core / 'go.mod').write_text('module '+MODULE+'\n')
        self.bin = self.root / 'bin'; self.bin.mkdir()
        self.mock_mobile = self.root / 'gomobile-template'
        self.mock_mobile.write_text('#!'+sys.executable+'\n'+GOMOBILE)
        for name, body in [('go',GO),('xcodebuild',XCODEBUILD)]:
            path=self.bin/name; path.write_text('#!'+sys.executable+'\n'+body);path.chmod(0o755)
        self.calls = self.root / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'], CALLS=str(self.calls),
                        PIN_VERSION=VERSION, FAKE_CORE=str(self.core), MOCK_GOMOBILE=str(self.mock_mobile))
        self.output = self.root / 'output with spaces'

    def run_builder(self, *args, environment=None):
        return subprocess.run(['bash',str(self.script),*map(str,args)],env=environment or self.env,
                              capture_output=True,text=True,timeout=15)

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_old_root_CA_toolchain_refused_before_source_copy(self):
        env = dict(self.env, MOCK_GO_VERSION='go1.27.2')
        result = self.run_builder('ios', self.output, '--vpn-routing', environment=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Go 1.27.3', result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual([call['args'] for call in self.recorded()], [['env', 'GOVERSION']])

    def test_default_uses_combined_lifetime_disposable_core_without_routing_tag(self):
        result=self.run_builder('ios',self.output)
        self.assertEqual(result.returncode,0,result.stderr)
        calls=self.recorded(); bind=next(c for c in calls if c['tool']=='gomobile')
        self.assertEqual(bind['cwd'],str(self.output/'classic/mobile'))
        self.assertIn('-tags=flutter_vless_darwin_interface_binding,flutter_vless_managed_service_lifetimes',bind['args'])
        self.assertEqual(json.loads((self.output/'preview.json').read_text()),{'platform':'ios','core':VERSION,'preflightABI':1,'published':False})
        self.assertFalse((self.output/'routing').exists())
        receipt=json.loads((self.output/'classic-preview.json').read_text())
        self.assertTrue(receipt['classic_dns_lifetime_applied'])
        self.assertTrue((self.output/'classic/Core/h3-applied').is_file())
        self.assert_lifetime_receipt(receipt)
        self.assertEqual(receipt['routing_capability_expected'],0)
        self.assertIn('third_party/xray-native-dns/classic_lifetime_patch.py',receipt['source_sha256'])

    def test_optional_build_uses_disposable_module_and_tag(self):
        original={p.name:p.read_bytes() for p in self.mobile.iterdir()}
        cached=(self.core/'go.mod').read_bytes()
        result=self.run_builder('ios',self.output,'--vpn-routing')
        self.assertEqual(result.returncode,0,result.stderr)
        bind=next(c for c in self.recorded() if c['tool']=='gomobile')
        self.assertEqual(bind['cwd'],str(self.output/'routing/mobile'))
        self.assertIn('-tags=flutter_vless_vpn_routing,flutter_vless_darwin_interface_binding,flutter_vless_managed_service_lifetimes',bind['args'])
        receipt=json.loads((self.output/'routing-preview.json').read_text())
        self.assertTrue(receipt['success']);self.assertEqual(receipt['routing_capability_expected'],1)
        self.assertFalse(receipt['runtime_executed'])
        self.assertEqual(receipt['core_replacement'],str(self.output/'routing/Core'))
        self.assertTrue(receipt['source_unchanged'] and receipt['module_cache_source_unchanged'] and receipt['copies_unchanged'])
        self.assertTrue(receipt['classic_dns_lifetime_applied'])
        self.assert_lifetime_receipt(receipt)
        self.assertIn('third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime.go',receipt['source_sha256'])
        self.assertEqual(original,{p.name:p.read_bytes() for p in self.mobile.iterdir()})
        self.assertEqual(cached,(self.core/'go.mod').read_bytes())

    def assert_lifetime_receipt(self, receipt):
        key = 'third_party/xray-native-dns/h3_lifetime_patch.py'
        self.assertIs(receipt['h3_lifetime_applied'], True)
        self.assertIs(receipt['darwin_interface_binding_source_applied'],True)
        self.assertEqual(receipt['darwin_interface_binding_capability_expected'],1)
        self.assertEqual(receipt['darwin_interface_binding_patch_sha256'],hashlib.sha256((self.root/'third_party/xray-native-dns/darwin_interface_bind_patch.py').read_bytes()).hexdigest())
        self.assertEqual(receipt['lifetime_patch_scope'], ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'])
        self.assertEqual(receipt['h3_lifetime_patch_sha256'], hashlib.sha256((self.root/key).read_bytes()).hexdigest())
        self.assertEqual(receipt['source_sha256'][key], receipt['h3_lifetime_patch_sha256'])

    def test_h3_patch_mutation_prevents_both_build_modes_success(self):
        helper = self.root/'third_party/xray-native-dns/h3_lifetime_patch.py'
        for routing in (False, True):
            with self.subTest(routing=routing):
                helper.write_text('shared-classic-fixture')
                output = self.root/('mutated-routing' if routing else 'mutated-ordinary')
                args = ('ios', output, '--vpn-routing') if routing else ('ios', output)
                result = self.run_builder(*args, environment=dict(self.env, MUTATE_INPUT=str(helper)))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output/('routing-preview.json' if routing else 'classic-preview.json')).exists())

    def test_optional_macos_preserves_static_xcframework_layout(self):
        result=self.run_builder('macos',self.output,'--vpn-routing')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.output/'libXRay.a').is_file())
        self.assertTrue((self.output/'XRay.xcframework/Headers/XRay.objc.h').is_file())

    def test_invalid_arguments_fail_before_build_or_output(self):
        for args in [[],['ios'],['unknown',self.output],['ios',self.output,'--unknown'],['--vpn-routing','ios',self.output],['ios',self.output,'--vpn-routing','extra']]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_builder(*args).returncode,0)
        self.assertEqual(self.recorded(),[]);self.assertFalse(self.output.exists())

    def test_existing_framework_is_never_replaced(self):
        target=self.output/'XRay.xcframework';target.mkdir(parents=True)
        (target/'keep').write_text('previous')
        self.assertNotEqual(self.run_builder('ios',self.output,'--vpn-routing').returncode,0)
        self.assertEqual((target/'keep').read_text(),'previous');self.assertEqual(self.recorded(),[])

    def test_wrong_module_checksum_fails_before_compile(self):
        result=self.run_builder('ios',self.output,'--vpn-routing',environment=dict(self.env,PIN_SUM='wrong'))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(c['args'][0]=='build' for c in self.recorded()))
        self.assertFalse((self.output/'routing-preview.json').exists())

    def test_missing_routing_header_never_has_success_receipt(self):
        result=self.run_builder('ios',self.output,'--vpn-routing',environment=dict(self.env,MISSING_SYMBOL='1'))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.output/'routing-preview.json').exists())

    def test_source_mutation_during_mock_compile_is_detected(self):
        result=self.run_builder('ios',self.output,'--vpn-routing',environment=dict(self.env,MUTATE_INPUT=str(self.mobile/'main.go')))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.output/'routing-preview.json').exists())

    def test_module_cache_mutation_during_mock_compile_is_detected(self):
        result=self.run_builder('ios',self.output,'--vpn-routing',environment=dict(self.env,MUTATE_INPUT=str(self.core/'go.mod')))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.output/'routing-preview.json').exists())

    def test_shared_classic_helper_mutation_prevents_ordinary_success(self):
        helper=self.root/'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime.go'
        result=self.run_builder('ios',self.output,environment=dict(self.env,MUTATE_INPUT=str(helper)))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.output/'classic-preview.json').exists())


if __name__ == '__main__':
    unittest.main()
