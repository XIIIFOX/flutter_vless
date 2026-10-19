#!/usr/bin/env python3
"""File-only command mocks for the opt-in Android routing CLI builder."""
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
VERSION = 'v1.260327.1-0.20261017152356-92ccc939aaf4'
CORE = 'github.com/xtls/xray-core'
MOBILE = 'github.com/EbrahimTahernejad/xray-mobile'
SUM = 'h1:fixture-core='
TAGS = 'flutter_vless_vpn_routing_cli,flutter_vless_vpn_routing'

GO = r'''
import json,os,pathlib,sys
p=pathlib.Path;a=sys.argv[1:];cwd=p.cwd()
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'go','args':a,'cwd':str(cwd),'arch':os.getenv('GOARCH'),'cc':os.getenv('CC'),'ldflags':os.getenv('LDFLAGS')})+'\n')
if a[:2]==['mod','download']:
 print(json.dumps({'Path':'github.com/xtls/xray-core','Version':os.environ.get('PIN_VERSION',os.environ['VERSION']),'Sum':os.environ.get('PIN_SUM',os.environ['SUM']),'Dir':os.environ['FAKE_CORE']}))
elif a==['env','GOMODCACHE']:
 print(str(p(os.environ['FAKE_CORE']).parent))
elif a[:2]==['mod','edit']:
 with (cwd/'go.mod').open('a') as f:
  for v in a[2:]:
   if v.startswith('-require='):f.write('\nrequire '+v.split('=',1)[1].replace('@',' ')+'\n')
   elif v.startswith('-replace='):f.write('\nreplace '+v.split('=',1)[1].replace('=',' => ',1)+'\n')
   else:raise SystemExit('unexpected edit')
elif a[:2]==['list','-m'] or a and a[0]=='list' and '-m' in a:
 module=a[-1];data={'Path':module,'Version':'v0.0.0' if module==os.environ['MOBILE'] else os.environ['VERSION']}
 for line in (cwd/'go.mod').read_text().splitlines():
  if line.startswith('replace '+module+' => '):data['Replace']={'Dir':line.split(' => ',1)[1]}
 if os.environ.get('WRONG_SELECTION'):data['Replace']={'Dir':'/wrong-copy'}
 print(json.dumps(data))
elif a and a[0]=='list':
 if os.environ.get('GRAPH_FAIL_STAGE')==cwd.name:
  print(os.environ['GRAPH_STDERR'],file=sys.stderr)
  raise SystemExit(int(os.environ.get('GRAPH_EXIT','1')))
 if os.environ.get('GRAPH_FAIL'):print('go: updates to go.mod needed; to update it:\n\tgo mod tidy');raise SystemExit(1)
elif a and a[0]=='build':
 if os.environ.get('EXPECT_ROUTING'):
  assert (cwd/'routing-applied').is_file() and (cwd/'protect-applied').is_file()
  assert (cwd/'go.mod').read_text().count('require '+os.environ['MOBILE']+' v0.0.0')==1
 output=p(a[a.index('-o')+1]);output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(b'inert fake ELF')
 if os.environ.get('MUTATE_INPUT'):p(os.environ['MUTATE_INPUT']).write_text('mock mutation')
 if os.environ.get('MUTATE_COPY'):(cwd/'routing-applied').write_text('changed copy')
else:raise SystemExit('unexpected go command')
'''

PROTECT = r'''
import pathlib,json,os,sys
root=pathlib.Path(sys.argv[1])
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'protect','root':str(root)})+'\n')
if os.environ.get('EXPECT_ROUTING'):assert (root/'routing-applied').is_file()
assert 'replace ' not in (root/'go.mod').read_text()
if os.environ.get('PROTECT_FAIL'):raise SystemExit(1)
(root/'protect-applied').write_text('H/P/D')
'''

ROUTING = r'''
import pathlib,shutil,json,os
def copy_and_apply(source,destination,**kwargs):
 source,destination=pathlib.Path(source),pathlib.Path(destination)
 with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'routing','source':str(source),'root':str(destination)})+'\n')
 assert not destination.exists()
 assert 'replace ' not in (source/'go.mod').read_text()
 shutil.copytree(source,destination);(destination/'routing-applied').write_text('routing')
 return destination
'''


def tree(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob('*') if p.is_file()}


class AndroidRoutingBuilderTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        android = self.root/'packages/flutter_vless_android/android'
        protect = android/'xray-protect';protect.mkdir(parents=True)
        self.script = android/'build_xray.sh'
        shutil.copyfile(ROOT/'packages/flutter_vless_android/android/build_xray.sh', self.script)
        (protect/'apply.py').write_text(PROTECT)
        (protect/'protect.go').write_text('package androidprotect\n')
        (protect/'main_android.go').write_text('package main\n')
        self.mobile = self.root/'third_party/xray-mobile';(self.mobile/'nativecli').mkdir(parents=True)
        (self.mobile/'go.mod').write_text('module '+MOBILE+'\nrequire '+CORE+' '+VERSION+'\n')
        (self.mobile/'go.sum').write_text(CORE+' '+VERSION+' '+SUM+'\n')
        (self.mobile/'mobile.go').write_text('package XRay\n')
        (self.mobile/'nativecli/nativecli.go').write_text('package nativecli\n')
        capability = self.root/'third_party/xray-vpn-routing';(capability/'overlay/main').mkdir(parents=True)
        (capability/'overlay/main/native_routing_cli.go').write_text('package main\n')
        (capability/'pin-manifest.json').write_text(json.dumps({'module':CORE,'module_version':VERSION,'module_sum':SUM,'core_commit':'92ccc939aaf4','capability':'native-vpn-routing-source-preview-v1'}))
        (capability/'apply.py').write_text(ROUTING)
        self.cache = self.root/'module-cache/Core';self.cache.mkdir(parents=True)
        (self.cache/'go.mod').write_text('module '+CORE+'\n')
        (self.cache/'go.sum').write_text('fixture sums\n')
        self.bin = self.root/'bin';self.bin.mkdir()
        go = self.bin/'go';go.write_text('#!'+sys.executable+'\n'+GO);go.chmod(0o755)
        self.ndk = self.root/'ndk'
        for host in ['darwin-x86_64','linux-x86_64']:
            b=self.ndk/'toolchains/llvm/prebuilt'/host/'bin';b.mkdir(parents=True)
            for target in ['aarch64-linux-android21','armv7a-linux-androideabi21','i686-linux-android21','x86_64-linux-android21']:
                (b/(target+'-clang')).write_text('inert compiler marker')
        self.calls = self.root/'calls.jsonl';self.output=self.root/'output with spaces'
        self.environment = dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],CALLS=str(self.calls),
                                VERSION=VERSION,SUM=SUM,MOBILE=MOBILE,FAKE_CORE=str(self.cache),
                                ANDROID_NDK_HOME=str(self.ndk),TARGET_DIR=str(self.output))
        self.environment.pop('XRAY_NATIVE_ROUTING',None)

    def run_builder(self, *, routing=False, **extra):
        env=dict(self.environment,**({'XRAY_NATIVE_ROUTING':'1','EXPECT_ROUTING':'1'} if routing else {}),**extra)
        return subprocess.run(['bash',str(self.script)],env=env,capture_output=True,text=True,timeout=20)

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def receipt(self):
        paths=list(self.output.glob('routing-preview-*.json'))
        self.assertEqual(len(paths),1)
        return json.loads(paths[0].read_text())

    def test_default_preserves_four_abis_flags_protect_and_no_routing(self):
        cache=tree(self.cache);result=self.run_builder()
        self.assertEqual(result.returncode,0,result.stderr)
        calls=self.recorded();builds=[c for c in calls if c['tool']=='go' and c['args'][0]=='build']
        self.assertEqual([c['arch'] for c in builds],['arm64','arm','386','amd64'])
        for c in builds:
            self.assertFalse(any(a.startswith('-tags') for a in c['args']))
            self.assertIn('-buildmode=pie',c['args']);self.assertIn('-Wl,-z,max-page-size=16384',c['ldflags'])
            self.assertEqual(Path(c['args'][c['args'].index('-o')+1]).name,'libxray.so')
        self.assertFalse(any(c['tool']=='routing' for c in calls))
        self.assertFalse(list(self.output.glob('routing-preview-*.json')));self.assertEqual(tree(self.cache),cache)

    def test_optin_composes_before_edits_and_uses_readonly_local_graph(self):
        original,cache=tree(self.mobile),tree(self.cache)
        result=self.run_builder(routing=True);self.assertEqual(result.returncode,0,result.stderr)
        calls=self.recorded();tools=[c['tool'] for c in calls]
        self.assertLess(tools.index('routing'),tools.index('protect'))
        edits=[i for i,c in enumerate(calls) if c['tool']=='go' and c['args'][:2]==['mod','edit']]
        self.assertTrue(edits);self.assertLess(tools.index('protect'),min(edits))
        builds=[c for c in calls if c['tool']=='go' and c['args'][0]=='build']
        self.assertEqual(len(builds),4)
        for c in builds:
            self.assertIn('-tags='+TAGS,c['args']);self.assertIn('-mod=readonly',c['args'])
            self.assertNotEqual(Path(c['cwd']),self.cache)
        self.assertFalse(any(c['tool']=='go' and c['args'][:2]==['mod','tidy'] for c in calls))
        receipt=self.receipt();self.assertTrue(receipt['success'])
        self.assertFalse(receipt['runtime_executed'] or receipt['published'])
        self.assertEqual(receipt['routing_tags'],TAGS.split(','))
        self.assertTrue(receipt['source_unchanged'] and receipt['module_cache_source_unchanged'] and receipt['copies_unchanged'])
        self.assertEqual(len(receipt['artifacts_sha256']),4)
        self.assertEqual(tree(self.mobile),original);self.assertEqual(tree(self.cache),cache)

    def test_optin_requires_explicit_target_before_go(self):
        self.environment.pop('TARGET_DIR')
        self.assertNotEqual(self.run_builder(routing=True).returncode,0)
        self.assertEqual(self.recorded(),[])

    def test_wrong_pin_or_checksum_refused_before_copy_or_build(self):
        for values in [{'PIN_VERSION':'wrong'},{'PIN_SUM':'wrong'}]:
            with self.subTest(values=values):
                result=self.run_builder(routing=True,**values)
                self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(c['tool'] in ['routing','protect'] or c.get('args',[None])[0]=='build' for c in self.recorded()))

    def test_mobile_pin_mismatch_refused_before_go(self):
        (self.mobile/'go.sum').write_text('wrong\n')
        self.assertNotEqual(self.run_builder(routing=True).returncode,0)
        self.assertEqual(self.recorded(),[])

    def test_protection_composition_failure_never_edits_or_builds(self):
        self.assertNotEqual(self.run_builder(routing=True,PROTECT_FAIL='1').returncode,0)
        self.assertFalse(any(c['tool']=='go' and c['args'][0] in ['build','list'] or c['tool']=='go' and c['args'][:2]==['mod','edit'] for c in self.recorded()))

    def test_readonly_failure_is_not_tidy_or_success(self):
        self.assertNotEqual(self.run_builder(routing=True,GRAPH_FAIL='1').returncode,0)
        self.assertFalse(any(c['tool']=='go' and (c['args'][0]=='build' or c['args'][:2]==['mod','tidy']) for c in self.recorded()))
        self.assertFalse(list(self.output.glob('routing-preview-*.json')))

    def test_failed_mobile_graph_surfaces_bounded_stderr_and_original_status(self):
        for message, absent in [('fixture-nativecli-graph-primary-error', ''),
                                ('private-prefix-not-replayed-' + 'x' * 20000 + '\nfixture-nativecli-graph-tail',
                                 'private-prefix-not-replayed-')]:
            with self.subTest(large=bool(absent)):
                result = self.run_builder(routing=True, GRAPH_FAIL_STAGE='mobile', GRAPH_EXIT='7', GRAPH_STDERR=message)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ROUTING_GRAPH_FAILURE stage=mobile exit=7', result.stderr)
                self.assertIn(message.splitlines()[-1], result.stderr)
                if absent:
                    self.assertNotIn(absent, result.stderr)
                    self.assertIn('tail_bytes=8192', result.stderr)
                self.assertIn('CalledProcessError', result.stderr)
                self.assertFalse(any(c['tool']=='go' and (c['args'][0]=='build' or c['args'][:2]==['mod','tidy']) for c in self.recorded()))
                self.assertFalse(list(self.output.glob('routing-preview-*.json')))

    def test_wrong_selected_module_copy_refused_before_build(self):
        self.assertNotEqual(self.run_builder(routing=True,WRONG_SELECTION='1').returncode,0)
        self.assertFalse(any(c['tool']=='go' and c['args'][0]=='build' for c in self.recorded()))

    def test_source_and_cache_mutations_never_publish_receipt(self):
        for target in [self.mobile/'mobile.go',self.cache/'go.mod',self.mobile/'new-source.go']:
            with self.subTest(target=target):
                self.assertNotEqual(self.run_builder(routing=True,MUTATE_INPUT=str(target)).returncode,0)
                self.assertFalse(list(self.output.glob('routing-preview-*.json')))

    def test_copy_mutation_and_empty_abi_selection_never_publish_receipt(self):
        self.assertNotEqual(self.run_builder(routing=True,MUTATE_COPY='1').returncode,0)
        self.assertFalse(list(self.output.glob('routing-preview-*.json')))
        self.calls.unlink()
        self.assertNotEqual(self.run_builder(routing=True,XRAY_BUILD_ARM64='0',XRAY_BUILD_ARMV7='0',
                                             XRAY_BUILD_X86='0',XRAY_BUILD_X86_64='0').returncode,0)
        self.assertFalse(any(c['tool']=='go' and c['args'][0]=='build' for c in self.recorded()))
        self.assertFalse(list(self.output.glob('routing-preview-*.json')))

    def test_single_abi_preserves_unknown_receipt(self):
        self.output.mkdir();prior=self.output/'routing-preview-keep.json';prior.write_text('unrelated receipt')
        result=self.run_builder(routing=True,XRAY_BUILD_ARM64='0',XRAY_BUILD_ARMV7='0',XRAY_BUILD_X86='0')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(prior.read_text(),'unrelated receipt')
        receipt=json.loads(next(p for p in self.output.glob('routing-preview-*.json') if p!=prior).read_text())
        self.assertEqual(receipt['selected_abis'],['x86_64'])
        self.assertEqual(list(receipt['artifacts_sha256']),['x86_64/libxray.so'])

    def test_optin_refuses_output_in_cache_or_source_before_writes(self):
        protected = [self.cache.parent, self.mobile, self.root/'third_party/xray-vpn-routing',
                     self.script.parent/'xray-protect']
        for directory in protected:
            with self.subTest(directory=directory):
                target = directory/'new-preview-output'
                before = tree(directory)
                result = self.run_builder(routing=True, TARGET_DIR=str(target))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(target.exists())
                self.assertEqual(tree(directory), before)
        self.assertFalse(any(c['tool'] in ['routing', 'protect'] or
                             c['tool']=='go' and c['args'][0]=='build'
                             for c in self.recorded()))

    def test_optin_resolves_output_symlink_before_cache_guard(self):
        target = self.root/'cache-alias'
        target.symlink_to(self.cache.parent, target_is_directory=True)
        before = tree(self.cache.parent)
        result = self.run_builder(routing=True, TARGET_DIR=str(target/'new-preview-output'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((target/'new-preview-output').exists())
        self.assertEqual(tree(self.cache.parent), before)
        self.assertFalse(any(c['tool']=='go' and c['args'][0]=='build' for c in self.recorded()))

    def test_optin_allows_explicit_official_output_directory(self):
        target = self.root/'android_runtime/xray_android/src/main/jniLibs'
        result = self.run_builder(routing=True, TARGET_DIR=str(target), XRAY_BUILD_ARM64='0',
                                  XRAY_BUILD_ARMV7='0', XRAY_BUILD_X86='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((target/'x86_64/libxray.so').is_file())
        self.assertEqual(len(list(target.glob('routing-preview-*.json'))), 1)

    def test_optin_refuses_selected_abi_or_binary_symlink_before_writes(self):
        self.output.mkdir()
        abi = self.output/'x86_64'
        for link_kind in ['directory', 'binary']:
            with self.subTest(link_kind=link_kind):
                if link_kind == 'directory':
                    abi.symlink_to(self.cache, target_is_directory=True)
                else:
                    abi.mkdir()
                    (abi/'libxray.so').symlink_to(self.mobile/'mobile.go')
                try:
                    before_cache, before_mobile = tree(self.cache), tree(self.mobile)
                    self.calls.unlink(missing_ok=True)
                    result = self.run_builder(routing=True, XRAY_BUILD_ARM64='0',
                                              XRAY_BUILD_ARMV7='0', XRAY_BUILD_X86='0')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(tree(self.cache), before_cache)
                    self.assertEqual(tree(self.mobile), before_mobile)
                    self.assertFalse(any(c['tool']=='go' and c['args'][0]=='build'
                                         for c in self.recorded()))
                finally:
                    if link_kind == 'directory':
                        abi.unlink()
                    else:
                        (abi/'libxray.so').unlink()
                        abi.rmdir()


if __name__ == '__main__':
    unittest.main()
