#!/usr/bin/env python3
"""Synthetic runner/copier controls only: never executes Go, Core or networking."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('vpn_routing_runner', Path(__file__).with_name('test_native_vpn_routing.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
applier = runner.load_module(runner.CAPABILITY / 'apply.py', 'routing_apply_guards')


class ApplyGuards(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, content='before\n'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target, overlay_root = root / 'source', root / 'copy', root / 'overlay-input'
            source.mkdir(); overlay = overlay_root / 'overlay/features/routing/native.go'
            overlay.parent.mkdir(parents=True); overlay.write_text('synthetic overlay\n')
            original = source / 'guarded.go'; original.write_text(content)
            manifest = {'upstream_sha256': {'guarded.go': runner.digest(original)}}
            with (mock.patch.object(applier, 'HERE', overlay_root),
                  mock.patch.object(applier, 'MANIFEST', manifest),
                  mock.patch.object(applier, 'patches', return_value=[('guarded.go', 'before\n', 'after\n')]),
                  mock.patch.object(applier, 'apply_classic_lifetime', create=True),
                  mock.patch.object(applier.subprocess, 'run', side_effect=AssertionError('No Go allowed in fake-copy guards'))):
                yield source, target, root, original

    def test_existing_or_symlink_destination_is_never_replaced(self):
        with self.fixture() as (source, target, root, original):
            target.mkdir(); (target / 'owned').write_text('retain')
            with self.assertRaisesRegex(ValueError, 'new'):
                applier.copy_and_apply(source, target, caches=[])
            self.assertEqual((target / 'owned').read_text(), 'retain')
            link = root / 'link'
            try:
                link.symlink_to(root / 'absent', target_is_directory=True)
            except OSError:
                return # Existing-directory refusal above remains exercised.
            with self.assertRaisesRegex(ValueError, 'new'):
                applier.copy_and_apply(source, link, caches=[])
            self.assertTrue(link.is_symlink())

    def test_module_cache_and_source_destinations_refuse_without_mutation(self):
        with self.fixture() as (source, target, root, original):
            before = runner.tree_snapshot(source)
            cache = root / 'custom-cache'
            for destination, caches in [(cache, [cache]), (cache / 'child', [cache]),
                                        (root / 'pkg/mod/child', []), (source / 'child', [])]:
                with self.subTest(destination=destination), self.assertRaises(ValueError):
                    applier.copy_and_apply(source, destination, caches=caches)
                self.assertFalse(destination.exists())
                self.assertEqual(runner.tree_snapshot(source), before)

    def test_wrong_pin_refuses_before_copy_and_keeps_source(self):
        with self.fixture() as (source, target, root, original):
            original.write_text('changed\n'); before = runner.tree_snapshot(source)
            with self.assertRaisesRegex(ValueError, 'Pinned source mismatch'):
                applier.copy_and_apply(source, target, caches=[])
            self.assertFalse(target.exists())
            self.assertEqual(runner.tree_snapshot(source), before)

    def test_replacements_must_match_exactly_once_even_when_hash_matches(self):
        for content in ['missing\n', 'before\nbefore\n']:
            with self.subTest(content=content), self.fixture(content) as (source, target, root, original):
                before = runner.tree_snapshot(source)
                with self.assertRaisesRegex(ValueError, 'replacement mismatch'):
                    applier.copy_and_apply(source, target, caches=[])
                self.assertFalse(target.exists())
                self.assertEqual(runner.tree_snapshot(source), before)

    def test_overlay_collision_and_source_symlink_refuse_before_copy(self):
        with self.fixture() as (source, target, root, original):
            collision = source / 'features/routing/native.go'
            collision.parent.mkdir(parents=True); collision.write_text('owned source')
            with self.assertRaisesRegex(ValueError, 'Overlay path already exists'):
                applier.copy_and_apply(source, target, caches=[])
            self.assertFalse(target.exists())
            collision.unlink()
            link = source / 'symlink'
            try:
                link.symlink_to(original)
            except OSError:
                return
            with self.assertRaisesRegex(ValueError, 'symlink'):
                applier.copy_and_apply(source, target, caches=[])
            self.assertFalse(target.exists())

    def test_positive_copy_patches_only_owned_copy(self):
        with self.fixture() as (source, target, root, original):
            before = runner.tree_snapshot(source)
            self.assertEqual(applier.copy_and_apply(source, target, caches=[]), target)
            self.assertEqual((target / 'guarded.go').read_text(), 'after\n')
            self.assertEqual((target / 'features/routing/native.go').read_text(), 'synthetic overlay\n')
            self.assertEqual(runner.tree_snapshot(source), before)
            self.assertEqual(original.read_text(), 'before\n')


class RunnerGuards(unittest.TestCase):
    def test_routing_and_classic_only_copies_apply_shared_lifetime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'; source.mkdir()
            (source / 'guarded.go').write_text('before\n')
            here = root / 'routing'; (here / 'overlay').mkdir(parents=True)
            calls = []
            def classic(copy):
                calls.append(copy)
                (copy / 'classic-proof').write_text('classic only')
            with mock.patch.object(applier, 'HERE', here), \
                    mock.patch.object(applier, 'MANIFEST', {'upstream_sha256': {'guarded.go': runner.digest(source / 'guarded.go')}}), \
                    mock.patch.object(applier, 'patches', return_value=[('guarded.go', 'before\n', 'after\n')]), \
                    mock.patch.object(applier, 'apply_classic_lifetime', side_effect=classic, create=True):
                routed = applier.copy_and_apply(source, root / 'routed', caches=[])
                self.assertEqual(calls, [routed])
                plain = applier.copy_and_apply_classic(source, root / 'plain', caches=[])
                self.assertEqual(calls, [routed, plain])
                self.assertEqual((plain / 'guarded.go').read_text(), 'before\n')
                self.assertEqual((routed / 'guarded.go').read_text(), 'after\n')
                self.assertEqual((source / 'guarded.go').read_text(), 'before\n')

    def test_child_environment_is_local_and_browser_dialer_cannot_initialize(self):
        parent = {'XRAY_BROWSER_DIALER': '127.0.0.1:1', 'xray.browser.dialer': '127.0.0.1:2',
                  'XrAy_Unknown': 'private', 'GOTOOLCHAIN': 'auto', 'GOWORK': '/foreign', 'KEEP': 'yes'}
        before = dict(parent); child = runner.child_environment(parent)
        self.assertEqual(parent, before)
        self.assertEqual(child, {'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'KEEP': 'yes',
                                 'XRAY_BROWSER_DIALER': '', 'xray.browser.dialer': ''})

    def test_runtime_needs_both_explicit_ci_flags(self):
        for environment in [{}, {'CI':'true'}, {'GITHUB_ACTIONS':'true'}, {'CI':'false','GITHUB_ACTIONS':'true'}]:
            self.assertFalse(runner.runtime_authorized(environment))
        self.assertTrue(runner.runtime_authorized({'CI':'true','GITHUB_ACTIONS':'true'}))
        with mock.patch.object(runner, 'runtime_authorized', return_value=False), mock.patch.object(runner, 'checked') as checked:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.main(['--run-runtime'])
            checked.assert_not_called()

    def test_mobile_pin_requires_version_and_actual_module_checksum(self):
        manifest = {'module':'synthetic.invalid/core', 'module_version':'v1.0.0', 'module_sum':'h1:correct'}
        module = 'module host\nrequire synthetic.invalid/core v1.0.0\n'
        sums = 'synthetic.invalid/core v1.0.0 h1:correct\n'
        runner.validate_mobile_pin(manifest, module, sums)
        for mod, checksum in [(module.replace('v1.0.0','v2.0.0'),sums), (module,sums.replace('correct','wrong')),
                              (module,'synthetic.invalid/core v1.0.0/go.mod h1:correct\n')]:
            with self.assertRaises(ValueError):runner.validate_mobile_pin(manifest, mod, checksum)

    def test_download_metadata_cannot_retarget_or_hide_checksum_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = {'module':'synthetic.invalid/core','module_version':'v1.0.0','module_sum':'h1:correct'}
            value = {'Path':manifest['module'],'Version':manifest['module_version'],'Sum':manifest['module_sum'],'Dir':temporary}
            self.assertEqual(runner.validate_metadata(manifest,value),Path(temporary).resolve())
            for key in ['Path','Version','Sum','Error']:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    runner.validate_metadata(manifest,{**value,key:'wrong'})

    def test_default_selection_excludes_runtime_and_children_and_anchors_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); package=root/'app/dispatcher';package.mkdir(parents=True)
            (package/'selected_test.go').write_text('func TestNativeVPNRoutingPure(t *testing.T) {}\nfunc TestNativeVPNRoutingRuntime(t *testing.T) {}\nfunc TestNativeVPNRoutingRuntimeChild(t *testing.T) {}\nfunc TestOther(t *testing.T) {}\n')
            selected=runner.selected_tests(root,'app/dispatcher')
            self.assertEqual(selected,['TestNativeVPNRoutingPure'])
            self.assertEqual(runner.test_pattern(selected),'^(TestNativeVPNRoutingPure)$')
            self.assertEqual(runner.selected_tests(root,'app/dispatcher',runtime=True),[runner.RUNTIME_TEST,runner.RUNTIME_TEST+'Child'])
            (package/'selected_test.go').write_text('func TestOther(t *testing.T) {}\n')
            for runtime in [False,True]:
                with self.assertRaises(ValueError):runner.selected_tests(root,'app/dispatcher',runtime=runtime)

    def test_success_markers_must_name_every_selected_top_level_test(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runner,'EVIDENCE',Path(temporary)):
            path=Path(temporary)/'pure.log'
            for text in ['PASS\n','testing: warning: no tests to run\nPASS\n','--- SKIP: TestNativeRoutingA (0.0s)\nPASS\n','--- PASS: TestNativeRoutingA/subcase (0.0s)\nPASS\n']:
                path.write_text(text)
                with self.assertRaises(RuntimeError):runner.require_pass('pure',['TestNativeRoutingA'],[{}])
            path.write_text('--- PASS: TestNativeRoutingA (0.0s)\n')
            with self.assertRaises(RuntimeError):runner.require_pass('pure',['TestNativeRoutingA','TestNativeRoutingB'],[{}])
            result=[{}];runner.require_pass('pure',['TestNativeRoutingA'],result)
            self.assertTrue(result[0]['selected_test_pass'])

    def test_main_pure_commands_are_exact_and_source_cache_mutation_cannot_pass(self):
        for mutate in [False,True]:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);evidence=root/'evidence';source=root/'cache/module';source.mkdir(parents=True)
                (source/'guarded.go').write_text('original\n')
                mobile=root/'mobile';mobile.mkdir();(mobile/'go.mod').write_text('require synthetic.invalid/core v1.0.0\n');(mobile/'go.sum').write_text('synthetic.invalid/core v1.0.0 h1:correct\n')
                cap=root/'cap';cap.mkdir();manifest={'capability':'synthetic','core_commit':'synthetic','module':'synthetic.invalid/core','module_version':'v1.0.0','module_sum':'h1:correct','upstream_sha256':{'guarded.go':runner.digest(source/'guarded.go')}}
                (cap/'pin-manifest.json').write_text(json.dumps(manifest))
                for name,package in runner.PACKAGES:
                    folder=cap/'overlay'/package;folder.mkdir(parents=True)
                    (folder/'pure_test.go').write_text('func TestNativeRouting'+name+'(t *testing.T) {}\nfunc TestNativeVPNRoutingRuntime(t *testing.T) {}\n')
                tool=root/'tools';tool.mkdir();go=tool/('go.exe' if os.name=='nt' else 'go');go.write_text('fake');go.with_name('gofmt.exe' if os.name=='nt' else 'gofmt').write_text('fake')
                commands=[]
                def checked(name, command, **kwargs):
                    commands.append(command);kwargs['results'].append({'name':name,'exit_code':0})
                    text=''
                    if name=='core-pin':text=json.dumps({'Path':manifest['module'],'Version':manifest['module_version'],'Sum':manifest['module_sum'],'Dir':str(source)})
                    if name=='module-cache':text=str(root/'cache')
                    if name.endswith('-pure'):
                        key=name.removesuffix('-pure');text='--- PASS: TestNativeRouting'+key+' (0.0s)\n'
                        if mutate:(source/'guarded.go').write_text('changed cache')
                    (evidence/(name+'.log')).write_text(text)
                fake=mock.Mock()
                def copy(src,dst,**kwargs):
                    shutil.copytree(src,dst)
                    for path in (cap/'overlay').rglob('*.go'):
                        dest=dst/path.relative_to(cap/'overlay');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
                fake.copy_and_apply.side_effect=copy;fake.patches.return_value=[('guarded.go','original','patched')]
                with (mock.patch.object(runner,'EVIDENCE',evidence),mock.patch.object(runner,'CAPABILITY',cap),
                      mock.patch.object(runner,'MOBILE',mobile),mock.patch.object(runner,'source_snapshot',return_value={'synthetic':'snapshot'}),
                      mock.patch.object(runner,'load_module',return_value=fake),mock.patch.object(runner,'checked',side_effect=checked),
                      mock.patch.object(runner.sys,'stderr',io.StringIO())):
                    status=runner.main(['--go',str(go)])
                report=json.loads((evidence/'result.json').read_text())
                self.assertEqual(status,1 if mutate else 0)
                self.assertEqual(report['success'],not mutate)
                self.assertEqual(report['module_cache_source_unchanged'],not mutate)
                selections=[cmd[cmd.index('-test.run')+1] for cmd in commands if '-test.run' in cmd]
                self.assertEqual(selections,['^(TestNativeRouting'+name+')$' for name,_ in runner.PACKAGES])
                self.assertFalse(any(runner.RUNTIME_TEST in value for value in selections))
                fmt=next(command for command in commands if command[0].endswith(('gofmt','gofmt.exe')))
                self.assertTrue(all(str(evidence/'Core') in p for p in fmt[2:]))


    @unittest.skipIf(os.name == 'nt', 'Cooperative POSIX signal control')
    def test_signal_reaps_only_owned_harmless_child_before_recording_interruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / 'evidence'; output.mkdir()
            go = root / 'go'; go.write_text('synthetic toolchain')
            go.with_name('gofmt').write_text('synthetic formatter')
            pidfile = root / 'child.pid'
            module = str(Path(runner.__file__).resolve())
            program = """import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('signal_routing_runner',sys.argv[1])
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
r.EVIDENCE=Path(sys.argv[2]);r.source_snapshot=lambda: {'synthetic':'fixed'}
r.selected_tests=lambda *args,**kwargs: ['TestNativeRoutingSynthetic']
owned=r.checked
child="import os,time;from pathlib import Path;Path("+repr(sys.argv[4])+").write_text(str(os.getpid()));time.sleep(30)"
def harmless(name,command,**kwargs):
    return owned(name,[sys.executable,'-c',child],**kwargs)
r.checked=harmless
raise SystemExit(r.main(['--go',sys.argv[3]]))
"""
            with (root / 'runner.log').open('wb') as log:
                process = subprocess.Popen([sys.executable,'-c',program,module,str(output),str(go),str(pidfile)],
                                           stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                child = None
                try:
                    deadline = time.monotonic()+5
                    while not pidfile.exists() and time.monotonic()<deadline and process.poll() is None:
                        time.sleep(.01)
                    self.assertTrue(pidfile.exists(),(root/'runner.log').read_text())
                    child = int(pidfile.read_text())
                    process.send_signal(signal.SIGTERM)
                    self.assertEqual(process.wait(timeout=10),128+signal.SIGTERM)
                    result = json.loads((output/'result.json').read_text())
                    self.assertFalse(result['success']); self.assertEqual(result['signal'],signal.SIGTERM)
                    with self.assertRaises(ProcessLookupError):os.kill(child,0)
                    self.assertFalse((output/'Core').exists())
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid,signal.SIGKILL)
                    process.wait(timeout=3)
                    if child is not None:
                        try:os.killpg(child,signal.SIGKILL)
                        except ProcessLookupError:pass


if __name__=='__main__':
    unittest.main()
