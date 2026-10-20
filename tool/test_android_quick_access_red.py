#!/usr/bin/env python3
"""CI-only actual a137 Android stale-tile assertion, reusing one already-built AAR.
No Core/SDK/AAR producer is called. Import/self-tests never run child commands.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

BASELINE='a137971a04aeb37f81178a89af03b175867fc42c'
VERSION='26.10.17-protect1'
EXPECTED_FIXTURE_SHA256='3eca885e94128dfd08b5c7a692b3a9fcf72cc0fe440f2a304aa77ebf806c33fc'
TEST_CLASS='com.github.tfox.flutter_vless.xray.service.QuickAccessPreflightRaceTest'
TEST_METHOD='disabledTileDuringActualFinalPreflightCannotSaveOrReplaceSession'
ASSERTION='Historical implementation admits stale tile after disable'
FIXTURE=Path('packages/flutter_vless_android/android/src/test/kotlin/com/github/tfox/flutter_vless/xray/service/QuickAccessPreflightRaceTest.kt')
RESULT_XML=Path('example/build/flutter_vless_android/test-results/testDebugUnitTest')/('TEST-'+TEST_CLASS+'.xml')
RUNTIME=Path('android_runtime/xray_android')
COMPONENT=Path('dev/tfox/fluttervless/xray-android')/VERSION
PRODUCER_FORBIDDEN='build_android_runtime_maven.sh'
BASELINE_SOURCE_SHA256={'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/NativeQuickAccess.kt': 'f012c3ba4b752e834bb0b8caa888dd7dbdc45dfee747675d6938c84529f35841', 'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/VlessTilePermissionActivity.kt': '73673fcefc56603c8da007f2ccecce2333409e646797954033dc71cb5550aeba', 'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/VlessTileService.kt': '07ba535c98fdfaccad133699fca00710c6719962204940985c36632df0c8fb52', 'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/xray/core/XrayCoreManager.kt': 'dea63444686a9789157a425972e29d881bcf2c5ffbe1ece6a23171113dfc448b', 'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/xray/service/AuthorizedProfileStore.kt': '38b23f78f7c849543b44c5ae4f7853eec198a486ace32e4efb2ec76c9ecc8dfe', 'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/xray/service/NativeOptionsStore.kt': '39edf763686fa8e0230a624765bf15ad369ca39ad0f0c114c9ebbb5b45a40cfb', 'packages/flutter_vless_android/android/src/main/kotlin/com/github/tfox/flutter_vless/xray/service/XrayVPNService.kt': 'fe6402ef1888a12a9665fd8abcfc98a6b0aff9fa97578b1eaf1d82779369e8e7'}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def admit(run_ci,env):
    if not run_ci or env.get('GITHUB_ACTIONS')!='true' or env.get('RUNNER_OS')!='Linux' or not re.fullmatch('[0-9a-f]{40}',env.get('GITHUB_SHA','')):
        raise ValueError('CI-only explicit Actions Linux admission required')

def classify(xml,returncode):
    if returncode!=1:raise ValueError('baseline must finish Gradle with its normal failed-test exit; not infrastructure/kill/success')
    if not xml.is_file() or xml.is_symlink() or xml.stat().st_size>1024*1024:raise ValueError('fresh bounded JUnit proof missing')
    root=ET.parse(xml).getroot()
    cases=list(root.iter('testcase'))
    if root.tag!='testsuite' or root.get('tests')!='1' or root.get('failures')!='1' or root.get('errors')!='0' or root.get('skipped')!='0' or len(cases)!=1:
        raise ValueError('semantic RED requires exactly one failed assertion, no error/skip/extra case')
    case=cases[0];failures=case.findall('failure')
    if case.get('classname')!=TEST_CLASS or case.get('name')!=TEST_METHOD or len(failures)!=1 or case.find('error') is not None or case.find('skipped') is not None:
        raise ValueError('wrong selected baseline test outcome')
    failure=failures[0]
    if failure.get('type')!='java.lang.AssertionError' or failure.get('message')!=ASSERTION or TEST_CLASS not in (failure.text or ''):
        raise ValueError('compile/infra/wrong assertion is not semantic RED')
    return {'class':TEST_CLASS,'method':TEST_METHOD,'type':'java.lang.AssertionError','message':ASSERTION,'XML_sha256':sha(xml)}

def regular_map(root):
    if root.is_symlink() or not root.is_dir():raise ValueError('prebuilt Maven directory unavailable')
    result={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink() or (not p.is_file() and not p.is_dir()):raise ValueError('nonregular Maven tree')
        if p.is_file():result[p.relative_to(root).as_posix()]=sha(p)
    if not result:raise ValueError('empty Maven tree')
    return result

def verify_prebuilt(repo,inputs):
    aar=repo/COMPONENT/('xray-android-'+VERSION+'.aar')
    pom=aar.with_suffix('.pom')
    if not aar.is_file() or not pom.is_file():raise ValueError('prebuilt AAR/POM required; producer will not be invoked')
    expected=json.loads(inputs.read_text())
    with zipfile.ZipFile(aar) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)):raise ValueError('duplicate AAR members')
        for name,wanted in expected.items():
            path=name.replace('jniLibs/','jni/',1)
            if hashlib.sha256(archive.read(path)).hexdigest()!=wanted:raise ValueError('AAR/input mismatch')
    return {'AAR_sha256':sha(aar),'POM_sha256':sha(pom),'input_manifest_sha256':sha(inputs)}

def group_exists(group):
    try:os.killpg(group,0);return True
    except ProcessLookupError:return False

def drain(group):
    # Only a PGID created by this runner's start_new_session=True is passed here.
    if not group_exists(group):return True
    for sig in (signal.SIGTERM,signal.SIGKILL):
        try:os.killpg(group,sig)
        except ProcessLookupError:return True
        limit=time.monotonic()+5
        while time.monotonic()<limit:
            if not group_exists(group):return True
            time.sleep(.05)
    return not group_exists(group)

def owned(argv,cwd,log,timeout,children,check=True):
    # No shell and no nested session wrapper. Flutter/Gradle descendants inherit this owned group.
    with log.open('xb') as stream:
        child=subprocess.Popen(argv,cwd=cwd,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        record={'argv':argv,'PID':child.pid,'PGID':child.pid,'returncode':None,'group_empty':False}
        children.append(record)
        primary=None
        try:
            child.wait(timeout=timeout)
        except BaseException as error:
            primary=error
        finally:
            try:
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        child.wait(timeout=5)
            finally:
                record['returncode']=child.poll()
                record['group_empty']=drain(child.pid)
        if record['returncode'] is None or not record['group_empty']:raise RuntimeError('owned group not reaped; worktree retained')
        if primary is not None:raise primary
        if check and child.returncode!=0:raise RuntimeError('CI prerequisite command failed; not semantic RED')
        return child.returncode

def execute(root,out,env,children):
    head=env['GITHUB_SHA']
    # Read-only Git binding happens only after the explicit CI gate.
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True,timeout=15).strip()
    if actual!=head:raise ValueError('current checkout/head mismatch')
    if out.exists() or out.is_symlink():raise ValueError('fresh evidence directory required')
    fixture=root/FIXTURE
    if fixture.is_symlink() or not fixture.is_file():raise ValueError('current exact baseline-compatible fixture missing')
    fixture_bytes=fixture.read_bytes();fixture_hash=sha(fixture)
    if fixture_hash!=EXPECTED_FIXTURE_SHA256:raise ValueError('unexpected baseline fixture bytes')
    repo=root/RUNTIME/'build/repo'
    before=regular_map(repo)
    runtime=verify_prebuilt(repo,root/RUNTIME/'runtime-inputs.sha256.json')
    out.mkdir(parents=True)
    work=out/'baseline-worktree';created=False
    result={'version':1,'head':head,'baseline':BASELINE,'fixture_sha256':fixture_hash,'prebuilt':runtime,'semantic_RED':False,'children':children,'worktree_removed':False,'Maven_unchanged':False,'current_fixture_unchanged':False}
    primary=None
    try:
        owned(['git','fetch','--no-tags','--depth=1','origin',BASELINE],root,out/'baseline-fetch.log',60,children)
        owned(['git','worktree','add','--detach',str(work),BASELINE],root,out/'worktree-add.log',60,children)
        created=True
        for name,wanted in BASELINE_SOURCE_SHA256.items():
            if sha(work/name)!=wanted:raise ValueError('baseline production source mismatch')
        result['baseline_source_sha256']=dict(BASELINE_SOURCE_SHA256)
        # The baseline fixture alone is transferred; no new production/helper source enters this worktree.
        if (work/FIXTURE).exists():raise ValueError('baseline unexpectedly already has new fixture')
        for relative in [RUNTIME/'runtime-inputs.sha256.json',Path('tool/with_android_local_runtime.py'),Path('tool/verify_android_runtime_inputs.py')]:
            if sha(root/relative)!=sha(work/relative):raise ValueError('baseline/runtime verification input drift')
        baseline_fixture=work/FIXTURE;baseline_fixture.parent.mkdir(parents=True,exist_ok=True);baseline_fixture.write_bytes(fixture_bytes)
        target=work/RUNTIME/'build/repo'
        if target.exists() or target.is_symlink():raise ValueError('baseline runtime output must be absent')
        target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(repo,target_is_directory=True)
        owned(['flutter','pub','get'],work/'example',out/'pub-get.log',120,children)
        xml=work/RESULT_XML
        if xml.exists() or xml.is_symlink():raise ValueError('stale baseline JUnit output')
        command=[sys.executable,str(work/'tool/with_android_local_runtime.py'),':flutter_vless_android:testDebugUnitTest','--tests',TEST_CLASS+'.'+TEST_METHOD,'--no-daemon','--max-workers=2','--stacktrace']
        assert all(PRODUCER_FORBIDDEN not in arg for arg in command)
        code=owned(command,work,out/'baseline-gradle.log',300,children,check=False)
        result['assertion']=classify(xml,code)
        log=(out/'baseline-gradle.log').read_text(errors='replace')
        if ':flutter_vless_android:testDebugUnitTest FAILED' not in log or '1 test completed, 1 failed' not in log:
            raise ValueError('selected Gradle test failure markers missing; not semantic RED')
        result['fixture_baseline_unchanged']=sha(baseline_fixture)==fixture_hash
        if not result['fixture_baseline_unchanged']:raise ValueError('baseline fixture mutated')
        (out/'baseline-assertion.xml').write_bytes(xml.read_bytes())
        result['semantic_RED']=True
    except BaseException as error:
        primary=error;result['error_category']=type(error).__name__
    finally:
        try:
            result['Maven_unchanged']=regular_map(repo)==before
            result['current_fixture_unchanged']=sha(fixture)==fixture_hash
            result['owned_groups_empty']=all(item['group_empty'] and item['returncode'] is not None for item in children)
            if not all(result[key] for key in ['Maven_unchanged','current_fixture_unchanged','owned_groups_empty']):raise RuntimeError('CI ownership/input invariant failed')
            # Do not delete a checkout while any owned compiler/Gradle descendant group may still be alive.
            # A partially created worktree must be retained and classified for root, never silently forgotten.
            if created:
                owned(['git','worktree','remove','--force',str(work)],root,out/'worktree-remove.log',30,children)
                result['worktree_removed']=not work.exists()
            else:
                result['worktree_removed']=not work.exists()
            if not result['worktree_removed']:raise RuntimeError('baseline worktree cleanup incomplete')
        except BaseException as cleanup:
            result['cleanup_error_category']=type(cleanup).__name__
            if primary is None:primary=cleanup
        result['passed']=primary is None and result['semantic_RED'] and result['worktree_removed']
        result['source_sha256']={FIXTURE.as_posix():fixture_hash,'tool/test_android_quick_access_red.py':sha(Path(__file__))}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    if primary is not None:raise primary
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-ci',action='store_true')
    parser.add_argument('--root',type=Path,default=Path(__file__).parents[1])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    admit(args.run_ci,os.environ) # MUST precede path resolve/files/directories/children.
    root=args.root.resolve();out=args.output.resolve()
    if root/'build' not in out.parents:raise ValueError('evidence/worktree must be inside exact current checkout build directory')
    result=execute(root,out,os.environ,[])
    if not result['passed']:raise RuntimeError('no semantic RED qualification')
    print('ANDROID_QUICK_ACCESS_STALE_PREFLIGHT_RED_PASS=1')
if __name__=='__main__':main()
