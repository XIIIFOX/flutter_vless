#!/usr/bin/env python3
"""Compile both mobile routing artifacts; run actual factory only in remote CI."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('routing_factory_prerequisite',ROOT/'tool/test_native_vpn_routing.py')
core_runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(core_runner)
EVIDENCE=ROOT/'build/native_routing_factory'
RUNTIME='TestNativeRoutingFactoryRuntime'

def tree_hash(path):
    return hashlib.sha256(json.dumps(core_runner.tree_snapshot(path),sort_keys=True).encode()).hexdigest()

def inputs():
    paths=[Path(__file__).resolve(),ROOT/'tool/test_native_routing_factory_runner.py',ROOT/'tool/test_native_vpn_routing.py',ROOT/'tool/test_native_dns_context_runtime.py',ROOT/'third_party/xray-mobile/go.mod',ROOT/'third_party/xray-mobile/go.sum']
    paths.extend(sorted((ROOT/'third_party/xray-mobile').glob('*.go')))
    return {str(p.relative_to(ROOT)).replace(os.sep,'/'):core_runner.digest(p) for p in paths}

def checked_core(directory):
    report=json.loads((directory/'result.json').read_text())
    if not all(report.get(key) is True for key in ['success','source_snapshot_unchanged','copied_source_unchanged','module_cache_source_unchanged']):
        raise ValueError('Verified routing Core prerequisite is required')
    if report['source_sha256']!=core_runner.source_snapshot():
        raise ValueError('Routing prerequisite input snapshot is stale or incomplete')
    source=directory/'Core'
    if tree_hash(source)!=report['copied_tree_sha256']:raise ValueError('Routing Core copy changed after verification')
    return source,report

def selected(log,tagged):
    names=[line for line in log.splitlines() if re.fullmatch(r'Test(?:NativeRouting\w+|PreflightEnvironmentIsolation|PreflightReportsClosedStages)',line) and line!=RUNTIME]
    required='TestNativeRoutingOptionalArtifactCapability' if tagged else 'TestNativeRoutingDefaultArtifactRefuses'
    if required not in names:raise ValueError('Artifact capability test not compiled: '+required)
    if not names:raise ValueError('No pure mobile routing tests compiled')
    return names

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',default='go')
    parser.add_argument('--core-evidence',type=Path,default=ROOT/'build/native_vpn_routing')
    parser.add_argument('--run-runtime',action='store_true')
    args=parser.parse_args(argv)
    if args.run_runtime and not core_runner.runtime_authorized():parser.error('Actual factory requires CI=true and GITHUB_ACTIONS=true')
    if EVIDENCE.exists():parser.error('Factory evidence already exists; retain it and use a fresh directory')
    EVIDENCE.mkdir(parents=True)
    report={'success':False,'runtime_requested':args.run_runtime,'results':[]};before=None;core=None;core_before=None;cache=None;cache_before=None;handlers={}
    def interrupted(number,frame):
        for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,signal.SIG_IGN)
        raise core_runner.Interrupted(number)
    try:
        for sig in (signal.SIGINT,signal.SIGTERM):handlers[sig]=signal.signal(sig,interrupted)
        before=inputs();report['source_sha256']=before
        core,receipt=checked_core(args.core_evidence.resolve());core_before=tree_hash(core)
        report['core_receipt_source_sha256']=receipt['source_sha256'];report['core_copy_before']=core_before
        metadata=json.loads((args.core_evidence/'core-pin.log').read_text())
        manifest=json.loads((ROOT/'third_party/xray-vpn-routing/pin-manifest.json').read_text())
        cache=core_runner.validate_metadata(manifest,metadata)
        cache_before=core_runner.tree_snapshot(cache)
        if cache_before!=receipt['module_source_before_sha256']:raise ValueError('Original Core cache changed after prerequisite verification')
        core_runner.EVIDENCE=EVIDENCE
        environment=core_runner.child_environment(os.environ)
        go=str(Path(shutil.which(args.go) or args.go).resolve())
        core_runner.checked('factory-runner-guards',[sys.executable,str(ROOT/'tool/test_native_routing_factory_runner.py')],environment=environment,cwd=ROOT,seconds=30,results=report['results'])
        mobile=EVIDENCE/'Mobile';mobile.mkdir()
        for p in (ROOT/'third_party/xray-mobile').iterdir():
            if p.is_file() and (p.suffix=='.go' or p.name in ['go.mod','go.sum']):shutil.copyfile(p,mobile/p.name)
        copied_before=core_runner.tree_snapshot(mobile)
        run=lambda name,command,seconds=120:core_runner.checked(name,command,environment=environment,cwd=mobile,seconds=seconds,results=report['results'])
        for tagged in [False,True]:
            mode='optional' if tagged else 'ordinary'
            if tagged:
                run('select-optional-core',[go,'mod','edit','-replace=github.com/xtls/xray-core='+str(core)],20)
                run('verify-optional-core',[go,'list','-m','-json','github.com/xtls/xray-core'],20)
                replacement=json.loads((EVIDENCE/'verify-optional-core.log').read_text())
                if replacement.get('Version')!=manifest['module_version'] or Path(replacement.get('Replace',{}).get('Dir','')).resolve()!=core:
                    raise ValueError('Optional mobile module does not select the verified Core copy')
                report['optional_core_selection']=replacement
            binary=EVIDENCE/(mode+('.test.exe' if os.name=='nt' else '.test'))
            command=[go,'test','-mod=readonly','-c','-o',str(binary)]
            if tagged:command+=['-tags','flutter_vless_vpn_routing']
            run(mode+'-compile',command+['.'],300)
            run(mode+'-list',[str(binary),'-test.list','^(TestNativeRouting.*|TestPreflightEnvironmentIsolation|TestPreflightReportsClosedStages)$'],30)
            names=selected((EVIDENCE/(mode+'-list.log')).read_text(),tagged)
            run(mode+'-pure',[str(binary),'-test.run',core_runner.test_pattern(names),'-test.v','-test.timeout=45s'],60)
            core_runner.require_pass(mode+'-pure',names,report['results'])
            if tagged and args.run_runtime:
                listing=(EVIDENCE/(mode+'-list.log')).read_text().splitlines()
                if RUNTIME not in listing:raise ValueError('Actual factory fixture was not compiled')
                run('actual-factory',[str(binary),'-test.run','^'+RUNTIME+'$','-test.v','-test.timeout=60s'],75)
                core_runner.require_pass('actual-factory',[RUNTIME],report['results'])
        copied_after=core_runner.tree_snapshot(mobile)
        if {p:v for p,v in copied_after.items() if p!='go.mod'}!={p:v for p,v in copied_before.items() if p!='go.mod'}:raise ValueError('Copied factory source changed')
        report['copied_module_before_sha256']=copied_before['go.mod']
        report['copied_source_sha256']=copied_after
        if inputs()!=before:raise ValueError('Factory source changed during verification')
        report['success']=True
    except core_runner.Interrupted as error:report.update(error='Interrupted',signal=error.number)
    except (OSError,ValueError,RuntimeError,KeyError) as error:report['error']=str(error);print(str(error),file=sys.stderr)
    finally:
        if cache is not None and cache_before is not None:
            try:report['module_cache_source_unchanged']=core_runner.tree_snapshot(cache)==cache_before
            except (OSError,ValueError):report['module_cache_source_unchanged']=False
            if not report['module_cache_source_unchanged']:report['success']=False
        if core is not None and core_before is not None:
            try:report['core_copy_unchanged']=tree_hash(core)==core_before
            except (OSError,ValueError):report['core_copy_unchanged']=False
            if not report['core_copy_unchanged']:report['success']=False
        if before is not None:
            try:report['source_unchanged']=inputs()==before
            except OSError:report['source_unchanged']=False
            if not report['source_unchanged']:report['success']=False
        (EVIDENCE/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        for sig,handler in handlers.items():signal.signal(sig,handler)
    return 0 if report['success'] else 128+report['signal'] if 'signal' in report else 1

if __name__=='__main__':raise SystemExit(main())
