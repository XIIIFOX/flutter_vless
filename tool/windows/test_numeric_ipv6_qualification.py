import copy
import unittest
import verify_numeric_ipv6_qualification as gate
from verify_numeric_ipv6_qualification import EvidenceError,verify_runtime
CASES=[('wrong_address','fd00:85:2::3',18443,6),('wrong_port','fd00:85:2::2',18444,6),('udp','fd00:85:2::2',18443,17),('wrong_image','fd00:85:2::2',18443,6)]
LOG='WINDOWS_NUMERIC_IPV6_OUTER_TCP_PASS=1\nWINDOWS_NUMERIC_IPV6_SCOPE_DENY_PASS=4\n'
def fixture():
    expected={'run_id':'1234','head':'a'*40,'source_sha256':{'tool/windows/runtime_probe.cpp':'b'*64,'tool/windows/runtime_smoke.py':'c'*64},'build_receipt_sha256':'d'*64,'SystemRoot':r'C:\Windows','Core_image_sha256':'e'*64,'binary_variant':'routing'}
    doc={'version':1,'binary_variant':'routing',**{k:copy.deepcopy(expected[k]) for k in ['run_id','head','source_sha256','build_receipt_sha256']},'nonce':'f'*32,'peer_nonce':'f'*32,'scope':{'remote':'fd00:85:2::2','port':18443,'protocol':6,'LUID':42,'CorePID':700,'controllerPID':500,'ServicePID':600,'CoreParentPID':600,'Core_image':r'C:\Windows\Temp\flutter-vless-protected-'+('a'*64)+r'\xray.exe','Core_image_sha256':expected['Core_image_sha256'],'owned_filter_ids':[101,102]},'positive':{'tcp_owner':{'PID':700,'local_address':'fd00:85:2::1','local_port':60000,'remote_address':'fd00:85:2::2','remote_port':18443},'source':'10.0.85.2','response_exact':True,'peer':{'syn_count':1,'authentication_count':1,'connect_count':1,'challenge_count':1,'complete':True,'error':0,'client_port':60000},'controlled_packets':{'baseline':[],'protected':[]}},'denied':[],'cleanup':{'service_exit0':True,'policy_filters':0,'capture_routes':0,'owned_adapter_absent':True,'owned_helpers_remaining':0},'passed':True,'skipped':False}
    for i,(case,remote,port,protocol) in enumerate(CASES):
        sender=500 if case=='wrong_image' else 700;source=50000+i
        doc['denied'].append({'case':case,'sender_attempted':True,'CorePID':None if case=='wrong_image' else 700,'SenderPID':sender,'protocol':protocol,'remote':remote,'port':port,'observer_baseline_positive':True,'matching_packets_after':0,'kernel':{'kind':'WSAEACCES' if case=='wrong_image' else 'owned_filter_event_5157','ProcessID':sender,'SourcePort':source,'FilterRTID':None if case=='wrong_image' else 101,'AfterRecordId':None if case=='wrong_image' else 500,'RecordId':None if case=='wrong_image' else 501}})
        base={'case':case,'remote':remote,'port':port,'protocol':protocol,'sourcePort':51000+i,'senderPID':500,'syn_packets':0 if protocol==17 else 1,'udp_packets':1 if protocol==17 else 0}
        doc['positive']['controlled_packets']['baseline'].append(base)
        doc['positive']['controlled_packets']['protected'].append({**base,'sourcePort':source,'senderPID':sender,'syn_packets':0,'udp_packets':0})
    return doc,expected
class Qualifier(unittest.TestCase):
    def check_bad(self,change,log=LOG):
        d,e=fixture();change(d,e)
        with self.assertRaises(EvidenceError):verify_runtime(d,e,log)
    def test_complete_current_scope_passes(self):
        d,e=fixture();self.assertTrue(verify_runtime(d,e,LOG))
    def test_missing_duplicate_wrong_marker_or_truncated_log(self):
        for log in ['',LOG+LOG.splitlines()[0]+'\n',LOG.replace('DENY_PASS=4','DENY_PASS=3'),LOG.rstrip(),LOG+'WINDOWS_NUMERIC_IPV6_OUTER_TCP_PASS=2\n','SKIP selected\n'+LOG,'FAIL selected\n'+LOG]:
            with self.subTest(log=log):self.check_bad(lambda d,e:None,log)
    def test_stale_run_head_source_or_build_receipt(self):
        for key in ['run_id','head','source_sha256','build_receipt_sha256']:
            with self.subTest(key=key):self.check_bad(lambda d,e,k=key:d.__setitem__(k,{} if k=='source_sha256' else '0'))
    def test_nonce_mismatch_and_zero_or_not_reached(self):
        for change in [lambda d,e:d.__setitem__('peer_nonce','0'*32),lambda d,e:d.__setitem__('nonce',''),lambda d,e:d.__setitem__('passed',False),lambda d,e:d.__setitem__('skipped',True),lambda d,e:d.__setitem__('positive',{}),lambda d,e:d.__setitem__('status','NOT_REACHED')]:
            with self.subTest(change=change):self.check_bad(change)
    def test_wrong_scope_and_core_identity(self):
        for key,value in [('remote','::1'),('port',18444),('protocol',17),('LUID',0),('CorePID',0),('Core_image','foreign.exe'),('Core_image_sha256','0'*64)]:
            with self.subTest(key=key):self.check_bad(lambda d,e,k=key,v=value:d['scope'].__setitem__(k,v))
    def test_private_image_and_service_parent_are_not_bundled_or_foreign(self):
        for value in [r'C:\ci\xray.exe',r'D:\Windows\Temp\flutter-vless-protected-'+('a'*64)+r'\xray.exe',r'C:\Windows\Temp\flutter-vless-protected-short\xray.exe',r'C:\Windows\Temp\flutter-vless-protected-'+('a'*64)+r'\other.exe']:
            with self.subTest(value=value):self.check_bad(lambda d,e:d['scope'].__setitem__('Core_image',value))
        for key,value in [('ServicePID',0),('ServicePID',700),('CoreParentPID',999)]:
            with self.subTest(key=key):self.check_bad(lambda d,e,k=key,v=value:d['scope'].__setitem__(k,v))
    def test_peer_partial_duplicate_error_and_cleanup(self):
        for key,value in [('syn_count',0),('authentication_count',2),('connect_count',0),('challenge_count',0),('complete',False),('error',1),('client_port',0)]:
            with self.subTest(key=key):self.check_bad(lambda d,e,k=key,v=value:d['positive']['peer'].__setitem__(k,v))
        for key,value in [('service_exit0',False),('policy_filters',1),('capture_routes',1),('owned_adapter_absent',False),('owned_helpers_remaining',1)]:
            with self.subTest(key=key):self.check_bad(lambda d,e,k=key,v=value:d['cleanup'].__setitem__(k,v))
    def test_kernel_event_must_be_newer_than_pre_attempt_record(self):
        for change in [lambda d,e:d['denied'][0]['kernel'].__setitem__('RecordId',500),lambda d,e:d['denied'][1]['kernel'].__setitem__('RecordId',499),lambda d,e:d['denied'][2]['kernel'].__setitem__('AfterRecordId',None),lambda d,e:d['denied'][3]['kernel'].__setitem__('RecordId',501)]:
            with self.subTest(change=change):self.check_bad(change)
    def test_independent_denial_identity_filter_and_observer(self):
        for change in [lambda d,e:d['denied'].pop(),lambda d,e:d['denied'][0].__setitem__('SenderPID',500),lambda d,e:d['denied'][0]['kernel'].__setitem__('ProcessID',999),lambda d,e:d['denied'][0]['kernel'].__setitem__('FilterRTID',999),lambda d,e:d['denied'][2].__setitem__('protocol',6),lambda d,e:d['denied'][0].__setitem__('matching_packets_after',1),lambda d,e:d['denied'][0].__setitem__('observer_baseline_positive',False),lambda d,e:d['positive']['controlled_packets']['baseline'][0].__setitem__('syn_packets',0),lambda d,e:d['positive']['controlled_packets']['protected'][0].__setitem__('sourcePort',123),lambda d,e:d['positive']['controlled_packets']['protected'][0].__setitem__('syn_packets',1),lambda d,e:d['positive']['peer'].__setitem__('client_port',50003)]:
            with self.subTest(change=change):self.check_bad(change)


import contextlib
import hashlib
import io
import json
import os
from unittest import mock
from pathlib import Path
import tempfile

class FileQualification(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve()/'repo'
        self.root.mkdir()
        self.directory=self.root/'build/windows-runtime'
        self.directory.mkdir(parents=True)
        for name in gate.MANDATORY_SOURCES:
            path=self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(('synthetic-source '+name+'\n').encode())
        (self.directory/'runtime_probe.exe').write_bytes(b'inert probe never executed')
        (self.directory/'xray.exe').write_bytes(b'inert routing Core never executed')
        (self.directory/'xray-official.exe').write_bytes(b'inert official Core never executed')
        self.run='1234';self.head='a'*40

    def prepare(self):
        receipt=gate.record_build(self.root,self.directory,self.run,self.head)
        d,_=fixture()
        d.update(run_id=self.run,head=self.head,source_sha256=gate.source_vector(self.root),
                 build_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest())
        d['scope']['Core_image_sha256']=hashlib.sha256((self.directory/'xray.exe').read_bytes()).hexdigest()
        (self.directory/'numeric-ipv6-results.json').write_text(json.dumps(d))
        (self.directory/'native-routing-runtime.log').write_text(LOG)
        return receipt,d

    def check(self):
        return gate.verify_files(self.root,self.directory,self.run,self.head,system_root=r'C:\Windows')

    def test_official_and_routing_variants_independently_bound(self):
        receipt,d=self.prepare()
        routing=(self.directory/'xray.exe').read_bytes()
        official=(self.directory/'xray-official.exe').read_bytes()
        self.assertNotEqual(hashlib.sha256(routing).hexdigest(),hashlib.sha256(official).hexdigest())
        with self.assertRaises(EvidenceError):gate.verify_files(self.root,self.directory,self.run,self.head,variant='official',system_root=r'C:\Windows')
        (self.directory/'xray.exe').write_bytes(official)
        d['binary_variant']='official';d['scope']['Core_image_sha256']=hashlib.sha256(official).hexdigest()
        (self.directory/'numeric-ipv6-results.json').write_text(json.dumps(d))
        self.assertTrue(gate.verify_files(self.root,self.directory,self.run,self.head,variant='official',system_root=r'C:\Windows'))
        with self.assertRaises(EvidenceError):self.check()

    def test_current_tcp_owner_proof_is_required(self):
        self.prepare()
        result=self.directory/'numeric-ipv6-results.json';d=json.loads(result.read_text())
        for field,value in [('PID',999),('local_address','::1'),('local_port',50003),('remote_address','fd00:85:2::3'),('remote_port',18444)]:
            with self.subTest(field=field):
                changed=copy.deepcopy(d);changed['positive']['tcp_owner'][field]=value
                result.write_text(json.dumps(changed))
                with self.assertRaises(EvidenceError):self.check()
        result.write_text(json.dumps(d))

    def test_cli_record_verify_and_variant_admission(self):
        receipt,_=self.prepare()
        base=['--root',str(self.root),'--directory',str(self.directory)]
        with mock.patch.dict(os.environ,{'GITHUB_RUN_ID':self.run,'GITHUB_SHA':self.head,'SystemRoot':r'C:\Windows'},clear=True):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(gate.main(base+['--variant','routing']),0)
            self.assertEqual(output.getvalue(),'WINDOWS_NUMERIC_IPV6_QUALIFIED=routing\n')
            for flags in [[],['--variant','official'],['--record-build']]:
                with self.subTest(flags=flags),contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(gate.main(base+flags),1)
            receipt.unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(base+['--record-build']),0)
            self.assertTrue(receipt.is_file())

    def test_cli_missing_current_identity_refuses_before_any_files(self):
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(gate,'source_vector',side_effect=AssertionError('file read')) as vector:
            error=io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(gate.main(['--root',str(self.root),'--directory',str(self.directory),'--record-build']),1)
            vector.assert_not_called()
            self.assertEqual(error.getvalue(),'WINDOWS_NUMERIC_IPV6_QUALIFICATION_FAILED=identity\n')
        self.assertFalse((self.directory/'numeric-ipv6-build-results.json').exists())

    def test_build_map_missing_variant_equal_or_wrong_hash_refused(self):
        receipt,d=self.prepare();original=json.loads(receipt.read_text())
        for value in [{'official':'f'*64},{'official':'f'*64,'routing':'f'*64},{'official':'f'*64,'routing':'0'*64}]:
            with self.subTest(value=value):
                changed=copy.deepcopy(original);changed['core_binaries_sha256']=value
                receipt.write_text(json.dumps(changed));d['build_receipt_sha256']=hashlib.sha256(receipt.read_bytes()).hexdigest()
                (self.directory/'numeric-ipv6-results.json').write_text(json.dumps(d))
                with self.assertRaises(EvidenceError):self.check()

    def test_static_roundtrip_and_exact_build_schema(self):
        receipt,_=self.prepare()
        data=json.loads(receipt.read_text())
        self.assertEqual(set(data),{'version','run_id','head','source_sha256','runtime_probe_sha256','core_binaries_sha256'})
        self.assertEqual(set(data['source_sha256']),set(gate.MANDATORY_SOURCES))
        self.assertTrue(self.check())

    def test_bad_identity_no_output_and_no_overwrite(self):
        for run,head in [('',self.head),(self.run,'x'*40),('0'*80,self.head)]:
            with self.subTest(run=run):
                with self.assertRaises(EvidenceError):gate.record_build(self.root,self.directory,run,head)
                self.assertFalse((self.directory/'numeric-ipv6-build-results.json').exists())
        self.prepare()
        with self.assertRaises(EvidenceError):gate.record_build(self.root,self.directory,self.run,self.head)

    def test_missing_source_and_probe_no_output(self):
        for path in [self.root/gate.MANDATORY_SOURCES[0],self.directory/'runtime_probe.exe']:
            with self.subTest(path=path.name):
                before=path.read_bytes();path.unlink()
                with self.assertRaises(EvidenceError):gate.record_build(self.root,self.directory,self.run,self.head)
                self.assertFalse((self.directory/'numeric-ipv6-build-results.json').exists())
                path.write_bytes(before)

    def test_mutated_source_probe_and_core_are_not_current(self):
        self.prepare()
        for path in [self.root/gate.MANDATORY_SOURCES[-1],self.directory/'runtime_probe.exe',self.directory/'xray.exe']:
            with self.subTest(path=path.name):
                before=path.read_bytes();path.write_bytes(before+b' mutated')
                with self.assertRaises(EvidenceError):self.check()
                path.write_bytes(before)

    def test_omitted_mandatory_source_refused_even_both_maps_agree(self):
        receipt,d=self.prepare()
        r=json.loads(receipt.read_text());name=gate.MANDATORY_SOURCES[0]
        del r['source_sha256'][name];del d['source_sha256'][name]
        receipt.write_text(json.dumps(r));d['build_receipt_sha256']=hashlib.sha256(receipt.read_bytes()).hexdigest()
        (self.directory/'numeric-ipv6-results.json').write_text(json.dumps(d))
        with self.assertRaises(EvidenceError):self.check()

    def test_duplicate_json_key_symlink_and_bounded_log_refused(self):
        self.prepare()
        result=self.directory/'numeric-ipv6-results.json';original=result.read_bytes()
        result.write_bytes(b'{"version":1,'+original[1:])
        with self.assertRaises(EvidenceError):self.check()
        result.write_bytes(original)
        source=self.root/gate.MANDATORY_SOURCES[0];payload=source.read_bytes()
        target=self.root/'outside';target.write_bytes(payload);source.unlink();source.symlink_to(target)
        with self.assertRaises(EvidenceError):self.check()
        source.unlink();source.write_bytes(payload)
        (self.directory/'native-routing-runtime.log').write_bytes(b'x'*(gate.LOG_LIMIT+1))
        with self.assertRaises(EvidenceError):self.check()

    def test_truncated_or_wrong_build_schema_refused(self):
        receipt,_=self.prepare();original=receipt.read_bytes()
        for content in [original[:-1],json.dumps({'version':1}).encode(),original.replace(b'"1234"',b'"4321"')]:
            with self.subTest(content=len(content)):
                receipt.write_bytes(content)
                with self.assertRaises(EvidenceError):self.check()
        receipt.write_bytes(original)

if __name__=='__main__':unittest.main()
