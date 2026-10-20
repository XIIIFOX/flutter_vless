"""File-only controls: mocked builder, synthetic ELF/ZIP; no binary execution."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

import build_android_routing_preview as builder
import verify_android_routing_preview as verifier


class RoutingPreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.output = self.root/'output'; self.ndk = self.root/'ndk'; self.ndk.mkdir()
        self.cache = self.root/'cache'; self.cache.mkdir(); self.calls = []
        self.h3_key = 'third_party/xray-native-dns/h3_lifetime_patch.py'
        self.binding_key = 'third_party/xray-native-dns/darwin_interface_bind_patch.py'
        self.inputs = {'fixed-input':'snapshot', self.h3_key:'a'*64, self.binding_key:'c'*64}
        patch = mock.patch.object(builder,'source_hashes',return_value=self.inputs); patch.start(); self.addCleanup(patch.stop)
        image = bytearray(256); image[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH',image,16,3,62); struct.pack_into('<QQ',image,24,0x1000,64)
        struct.pack_into('<HH',image,54,56,1); struct.pack_into('<I',image,64,1); struct.pack_into('<Q',image,112,16384)
        self.image = bytes(image)
        pin = json.loads((builder.CAPABILITY/'pin-manifest.json').read_text())
        self.receipt = {'core_module':pin['module'],'core':pin['module_version'],'core_sum':pin['module_sum'],'core_commit':pin['core_commit'],
            'overlay_capability':pin['capability'],'routing_tags':builder.TAGS,'selected_abis':['x86_64'],'protection_overlay':'ordinary H/P/D',
            'routing_capability_expected':1,'runtime_executed':False,'published':False,'success':True,'source_unchanged':True,
            'classic_dns_lifetime_applied':True,
            'h3_lifetime_applied':True,'lifetime_patch_scope':['classic_dns','xhttp_h3_dial'],'h3_lifetime_patch_sha256':'a'*64,
            'darwin_interface_binding_source_applied':True,'darwin_interface_binding_patch_sha256':self.inputs[self.binding_key],
            'module_cache_source_unchanged':True,'copies_unchanged':True,'source_sha256':self.inputs,
            'output_directory':str(self.output/'raw'),'artifacts_sha256':{'x86_64/libxray.so':hashlib.sha256(self.image).hexdigest()}}
        def owned(command,**options):
            self.calls.append((command,options))
            if command[:2] == ['go','env']: return str(self.cache)
            raw = Path(options['environment']['TARGET_DIR']); (raw/'x86_64').mkdir(parents=True)
            (raw/'x86_64/libxray.so').write_bytes(self.image); (raw/'routing-preview-owned.json').write_text(json.dumps(self.receipt))
            return ''
        patch = mock.patch.object(builder.common,'owned',side_effect=owned); patch.start(); self.addCleanup(patch.stop)

    def build(self): return builder.main(['--output',str(self.output),'--ndk',str(self.ndk)])
    def metadata(self): return json.loads((self.output/'result.json').read_text())
    def update(self,metadata): (self.output/'result.json').write_text(json.dumps(metadata))

    def test_one_abi_receipt_protect_and_rename_no_execution(self):
        self.assertEqual(self.build(),0); report = verifier.verify(self.output)
        self.assertEqual(report['load_alignments'],[16384]); self.assertFalse((self.output/'raw/x86_64/libxray.so').exists())
        self.assertEqual(len(self.calls),2); command,options = self.calls[-1]
        self.assertEqual(command,['bash',str(builder.BUILD)])
        env = options['environment']; self.assertEqual(env['XRAY_NATIVE_ROUTING'],'1')
        self.assertEqual([env[key] for key in builder.FLAGS.values()],['0','0','0','1'])
        self.assertFalse(self.metadata()['runtime_executed'])

    def test_bad_pin_tags_protection_stale_or_partial_receipt_refused(self):
        for key,value in [('core','foreign'),('routing_tags',['other']),('protection_overlay','none'),('selected_abis',['x86']),
            ('classic_dns_lifetime_applied',False),
            ('classic_dns_lifetime_applied',1),
            ('h3_lifetime_applied',False),('h3_lifetime_applied',1),('h3_lifetime_patch_sha256','b'*64),
            ('darwin_interface_binding_source_applied',False),('darwin_interface_binding_source_applied',1),
            ('darwin_interface_binding_patch_sha256','d'*64),
            ('lifetime_patch_scope',['classic_dns']),('lifetime_patch_scope',['classic_dns','xhttp_h3_dial','full_dns']),
            ('source_sha256',{}),('success',False),('copies_unchanged',False),('runtime_executed',True),('runtime_executed',0)]:
            with self.subTest(key=key,value=value):
                receipt = copy.deepcopy(self.receipt); receipt[key] = value
                with self.assertRaises(ValueError): builder.validate_receipt(receipt,'x86_64',self.output/'raw')

    def test_missing_binding_source_or_receipt_proof_refused(self):
        for field in ('darwin_interface_binding_source_applied','darwin_interface_binding_patch_sha256'):
            with self.subTest(missing=field):
                receipt=copy.deepcopy(self.receipt);del receipt[field]
                with self.assertRaises(ValueError):builder.validate_receipt(receipt,'x86_64',self.output/'raw')
        receipt=copy.deepcopy(self.receipt);del receipt['source_sha256'][self.binding_key]
        with self.assertRaisesRegex(ValueError,'source snapshot'):builder.validate_receipt(receipt,'x86_64',self.output/'raw')
        self.assertEqual(self.calls,[]);self.assertFalse(self.output.exists())

    def test_source_and_cache_destination_refused_before_writes(self):
        for target in [builder.MOBILE/'uncreated-routing-test',self.cache/'new']:
            with self.subTest(target=target),self.assertRaises(SystemExit):
                builder.main(['--output',str(target),'--ndk',str(self.ndk)])
            self.assertFalse(target.exists())
        self.assertFalse(any(command[0]=='bash' for command,_ in self.calls))

    def test_mutation_alignment_extra_abi_and_missing_proof_refused(self):
        self.build(); original=self.metadata(); artifact=Path(original['artifact'])
        artifact.write_bytes(self.image+b'changed')
        with self.assertRaisesRegex(ValueError,'checksum'): verifier.verify(self.output)
        artifact.write_bytes(self.image)
        extra=self.output/'jniLibs/arm64-v8a'; extra.mkdir()
        with self.assertRaisesRegex(ValueError,'unverified'): verifier.verify(self.output)
        extra.rmdir()
        value=copy.deepcopy(original);value['build_receipt']['copies_unchanged']=False;self.update(value)
        with self.assertRaises(ValueError):verifier.verify(self.output)
        self.update(original)
        self.assertEqual(verifier.verify(self.output)['arch'],'x86_64')

    def test_symlink_artifact_refused(self):
        self.build();artifact=Path(self.metadata()['artifact']);other=self.root/'other';artifact.rename(other)
        try:artifact.symlink_to(other)
        except OSError:self.skipTest('Platform cannot create a symlink')
        with self.assertRaises(ValueError):verifier.verify(self.output)

    def test_harness_help_and_missing_flag_are_inert(self):
        script = builder.ROOT/'tool/test_android_security_emulator.sh'
        result = subprocess.run(['bash',str(script),'--help'],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0); self.assertIn('--native-routing-preview',result.stdout)
        result = subprocess.run(['bash',str(script),'--native-routing-preview'],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,2); self.assertIn('Usage:',result.stderr)

    def test_apk_exact_bytes_and_foreign_duplicate_mutation_refused(self):
        self.build(); report=verifier.verify(self.output); apk=self.root/'test.apk';name='lib/x86_64/'+builder.NAME
        for entries,valid in [([(name,self.image)],True),([],False),([(name,b'changed')],False),
                ([(name,self.image),('lib/x86/'+builder.NAME,self.image)],False),([(name,self.image),(name,self.image)],False)]:
            with self.subTest(entries=len(entries),valid=valid):
                with zipfile.ZipFile(apk,'w') as archive:
                    for path,data in entries:archive.writestr(path,data)
                if valid:self.assertTrue(verifier.verify_apk(apk,report)['verified'])
                else:
                    with self.assertRaises(ValueError):verifier.verify_apk(apk,report)
        with zipfile.ZipFile(apk,'w') as archive:
            info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16;archive.writestr(info,self.image)
        with self.assertRaises(ValueError):verifier.verify_apk(apk,report)


if __name__=='__main__':unittest.main()
