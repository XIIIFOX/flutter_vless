"""Inert generator/CI gate controls; no Go or OS network backend executes."""
import hashlib
import re
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_darwin_interface_bind_semantics as subject


class DarwinSemanticGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.core=self.root/'Core';self.output=self.root/'generated'
        self.patch=subject.load_patch()
        sockopt='''package internet
func isTCPSocket(network string)bool{return true}
func (v *SocketConfig) ParseTFOValue() int { return 0 }
type BindError struct { err error }
func NewBindError(err error)*BindError { return &BindError{err} }
'''
        control='func(network, address string, c syscall.RawConn) error { return nil }'
        self.original={'transport/internet/sockopt_darwin.go':'prefix\n'+self.patch.BEFORE+'\nreturn nil\n}\n',
                       'transport/internet/sockopt.go':sockopt,
                       'transport/internet/system_dialer.go':'dialer.Control = '+control+'\nlc.Control = '+control}
        pin={'upstream_sha256':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in self.original.items()}}
        self.pin=self.root/'pin.json';self.pin.write_text(json.dumps(pin))
        for name,text in self.original.items():
            path=self.core/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(text.replace(self.patch.BEFORE,self.patch.AFTER) if name==self.patch.PATH else text)

    def generate(self):
        with mock.patch.object(subject,'PIN',self.pin):return subject.generate(self.core,self.output)

    def test_actual_bodies_are_exact_and_all_qualified_OS_namespaces_are_recording_fakes(self):
        receipt=self.generate();actual=(self.output/'actual.go').read_text()
        expected='func applyOutboundSocketOptions'+subject.block((self.core/self.patch.PATH).read_text(),'func applyOutboundSocketOptions')
        self.assertIn(expected,actual)
        self.assertEqual(receipt['actual_function_sha256'],hashlib.sha256(expected.encode()).hexdigest())
        for backend in ['net','unix','syscall','errors']:self.assertIn('binding.test/fake'+backend,actual)
        self.assertNotIn('"net"',actual);self.assertNotIn('"syscall"',actual)
        tests=(self.output/'actual_test.go').read_text();self.assertEqual(tests.count('func Test'),15)
        self.assertIn('OptionalFailure=true',tests);self.assertIn('BindFailure=true',tests)

    def test_unpatched_wrong_or_missing_boundary_is_not_qualified(self):
        path=self.core/self.patch.PATH
        for text in [self.original[self.patch.PATH],path.read_text()+'outside changed']:
            path.write_text(text)
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse(self.output.exists())

    def test_changed_control_source_pin_refuses_before_outputs(self):
        (self.core/'transport/internet/system_dialer.go').write_text('changed fake control')
        with self.assertRaisesRegex(ValueError,'source pin'):self.generate()
        self.assertFalse(self.output.exists())

    def test_native_execution_gate_is_before_any_files_or_children(self):
        args=['fixture','--core-copy',str(self.core),'--output',str(self.output)]
        with mock.patch.dict(subject.os.environ,{},clear=True),mock.patch.object(subject.os.sys,'argv',args), \
                mock.patch.object(subject.subprocess,'run',side_effect=AssertionError('No local Go allowed')):
            with self.assertRaises(SystemExit):subject.main()
        self.assertFalse(self.output.exists())

    def test_exact_controls_refuse_missing_duplicate_skip_unknown_and_unclosed_output(self):
        receipt=self.generate();names=receipt['selected_tests']
        output=''.join('--- PASS: '+name+' (0.00s)\n' for name in names)
        result={'exit_code':0,'process_exit_code':0,'timed_out':False,'output_closed':True,'output_eof':True,'output_errors':[]}
        subject.require_pass(output,result,names)
        for altered in [output.split('\n',1)[1],output+output.splitlines()[0]+'\n',
                        output.replace(names[0],'TestUnknown'),output+'--- SKIP: TestHidden (0.00s)\n']:
            with self.assertRaises(ValueError):subject.require_pass(altered,result,names)
        for key,value in [('exit_code',1),('process_exit_code',1),('timed_out',True),('output_eof',False),('output_errors',['truncated'])]:
            with self.assertRaises(ValueError):subject.require_pass(output,dict(result,**{key:value}),names)

    def test_main_uses_owned_bounded_child_and_preserves_failure_receipt(self):
        args=['fixture','--core-copy',str(self.core),'--output',str(self.output)]
        def child(name,command,**kw):
            self.assertEqual(name,'semantic-go');self.assertEqual(command,['go','test','-count=1','-timeout=20s','-v','./...'])
            self.assertEqual(kw['seconds'],60)
            kw['results'].append({'exit_code':0,'process_exit_code':0,'timed_out':False,'output_closed':True,'output_eof':True,'output_errors':[]})
            (self.output/'semantic-go.log').write_text('PASS\n') # Missing all exact controls must fail.
        with mock.patch.dict(subject.os.environ,{'CI':'true','GITHUB_ACTIONS':'true'},clear=True), \
                mock.patch.object(subject.os.sys,'argv',args),mock.patch.object(subject,'PIN',self.pin), \
                mock.patch.object(subject.processes,'checked',side_effect=child):
            with self.assertRaises(ValueError):subject.main()
        self.assertFalse(json.loads((self.output/'execution.json').read_text())['passed'])


if __name__=='__main__':unittest.main()
