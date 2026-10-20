#!/usr/bin/env python3
"""CI-only Go control-flow test of exact Core code with fake OS namespaces.

Generation is file-only. No generated package imports a socket/syscall backend;
CI compiles actual outbound/Control function bodies against recording fakes.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

import test_native_dns_context_runtime as processes

ROOT=Path(__file__).resolve().parents[1]
PIN=ROOT/'third_party/xray-native-dns/pin-manifest.json'
PATCH=ROOT/'third_party/xray-native-dns/darwin_interface_bind_patch.py'


def load_patch():
    spec=importlib.util.spec_from_file_location('darwin_binding_semantic_patch',PATCH)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def block(text, marker):
    start=text.index(marker)+len(marker)
    opening=text.index('{',start);depth=1;end=opening+1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return text[start:end]


def generate(core, output):
    if output.exists() or output.is_symlink():raise ValueError('Output must be new')
    patch=load_patch();pin=json.loads(PIN.read_text())
    path=core/patch.PATH
    if path.is_symlink():raise ValueError('Real copied Darwin source required')
    source=path.read_text()
    if source.count(patch.AFTER)!=1:raise ValueError('Exact patched Darwin boundary required')
    original=source.replace(patch.AFTER,patch.BEFORE)
    if hashlib.sha256(original.encode()).hexdigest()!=pin['upstream_sha256'][patch.PATH]:
        raise ValueError('Darwin source differs outside the owned edit')
    texts={}
    for name in ['sockopt.go','system_dialer.go']:
        relative='transport/internet/'+name;candidate=core/relative
        if candidate.is_symlink() or hashlib.sha256(candidate.read_bytes()).hexdigest()!=pin['upstream_sha256'][relative]:
            raise ValueError('Control/type source pin differs')
        texts[name]=candidate.read_text()
    function='func applyOutboundSocketOptions'+block(source,'func applyOutboundSocketOptions')
    is_tcp='func isTCPSocket'+block(texts['sockopt.go'],'func isTCPSocket')
    tfo='func (v *SocketConfig) ParseTFOValue'+block(texts['sockopt.go'],'func (v *SocketConfig) ParseTFOValue')
    bind=texts['sockopt.go'][texts['sockopt.go'].index('type BindError struct'):]
    tcp=block(texts['system_dialer.go'],'dialer.Control = ')
    udp=block(texts['system_dialer.go'],'lc.Control = ')
    actual='''package internet
import("context";"runtime";"strconv";"strings";errors "binding.test/fakeerrors";net "binding.test/fakenet";syscall "binding.test/fakesyscall";"binding.test/fakeunix")
const TCP_FASTOPEN_CLIENT=2
const sysTCP_KEEPINTVL=0x101
var ctx=context.Background()
var Controllers []func(string,string,syscall.RawConn)error
var sockopt *SocketConfig
var destAddr=destination{}
type destination struct{}
func(destination)String()string{return "[2001:db8::7]:443"}
type SocketConfig struct{Tfo int32;TcpKeepAliveIdle,TcpKeepAliveInterval int32;Interface string;CustomSockopt []*custom}
type custom struct{System,Network,Opt,Level,Type,Value string}
'''.replace('"binding.test/fakeunix"','unix "binding.test/fakeunix"')+is_tcp+'\n'+tfo+'\n'+bind+'\n'+function+'\nvar actualTCPControl='+tcp+'\nvar actualUDPControl='+udp+'\n'
    fakeunix='''package fakeunix
import "fmt"
const(IPPROTO_TCP=iota+1;IPPROTO_IPV6;IPPROTO_IP;TCP_FASTOPEN;TCP_KEEPALIVE;SOL_SOCKET;SO_KEEPALIVE;IPV6_BOUND_IF;IP_BOUND_IF)
type Call struct{Level,Opt,Value int}
var Calls []Call
var BindFailure,OptionalFailure bool
var FailOpt,CurrentBinding int
func Reset(){Calls=nil;BindFailure=false;OptionalFailure=false;FailOpt=0;CurrentBinding=0}
func SetsockoptInt(fd,level,opt,value int)error{Calls=append(Calls,Call{level,opt,value});if opt==IPV6_BOUND_IF||opt==IP_BOUND_IF{if BindFailure&&value==4{return fmt.Errorf("fixed bind failure")};CurrentBinding=value}else if OptionalFailure||opt==FailOpt{return fmt.Errorf("fixed optional failure")};return nil}
'''
    files={'go.mod':'module binding.test\n\ngo 1.23\n','actual.go':actual,
        'fakeunix/fake.go':fakeunix,
        'fakeerrors/fake.go':'''package fakeerrors
import("context";"fmt")
type Error struct{cause error}
func(e *Error)Error()string{return "fixed fake error"}
func(e *Error)Base(err error)*Error{e.cause=err;return e}
func New(values ...any)*Error{_ = fmt.Sprint(values...);return &Error{}}
func LogInfoInner(context.Context,error,...any){}
func LogDebug(context.Context,...any){}
''',
        'fakenet/fake.go':'''package fakenet
import "fmt"
type Interface struct{Index int}
func InterfaceByName(name string)(*Interface,error){if name!="en0"{return nil,fmt.Errorf("fixed missing interface")};return &Interface{4},nil}
''',
        'fakesyscall/fake.go':'''package fakesyscall
import "binding.test/fakeunix"
type RawConn interface{Control(func(uintptr))error}
func SetsockoptInt(fd,level,opt,value int)error{return fakeunix.SetsockoptInt(fd,level,opt,value)}
func SetsockoptString(fd,level,opt int,value string)error{return nil}
''',
        'actual_test.go':'''package internet
import("testing";"binding.test/fakeunix")
type raw struct{}
func(raw)Control(f func(uintptr))error{f(1);return nil}
func optional(t *testing.T,network string,keepalive bool){t.Helper();fakeunix.Reset();fakeunix.OptionalFailure=true;sockopt=&SocketConfig{Interface:"en0",Tfo:1};if keepalive{sockopt.Tfo=0;sockopt.TcpKeepAliveIdle=11};if err:=actualTCPControl(network,"fixture",raw{});err!=nil{t.Fatal(err)};if len(fakeunix.Calls)!=2||fakeunix.Calls[1].Value!=4||fakeunix.CurrentBinding!=4{t.Fatalf("final mandatory binding missing after ignored error: %+v",fakeunix.Calls)}}
func TestFinalBindingAfterIgnoredTCP4TFOFailure(t *testing.T){optional(t,"tcp4",false)}
func TestFinalBindingAfterIgnoredTCP6TFOFailure(t *testing.T){optional(t,"tcp6",false)}
func TestFinalBindingAfterIgnoredTCP4KeepaliveFailure(t *testing.T){optional(t,"tcp4",true)}
func TestFinalBindingAfterIgnoredTCP6KeepaliveFailure(t *testing.T){optional(t,"tcp6",true)}
func denied(t *testing.T,network string,keepalive bool){t.Helper();fakeunix.Reset();fakeunix.BindFailure=true;fakeunix.OptionalFailure=true;sockopt=&SocketConfig{Interface:"en0",Tfo:1};if keepalive{sockopt.Tfo=0;sockopt.TcpKeepAliveIdle=11};err:=actualTCPControl(network,"fixture",raw{});if _,ok:=err.(*BindError);!ok{t.Fatalf("final bind failure was hidden: %T",err)};if len(fakeunix.Calls)!=2{t.Fatalf("final binding was not attempted after optional error: %+v",fakeunix.Calls)}}
func TestTCP4FinalBindFailureOverridesTFOError(t *testing.T){denied(t,"tcp4",false)}
func TestTCP6FinalBindFailureOverridesTFOError(t *testing.T){denied(t,"tcp6",false)}
func TestTCP4FinalBindFailureOverridesKeepaliveError(t *testing.T){denied(t,"tcp4",true)}
func TestTCP6FinalBindFailureOverridesKeepaliveError(t *testing.T){denied(t,"tcp6",true)}
func customOverride(t *testing.T,network string,failBind bool){t.Helper();fakeunix.Reset();fakeunix.FailOpt=999;fakeunix.BindFailure=failBind;level,opt,value:=fakeunix.IPPROTO_IP,fakeunix.IP_BOUND_IF,0;if network=="tcp6"{level,opt,value=fakeunix.IPPROTO_IPV6,fakeunix.IPV6_BOUND_IF,99};sockopt=&SocketConfig{Interface:"en0",CustomSockopt:[]*custom{{Network:"tcp",Type:"int",Level:itoa(level),Opt:itoa(opt),Value:itoa(value)},{Network:"tcp",Type:"int",Level:"123",Opt:"999",Value:"5"}}};err:=actualTCPControl(network,"fixture",raw{});if failBind{if _,ok:=err.(*BindError);!ok{t.Fatalf("mandatory bind failure hidden by custom error: %T",err)}}else if err!=nil||fakeunix.CurrentBinding!=4{t.Fatal("custom override survived final mandatory bind",err)};if len(fakeunix.Calls)!=3||fakeunix.Calls[0].Value!=value||fakeunix.Calls[2].Value!=4{t.Fatalf("custom values or final binding changed: %+v",fakeunix.Calls)}}
func itoa(value int)string{const digits="0123456789";if value==0{return "0"};var result string;for value>0{result=string(digits[value%10])+result;value/=10};return result}
func TestTCP4CustomClearThenErrorCannotRemoveFinalBinding(t *testing.T){customOverride(t,"tcp4",false)}
func TestTCP6CustomChangeThenErrorCannotRemoveFinalBinding(t *testing.T){customOverride(t,"tcp6",false)}
func TestTCP4FinalBindFailureOverridesCustomError(t *testing.T){customOverride(t,"tcp4",true)}
func TestTCP6FinalBindFailureOverridesCustomError(t *testing.T){customOverride(t,"tcp6",true)}
func TestMissingInterfaceFinalBindFailsClosed(t *testing.T){fakeunix.Reset();fakeunix.OptionalFailure=true;sockopt=&SocketConfig{Interface:"missing",Tfo:1};if _,ok:=actualTCPControl("tcp6","fixture",raw{}).(*BindError);!ok{t.Fatal("missing interface did not fail closed")};if len(fakeunix.Calls)!=1{t.Fatal("optional error did not reach final interface lookup")}}
func TestUDPFinalBindFailureStillPropagates(t *testing.T){fakeunix.Reset();fakeunix.BindFailure=true;sockopt=&SocketConfig{Interface:"en0"};if _,ok:=actualUDPControl("udp6","fixture",raw{}).(*BindError);!ok{t.Fatal("UDP binding failure swallowed")}}
func TestCallerOptionalAndCustomValuesRetained(t *testing.T){fakeunix.Reset();sockopt=&SocketConfig{Interface:"en0",Tfo:1,TcpKeepAliveIdle:11,TcpKeepAliveInterval:22,CustomSockopt:[]*custom{{Network:"tcp",Type:"int",Level:"123",Opt:"456",Value:"789"}}};if err:=actualTCPControl("tcp6","fixture",raw{});err!=nil{t.Fatal(err)};if len(fakeunix.Calls)!=6||fakeunix.Calls[4]!=(fakeunix.Call{123,456,789})||fakeunix.Calls[5].Value!=4{t.Fatalf("caller option values or final binding changed: %+v",fakeunix.Calls)}}
'''}
    output.mkdir(parents=True)
    for name,text in files.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    receipt={'version':1,'fake_OS_backends_only':True,'actual_function_sha256':hashlib.sha256(function.encode()).hexdigest(),
             'actual_TCP_Control_sha256':hashlib.sha256(tcp.encode()).hexdigest(),'actual_UDP_Control_sha256':hashlib.sha256(udp.encode()).hexdigest(),
             'source_sha256':{patch.PATH:hashlib.sha256(source.encode()).hexdigest(),**{f'transport/internet/{n}':hashlib.sha256(v.encode()).hexdigest() for n,v in texts.items()}},
             'generated_sha256':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in files.items()},
             'selected_tests':re.findall(r'func (Test\w+)\(',files['actual_test.go'])}
    (output/'source.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt


def require_pass(output, result, selected):
    names=re.findall(r'^--- PASS: (Test\S+) \(',output,re.M)
    if len(selected)!=15 or len(set(selected))!=15 or sorted(names)!=sorted(selected) \
            or re.search(r'^--- (?:FAIL|SKIP):',output,re.M) \
            or result.get('exit_code')!=0 or result.get('process_exit_code')!=0 \
            or result.get('timed_out') is not False or result.get('output_closed') is not True \
            or result.get('output_eof') is not True or result.get('output_errors')!=[]:
        raise ValueError('Exact Darwin binding controls/exit/output evidence missing')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--core-copy',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--go',default='go');parser.add_argument('--generate-only',action='store_true');args=parser.parse_args()
    if not args.generate_only and (os.environ.get('CI')!='true' or os.environ.get('GITHUB_ACTIONS')!='true'):
        parser.error('Go semantic execution is CI-only')
    receipt=generate(args.core_copy,args.output)
    if args.generate_only:return
    results=[]
    execution={'passed':False,'results':results,'selected_tests':receipt['selected_tests'],'fake_OS_backends_only':True}
    try:
        processes.EVIDENCE=args.output
        processes.checked('semantic-go',[args.go,'test','-count=1','-timeout=20s','-v','./...'],cwd=args.output,
            environment=dict(os.environ,GOWORK='off',GOTOOLCHAIN='local'),seconds=60,results=results)
        output=(args.output/'semantic-go.log').read_text()
        require_pass(output,results[-1],receipt['selected_tests'])
        execution['passed']=True
    finally:
        (args.output/'execution.json').write_text(json.dumps(execution,indent=2)+'\n')
    print('DARWIN_INTERFACE_BIND_FAULT_PASS=15')


if __name__=='__main__':main()
