#!/usr/bin/env python3
"""Generate actual Windows tray/queued-action tests with inert OS/Core boundaries.

No subprocess, Win32 API, Core, service or network is executed by this generator.
Compile the output as C++17 (MSVC /W4 /WX or clang -Wall -Wextra -Werror).
"""
from pathlib import Path
import argparse
import hashlib
import json

REL = Path("packages/flutter_vless_windows/windows")
WIN32 = r'''
#include <cstdint>
#include <cwchar>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using HWND=void*; using HICON=void*; using HMENU=void*; using UINT=unsigned; using LPARAM=std::intptr_t;
constexpr unsigned NIN_SELECT=1,NIN_KEYSELECT=2,WM_CONTEXTMENU=3,WM_NULL=4;
constexpr unsigned IMAGE_ICON=1,LR_LOADFROMFILE=2,LR_DEFAULTSIZE=4,MF_STRING=8,MF_GRAYED=16;
constexpr unsigned TPM_RETURNCMD=1,TPM_NONOTIFY=2,TPM_RIGHTBUTTON=4;
constexpr unsigned NIF_MESSAGE=1,NIF_ICON=2,NIF_TIP=4,NIF_SHOWTIP=8;
constexpr unsigned NIM_MODIFY=1,NIM_ADD=2,NIM_SETVERSION=3,NIM_DELETE=4,NOTIFYICON_VERSION_4=4;
constexpr int GCLP_HICONSM=1,FALSE=0; constexpr auto IDI_APPLICATION=L"app"; constexpr std::size_t _TRUNCATE=127;
struct POINT{int x=0,y=0;};
struct NOTIFYICONDATAW {unsigned cbSize=0; HWND hWnd=nullptr; unsigned uID=0,uFlags=0,uCallbackMessage=0; HICON hIcon=nullptr; wchar_t szTip[128]{}; unsigned uVersion=0;};
static std::function<void()> reenter; static UINT selected=1;
UINT LOWORD(LPARAM p){return static_cast<UINT>(p)&65535;}
UINT RegisterWindowMessageW(const wchar_t* p){return std::wstring(p)==L"TaskbarCreated"?101:100;}
void* LoadImageW(void*,const wchar_t*,unsigned,int,int,unsigned){return nullptr;}
void DestroyIcon(HICON){} std::intptr_t GetClassLongPtrW(HWND,int){return 0;}
HICON LoadIconW(void*,const wchar_t*){return reinterpret_cast<HICON>(1);}
template<std::size_t N> void wcsncpy_s(wchar_t(&out)[N],const wchar_t* in,std::size_t){std::wcsncpy(out,in,N-1);out[N-1]=0;}
int Shell_NotifyIconW(unsigned,NOTIFYICONDATAW*){return 1;}
HMENU CreatePopupMenu(){return reinterpret_cast<HMENU>(1);}
void AppendMenuW(HMENU,unsigned,unsigned,const wchar_t*){}
void GetCursorPos(POINT*){} void SetForegroundWindow(HWND){}
UINT TrackPopupMenu(HMENU,unsigned,int,int,int,HWND,void*){if(reenter)reenter();return selected;}
void DestroyMenu(HMENU){} void PostMessageW(HWND,unsigned,int,int){}
namespace flutter_vless {
struct NativeOptions {bool quick_enabled=false,require_unlock=true;std::string quick_action="toggle",surface="platformDefault",windows_icon,label="VPN";};
namespace native {std::wstring Wide(const std::string& s){return {s.begin(),s.end()};}}
}
static int passed=0,failed=0;
void Check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F> void Test(const char* name,F fn){try{fn();++passed;std::cout<<"PASS "<<name<<"\n";}catch(const std::exception& e){++failed;std::cout<<"FAIL "<<name<<": "<<e.what()<<"\n";}}
'''
TRAY_CASES = r'''
struct Fixture {
  int toggles=0,opens=0; bool expected=false; std::uint64_t revision=0;
  flutter_vless::NativeOptions options;
  flutter_vless::SystemTray tray;
  Fixture():tray(reinterpret_cast<HWND>(1),TOGGLE_CALLBACK,[this]{++opens;} PROFILE_CALLBACK){options.quick_enabled=true;Check(tray.Configure(options),"configure");reenter={};selected=1;}
  void Popup(){tray.Handle(100,WM_CONTEXTMENU);}
};
int main(){
  Test("stable direct toggle",[]{Fixture f;f.tray.Handle(100,NIN_SELECT);Check(f.toggles==1,"toggle missing");});
  Test("pending direct suppressed",[]{Fixture f;f.tray.Refresh(false,true);f.tray.Handle(100,NIN_SELECT);Check(f.toggles==0,"pending toggle");});
  Test("stable open action",[]{Fixture f;f.options.quick_action="openApp";f.tray.Configure(f.options);f.tray.Handle(100,NIN_SELECT);Check(f.opens==1&&f.toggles==0,"open action");});
  Test("stable popup toggle",[]{Fixture f;f.Popup();Check(f.toggles==1,"popup toggle");});
  Test("stable popup open",[]{Fixture f;f.options.quick_action="openApp";f.tray.Configure(f.options);f.Popup();Check(f.opens==1&&f.toggles==0,"popup open");});
  Test("secondary open while pending",[]{Fixture f;f.tray.Refresh(false,true);selected=2;f.Popup();Check(f.opens==1&&f.toggles==0,"secondary open");});
  Test("displayed Open app cannot become toggle",[]{Fixture f;f.options.quick_action="openApp";f.tray.Configure(f.options);reenter=[&]{f.options.quick_action="toggle";f.tray.Configure(f.options);};f.Popup();Check(f.toggles==0&&f.opens==0,"stale action dispatched");});
  Test("disabled popup primary revoked",[]{Fixture f;reenter=[&]{f.options.quick_enabled=false;f.tray.Configure(f.options);};f.Popup();Check(f.toggles==0&&f.opens==0,"disabled primary");});
  Test("disabled popup secondary revoked",[]{Fixture f;selected=2;reenter=[&]{f.options.quick_enabled=false;f.tray.Configure(f.options);};f.Popup();Check(f.opens==0,"disabled secondary");});
  Test("unlock policy change revoked",[]{Fixture f;reenter=[&]{f.options.require_unlock=!f.options.require_unlock;f.tray.Configure(f.options);};f.Popup();Check(f.toggles==0,"unlock changed");});
  Test("action ABA revoked",[]{Fixture f;reenter=[&]{f.options.quick_action="openApp";f.tray.Configure(f.options);f.options.quick_action="toggle";f.tray.Configure(f.options);};f.Popup();Check(f.toggles==0,"ABA action");});
  Test("profile revision revoked",[]{Fixture f;reenter=[&]{++f.revision;};f.Popup();Check(f.toggles==0,"profile changed");});
  Test("active target changed revoked",[]{Fixture f;reenter=[&]{f.tray.Refresh(true);};f.Popup();Check(f.toggles==0,"newer active state");});
  Test("pending changed revoked",[]{Fixture f;reenter=[&]{f.tray.Refresh(false,true);};f.Popup();Check(f.toggles==0,"new pending state");});
  Test("unrelated label preserved",[]{Fixture f;reenter=[&]{f.options.label="New label";f.tray.Configure(f.options);};f.Popup();Check(f.toggles==1&&f.options.label=="New label","unrelated write lost");});
  Test("failed icon leaves valid policy",[]{Fixture f;reenter=[&]{auto invalid=f.options;invalid.windows_icon="missing.ico";invalid.quick_action="openApp";Check(!f.tray.Configure(invalid),"invalid icon accepted");};f.Popup();Check(f.toggles==1&&f.opens==0,"failed configure altered intent");});
  std::cout<<"WINDOWS_TRAY_FAKE_PASS="<<passed<<" FAIL="<<failed<<"\n";return failed?1:0;
}
'''
QUEUED = r'''
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
namespace flutter {struct EncodableValue{explicit EncodableValue(const char*){}};using EncodableList=std::vector<EncodableValue>;}
struct Options {bool quick_enabled=true;std::string label="original";};
struct V2rayManager {
 bool running=false,protecting=false,proxy=false;int starts=0,stops=0;std::function<void()> on_start;
 static V2rayManager& GetInstance(){static V2rayManager x;return x;}
 bool IsRunning()const{return running;}bool IsProxyOnly()const{return proxy;}bool IsProtecting()const{return protecting;}
 bool Start(const std::string&,bool,const Options&,const std::string&,const std::string&){++starts;running=true;if(on_start)on_start();return true;}
 void Stop(){++stops;running=protecting=false;}
};
struct Queue {std::vector<std::function<void()>> tasks;void Submit(std::function<void()> f){tasks.push_back(std::move(f));}void Drain(){while(!tasks.empty()){auto f=std::move(tasks.front());tasks.erase(tasks.begin());f();}}};
struct Probe {
 Options native_options_;std::atomic<unsigned> options_generation_{0};std::atomic<std::uint64_t> quick_profile_generation_{0};
 bool tray_pending_=false;std::mutex lifecycle_mutex_;Queue operations_;std::atomic<bool> is_running_{false};
 std::chrono::steady_clock::time_point start_time_;int opens=0;
 struct QuickProfile{std::string config="config",assets="assets",routing="routing";};std::optional<QuickProfile> quick_profile_{QuickProfile{}};
 Probe(){V2rayManager::GetInstance()=V2rayManager{};}
 void OpenApp(){++opens;}void RefreshTray(){}void StopStatusTimer(){}void StartStatusTimer(){}void UpdateStatus(){}void SendStatusToUI(const flutter::EncodableList&){}
 void RunOnUIThread(std::function<void()> fn){fn();}
 ACTUAL_METHOD
 void PublishManualStart(bool ready,bool proxy_only,const Options& options,unsigned generation,const std::string& config,const std::string& assets,const std::string& routing){
 ACTUAL_PROFILE_PUBLICATION
 }
};
static int passed=0,failed=0;
void Check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F> void Test(const char* name,F fn){try{fn();++passed;std::cout<<"PASS "<<name<<"\n";}catch(const std::exception& e){++failed;std::cout<<"FAIL "<<name<<": "<<e.what()<<"\n";}}
void Invoke(Probe& p,bool active){INVOKE;}
int main(){
 Test("stable queued connect",[]{Probe p;Invoke(p,false);p.operations_.Drain();Check(V2rayManager::GetInstance().starts==1,"connect missing");});
 Test("stable queued disconnect",[]{Probe p;auto& m=V2rayManager::GetInstance();m.running=true;Invoke(p,true);p.operations_.Drain();Check(m.stops==1,"stop missing");});
 Test("pending queue suppressed",[]{Probe p;p.tray_pending_=true;Invoke(p,false);Check(p.operations_.tasks.empty(),"queued while pending");});
 Test("proxy-only opens app",[]{Probe p;auto& m=V2rayManager::GetInstance();m.running=m.proxy=true;Invoke(p,true);Check(p.opens==1&&p.operations_.tasks.empty(),"proxy toggled");});
 Test("new options cancel queued action",[]{Probe p;Invoke(p,false);++p.options_generation_;p.native_options_.label="new";p.operations_.Drain();Check(V2rayManager::GetInstance().starts==0&&p.native_options_.label=="new","options overwritten");});
 Test("new profile cancels queued action",[]{Probe p;Invoke(p,false);++p.quick_profile_generation_;p.operations_.Drain();Check(V2rayManager::GetInstance().starts==0,"new profile started");});
 Test("actual manual profile publication revokes queued action",[]{Probe p;Invoke(p,false);p.PublishManualStart(true,false,p.native_options_,p.options_generation_.load(),"new-config","assets","routing");p.operations_.Drain();Check(V2rayManager::GetInstance().starts==0&&p.quick_profile_->config=="new-config","published profile reused by stale action");});
 Test("new session cannot become stale disconnect",[]{Probe p;Invoke(p,false);auto& m=V2rayManager::GetInstance();m.running=true;p.operations_.Drain();Check(m.stops==0&&m.running,"new session stopped");});
 Test("stale disconnect cannot reconnect",[]{Probe p;auto& m=V2rayManager::GetInstance();m.running=true;Invoke(p,true);m.running=false;p.operations_.Drain();Check(m.starts==0,"stale stop started");});
 Test("state publication revokes queued-era menu",[]{Probe p;Invoke(p,false);auto admitted=p.quick_profile_generation_.load();p.operations_.Drain();Check(p.quick_profile_generation_.load()!=admitted,"no state publication revision");});
 Test("state publication preserves newer owner",[]{Probe p;Invoke(p,false);std::uint64_t newer=0;V2rayManager::GetInstance().on_start=[&]{newer=++p.quick_profile_generation_;};p.operations_.Drain();Check(p.quick_profile_generation_.load()==newer,"new owner invalidated by old publication");});
 Test("no cached profile opens app",[]{Probe p;p.quick_profile_.reset();Invoke(p,false);p.operations_.Drain();Check(p.opens==1&&V2rayManager::GetInstance().starts==0,"no-profile action");});
 Test("disabled quick action suppressed",[]{Probe p;p.native_options_.quick_enabled=false;Invoke(p,false);Check(p.operations_.tasks.empty(),"disabled queued");});
 std::cout<<"WINDOWS_QUEUED_FAKE_PASS="<<passed<<" FAIL="<<failed<<"\n";return failed?1:0;
}
'''


INTERLEAVED = r'''
struct Joined {
 Probe p; flutter_vless::NativeOptions options; flutter_vless::SystemTray tray;
 Joined():tray(reinterpret_cast<HWND>(1),[this](bool active){Invoke(p,active);},[this]{p.OpenApp();},[this]{return p.quick_profile_generation_.load();}){
  p.native_options_.quick_enabled=true;options.quick_enabled=true;tray.Configure(options);reenter={};selected=1;
 }
 void Sync(){const auto& m=V2rayManager::GetInstance();tray.Refresh((m.IsRunning()&&!m.IsProxyOnly())||m.IsProtecting(),p.tray_pending_);}
 void Drain(){p.operations_.Drain();Sync();}
};
int main(){
 Test("popup cannot reconnect after newer tray Start then Stop",[]{Joined f;
  reenter=[&]{f.tray.Handle(100,NIN_SELECT);f.Drain();f.tray.Handle(100,NIN_SELECT);f.Drain();};
  f.tray.Handle(100,WM_CONTEXTMENU);f.Drain();auto& m=V2rayManager::GetInstance();
  Check(m.starts==1&&m.stops==1&&!m.running,"old popup replayed Connect after newer Stop");
 });
 Test("queued-era popup revoked by actual state publication",[]{Joined f;
  f.tray.Handle(100,NIN_SELECT);f.Sync();selected=2;reenter=[&]{f.Drain();};
  f.tray.Handle(100,WM_CONTEXTMENU);auto& m=V2rayManager::GetInstance();
  Check(m.starts==1&&m.running&&f.p.opens==0,"queued-era popup survived publication");
 });
 std::cout<<"WINDOWS_INTERLEAVED_FAKE_PASS="<<passed<<" FAIL="<<failed<<"\n";return failed?1:0;
}
'''

def method(source, marker):
    start=source.index(marker)
    begin=source.index('{',start)
    depth=1;i=begin+1
    while depth:
        depth += (source[i]=='{')-(source[i]=='}');i+=1
    return source[start:i]

def source_wiring(root):
    s=(root/REL/'flutter_vless_plugin.cpp').read_text()
    findings=[]
    clear=s[s.index('  } else if (method_call.method_name() == "clearQuickAccessProfile")'):s.index('  } else if (method_call.method_name().compare("requestPermission")')]
    start=s[s.index('        const auto options = native_options_;',s.index('method_call.method_name().compare("startVless")')):s.index('\n      } else {\n        result->Error("INVALID_ARGUMENTS", "Missing remark or config")')]
    stop=s[s.index('  } else if (method_call.method_name().compare("stopVless")'):s.index('  } else if (method_call.method_name().compare("getServerDelay")')]
    for name,body in [('clear',clear),('manual_start',start),('manual_stop',stop)]:
        if not ('++quick_profile_generation_;' in body and body.index('++quick_profile_generation_;')<body.index('operations_.Submit')):findings.append(name)
    if '[this] { return quick_profile_generation_.load(); }' not in s:findings.append('menu_revision_binding')
    for name,body in [('clear',clear),('manual_stop',stop)]:
        if '++quick_profile_generation_;' not in body[body.index('operations_.Submit'):]:findings.append(name+'_execution_revocation')
    return findings

def generate_source(root):
    header=(root/REL/'system_tray.h').read_text()
    cpp=(root/REL/'flutter_vless_plugin.cpp').read_text()
    if header.count('std::function<void(bool)>')!=2 or cpp.count('  void ToggleFromTray(bool expected_active)')!=1:
        raise ValueError('unexpected-actual-tray-callback-or-method-shape')
    failures=source_wiring(root)
    if failures:raise ValueError('missing-actual-manual-intent-revocation:'+','.join(failures))
    actual='\n'.join(line for line in header.splitlines() if not line.startswith('#include'))
    queued=method(cpp,'  void ToggleFromTray(')
    begin=cpp.index('          if (ready) ++quick_profile_generation_;')
    publication=cpp[begin:cpp.index('          if (ready) {',begin)]
    queued_source=QUEUED.replace('ACTUAL_METHOD',queued).replace('ACTUAL_PROFILE_PUBLICATION',publication).replace('INVOKE','p.ToggleFromTray(active)')
    probe=queued_source[:queued_source.index('static int passed=0,failed=0;')]
    probe=probe.replace('struct Options {bool quick_enabled=true;std::string label="original";};','using Options=flutter_vless::NativeOptions;')
    probe=probe.replace('Probe(){V2rayManager::GetInstance()=V2rayManager{};}','Probe(){native_options_.quick_enabled=true;V2rayManager::GetInstance()=V2rayManager{};}')
    # The real header's CRT call is one of the fake OS presentation boundaries.
    # Avoid a secure-CRT template collision/deprecation on MSVC itself.
    win32=WIN32.replace('constexpr std::size_t _TRUNCATE=127;','#ifndef _TRUNCATE\nconstexpr std::size_t _TRUNCATE=127;\n#endif')
    win32=win32.replace('template<std::size_t N> void wcsncpy_s(wchar_t(&out)[N],const wchar_t* in,std::size_t){std::wcsncpy(out,in,N-1);out[N-1]=0;}',
                        'template<std::size_t N> void CopyTrayTip(wchar_t(&out)[N],const wchar_t* in,std::size_t){std::size_t i=0;while(i<N-1&&in[i]){out[i]=in[i];++i;}out[i]=0;}')
    # The replacement above begins after a shared declaration on the same line.
    win32=win32.replace('constexpr auto IDI_APPLICATION=L"app"; #ifndef','constexpr auto IDI_APPLICATION=L"app";\n#ifndef')
    body=TRAY_CASES.replace('TOGGLE_CALLBACK','[this](bool active){++toggles;expected=active;}').replace(' PROFILE_CALLBACK',',[this]{return revision;}')
    return (win32+'\n#define wcsncpy_s CopyTrayTip\n'+actual+'\n#undef wcsncpy_s\n'+probe+
            '\nvoid Invoke(Probe& p,bool active){p.ToggleFromTray(active);}\n'+
            body.replace('int main(){','int RunTrayCases(){',1)+
            queued_source[queued_source.index('int main(){'):].replace('int main(){','int RunQueuedCases(){',1)+
            INTERLEAVED.replace('int main(){','int RunInterleavedCases(){',1)+
            '\nint main(){(void)RunTrayCases();(void)RunQueuedCases();(void)RunInterleavedCases();'
            'std::cout<<"WINDOWS_QUICK_ACCESS_PASS="<<passed<<" FAIL="<<failed<<"\\n";return failed?1:0;}\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root','--source-root',dest='root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--generate',type=Path,required=True)
    args=p.parse_args();root=args.root.resolve();out=args.generate.resolve()
    manifest=out.with_suffix('.sources.json')
    if out.exists() or manifest.exists():raise ValueError('fresh-output-required')
    generated=generate_source(root)
    inputs={str(REL/name):hashlib.sha256((root/REL/name).read_bytes()).hexdigest() for name in ['system_tray.h','flutter_vless_plugin.cpp']}
    receipt={'version':1,'source_sha256':inputs,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'generated_sha256':hashlib.sha256(generated.encode()).hexdigest(),'expected_cases':31,
             'expected_marker':'WINDOWS_QUICK_ACCESS_PASS=31 FAIL=0','execution':'NOT_RUN_BY_GENERATOR',
             'actual_boundaries':'full SystemTray, exact ToggleFromTray and manual profile-publication statements',
             'inert_boundaries':['Win32 presentation','options values','manager','FIFO operation queue']}
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as f:f.write(generated)
    with manifest.open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
    print(json.dumps({'generated':str(out),'sha256':receipt['generated_sha256'],'cases':31}))
if __name__=='__main__':main()
