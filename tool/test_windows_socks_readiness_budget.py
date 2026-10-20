#!/usr/bin/env python3
"""Generate actual SOCKS readiness/budget and both startup consumers with inert I/O.

All Winsock APIs, worker/process effects and the monotonic clock are fakes.
The production auth, cancellation, deadline and caller admission bodies remain.
"""
import argparse
import hashlib
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
WINDOWS=ROOT/"packages/flutter_vless_windows/windows"
NAMES=("native_runtime.h","native_runtime.cpp","vpn_service.cpp","proxy_service.cpp")

def section(text,first,after):
    if text.count(first)!=1 or text.count(after)!=1:
        raise ValueError("actual source boundary changed")
    start,end=text.index(first),text.index(after)
    if start>=end:raise ValueError("actual source order changed")
    return text[start:end]

def sources():
    return {name:(WINDOWS/name).read_text() for name in NAMES}

def actual(data):
    declaration=section(data["native_runtime.h"],"class SocksReadinessBudget {","// A point-in-time TCP loopback bind check;")
    body=section(data["native_runtime.cpp"],"bool SocksReady(","\n}  // namespace flutter_vless::native")
    proxy=section(data["proxy_service.cpp"],"  const flutter_vless::native::SocksReadinessBudget readiness_budget(","  start_time_ = std::chrono::steady_clock::now();")
    vpn=section(data["vpn_service.cpp"],"  const native::SocksReadinessBudget readiness_budget(","  // Credentials live only in a private file")
    text=ADAPTER.replace("ACTUAL",declaration+body).replace("PROXY",proxy).replace("VPN",vpn)
    text=text.replace("std::chrono::steady_clock","FakeClock").replace("std::this_thread::sleep_for","InertSleep")
    for old,new in (("htons(","InertHtons("),("fd_set","InertFdSet"),("timeval","InertTimeval"),
                    ("FD_ZERO(","InertFD_ZERO("),("FD_SET(","InertFD_SET("),("select(","InertSelect(")):
        text=text.replace(old,new)
    return text

FAKES = r'''

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>
using u_long = unsigned long;
using SOCKET = int; using DWORD = unsigned long; using HANDLE = void*;
enum { INVALID_SOCKET=-1, SOCKET_ERROR=-1, AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6,
       SOL_SOCKET=1, SO_RCVTIMEO=2, SO_SNDTIMEO=3, SO_ERROR=4, FIONBIO=5,
       WSAEINTR=10004, WSAECONNRESET=10054, WSAEWOULDBLOCK=10035, WSAEINPROGRESS=10036 };
struct InertTimeval { long tv_sec=0, tv_usec=0; };
struct InertFdSet { SOCKET value=INVALID_SOCKET; };
void InertFD_ZERO(InertFdSet* value) { value->value=INVALID_SOCKET; }
void InertFD_SET(SOCKET fd,InertFdSet* value) { value->value=fd; }
struct WSADATA {}; struct sockaddr {}; struct sockaddr_in {
  int sin_family=0; uint16_t sin_port=0; uint32_t sin_addr=0;
};
struct Kernel {
  int64_t now=0, connect_delay=0, send_delay=0, recv_delay=0, sub_ms_us=0;
  int poll_delay=0, poll_result=1, option_result=0, socket_error=0, nonblock_result=0;
  int close_delay=0, cleanup_delay=0;bool cancel_on_close=false,cancel_on_cleanup=false;
  int polls=0, option_reads=0, nonblock_calls=0, connects=0, max_poll=0;
  bool delay_readiness=false;int64_t ready_remaining=-1;
  int send_wouldblock=0, recv_wouldblock=0, select_interrupts=0;
  bool cancel_in_poll=false, cancel_in_nonblock=false, nonblocking=false;
  bool ready_result=true; int ready_calls=0, ready_delay=0;
  int connect_result=0, send_result=-2, recv_result=-2, start_result=0;
  int opens=0, closes=0, startup=0, cleanup=0, sends=0, receives=0, error=WSAECONNRESET;
  size_t chunk=2, offset=0; bool cancel=false, fail_socket=false, cancel_on_receive=false;
  std::string reply, written; std::set<int> live;
  int proxy_effects=0, tun_effects=0, api_effects=0, ready_effects=0;
  std::function<void()> after_ready, during_proxy, during_api;
} kernel;
struct FakeClock {
  using duration=std::chrono::microseconds; using rep=duration::rep; using period=duration::period;
  using time_point=std::chrono::time_point<FakeClock>; static constexpr bool is_steady=true;
  static time_point now() { return time_point(duration(kernel.now*1000+kernel.sub_ms_us)); }
};
void RequireNonblocking(){if(!kernel.nonblocking)throw std::runtime_error("blocking_socket_operation");}
int ioctlsocket(SOCKET,long,u_long* value){++kernel.nonblock_calls;kernel.nonblocking=*value!=0;if(kernel.cancel_in_nonblock)kernel.cancel=true;return kernel.nonblock_result;}
int getsockopt(SOCKET,int,int,char* value,int*){++kernel.option_reads;*reinterpret_cast<int*>(value)=kernel.socket_error;return kernel.option_result;}
int InertSelect(int,InertFdSet*,InertFdSet* writing,InertFdSet*,InertTimeval* wait){
  ++kernel.polls;const long ms=wait->tv_sec*1000+wait->tv_usec/1000;kernel.max_poll=std::max(kernel.max_poll,static_cast<int>(ms));
  if(kernel.delay_readiness){
    if(kernel.ready_remaining<0)kernel.ready_remaining=writing?kernel.send_delay:kernel.recv_delay;
    const auto step=std::min(kernel.ready_remaining,static_cast<int64_t>(ms));kernel.now+=step;kernel.ready_remaining-=step;
    if(kernel.ready_remaining>0)return 0;
  }else kernel.now+=std::min(static_cast<long>(kernel.poll_delay),ms);
  if(kernel.cancel_in_poll)kernel.cancel=true;
  if(kernel.select_interrupts>0){--kernel.select_interrupts;kernel.error=WSAEINTR;return SOCKET_ERROR;}
  return kernel.poll_result;
}
int MAKEWORD(int a, int b) { return a|(b<<8); }
int WSAStartup(int, WSADATA*) { ++kernel.startup; return kernel.start_result; }
int WSACleanup() { ++kernel.cleanup;kernel.now+=kernel.cleanup_delay;if(kernel.cancel_on_cleanup)kernel.cancel=true;return 0; }
SOCKET socket(int,int,int) { if(kernel.fail_socket) return INVALID_SOCKET; ++kernel.opens;kernel.live.insert(42);return 42; }
int closesocket(SOCKET fd) { if(!kernel.live.erase(fd)) throw std::runtime_error("double_close");++kernel.closes;kernel.now+=kernel.close_delay;if(kernel.cancel_on_close)kernel.cancel=true;return 0; }
int setsockopt(SOCKET,int,int,const char*,int) { return 0; }
uint16_t InertHtons(uint16_t value) { return value; }
int InetPtonA(int,const char*,uint32_t* address) { *address=0x7f000001;return 1; }
int connect(SOCKET,sockaddr*,int) { ++kernel.connects;RequireNonblocking();kernel.now+=kernel.connect_delay;return kernel.connect_result; }
int send(SOCKET,const char* data,int size,int) { ++kernel.sends;RequireNonblocking();if(!kernel.delay_readiness)kernel.now+=kernel.send_delay;kernel.ready_remaining=-1;
  if(kernel.send_wouldblock>0){--kernel.send_wouldblock;kernel.error=WSAEWOULDBLOCK;return SOCKET_ERROR;}
  if(kernel.send_result == SOCKET_ERROR) return SOCKET_ERROR;
  const int count=kernel.send_result == -2?size:std::min(size,kernel.send_result);
  kernel.written.append(data,static_cast<size_t>(count));return count;
}
int recv(SOCKET,char* data,int size,int) { ++kernel.receives;RequireNonblocking();if(!kernel.delay_readiness)kernel.now+=kernel.recv_delay;kernel.ready_remaining=-1;
  if(kernel.recv_wouldblock>0){--kernel.recv_wouldblock;kernel.error=WSAEWOULDBLOCK;return SOCKET_ERROR;}
  if(kernel.cancel_on_receive) kernel.cancel=true;
  if(kernel.recv_result != -2) return kernel.recv_result;
  const auto count=std::min({static_cast<size_t>(size),kernel.chunk,kernel.reply.size()-kernel.offset});
  std::copy_n(kernel.reply.data()+kernel.offset,count,data);kernel.offset+=count;return static_cast<int>(count);
}
int WSAGetLastError() { return kernel.error; }
void GetExitCodeProcess(HANDLE,DWORD* code) { *code=1; }
void InertSleep(std::chrono::milliseconds duration) { kernel.now+=duration.count(); }
void Require(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
void Reset(bool auth=false) { kernel=Kernel{};kernel.reply=auth?std::string("\5\2\1\0",4):std::string("\5\0",2); }

'''

ADAPTER = r'''

namespace readiness_under_test {
ACTUAL
bool WithBudget(uint16_t port,const std::string& user,const std::string& password,
                int64_t deadline, const std::function<bool()>& cancelled) {
  const SocksReadinessBudget parent(FakeClock::time_point(std::chrono::milliseconds(deadline)),cancelled);
  return SocksReady(port,user,password,&parent);
}
}
namespace flutter_vless { namespace native {
using SocksReadinessBudget=readiness_under_test::SocksReadinessBudget;
bool SocksReady(uint16_t,const std::string&,const std::string&,const SocksReadinessBudget* budget) {
  ++kernel.ready_calls;
  for(int elapsed=0;elapsed<kernel.ready_delay;elapsed+=50){if(!budget->CanContinue())return false;kernel.now+=50;}
  if(kernel.after_ready) kernel.after_ready();
  return kernel.ready_result;
}
} }
class ProxyConsumer {
 public:
  std::atomic<bool> is_running_{true};
  struct Process { bool IsRunning()const{return true;} } process;
  Process* xray_process_=&process;
  bool SetSystemProxy(const char*,uint16_t) { ++kernel.proxy_effects;if(kernel.during_proxy)kernel.during_proxy();return true; }
  void InitializeApiClient() {++kernel.api_effects;if(kernel.during_api)kernel.during_api();}
  void StopXrayProcess() {} void CleanupTempFiles() {} void finish(bool ready) { if(ready)++kernel.ready_effects; }
  void Run() { auto port=std::optional<uint16_t>(uint16_t{10808});std::string user="u",password="p";
PROXY
    finish(true);
  }
};
class VpnConsumer {
 public:
  std::atomic<bool> requested_{true};
  struct Process { bool IsRunning()const{return true;} HANDLE hProcess=nullptr; } process;
  Process* xray_process_=&process;uint16_t socks_port_=10808;std::string username_="u",password_="p";
  void Event(const char*) {}
  bool Run() { auto fail=[](const char*){return false;};
    using namespace flutter_vless;
VPN
    ++kernel.tun_effects;return true;
  }
};

'''

CONTROLS = r'''

int main() {
  int total=0,failed=0;
  auto test=[&](const char* name,auto run){++total;Reset();try{run();Require(kernel.live.empty(),"socket_leak");
    std::cout<<"PASS "<<name<<"\n";}catch(const std::exception& error){++failed;std::cout<<"FAIL "<<name<<" "<<error.what()<<"\n";}};
  auto call=[](bool auth=false,int64_t deadline=3000){return readiness_under_test::WithBudget(10808,auth?"u":"",auth?"p":"",deadline,[]{return kernel.cancel;});};
  test("legacy-one-argument-source-compatible",[&]{Require(readiness_under_test::SocksReady(10808),"legacy_one_arg_refused");});
  test("legacy-two-argument-source-compatible",[&]{Reset(true);Require(readiness_under_test::SocksReady(10808,"u"),"legacy_two_args_refused");Require(kernel.written==std::string("\5\1\2\1\1u\0",7),"legacy_empty_password_changed");});
  test("legacy-three-argument-source-compatible",[&]{Reset(true);Require(readiness_under_test::SocksReady(10808,"u","p"),"legacy_three_args_refused");});
  test("legacy-noauth-exact",[&]{Require(call(),"noauth_rejected");Require(kernel.written==std::string("\5\1\0",3),"wrong_noauth_bytes");});
  test("legacy-auth-exact",[&]{Reset(true);Require(call(true),"auth_rejected");Require(kernel.written==std::string("\5\1\2\1\1u\1p",8),"wrong_auth_bytes");});
  test("auth-method-downgrade-refused",[&]{Require(!call(true),"auth_downgraded");Require(kernel.sends==1,"auth_after_downgrade");});
  test("wrong-method-version-refused",[&]{kernel.reply=std::string("\4\0",2);Require(!call(),"wrong_version_accepted");});
  test("auth-denial-refused",[&]{Reset(true);kernel.reply=std::string("\5\2\1\1",4);Require(!call(true),"auth_denial_accepted");});
  test("fragmented-reply-success",[&]{Reset(true);kernel.chunk=1;Require(call(true),"valid_fragments_refused");Require(kernel.receives==4,"missing_auth_reply_reads");});
  test("EOF-before-exact-reply",[&]{kernel.reply=std::string("\5",1);Require(!call(),"EOF_accepted");Require(kernel.receives==2,"EOF_retried");});
  test("recv-fatal-error-not-retried",[&]{kernel.recv_result=SOCKET_ERROR;Require(!call(),"fatal_error_accepted");Require(kernel.receives==1,"fatal_error_retried");});
  test("recv-interruption-policy-retained",[&]{kernel.recv_result=SOCKET_ERROR;kernel.error=WSAEINTR;Require(!call(),"interruption_accepted");Require(kernel.receives==1,"interruption_retried");});
  test("partial-send-advances-under-one-budget",[&]{kernel.send_result=1;Require(call(),"partial_send_lost_progress");Require(kernel.written==std::string("\5\1\0",3),"partial_send_replayed_bytes");});
  test("oversized-auth-refused-before-I/O",[&]{Reset(true);Require(!readiness_under_test::WithBudget(10808,std::string(256,'u'),"p",3000,[]{return false;}),"oversized_auth_accepted");Require(kernel.sends==0&&kernel.opens==0&&kernel.startup==0,"I/O_before_invalid_auth_refusal");});
  test("oversized-password-refused-before-I/O",[&]{Reset(true);Require(!readiness_under_test::WithBudget(10808,"u",std::string(256,'p'),3000,[]{return false;}),"oversized_password_accepted");Require(kernel.sends==0&&kernel.opens==0&&kernel.startup==0,"I/O_before_invalid_password_refusal");});
  test("noauth-ignores-unused-password",[&]{Require(readiness_under_test::WithBudget(10808,"",std::string(256,'p'),3000,[]{return false;}),"unused_password_narrowed_legacy_noauth");});
  test("socket-create-failure-balanced",[&]{kernel.fail_socket=true;Require(!call(),"bad_socket_accepted");Require(kernel.startup==1&&kernel.cleanup==1,"WSA_reference_leak");});
  test("fragmentation-cannot-renew-total",[&]{Reset(true);kernel.chunk=1;kernel.delay_readiness=true;kernel.connect_delay=490;kernel.send_delay=490;kernel.recv_delay=490;Require(!call(true),"late_fragmented_auth_accepted");Require(kernel.now<=3050,"fragmentation_extended_budget");});
  test("connect-completion-after-deadline-refused",[&]{kernel.connect_delay=10000;Require(!call(),"late_connect_accepted");Require(kernel.sends==0,"send_after_late_connect");});
  test("cancel-before-I/O",[&]{kernel.cancel=true;Require(!call(),"cancel_ignored");Require(kernel.opens==0&&kernel.startup==0,"I/O_after_cancel");});
  test("cancel-after-partial-reply",[&]{kernel.chunk=1;kernel.cancel_on_receive=true;Require(!call(),"cancelled_reply_accepted");Require(kernel.receives==1,"I/O_after_cancel");});
  test("same-budget-across-caller-retries",[&]{kernel.connect_result=SOCKET_ERROR;kernel.connect_delay=800;Require(!call(false,1000),"refused_connect_accepted");kernel.connect_result=0;kernel.connect_delay=300;Require(!call(false,1000),"retry_refreshed_shared_deadline");});
  test("deadline-boundary-rejects-success",[&]{kernel.connect_delay=1000;Require(!call(false,1000),"deadline_equal_accepted");});
  test("proxy-Stop-during-listener-cannot-install-system-proxy",[&]{ProxyConsumer service;kernel.after_ready=[&]{service.is_running_.store(false);};service.Run();Require(kernel.proxy_effects==0,"late_proxy_side_effect");});
  test("proxy-Stop-during-system-proxy-setup-cannot-publish-ready",[&]{ProxyConsumer service;kernel.during_proxy=[&]{service.is_running_.store(false);};service.Run();Require(kernel.proxy_effects==1,"expected_owned_setup");Require(kernel.api_effects==0&&kernel.ready_effects==0,"ready_after_Stop");});
  test("VPN-Stop-during-listener-cannot-admit-tun",[&]{VpnConsumer service;kernel.after_ready=[&]{service.requested_.store(false);};Require(!service.Run(),"late_tun_admitted");Require(kernel.tun_effects==0,"late_tun_side_effect");});
  test("invalid-zero-port-no-I/O",[&]{Require(!readiness_under_test::WithBudget(0,"","",3000,[]{return false;}),"zero_port_accepted");Require(kernel.opens==0&&kernel.startup==0,"zero_port_I/O");});
  test("WSA-start-failure-does-not-release-unowned-reference",[&]{kernel.start_result=1;Require(!call(),"WSA_failure_accepted");Require(kernel.opens==0&&kernel.cleanup==0,"unowned_WSA_release");});
  test("pending-connect-verifies-SO-ERROR",[&]{kernel.connect_result=SOCKET_ERROR;kernel.error=WSAEWOULDBLOCK;Require(call(),"valid_pending_connect_refused");Require(kernel.option_reads==1,"pending_connect_skipped_SO_ERROR");});
  test("pending-connect-error-refused",[&]{kernel.connect_result=SOCKET_ERROR;kernel.error=WSAEINPROGRESS;kernel.socket_error=WSAECONNRESET;Require(!call(),"SO_ERROR_ignored");Require(kernel.sends==0&&kernel.option_reads==1,"traffic_after_failed_connect");});
  test("pending-connect-option-read-failure-refused",[&]{kernel.connect_result=SOCKET_ERROR;kernel.error=WSAEWOULDBLOCK;kernel.option_result=SOCKET_ERROR;Require(!call(),"SO_ERROR_read_failure_ignored");Require(kernel.sends==0,"traffic_after_option_failure");});
  test("fatal-connect-error-no-select-retry",[&]{kernel.connect_result=SOCKET_ERROR;kernel.error=WSAECONNRESET;Require(!call(),"fatal_connect_accepted");Require(kernel.polls==0,"fatal_connect_retried");});
  test("nonblock-setup-failure-owned-cleanup",[&]{kernel.nonblock_result=SOCKET_ERROR;Require(!call(),"nonblock_failure_accepted");Require(kernel.connects==0&&kernel.closes==1&&kernel.cleanup==1,"nonblock_failure_leak");});
  test("cancel-after-nonblock-before-connect",[&]{kernel.cancel_in_nonblock=true;Require(!call(),"cancel_after_nonblock_ignored");Require(kernel.connects==0,"connect_after_cancel");});
  test("pending-connect-cancel-does-not-admit-auth",[&]{kernel.connect_result=SOCKET_ERROR;kernel.error=WSAEWOULDBLOCK;kernel.cancel_in_poll=true;Require(!call(),"pending_cancel_ignored");Require(kernel.sends==0,"auth_after_pending_cancel");});
  test("wouldblock-send-retains-exact-progress",[&]{kernel.send_wouldblock=2;kernel.send_result=1;kernel.poll_delay=1;Require(call(),"send_wouldblock_refused");Require(kernel.written==std::string("\5\1\0",3),"send_wouldblock_replayed_bytes");});
  test("wouldblock-receive-retains-exact-progress",[&]{kernel.recv_wouldblock=2;kernel.chunk=1;kernel.poll_delay=1;Require(call(),"recv_wouldblock_refused");Require(kernel.receives==4,"wrong_receive_progress");});
  test("endless-wouldblock-respects-total",[&]{kernel.recv_wouldblock=100000;kernel.poll_delay=50;Require(!call(false,175),"wouldblock_extended_budget");Require(kernel.now==175&&kernel.max_poll<=50,"wouldblock_deadline_refreshed");});
  test("select-interruption-rechecks-same-budget",[&]{kernel.select_interrupts=100000;kernel.poll_delay=50;Require(!call(false,175),"interruption_extended_budget");Require(kernel.now==175&&kernel.sends==0,"I/O_after_interruption_deadline");});
  test("zero-send-is-fatal",[&]{kernel.send_result=0;Require(!call(),"zero_send_accepted");Require(kernel.sends==1&&kernel.receives==0,"zero_send_retried");});
  test("late-complete-reply-rejected",[&]{kernel.recv_delay=1000;Require(!call(false,1000),"late_full_reply_accepted");});
  test("fractional-tail-rejects-late-readiness",[&]{kernel.sub_ms_us=500;kernel.poll_delay=50;kernel.poll_result=0;Require(!call(false,1),"fractional_tail_accepted");Require(kernel.max_poll==1&&kernel.sends==0,"fractional_tail_I/O");});
  test("throwing-cancellation-fails-closed-before-I/O",[&]{Require(!readiness_under_test::WithBudget(10808,"","",3000,[]() -> bool {throw std::runtime_error("synthetic");}),"throwing_cancel_accepted");Require(kernel.opens==0&&kernel.startup==0,"I/O_after_callback_failure");});
  test("actual-VPN-parent-budget-shared-across-retries",[&]{VpnConsumer service;kernel.ready_result=false;kernel.ready_delay=1000;Require(!service.Run(),"bad_listener_admitted");Require(kernel.ready_calls==6&&kernel.now<=6100,"VPN_parent_deadline_refreshed");});
  test("actual-Proxy-parent-budget-shared-across-retries",[&]{ProxyConsumer service;kernel.ready_result=false;kernel.ready_delay=1000;service.Run();Require(kernel.ready_calls==5&&kernel.now<=5100,"Proxy_parent_deadline_refreshed");Require(kernel.proxy_effects==0,"proxy_without_listener");});
  test("proxy-Stop-during-API-cannot-publish-ready",[&]{ProxyConsumer service;kernel.during_api=[&]{service.is_running_.store(false);};service.Run();Require(kernel.api_effects==1&&kernel.ready_effects==0,"ready_after_API_Stop");});
  test("close-deadline-expiry-rejects-success",[&]{kernel.close_delay=1000;Require(!call(false,1000),"success_after_close_deadline");Require(kernel.closes==1&&kernel.cleanup==1,"close_not_once");});
  test("WSA-cleanup-deadline-expiry-rejects-success",[&]{kernel.cleanup_delay=1000;Require(!call(false,1000),"success_after_WSA_cleanup_deadline");Require(kernel.closes==1&&kernel.cleanup==1,"cleanup_not_once");});
  test("close-cancellation-rejects-success",[&]{kernel.cancel_on_close=true;Require(!call(),"success_after_close_cancel");Require(kernel.closes==1&&kernel.cleanup==1,"close_cancel_cleanup_not_once");});
  test("WSA-cleanup-cancellation-rejects-success",[&]{kernel.cancel_on_cleanup=true;Require(!call(),"success_after_WSA_cleanup_cancel");Require(kernel.closes==1&&kernel.cleanup==1,"WSA_cancel_cleanup_not_once");});
  test("VPN-deadline-after-listener-cannot-admit-tun",[&]{VpnConsumer service;kernel.after_ready=[&]{kernel.now=6000;};Require(!service.Run(),"expired_listener_admitted_tun");Require(kernel.tun_effects==0,"tun_after_parent_deadline");});
  test("Proxy-deadline-after-listener-cannot-install-proxy",[&]{ProxyConsumer service;kernel.after_ready=[&]{kernel.now=5000;};service.Run();Require(kernel.proxy_effects==0&&kernel.api_effects==0&&kernel.ready_effects==0,"proxy_after_parent_deadline");});
  std::cout<<"WINDOWS_SOCKS_READINESS_BUDGET_PURE_PASS="<<(total-failed)<<" FAIL="<<failed<<"\n";if(total!=52)return 2;return failed?1:0;
}

'''

class Boundaries(unittest.TestCase):
    def test_missing_or_duplicate_real_body_refuses(self):
        for name,token in (("native_runtime.h","class SocksReadinessBudget {"),("native_runtime.cpp","bool SocksReady("),
                           ("proxy_service.cpp","  start_time_ = std::chrono::steady_clock::now();"),
                           ("vpn_service.cpp","  // Credentials live only in a private file")):
            for replacement in ("",token+token):
                data=sources();data[name]=data[name].replace(token,replacement)
                with self.assertRaises(ValueError):actual(data)

    def test_no_unrelated_platform_work_selected(self):
        text=actual(sources())
        self.assertNotIn("native::Launch(",text)
        self.assertNotIn("WriteConfig(",text)
        self.assertNotIn("WSAStartup(",text[:text.index("bool SocksReady(")])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--generate",type=Path,required=True)
    args=parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Boundaries))
    if not result.wasSuccessful():return 1
    data=sources();args.generate.parent.mkdir(parents=True,exist_ok=True)
    args.generate.write_text(FAKES+actual(data)+CONTROLS)
    args.generate.with_suffix(".sources.json").write_text(json.dumps({
        "production_sha256":{n:hashlib.sha256(v.encode()).hexdigest() for n,v in data.items()},
        "test_tool_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "native_builder_sha256":hashlib.sha256((ROOT/"tool/windows/build_native_tests.cmd").read_bytes()).hexdigest(),
        "actual_bodies":["SocksReadinessBudget","SocksReady","VPN startup listener admission","Proxy startup listener/API admission"],
        "real_socket_process_thread_Core":False,"source_guards":result.testsRun,
    },indent=2)+"\n")
    return 0

if __name__=="__main__":raise SystemExit(main())
