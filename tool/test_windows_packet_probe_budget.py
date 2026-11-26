#!/usr/bin/env python3
"""Generate actual packet-probe I/O consumers with fake Winsock/clock boundaries.

No socket, thread, Core, process or Windows API is executed by the generated
test. The production Check/Serve/framing bodies are retained; only clock,
thread type and platform fd-set/timeval names are adapted for portable C++.
"""
import argparse
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "packages/flutter_vless_windows/windows"


def section(source, first, after):
    if source.count(first) != 1 or source.count(after) != 1:
        raise ValueError("production source boundary changed")
    start, end = source.index(first), source.index(after)
    if start >= end:
        raise ValueError("production source order changed")
    return source[start:end]


def sources():
    return {name: (WINDOWS / name).read_text() for name in
            ("packet_path_probe.h", "packet_path_probe.cpp", "vpn_service.cpp")}


def actual(data):
    header, source, service = (data[n] for n in
                              ("packet_path_probe.h", "packet_path_probe.cpp", "vpn_service.cpp"))
    declaration = section(header, "class PacketPathProbe {", "\n}  // namespace flutter_vless")
    if declaration.count("std::thread worker_;") != 1 or declaration.count("\n private:") != 1:
        raise ValueError("probe ownership boundary changed")
    declaration = declaration.replace("std::thread worker_;", "InertWorker worker_;").replace("\n private:", "\n public:")
    helper = section(source, "namespace {\n", "PacketPathProbe::~PacketPathProbe() {")
    if "std::chrono::steady_clock" in helper:
        if helper.count("std::chrono::steady_clock") != 1:
            raise ValueError("multiple real clock boundaries")
        helper = helper.replace("std::chrono::steady_clock", "FakeClock")
    destructor = section(source, "PacketPathProbe::~PacketPathProbe() {", "bool PacketPathProbe::Start() {")
    serve = section(source, "void PacketPathProbe::Serve() {", "bool PacketPathProbe::Configure(")
    check = section(source, "bool PacketPathProbe::Check(", "}  // namespace flutter_vless")
    probe = "namespace flutter_vless {\n" + declaration + helper + destructor + serve + check + "}\n"
    # The Windows fd types/macros are fakes, not Darwin's similarly named APIs.
    probe = probe.replace("fd_set", "InertFdSet").replace("timeval", "InertTimeval")
    # Preserve the actual post-listener admission block before tun config work.
    admission = section(service, "  const native::SocksReadinessBudget readiness_budget(", "  // Credentials live only in a private file")
    if admission.count("native::SocksReady(") != 1:
        raise ValueError("listener admission boundary changed")
    admission = admission.replace("std::this_thread::sleep_for", "InertSleep")
    periodic = section(service, "      if (!xray_process_->IsRunning()", "      if (++ticks % 2 == 0)")
    if periodic.count("break;") != 1:
        raise ValueError("periodic health consumer changed")
    periodic = periodic.replace("break;", "return false;")
    startup = section(service, "    if (worker_candidate_->PacketProbe().Check(", "    std::this_thread::sleep_for(std::chrono::milliseconds(100));\n  }\n  return fail(\"Private packet-path challenge")
    optimistic_dad = section(service, "bool IsTun2socksDescription(", "bool TunnelReady(")
    optimistic_dad = optimistic_dad.replace("_wcsnicmp", "InertWcsnicmp")
    cancel = "const std::function<bool()>&" in declaration
    adapter = "return probe.Check(PacketPathProbe::address, [] { return kernel.cancel; });" if cancel else "return probe.Check();"
    return probe + optimistic_dad + r'''
namespace flutter_vless {
bool CheckWithCancel(PacketPathProbe& probe) { ADAPTER }
namespace native {
class SocksReadinessBudget {
 public:
  SocksReadinessBudget(std::chrono::milliseconds, std::function<bool()> cancelled) : cancelled_(std::move(cancelled)) {}
  bool CanContinue() const { return !cancelled_(); }
 private:
  std::function<bool()> cancelled_;
};
bool SocksReady(uint16_t, const std::string&, const std::string&, const SocksReadinessBudget*) {
  ++kernel.socks_ready; kernel.cancel = true; if (kernel.join) kernel.join(); return true;
} }
struct StartupTiming { void Mark(const char*) const {} };
class AdmissionConsumer {
 public:
  std::atomic<bool> requested_{true};
  struct Process { bool IsRunning() const { return true; } void* hProcess = nullptr; } process;
  Process* xray_process_ = &process;
  uint16_t socks_port_ = 10808; std::string username_, password_;
  bool ContinueAfterListener() {
    auto fail = [](const char*) { return false; }; (void)fail;
    [[maybe_unused]] StartupTiming timing;
ADMISSION
    ++kernel.tun_side_effects; return true;
  }
};
struct InertReport {};
struct ProbeCandidate {
  PacketPathProbe probe;
  PacketPathProbe& PacketProbe() { return probe; }
  InertReport PreparationReport() { return {}; }
};
class PeriodicConsumer {
 public:
  std::atomic<bool> requested_{true};
  AdmissionConsumer::Process process;
  AdmissionConsumer::Process* xray_process_ = &process;
  AdmissionConsumer::Process* tun2socks_process_ = &process;
  ProbeCandidate candidate;
  ProbeCandidate* worker_candidate_ = &candidate;
  bool Poll() {
PERIODIC
    return true;
  }
  bool StartupPoll() {
    InertReport* report = nullptr;
    [[maybe_unused]] StartupTiming timing;
    const int ipv4 = 0;
    const int ipv6 = 1;
    const std::string ipv6_source = session_source_v6_text;
    const bool optimistic_ipv6 = kernel.optimistic_ipv6;
    const auto TunnelReady = [](int family) { return family ? kernel.ipv6_ready : kernel.ipv4_ready; };
    const auto fail = [](const char*) { return false; };
STARTUP
    return false;
  }
};
}
'''.replace("ADAPTER", adapter).replace("ADMISSION", admission).replace("PERIODIC", periodic).replace("STARTUP", startup)


FAKES = r'''
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <functional>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
using SOCKET = int; using DWORD = unsigned long; using u_long = unsigned long; using HANDLE = void*;
enum { INVALID_SOCKET = -1, SOCKET_ERROR = -1, AF_INET = 2, AF_INET6 = 23, SOCK_STREAM = 1, IPPROTO_TCP = 6,
    SOL_SOCKET = 1, SO_RCVTIMEO = 2, SO_SNDTIMEO = 3, SO_ERROR = 4, FIONBIO = 5,
    WSAEWOULDBLOCK = 10035, WSAEINTR = 10004, WSAEINPROGRESS = 10036 };
struct InertTimeval { long tv_sec, tv_usec; };
struct InertFdSet { SOCKET fd = INVALID_SOCKET; };
#undef FD_ZERO
#undef FD_SET
#define FD_ZERO(p) ((p)->fd = INVALID_SOCKET)
#define FD_SET(fd_, p) ((p)->fd = (fd_))
struct in_addr { struct { uint32_t S_addr = 0; } S_un; };
struct in6_addr { uint8_t bytes[16]{}; };
using IN6_ADDR = in6_addr;
struct sockaddr {};
struct sockaddr_in { int sin_family = 0; uint16_t sin_port = 0; in_addr sin_addr; };
struct sockaddr_in6 { int sin6_family = 0; uint16_t sin6_port = 0; in6_addr sin6_addr; };
constexpr in6_addr probe_target_v6{{0x20,0x01,0x0d,0xb8,0,0x85,0,0,0,0,0,0,0,0,0,0x54}};
constexpr in6_addr wintun_source_v6{{0xfd,0,0x01,0x98,0,0x18,0,0,0,0,0,0,0,0,0,2}};
constexpr char session_source_v6_text[] = "fd00:198:18:0:aabb:ccdd:1122:3344";
constexpr in6_addr session_source_v6{{0xfd,0,0x01,0x98,0,0x18,0,0,0xaa,0xbb,0xcc,0xdd,0x11,0x22,0x33,0x44}};
using ULONG = unsigned long;
enum { NO_ERROR = 0, IF_TYPE_PROP_VIRTUAL = 53, NdisMediumIP = 19,
    IpDadStateTentative = 1, IpDadStatePreferred = 4, ERROR_OBJECT_ALREADY_EXISTS = 5010 };
struct MIB_IF_ROW2 {
  int Type = IF_TYPE_PROP_VIRTUAL, MediaType = NdisMediumIP;
  struct { bool HardwareInterface = false; } InterfaceAndOperStatusFlags;
  const wchar_t* Description = L"tun2socks Tunnel";
};
struct MIB_UNICASTIPADDRESS_ROW {
  struct { int si_family = AF_INET; sockaddr_in Ipv4; sockaddr_in6 Ipv6; } Address;
  int DadState = IpDadStateTentative;
};
struct MIB_UNICASTIPADDRESS_TABLE { ULONG NumEntries = 0; MIB_UNICASTIPADDRESS_ROW Table[2]; };
using PMIB_UNICASTIPADDRESS_TABLE = MIB_UNICASTIPADDRESS_TABLE*;
struct Kernel {
  int64_t now = 0, next_ready = 0, step = 0;
  bool cancel = false, eof = false, wrong = false, would_block = false, connect_pending = false;
  bool ipv4_ready = true, ipv6_ready = true, optimistic_ipv6 = false, reject_optimistic = false;
  int client_family = 0;
  bool exact_ipv6_target = false;
  in6_addr socket_source_v6 = wintun_source_v6;
  MIB_UNICASTIPADDRESS_TABLE local_ipv4;
  bool ipv4_query_failed = false, ipv4_no_table = false, ipv4_table_owned = false;
  unsigned ipv4_queries = 0, ipv4_frees = 0, queried_family = 0, address_creations = 0;
  unsigned io = 0, selects = 0, accepted = 0, closes = 0, joins = 0, socks_ready = 0, tun_side_effects = 0;
  unsigned cancel_after = 0;
  unsigned eof_after = 0;
  int error = 0; std::set<SOCKET> handles, nonblocking;
  std::string incoming, sent; std::size_t offset = 0;
  std::function<void()> after_io, on_close, join;
} kernel;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int InertWcsnicmp(const wchar_t* left, const wchar_t* right, std::size_t count) {
  for (std::size_t i = 0; i < count; ++i) {
    if (std::towlower(left[i]) != std::towlower(right[i])) return 1;
    if (!left[i]) break;
  }
  return 0;
}
int GetUnicastIpAddressTable(int family, PMIB_UNICASTIPADDRESS_TABLE* result) {
  Require((family == AF_INET || family == AF_INET6) && !kernel.ipv4_table_owned, "invalid local IP query");
  kernel.queried_family = family;
  ++kernel.ipv4_queries;
  if (kernel.ipv4_query_failed) return 5;
  if (!kernel.ipv4_no_table) {
    *result = &kernel.local_ipv4;
    kernel.ipv4_table_owned = true;
  }
  return NO_ERROR;
}
ULONG CreateUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* address) {
  ++kernel.address_creations;
  return kernel.reject_optimistic && address->DadState == IpDadStatePreferred ? 87 : NO_ERROR;
}
void FreeMibTable(void* table) {
  Require(table == &kernel.local_ipv4 && kernel.ipv4_table_owned, "invalid local IPv4 table free");
  kernel.ipv4_table_owned = false;
  ++kernel.ipv4_frees;
}
struct FakeClock {
  using duration = std::chrono::milliseconds; using time_point = std::chrono::time_point<FakeClock>;
  static time_point now() { return time_point(duration(kernel.now)); }
};
void Reset() { Require(kernel.handles.empty(), "fake handle retained"); kernel = {}; }
struct InertWorker {
  bool active = false; bool joinable() const { return active; }
  void join() { Require(active, "join without owner"); ++kernel.joins; if (kernel.join) kernel.join(); active = false; }
};
int WSACleanup() { return 0; }
SOCKET socket(int family, int, int) { kernel.client_family = family; Require(kernel.handles.insert(9).second, "socket reused live handle"); return 9; }
int closesocket(SOCKET fd) { Require(kernel.handles.erase(fd) == 1, "double/foreign close"); ++kernel.closes; if (fd == 9 && kernel.on_close) kernel.on_close(); return 0; }
int setsockopt(SOCKET, int, int, const char*, std::size_t) { return 0; }
int InetPtonA(int family, const char* literal, void* address) {
  if (family == AF_INET) return 1;
  if (family != AF_INET6) return 0;
  const std::string_view value(literal);
  if (value == "2001:db8:85::54") *static_cast<in6_addr*>(address) = probe_target_v6;
  else if (value == "fd00:198:18::2") *static_cast<in6_addr*>(address) = wintun_source_v6;
  else if (value == session_source_v6_text) *static_cast<in6_addr*>(address) = session_source_v6;
  else return 0;
  return 1;
}
#undef htons
uint16_t htons(uint16_t value) { return value; }
int ioctlsocket(SOCKET fd, long, u_long* mode) { if (*mode) kernel.nonblocking.insert(fd); else kernel.nonblocking.erase(fd); return 0; }
int WSAGetLastError() { return kernel.error; }
int connect(SOCKET, const sockaddr* address, int length) {
  if (kernel.client_family == AF_INET6 && length == static_cast<int>(sizeof(sockaddr_in6))) {
    const auto& target = *reinterpret_cast<const sockaddr_in6*>(address);
    kernel.exact_ipv6_target = target.sin6_family == AF_INET6 && target.sin6_port == 50001 &&
        std::memcmp(&target.sin6_addr, &probe_target_v6, sizeof(probe_target_v6)) == 0;
  }
  if (!kernel.connect_pending) return 0;
  kernel.error = WSAEWOULDBLOCK; return SOCKET_ERROR;
}
int getsockname(SOCKET fd, sockaddr* address, int* length) {
  Require(fd == 9 && kernel.client_family == AF_INET6 && *length == static_cast<int>(sizeof(sockaddr_in6)),
      "IPv6 source checked on the wrong socket");
  auto& local = *reinterpret_cast<sockaddr_in6*>(address);
  local.sin6_family = AF_INET6;
  local.sin6_addr = kernel.socket_source_v6;
  return 0;
}
int getsockopt(SOCKET, int, int, char* result, int*) { *reinterpret_cast<int*>(result) = 0; return 0; }
int select(int, InertFdSet* read, InertFdSet* write, InertFdSet*, InertTimeval* timeout) {
  ++kernel.selects;
  if (read && read->fd == 7) return 1;
  Require((read && read->fd == 9) || (write && write->fd == 9), "select unowned socket");
  const auto wait = static_cast<int64_t>(timeout->tv_sec) * 1000 + timeout->tv_usec / 1000;
  Require(wait >= 0 && wait <= 750, "unbounded fake select");
  if (kernel.next_ready > kernel.now) {
    kernel.now += std::min(wait, kernel.next_ready - kernel.now);
    if (kernel.next_ready > kernel.now) return 0;
  }
  return 1;
}
SOCKET accept(SOCKET fd, sockaddr*, int*) { Require(fd == 7 && kernel.accepted++ == 0, "unexpected accepted client"); kernel.handles.insert(9); return 9; }
void Progress(SOCKET fd) {
  if (!kernel.nonblocking.count(fd)) kernel.now += kernel.step;
  kernel.next_ready = kernel.now + kernel.step; ++kernel.io;
  if (kernel.after_io) kernel.after_io();
  if (kernel.cancel_after && kernel.io == kernel.cancel_after) kernel.cancel = true;
}
int send(SOCKET fd, const char* bytes, int size, int) {
  Require(kernel.handles.count(fd) && size > 0, "send unowned/empty");
  if (kernel.would_block) { kernel.error = WSAEWOULDBLOCK; kernel.now += 25; return SOCKET_ERROR; }
  kernel.sent.push_back(*bytes); Progress(fd); return 1;
}
int recv(SOCKET fd, char* bytes, int size, int) {
  Require(kernel.handles.count(fd) && size > 0, "recv unowned/empty");
  if (kernel.eof || (kernel.eof_after && kernel.offset == kernel.eof_after)) return 0;
  if (kernel.would_block) { kernel.error = WSAEWOULDBLOCK; kernel.now += 25; return SOCKET_ERROR; }
  Require(kernel.offset < kernel.incoming.size(), "fake reply overread");
  *bytes = kernel.wrong ? '!' : kernel.incoming[kernel.offset++]; Progress(fd); return 1;
}
void InertSleep(std::chrono::milliseconds) { throw std::runtime_error("unexpected retry sleep"); }
int GetExitCodeProcess(HANDLE, DWORD* code) { *code = 0; return 1; }
void Event(const char*) {}
namespace flutter_vless { namespace xray_config { struct Json {}; } }
'''


CONTROLS = r'''
int main() {
  std::cout.setf(std::ios::unitbuf);
  using flutter_vless::PacketPathProbe;
  unsigned passed = 0, failed = 0;
  auto test = [&](const char* name, const std::function<void()>& body) {
    try { Reset(); body(); Require(kernel.handles.empty() && !kernel.ipv4_table_owned, "fake handles leaked"); ++passed; std::cout << "PASS " << name << '\n'; }
    catch (const std::exception& e) { ++failed; std::cout << "FAIL " << name << ": " << e.what() << '\n'; kernel.handles.clear(); }
  };
  const std::string nonce(64, 'n');
  auto configure = [&](PacketPathProbe& probe) { probe.running_.store(true); probe.port_ = 50001; probe.challenge_ = nonce; kernel.incoming = nonce + "-ok"; };
  test("fragmented-correct", [&] { PacketPathProbe probe; configure(probe); Require(probe.Check(), "correct response rejected"); Require(kernel.sent == nonce && kernel.offset == nonce.size()+3 && kernel.closes == 1, "framing changed"); });
  test("ipv6-authenticated-challenge-uses-exact-endpoint-and-source", [&] {
    PacketPathProbe probe; configure(probe); kernel.connect_pending = true;
    kernel.socket_source_v6 = session_source_v6;
    Require(probe.Check(PacketPathProbe::ipv6_address, {}, session_source_v6_text)
        && kernel.client_family == AF_INET6 && kernel.exact_ipv6_target,
        "IPv6 challenge missed the configured endpoint");
    Require(kernel.sent == nonce && kernel.offset == nonce.size()+3 && kernel.closes == 1,
        "IPv6 challenge response changed");
  });
  test("ipv6-unexpected-source-rejects-before-sending-nonce", [&] {
    PacketPathProbe probe; configure(probe);
    Require(!probe.Check(PacketPathProbe::ipv6_address, {}, session_source_v6_text)
        && kernel.exact_ipv6_target && kernel.sent.empty()
        && kernel.io == 0 && kernel.closes == 1, "IPv6 challenge admitted a non-tunnel source");
  });
  test("ipv6-challenge-requires-a-valid-source-address-before-opening-a-socket", [&] {
    PacketPathProbe probe; configure(probe);
    Require(!probe.Check(PacketPathProbe::ipv6_address)
        && !probe.Check(PacketPathProbe::ipv6_address, {}, "10.0.85.2")
        && kernel.client_family == 0 && kernel.io == 0 && kernel.closes == 0,
        "IPv6 challenge opened a socket without a valid source address");
  });
  test("fragmented-total-deadline", [&] { PacketPathProbe probe; configure(probe); kernel.step = 700; Require(!probe.Check(), "fragmentation renewed deadline"); Require(kernel.now < 4000 && kernel.io < nonce.size(), "aggregate budget absent"); });
  test("running-cancel-after-partial", [&] { PacketPathProbe probe; configure(probe); kernel.after_io = [&] { if (kernel.io == 2) probe.running_.store(false); }; Require(!probe.Check() && kernel.io == 2, "probe Stop did not cancel partial I/O"); });
  test("caller-cancel-after-partial", [&] { PacketPathProbe probe; configure(probe); kernel.cancel_after = 2; Require(!flutter_vless::CheckWithCancel(probe) && kernel.io == 2, "worker Stop did not cancel partial I/O"); });
  test("pre-cancel-does-not-open", [&] { PacketPathProbe probe; configure(probe); kernel.cancel = true; Require(!flutter_vless::CheckWithCancel(probe) && kernel.closes == 0 && kernel.io == 0, "cancelled worker opened probe"); });
  test("invalid-response", [&] { PacketPathProbe probe; configure(probe); kernel.wrong = true; Require(!probe.Check(), "invalid nonce accepted"); });
  test("complete-but-late-response", [&] { PacketPathProbe probe; configure(probe); kernel.after_io = [&] { if (kernel.offset == kernel.incoming.size()) kernel.now = 2250; }; Require(!probe.Check(), "late complete response accepted"); });
  test("EOF", [&] { PacketPathProbe probe; configure(probe); kernel.eof = true; Require(!probe.Check() && kernel.io == nonce.size(), "EOF accepted/retried"); });
  test("partial-then-EOF", [&] { PacketPathProbe probe; configure(probe); kernel.eof_after = 2; Require(!probe.Check() && kernel.offset == 2, "partial EOF accepted/retried"); });
  test("would-block-budget", [&] { PacketPathProbe probe; configure(probe); kernel.would_block = true; Require(!probe.Check() && kernel.now <= 2300, "would-block deadline lost"); });
  test("pending-connect", [&] { PacketPathProbe probe; configure(probe); kernel.connect_pending = true; Require(probe.Check() && kernel.closes == 1, "pending connect broken"); });
  test("pending-connect-timeout", [&] { PacketPathProbe probe; configure(probe); kernel.connect_pending = true; kernel.next_ready = 10000; Require(!probe.Check() && !kernel.io && kernel.now <= 2250, "connect exceeded exchange budget"); });
  auto server = [&](bool cancel, bool drip) {
    PacketPathProbe probe; configure(probe); probe.listener_ = 7; kernel.handles.insert(7); kernel.incoming = nonce;
    kernel.on_close = [&] { probe.running_.store(false); };
    if (drip) kernel.step = 700;
    if (cancel) kernel.after_io = [&] { if (kernel.io == 2) probe.running_.store(false); };
    probe.Serve();
    Require(kernel.accepted == 1 && kernel.closes == 1 && kernel.handles.count(7), "accepted socket ownership changed");
    if (drip) Require(kernel.now < 3000 && kernel.sent.empty(), "server fragmentation renewed deadline");
    else if (cancel) Require(kernel.io == 2 && kernel.sent.empty(), "server stop did not cancel partial read");
    else Require(kernel.sent == nonce + "-ok", "server nonce response changed");
  };
  test("server-correct", [&] { server(false,false); });
  test("server-total-deadline", [&] { server(false,true); });
  test("server-cancel-closes-accepted", [&] { server(true,false); });
  test("server-rejects-invalid-nonce", [&] { PacketPathProbe probe; configure(probe); probe.listener_ = 7; kernel.handles.insert(7); kernel.incoming = nonce; kernel.wrong = true; kernel.on_close = [&] { probe.running_.store(false); }; probe.Serve(); Require(kernel.sent.empty() && kernel.closes == 1 && kernel.handles.count(7), "server accepted invalid nonce/leaked client"); });
  test("destructor-cancel-join-before-close", [&] { auto probe = std::make_unique<PacketPathProbe>(); configure(*probe); probe->listener_ = 7; kernel.handles.insert(7); probe->worker_.active = true; const auto* owned = probe.get(); kernel.join = [&] { Require(!owned->running_.load() && kernel.handles.count(7), "close before joined cancellation"); }; probe.reset(); Require(kernel.joins == 1 && kernel.closes == 1, "listener ownership lost"); });
  test("cancelled-listener-cannot-admit-tun", [&] { flutter_vless::AdmissionConsumer service; kernel.after_io = {}; service.requested_.store(true); kernel.cancel = false;
    // This models Stop arriving during the synchronous readiness callback.
    kernel.join = [&] { service.requested_.store(false); };
    Require(!service.ContinueAfterListener() && kernel.tun_side_effects == 0, "late listener success admitted tun worker"); });
  test("actual-periodic-Stop-callback", [&] { flutter_vless::PeriodicConsumer service; configure(service.candidate.probe); kernel.after_io = [&] { if (kernel.io == 2) service.requested_.store(false); }; Require(!service.Poll() && kernel.io == 2, "actual periodic health lost Stop callback"); });
  test("actual-startup-Stop-callback", [&] { flutter_vless::PeriodicConsumer service; configure(service.candidate.probe); kernel.after_io = [&] { if (kernel.io == 2) service.requested_.store(false); }; Require(!service.StartupPoll() && kernel.io == 2, "actual startup health lost Stop callback"); });
  test("actual-startup-rejects-ipv4-loss-after-packet-check", [&] {
    flutter_vless::PeriodicConsumer service; configure(service.candidate.probe);
    kernel.on_close = [&] { kernel.ipv4_ready = false; };
    Require(!service.StartupPoll(), "Successful packet probe admitted an invalid IPv4 address");
  });
  test("actual-startup-requires-ipv6-packet-and-address-for-optimistic-v6", [&] {
    flutter_vless::PeriodicConsumer service; configure(service.candidate.probe);
    kernel.optimistic_ipv6 = true;
    kernel.socket_source_v6 = session_source_v6;
    kernel.on_close = [&] {
      if (kernel.client_family == AF_INET) kernel.offset = 0;
      else kernel.ipv6_ready = false;
    };
    Require(!service.StartupPoll() && kernel.exact_ipv6_target && kernel.closes == 2,
        "Optimistic IPv6 startup bypassed the second nonce or the final address check");
  });
  MIB_UNICASTIPADDRESS_ROW address{};
  address.Address.Ipv4.sin_addr.S_un.S_addr = 1;
  test("raw-ip-wintun-with-free-local-address-can-use-optimistic-dad", [&] {
    MIB_IF_ROW2 wintun{}; wintun.Description = L"TUN2SOCKS TUNNEL";
    kernel.local_ipv4.NumEntries = 1;
    kernel.local_ipv4.Table[0].Address.Ipv4.sin_addr.S_un.S_addr = 2;
    Require(CanUseOptimisticDad(wintun, address) && kernel.ipv4_queries == 1 && kernel.ipv4_frees == 1,
        "private raw-IP tunnel rejected without a local conflict");
  });
  test("windows-numbered-wintun-descriptions-can-use-optimistic-dad", [&] {
    MIB_IF_ROW2 wintun{};
    for (const auto* description : {L"tun2socks Tunnel #2", L"TUN2SOCKS TUNNEL #19"}) {
      wintun.Description = description;
      Require(CanUseOptimisticDad(wintun, address), "numbered Windows tunnel description rejected");
    }
    Require(kernel.ipv4_queries == 2 && kernel.ipv4_frees == 2, "numbered tunnel bypassed inventory check");
  });
  test("wintun-description-lookalikes-keep-standard-dad", [&] {
    MIB_IF_ROW2 lookalike{};
    for (const auto* description : {L"tun2socks Tunne", L"tun2socks Tunnel backup", L"tun2socks Tunnel #",
        L"tun2socks Tunnel #0", L"tun2socks Tunnel #02", L"tun2socks Tunnel #\u0662", L"tun2socks Tunnel #2 backup",
        L"tun2socks Tunnel #2 ", L"tun2socks Tunnel#2"}) {
      lookalike.Description = description;
      Require(!CanUseOptimisticDad(lookalike, address), "lookalike description allowed optimistic DAD");
    }
    Require(kernel.ipv4_queries == 0, "a lookalike triggered an address query");
  });
  test("local-duplicate-address-keeps-standard-dad", [&] {
    kernel.local_ipv4.NumEntries = 2;
    kernel.local_ipv4.Table[1] = address;
    Require(!CanUseOptimisticDad(MIB_IF_ROW2{}, address) && kernel.ipv4_frees == 1,
        "local duplicate allowed optimistic DAD");
  });
  test("unexpected-identity-or-media-keeps-standard-dad", [&] {
    MIB_IF_ROW2 wrong_type{}, ethernet{}, hardware{}, other_driver{};
    wrong_type.Type = 1;
    ethernet.MediaType = 0;
    hardware.InterfaceAndOperStatusFlags.HardwareInterface = true;
    other_driver.Description = L"Another Tunnel";
    for (const auto& adapter : {wrong_type, ethernet, hardware, other_driver})
      Require(!CanUseOptimisticDad(adapter, address), "unexpected adapter allowed optimistic DAD");
    Require(kernel.ipv4_queries == 0, "unexpected adapter triggered an address query");
  });
  test("unavailable-address-inventory-keeps-standard-dad", [&] {
    kernel.ipv4_query_failed = true;
    Require(!CanUseOptimisticDad(MIB_IF_ROW2{}, address), "failed IPv4 inventory allowed optimistic DAD");
    kernel.ipv4_query_failed = false; kernel.ipv4_no_table = true;
    Require(!CanUseOptimisticDad(MIB_IF_ROW2{}, address) && kernel.ipv4_queries == 2 && kernel.ipv4_frees == 0,
        "missing IPv4 inventory allowed optimistic DAD");
  });
  test("ipv6-inventory-rejects-duplicate-and-accepts-distinct-address", [&] {
    MIB_UNICASTIPADDRESS_ROW target{}; target.Address.si_family = AF_INET6;
    target.Address.Ipv6.sin6_addr = wintun_source_v6;
    kernel.local_ipv4.NumEntries = 1;
    kernel.local_ipv4.Table[0] = target;
    Require(!CanUseOptimisticDad(MIB_IF_ROW2{}, target) && kernel.queried_family == AF_INET6,
        "IPv6 duplicate escaped its address-family inventory");
    kernel.local_ipv4.Table[0].Address.Ipv6.sin6_addr = probe_target_v6;
    Require(CanUseOptimisticDad(MIB_IF_ROW2{}, target) && kernel.ipv4_frees == 2,
        "Unrelated IPv6 address blocked optimistic DAD or leaked the inventory");
  });
  test("ipv6-optimistic-create-rejection-retries-ordinary-dad", [&] {
    MIB_UNICASTIPADDRESS_ROW target{}; target.Address.si_family = AF_INET6;
    kernel.reject_optimistic = true;
    Require(CreateTunnelAddress(target, true) == NO_ERROR && target.DadState == IpDadStateTentative
        && kernel.address_creations == 2, "An unsupported optimistic request skipped ordinary DAD");
  });
  std::cout << "WINDOWS_PACKET_PROBE_BUDGET_PURE_PASS=" << passed << " FAIL=" << failed << '\n';
  if (passed + failed != 33) return 2;
  return failed ? 1 : 0;
}
'''


class Boundaries(unittest.TestCase):
    def test_actual_framing_and_consumers_are_selected(self):
        result = actual(sources())
        for token in ("PacketPathProbe::Check(", "PacketPathProbe::Serve()", "bytes == expected", "native::SocksReady(", "CanUseOptimisticDad("):
            self.assertIn(token, result)
        self.assertNotIn("::Configure(", result)

    def test_missing_or_duplicate_consumer_refuses(self):
        for token in ("void PacketPathProbe::Serve() {", "bool PacketPathProbe::Check("):
            for replacement in ("", token + token):
                data = sources(); data["packet_path_probe.cpp"] = data["packet_path_probe.cpp"].replace(token, replacement)
                with self.assertRaises(ValueError):
                    actual(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", type=Path, required=True)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Boundaries))
    if not result.wasSuccessful():
        return 1
    data = sources()
    output = FAKES.replace("#include <iostream>", "#include <iostream>\n#include <memory>") + actual(data) + CONTROLS
    args.generate.parent.mkdir(parents=True, exist_ok=True)
    args.generate.write_text(output)
    args.generate.with_suffix(".sources.json").write_text(json.dumps({
        "production_sha256": {n: hashlib.sha256(v.encode()).hexdigest() for n, v in data.items()},
        "test_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "native_builder_sha256": hashlib.sha256((ROOT / "tool/windows/build_native_tests.cmd").read_bytes()).hexdigest(),
        "inert_boundaries": ["all Winsock APIs", "monotonic clock", "worker thread", "listener readiness callback", "admission continuation effect counter", "startup diagnostics", "Windows local address inventory"],
        "actual_bodies": ["Send", "Receive", "Check", "Serve", "destructor", "post-SocksReady admission block", "RunVpn health condition", "StartWorkers packet condition", "CanUseOptimisticDad"],
        "source_guards": result.testsRun, "real_socket_process_thread_Core": False,
    }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
