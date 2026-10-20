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
    admission = section(service, "  bool listening = false;", "  // Credentials live only in a private file")
    if admission.count("native::SocksReady(") != 1:
        raise ValueError("listener admission boundary changed")
    admission = admission.replace("std::this_thread::sleep_for", "InertSleep")
    periodic = section(service, "      if (!xray_process_->IsRunning()", "      if (++ticks % 2 == 0)")
    if periodic.count("break;") != 1:
        raise ValueError("periodic health consumer changed")
    periodic = periodic.replace("break;", "return false;")
    startup = section(service, "    if (worker_candidate_->PacketProbe().Check(", "    std::this_thread::sleep_for(std::chrono::milliseconds(100));\n  }\n  return fail(\"Private packet-path challenge")
    cancel = "const std::function<bool()>&" in declaration
    adapter = "return probe.Check(PacketPathProbe::address, [] { return kernel.cancel; });" if cancel else "return probe.Check();"
    return probe + r'''
namespace flutter_vless {
bool CheckWithCancel(PacketPathProbe& probe) { ADAPTER }
namespace native { bool SocksReady(uint16_t, const std::string&, const std::string&) {
  ++kernel.socks_ready; kernel.cancel = true; if (kernel.join) kernel.join(); return true;
} }
class AdmissionConsumer {
 public:
  std::atomic<bool> requested_{true};
  struct Process { bool IsRunning() const { return true; } void* hProcess = nullptr; } process;
  Process* xray_process_ = &process;
  unsigned socks_port_ = 10808; std::string username_, password_;
  bool ContinueAfterListener() {
    auto fail = [](const char*) { return false; }; (void)fail;
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
#include <functional>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
using SOCKET = int; using DWORD = unsigned long; using u_long = unsigned long; using HANDLE = void*;
enum { INVALID_SOCKET = -1, SOCKET_ERROR = -1, AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6,
    SOL_SOCKET = 1, SO_RCVTIMEO = 2, SO_SNDTIMEO = 3, SO_ERROR = 4, FIONBIO = 5,
    WSAEWOULDBLOCK = 10035, WSAEINTR = 10004, WSAEINPROGRESS = 10036 };
struct InertTimeval { long tv_sec, tv_usec; };
struct InertFdSet { SOCKET fd = INVALID_SOCKET; };
#undef FD_ZERO
#undef FD_SET
#define FD_ZERO(p) ((p)->fd = INVALID_SOCKET)
#define FD_SET(fd_, p) ((p)->fd = (fd_))
struct in_addr {};
struct sockaddr {};
struct sockaddr_in { int sin_family = 0; uint16_t sin_port = 0; in_addr sin_addr; };
struct Kernel {
  int64_t now = 0, next_ready = 0, step = 0;
  bool cancel = false, eof = false, wrong = false, would_block = false, connect_pending = false;
  unsigned io = 0, selects = 0, accepted = 0, closes = 0, joins = 0, socks_ready = 0, tun_side_effects = 0;
  unsigned cancel_after = 0;
  unsigned eof_after = 0;
  int error = 0; std::set<SOCKET> handles, nonblocking;
  std::string incoming, sent; std::size_t offset = 0;
  std::function<void()> after_io, on_close, join;
} kernel;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
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
SOCKET socket(int, int, int) { Require(kernel.handles.insert(9).second, "socket reused live handle"); return 9; }
int closesocket(SOCKET fd) { Require(kernel.handles.erase(fd) == 1, "double/foreign close"); ++kernel.closes; if (fd == 9 && kernel.on_close) kernel.on_close(); return 0; }
int setsockopt(SOCKET, int, int, const char*, std::size_t) { return 0; }
int InetPtonA(int, const char*, in_addr*) { return 1; }
#undef htons
uint16_t htons(uint16_t value) { return value; }
int ioctlsocket(SOCKET fd, long, u_long* mode) { if (*mode) kernel.nonblocking.insert(fd); else kernel.nonblocking.erase(fd); return 0; }
int WSAGetLastError() { return kernel.error; }
int connect(SOCKET, const sockaddr*, int) { if (!kernel.connect_pending) return 0; kernel.error = WSAEWOULDBLOCK; return SOCKET_ERROR; }
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
    try { Reset(); body(); Require(kernel.handles.empty(), "fake handles leaked"); ++passed; std::cout << "PASS " << name << '\n'; }
    catch (const std::exception& e) { ++failed; std::cout << "FAIL " << name << ": " << e.what() << '\n'; kernel.handles.clear(); }
  };
  const std::string nonce(64, 'n');
  auto configure = [&](PacketPathProbe& probe) { probe.running_.store(true); probe.port_ = 50001; probe.challenge_ = nonce; kernel.incoming = nonce + "-ok"; };
  test("fragmented-correct", [&] { PacketPathProbe probe; configure(probe); Require(probe.Check(), "correct response rejected"); Require(kernel.sent == nonce && kernel.offset == nonce.size()+3 && kernel.closes == 1, "framing changed"); });
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
  std::cout << "WINDOWS_PACKET_PROBE_BUDGET_PURE_PASS=" << passed << " FAIL=" << failed << '\n';
  if (passed + failed != 20) return 2;
  return failed ? 1 : 0;
}
'''


class Boundaries(unittest.TestCase):
    def test_actual_framing_and_consumers_are_selected(self):
        result = actual(sources())
        for token in ("PacketPathProbe::Check(", "PacketPathProbe::Serve()", "bytes == expected", "native::SocksReady("):
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
        "inert_boundaries": ["all Winsock APIs", "monotonic clock", "worker thread", "listener readiness callback", "admission continuation effect counter"],
        "actual_bodies": ["Send", "Receive", "Check", "Serve", "destructor", "post-SocksReady admission block", "RunVpn health condition", "StartWorkers packet condition"],
        "source_guards": result.testsRun, "real_socket_process_thread_Core": False,
    }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
