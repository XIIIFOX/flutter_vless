#!/usr/bin/env python3
"""Generate an inert test of the actual Windows probe allocator (no OS I/O).

The production class/constructor, destructor and Start body are copied verbatim,
apart from access for assertions and the two guarded thread-type/launch seams.
All Winsock names below are recording fakes. Serve is never compiled or called.
"""
import argparse
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "packages/flutter_vless_windows/windows"
THREAD = "worker_ = std::thread(&PacketPathProbe::Serve, this);"
FACTORY = "[ports = *excluded] { return std::make_unique<flutter_vless::PacketPathProbe>(ports); }"
EXCLUSIONS = "ListenerPortExclusions(flutter_vless::xray_config::Parse(base))"


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("production source boundary changed")
    return text.replace(old, new, 1)


def section(text, first, after):
    if text.count(first) != 1 or text.count(after) != 1:
        raise ValueError("production source boundary changed")
    start, end = text.index(first), text.index(after)
    if start >= end:
        raise ValueError("production source boundary changed")
    return text[start:end]


def adapted(header, source, service):
    # Refuse an unwired helper: the real factory must seed the actual probe from
    # the same canonical base whose bytes are finalized and checked next.
    if service.count(FACTORY) != 1 or service.count(EXCLUSIONS) != 1:
        raise ValueError("production probe exclusion factory changed")
    declaration = section(header, "class PacketPathProbe {", "\n}  // namespace flutter_vless")
    declaration = once(declaration, "std::thread worker_;", "InertWorker worker_;")
    declaration = once(declaration, "\n private:", "\n public:  // inert assertions only")
    destructor = section(source, "PacketPathProbe::~PacketPathProbe() {", "bool PacketPathProbe::Start() {")
    start = section(source, "bool PacketPathProbe::Start() {", "void PacketPathProbe::Serve() {")
    start = once(start, THREAD, "worker_ = InertThreadLaunch();")
    result = declaration + destructor + start
    if "std::thread" in result or "::Serve" in result:
        raise ValueError("unexpected real worker boundary")
    return "namespace flutter_vless {\n" + result + "\n}\n"


FAKES = r'''
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
using SOCKET = int;
using BOOL = int;
constexpr int INVALID_SOCKET = -1, TRUE = 1, AF_INET = 2, SOCK_STREAM = 1,
    IPPROTO_TCP = 6, SOL_SOCKET = 1, SO_EXCLUSIVEADDRUSE = 2;
struct WSADATA {};
struct in_addr { unsigned value = 0; };
struct sockaddr {};
struct sockaddr_in { int sin_family = 0; uint16_t sin_port = 0; in_addr sin_addr; };
enum class Fail { none, startup, challenge, socket_, options, address, bind_, bind_after_collision, name, zero, listen_, worker };
struct Kernel {
  std::vector<uint16_t> ports;
  std::set<SOCKET> handles;
  std::vector<SOCKET> closed;
  unsigned reads = 0, issued = 0, listens = 0, starts = 0, joins = 0;
  int wsa = 0;
  Fail fail = Fail::none;
} kernel;
void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void Reset(std::vector<uint16_t> ports, Fail fail = Fail::none) {
  Require(kernel.handles.empty() && kernel.wsa == 0, "previous fake handle leaked");
  kernel = {}; kernel.ports = std::move(ports); kernel.fail = fail;
}
void Drained() {
  Require(kernel.handles.empty() && kernel.wsa == 0, "fake descriptor/WSA ownership leaked");
  Require(kernel.joins == kernel.starts, "fake worker was not joined");
}
int MAKEWORD(int, int) { return 0; }
int WSAStartup(int, WSADATA*) { if (kernel.fail == Fail::startup) return 1; ++kernel.wsa; return 0; }
int WSACleanup() { Require(kernel.wsa == 1, "unpaired WSA cleanup"); --kernel.wsa; return 0; }
SOCKET socket(int family, int type, int protocol) {
  Require(family == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP, "unexpected socket kind");
  if (kernel.fail == Fail::socket_) return INVALID_SOCKET;
  const auto fd = static_cast<SOCKET>(++kernel.issued); kernel.handles.insert(fd); return fd;
}
int closesocket(SOCKET fd) {
  Require(kernel.handles.erase(fd) == 1, "double/foreign fake close"); kernel.closed.push_back(fd); return 0;
}
int setsockopt(SOCKET fd, int level, int option, const char*, std::size_t) {
  Require(kernel.handles.count(fd) && level == SOL_SOCKET && option == SO_EXCLUSIVEADDRUSE, "unexpected socket option");
  return kernel.fail == Fail::options ? -1 : 0;
}
int InetPtonA(int family, const char* text, in_addr*) {
  Require(family == AF_INET && std::string(text) == "127.0.0.1", "probe bind is not numeric loopback");
  return kernel.fail == Fail::address ? 0 : 1;
}
int bind(SOCKET fd, sockaddr* value, std::size_t) {
  const auto* local = reinterpret_cast<sockaddr_in*>(value);
  Require(kernel.handles.count(fd) && local->sin_family == AF_INET && local->sin_port == 0, "not an owned port0 bind");
  return kernel.fail == Fail::bind_ || (kernel.fail == Fail::bind_after_collision && kernel.issued == 2) ? -1 : 0;
}
int getsockname(SOCKET fd, sockaddr* value, int*) {
  Require(kernel.handles.count(fd), "name on unowned fake socket");
  if (kernel.fail == Fail::name) return -1;
  Require(kernel.reads < kernel.ports.size(), "unbounded port0 attempts");
  reinterpret_cast<sockaddr_in*>(value)->sin_port = kernel.fail == Fail::zero ? 0 : kernel.ports[kernel.reads];
  ++kernel.reads; return 0;
}
int listen(SOCKET fd, int backlog) {
  Require(kernel.handles.count(fd) && backlog == 4, "listen on unowned socket"); ++kernel.listens;
  return kernel.fail == Fail::listen_ ? -1 : 0;
}
#undef ntohs
uint16_t ntohs(uint16_t value) { return value; }
struct InertWorker {
  bool active = false;
  bool joinable() const { return active; }
  void join() { Require(active, "fake join without worker"); active = false; ++kernel.joins; }
};
InertWorker InertThreadLaunch() {
  Require(kernel.handles.size() == 1 && kernel.listens == 1, "worker before owned accepted listener");
  if (kernel.fail == Fail::worker) throw std::runtime_error("inert worker construction failure");
  ++kernel.starts; return {true};
}
namespace flutter_vless {
namespace xray_config { struct Json {}; }
namespace native {
std::string RandomHex(unsigned length) {
  Require(length == 32, "challenge length changed");
  return kernel.fail == Fail::challenge ? "" : "inert-challenge";
}
}
}
'''

CONTROLS = r'''
int main() try {
  using flutter_vless::PacketPathProbe;
  unsigned passed = 0;
  Reset({50001});
  {
    PacketPathProbe probe;
    Require(probe.Start() && probe.port_ == 50001 && kernel.handles.size() == 1 && kernel.wsa == 1,
        "free listener not retained");
    const auto fd = probe.listener_;
    Require(!probe.Start() && probe.listener_ == fd && kernel.starts == 1 && kernel.reads == 1,
        "second Start changed active ownership");
  }
  Drained(); ++passed;

  Reset({10807, 10086, 18080, 50001});
  {
    PacketPathProbe probe({10807, 10086, 18080});
    Require(probe.Start() && probe.port_ == 50001 && kernel.reads == 4 && kernel.listens == 1
        && kernel.starts == 1 && kernel.closed == std::vector<SOCKET>{1,2,3} && probe.listener_ == 4,
        "declared collisions were admitted or not closed before worker");
  }
  Drained(); ++passed;

  Reset(std::vector<uint16_t>(33, 10807));
  {
    PacketPathProbe probe({10807});
    Require(!probe.Start() && kernel.reads == 32 && kernel.closed.size() == 32
        && !kernel.starts && !kernel.listens && !probe.running_.load() && !probe.port_,
        "collision exhaustion not closed at32");
    Drained();
  }
  Drained(); ++passed;

  auto last = std::vector<uint16_t>(31, 10807); last.push_back(50001);
  Reset(last);
  {
    PacketPathProbe probe({10807});
    Require(probe.Start() && probe.port_ == 50001 && kernel.reads == 32 && kernel.closed.size() == 31,
        "last permitted attempt was not usable");
  }
  Drained(); ++passed;

  for (const auto failure : {Fail::startup, Fail::challenge, Fail::socket_, Fail::options,
      Fail::address, Fail::bind_, Fail::name, Fail::zero, Fail::listen_}) {
    Reset({50001}, failure);
    {
      PacketPathProbe probe({10807});
      Require(!probe.Start() && !probe.running_.load() && !probe.port_ && !kernel.starts,
          "failed allocator admitted a worker");
      Drained();
    }
    Drained();
  }
  ++passed;

  Reset({50001, 50002}, Fail::worker);
  {
    PacketPathProbe probe;
    Require(!probe.Start() && !probe.running_.load() && !probe.port_ && !kernel.starts,
        "worker constructor failure retained ownership");
    Drained(); kernel.fail = Fail::none; kernel.listens = 0;
    Require(probe.Start() && probe.port_ == 50002, "failed Start could not retry cleanly");
  }
  Drained(); ++passed;

  Reset({10807,50001});
  {
    std::set<unsigned> caller{10807}; PacketPathProbe probe(caller); caller.clear();
    Require(probe.Start() && probe.port_ == 50001 && kernel.reads == 2,
        "constructor did not freeze exclusions");
  }
  Drained(); ++passed;

  Reset({10807, 50001}, Fail::bind_after_collision);
  {
    PacketPathProbe probe({10807});
    Require(!probe.Start() && kernel.reads == 1 && kernel.closed == std::vector<SOCKET>{1,2}
        && !kernel.listens && !kernel.starts,
        "post-collision bind failure was not terminal before listen/worker");
  }
  Drained(); ++passed;
  Require(passed == 8, "control count changed");
  std::cout << "WINDOWS_PACKET_PROBE_EXCLUSION_PURE_PASS=" << passed << '\n';
  return 0;
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
'''


def sources():
    return tuple((WINDOWS / name).read_text() for name in
                 ("packet_path_probe.h", "packet_path_probe.cpp", "vpn_service.cpp"))


class SourceGuards(unittest.TestCase):
    def test_actual_production_boundaries(self):
        output = adapted(*sources())
        self.assertIn("excluded_ports_(std::move(excluded_ports))", output)
        self.assertIn("InertThreadLaunch()", output)
        self.assertNotIn("std::thread", output)
        self.assertNotIn("::Serve", output)

    def test_missing_or_duplicate_worker_launch_refuses(self):
        header, source, service = sources()
        for replacement in ("", THREAD + THREAD):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    adapted(header, source.replace(THREAD, replacement), service)

    def test_worker_type_or_extra_start_boundary_refuses(self):
        header, source, service = sources()
        with self.assertRaises(ValueError):
            adapted(header.replace("std::thread worker_;", ""), source, service)
        with self.assertRaises(ValueError):
            adapted(header, source + "bool PacketPathProbe::Start() {", service)

    def test_real_factory_must_supply_canonical_exclusions(self):
        header, source, service = sources()
        for token in (FACTORY, EXCLUSIONS):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    adapted(header, source, service.replace(token, ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", type=Path, help="write inert portable C++ controls")
    options = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SourceGuards))
    if not result.wasSuccessful():
        return 1
    if options.generate:
        data = sources()
        output = FAKES + adapted(*data) + CONTROLS
        options.generate.parent.mkdir(parents=True, exist_ok=True)
        options.generate.write_text(output)
        options.generate.with_suffix(".sources.json").write_text(json.dumps({
            "production_sha256": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in zip(
                ("packet_path_probe.h", "packet_path_probe.cpp", "vpn_service.cpp"), data)},
            "inert_boundaries": ["all Winsock functions are recording fakes", "thread type and launch", "assertion access"],
            "source_guard_tests": result.testsRun, "real_socket_thread_serve_executed": False,
            "scope": "actual constructor, Start allocation and destructor ownership only"
        }, indent=2) + "\n")
    print("WINDOWS_PACKET_PROBE_SOURCE_GUARD_PASS=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
