#!/usr/bin/env python3
"""Generate inert tests of actual Windows fresh/recovery caller decisions.

No compiler or service is invoked here. The generated C++ uses actual
VpnWorkerCandidate::Prepare/Rebind; probe, underlay, Core check and lifecycle
boundaries are in-memory fakes. --source-root can select an ignored RED/fixed
source tree; unchanged dependencies fall back to the repository.
"""
import argparse
import hashlib
import json
from pathlib import Path
import unittest


def repository_root():
    for path in Path(__file__).resolve().parents:
        if (path / ".git").exists():
            return path
    raise ValueError("repository root not found")


ROOT = repository_root()
RELATIVE = Path("packages/flutter_vless_windows/windows")


def extract(sources):
    def part(text, begin, end, label):
        if text.count(begin) != 1 or text.count(end) != 1:
            raise ValueError("actual Windows " + label + " boundary changed")
        first, last = text.index(begin), text.index(end)
        if first >= last:
            raise ValueError("actual Windows " + label + " order changed")
        return text[first:last]

    cpp = sources["vpn_service.cpp"]
    start = part(cpp, "bool VpnService::Start(", "\nvoid VpnService::StopSession(", "Start")
    fresh = part(start, "  const auto managed_port =", "  bootstrap_cache_ = std::move(cache);", "fresh admission")
    anchors = ("auto candidate =", "if (!candidate)", "if (admitted) admitted();", "if (requested_.load()) StopSession(false);")
    if any(fresh.count(anchor) != 1 for anchor in anchors) or [fresh.index(a) for a in anchors] != sorted(fresh.index(a) for a in anchors):
        raise ValueError("actual Windows fresh check/admission/Stop order changed")
    helper = part(cpp, "std::unique_ptr<VpnService::WorkerCandidate> VpnService::PrepareWorkerCandidate(",
                  "\nbool VpnService::StartWorkers(", "candidate")
    if helper.count("WorkerCandidate::Prepare(") != 1 or helper.count("return candidate;") != 1:
        raise ValueError("actual Windows final candidate no longer owns check")
    workers = part(cpp, "bool VpnService::StartWorkers(", "\nvoid VpnService::StopWorkers(", "StartWorkers")
    recovery = part(workers, "  worker_candidate_ = pending_candidate_ ?", "  const auto command = worker_candidate_->Routing()", "recovery")
    if recovery.count("PrepareWorkerCandidate(") != 1 or recovery.count("current_identity != worker_candidate_->Identity()") != 1:
        raise ValueError("actual Windows recovery identity/check boundary changed")
    header = sources["vpn_service.h"]
    begin = "  std::unique_ptr<WorkerCandidate> PrepareWorkerCandidate("
    if header.count(begin) != 1:
        raise ValueError("actual Windows candidate declaration changed")
    first = header.index(begin)
    last = header.index(");", first) + 2
    declaration = header[first:last]
    if "StopWorkers" in declaration:
        raise ValueError("actual Windows candidate declaration is incomplete")
    return fresh, recovery, helper, declaration


HEADER = r'''
#ifdef _WIN32
#include <winsock2.h>
#endif
#include "ipv6_tcp_scope.h"
#include "vpn_worker_candidate.h"
#include "native_routing_spec.h"
#include <atomic>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#ifndef _WIN32
using UINT64 = uint64_t;
using ADDRESS_FAMILY = unsigned short;
constexpr ADDRESS_FAMILY AF_INET = 2, AF_INET6 = 23;
#endif
namespace fs = std::filesystem;
using Root = flutter_vless::asset_location::Root;
using Intent = flutter_vless::native_routing::NativeRoutingIntent;
using Provenance = flutter_vless::xray_config::VpnRoutingProvenance;
using Json = flutter_vless::xray_config::Json;
struct FakeBoundary {
  bool accept = true;
  unsigned checks = 0, removed = 0;
  std::string checked;
  std::function<void()> during_check;
} boundary;
namespace flutter_vless {
struct PacketPathProbe {
  explicit PacketPathProbe(const std::set<unsigned>&) {}
  bool Start() { return true; }
  bool Configure(xray_config::Json&, uint16_t port, std::vector<int64_t>* guards) {
    *guards = {0}; return port == 10808;
  }
};
}
namespace flutter_vless::native {
struct ProtectedRuntime {};
bool RoutingCapability(ProtectedRuntime&, const Root&) { return true; }
bool CheckPreparedConfig(const std::string& bytes, ProtectedRuntime&, fs::path& path,
    const Root&, preparation::Stage*) {
  ++boundary.checks; boundary.checked = bytes; path = "inert-checked-file";
  if (boundary.during_check) boundary.during_check();
  return boundary.accept;
}
bool CheckRoutingPreparedConfig(const std::string&, const std::string&, ProtectedRuntime&,
    fs::path&, fs::path&, const Root&, preparation::Stage*) { return false; }
void RemovePrivateConfig(fs::path& path) { ++boundary.removed; path.clear(); }
}
namespace flutter_vless::native_routing {
NativeRoutingResult NativeRoutingSpec::Freeze(std::string_view, int64_t, const std::string&,
    const std::string&, const std::optional<NativeRoutingIntent>&, std::optional<int64_t>,
    const std::vector<int64_t>&) { return {std::nullopt, NativeRoutingError::invalid_intent}; }
}
class VpnService { public:
  using WorkerCandidate = flutter_vless::native::VpnWorkerCandidate<flutter_vless::PacketPathProbe>;
  std::optional<flutter_vless::Ipv6TcpScope> ipv6_tcp_scope_;
  std::optional<std::string> v4 = "physical-four", v6 = "physical-six";
  UINT64 v4_luid = 4, v6_luid = 6;
  std::vector<ADDRESS_FAMILY> queried;
  std::atomic<bool> requested_{true};
  unsigned stopped = 0, admissions = 0;
  std::unique_ptr<WorkerCandidate> accepted_, worker_candidate_, pending_candidate_;
  std::unique_ptr<flutter_vless::native::ProtectedRuntime> private_runtime_ =
      std::make_unique<flutter_vless::native::ProtectedRuntime>();
  std::string current_config_, username_ = "inert-auth", underlay_name_;
  UINT64 underlay_luid_ = 0;
  ADDRESS_FAMILY underlay_family_ = AF_INET6;
  uint16_t socks_port_ = 10808;
  Root asset_directory_;
  std::optional<Intent> routing_intent_;
  Provenance routing_provenance_;
  static void Event(const char*) {}
  std::optional<std::string> Underlay(UINT64* identity = nullptr, ADDRESS_FAMILY family = AF_INET) {
    queried.push_back(family);
    const auto& result = family == AF_INET6 ? v6 : v4;
    if (identity) *identity = result ? (family == AF_INET6 ? v6_luid : v4_luid) : 0;
    return result;
  }
  void StopSession(bool) { ++stopped; requested_.store(false); ipv6_tcp_scope_.reset(); }
  bool Fresh(const std::string& base, const Provenance& provenance);
  bool Recover();
'''

FRESH_PREFIX = r'''
bool VpnService::Fresh(const std::string& base, const Provenance& provenance) {
  using namespace flutter_vless;
  const std::optional<std::string> prepared = base;
  auto runtime = std::make_unique<native::ProtectedRuntime>();
  Root assets; std::optional<Intent> routing;
  const std::string user = "inert-auth";
  preparation::Report changes;
  preparation::StartupOutcome failed;
  auto* outcome = &failed;
  const std::function<void()> admitted = [this] { ++admissions; };
'''
FRESH_SUFFIX = r'''
  accepted_ = std::move(candidate);
  return true;
}
'''
RECOVERY_PREFIX = r'''
bool VpnService::Recover() {
  const auto fail = [](const char*) { return false; };
'''
RECOVERY_SUFFIX = r'''
  return true;
}
'''

TESTS = r'''
void Require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
std::string Base(bool ipv6 = true) {
  auto config = flutter_vless::xray_config::Parse(R"({"inbounds":[{"tag":"managed","protocol":"socks","listen":"127.0.0.1","port":10808}],"outbounds":[{"tag":"outer","protocol":"socks","settings":{"servers":[{"address":"fd00:85:2::2","port":18443}]},"streamSettings":{"network":"tcp","sockopt":{"interface":"initial-four"},"xhttpSettings":{"downloadSettings":{"sockopt":{"interface":"initial-four"}}}}}],"routing":{"rules":[]}})");
  if (!ipv6) config["outbounds"][0]["settings"]["servers"][0]["address"] = "192.0.2.44";
  return config.dump();
}
Provenance V6() {
  Provenance value;
  value.ipv6_tcp_endpoints.push_back({{0xfd,0,0,0x85,0,2,0,0,0,0,0,0,0,0,0,2}, 18443});
  return value;
}
void OldOwnerPreserved(const VpnService& service) {
  Require(service.stopped == 0 && service.admissions == 0 && service.requested_.load()
      && service.ipv6_tcp_scope_ && service.ipv6_tcp_scope_->interface_luid == 88,
      "failed actual fresh preflight altered previous owner");
}
void FreshDifferentV6() {
  VpnService service; service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{88, V6().ipv6_tcp_endpoints};
  Require(service.Fresh(Base(), V6()), "actual fresh IPv6 replacement inherited old recovery LUID");
  Require(service.stopped == 1 && service.admissions == 1 && service.accepted_
      && service.accepted_->Identity() == 6, "fresh actual candidate was not admitted before one old Stop");
}
void FreshV6ToV4() {
  VpnService service; service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{88, V6().ipv6_tcp_endpoints};
  Require(service.Fresh(Base(false), {}), "actual IPv6-to-IPv4 replacement inherited old recovery LUID");
  Require(service.accepted_->Identity() == 4 && service.stopped == 1 && service.admissions == 1,
      "actual fresh IPv4 replacement checked wrong family");
}
void MissingFamily() {
  VpnService service; service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{88, V6().ipv6_tcp_endpoints};
  service.v6.reset(); Require(!service.Fresh(Base(), V6()), "absent required IPv6 adapter admitted via IPv4");
  OldOwnerPreserved(service); Require(boundary.checks == 0, "absent family reached Core boundary");
}
void NativeRejected() {
  VpnService service; service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{88, V6().ipv6_tcp_endpoints};
  boundary.accept = false;
  Require(!service.Fresh(Base(), V6()), "actual rejected native check admitted replacement");
  OldOwnerPreserved(service); Require(boundary.checks == 1 && boundary.removed == 1,
      "actual candidate check or rejected-file ownership bypassed");
}
void RecoveryStale() {
  VpnService service; service.current_config_ = Base(); service.routing_provenance_ = V6();
  service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{88, V6().ipv6_tcp_endpoints};
  Require(!service.Recover() && boundary.checks == 0 && !service.worker_candidate_,
      "actual recovery failed to retain prior IPv6 LUID before native check");
  OldOwnerPreserved(service);
}
void RecoverySame() {
  VpnService service; service.current_config_ = Base(); service.routing_provenance_ = V6();
  service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{6, V6().ipv6_tcp_endpoints};
  Require(service.Recover() && boundary.checks == 1 && service.worker_candidate_
      && service.underlay_luid_ == 6 && service.underlay_name_ == "physical-six",
      "actual same-scope recovery refused or published wrong candidate");
  Require(service.stopped == 0 && service.admissions == 0, "recovery invoked fresh-owner lifecycle");
}
void DualDefaultFinalBytes() {
  VpnService service;
  Require(service.Fresh(Base(), V6()) && boundary.checks == 1, "dual default refused IPv6 final candidate");
  const auto checked = flutter_vless::xray_config::Parse(boundary.checked);
  const auto& stream = checked["outbounds"][0]["streamSettings"];
  Require(stream["sockopt"]["interface"] == "physical-six"
      && stream["xhttpSettings"]["downloadSettings"]["sockopt"]["interface"] == "physical-six"
      && boundary.checked == service.accepted_->Bytes()
      && service.accepted_->Underlay() == "physical-six" && service.accepted_->Identity() == 6,
      "real final Rebind/native-check bytes retained initial IPv4 alias");
  Require(!service.queried.empty() && std::all_of(service.queried.begin(), service.queried.end(),
      [](ADDRESS_FAMILY family) { return family == AF_INET6; }), "final candidate queried wrong underlay family");
}
void SlowIdentityChange() {
  VpnService service; service.ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{88, V6().ipv6_tcp_endpoints};
  boundary.during_check = [&service] { service.v6_luid = 77; };
  Require(!service.Fresh(Base(), V6()), "slow native check admitted changed adapter identity");
  OldOwnerPreserved(service); Require(boundary.checks == 1 && boundary.removed == 1,
      "actual slow-check candidate not checked and privately retired");
}
int main() {
  const std::vector<std::pair<const char*, void(*)()>> tests = {
    {"fresh-different-v6", FreshDifferentV6}, {"fresh-v6-to-v4", FreshV6ToV4},
    {"missing-family-preserves-old", MissingFamily}, {"native-reject-preserves-old", NativeRejected},
    {"recovery-stale-refuses", RecoveryStale}, {"recovery-same-accepts", RecoverySame},
    {"dual-default-final-v6-bytes", DualDefaultFinalBytes}, {"slow-check-change-preserves-old", SlowIdentityChange}};
  unsigned failures = 0;
  for (const auto& test : tests) {
    boundary = {};
    try { test.second(); std::cout << "CALLER_CASE_PASS=" << test.first << '\n'; }
    catch (const std::exception& error) { ++failures; std::cerr << "CALLER_CASE_FAIL=" << test.first << ": " << error.what() << '\n'; }
  }
  if (failures) return 1;
  std::cout << "WINDOWS_NUMERIC_IPV6_CALLERS_PASS=8\n";
}
'''


def generated(sources):
    fresh, recovery, helper, declaration = extract(sources)
    return HEADER + declaration + "\n};\n" + helper + FRESH_PREFIX + fresh + FRESH_SUFFIX + RECOVERY_PREFIX + recovery + RECOVERY_SUFFIX + TESTS


def load_sources(source_root):
    return {name: (source_root / RELATIVE / name).read_text() for name in ("vpn_service.cpp", "vpn_service.h")}


DEPENDENCIES = ("vpn_service.cpp", "vpn_service.h", "vpn_worker_candidate.h", "xray_config.h",
                "ipv6_tcp_scope.h", "preparation_report.h", "asset_location.h", "native_routing_spec.h",
                "third_party/nlohmann/json.hpp")


def generate_snapshot(source_root, output):
    """Read every input once, then emit one complete immutable header closure.

    A compiler must use ONLY the returned include_root. In particular, adding
    -I repository as a fallback could let a quoted sibling include silently
    select an old xray_config.h beside the repository candidate header.
    """
    captured = {}
    for name in DEPENDENCIES:
        selected = source_root / RELATIVE / name
        if not selected.is_file():
            selected = ROOT / RELATIVE / name
        if not selected.is_file() or selected.is_symlink():
            raise ValueError("actual Windows dependency is not a regular owned source: " + name)
        captured[name] = (selected.resolve(), selected.read_bytes())
    sources = {name: captured[name][1].decode("utf-8") for name in ("vpn_service.cpp", "vpn_service.h")}
    cpp = generated(sources)
    include_root = output.parent / (output.stem + "-headers")
    receipt = output.with_suffix(".sources.json")
    if any(path.exists() for path in (output, include_root, receipt)):
        raise ValueError("refusing to overwrite a caller snapshot")
    output.parent.mkdir(parents=True, exist_ok=True)
    include_root.mkdir(mode=0o700)
    hashes = {}
    for name, (selected, data) in captured.items():
        destination = include_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(0o600)
        digest = hashlib.sha256(data).hexdigest()
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise ValueError("caller snapshot copy differs")
        hashes[name] = {"source": str(selected), "sha256": digest}
    with output.open("x") as stream:
        stream.write(cpp)
    output.chmod(0o600)
    manifest = {"include_root": str(include_root.resolve()), "include_policy": "ONLY this complete closure; no fallback include directories",
                "dependencies": hashes, "generated_cpp_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with receipt.open("x") as stream:
        stream.write(json.dumps(manifest, indent=2) + "\n")
    receipt.chmod(0o600)
    return manifest


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.sources = load_sources(SOURCE_ROOT)

    def test_actual_sources_generate(self):
        self.assertIn("WINDOWS_NUMERIC_IPV6_CALLERS_PASS=8", generated(self.sources))

    def test_missing_fresh_boundary_refused(self):
        self.sources["vpn_service.cpp"] = self.sources["vpn_service.cpp"].replace("  const auto managed_port =", "  const auto renamed_port =")
        with self.assertRaises(ValueError):
            generated(self.sources)

    def test_reordered_stop_before_check_refused(self):
        text = self.sources["vpn_service.cpp"]
        text = text.replace("  if (requested_.load()) StopSession(false);\n", "")
        self.sources["vpn_service.cpp"] = text.replace("  const auto managed_port =", "  if (requested_.load()) StopSession(false);\n  const auto managed_port =")
        with self.assertRaises(ValueError):
            generated(self.sources)

    def test_missing_recovery_identity_refused(self):
        self.sources["vpn_service.cpp"] = self.sources["vpn_service.cpp"].replace("current_identity != worker_candidate_->Identity()", "false")
        with self.assertRaises(ValueError):
            generated(self.sources)

    def test_renamed_declaration_refused(self):
        self.sources["vpn_service.h"] = self.sources["vpn_service.h"].replace("PrepareWorkerCandidate(", "RenamedCandidate(")
        with self.assertRaises(ValueError):
            generated(self.sources)


SOURCE_ROOT = ROOT
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--generate", type=Path)
    args = parser.parse_args()
    SOURCE_ROOT = args.source_root.resolve()
    if args.generate:
        generate_snapshot(SOURCE_ROOT, args.generate.resolve())
    else:
        unittest.main(argv=[__file__])
