#include "vpn_worker_candidate.h"
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct State {
  std::vector<std::string> events;
  unsigned live_probes = 0, next_port = 24000;
  bool start = true, configure = true, check = true, throw_check = false;
  std::string checked, written, launched;
};
struct Probe {
  explicit Probe(State& state) : state_(state) { ++state_.live_probes; }
  ~Probe() { --state_.live_probes; state_.events.push_back("probe-close"); }
  bool Start() { state_.events.push_back("probe-start"); port_ = ++state_.next_port; return state_.start; }
  bool Configure(flutter_vless::xray_config::Json& config, uint16_t managed_port,
      std::vector<int64_t>* generated = nullptr) const {
    state_.events.push_back("probe-configure");
    if (!state_.configure || managed_port != 19000) return false;
    config["outbounds"].push_back({{"tag", "private-probe"}, {"protocol", "freedom"},
        {"settings", {{"redirect", "127.0.0.1:" + std::to_string(port_)}}}});
    config["routing"]["rules"].insert(config["routing"]["rules"].begin(),
        flutter_vless::xray_config::Json{{"type", "field"}, {"inboundTag", {"private-socks"}}, {"outboundTag", "private-probe"}});
    if (generated) *generated = {0};
    return true;
  }
  State& state_;
  unsigned port_ = 0;
};
using Candidate = flutter_vless::native::VpnWorkerCandidate<Probe>;
const std::string base = R"({"inbounds":[{"tag":"private-socks","protocol":"socks","port":19000}],"outbounds":[{"tag":"caller","protocol":"freedom","streamSettings":{"sockopt":{"interface":"old","tcpKeepAliveIdle":30},"xhttpSettings":{"extra":{"downloadSettings":{"sockopt":{"interface":"old-child","tcpKeepAliveIdle":7}}}}}}],"routing":{"rules":[{"type":"field","domain":["full:blocked.invalid"],"outboundTag":"caller"}]},"dns":{"hosts":{"static.invalid":"127.0.0.1"}}})";
std::unique_ptr<Candidate> Prepare(State& state, const std::string& interface_name, uint64_t identity) {
  return Candidate::Prepare(base, interface_name, identity, 19000,
      [&] { return std::make_unique<Probe>(state); },
      [&](const std::string& bytes, std::filesystem::path& path) {
        state.events.push_back("check"); state.checked = bytes; state.written = bytes;
        path = std::filesystem::path("synthetic-checked-") += std::to_string(state.next_port);
        if (state.throw_check) throw std::runtime_error("fixed check failure");
        return state.check;
      },
      [&](std::filesystem::path& path) { state.events.push_back("file-remove"); path.clear(); });
}
void AssertFinal(const Candidate& candidate, const State& state, const std::string& interface_name, uint64_t identity) {
  using flutter_vless::xray_config::Parse;
  const auto config = Parse(candidate.Bytes());
  Require(candidate.Bytes() == state.checked && state.checked == state.written, "checked bytes differ from frozen private document");
  Require(candidate.Underlay() == interface_name && candidate.Identity() == identity, "underlay identity changed after check");
  Require(config["outbounds"][0]["streamSettings"]["sockopt"]["interface"] == interface_name, "upload rebound after check");
  Require(config["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["sockopt"]["interface"] == interface_name,
      "download underlay omitted from final check");
  Require(config["outbounds"][0]["streamSettings"]["sockopt"]["tcpKeepAliveIdle"] == 30, "caller socket setting changed");
  Require(config["outbounds"][1]["tag"] == "private-probe" && config["routing"]["rules"][0]["outboundTag"] == "private-probe",
      "probe changes absent from preflight");
  Require(config["routing"]["rules"][1] == Parse(base)["routing"]["rules"][0] && config["dns"] == Parse(base)["dns"], "caller rules or DNS changed");
}
}

int main() try {
  State state;
  const auto source_snapshot = base;
  auto active = Prepare(state, "adapter-A", 41);
  Require(static_cast<bool>(active), "initial candidate rejected");
  AssertFinal(*active, state, "adapter-A", 41);
  const auto old_file = active->Path(); const auto old_bytes = active->Bytes();
  Require(state.events == std::vector<std::string>({"probe-start", "probe-configure", "check"}), "check preceded final configuration");
  state.events.clear(); state.check = false;
  auto rejected = Prepare(state, "adapter-B", 42);
  Require(!rejected && active->Path() == old_file && active->Bytes() == old_bytes && state.live_probes == 1,
      "rejected replacement retired working candidate");
  Require(state.events == std::vector<std::string>({"probe-start", "probe-configure", "check", "file-remove", "probe-close"}),
      "rejected candidate leaked or cleanup touched old worker");
  state.events.clear(); state.check = true;
  auto pending = Prepare(state, "adapter-B", 42);
  Require(pending && pending->Path() != old_file && state.live_probes == 2, "candidate did not retain its own probe/file before commit");
  AssertFinal(*pending, state, "adapter-B", 42);
  state.events.push_back("old-stop"); active.reset(); active = std::move(pending);
  state.launched = active->Bytes(); state.events.push_back("launch-checked-file");
  Require(state.launched == state.checked && state.launched == state.written, "launch reserialized checked bytes");
  Require(state.events == std::vector<std::string>({"probe-start", "probe-configure", "check", "old-stop", "file-remove", "probe-close", "launch-checked-file"}),
      "replacement stopped old worker before final preflight");
  const auto first_attempt_bytes = active->Bytes(); active.reset();
  state.events.clear(); auto recovery = Prepare(state, "adapter-C", 43);
  Require(recovery && recovery->Bytes() != first_attempt_bytes, "recovery reused stale probe/underlay");
  AssertFinal(*recovery, state, "adapter-C", 43);
  recovery.reset(); Require(state.live_probes == 0, "recovery retained probe");
  for (const auto* failure : {"start", "configure", "check", "throw"}) {
    state.events.clear(); state.start = std::string(failure) != "start";
    state.configure = std::string(failure) != "configure";
    state.check = std::string(failure) != "check"; state.throw_check = std::string(failure) == "throw";
    std::unique_ptr<Candidate> failed;
    bool threw = false;
    try { failed = Prepare(state, "adapter-D", 44); }
    catch (const std::runtime_error&) { threw = true; }
    Require(!failed && threw == state.throw_check, "failed stage returned usable candidate or masked its error");
    Require(state.live_probes == 0, "failure leaked candidate probe");
    Require(state.events.back() == "probe-close", "probe cleanup missing");
    if (std::string(failure) == "start") Require(state.events.size() == 2, "failed start reached config/check");
    if (std::string(failure) == "configure") Require(state.events.size() == 3, "failed configure reached check");
  }
  Require(base == source_snapshot, "source mutated");
  std::cout << "VPN_FINAL_PREFLIGHT_PURE_PASS=8\n";
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
