#!/usr/bin/env python3
"""Generate portable actual-consumer traffic tests; every command/UI boundary is inert."""
import argparse
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "packages/flutter_vless_windows/windows"
PARTS = (
    ("proxy_service.cpp", "bool ApiClient::GetStats(", "\nint ApiClient::MeasureDelay("),
    ("proxy_service.cpp", "void ProxyService::UpdateTrafficStats() {", "\nint ProxyService::GetServerDelay("),
    ("vpn_service.cpp", "void VpnService::UpdateTrafficStats() {", None),
    ("v2ray_manager.cpp", "flutter_vless::traffic::Sample V2rayManager::GetTrafficSample() {", "\nbool V2rayManager::ValidateConfig("),
    ("flutter_vless_plugin.cpp", "void FlutterVlessPlugin::UpdateStatus() {", "\n// EventSink delivery belongs"),
)


def extracted(sources):
    output = []
    for name, begin, end in PARTS:
        source = sources[name]
        if source.count(begin) != 1 or end is not None and source.count(end) != 1:
            raise ValueError("Actual traffic consumer boundary changed")
        first = source.index(begin)
        last = source.index(end) if end else len(source)
        if first >= last:
            raise ValueError("Actual traffic consumer boundary changed")
        output.append(source[first:last])
    # Check each real lifecycle body separately; one surviving reset must not
    # mask a regression in another path. Worker/timer methods are never run.
    for name, begin, end, token in (
        ("proxy_service.cpp", "void ProxyService::Stop() {", "bool ProxyService::IsRunning()", "traffic_sample_ = {};"),
        ("vpn_service.cpp", "void VpnService::StopSession(bool release) {", "void VpnService::Stop()", "traffic_sample_ = {};"),
        ("vpn_service.cpp", "void VpnService::StopWorkers() {", "bool VpnService::RetireIPv6Address()", "traffic_sample_ = {};"),
        ("flutter_vless_plugin.cpp", "void FlutterVlessPlugin::StartStatusTimer() {", "void FlutterVlessPlugin::StopStatusTimer()", "upload_baseline_.Reset(); download_baseline_.Reset();"),
        ("flutter_vless_plugin.cpp", "void FlutterVlessPlugin::StopStatusTimer() {", "/**", "upload_baseline_.Reset(); download_baseline_.Reset();"),
    ):
        source = sources[name]
        if source.count(begin) != 1:
            raise ValueError("Traffic lifecycle reset boundary changed")
        first = source.index(begin)
        last = source.find(end, first + len(begin))
        if last < first or token not in source[first:last]:
            raise ValueError("Traffic lifecycle reset boundary changed")
    return "\n".join(output)


HEADER = r'''
#include "traffic_counters.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
using Json = flutter_vless::xray_config::Json;
namespace fs = std::filesystem;
struct Reply { bool ok = true; unsigned calls = 0; std::string output; } reply;
namespace flutter_vless::native {
bool Command(const fs::path&, const std::vector<std::wstring>&, std::string& output) {
  ++reply.calls; output = reply.output; return reply.ok;
}
}
struct ApiClient {
  void* service_ = this; std::string api_address_ = "127.0.0.1"; int api_port_ = 10086;
  bool GetStats(flutter_vless::traffic::Stats& stats);
  bool RunXrayApiCommand(const std::string&, std::string& output) {
    ++reply.calls; output = reply.output; return reply.ok;
  }
};
class ProxyService { public:
  std::unique_ptr<ApiClient> api_client_ = std::make_unique<ApiClient>();
  std::string current_config_;
  std::atomic<bool> ready_{true}; std::mutex stats_mutex_;
  flutter_vless::traffic::Sample traffic_sample_;
  void UpdateTrafficStats(); flutter_vless::traffic::Sample GetTrafficSample();
  void GetTrafficStats(int64_t&, int64_t&);
};
class VpnService { public:
  uint16_t api_port_ = 10086; fs::path xray_executable_path_ = "inert";
  flutter_vless::xray_config::VpnRoutingProvenance routing_provenance_;
  std::atomic<bool> ready_{true}; std::mutex stats_mutex_;
  flutter_vless::traffic::Sample traffic_sample_;
  void UpdateTrafficStats(); flutter_vless::traffic::Sample GetTrafficSample();
  void GetTrafficStats(int64_t&, int64_t&);
};
class V2rayManager { public:
  static V2rayManager& GetInstance() { static V2rayManager value; return value; }
  bool proxy_only_ = false;
  std::unique_ptr<ProxyService> proxy_service_ = std::make_unique<ProxyService>();
  std::unique_ptr<VpnService> vpn_service_ = std::make_unique<VpnService>();
  flutter_vless::traffic::Sample GetTrafficSample(); void GetTrafficStats(int64_t&, int64_t&);
  bool IsRunning() const { return true; } bool IsProtecting() const { return false; }
};
namespace flutter { using EncodableValue = std::string; using EncodableList = std::vector<std::string>; }
class FlutterVlessPlugin { public:
  std::atomic<int> last_tray_state_{-1}; bool is_running_ = true, status_sink_ = true;
  std::mutex status_mutex_, sink_mutex_; std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
  int64_t total_upload_ = 0, total_download_ = 0, upload_speed_ = 0, download_speed_ = 0;
  flutter_vless::traffic::Baseline upload_baseline_, download_baseline_;
  flutter::EncodableList emitted_status;
  void UpdateStatus(); void RefreshTray() {}
  void RunOnUIThread(const std::function<void()>& action) { action(); } // no OS/UI thread
  void SendStatusToUI(const flutter::EncodableList& value) { emitted_status = value; }
  void LogMessage(const std::string&) {}
};
'''

TESTS = r'''
void Require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
Json ProxyConfig(const std::string& tag) {
  return Json{{"inbounds", Json::array({{{"protocol","http"},{"listen","127.0.0.1"},{"port",18080},{"tag","imported"}},
      {{"protocol","socks"},{"listen","127.0.0.1"},{"port",10808},{"tag",tag}}})},
      {"outbounds",Json::array({{{"protocol","freedom"},{"tag","arbitrary-edge"}}})},
      {"policy",{{"system",{{"statsInboundUplink",false},{"statsInboundDownlink",false}}}}}};
}
std::optional<int64_t> Expected(const Json& value) { return value.is_null() ? std::nullopt : std::optional<int64_t>{value.get<int64_t>()}; }
void Same(flutter_vless::traffic::Sample sample, const Json& expected) {
  Require(sample.upload == Expected(expected["uplink"]) && sample.download == Expected(expected["downlink"]), "direction-local owned sample mismatch");
}
void Public(FlutterVlessPlugin& plugin, int64_t up, int64_t down, int64_t us = 0, int64_t ds = 0) {
  plugin.UpdateStatus();
  Require(plugin.emitted_status.size() == 6 && plugin.emitted_status[1] == std::to_string(us) && plugin.emitted_status[2] == std::to_string(ds)
      && plugin.emitted_status[3] == std::to_string(up) && plugin.emitted_status[4] == std::to_string(down) && plugin.emitted_status[5] == "CONNECTED",
      "public6 fields changed or unavailable/gap/reset produced fabricated speed");
}
int main(int argc, char** argv) try {
  Require(argc == 2, "pass shared traffic-counters.json");
  std::ifstream stream(argv[1]); Json corpus; stream >> corpus; Require(corpus.is_array() && corpus.size() == 11, "shared corpus must contain11 cases");
  auto& manager = V2rayManager::GetInstance(); auto& vpn = *manager.vpn_service_; auto& proxy = *manager.proxy_service_;
  unsigned wire_passed = 0, controls = 0;
  for (const auto& test : corpus) {
    const auto tag = test["tag"].get<std::string>(); reply = {}; reply.output = test["wire"].dump();
    vpn.routing_provenance_.managed_tag = tag; const auto original = ProxyConfig(tag).dump(); proxy.current_config_ = original;
    // Both real producer methods plus real ApiClient parse, manager delegation
    // and plugin event assembly run unchanged, with only Command/UI fakes.
    vpn.UpdateTrafficStats(); proxy.UpdateTrafficStats();
    Same(vpn.GetTrafficSample(), test["expected"]); Same(proxy.GetTrafficSample(), test["expected"]);
    for (bool proxy_only : {false,true}) {
      manager.proxy_only_ = proxy_only; Same(manager.GetTrafficSample(), test["expected"]);
      FlutterVlessPlugin plugin;
      Public(plugin, Expected(test["expected"]["uplink"]).value_or(0), Expected(test["expected"]["downlink"]).value_or(0));
    }
    Require(proxy.current_config_ == original, "counter collection changed source policy/config");
    ++wire_passed;
  }
  const std::string tag = "owned"; auto config = ProxyConfig(tag);
  proxy.current_config_ = config.dump(); vpn.routing_provenance_.managed_tag = tag;
  auto sample = [&](const Json& rows) { reply = {}; reply.output = Json{{"stat",rows}}.dump(); vpn.UpdateTrafficStats(); proxy.UpdateTrafficStats(); };
  const std::string up = "inbound>>>owned>>>traffic>>>uplink", down = "inbound>>>owned>>>traffic>>>downlink";
  sample(Json::array({{{"name",up},{"value",37}},{{"name",down},{"value",61}},{{"name","noise"},{"value",Json::object()}}}));
  Same(vpn.GetTrafficSample(), Json{{"uplink",37},{"downlink",61}}); Same(proxy.GetTrafficSample(), Json{{"uplink",37},{"downlink",61}}); ++controls;
  for (const auto& bad : {Json(nullptr),Json("37"),Json(1.5),Json(-1),Json(uint64_t{9223372036854775808ULL})}) {
    sample(Json::array({{{"name",up},{"value",bad}},{{"name",down},{"value",61}}}));
    Same(vpn.GetTrafficSample(), Json{{"uplink",nullptr},{"downlink",61}}); Same(proxy.GetTrafficSample(), Json{{"uplink",nullptr},{"downlink",61}});
  }
  ++controls;
  sample(Json::array({{{"name",up},{"value",37}},{{"name",down},{"value",61}},{{"name",up}}}));
  Same(vpn.GetTrafficSample(), Json{{"uplink",nullptr},{"downlink",61}}); Same(proxy.GetTrafficSample(), Json{{"uplink",nullptr},{"downlink",61}}); ++controls;
  reply.ok = false; vpn.UpdateTrafficStats(); proxy.UpdateTrafficStats(); Same(vpn.GetTrafficSample(),Json{{"uplink",nullptr},{"downlink",nullptr}}); Same(proxy.GetTrafficSample(),Json{{"uplink",nullptr},{"downlink",nullptr}}); ++controls;
  for (const auto* bad : {"not-json", "{\"stat\":[]} trailing", "{\"stat\":{}}"}) {
    reply = {}; reply.output = bad; vpn.UpdateTrafficStats(); proxy.UpdateTrafficStats();
    Require(!vpn.GetTrafficSample().upload && !proxy.GetTrafficSample().upload, "invalid API JSON became counters");
  }
  ++controls;
  config["inbounds"][1].erase("tag"); proxy.current_config_ = config.dump(); reply.calls = 0; proxy.UpdateTrafficStats();
  Require(!proxy.GetTrafficSample().upload && reply.calls == 0, "untagged primary was invented/queried"); ++controls;
  config = ProxyConfig(tag); config["inbounds"].push_back(config["inbounds"][1]); proxy.current_config_ = config.dump(); reply.calls = 0; proxy.UpdateTrafficStats();
  Require(!proxy.GetTrafficSample().upload && reply.calls == 0, "ambiguous primary was queried"); ++controls;
  config = ProxyConfig(tag); config["inbounds"][0]["tag"] = tag; proxy.current_config_ = config.dump(); reply.calls = 0; proxy.UpdateTrafficStats();
  Require(!proxy.GetTrafficSample().upload && reply.calls == 0, "duplicate namespace was queried"); ++controls;
  proxy.current_config_ = ProxyConfig(tag).dump(); vpn.api_port_ = 0; reply.calls = 0; vpn.UpdateTrafficStats();
  Require(!vpn.GetTrafficSample().upload && reply.calls == 0, "unowned API was queried"); vpn.api_port_ = 10086;
  proxy.api_client_.reset(); proxy.UpdateTrafficStats(); Require(!proxy.GetTrafficSample().upload, "absent owned API retained old counters"); proxy.api_client_ = std::make_unique<ApiClient>(); ++controls;
  sample(Json::array({{{"name",up},{"value",37}},{{"name",down},{"value",61}}}));
  vpn.ready_.store(false); proxy.ready_.store(false); Require(!vpn.GetTrafficSample().upload && !proxy.GetTrafficSample().upload, "stopped worker exposed stale counters");
  vpn.ready_.store(true); proxy.ready_.store(true); ++controls;
  for (bool proxy_only : {false,true}) {
    manager.proxy_only_ = proxy_only; FlutterVlessPlugin plugin;
    sample(Json::array({{{"name",up},{"value",37}},{{"name",down},{"value",61}}})); Public(plugin,37,61);
    sample(Json::array({{{"name",up},{"value",41}},{{"name",down},{"value",66}}})); Public(plugin,41,66,4,5);
    sample(Json::array({{{"name",up},{"value",43}}})); Public(plugin,43,0,2,0);
    sample(Json::array({{{"name",up},{"value",45}},{{"name",down},{"value",80}}})); Public(plugin,45,80,2,0);
    reply.ok = false; vpn.UpdateTrafficStats(); proxy.UpdateTrafficStats(); Public(plugin,0,0);
    sample(Json::array({{{"name",up},{"value",80}},{{"name",down},{"value",90}}})); Public(plugin,80,90);
    sample(Json::array({{{"name",up}},{{"name",down}}})); Public(plugin,0,0);
    sample(Json::array({{{"name",up},{"value",3}},{{"name",down},{"value",5}}})); Public(plugin,3,5,3,5);
    plugin.upload_baseline_.Reset(); plugin.download_baseline_.Reset(); Public(plugin,3,5);
  }
  ++controls;
  auto prepared = ProxyConfig(tag).dump(); const auto original_policy = Json::parse(prepared)["policy"];
  Require(flutter_vless::xray_config::PrepareProxy(prepared,[](uint16_t){return true;},[]{return uint16_t{19001};})
      && Json::parse(prepared)["policy"] == original_policy, "stats collection enabled caller policy"); ++controls;
  Require(controls == 12, "control count changed");
  std::cout << "WINDOWS_TRAFFIC_WIRE_PASS=" << wire_passed << '\n' << "WINDOWS_TRAFFIC_CONSUMER_PASS=" << controls << '\n';
  return 0;
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
'''


def sources():
    return {name: (WINDOWS / name).read_text() for name in {p[0] for p in PARTS}}


class Guards(unittest.TestCase):
    def test_actual_consumers_and_public_shape(self):
        body = extracted(sources())
        self.assertEqual(body.count("status.push_back("), 6)
        self.assertIn("flutter::EncodableList emitted_status;", HEADER)
        self.assertNotIn("flutter::EncodableList status;", HEADER)
        self.assertIn("ApiClient::GetStats", body)
        self.assertIn("routing_provenance_.managed_tag", body)

    def test_missing_or_duplicate_consumer_refuses(self):
        for duplicate in (False, True):
            value = sources(); name, begin, _ = PARTS[0]
            value[name] = value[name].replace(begin, begin + begin if duplicate else "")
            with self.assertRaises(ValueError): extracted(value)

    def test_lifecycle_reset_is_required(self):
        value = sources(); value["flutter_vless_plugin.cpp"] = value["flutter_vless_plugin.cpp"].replace(
            "upload_baseline_.Reset(); download_baseline_.Reset();", "", 1)
        with self.assertRaises(ValueError): extracted(value)

    def test_no_native_process_worker_or_socket_body_is_copied(self):
        body = extracted(sources())
        for forbidden in ("CreateProcess", "std::thread", "WSAStartup", "bind(", "RunV2ray()"):
            self.assertNotIn(forbidden, body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Guards))
    if not result.wasSuccessful(): return 1
    if args.generate:
        current = sources(); args.generate.parent.mkdir(parents=True, exist_ok=True)
        args.generate.write_text(HEADER + extracted(current) + TESTS)
        args.generate.with_suffix(".sources.json").write_text(json.dumps({
            "source_sha256": {p: hashlib.sha256(text.encode()).hexdigest() for p, text in current.items()},
            "real_native_runtime_executed": False, "source_guard_tests": 4
        }, indent=2) + "\n")
    print("WINDOWS_TRAFFIC_SOURCE_GUARD_PASS=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
