#!/usr/bin/env python3
"""Portable tests of actual Windows startup/result consumers; all service/UI boundaries are inert."""
import argparse
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "packages/flutter_vless_windows/windows"


def extract(sources):
    def part(name, begin, end):
        text = sources[name]
        if text.count(begin) != 1 or text.count(end) != 1:
            raise ValueError("Windows startup consumer boundary changed")
        first, last = text.index(begin), text.index(end)
        if first >= last:
            raise ValueError("Windows startup consumer boundary changed")
        return text[first:last]
    manager = part("v2ray_manager.cpp", "bool V2rayManager::Start(", "\nvoid V2rayManager::Stop()")
    codec = part("flutter_vless_plugin.cpp", "flutter::EncodableValue StartupSuccessValue(",
                 "\n/**\n * @brief Helper function to log messages")
    plugin = sources["flutter_vless_plugin.cpp"]
    begin = "        operations_.Submit([this, config, proxy_only, assets, routing, shared_result, options, generation, preparation_changes]() {"
    if plugin.count(begin) != 1:
        raise ValueError("Windows startup submission boundary changed")
    first = plugin.index(begin)
    last = plugin.index("\n        });", first) + len("\n        });")
    submission = plugin[first:last]
    if submission.count("CompleteStartup(*shared_result, ready, protecting, outcome);") != 1:
        raise ValueError("Windows startup callback no longer owns its outcome")
    runtime = part("native_runtime.cpp", "bool CheckConfig(", "\nbool RoutingCapability(")
    return manager, codec, submission, runtime


HEADER = r'''
#include "preparation_report.h"
#include "asset_location.h"
#include "xray_config.h"
#include "native_options.h"
#include "native_routing_spec.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
using Json = nlohmann::ordered_json;
using Report = flutter_vless::preparation::Report;
using Outcome = flutter_vless::preparation::StartupOutcome;
using Stage = flutter_vless::preparation::Stage;
using Root = flutter_vless::asset_location::Root;
using Intent = flutter_vless::native_routing::NativeRoutingIntent;
namespace fs = std::filesystem;
#ifndef _WIN32
using DWORD = unsigned long;
using HANDLE = void*;
constexpr DWORD WAIT_OBJECT_0 = 0;
#endif
struct NativeState { bool write = true, launch = true, wait = true; DWORD exit = 0; std::string written; fs::path launched; } native_state;
namespace flutter_vless::native {
DWORD WaitForSingleObject(HANDLE, unsigned) { return native_state.wait ? WAIT_OBJECT_0 : 258; }
bool GetExitCodeProcess(HANDLE, DWORD* code) { *code = native_state.exit; return true; }
enum class ConfigCheckStorage { currentUser, administrators };
struct ProcessHandle { intptr_t hProcess = 1; };
bool WritePrivateConfig(const std::string& config, fs::path& path) {
  if (!native_state.write) return false;
  native_state.written = config; path = "private-checked-file"; return true;
}
void RemovePrivateConfig(fs::path& path) { path.clear(); }
struct ProtectedRuntime {
  bool Create(const fs::path&, bool) const { return true; }
  bool WriteConfig(const std::string& config, fs::path& path) const { return WritePrivateConfig(config, path); }
  fs::path Executable() const { return "private-owned-image"; }
};
std::unique_ptr<ProcessHandle> Launch(const fs::path&, const std::vector<std::wstring>& arguments, bool, const Root&) {
  native_state.launched = arguments.back();
  return native_state.launch ? std::make_unique<ProcessHandle>() : nullptr;
}
}

namespace flutter_vless {
struct DiagnosticsLog {
  static DiagnosticsLog& Instance() { static DiagnosticsLog log; return log; }
  void Append(const char*, const char*) {} void Reset() {}
};
}
struct FakeService {
  bool accept = true, legacy = false, proxy = false, protecting = false;
  Stage failure = Stage::core_check;
  bool Start(const std::string&, const flutter_vless::NativeOptions&, Root, std::optional<Intent>,
      std::function<void()> admitted, Outcome* outcome, Report changes) {
    if (!accept) { if (outcome) outcome->Fail(failure); return false; }
    if (admitted) admitted();
    if (!legacy && outcome) {
      if (proxy) changes.CheckedHost(); else changes.CheckedFinal();
      outcome->Succeed(changes);
    }
    return true;
  }
  bool Start(const std::string& config, Root assets, Outcome* outcome, Report changes, std::function<void()> admitted) {
    return Start(config, {}, assets, std::nullopt, std::move(admitted), outcome, changes);
  }
};
class V2rayManager { public:
  static V2rayManager& GetInstance() { static V2rayManager manager; return manager; }
  std::atomic<bool> is_running_{false}, proxy_only_{false}; std::string current_config_;
  bool valid = true;
  std::unique_ptr<FakeService> proxy_service_ = std::make_unique<FakeService>();
  std::unique_ptr<FakeService> vpn_service_ = std::make_unique<FakeService>();
  bool Start(const std::string&, bool, const flutter_vless::NativeOptions& = {}, Root = {},
      std::optional<Intent> = {}, Outcome* = nullptr, Report = {});
  bool ValidateConfig(const std::string&, bool, const Root&, Stage* failure) { if (failure) *failure = Stage::core_check; return valid; }
  bool IsRunning() const { return is_running_.load(); }
  bool IsProtecting() const { return vpn_service_->protecting; }
};
namespace flutter {
struct EncodableValue;
using EncodableList = std::vector<EncodableValue>;
using EncodableMap = std::map<EncodableValue, EncodableValue>;
struct EncodableValue {
  Json value;
  EncodableValue() = default;
  EncodableValue(std::nullptr_t) : value(nullptr) {}
  EncodableValue(int input) : value(input) {}
  EncodableValue(const char* input) : value(input) {}
  EncodableValue(const std::string& input) : value(input) {}
  EncodableValue(const EncodableList& input) : value(Json::array()) { for (const auto& item : input) value.push_back(item.value); }
  EncodableValue(const EncodableMap& input) : value(Json::object()) {
    for (const auto& item : input) value[item.first.value.get<std::string>()] = item.second.value;
  }
  bool operator<(const EncodableValue& other) const { return value.dump() < other.value.dump(); }
};
template<class T> struct MethodResult {
  Json success, details; std::string error;
  void Success(const T& value) { success = value.value; }
  void Error(const std::string& code, const std::string&, const T& value) { error = code; details = value.value; }
};
}
class FlutterVlessPlugin { public:
  struct Queue { void Submit(const std::function<void()>& action) { action(); } } operations_;
  struct QuickProfile { std::string config; Root assets; std::optional<Intent> routing; };
  std::optional<QuickProfile> quick_profile_;
  std::atomic<std::uint64_t> quick_profile_generation_{0};
  std::atomic<unsigned> options_generation_{0}; std::mutex lifecycle_mutex_; bool is_running_ = false;
  std::chrono::steady_clock::time_point start_time_;
  std::vector<std::function<void()>> callbacks;
  void LogMessage(const char*) {} void RefreshTray() {} void StartStatusTimer() {}
  void RunOnUIThread(const std::function<void()>& action) { callbacks.push_back(action); }
  void Submit(const std::string& config, bool proxy_only, Report preparation_changes,
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result);
};
'''

TESTS = r'''
void Require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
int main() try {
  auto& manager = V2rayManager::GetInstance(); FlutterVlessPlugin plugin;
  using Result = flutter::MethodResult<flutter::EncodableValue>;
  Report certificate; certificate.Add(flutter_vless::preparation::Change::certificate_refs_bound);
  Report address; address.Add(flutter_vless::preparation::Change::address_environment_bound);
  auto first = std::make_shared<Result>(), second = std::make_shared<Result>();
  plugin.Submit("secret-first-host.invalid", false, certificate, first);
  plugin.Submit("secret-second-token", false, address, second);
  Require(plugin.callbacks.size() == 2, "actual submission lost one UI callback");
  plugin.callbacks[1](); plugin.callbacks[0](); plugin.callbacks.clear();
  Require(first->success["preparationReport"]["changes"] == Json::array({"certificate_refs_bound"})
      && second->success["preparationReport"]["changes"] == Json::array({"address_environment_bound"}),
      "delayed callbacks swapped per-call reports");
  Require(first->success["preparationReport"]["scope"] == "runtimeFinal"
      && first->success["preparationReport"]["coreCheck"] == "passed", "final candidate scope lost");
  const auto accepted = manager.current_config_;
  manager.vpn_service_->accept = false;
  auto rejected = std::make_shared<Result>(); plugin.Submit("rejected-private-canary", false, {}, rejected);
  plugin.callbacks.back()(); plugin.callbacks.clear();
  Require(manager.current_config_ == accepted && manager.is_running_, "preflight rejection published over old owner");
  Require(rejected->error == "VPN_START_FAILED" && rejected->details == Json({{"stage","core-check"},{"version",1}})
      && rejected->success.is_null(), "preflight rejection leaked old successful report");
  manager.vpn_service_->failure = Stage::persist;
  auto persist = std::make_shared<Result>(); plugin.Submit("secret-path", false, {}, persist);
  plugin.callbacks.back()(); plugin.callbacks.clear();
  Require(persist->details["stage"] == "persist", "known private write failure lost stage");
  manager.vpn_service_->accept = true; manager.vpn_service_->legacy = true;
  auto legacy = std::make_shared<Result>(); plugin.Submit("legacy", false, {}, legacy);
  plugin.callbacks.back()(); plugin.callbacks.clear();
  Require(legacy->success["preparationReport"]["scope"] == "host"
      && legacy->success["preparationReport"]["coreCheck"] == "unavailable", "legacy fabricated Core acceptance");
  manager.is_running_ = false; manager.vpn_service_->legacy = false; manager.proxy_service_->proxy = true;
  auto proxy = std::make_shared<Result>(); plugin.Submit("proxy", true, {}, proxy);
  plugin.callbacks.back()(); plugin.callbacks.clear();
  Require(proxy->success["preparationReport"]["scope"] == "host"
      && proxy->success["preparationReport"]["coreCheck"] == "passed", "proxy claimed final-file identity");
  manager.valid = false;
  Outcome refused; Require(!manager.Start("raw-private-invalid", false, {}, {}, {}, &refused)
      && !refused.report && refused.Details()["stage"] == "core-check", "raw check refusal fabricated report");
  for (const auto* secret : {"secret", "canary", "invalid", "token", "path"})
    Require((first->success.dump() + second->success.dump() + rejected->details.dump() + persist->details.dump()).find(secret) == std::string::npos,
        "channel report disclosed caller content");
  Require(!manager.Start("legacy-bool", false), "source-compatible bool call ignored refusal");
  using namespace flutter_vless::native;
  ProtectedRuntime runtime; Stage failure = Stage::start; fs::path checked;
  Require(!CheckPreparedConfig("invalid-private-canary", runtime, checked, {}, &failure)
      && failure == Stage::prepare, "invalid final shape did not retain prepare stage");
  native_state.write = false;
  Require(!CheckPreparedConfig("{}", runtime, checked, {}, &failure)
      && failure == Stage::persist, "actual private write refusal lost persist stage");
  native_state.write = true; native_state.wait = false;
  Require(!CheckPreparedConfig("{}", runtime, checked, {}, &failure)
      && failure == Stage::core_check, "actual bounded checker failure lost core-check stage");
  native_state.wait = true; checked.clear();
  const std::string exact = "{ \"outbounds\": [] }\n";
  Require(CheckPreparedConfig(exact, runtime, checked, {}, &failure)
      && native_state.written == exact && native_state.launched == checked, "actual final check changed bytes or file");
  std::cout << "WINDOWS_PREPARATION_REPORT_CONSUMER_PASS=12\n";
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
'''


def generated(sources):
    manager, codec, submission, runtime = extract(sources)
    return HEADER + "\nnamespace flutter_vless::native {\n" + runtime + "\n}\n" + manager + codec + r'''
void FlutterVlessPlugin::Submit(const std::string& config, bool proxy_only, Report preparation_changes,
    std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result) {
  Root assets; std::optional<Intent> routing; flutter_vless::NativeOptions options;
  const auto generation = options_generation_.load();
''' + submission + "\n}\n" + TESTS


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.sources = {name: (WINDOWS / name).read_text() for name in ("v2ray_manager.cpp", "flutter_vless_plugin.cpp", "native_runtime.cpp")}

    def test_actual_sources_generate(self):
        self.assertIn("WINDOWS_PREPARATION_REPORT_CONSUMER_PASS=12", generated(self.sources))

    def test_missing_outcome_callback_refused(self):
        self.sources["flutter_vless_plugin.cpp"] = self.sources["flutter_vless_plugin.cpp"].replace(
            "CompleteStartup(*shared_result, ready, protecting, outcome);", "CompleteStartup(*shared_result, ready, protecting, {});")
        with self.assertRaises(ValueError):
            generated(self.sources)

    def test_changed_manager_boundary_refused(self):
        self.sources["v2ray_manager.cpp"] = self.sources["v2ray_manager.cpp"].replace("bool V2rayManager::Start(", "bool Other::Start(")
        with self.assertRaises(ValueError):
            generated(self.sources)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", type=Path)
    args = parser.parse_args()
    if args.generate:
        sources = {name: (WINDOWS / name).read_text() for name in ("v2ray_manager.cpp", "flutter_vless_plugin.cpp", "native_runtime.cpp")}
        args.generate.parent.mkdir(parents=True, exist_ok=True)
        args.generate.write_text(generated(sources))
        hashes = {str((WINDOWS / name).relative_to(ROOT)): hashlib.sha256((WINDOWS / name).read_bytes()).hexdigest()
                  for name in (*sources, "preparation_report.h", "vpn_worker_candidate.h", "xray_config.h")}
        args.generate.with_suffix(".sources.json").write_text(json.dumps(hashes, indent=2) + "\n")
    else:
        unittest.main(argv=[__file__])
