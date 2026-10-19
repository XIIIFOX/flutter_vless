#include "v2ray_manager.h"
#include "diagnostics_log.h"
#include "xray_config.h"
#include "native_runtime.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <process.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <regex>
#include <map>
#include <vector>
#include <cstring>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")

// JSON parsing helpers (simple implementation, can be replaced with nlohmann/json)
namespace {
namespace json_utils {
  bool IsValidJson(const std::string& json_str) {
    // Basic JSON validation - check for balanced braces and brackets
    int brace_count = 0;
    int bracket_count = 0;
    bool in_string = false;
    bool escaped = false;
    
    for (char c : json_str) {
      if (escaped) {
        escaped = false;
        continue;
      }
      
      if (c == '\\') {
        escaped = true;
        continue;
      }
      
      if (c == '"') {
        in_string = !in_string;
        continue;
      }
      
      if (in_string) continue;
      
      if (c == '{') brace_count++;
      else if (c == '}') brace_count--;
      else if (c == '[') bracket_count++;
      else if (c == ']') bracket_count--;
      
      if (brace_count < 0 || bracket_count < 0) return false;
    }
    
    return brace_count == 0 && bracket_count == 0 && !in_string;
  }
}
}

V2rayManager::V2rayManager() {
  proxy_service_ = std::make_unique<ProxyService>();
  vpn_service_ = std::make_unique<VpnService>();
}

V2rayManager::~V2rayManager() {
  Shutdown();
}

V2rayManager& V2rayManager::GetInstance() {
  static V2rayManager instance;
  return instance;
}

bool V2rayManager::Start(const std::string& config, bool proxy_only, const flutter_vless::NativeOptions& options,
    flutter_vless::asset_location::Root assets,
    std::optional<flutter_vless::native_routing::NativeRoutingIntent> routing,
    flutter_vless::preparation::StartupOutcome* outcome, flutter_vless::preparation::Report changes) try {
  using flutter_vless::preparation::Stage;
  if (outcome) outcome->Fail(Stage::prepare);
  if (proxy_only && routing) return false;
  if (!flutter_vless::asset_location::Valid(assets)) return false;
  auto failure = Stage::core_check;
  if (!ValidateConfig(config, proxy_only, assets, &failure)) {
    if (outcome) outcome->Fail(failure);
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Xray configuration check rejected candidate; active session preserved");
    return false;
  }
  if (is_running_.load() && (proxy_only || proxy_only_)) {
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Stop the active session before changing proxy-only mode or configuration");
    return false;
  }
  // The callback runs only after the service admits its own checked candidate.
  // Rejection cannot publish the replacement into manager state or its report.
  const auto publish = [&] {
    flutter_vless::DiagnosticsLog::Instance().Reset();
    flutter_vless::DiagnosticsLog::Instance().Append("runtime", proxy_only
        ? "Starting Windows proxy-only session" : "Starting Windows VPN session");
    current_config_ = config; proxy_only_ = proxy_only; is_running_.store(true);
  };
  if (proxy_only) return proxy_service_ && proxy_service_->Start(config, assets, outcome, changes, publish);
  return vpn_service_ && vpn_service_->Start(config, options, assets, std::move(routing), publish, outcome, changes);
} catch (...) {
  if (outcome) outcome->Fail(outcome->stage);
  flutter_vless::DiagnosticsLog::Instance().Append("runtime", "Native configuration or startup rejected");
  return false;
}

void V2rayManager::Stop() {
  is_running_.store(false);
  
  if (proxy_only_) {
    if (proxy_service_) {
      proxy_service_->Stop();
    }
  } else {
    if (vpn_service_) {
      vpn_service_->Stop();
    }
  }
}

void V2rayManager::Shutdown() {
  is_running_.store(false);
  if (proxy_service_) proxy_service_->Stop();
  if (vpn_service_) vpn_service_->Shutdown();
}

bool V2rayManager::IsRunning() const {
  return is_running_.load() && (proxy_only_
      ? (proxy_service_ && proxy_service_->IsRunning())
      : (vpn_service_ && vpn_service_->IsRunning()));
}

void V2rayManager::RunV2ray() {
  // VPN Stub: Simulate running state
  std::cerr << "VPN functionality is currently disabled. Printing to console only." << std::endl;
  
  while (is_running_.load()) {
    // Simulate activity
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

std::future<int> V2rayManager::GetServerDelayAsync(const std::string& config, const std::string& url) {
  return std::async(std::launch::async, [this, config, url]() {
    return GetServerDelay(config, url);
  });
}

int V2rayManager::GetServerDelay(const std::string& config, const std::string& url) {
  if (proxy_service_) {
    return proxy_service_->MeasureDelayStateless(config, url);
  }
  return -1;
}

int V2rayManager::GetConnectedServerDelay(const std::string& url) {
  if (proxy_only_ && proxy_service_) {
    return proxy_service_->GetServerDelay(url);
  }
  return -1;
}

std::string V2rayManager::GetCoreVersion() {
  if (proxy_service_) {
    return proxy_service_->GetCoreVersion();
  }
  return "Unknown";
}

std::string V2rayManager::GetProviderDebugSnapshot() {
  return flutter_vless::DiagnosticsLog::Instance().Snapshot();
}

/**
 * @brief Retrieves current traffic statistics from the active service.
 * 
 * @param[out] upload Total bytes uploaded.
 * @param[out] download Total bytes downloaded.
 * 
 * @details This function delegates stats retrieval to either ProxyService or VpnService
 * depending on the current mode (proxy_only_ flag).
 * 
 * @note CRITICAL FIX: This method used to only query ProxyService, causing zero stats
 * in VPN mode. Now it correctly checks the mode and queries the appropriate service.
 */
flutter_vless::traffic::Sample V2rayManager::GetTrafficSample() {
  return proxy_only_ ? (proxy_service_ ? proxy_service_->GetTrafficSample() : flutter_vless::traffic::Sample{})
      : (vpn_service_ ? vpn_service_->GetTrafficSample() : flutter_vless::traffic::Sample{});
}
void V2rayManager::GetTrafficStats(int64_t& upload, int64_t& download) {
  const auto sample = GetTrafficSample();
  upload = sample.upload.value_or(0); download = sample.download.value_or(0);
}

bool V2rayManager::ValidateConfig(const std::string& config, bool proxy_only, const flutter_vless::asset_location::Root& assets,
    flutter_vless::preparation::Stage* failure) {
  const auto executable = flutter_vless::native::FindBundledFile(L"xray.exe");
  const auto storage = proxy_only ? flutter_vless::native::ConfigCheckStorage::currentUser
                                 : flutter_vless::native::ConfigCheckStorage::administrators;
  return executable && flutter_vless::native::CheckConfig(config, *executable, storage, assets, failure);
}

// Kept for reference but unused in VPN stub
std::string V2rayManager::ModifyConfigForWindows(const std::string& config, bool proxy_only) {
  return config;
}

bool V2rayManager::IsProtecting() const { return !proxy_only_ && vpn_service_ && vpn_service_->IsProtecting(); }
