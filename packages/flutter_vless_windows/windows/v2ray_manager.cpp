#include "v2ray_manager.h"
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
  Stop();
}

V2rayManager& V2rayManager::GetInstance() {
  static V2rayManager instance;
  return instance;
}

bool V2rayManager::Start(const std::string& config, bool proxy_only, bool configure_system_proxy) {
  if (is_running_.load()) {
    Stop();
  }

  if (!ValidateConfig(config)) {
    std::cerr << "Invalid Xray configuration JSON" << std::endl;
    return false;
  }

  current_config_ = config;
  proxy_only_ = proxy_only;
  
  if (proxy_only_) {
    // Proxy Mode: Delegate to ProxyService
    if (proxy_service_) {
      is_running_.store(true);
      return proxy_service_->Start(config, configure_system_proxy);
    }
    return false;
  } else {
    // VPN Mode: Delegate to VpnService
    std::cerr << "Starting VPN mode with Tun2Socks..." << std::endl;
    if (vpn_service_) {
      is_running_.store(true);
      return vpn_service_->Start(config);
    }
    return false;
  }
}

void V2rayManager::Stop() {
  if (!is_running_.load()) {
    return;
  }

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

bool V2rayManager::IsRunning() const {
  return is_running_.load();
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
void V2rayManager::GetTrafficStats(int64_t& upload, int64_t& download) {
  if (proxy_only_) {
    // Proxy Mode: Get stats from ProxyService
    if (proxy_service_) {
      proxy_service_->GetTrafficStats(upload, download);
    } else {
      upload = 0;
      download = 0;
    }
  } else {
    // VPN Mode: Get stats from VpnService
    if (vpn_service_) {
      vpn_service_->GetTrafficStats(upload, download);
    } else {
      upload = 0;
      download = 0;
    }
  }
}

bool V2rayManager::ValidateConfig(const std::string& config) {
  return json_utils::IsValidJson(config);
}

// Kept for reference but unused in VPN stub
std::string V2rayManager::ModifyConfigForWindows(const std::string& config, bool proxy_only) {
  return config;
}
