#ifndef V2RAY_MANAGER_H_
#define V2RAY_MANAGER_H_

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
#include <filesystem>
#include <chrono>
#include <future>
#include <map>
#include <cstdint>

#include "proxy_service.h"
#include "vpn_service.h"

namespace fs = std::filesystem;

class V2rayManager {
 public:
  static V2rayManager& GetInstance();

  bool Start(const std::string& config, bool proxy_only);
  void Stop();
  bool IsRunning() const;

  // Stats
  void GetTrafficStats(int64_t& upload, int64_t& download);
  
  // Delay measurement
  std::future<int> GetServerDelayAsync(const std::string& config, const std::string& url);
  int GetServerDelay(const std::string& config, const std::string& url);
  int GetConnectedServerDelay(const std::string& url);
  
  // Version
  std::string GetCoreVersion();

  // Bounded stdout/stderr from the current or most recent native session.
  std::string GetProviderDebugSnapshot();

 private:
  V2rayManager();
  ~V2rayManager();

  V2rayManager(const V2rayManager&) = delete;
  V2rayManager& operator=(const V2rayManager&) = delete;

  // Helper methods
  void RunV2ray();
  bool ValidateConfig(const std::string& config);
  std::string ModifyConfigForWindows(const std::string& config, bool proxy_only);
  
  // Thread synchronization and state
  std::atomic<bool> is_running_{false};
  std::thread v2ray_thread_;
  std::string current_config_;
  bool proxy_only_ = false;
  
  // Service delegates
  std::unique_ptr<ProxyService> proxy_service_;
  std::unique_ptr<VpnService> vpn_service_;
};

#endif  // V2RAY_MANAGER_H_
