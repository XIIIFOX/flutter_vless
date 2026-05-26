#ifndef PROXY_SERVICE_H_
#define PROXY_SERVICE_H_

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
#include <vector>
#include <cstdint>

namespace fs = std::filesystem;

// Forward declarations
struct ProcessHandle;
struct ApiClient;
class V2rayManager; // Forward declaration for friend relationship if needed

/**
 * @brief Service class responsible for handling Proxy mode operations.
 * 
 * @details
 * This class encapsulates all logic related to running Xray in Proxy mode,
 * including process management, system proxy configuration, and statistics retrieval.
 * It is designed to be used by V2rayManager.
 */
class ProxyService {
 public:
  ProxyService();
  ~ProxyService();

  // Non-copyable, movable
  ProxyService(const ProxyService&) = delete;
  ProxyService& operator=(const ProxyService&) = delete;
  ProxyService(ProxyService&&) = default;
  ProxyService& operator=(ProxyService&&) = default;

  /**
   * @brief Starts the proxy service.
   * @param config The Xray configuration JSON.
   * @return true if started successfully, false otherwise.
   */
  bool Start(const std::string& config, bool configure_system_proxy = true);

  /**
   * @brief Stops the proxy service.
   */
  void Stop();

  /**
   * @brief Checks if the service is running.
   */
  bool IsRunning() const;

  /**
   * @brief Gets current traffic statistics.
   */
  void GetTrafficStats(int64_t& upload, int64_t& download);

  /**
   * @brief Measures delay to a target URL.
   */
  int GetServerDelay(const std::string& url);

  /**
   * @brief Measures delay using a temporary Xray process (stateless).
   */
  int MeasureDelayStateless(const std::string& config, const std::string& url);

  /**
   * @brief Gets the Xray core version.
   */
  std::string GetCoreVersion();

 private:
  friend struct ApiClient;

  void RunV2ray();
  bool StartXrayProcess(const std::string& config_path);
  void StopXrayProcess();
  bool WriteConfigToFile(const std::string& config, fs::path& config_path);
  
  // API communication
  bool InitializeApiClient();
  void UpdateTrafficStats();
  
  // Port helpers
  bool IsPortFree(uint16_t port);
  uint16_t FindFreePort();
  bool ReplacePortsInConfigFile(const fs::path& config_path);
  std::optional<std::string> DetectApiAddressInConfig(const fs::path& config_path);
  
  // Helper methods
  std::optional<fs::path> FindXrayExecutable();
  std::optional<fs::path> FindXrayAssets(const fs::path& executable_path);
  bool ValidateConfig(const std::string& config);
  void CleanupTempFiles();
  
  // System Proxy methods
  bool SetSystemProxy(const std::string& proxy_address, uint16_t proxy_port);
  bool ClearSystemProxy();

  // Thread synchronization and state
  std::atomic<bool> is_running_{false};
  std::thread v2ray_thread_;
  std::thread stats_thread_;
  std::string current_config_;
  bool configure_system_proxy_ = true;
  
  // Traffic statistics
  std::mutex stats_mutex_;
  int64_t total_upload_ = 0;
  int64_t total_download_ = 0;
  int64_t upload_speed_ = 0;
  int64_t download_speed_ = 0;
  
  // Process management
  std::unique_ptr<ProcessHandle> xray_process_;
  std::unique_ptr<ApiClient> api_client_;
  
  // Configuration and paths
  fs::path temp_config_path_;
  fs::path xray_executable_path_;
  std::string api_address_ = "127.0.0.1:10085";
  std::chrono::steady_clock::time_point start_time_;
  
  // Proxy settings buffers
  std::vector<char> proxy_server_buf_;
  std::vector<char> proxy_bypass_buf_;
};

// Process handle wrapper (moved from v2ray_manager.h)
struct ProcessHandle {
  std::uintptr_t hProcess = 0;
  std::uintptr_t hThread = 0;
  std::uintptr_t hStdOutRead = 0;
  std::uintptr_t hStdErrRead = 0;

  ProcessHandle();
  ~ProcessHandle();
  void Close();
  bool IsRunning() const;
};

// ApiClient (moved from v2ray_manager.h)
struct ApiClient {
  std::string api_address_;
  int api_port_ = 10085;
  
  bool GetStats(std::map<std::string, int64_t>& stats);
  int MeasureDelay(const std::string& url);
  std::string GetVersion();
  
 private:
  bool RunXrayApiCommand(const std::string& args, std::string& output);
  ProxyService* service_ = nullptr; // Changed from manager_
  friend class ProxyService;
};

#endif  // PROXY_SERVICE_H_
