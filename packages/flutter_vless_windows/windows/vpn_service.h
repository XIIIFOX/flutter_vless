#ifndef VPN_SERVICE_H_
#define VPN_SERVICE_H_

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <filesystem>
#include <optional>
#include <vector>
#include <map>

#include <condition_variable>
#include "traffic_protection.h"
#include "protected_runtime.h"
#include "packet_path_probe.h"
#include "proxy_service.h" // For ProcessHandle and helper functions

namespace fs = std::filesystem;

/**
 * @brief Manages the VPN connection lifecycle using Xray and Tun2Socks.
 * 
 * @details Architecture:
 * This service orchestrates a full VPN connection on Windows by combining two core components:
 * 1. **Xray Core**: Handles the VLESS protocol, encryption, and routing. It runs as a SOCKS5 proxy locally.
 * 2. **Tun2Socks**: Creates a virtual TUN interface (Layer 3) and redirects all traffic from it to the Xray SOCKS5 proxy.
 * 
 * @details Key Responsibilities:
 * - **Process Management**: Starts and stops Xray and Tun2Socks processes.
 * - **Configuration Injection**: Modifies the Xray config to inject API, DNS, and Routing rules required for VPN mode.
 * - **Network Configuration**: Configures the Windows TUN interface (IP, DNS, Routes) using Windows APIs and a trusted system utility.
 * - **Traffic Statistics**: Periodically queries the Xray API to retrieve upload/download traffic stats.
 * - **Routing Management**: Sets up split tunneling (bypassing the VPN server IP) to prevent routing loops.
 */
class VpnService {
 public:
  VpnService();
  ~VpnService();

  /**
   * @brief Starts the VPN service.
   * 
   * @param config The raw Xray configuration JSON string.
   * @return true if both Xray and Tun2Socks started successfully, false otherwise.
   * 
   * @details Workflow:
   * 1. Injects necessary VPN configuration (API, DNS, Routing) into the config.
   * 2. Starts Xray process with the modified config.
   * 3. Detects the SOCKS port Xray is listening on.
   * 4. Starts Tun2Socks pointing to that SOCKS port.
   * 5. Configures the OS network interface and routes.
   */
  bool Start(const std::string& config);

  /**
   * @brief Stops the VPN service and cleans up resources.
   * 
   * @details
   * - Terminates Xray and Tun2Socks processes.
   * - Cleans up temporary configuration files.
   * - Resets traffic statistics.
   * - Removes this session's capture routes before stopping Tun2Socks.
   */
  void Stop();
  void Shutdown();

  /**
   * @brief Checks if the VPN service is currently running.
   * @return true if the service is active.
   */
  bool IsRunning() const;

  /**
   * @brief Retrieves the current cumulative traffic statistics.
   * 
   * @param[out] upload Total bytes uploaded since connection start.
   * @param[out] download Total bytes downloaded since connection start.
   * 
   * @note Thread-safe.
   */
  void GetTrafficStats(int64_t& upload, int64_t& download);

 private:
  void RunVpn();
  bool StartWorkers();
  void StopWorkers();
  void StopSession(bool release_protection);
  void UpdateTrafficStats();
  std::atomic<bool> requested_{false};
  std::atomic<bool> ready_{false};
  std::thread vpn_thread_;
  std::mutex state_mutex_;
  std::condition_variable state_changed_;
  bool first_attempt_finished_ = false;
  std::unique_ptr<ProcessHandle> xray_process_;
  std::unique_ptr<ProcessHandle> tun2socks_process_;
  fs::path xray_executable_path_;
  fs::path tun2socks_executable_path_;
  fs::path temp_config_path_;
  fs::path tun_config_path_;
  std::string current_config_;
  std::map<std::string, std::string> bootstrap_cache_;
  std::string username_, password_;
  // Used only by the VPN worker to detect an underlay change independently of
  // the local TUN probe, which remains healthy when a physical adapter changes.
  std::string underlay_name_;
  UINT64 underlay_luid_ = 0;
  uint16_t socks_port_ = 0;
  flutter_vless::TrafficProtection protection_;
  std::unique_ptr<flutter_vless::native::ProtectedRuntime> private_runtime_;
  std::unique_ptr<flutter_vless::PacketPathProbe> packet_probe_;
  std::vector<MIB_IPFORWARD_ROW2> capture_routes_;
  std::mutex stats_mutex_;
  int64_t total_upload_ = 0, total_download_ = 0;
 public:
  bool IsProtecting() const { return protection_.Active(); }
};
#endif
