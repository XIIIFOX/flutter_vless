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
 * - **Network Configuration**: Configures the Windows TUN interface (IP, DNS, Routes) using `netsh` and `route` commands.
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
  // --- Lifecycle Methods ---
  
  /**
   * @brief Main loop for the VPN service thread.
   * @details Monitors the processes and keeps the service alive.
   */
  void RunVpn();

  /**
   * @brief Starts the Xray process.
   * @param config_path Path to the temporary JSON configuration file.
   * @return true if started successfully.
   */
  bool StartXrayProcess(const std::string& config_path);

  /**
   * @brief Starts the Tun2Socks process.
   * @param socks_port The local SOCKS port Xray is listening on.
   * @return true if started successfully.
   */
  bool StartTun2SocksProcess(uint16_t socks_port);

  /**
   * @brief Terminates both child processes.
   */
  void StopProcesses();
  
  // --- Statistics Methods ---

  /**
   * @brief Periodically queries Xray API for traffic stats.
   * @details Runs in a separate thread (`stats_thread_`).
   */
  void UpdateTrafficStats();

  /**
   * @brief Executes an Xray API command via the executable.
   * @param args Command line arguments for the API call.
   * @param[out] output The stdout output from the command.
   * @return true if the command executed successfully.
   */
  bool RunXrayApiCommand(const std::string& args, std::string& output);

  /**
   * @brief Injects VPN-specific configuration into the user's Xray config.
   * 
   * @param config Original user configuration.
   * @return Modified configuration string.
   * 
   * @details Adds a dedicated API listener and statistics policy while preserving
   * caller routing rules, DNS settings and outbound transport configuration.
   */
  std::string InjectApiConfig(const std::string& config);
  
  // --- Helper Methods ---

  bool WriteConfigToFile(const std::string& config, fs::path& config_path);
  std::optional<fs::path> FindTun2SocksExecutable();
  std::optional<fs::path> FindXrayExecutable();
  std::optional<fs::path> FindXrayAssets(const fs::path& executable_path);
  
  // --- Routing Helpers ---

  /**
   * @brief Extracts the VPN server address (domain or IP) from the config.
   */
  std::string ExtractServerAddress(const std::string& config);

  /**
   * @brief Resolves a domain name to an IP address.
   * @details Used to create specific route bypass rules for the VPN server.
   */
  std::string ResolveToIP(const std::string& address);

  /**
   * @brief Retrieves the system's default gateway IP.
   * @details Used to construct `route ADD` commands for bypass routes.
   */
  std::string GetDefaultGateway();

  // --- Members ---
  
  std::atomic<bool> is_running_{false};
  std::thread vpn_thread_;
  std::thread stats_thread_;
  
  std::unique_ptr<ProcessHandle> xray_process_;
  std::unique_ptr<ProcessHandle> tun2socks_process_;
  
  fs::path xray_executable_path_;
  fs::path tun2socks_executable_path_;
  fs::path temp_config_path_;
  
  std::string current_config_;
  std::vector<std::string> capture_routes_;
  
  // Stats synchronization
  std::mutex stats_mutex_;
  int64_t total_upload_ = 0;
  int64_t total_download_ = 0;
  std::string api_address_ = "127.0.0.1:10086"; // Dedicated API port for VPN service
};

#endif // VPN_SERVICE_H_
