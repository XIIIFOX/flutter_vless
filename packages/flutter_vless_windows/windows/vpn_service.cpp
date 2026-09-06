#include "vpn_service.h"
#include "diagnostics_log.h"
#include "xray_config.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wininet.h>
#include <process.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <regex>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")

#pragma comment(lib, "iphlpapi.lib")

namespace {
std::optional<std::string> DefaultInterfaceName() {
  MIB_IF_ROW2 row{};
  // Select the current outbound route before the plugin installs its TUN route.
  if (GetBestInterface(0x08080808, &row.InterfaceIndex) != NO_ERROR ||
      GetIfEntry2(&row) != NO_ERROR) return std::nullopt;
  const int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
  if (size <= 1) return std::nullopt;
  std::string name(static_cast<size_t>(size), '\0');
  if (!WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, name.data(), size, nullptr, nullptr)) {
    return std::nullopt;
  }
  name.resize(static_cast<size_t>(size - 1));
  if (name == "flutter_vless_tun") return std::nullopt;
  return name;
}
}  // namespace

VpnService::VpnService() {
  xray_executable_path_ = FindXrayExecutable().value_or(fs::path());
  if (!xray_executable_path_.empty()) {
    std::cerr << "VpnService: Found Xray executable at: " << xray_executable_path_ << std::endl;
  } else {
    std::cerr << "VpnService: WARNING - Xray executable not found!" << std::endl;
  }
  
  tun2socks_executable_path_ = FindTun2SocksExecutable().value_or(fs::path());
  if (!tun2socks_executable_path_.empty()) {
    std::cerr << "VpnService: Found Tun2Socks executable at: " << tun2socks_executable_path_ << std::endl;
  } else {
    std::cerr << "VpnService: WARNING - Tun2Socks executable not found!" << std::endl;
  }
}

VpnService::~VpnService() {
  Stop();
  if (!temp_config_path_.empty() && fs::exists(temp_config_path_)) {
    try { fs::remove(temp_config_path_); } catch (...) {}
  }
}

bool VpnService::Start(const std::string& config) {
  Stop();

  current_config_ = config;
  
  if (xray_executable_path_.empty()) {
    std::cerr << "Xray executable not found." << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Xray executable not found for Windows VPN service");
    return false;
  }
  
  if (tun2socks_executable_path_.empty()) {
    std::cerr << "Tun2Socks executable not found." << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Tun2Socks executable not found for Windows VPN service");
    return false;
  }

  is_running_.store(true);
  vpn_thread_ = std::thread(&VpnService::RunVpn, this);
  
  return true;
}

void VpnService::Stop() {
  is_running_.store(false);
  
  if (vpn_thread_.joinable()) {
    vpn_thread_.join();
  }
  
  if (stats_thread_.joinable()) {
    stats_thread_.join();
  }
  
  StopProcesses();
  
  if (!temp_config_path_.empty() && fs::exists(temp_config_path_)) {
    try { fs::remove(temp_config_path_); } catch (...) {}
  }
}

bool VpnService::IsRunning() const {
  return is_running_.load();
}

/**
 * @brief Main VPN service loop that orchestrates the entire connection.
 * 
 * @details This method runs in a separate thread and performs the following:
 * 1. Injects VPN-specific config (API, DNS, Routing) into user's Xray config
 * 2. Starts Xray process (VLESS/SOCKS proxy)
 * 3. Detects SOCKS port and starts Tun2Socks
 * 4. Configures OS network (TUN interface IP, DNS, routes)
 * 5. Monitors processes and keeps VPN alive
 */
void VpnService::RunVpn() {
  // === PHASE 1: Prepare and start Xray ===
  // Inject API, DNS, and routing configuration required for VPN mode
  std::string config_with_api = InjectApiConfig(current_config_);
  const auto outbound_interface = DefaultInterfaceName();
  if (config_with_api.empty() || !outbound_interface ||
      !flutter_vless::xray_config::BindDirectOutbounds(config_with_api, *outbound_interface)) {
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Could not prepare Windows VPN configuration and direct interface");
    is_running_.store(false);
    return;
  }
  
  fs::path config_path;
  if (!WriteConfigToFile(config_with_api, config_path)) {
    std::cerr << "Failed to write Xray config for VPN" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to write Windows VPN Xray configuration file");
    is_running_.store(false);
    return;
  }
  temp_config_path_ = config_path;

  // Start Xray process with modified config
  if (!StartXrayProcess(config_path.string())) {
    std::cerr << "Failed to start Xray for VPN" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to start Windows VPN Xray process");
    is_running_.store(false);
    return;
  }
  
  std::cerr << "VPN Service: Xray started successfully" << std::endl;

  // Wait for Xray to fully initialize its listeners
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  const auto selected_port = flutter_vless::xray_config::SocksPort(config_with_api);
  if (!selected_port) {
    StopProcesses();
    is_running_.store(false);
    return;
  }
  const uint16_t socks_port = *selected_port;
  std::cerr << "VPN Service: Xray SOCKS port detected as " << socks_port << std::endl;

  // 4. Start Tun2Socks with IP configuration
  if (!StartTun2SocksProcess(socks_port)) {
    std::cerr << "Failed to start Tun2Socks" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to start Windows VPN Tun2Socks process");
    StopProcesses();
    is_running_.store(false);
    return;
  }

  // === PHASE 4: Configure OS Network Stack ===
  // Wait for Tun2Socks to fully create and initialize the TUN interface
  std::this_thread::sleep_for(std::chrono::milliseconds(2000));
  
  std::cerr << "VPN Service: Configuring TUN interface..." << std::endl;
  
  // Assign IP address to the virtual TUN interface
  // 10.0.85.2 = TUN interface IP, 10.0.85.1 = virtual gateway
  std::string set_ip_cmd = "netsh interface ip set address name=\"flutter_vless_tun\" source=static addr=10.0.85.2 mask=255.255.255.0 gateway=none";
  std::cerr << "VPN Service: Executing: " << set_ip_cmd << std::endl;
  system(set_ip_cmd.c_str());
  
  // === CRITICAL: Setup Bypass Routes ===
  // PROBLEM: If we route all traffic through the TUN, including VPN server traffic,
  // we create a routing loop (VPN server traffic → TUN → Xray → VPN server → TUN → ...)
  // SOLUTION: Add specific OS routes that bypass the TUN for:
  // 1. VPN server IP (must go through physical interface)
  // 2. DNS servers (8.8.8.8, 1.1.1.1) to ensure reliable resolution
  
  std::string server_address = ExtractServerAddress(current_config_);
  if (!server_address.empty()) {
    std::cerr << "VPN Service: Extracting server address: " << server_address << std::endl;
    
    // Resolve domain to IP (Windows routes require IP, not domain)
    std::string server_ip = ResolveToIP(server_address);
    if (!server_ip.empty()) {
      std::cerr << "VPN Service: Resolved server to IP: " << server_ip << std::endl;
      
      // Get physical gateway (e.g., router IP like 192.168.1.1)
      std::string default_gateway = GetDefaultGateway();
      if (!default_gateway.empty()) {
        std::cerr << "VPN Service: Default gateway: " << default_gateway << std::endl;
        
        // Clean up any existing route first to avoid "object already exists" errors
        std::string delete_bypass_route_cmd = "route DELETE " + server_ip;
        system(delete_bypass_route_cmd.c_str());
        
        // Add bypass route: VPN server IP → physical gateway (not through TUN)
        std::string bypass_route_cmd = "route ADD " + server_ip + " MASK 255.255.255.255 " + default_gateway + " METRIC 1";
        std::cerr << "VPN Service: Adding bypass route: " << bypass_route_cmd << std::endl;
        system(bypass_route_cmd.c_str());
        
        // Also bypass DNS servers (used by Xray's internal DNS resolver)
        // These match the DNS servers in the injected Xray config
        std::string delete_dns1_cmd = "route DELETE 8.8.8.8";
        std::string delete_dns2_cmd = "route DELETE 1.1.1.1";
        system(delete_dns1_cmd.c_str());
        system(delete_dns2_cmd.c_str());
        
        std::string dns1_route_cmd = "route ADD 8.8.8.8 MASK 255.255.255.255 " + default_gateway + " METRIC 1";
        std::string dns2_route_cmd = "route ADD 1.1.1.1 MASK 255.255.255.255 " + default_gateway + " METRIC 1";
        std::cerr << "VPN Service: Adding DNS bypass routes..." << std::endl;
        system(dns1_route_cmd.c_str());
        system(dns2_route_cmd.c_str());
      } else {
        std::cerr << "VPN Service: WARNING - Could not find default gateway for bypass route" << std::endl;
      }
    } else {
      std::cerr << "VPN Service: WARNING - Could not resolve server address" << std::endl;
    }
  } else {
    std::cerr << "VPN Service: WARNING - Could not extract server address from config" << std::endl;
  }
  
  // === Add Default Route ===
  // Route ALL traffic (0.0.0.0/0) through the TUN interface
  // This must come AFTER bypass routes to ensure specific routes take precedence
  std::string add_route_cmd = "netsh interface ip add route 0.0.0.0/0 \"flutter_vless_tun\" 10.0.85.1 metric=1";
  std::cerr << "VPN Service: Adding default route: " << add_route_cmd << std::endl;
  system(add_route_cmd.c_str());
  
  // Allow network stack to stabilize
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  
  // === Configure DNS Servers ===
  // Set DNS servers for the TUN interface to ensure name resolution works
  // Uses 'ipv4' explicitly and 'validate=no' to prevent validation errors
  // These DNS requests will go through the VPN tunnel (except for the DNS servers themselves,
  // which are bypassed via OS routes and Xray routing rules)
  std::string dns_cmd1 = "netsh interface ipv4 set dns name=\"flutter_vless_tun\" static 8.8.8.8 primary validate=no";
  std::string dns_cmd2 = "netsh interface ipv4 add dns name=\"flutter_vless_tun\" 1.1.1.1 index=2 validate=no";
  std::cerr << "VPN Service: Configuring DNS servers for TUN interface..." << std::endl;
  system(dns_cmd1.c_str());
  system(dns_cmd2.c_str());
  std::cerr << "VPN Service: DNS servers configured (8.8.8.8, 1.1.1.1)" << std::endl;
  
  std::cerr << "VPN Service: TUN interface configured and default route added" << std::endl;

  // Start stats thread
  stats_thread_ = std::thread(&VpnService::UpdateTrafficStats, this);

  // Monitor processes
  while (is_running_.load()) {
    if (xray_process_ && !xray_process_->IsRunning()) {
      std::cerr << "Xray process exited unexpectedly" << std::endl;
      flutter_vless::DiagnosticsLog::Instance().Append(
          "runtime", "Windows VPN Xray process exited unexpectedly");
      is_running_.store(false);
      break;
    }
    if (tun2socks_process_ && !tun2socks_process_->IsRunning()) {
      std::cerr << "Tun2Socks process exited unexpectedly" << std::endl;
      flutter_vless::DiagnosticsLog::Instance().Append(
          "runtime", "Windows VPN Tun2Socks process exited unexpectedly");
      is_running_.store(false);
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  
  StopProcesses();
}

bool VpnService::StartXrayProcess(const std::string& config_path) {
  if (xray_executable_path_.empty() || !fs::exists(xray_executable_path_)) {
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Windows VPN Xray executable is unavailable");
    return false;
  }
  xray_process_ = std::make_unique<ProcessHandle>();
  
  std::string command_line = "\"" + xray_executable_path_.string() + "\" -config \"" + config_path + "\"";
  std::vector<char> cmd_buffer(command_line.begin(), command_line.end());
  cmd_buffer.push_back('\0');
  
  // Create pipes to capture stdout and stderr
  HANDLE hChildStdOutRead = INVALID_HANDLE_VALUE;
  HANDLE hChildStdOutWrite = INVALID_HANDLE_VALUE;
  HANDLE hChildStdErrRead = INVALID_HANDLE_VALUE;
  HANDLE hChildStdErrWrite = INVALID_HANDLE_VALUE;

  SECURITY_ATTRIBUTES saAttr;
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  if (!CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &saAttr, 0)) {
    std::cerr << "VPN Service: Failed to create Xray stdout pipe" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to create Windows VPN Xray stdout pipe");
  } else {
    SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0);
  }

  if (!CreatePipe(&hChildStdErrRead, &hChildStdErrWrite, &saAttr, 0)) {
    std::cerr << "VPN Service: Failed to create Xray stderr pipe" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to create Windows VPN Xray stderr pipe");
  } else {
    SetHandleInformation(hChildStdErrRead, HANDLE_FLAG_INHERIT, 0);
  }
  
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = hChildStdOutWrite != INVALID_HANDLE_VALUE ? hChildStdOutWrite : GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = hChildStdErrWrite != INVALID_HANDLE_VALUE ? hChildStdErrWrite : GetStdHandle(STD_ERROR_HANDLE);
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  
  PROCESS_INFORMATION pi = {};
  
  std::string working_dir = xray_executable_path_.parent_path().string();
  
  // Set assets location env var if needed
  auto assets_dir = FindXrayAssets(xray_executable_path_);
  if (assets_dir && *assets_dir != xray_executable_path_.parent_path()) {
    SetEnvironmentVariableA("XRAY_LOCATION_ASSET", assets_dir->string().c_str());
  }

  if (!CreateProcessA(NULL, cmd_buffer.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, working_dir.c_str(), &si, &pi)) {
    const DWORD error = GetLastError();
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to create Windows VPN Xray process (Win32 error " +
                       std::to_string(error) + ")");
    if (hChildStdOutRead != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutRead);
    if (hChildStdOutWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutWrite);
    if (hChildStdErrRead != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrRead);
    if (hChildStdErrWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrWrite);
    return false;
  }
  
  // Close write ends in parent
  if (hChildStdOutWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutWrite);
  if (hChildStdErrWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrWrite);
  
  xray_process_->hProcess = reinterpret_cast<std::uintptr_t>(pi.hProcess);
  xray_process_->hThread = reinterpret_cast<std::uintptr_t>(pi.hThread);
  xray_process_->hStdOutRead = reinterpret_cast<std::uintptr_t>(hChildStdOutRead);
  xray_process_->hStdErrRead = reinterpret_cast<std::uintptr_t>(hChildStdErrRead);
  
  // Create threads to read stdout and stderr
  const auto xray_diagnostics_generation =
      flutter_vless::DiagnosticsLog::Instance().CurrentGeneration();
  auto reader = [xray_diagnostics_generation](std::uintptr_t readHandlePtr,
                                              const char* label) {
    HANDLE readHandle = reinterpret_cast<HANDLE>(readHandlePtr);
    if (readHandle == INVALID_HANDLE_VALUE || readHandle == nullptr) return;
    const DWORD bufSize = 4096;
    std::vector<char> buffer(bufSize);
    std::string pending;
    DWORD bytesRead = 0;
    while (true) {
      BOOL result = ReadFile(readHandle, buffer.data(), bufSize, &bytesRead, nullptr);
      if (!result || bytesRead == 0) break;
      const std::string chunk(buffer.data(), bytesRead);
      std::cerr << "[Xray " << label << "] " << chunk;
      pending.append(chunk);
      std::size_t newline = std::string::npos;
      while ((newline = pending.find('\n')) != std::string::npos) {
        flutter_vless::DiagnosticsLog::Instance().Append(
            xray_diagnostics_generation, std::string("xray-") + label,
            pending.substr(0, newline));
        pending.erase(0, newline + 1);
      }
      if (pending.size() > 32 * 1024) {
        std::size_t start = pending.size() - 16 * 1024;
        while (start < pending.size() &&
               (static_cast<unsigned char>(pending[start]) & 0xC0) == 0x80) {
          ++start;
        }
        pending.erase(0, start);
      }
    }
    if (!pending.empty()) {
      flutter_vless::DiagnosticsLog::Instance().Append(
          xray_diagnostics_generation, std::string("xray-") + label,
          pending);
    }
    CloseHandle(readHandle);
  };

  if (xray_process_->hStdOutRead != 0) {
    std::thread(reader, xray_process_->hStdOutRead, "stdout").detach();
    xray_process_->hStdOutRead = 0;
  }
  if (xray_process_->hStdErrRead != 0) {
    std::thread(reader, xray_process_->hStdErrRead, "stderr").detach();
    xray_process_->hStdErrRead = 0;
  }
  
  return true;
}

bool VpnService::StartTun2SocksProcess(uint16_t socks_port) {
  tun2socks_process_ = std::make_unique<ProcessHandle>();
  
  // Command: tun2socks.exe -device "flutter_vless_tun" -proxy socks5://127.0.0.1:<port>
  // Switching back to IPv4 (127.0.0.1) as [::1] seems to cause connection refused errors on some systems
  // Xray usually listens on 0.0.0.0 or 127.0.0.1 as well, or we can force it.
  std::string proxy_arg = "socks5://127.0.0.1:" + std::to_string(socks_port);
  std::string command_line = "\"" + tun2socks_executable_path_.string() + 
                              "\" -device \"flutter_vless_tun\"" +
                              " -proxy " + proxy_arg +
                              " -loglevel info";
  
  std::cerr << "VPN Service: Starting Tun2Socks with command: " << command_line << std::endl;
  
  std::vector<char> cmd_buffer(command_line.begin(), command_line.end());
  cmd_buffer.push_back('\0');
  
  // Create pipes to capture stdout and stderr
  HANDLE hChildStdOutRead = INVALID_HANDLE_VALUE;
  HANDLE hChildStdOutWrite = INVALID_HANDLE_VALUE;
  HANDLE hChildStdErrRead = INVALID_HANDLE_VALUE;
  HANDLE hChildStdErrWrite = INVALID_HANDLE_VALUE;

  SECURITY_ATTRIBUTES saAttr;
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  if (!CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &saAttr, 0)) {
    std::cerr << "VPN Service: Failed to create stdout pipe" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to create Windows Tun2Socks stdout pipe");
  } else {
    SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0);
  }

  if (!CreatePipe(&hChildStdErrRead, &hChildStdErrWrite, &saAttr, 0)) {
    std::cerr << "VPN Service: Failed to create stderr pipe" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to create Windows Tun2Socks stderr pipe");
  } else {
    SetHandleInformation(hChildStdErrRead, HANDLE_FLAG_INHERIT, 0);
  }
  
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = hChildStdOutWrite != INVALID_HANDLE_VALUE ? hChildStdOutWrite : GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = hChildStdErrWrite != INVALID_HANDLE_VALUE ? hChildStdErrWrite : GetStdHandle(STD_ERROR_HANDLE);
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  
  PROCESS_INFORMATION pi = {};
  
  // Tun2Socks needs admin rights
  if (!CreateProcessA(NULL, cmd_buffer.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    DWORD error = GetLastError();
    std::cerr << "VPN Service: Failed to launch tun2socks. Error code: " << error << std::endl;
    std::cerr << "VPN Service: Make sure the application is running as Administrator!" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to create Windows Tun2Socks process (Win32 error " +
                       std::to_string(error) +
                       "); administrator privileges may be required");
    
    if (hChildStdOutRead != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutRead);
    if (hChildStdOutWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutWrite);
    if (hChildStdErrRead != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrRead);
    if (hChildStdErrWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrWrite);
    return false;
  }
  
  // Close write ends in parent
  if (hChildStdOutWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutWrite);
  if (hChildStdErrWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrWrite);
  
  std::cerr << "VPN Service: Tun2Socks process started successfully (PID: " << pi.dwProcessId << ")" << std::endl;
  
  tun2socks_process_->hProcess = reinterpret_cast<std::uintptr_t>(pi.hProcess);
  tun2socks_process_->hThread = reinterpret_cast<std::uintptr_t>(pi.hThread);
  tun2socks_process_->hStdOutRead = reinterpret_cast<std::uintptr_t>(hChildStdOutRead);
  tun2socks_process_->hStdErrRead = reinterpret_cast<std::uintptr_t>(hChildStdErrRead);
  
  // Create threads to read stdout and stderr
  const auto tun_diagnostics_generation =
      flutter_vless::DiagnosticsLog::Instance().CurrentGeneration();
  auto reader = [tun_diagnostics_generation](std::uintptr_t readHandlePtr,
                                             const char* label) {
    HANDLE readHandle = reinterpret_cast<HANDLE>(readHandlePtr);
    if (readHandle == INVALID_HANDLE_VALUE || readHandle == nullptr) return;
    const DWORD bufSize = 4096;
    std::vector<char> buffer(bufSize);
    std::string pending;
    DWORD bytesRead = 0;
    while (true) {
      BOOL result = ReadFile(readHandle, buffer.data(), bufSize, &bytesRead, nullptr);
      if (!result || bytesRead == 0) break;
      const std::string chunk(buffer.data(), bytesRead);
      std::cerr << "[Tun2Socks " << label << "] " << chunk;
      pending.append(chunk);
      std::size_t newline = std::string::npos;
      while ((newline = pending.find('\n')) != std::string::npos) {
        flutter_vless::DiagnosticsLog::Instance().Append(
            tun_diagnostics_generation, std::string("tun2socks-") + label,
            pending.substr(0, newline));
        pending.erase(0, newline + 1);
      }
      if (pending.size() > 32 * 1024) {
        std::size_t start = pending.size() - 16 * 1024;
        while (start < pending.size() &&
               (static_cast<unsigned char>(pending[start]) & 0xC0) == 0x80) {
          ++start;
        }
        pending.erase(0, start);
      }
    }
    if (!pending.empty()) {
      flutter_vless::DiagnosticsLog::Instance().Append(
          tun_diagnostics_generation, std::string("tun2socks-") + label,
          pending);
    }
    CloseHandle(readHandle);
  };

  if (tun2socks_process_->hStdOutRead != 0) {
    std::thread(reader, tun2socks_process_->hStdOutRead, "stdout").detach();
    tun2socks_process_->hStdOutRead = 0;
  }
  if (tun2socks_process_->hStdErrRead != 0) {
    std::thread(reader, tun2socks_process_->hStdErrRead, "stderr").detach();
    tun2socks_process_->hStdErrRead = 0;
  }
  
  return true;
}

void VpnService::StopProcesses() {
  if (tun2socks_process_) {
    tun2socks_process_->Close();
    tun2socks_process_.reset();
  }
  if (xray_process_) {
    xray_process_->Close();
    xray_process_.reset();
  }
}

std::string VpnService::InjectApiConfig(const std::string& config) {
  return flutter_vless::xray_config::PrepareVpn(config).value_or("");
}

bool VpnService::RunXrayApiCommand(const std::string& args, std::string& output) {
  if (xray_executable_path_.empty()) return false;
  
  std::string command = "\"" + xray_executable_path_.string() + "\" " + args;
  
  // Create pipe for stdout
  HANDLE hRead, hWrite;
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  
  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return false;
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
  
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.hStdOutput = hWrite;
  si.hStdError = hWrite; // Capture stderr too
  si.wShowWindow = SW_HIDE;
  
  PROCESS_INFORMATION pi = {};
  
  std::vector<char> cmd_buf(command.begin(), command.end());
  cmd_buf.push_back('\0');
  
  if (!CreateProcessA(NULL, cmd_buf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(hRead);
    CloseHandle(hWrite);
    return false;
  }
  
  CloseHandle(hWrite); // Close write end in parent
  
  // Read output
  char buffer[4096];
  DWORD bytesRead;
  std::string result;
  
  while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
    buffer[bytesRead] = '\0';
    result += buffer;
  }
  
  CloseHandle(hRead);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  
  output = result;
  return true;
}

void VpnService::GetTrafficStats(int64_t& upload, int64_t& download) {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  upload = total_upload_;
  download = total_download_;
}

/**
 * @brief Periodically queries Xray API for traffic statistics.
 * 
 * @details This function runs in a dedicated thread and performs the following:
 * 1. Executes `xray api statsquery` command every second
 * 2. Parses the JSON response to extract upload/download bytes
 * 3. Updates cumulative statistics (thread-safe)
 * 
 * @details JSON Response Format:
 * ```json
 * {
 *   "stat": [
 *     { "name": "inbound>>>socks>>>traffic>>>uplink" },
 *     { "name": "inbound>>>socks>>>traffic>>>downlink" },
 *     { "name": "outbound>>>proxy>>>traffic>>>uplink", "value": 12345 },
 *     { "name": "outbound>>>proxy>>>traffic>>>downlink", "value": 67890 }
 *   ]
 * }
 * ```
 * 
 * @note CRITICAL: Some stat objects are missing the "value" field (when traffic is 0).
 * This is why we use robust object-by-object parsing instead of simple regex.
 * 
 * @details Parsing Strategy:
 * - Iterate through each JSON object in the "stat" array
 * - Extract "name" and "value" independently for each object
 * - Filter for "outbound>>>proxy>>>traffic>>>uplink" and "downlink"
 * - Accumulate values across all matching stats
 * 
 * @note This approach prevents mismatching values when some stats are missing.
 */
void VpnService::UpdateTrafficStats() {
  while (is_running_.load()) {
    std::string output;
    // Query Xray API: xray.exe api statsquery -server=127.0.0.1:10086
    std::string args = "api statsquery -server=" + api_address_;
    
    if (RunXrayApiCommand(args, output)) {
      // === Parse JSON manually (no external dependencies) ===
      // Expected format: { "stat": [ { "name": "...", "value": ... }, ... ] }
      
      int64_t new_uplink = 0;
      int64_t new_downlink = 0;
      
      // === Robust Object-by-Object Parsing ===
      // WHY: Simple regex can fail when "value" is missing in some objects
      // SOLUTION: Parse each object separately, matching name to value within the same object
      size_t stat_pos = output.find("\"stat\"");
      if (stat_pos != std::string::npos) {
        size_t array_start = output.find('[', stat_pos);
        if (array_start != std::string::npos) {
          size_t current_pos = array_start + 1;
          
          while (true) {
            // Find next object boundary
            size_t obj_start = output.find('{', current_pos);
            if (obj_start == std::string::npos) break;
            
            size_t obj_end = output.find('}', obj_start);
            if (obj_end == std::string::npos) break;
            
            // Extract this specific object
            std::string obj_str = output.substr(obj_start, obj_end - obj_start + 1);
            
            // Extract "name" field from this object
            std::string name;
            std::regex name_pattern("\"name\"\\s*:\\s*\"([^\"]+)\"");
            std::smatch name_match;
            if (std::regex_search(obj_str, name_match, name_pattern)) {
              name = name_match[1].str();
            }
            
            // Extract "value" field from this object (if present)
            int64_t value = 0;
            std::regex value_pattern("\"value\"\\s*:\\s*(\\d+)");
            std::smatch value_match;
            if (std::regex_search(obj_str, value_match, value_pattern)) {
              value = std::stoll(value_match[1].str());
            }
            
            // Accumulate proxy outbound stats
            if (!name.empty()) {
              if (name.find("outbound>>>proxy>>>traffic>>>uplink") != std::string::npos) {
                new_uplink += value;
              } else if (name.find("outbound>>>proxy>>>traffic>>>downlink") != std::string::npos) {
                new_downlink += value;
              }
            }
            
            current_pos = obj_end + 1;
          }
        }
      }
      
      // Update cumulative stats (thread-safe)
      {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        total_upload_ = new_uplink;
        total_download_ = new_downlink;
      }
    }
    
    // Poll every second
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

bool VpnService::WriteConfigToFile(const std::string& config, fs::path& config_path) {
  try {
    fs::path temp_dir = fs::temp_directory_path() / "flutter_vless_vpn";
    fs::create_directories(temp_dir);
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    config_path = temp_dir / ("vpn_config_" + std::to_string(timestamp) + ".json");
    std::ofstream file(config_path, std::ios::binary);
    if (!file.is_open()) return false;
    file << config;
    return true;
  } catch (...) { return false; }
}

std::optional<fs::path> VpnService::FindXrayExecutable() {
  // Simplified search logic
  std::vector<fs::path> search_paths = {
    fs::current_path() / "xray.exe",
    fs::current_path() / "xray" / "xray.exe",
    fs::current_path() / "windows" / "xray" / "xray.exe",
  };
  
  char exe_path[MAX_PATH];
  if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
    fs::path exe_dir = fs::path(exe_path).parent_path();
    search_paths.push_back(exe_dir / "xray.exe");
    search_paths.push_back(exe_dir / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "windows" / "xray" / "xray.exe");
  }
  
  for (const auto& path : search_paths) {
    if (fs::exists(path)) return path;
  }
  return std::nullopt;
  
}

std::optional<fs::path> VpnService::FindTun2SocksExecutable() {
  // Look for tun2socks.exe in similar locations to xray.exe
  std::vector<fs::path> search_paths = {
    fs::current_path() / "tun2socks.exe",
    fs::current_path() / "xray" / "tun2socks.exe",
    fs::current_path() / "windows" / "xray" / "tun2socks.exe",
  };
  
  char exe_path[MAX_PATH];
  if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
    fs::path exe_dir = fs::path(exe_path).parent_path();
    search_paths.push_back(exe_dir / "tun2socks.exe");
    search_paths.push_back(exe_dir / "xray" / "tun2socks.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "tun2socks.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "xray" / "tun2socks.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "windows" / "xray" / "tun2socks.exe");
  }
  
  for (const auto& path : search_paths) {
    if (fs::exists(path)) return path;
  }
  return std::nullopt;
}

std::optional<fs::path> VpnService::FindXrayAssets(const fs::path& executable_path) {
  fs::path exe_dir = executable_path.parent_path();
  if (fs::exists(exe_dir / "geoip.dat")) return exe_dir;
  return std::nullopt;
}

// Extract VPN server address from Xray config
std::string VpnService::ExtractServerAddress(const std::string& config) {
  auto normalize_address = [](std::string address) -> std::string {
    if (address.size() > 2 && address.front() == '[') {
      const size_t closing_bracket = address.find(']');
      if (closing_bracket != std::string::npos) {
        return address.substr(1, closing_bracket - 1);
      }
    }

    const size_t colon_count = static_cast<size_t>(
        std::count(address.begin(), address.end(), ':'));
    if (colon_count == 1) {
      const size_t colon = address.rfind(':');
      if (colon != std::string::npos && colon > 0) {
        return address.substr(0, colon);
      }
    }

    return address;
  };

  // Try multiple patterns to find server address
  std::vector<std::regex> patterns = {
    // Pattern 1: Look for "address" field in outbounds
    std::regex("\"outbounds\"[\\s\\S]{0,2000}?\"address\"\\s*:\\s*\"([^\"]+)\""),
    // Pattern 2: Look for protocol + address together
    std::regex("\"protocol\"\\s*:\\s*\"(?:vless|vmess|trojan|shadowsocks|hysteria)\"[\\s\\S]{0,1000}?\"address\"\\s*:\\s*\"([^\"]+)\""),
    // Pattern 3: Look in vnext array
    std::regex("\"vnext\"[\\s\\S]{0,1000}?\"address\"\\s*:\\s*\"([^\"]+)\""),
    // Pattern 4: Look in servers array
    std::regex("\"servers\"[\\s\\S]{0,1000}?\"address\"\\s*:\\s*\"([^\"]+)\""),
    // Pattern 5: WireGuard stores remote server as peer endpoint host:port
    std::regex("\"protocol\"\\s*:\\s*\"wireguard\"[\\s\\S]{0,2000}?\"endpoint\"\\s*:\\s*\"([^\"]+)\""),
  };
  
  std::smatch match;
  for (const auto& pattern : patterns) {
    if (std::regex_search(config, match, pattern)) {
      std::string address = normalize_address(match[1].str());
      // Skip localhost addresses
      if (address != "127.0.0.1" && address != "localhost" && address != "::1") {
        std::cerr << "VPN Service: Extracted server address: " << address << std::endl;
        return address;
      }
    }
  }
  
  std::cerr << "VPN Service: Could not extract remote server address" << std::endl;
  
  return "";
}

// Resolve domain to IP address
std::string VpnService::ResolveToIP(const std::string& address) {
  // Check if already an IP address
  std::regex ip_pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
  if (std::regex_match(address, ip_pattern)) {
    return address; // Already an IP
  }
  
  // Resolve domain name
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    return "";
  }
  
  struct addrinfo hints = {};
  struct addrinfo* result = nullptr;
  hints.ai_family = AF_INET; // IPv4
  hints.ai_socktype = SOCK_STREAM;
  
  if (getaddrinfo(address.c_str(), nullptr, &hints, &result) == 0 && result != nullptr) {
    struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
    std::string ip(ip_str);
    freeaddrinfo(result);
    WSACleanup();
    return ip;
  }
  
  if (result) freeaddrinfo(result);
  WSACleanup();
  return "";
}

// Get default gateway IP
std::string VpnService::GetDefaultGateway() {
  // Use ipconfig to get default gateway
  FILE* pipe = _popen("ipconfig", "r");
  if (!pipe) return "";
  
  char buffer[256];
  std::string result;
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  }
  _pclose(pipe);
  
  // Look for "Default Gateway" line
  std::regex gateway_pattern("Default Gateway[^:]*:[\\s]+(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
  std::smatch match;
  
  if (std::regex_search(result, match, gateway_pattern)) {
    return match[1].str();
  }
  
  return "";
}
