#include "proxy_service.h"
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

// JSON parsing helpers (copied from v2ray_manager.cpp)
namespace {
namespace json_utils {
  bool IsValidJson(const std::string& json_str) {
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

// ProcessHandle implementation
ProcessHandle::ProcessHandle() = default;

ProcessHandle::~ProcessHandle() {
  Close();
}

void ProcessHandle::Close() {
  if (hProcess != 0) {
    HANDLE hp = reinterpret_cast<HANDLE>(hProcess);
    if (hp != INVALID_HANDLE_VALUE) {
      TerminateProcess(hp, 0);
      CloseHandle(hp);
    }
    if (hThread != 0) {
      HANDLE ht = reinterpret_cast<HANDLE>(hThread);
      if (ht != INVALID_HANDLE_VALUE) CloseHandle(ht);
    }
    hProcess = 0;
    hThread = 0;
  }
  if (hStdOutRead != 0) {
    HANDLE hr = reinterpret_cast<HANDLE>(hStdOutRead);
    if (hr != INVALID_HANDLE_VALUE) CloseHandle(hr);
    hStdOutRead = 0;
  }
  if (hStdErrRead != 0) {
    HANDLE he = reinterpret_cast<HANDLE>(hStdErrRead);
    if (he != INVALID_HANDLE_VALUE) CloseHandle(he);
    hStdErrRead = 0;
  }
}

bool ProcessHandle::IsRunning() const {
  if (hProcess == 0) return false;
  HANDLE hp = reinterpret_cast<HANDLE>(hProcess);
  if (hp == INVALID_HANDLE_VALUE) return false;
  DWORD exit_code = 0;
  if (GetExitCodeProcess(hp, &exit_code)) {
    return exit_code == STILL_ACTIVE;
  }
  return false;
}

// Helper function to convert std::string to std::wstring
static std::wstring StringToWString(const std::string& str) {
  if (str.empty()) return std::wstring();
  int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
  if (size_needed <= 0) return std::wstring();
  std::wstring wstr(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
  wstr.resize(size_needed - 1); // Remove null terminator
  return wstr;
}

// ProxyService implementation

ProxyService::ProxyService() {
  xray_executable_path_ = FindXrayExecutable().value_or(fs::path());
}

ProxyService::~ProxyService() {
  Stop();
  CleanupTempFiles();
}

bool ProxyService::Start(const std::string& config, bool configure_system_proxy) {
  if (is_running_.load()) {
    Stop();
  }

  if (!ValidateConfig(config)) {
    std::cerr << "Invalid Xray configuration JSON" << std::endl;
    return false;
  }

  current_config_ = config;
  configure_system_proxy_ = configure_system_proxy;
  
  if (xray_executable_path_.empty()) {
    std::cerr << "Xray executable not found. Please ensure xray.exe is available." << std::endl;
    return false;
  }
  
  is_running_.store(true);
  v2ray_thread_ = std::thread(&ProxyService::RunV2ray, this);
  
  return true;
}

void ProxyService::Stop() {
  if (!is_running_.load()) {
    return;
  }

  is_running_.store(false);
  
  ClearSystemProxy();
  
  if (stats_thread_.joinable()) {
    stats_thread_.join();
  }
  
  if (v2ray_thread_.joinable()) {
    v2ray_thread_.join();
  }
  
  StopXrayProcess();
  CleanupTempFiles();

  std::lock_guard<std::mutex> lock(stats_mutex_);
  total_upload_ = 0;
  total_download_ = 0;
  upload_speed_ = 0;
  download_speed_ = 0;
}

bool ProxyService::IsRunning() const {
  return is_running_.load();
}

void ProxyService::RunV2ray() {
  // Proxy mode: configuration remains unchanged
  std::string modified_config = current_config_;
  
  fs::path config_path;
  if (!WriteConfigToFile(modified_config, config_path)) {
    std::cerr << "Failed to write Xray configuration file" << std::endl;
    is_running_.store(false);
    return;
  }
  
  temp_config_path_ = config_path;
  
  if (!StartXrayProcess(config_path.string())) {
    std::cerr << "Failed to start Xray process" << std::endl;
    is_running_.store(false);
    CleanupTempFiles();
    return;
  }
  
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  
  {
    std::string config_str;
    std::ifstream config_in(config_path);
    if (config_in.is_open()) {
      std::stringstream buffer;
      buffer << config_in.rdbuf();
      config_str = buffer.str();
    } else {
      config_str = modified_config;
      std::cerr << "Warning: Failed to read actual config file, using original" << std::endl;
    }

    uint16_t socks_port = 10807;
    
    std::regex in_proxy_pattern("\"tag\"\\s*:\\s*\"in_proxy\"[\\s\\S]*?\"port\"\\s*:\\s*(\\d+)");
    std::smatch match;
    if (std::regex_search(config_str, match, in_proxy_pattern)) {
      socks_port = static_cast<uint16_t>(std::stoi(match[1].str()));
    } else {
      std::regex socks_pattern("\"protocol\"\\s*:\\s*\"socks\"[\\s\\S]*?\"port\"\\s*:\\s*(\\d+)");
      if (std::regex_search(config_str, match, socks_pattern)) {
        socks_port = static_cast<uint16_t>(std::stoi(match[1].str()));
      } else {
        std::regex port_pattern("\"inbounds\"[\\s\\S]*?\"port\"\\s*:\\s*(\\d+)");
        if (std::regex_search(config_str, match, port_pattern)) {
          socks_port = static_cast<uint16_t>(std::stoi(match[1].str()));
        }
      }
    }
    
    if (configure_system_proxy_) {
      if (!SetSystemProxy("localhost", socks_port)) {
        std::cerr << "Warning: Failed to set system proxy. Proxy mode may not work correctly." << std::endl;
      } else {
        std::cerr << "System proxy set to localhost:" << socks_port << std::endl;
      }
    }
  }
  
  if (!InitializeApiClient()) {
    std::cerr << "Warning: Failed to initialize Xray API client. Stats may not be available." << std::endl;
  }
  
  start_time_ = std::chrono::steady_clock::now();
  
  stats_thread_ = std::thread([this]() {
    while (is_running_.load()) {
      UpdateTrafficStats();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  });
  
  while (is_running_.load()) {
    if (xray_process_ && !xray_process_->IsRunning()) {
      std::cerr << "Xray process terminated unexpectedly" << std::endl;
      is_running_.store(false);
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

bool ProxyService::StartXrayProcess(const std::string& config_path) {
  if (xray_executable_path_.empty() || !fs::exists(xray_executable_path_)) {
    return false;
  }

  try {
    ReplacePortsInConfigFile(fs::path(config_path));
    if (auto detected = DetectApiAddressInConfig(fs::path(config_path))) {
      api_address_ = *detected;
      std::cerr << "Detected Xray API address: " << api_address_ << std::endl;
    }
  } catch (...) {}
  
  xray_process_ = std::make_unique<ProcessHandle>();
  
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;

  SECURITY_ATTRIBUTES saAttr;
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  HANDLE hChildStdOutRead = INVALID_HANDLE_VALUE;
  HANDLE hChildStdOutWrite = INVALID_HANDLE_VALUE;
  HANDLE hChildStdErrRead = INVALID_HANDLE_VALUE;
  HANDLE hChildStdErrWrite = INVALID_HANDLE_VALUE;

  if (!CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &saAttr, 0)) {
    std::cerr << "Failed to create stdout pipe" << std::endl;
  } else {
    SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0);
  }

  if (!CreatePipe(&hChildStdErrRead, &hChildStdErrWrite, &saAttr, 0)) {
    std::cerr << "Failed to create stderr pipe" << std::endl;
  } else {
    SetHandleInformation(hChildStdErrRead, HANDLE_FLAG_INHERIT, 0);
  }

  si.hStdOutput = hChildStdOutWrite != INVALID_HANDLE_VALUE ? hChildStdOutWrite : GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = hChildStdErrWrite != INVALID_HANDLE_VALUE ? hChildStdErrWrite : GetStdHandle(STD_ERROR_HANDLE);
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  
  std::string command_line = "\"" + xray_executable_path_.string() + "\" -config \"" + config_path + "\"";
  std::vector<char> cmd_buffer(command_line.begin(), command_line.end());
  cmd_buffer.push_back('\0');
  
  PROCESS_INFORMATION pi = {};
  
  std::string working_dir = xray_executable_path_.parent_path().string();
  
  auto assets_dir = FindXrayAssets(xray_executable_path_);
  if (assets_dir) {
    std::cerr << "Found Xray assets at: " << *assets_dir << std::endl;
    if (*assets_dir != xray_executable_path_.parent_path()) {
      std::string assets_path_str = assets_dir->string();
      SetEnvironmentVariableA("XRAY_LOCATION_ASSET", assets_path_str.c_str());
    }
  }
  
  BOOL success = CreateProcessA(
    nullptr,
    cmd_buffer.data(),
    nullptr,
    nullptr,
    TRUE,
    CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
    nullptr,
    working_dir.c_str(),
    &si,
    &pi
  );
  
  if (!success) {
    DWORD error = GetLastError();
    std::cerr << "Failed to start Xray process. Error: " << error << std::endl;
    if (hChildStdOutRead != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutRead);
    if (hChildStdOutWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdOutWrite);
    if (hChildStdErrRead != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrRead);
    if (hChildStdErrWrite != INVALID_HANDLE_VALUE) CloseHandle(hChildStdErrWrite);
    xray_process_.reset();
    return false;
  }
  
  if (hChildStdOutWrite != INVALID_HANDLE_VALUE) {
    CloseHandle(hChildStdOutWrite);
    hChildStdOutWrite = INVALID_HANDLE_VALUE;
  }
  if (hChildStdErrWrite != INVALID_HANDLE_VALUE) {
    CloseHandle(hChildStdErrWrite);
    hChildStdErrWrite = INVALID_HANDLE_VALUE;
  }

  xray_process_->hProcess = reinterpret_cast<std::uintptr_t>(pi.hProcess);
  xray_process_->hThread = reinterpret_cast<std::uintptr_t>(pi.hThread);
  xray_process_->hStdOutRead = reinterpret_cast<std::uintptr_t>(hChildStdOutRead);
  xray_process_->hStdErrRead = reinterpret_cast<std::uintptr_t>(hChildStdErrRead);

  auto reader = [](std::uintptr_t readHandlePtr, const char* label) {
    HANDLE readHandle = reinterpret_cast<HANDLE>(readHandlePtr);
    if (readHandle == INVALID_HANDLE_VALUE || readHandle == nullptr) return;
    const DWORD bufSize = 4096;
    std::vector<char> buffer(bufSize + 1);
    DWORD bytesRead = 0;
    while (true) {
      BOOL result = ReadFile(readHandle, buffer.data(), bufSize, &bytesRead, nullptr);
      if (!result || bytesRead == 0) break;
      buffer[bytesRead] = '\0';
      std::cerr << "[Xray " << label << "] " << buffer.data();
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

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  if (!xray_process_->IsRunning()) {
    xray_process_->Close();
    xray_process_.reset();
    return false;
  }

  return true;
}

void ProxyService::StopXrayProcess() {
  if (xray_process_) {
    xray_process_->Close();
    xray_process_.reset();
  }
  api_client_.reset();
}

bool ProxyService::WriteConfigToFile(const std::string& config, fs::path& config_path) {
  try {
    fs::path temp_dir = fs::temp_directory_path() / "flutter_vless";
    fs::create_directories(temp_dir);
    
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
      now.time_since_epoch()).count();
    
    config_path = temp_dir / ("xray_config_" + std::to_string(timestamp) + ".json");
    
    std::ofstream file(config_path, std::ios::binary);
    if (!file.is_open()) {
      return false;
    }
    
    file << config;
    file.close();
    
    return true;
  } catch (const std::exception& e) {
    std::cerr << "Error writing config file: " << e.what() << std::endl;
    return false;
  }
}

bool ProxyService::InitializeApiClient() {
  if (!api_client_) {
    api_client_ = std::make_unique<ApiClient>();
  }
  
  api_client_->service_ = this;
  
  size_t colon_pos = api_address_.find(':');
  if (colon_pos != std::string::npos) {
    api_client_->api_address_ = api_address_.substr(0, colon_pos);
    try {
      api_client_->api_port_ = std::stoi(api_address_.substr(colon_pos + 1));
    } catch (...) {
      api_client_->api_port_ = 10085;
    }
  } else {
    api_client_->api_address_ = api_address_;
    api_client_->api_port_ = 10085;
  }
  
  return true;
}

void ProxyService::UpdateTrafficStats() {
  if (!api_client_) return;
  
  std::map<std::string, int64_t> stats;
  if (!api_client_->GetStats(stats)) return;
  
  std::lock_guard<std::mutex> lock(stats_mutex_);
  
  int64_t new_upload = 0;
  int64_t new_download = 0;
  
  for (const auto& [key, value] : stats) {
    if (key.find("uplink") != std::string::npos) {
      new_upload += value;
    } else if (key.find("downlink") != std::string::npos) {
      new_download += value;
    }
  }
  
  upload_speed_ = new_upload - total_upload_;
  download_speed_ = new_download - total_download_;
  total_upload_ = new_upload;
  total_download_ = new_download;
}

void ProxyService::GetTrafficStats(int64_t& upload, int64_t& download) {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  upload = total_upload_;
  download = total_download_;
}

int ProxyService::GetServerDelay(const std::string& url) {
  if (!api_client_) return -1;
  return api_client_->MeasureDelay(url);
}

int ProxyService::MeasureDelayStateless(const std::string& config, const std::string& url) {
  if (!ValidateConfig(config)) {
    return -1;
  }
  
  fs::path temp_config;
  if (!WriteConfigToFile(config, temp_config)) {
    return -1;
  }
  
  auto temp_process = std::make_unique<ProcessHandle>();
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  
  std::string command_line = "\"" + xray_executable_path_.string() + "\" -config \"" + temp_config.string() + "\"";
  
  PROCESS_INFORMATION pi = {};
  BOOL success = CreateProcessA(
    nullptr,
    const_cast<char*>(command_line.c_str()),
    nullptr,
    nullptr,
    FALSE,
    CREATE_NO_WINDOW,
    nullptr,
    nullptr,
    &si,
    &pi
  );
  
  if (!success) {
    fs::remove(temp_config);
    return -1;
  }
  
  temp_process->hProcess = reinterpret_cast<std::uintptr_t>(pi.hProcess);
  temp_process->hThread = reinterpret_cast<std::uintptr_t>(pi.hThread);
  
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  
  auto temp_api = std::make_unique<ApiClient>();
  temp_api->service_ = this;
  
  // Need to detect the port from the config we just wrote
  if (auto detected = DetectApiAddressInConfig(temp_config)) {
      std::string addr = *detected;
      size_t colon = addr.find(':');
      if (colon != std::string::npos) {
          temp_api->api_address_ = addr.substr(0, colon);
          try {
              temp_api->api_port_ = std::stoi(addr.substr(colon + 1));
          } catch(...) { temp_api->api_port_ = 10085; }
      } else {
          temp_api->api_address_ = addr;
          temp_api->api_port_ = 10085;
      }
  } else {
      // Fallback to default
      temp_api->api_address_ = "127.0.0.1";
      temp_api->api_port_ = 10085;
  }

  auto start = std::chrono::steady_clock::now();
  int delay = temp_api->MeasureDelay(url);
  auto end = std::chrono::steady_clock::now();
  
  temp_process->Close();
  fs::remove(temp_config);
  
  if (delay < 0) {
    return -1;
  }
  
  auto overhead_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  return delay + static_cast<int>(overhead_ms);
}

std::string ProxyService::GetCoreVersion() {
  if (api_client_) {
    std::string version = api_client_->GetVersion();
    if (!version.empty()) return version;
  }
  
  if (!xray_executable_path_.empty() && fs::exists(xray_executable_path_)) {
    std::string command = "\"" + xray_executable_path_.string() + "\" -version";
    FILE* pipe = _popen(command.c_str(), "r");
    if (pipe != nullptr) {
      char buffer[128];
      std::string result = "";
      while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
      }
      _pclose(pipe);
      
      std::regex version_pattern(R"(Xray\s+(\d+\.\d+\.\d+))");
      std::smatch match;
      if (std::regex_search(result, match, version_pattern)) {
        return match[1].str();
      }
    }
  }
  return "Unknown";
}

bool ProxyService::SetSystemProxy(const std::string& proxy_address, uint16_t proxy_port) {
  try {
    std::string proxy_string = "socks=" + proxy_address + ":" + std::to_string(proxy_port);
    std::wstring proxy_wstring = StringToWString(proxy_string);
    
    std::string bypass_str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*";
    std::wstring bypass_wstring = StringToWString(bypass_str);
    
    proxy_server_buf_.clear();
    proxy_server_buf_.resize((proxy_wstring.length() + 1) * sizeof(wchar_t));
    memcpy(proxy_server_buf_.data(), proxy_wstring.c_str(), proxy_server_buf_.size());
    
    proxy_bypass_buf_.clear();
    proxy_bypass_buf_.resize((bypass_wstring.length() + 1) * sizeof(wchar_t));
    memcpy(proxy_bypass_buf_.data(), bypass_wstring.c_str(), proxy_bypass_buf_.size());
    
    INTERNET_PER_CONN_OPTION_LISTW option_list;
    INTERNET_PER_CONN_OPTIONW options[3];
    DWORD dwBufSize = sizeof(INTERNET_PER_CONN_OPTION_LISTW);
    
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT;
    
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = reinterpret_cast<LPWSTR>(proxy_server_buf_.data());
    
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = reinterpret_cast<LPWSTR>(proxy_bypass_buf_.data());
    
    option_list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LISTW);
    option_list.pszConnection = nullptr;
    option_list.dwOptionCount = 3;
    option_list.dwOptionError = 0;
    option_list.pOptions = options;
    
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &option_list, dwBufSize)) {
      return false;
    }
    
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    
    return true;
  } catch (...) {
    return false;
  }
}

bool ProxyService::ClearSystemProxy() {
  try {
    INTERNET_PER_CONN_OPTION_LISTW option_list;
    INTERNET_PER_CONN_OPTIONW options[1];
    DWORD dwBufSize = sizeof(INTERNET_PER_CONN_OPTION_LISTW);
    
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_DIRECT;
    
    option_list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LISTW);
    option_list.pszConnection = nullptr;
    option_list.dwOptionCount = 1;
    option_list.dwOptionError = 0;
    option_list.pOptions = options;
    
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &option_list, dwBufSize)) {
      return false;
    }
    
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    
    return true;
  } catch (...) {
    return false;
  }
}

std::optional<fs::path> ProxyService::FindXrayExecutable() {
  std::vector<fs::path> search_paths = {
    fs::current_path() / "xray.exe",
    fs::current_path() / "xray" / "xray.exe",
    fs::current_path() / "windows" / "xray" / "xray.exe",
    fs::current_path() / "example" / "windows" / "xray" / "xray.exe",
    fs::current_path().parent_path() / "xray.exe",
    fs::current_path().parent_path() / "xray" / "xray.exe",
    fs::current_path().parent_path() / "windows" / "xray" / "xray.exe",
  };
  
  char appdata_path[MAX_PATH];
  if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appdata_path) == S_OK) {
    search_paths.push_back(fs::path(appdata_path) / "flutter_vless" / "xray.exe");
  }
  
  char program_files[MAX_PATH];
  if (SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILES, nullptr, SHGFP_TYPE_CURRENT, program_files) == S_OK) {
    search_paths.push_back(fs::path(program_files) / "Xray" / "xray.exe");
  }
  
  char exe_path[MAX_PATH];
  if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
    fs::path exe_dir = fs::path(exe_path).parent_path();
    search_paths.push_back(exe_dir / "xray.exe");
    search_paths.push_back(exe_dir / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "assets" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "assets" / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "windows" / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "data" / "flutter_assets" / "windows" / "runner" / "xray" / "xray.exe");
    search_paths.push_back(exe_dir / "windows" / "xray" / "xray.exe");
  }
  
  for (const auto& path : search_paths) {
    if (fs::exists(path) && fs::is_regular_file(path)) {
      std::cerr << "Found Xray executable: " << path << std::endl;
      return path;
    }
  }
  
  return std::nullopt;
}

std::optional<fs::path> ProxyService::FindXrayAssets(const fs::path& executable_path) {
  const std::string geoip = "geoip.dat";
  
  fs::path exe_dir = executable_path.parent_path();
  if (fs::exists(exe_dir / geoip)) {
    return exe_dir;
  }
  
  if (fs::exists(fs::current_path() / geoip)) {
    return fs::current_path();
  }
  
  char app_path_buffer[MAX_PATH];
  if (GetModuleFileNameA(nullptr, app_path_buffer, MAX_PATH) > 0) {
    fs::path app_dir = fs::path(app_path_buffer).parent_path();
    fs::path assets_dir = app_dir / "data" / "flutter_assets";
    if (fs::exists(assets_dir / geoip)) return assets_dir;
    if (fs::exists(assets_dir / "assets" / geoip)) return assets_dir / "assets";
    if (fs::exists(assets_dir / "xray" / geoip)) return assets_dir / "xray";
    if (fs::exists(assets_dir / "assets" / "xray" / geoip)) return assets_dir / "assets" / "xray";
    if (fs::exists(assets_dir / "windows" / "xray" / geoip)) return assets_dir / "windows" / "xray";
  }
  
  return std::nullopt;
}

bool ProxyService::ValidateConfig(const std::string& config) {
  return json_utils::IsValidJson(config);
}

void ProxyService::CleanupTempFiles() {
  try {
    if (!temp_config_path_.empty() && fs::exists(temp_config_path_)) {
      fs::remove(temp_config_path_);
    }
  } catch (...) {}
}

bool ProxyService::IsPortFree(uint16_t port) {
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    WSACleanup();
    return false;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  if (InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    WSACleanup();
    return false;
  }
  addr.sin_port = htons(port);
  int result = bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  closesocket(s);
  WSACleanup();
  return result == 0;
}

uint16_t ProxyService::FindFreePort() {
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 0;
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    WSACleanup();
    return 0;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  if (InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    WSACleanup();
    return 0;
  }
  addr.sin_port = htons(0);
  if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    closesocket(s);
    WSACleanup();
    return 0;
  }
  sockaddr_in assigned{};
  int len = sizeof(assigned);
  if (getsockname(s, reinterpret_cast<sockaddr*>(&assigned), &len) != 0) {
    closesocket(s);
    WSACleanup();
    return 0;
  }
  uint16_t port = ntohs(assigned.sin_port);
  closesocket(s);
  WSACleanup();
  return port;
}

/**
 * @brief Modifies the Xray configuration file to ensure ports are free and API is enabled.
 * 
 * @details Port Conflict Resolution:
 * Scans the configuration for "port" and "listen" fields. If a configured port is
 * already in use on the system, it replaces it with a free ephemeral port.
 * 
 * @details API Injection Strategy:
 * The Xray API is required for statistics and control. This function injects the
 * "api" configuration block if it's missing.
 * 
 * CRITICAL: The injection position is vital for valid JSON.
 * 1. It attempts to find the "log" section and insert the "api" block *after* it.
 *    This is the most reliable location in standard Xray configs.
 * 2. It handles comma insertion correctly to ensure the resulting JSON is valid.
 * 3. It uses the "listen" field (e.g., "127.0.0.1:10085") which is the standard
 *    way to configure the API address in recent Xray versions.
 * 
 * @param config_path Path to the configuration file to modify.
 * @return true if modification was successful (or unnecessary), false on error.
 */
bool ProxyService::ReplacePortsInConfigFile(const fs::path& config_path) {
  if (!fs::exists(config_path)) return false;
  std::ifstream ifs(config_path);
  if (!ifs.is_open()) return false;
  std::stringstream ss;
  ss << ifs.rdbuf();
  std::string content = ss.str();
  ifs.close();

  bool modified = false;
  std::regex port_key_pattern("\"port\"\\s*:\\s*(\\d+)");
  std::smatch match;
  std::string new_content = content;
  auto search_start = new_content.cbegin();
  
  while (std::regex_search(search_start, new_content.cend(), match, port_key_pattern)) {
    int port = std::stoi(match[1].str());
    if (port >= 1 && port <= 65535) {
      if (!IsPortFree(static_cast<uint16_t>(port))) {
        uint16_t free_port = FindFreePort();
        if (free_port != 0) {
          auto pos = match.position(1) + (search_start - new_content.cbegin());
          new_content.replace(pos, match[1].length(), std::to_string(free_port));
          modified = true;
          search_start = new_content.cbegin() + pos + std::to_string(free_port).length();
          continue;
        }
      }
    }
    search_start = match.suffix().first;
  }

  std::regex listen_ip_pattern("127\\.0\\.0\\.1\\s*:\\s*(\\d+)");
  search_start = new_content.cbegin();
  while (std::regex_search(search_start, new_content.cend(), match, listen_ip_pattern)) {
    int port = std::stoi(match[1].str());
    if (port >= 1 && port <= 65535) {
      if (!IsPortFree(static_cast<uint16_t>(port))) {
        uint16_t free_port = FindFreePort();
        if (free_port != 0) {
          auto pos = match.position(1) + (search_start - new_content.cbegin());
          new_content.replace(pos, match[1].length(), std::to_string(free_port));
          modified = true;
          search_start = new_content.cbegin() + pos + std::to_string(free_port).length();
          continue;
        }
      }
    }
    search_start = match.suffix().first;
  }

  if (modified) {
    std::ofstream ofs(config_path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs << new_content;
    ofs.close();
  }

  if (new_content.find("\"stats\"") == std::string::npos) {
    size_t first_brace = new_content.find('{');
    if (first_brace != std::string::npos) {
      new_content.insert(first_brace + 1, "\n  \"stats\": {},");
      modified = true;
    }
  }

  if (new_content.find("\"policy\"") == std::string::npos) {
    size_t first_brace = new_content.find('{');
    if (first_brace != std::string::npos) {
      std::string policy_block = "\n  \"policy\": {\n    \"system\": {\n      \"statsInboundUplink\": true,\n      \"statsInboundDownlink\": true,\n      \"statsOutboundUplink\": true,\n      \"statsOutboundDownlink\": true\n    }\n  },";
      new_content.insert(first_brace + 1, policy_block);
      modified = true;
    }
  }

  if (modified) {
    std::ofstream ofs(config_path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs << new_content;
    ofs.close();
  }

  std::regex api_key_re("\"api\"\\s*:\\s*");
  if (!std::regex_search(new_content, api_key_re)) {
    uint16_t api_port = 10085;
    if (!IsPortFree(api_port)) {
      uint16_t p = FindFreePort();
      if (p != 0) api_port = p;
    }

    // Strategy: Find the position after the "log" section closes.
    // Then insert the api block with a comma separator between them.
    size_t insert_pos = std::string::npos;
    
    // Look for the pattern: "log" : { ... } (with proper brace matching)
    std::regex log_start_re("\"log\"\\s*:\\s*\\{");
    std::smatch m;
    if (std::regex_search(new_content, m, log_start_re)) {
      // Found "log" section start. Now find the matching closing brace.
      size_t brace_start = m.position(0) + m.length(0) - 1;  // position of '{'
      int depth = 1;
      size_t pos = brace_start + 1;
      bool in_string = false;
      bool escaped = false;
      
      while (pos < new_content.length() && depth > 0) {
        char c = new_content[pos];
        if (escaped) {
          escaped = false;
          pos++;
          continue;
        }
        if (c == '\\') {
          escaped = true;
          pos++;
          continue;
        }
        if (c == '"') {
          in_string = !in_string;
        }
        if (!in_string) {
          if (c == '{') depth++;
          else if (c == '}') depth--;
        }
        pos++;
      }
      
      if (depth == 0) {
        // pos is now one position after the closing brace of "log"
        // Consume any whitespace after the closing brace
        while (pos < new_content.length() && 
               (new_content[pos] == ' ' || new_content[pos] == '\n' || 
                new_content[pos] == '\r' || new_content[pos] == '\t')) {
          pos++;
        }
        insert_pos = pos;
      }
    }
    
    // Fallback: if no "log" section found, insert after root opening brace
    if (insert_pos == std::string::npos) {
      auto brace_pos = new_content.find('{');
      if (brace_pos != std::string::npos) {
        insert_pos = brace_pos + 1;
      }
    }

    if (insert_pos != std::string::npos) {
      // Create a proper api block with leading comma separator
      // Use the modern format with "listen" instead of separate "address" and "port"
      std::ostringstream api_block;
      api_block << ",\n  \"api\": {\n";
      api_block << "    \"tag\": \"api\",\n";
      api_block << "    \"listen\": \"127.0.0.1:" << api_port << "\",\n";
      api_block << "    \"services\": [\"HandlerService\", \"StatsService\", \"LoggerService\"]\n";
      api_block << "  }";

      new_content.insert(insert_pos, api_block.str());
      
      // Write back
      std::ofstream ofs2(config_path, std::ios::binary | std::ios::trunc);
      if (ofs2.is_open()) {
        ofs2 << new_content;
        ofs2.close();
        api_address_ = std::string("127.0.0.1:") + std::to_string(api_port);
      }
    }
  }

  return true;
}

std::optional<std::string> ProxyService::DetectApiAddressInConfig(const fs::path& config_path) {
  try {
    std::ifstream in(config_path.string());
    if (!in) return std::nullopt;
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    std::regex api_re("\"api\"\\s*:\\s*\\{([\\s\\S]*?)\\}", std::regex_constants::icase);
    std::smatch api_match;
    if (!std::regex_search(s, api_match, api_re)) return std::nullopt;

    std::string api_body = api_match[1].str();

    // Try to find "listen": "..."
    std::regex listen_re("\"listen\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch listen_match;
    if (std::regex_search(api_body, listen_match, listen_re)) {
      return listen_match[1].str();
    }

    std::regex addr_re("\"address\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch addr_match;
    std::string address;
    if (std::regex_search(api_body, addr_match, addr_re)) {
      address = addr_match[1].str();
    }

    std::regex port_re("\"port\"\\s*:\\s*(\\d+)");
    std::smatch port_match;
    std::string port;
    if (std::regex_search(api_body, port_match, port_re)) {
      port = port_match[1].str();
    }

    if (!address.empty() && !port.empty()) {
      if (address.find(':') != std::string::npos) return address;
      return address + ":" + port;
    }

    if (!address.empty()) return address;
    if (!port.empty()) return std::string("127.0.0.1:") + port;

    return std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}

/**
 * @brief Retrieves traffic statistics from Xray API.
 * 
 * @param stats Output map of statistic names to values.
 * 
 * @return true if statistics were retrieved successfully, false otherwise.
 * 
 * @details Statistics Format:
 * Xray returns statistics in format:
 * "inbound>>>tag>>>traffic>>>uplink" and "inbound>>>tag>>>traffic>>>downlink"
 * 
 * The function parses these and aggregates upload/download totals.
 * 
 * @warning CRITICAL: This function relies on the specific JSON output format of
 *          `xray api statsquery`. If Xray changes its output format, this parser
 *          may need to be updated. The parser manually extracts "name" and "value"
 *          fields to avoid heavy JSON library dependencies.
 */
bool ApiClient::GetStats(std::map<std::string, int64_t>& stats) {
  // std::cerr << "GetStats: entry" << std::endl;
  if (!service_) {
    // std::cerr << "GetStats: service is null" << std::endl;
    return false;
  }

  std::string output;
  // Use "api statsquery" to get all stats. 
  // -s specifies the API server address.
  // -pattern "" matches everything.
  std::string args = "api statsquery -s " + api_address_ + ":" + std::to_string(api_port_) + " -pattern \"\"";
  
  // std::cerr << "GetStats: calling RunXrayApiCommand" << std::endl;
  if (!RunXrayApiCommand(args, output)) {
    // std::cerr << "GetStats: RunXrayApiCommand failed" << std::endl;
    return false;
  }

  // Log raw stats for debugging as requested
  // std::cerr << "Raw stats output:\n" << output << std::endl;

  // Parse JSON output line by line
  std::istringstream iss(output);
  std::string line;
  std::string current_name;
  int64_t current_value = 0;
  
  while (std::getline(iss, line)) {
    // Look for "name": "..."
    size_t name_pos = line.find("\"name\"");
    if (name_pos != std::string::npos) {
      size_t colon = line.find(':', name_pos);
      if (colon != std::string::npos) {
        size_t start_quote = line.find('"', colon + 1);
        if (start_quote != std::string::npos) {
           size_t end_quote = line.find('"', start_quote + 1);
           if (end_quote != std::string::npos) {
             current_name = line.substr(start_quote + 1, end_quote - start_quote - 1);
             current_value = 0; // Reset value for new entry
           }
        }
      }
    }
    
    // Look for "value": ...
    size_t value_pos = line.find("\"value\"");
    if (value_pos != std::string::npos) {
      size_t colon = line.find(':', value_pos);
      if (colon != std::string::npos) {
        std::string val_str = line.substr(colon + 1);
        // Remove trailing comma if present
        size_t comma = val_str.find(',');
        if (comma != std::string::npos) {
          val_str = val_str.substr(0, comma);
        }
        try {
          current_value = std::stoll(val_str);
        } catch (...) {
          current_value = 0;
        }
      }
    }
    
    // Look for closing brace of an object
    if (line.find('}') != std::string::npos) {
      if (!current_name.empty()) {
        stats[current_name] = current_value;
        current_name.clear();
        current_value = 0;
      }
    }
  }
  
  // std::cerr << "Parsed stats count: " << stats.size() << std::endl;
  return true;
}

int ApiClient::MeasureDelay(const std::string& url) {
  return -1; 
}

std::string ApiClient::GetVersion() {
  if (!service_) return "";
  
  std::string output;
  if (RunXrayApiCommand("version", output)) {
    std::istringstream iss(output);
    std::string line;
    if (std::getline(iss, line)) {
      return line;
    }
  }
  return "";
}

/**
 * @brief Executes an Xray API command with timeout and non-blocking I/O.
 * 
 * @details Deadlock Prevention:
 * This function uses a non-blocking read loop with a strict timeout to prevent
 * deadlocks. Standard ReadFile() is blocking; if the Xray process hangs or
 * doesn't output data (e.g., zombie process), a blocking read would hang
 * the stats thread indefinitely.
 * 
 * Implementation Strategy:
 * 1. PeekNamedPipe: Checks if data is available in the pipe without removing it.
 * 2. Conditional ReadFile: ONLY calls ReadFile if bytes are actually available.
 *    - Reads only the available amount (min(buffer, available)) to ensure
 *      ReadFile returns immediately.
 * 3. Timeout Loop: Enforces a hard timeout (3 seconds). If the command doesn't
 *    complete, the process is terminated to free the thread.
 * 
 * @warning IMPORTANT: Do not use `_popen` or blocking `ReadFile` here. They have
 *          caused application freezes in the past when Xray becomes unresponsive.
 *          The current `CreateProcess` + `PeekNamedPipe` approach is robust.
 * 
 * @param args The command line arguments for the API call.
 * @param output String to store the command output.
 * @return true if command executed successfully, false on error or timeout.
 */
bool ApiClient::RunXrayApiCommand(const std::string& args, std::string& output) {
  if (!service_) {
    // std::cerr << "RunXrayApiCommand failed: service is null" << std::endl;
    return false;
  }
  
  fs::path xray_path = service_->xray_executable_path_;
  if (xray_path.empty() || !fs::exists(xray_path)) {
    // std::cerr << "RunXrayApiCommand failed: xray path invalid: " << xray_path << std::endl;
    return false;
  }

  std::string command_line = "\"" + xray_path.string() + "\" " + args;
  
  // Create pipe for stdout
  HANDLE hRead, hWrite;
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
    // std::cerr << "RunXrayApiCommand failed: CreatePipe error " << GetLastError() << std::endl;
    return false;
  }
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.hStdOutput = hWrite;
  si.hStdError = hWrite; // Capture stderr too
  si.wShowWindow = SW_HIDE; // Hide the console window

  PROCESS_INFORMATION pi = {};
  
  std::vector<char> cmd_buffer(command_line.begin(), command_line.end());
  cmd_buffer.push_back('\0');

  // We need to set working directory to where xray is, just in case
  std::string working_dir = xray_path.parent_path().string();

  // Log start of command (Debug only)
  // std::cerr << "RunXrayApiCommand: Starting command " << args << std::endl;

  if (!CreateProcessA(NULL, cmd_buffer.data(), NULL, NULL, TRUE, 0, NULL, working_dir.c_str(), &si, &pi)) {
    // std::cerr << "RunXrayApiCommand failed: CreateProcess error " << GetLastError() << std::endl;
    CloseHandle(hRead);
    CloseHandle(hWrite);
    return false;
  }

  // Close write end in parent
  CloseHandle(hWrite);

  // Read output with timeout
  char buffer[4096];
  DWORD bytesRead;
  std::stringstream ss;
  
  auto start_time = std::chrono::steady_clock::now();
  // 3 second timeout for API commands
  const auto timeout = std::chrono::seconds(3); 
  
  while (true) {
    // Check for timeout
    if (std::chrono::steady_clock::now() - start_time > timeout) {
      std::cerr << "RunXrayApiCommand: Timeout waiting for command: " << args << std::endl;
      TerminateProcess(pi.hProcess, 1);
      break;
    }
    
    DWORD bytesAvailable = 0;
    // std::cerr << "RunXrayApiCommand: Peeking pipe..." << std::endl;
    BOOL peekResult = PeekNamedPipe(hRead, NULL, 0, NULL, &bytesAvailable, NULL);
    
    if (peekResult && bytesAvailable > 0) {
      // Data is available, read it
      // std::cerr << "RunXrayApiCommand: Data available: " << bytesAvailable << std::endl;
      
      // Read only what is available to avoid blocking
      DWORD toRead = std::min((DWORD)(sizeof(buffer) - 1), bytesAvailable);
      
      if (ReadFile(hRead, buffer, toRead, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        ss << buffer;
        // std::cerr << "RunXrayApiCommand: Read " << bytesRead << " bytes" << std::endl;
      }
    } else {
      // No data available right now
      // Check if process has exited
      if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
        // Process exited.
        // std::cerr << "RunXrayApiCommand: Process exited" << std::endl;
        // Check one last time for any remaining data in the pipe
        while (PeekNamedPipe(hRead, NULL, 0, NULL, &bytesAvailable, NULL) && bytesAvailable > 0) {
           DWORD toRead = std::min((DWORD)(sizeof(buffer) - 1), bytesAvailable);
           if (ReadFile(hRead, buffer, toRead, &bytesRead, NULL) && bytesRead > 0) {
             buffer[bytesRead] = '\0';
             ss << buffer;
           } else {
             break;
           }
        }
        break;
      }
      
      // Process still running and no data, sleep briefly
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  
  // std::cerr << "RunXrayApiCommand: Finished command " << args << std::endl;
  
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hRead);

  output = ss.str();
  return true;
}
