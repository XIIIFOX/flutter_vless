#include "proxy_service.h"
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
  if (hStdInWrite) {
    CloseHandle(reinterpret_cast<HANDLE>(hStdInWrite)); hStdInWrite = 0;
    // Only opt-in private CLI workers receive this pipe. EOF requests their
    // synchronous factory Stop before the existing job/termination fallback.
    if (hProcess && IsRunning()) WaitForSingleObject(reinterpret_cast<HANDLE>(hProcess), 3000);
  }
  if (hJob) { CloseHandle(reinterpret_cast<HANDLE>(hJob)); hJob = 0; }
  if (hProcess) {
    HANDLE process = reinterpret_cast<HANDLE>(hProcess);
    if (IsRunning()) TerminateProcess(process, 0);
    WaitForSingleObject(process, 3000);
    CloseHandle(process); hProcess = 0;
  }
  for (auto* slot : {&hThread, &hStdOutRead, &hStdErrRead}) {
    if (*slot && reinterpret_cast<HANDLE>(*slot) != INVALID_HANDLE_VALUE) CloseHandle(reinterpret_cast<HANDLE>(*slot));
    *slot = 0;
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

bool ProxyService::Start(const std::string& config, flutter_vless::asset_location::Root assets,
    flutter_vless::preparation::StartupOutcome* outcome, flutter_vless::preparation::Report changes,
    std::function<void()> admitted) {
  using flutter_vless::preparation::Stage;
  if (outcome) outcome->Fail(Stage::prepare);
  if (!flutter_vless::asset_location::Valid(assets)) return false;
  std::string prepared = config;
  if (!flutter_vless::xray_config::PrepareProxy(prepared,
      [this](uint16_t port) { return IsPortFree(port); }, [this] { return FindFreePort(); }, &changes)) return false;
  auto executable = FindXrayExecutable();
  auto failure = Stage::core_check;
  if (!executable || !flutter_vless::native::CheckConfig(prepared, *executable,
      flutter_vless::native::ConfigCheckStorage::currentUser, assets, &failure)) {
    if (outcome) outcome->Fail(failure);
    return false;
  }
  // CheckConfig normalizes its private copy; the worker writes a separate file.
  changes.CheckedHost();
  const auto owned_api_port = flutter_vless::xray_config::OwnedApiPort(config, prepared);
  if (admitted) admitted();
  Stop();
  xray_executable_path_ = *executable;
  current_config_ = prepared;
  asset_directory_ = std::move(assets);
  api_address_ = owned_api_port ? "127.0.0.1:" + std::to_string(*owned_api_port) : "";
  ready_.store(false); is_running_.store(true);
  auto startup = std::make_shared<flutter_vless::preparation::StartupCompletion>();
  startup->report = changes;
  if (outcome) outcome->Fail(Stage::start);
  v2ray_thread_ = std::thread(&ProxyService::RunV2ray, this, startup);
  std::unique_lock<std::mutex> lock(start_mutex_);
  start_changed_.wait_for(lock, std::chrono::seconds(10), [&] { return startup->finished; });
  const bool ready = startup->finished && startup->ready && ready_.load();
  if (outcome) { if (ready) outcome->Succeed(startup->report); else outcome->Fail(startup->stage); }
  return ready;
}

void ProxyService::Stop() {
  is_running_.store(false);
  ready_.store(false);
  // A failed worker still owns a joinable thread.

  
  if (v2ray_thread_.joinable()) v2ray_thread_.join();
  if (stats_thread_.joinable()) stats_thread_.join();
  if (proxy_snapshot_) ClearSystemProxy();
  
  StopXrayProcess();
  CleanupTempFiles();
  api_address_.clear();
  asset_directory_.reset();

  std::lock_guard<std::mutex> lock(stats_mutex_);
  traffic_sample_ = {};
}

bool ProxyService::IsRunning() const {
  return ready_.load();
}

void ProxyService::RunV2ray(std::shared_ptr<flutter_vless::preparation::StartupCompletion> startup) try {
  auto finish = [this, startup](bool ready, flutter_vless::preparation::Stage stage = flutter_vless::preparation::Stage::start) {
    ready_.store(ready);
    { std::lock_guard<std::mutex> lock(start_mutex_); startup->ready = ready; startup->stage = stage; startup->finished = true; }
    start_changed_.notify_all();
  };
  if (!WriteConfigToFile(current_config_, temp_config_path_)) {
    is_running_.store(false); finish(false, flutter_vless::preparation::Stage::persist); CleanupTempFiles(); return;
  }
  if (!StartXrayProcess(temp_config_path_.string())) {
    is_running_.store(false); finish(false); CleanupTempFiles(); return;
  }
  auto json = flutter_vless::xray_config::Parse(current_config_);
  auto port = flutter_vless::xray_config::SocksPort(current_config_);
  std::string user, password;
  for (const auto& entry : json["inbounds"]) if (flutter_vless::xray_config::Port(entry) == port
      && entry.contains("settings") && entry["settings"].is_object()) {
    const auto& settings = entry["settings"];
    if (settings.contains("auth") && settings["auth"] == "password" && settings.contains("accounts")
        && settings["accounts"].is_array() && !settings["accounts"].empty()) {
      const auto& account = settings["accounts"][0];
      if (account.contains("user") && account["user"].is_string() && account.contains("pass") && account["pass"].is_string()) {
        user = account["user"].get<std::string>(); password = account["pass"].get<std::string>();
      }
    }
  }
  bool listening = false;
  for (int i = 0; i < 50 && is_running_.load() && xray_process_->IsRunning(); ++i) {
    if (port && flutter_vless::native::SocksReady(*port, user, password)) { listening = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!listening || !SetSystemProxy("localhost", *port)) {
    is_running_.store(false); finish(false); StopXrayProcess(); CleanupTempFiles(); return;
  }
  InitializeApiClient();
  start_time_ = std::chrono::steady_clock::now();
  finish(true);
  CleanupTempFiles();
  while (is_running_.load() && xray_process_->IsRunning()) {
    UpdateTrafficStats();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  ready_.store(false); is_running_.store(false);
  flutter_vless::DiagnosticsLog::Instance().Append("runtime", "Proxy forwarding stopped");
  // Keep the proxy pointing at the unavailable listener until explicit stop;
  // applications choosing this proxy must not silently fall back to direct.
  StopXrayProcess();
} catch (...) {
  ready_.store(false); is_running_.store(false);
  { std::lock_guard<std::mutex> lock(start_mutex_); startup->ready = false; startup->stage = flutter_vless::preparation::Stage::start; startup->finished = true; }
  start_changed_.notify_all();
  StopXrayProcess(); CleanupTempFiles();
  flutter_vless::DiagnosticsLog::Instance().Append("runtime", "Native proxy operation failed");
}

bool ProxyService::StartXrayProcess(const std::string& config_path) {
  xray_process_ = flutter_vless::native::Launch(xray_executable_path_,
      {L"run", L"-config", fs::path(config_path).wstring()}, false, asset_directory_);
  return xray_process_ != nullptr;
}

void ProxyService::StopXrayProcess() {
  if (xray_process_) {
    xray_process_->Close();
    xray_process_.reset();
  }
  api_client_.reset();
}

bool ProxyService::WriteConfigToFile(const std::string& config, fs::path& config_path) {
  return flutter_vless::native::WritePrivateConfig(config, config_path);
}

bool ProxyService::InitializeApiClient() {
  api_client_.reset();
  if (api_address_.empty()) return false;
  const auto port = flutter_vless::xray_config::ApiPort(
      flutter_vless::xray_config::Json{{"api", {{"listen", api_address_}}}}.dump());
  if (!port) return false;
  api_client_ = std::make_unique<ApiClient>();
  api_client_->service_ = this;
  api_client_->api_address_ = "127.0.0.1";
  api_client_->api_port_ = *port;
  return true;
}

void ProxyService::UpdateTrafficStats() {
  flutter_vless::traffic::Sample sample;
  const auto tag = flutter_vless::traffic::ProxyTag(current_config_);
  flutter_vless::traffic::Stats stats;
  if (api_client_ && !tag.empty() && api_client_->GetStats(stats))
    sample = flutter_vless::traffic::Select(stats, tag);
  std::lock_guard<std::mutex> lock(stats_mutex_); traffic_sample_ = sample;
}
flutter_vless::traffic::Sample ProxyService::GetTrafficSample() {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  return ready_.load() ? traffic_sample_ : flutter_vless::traffic::Sample{};
}
void ProxyService::GetTrafficStats(int64_t& upload, int64_t& download) {
  const auto sample = GetTrafficSample();
  upload = sample.upload.value_or(0); download = sample.download.value_or(0);
}

int ProxyService::GetServerDelay(const std::string& url) {
  if (!api_client_) return -1;
  return api_client_->MeasureDelay(url);
}

int ProxyService::MeasureDelayStateless(const std::string& config, const std::string& url) {
  (void)config; (void)url;
  return -1;
}

std::string ProxyService::GetCoreVersion() {
  const auto path = FindXrayExecutable();
  std::string output;
  if (!path || !flutter_vless::native::Command(*path, {L"version"}, output)) return "Unknown";
  std::smatch match;
  const std::regex version(R"(Xray\s+(\d+\.\d+\.\d+))");
  return std::regex_search(output, match, version) ? match[1].str() : "Unknown";
}

bool ProxyService::SetSystemProxy(const std::string& proxy_address, uint16_t proxy_port) {
  try {
    if (!proxy_snapshot_) {
      INTERNET_PER_CONN_OPTIONW saved[4]{};
      const DWORD keys[] = {INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_PROXY_SERVER,
          INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_AUTOCONFIG_URL};
      for (int i=0; i<4; ++i) saved[i].dwOption=keys[i];
      INTERNET_PER_CONN_OPTION_LISTW list{}; list.dwSize=sizeof(list); list.dwOptionCount=4; list.pOptions=saved;
      DWORD size=sizeof(list);
      if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) return false;
      saved_proxy_flags_=saved[0].Value.dwValue;
      auto keep=[](LPWSTR value) { std::wstring result=value?value:L""; if(value) GlobalFree(value); return result; };
      saved_proxy_server_=keep(saved[1].Value.pszValue);
      saved_proxy_bypass_=keep(saved[2].Value.pszValue);
      saved_proxy_pac_=keep(saved[3].Value.pszValue);
      proxy_snapshot_=true;
    }
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
    options[0].Value.dwValue = PROXY_TYPE_PROXY;
    
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
  if (!proxy_snapshot_) return true;
  INTERNET_PER_CONN_OPTIONW options[4]{};
  options[0].dwOption=INTERNET_PER_CONN_FLAGS; options[0].Value.dwValue=saved_proxy_flags_;
  options[1].dwOption=INTERNET_PER_CONN_PROXY_SERVER; options[1].Value.pszValue=saved_proxy_server_.data();
  options[2].dwOption=INTERNET_PER_CONN_PROXY_BYPASS; options[2].Value.pszValue=saved_proxy_bypass_.data();
  options[3].dwOption=INTERNET_PER_CONN_AUTOCONFIG_URL; options[3].Value.pszValue=saved_proxy_pac_.data();
  INTERNET_PER_CONN_OPTION_LISTW list{}; list.dwSize=sizeof(list); list.dwOptionCount=4; list.pOptions=options;
  if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list))) return false;
  InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
  InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
  proxy_snapshot_=false; return true;
}

std::optional<fs::path> ProxyService::FindXrayExecutable() {
  return flutter_vless::native::FindBundledFile(L"xray.exe");
}

std::optional<fs::path> ProxyService::FindXrayAssets(const fs::path& executable_path) {
  auto directory = executable_path.parent_path();
  return fs::is_regular_file(directory / "geoip.dat") ? std::optional<fs::path>(directory) : std::nullopt;
}

bool ProxyService::ValidateConfig(const std::string& config) {
  return flutter_vless::xray_config::Parse(config).is_object();
}

void ProxyService::CleanupTempFiles() {
  flutter_vless::native::RemovePrivateConfig(temp_config_path_);
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

bool ProxyService::ReplacePortsInConfigFile(const fs::path& config_path) {
  std::ifstream input(config_path);
  if (!input) return false;
  std::string content((std::istreambuf_iterator<char>(input)), {});
  input.close();
  if (!flutter_vless::xray_config::PrepareProxy(content,
      [this](uint16_t port) { return IsPortFree(port); },
      [this]() { return FindFreePort(); })) return false;
  std::ofstream output(config_path, std::ios::binary | std::ios::trunc);
  output << content;
  return output.good();
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
 * The function preserves exact decoded names and direction-local availability.
 * 
 * @warning CRITICAL: This function relies on the specific JSON output format of
 *          `xray api statsquery`. If Xray changes its output format, this parser
 *          may need to be updated. A unique record with an omitted value is the
 *          Core's serialized zero; malformed or duplicated records are unavailable.
 */
bool ApiClient::GetStats(flutter_vless::traffic::Stats& stats) {
  stats.clear();
  if (!service_) return false;
  std::string output;
  const std::string args = "api statsquery -s " + api_address_ + ":" + std::to_string(api_port_) + " -pattern \"\"";
  return RunXrayApiCommand(args, output) && flutter_vless::traffic::ParseStats(output, stats);
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
  (void)args;
  if (!service_ || api_port_ <= 0 || service_->api_address_.empty()) return false;
  return flutter_vless::native::Command(service_->xray_executable_path_,
      {L"api", L"statsquery", L"-server=" + flutter_vless::native::Wide(service_->api_address_)}, output);
}
