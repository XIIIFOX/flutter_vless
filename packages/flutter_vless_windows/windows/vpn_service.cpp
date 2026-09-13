#include "vpn_service.h"
#include "native_runtime.h"
#include "diagnostics_log.h"
#include "xray_config.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>

namespace {
void Event(const char* message) { flutter_vless::DiagnosticsLog::Instance().Append("vpn", message); }
std::optional<std::string> Underlay() {
  // Select a usable default without allowing our own more-specific capture
  // routes to become the next transport's underlay. Include adapter metrics.
  MIB_IPFORWARD_TABLE2* routes = nullptr;
  if (GetIpForwardTable2(AF_INET, &routes) != NO_ERROR) return std::nullopt;
  std::optional<std::string> result;
  uint64_t best = UINT64_MAX;
  for (ULONG i = 0; i < routes->NumEntries; ++i) {
    const auto& route = routes->Table[i];
    if (route.DestinationPrefix.PrefixLength != 0) continue;
    MIB_IF_ROW2 row{}; row.InterfaceLuid = route.InterfaceLuid;
    if (GetIfEntry2(&row) != NO_ERROR || row.OperStatus != IfOperStatusUp
        || std::wstring(row.Alias) == L"flutter_vless_tun") continue;
    MIB_IPINTERFACE_ROW ip{}; InitializeIpInterfaceEntry(&ip);
    ip.Family = AF_INET; ip.InterfaceLuid = row.InterfaceLuid;
    if (GetIpInterfaceEntry(&ip) != NO_ERROR) continue;
    const uint64_t metric = static_cast<uint64_t>(route.Metric) + ip.Metric;
    if (metric >= best) continue;
    int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) continue;
    std::string name(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, name.data(), size, nullptr, nullptr);
    name.pop_back(); result = name; best = metric;
  }
  FreeMibTable(routes);
  return result;
}
void Rebind(flutter_vless::xray_config::Json& node, const std::string& interface_name) {
  if (!node.is_object()) return;
  if (node.contains("sockopt") && node["sockopt"].is_object()) node["sockopt"]["interface"] = interface_name;
  for (auto it = node.begin(); it != node.end(); ++it) {
    if (it.key() == "streamSettings" || it.key() == "xhttpSettings" || it.key() == "splithttpSettings"
        || it.key() == "extra" || it.key() == "downloadSettings") Rebind(it.value(), interface_name);
  }
}
std::string Bootstrap(const std::string& name) {
  WSADATA data{}; if (WSAStartup(MAKEWORD(2,2), &data)) return {};
  addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
  addrinfo* addresses = nullptr; std::string result;
  if (getaddrinfo(name.c_str(), nullptr, &hints, &addresses) == 0) {
    char buffer[INET_ADDRSTRLEN]{};
    if (addresses && InetNtopA(AF_INET, &reinterpret_cast<sockaddr_in*>(addresses->ai_addr)->sin_addr, buffer, sizeof(buffer))) result = buffer;
    freeaddrinfo(addresses);
  }
  WSACleanup(); return result;
}
bool TunnelReady(NET_LUID& luid) {
  if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &luid) != NO_ERROR) return false;
  MIB_UNICASTIPADDRESS_ROW address{}; InitializeUnicastIpAddressEntry(&address);
  address.InterfaceLuid = luid; address.Address.Ipv4.sin_family = AF_INET;
  InetPtonA(AF_INET, "10.0.85.2", &address.Address.Ipv4.sin_addr);
  return GetUnicastIpAddressEntry(&address) == NO_ERROR && address.DadState == IpDadStatePreferred;
}
}
VpnService::VpnService() = default;
VpnService::~VpnService() { Shutdown(); }
bool VpnService::Start(const std::string& config) {
  using namespace flutter_vless;
  // Validate before retiring an existing session. No setup failure is reported
  // as connected, and reconnect never releases the independent WFP barrier.
  auto xray = native::FindBundledFile(L"xray.exe");
  auto tun = native::FindBundledFile(L"tun2socks.exe");
  auto wintun = native::FindBundledFile(L"wintun.dll");
  if (!native::IsAdministrator() || !xray || !tun || !wintun || wintun->parent_path() != tun->parent_path()) {
    Event("VPN requires administrator rights and bundled native executables"); return false;
  }
  if (!protection_.Inspect()) { Event("Windows traffic protection is unavailable or another VPN session owns it"); return false; }
  auto underlay = Underlay();
  auto user = native::RandomHex(16), password = native::RandomHex(32);
  auto cache = bootstrap_cache_;
  auto resolve = [&](const std::string& name) {
    const auto key = xray_config::Fold(name);
    auto found = cache.find(key);
    if (found != cache.end()) return found->second;
    // Once protected, never create an underlay DNS exception to restart.
    if (protection_.Active()) {
      Event("Endpoint is not cached while traffic protection is active; explicitly stop before bootstrapping a new endpoint");
      return std::string();
    }
    auto address = Bootstrap(name);
    if (!address.empty()) cache[key] = address;
    return address;
  };
  auto prepared = underlay ? xray_config::PrepareProtectedVpn(config, user, password, *underlay, resolve) : std::nullopt;
  if (!prepared) {
    Event("VPN configuration rejected or endpoint bootstrap unavailable");
    if (!protection_.Active()) protection_.Release();
    return false;
  }
  auto runtime = std::make_unique<native::ProtectedRuntime>();
  if (!runtime->Create(*xray)) {
    Event("Cannot create private administrator-owned VPN runtime");
    if (!protection_.Active()) protection_.Release();
    return false;
  }
  if (requested_.load()) StopSession(false);
  bootstrap_cache_ = std::move(cache);
  private_runtime_ = std::move(runtime);
  xray_executable_path_ = private_runtime_->Executable(); tun2socks_executable_path_ = *tun;
  current_config_ = *prepared; username_ = user; password_ = password;
  socks_port_ = *xray_config::SocksPort(current_config_);
  // WFP must exist before native workers, resolver configuration or capture.
  if (!protection_.Install(xray_executable_path_)) { Event("Could not install mandatory Windows traffic protection"); return false; }
  requested_.store(true); ready_.store(false);
  { std::lock_guard<std::mutex> lock(state_mutex_); first_attempt_finished_ = false; }
  vpn_thread_ = std::thread(&VpnService::RunVpn, this);
  std::unique_lock<std::mutex> lock(state_mutex_);
  state_changed_.wait_for(lock, std::chrono::seconds(40), [&] { return first_attempt_finished_; });
  return ready_.load();
}
void VpnService::StopSession(bool release) {
  requested_.store(false); ready_.store(false);
  if (vpn_thread_.joinable()) vpn_thread_.join();
  StopWorkers();
  private_runtime_.reset();
  if (release && !protection_.Release()) Event("Traffic protection cleanup failed; restart as administrator and stop again");
  username_.clear(); password_.clear(); current_config_.clear();
  if (release) bootstrap_cache_.clear();
  std::lock_guard<std::mutex> lock(stats_mutex_); total_upload_ = 0; total_download_ = 0;
}
void VpnService::Stop() { StopSession(true); }
void VpnService::Shutdown() { StopSession(false); }
bool VpnService::IsRunning() const { return ready_.load(); }
void VpnService::RunVpn() {
  while (requested_.load()) {
    bool started = false;
    try { started = StartWorkers(); } catch (...) { Event("Native VPN setup failed"); }
    ready_.store(started && requested_.load());
    { std::lock_guard<std::mutex> lock(state_mutex_); first_attempt_finished_ = true; }
    state_changed_.notify_all();
    if (started) Event("Protected VPN forwarding ready");
    unsigned ticks = 0;
    while (ready_.load() && requested_.load()) {
      if (!xray_process_->IsRunning() || !tun2socks_process_->IsRunning()
          || !packet_probe_ || !packet_probe_->Check()) break;
      if (++ticks % 2 == 0) UpdateTrafficStats();
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    ready_.store(false);
    StopWorkers();
    if (requested_.load()) Event("VPN forwarding unavailable; traffic remains blocked during recovery");
    for (int i = 0; i < 30 && requested_.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}
bool VpnService::StartWorkers() {
  using namespace flutter_vless;
  auto underlay = Underlay();
  if (!underlay) return false;
  auto config = xray_config::Parse(current_config_);
  for (auto& outbound : config["outbounds"]) Rebind(outbound, *underlay);
  packet_probe_ = std::make_unique<PacketPathProbe>();
  if (!packet_probe_->Start() || !packet_probe_->Configure(config)) return false;
  if (!private_runtime_ || !private_runtime_->WriteConfig(config.dump(), temp_config_path_)) return false;
  xray_process_ = native::Launch(xray_executable_path_, {L"run", L"-config", temp_config_path_.wstring()});
  if (!xray_process_) return false;
  bool listening = false;
  for (int i = 0; i < 60 && requested_.load() && xray_process_->IsRunning(); ++i) {
    if (native::SocksReady(socks_port_, username_, password_)) { listening = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!listening) return false;
  // Credentials live only in a private file, never in the process command line.
  std::string tun = "device: wintun://flutter_vless_tun\nproxy: socks5://" + username_ + ":" + password_
      + "@127.0.0.1:" + std::to_string(socks_port_) + "\nloglevel: silent\nmtu: 1500\n";
  if (!private_runtime_->WriteConfig(tun, tun_config_path_)) return false;
  tun2socks_process_ = native::Launch(tun2socks_executable_path_, {L"-config", tun_config_path_.wstring()});
  if (!tun2socks_process_) return false;
  NET_LUID luid{};
  for (int i = 0; i < 100 && requested_.load(); ++i) {
    if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &luid) == NO_ERROR) break;
    if (!tun2socks_process_->IsRunning()) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!luid.Value || !requested_.load()) return false;
  if (!native::SystemCommand(L"netsh.exe", {L"interface", L"ipv4", L"set", L"address",
      L"name=flutter_vless_tun", L"source=static", L"address=10.0.85.2", L"mask=255.255.255.0", L"gateway=none"})) return false;
  bool addressed = false;
  for (int i = 0; i < 150 && requested_.load(); ++i) {
    if (TunnelReady(luid)) { addressed = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!addressed || !native::SystemCommand(L"netsh.exe", {L"interface", L"ipv4", L"set", L"dnsservers",
      L"name=flutter_vless_tun", L"source=static", L"address=198.18.0.2", L"validate=no"})) return false;
  for (auto prefix : {std::pair<const char*, UINT8>{"0.0.0.0", 1}, {"128.0.0.0", 1}, {xray_config::kVirtualDns, 32}}) {
    MIB_IPFORWARD_ROW2 row{}; InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid; row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.PrefixLength = prefix.second;
    InetPtonA(AF_INET, prefix.first, &row.DestinationPrefix.Prefix.Ipv4.sin_addr);
    row.NextHop.Ipv4.sin_family = AF_INET;
    InetPtonA(AF_INET, "10.0.85.1", &row.NextHop.Ipv4.sin_addr);
    row.Metric = 0; row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    // Never delete or claim an existing administrator/other-session route.
    if (CreateIpForwardEntry2(&row) != NO_ERROR) return false;
    capture_routes_.push_back(row);
  }
  if (!protection_.Install(xray_executable_path_, &luid)) return false;
  native::RemovePrivateConfig(temp_config_path_);
  native::RemovePrivateConfig(tun_config_path_);
  for (int i = 0; i < 10 && requested_.load() && xray_process_->IsRunning() && tun2socks_process_->IsRunning(); ++i) {
    if (packet_probe_->Check()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return false;
}
void VpnService::StopWorkers() {
  // The separate WFP barrier remains installed, including during route removal.
  for (const auto& route : capture_routes_) DeleteIpForwardEntry2(&route);
  capture_routes_.clear();
  tun2socks_process_.reset(); xray_process_.reset();
  packet_probe_.reset();
  flutter_vless::native::RemovePrivateConfig(temp_config_path_);
  flutter_vless::native::RemovePrivateConfig(tun_config_path_);
}
void VpnService::UpdateTrafficStats() {
  std::string output;
  if (!flutter_vless::native::Command(xray_executable_path_, {L"api", L"statsquery", L"-server=127.0.0.1:10086"}, output)) return;
  auto stats = flutter_vless::xray_config::Parse(output);
  if (!stats.is_object() || !stats.contains("stat") || !stats["stat"].is_array()) return;
  int64_t up = 0, down = 0;
  for (const auto& entry : stats["stat"]) {
    if (!entry.is_object() || !entry.contains("name") || !entry["name"].is_string()) continue;
    const auto name = entry["name"].get<std::string>();
    if (name.rfind("inbound>>>", 0) != 0 || !entry.contains("value") || !entry["value"].is_number_integer()) continue;
    const auto value = entry["value"].get<int64_t>();
    if (value < 0) continue;
    if (name.find(">>>traffic>>>uplink") != std::string::npos && value <= INT64_MAX - up) up += value;
    if (name.find(">>>traffic>>>downlink") != std::string::npos && value <= INT64_MAX - down) down += value;
  }
  std::lock_guard<std::mutex> lock(stats_mutex_); total_upload_ = up; total_download_ = down;
}
void VpnService::GetTrafficStats(int64_t& upload, int64_t& download) {
  std::lock_guard<std::mutex> lock(stats_mutex_); upload = total_upload_; download = total_download_;
}
