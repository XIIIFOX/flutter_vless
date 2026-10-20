#include "vpn_service.h"
#include "native_runtime.h"
#include "diagnostics_log.h"
#include "xray_config.h"
#include "owned_address.h"
#include "windows_underlay.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>

namespace {
void Event(const char* message) { flutter_vless::DiagnosticsLog::Instance().Append("vpn", message); }
std::optional<std::string> Underlay(UINT64* identity = nullptr, ADDRESS_FAMILY family = AF_INET) {
  return flutter_vless::native::SelectUnderlay(family, identity);
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
  return GetUnicastIpAddressEntry(&address) == NO_ERROR && address.DadState == IpDadStatePreferred
      && address.OnLinkPrefixLength == 24;
}
bool TunnelIPv6Ready(const NET_LUID& luid) {
  MIB_UNICASTIPADDRESS_ROW address{}; InitializeUnicastIpAddressEntry(&address);
  address.InterfaceLuid = luid; address.Address.Ipv6.sin6_family = AF_INET6;
  if (InetPtonA(AF_INET6, "fd00:198:18::2", &address.Address.Ipv6.sin6_addr) != 1) return false;
  return GetUnicastIpAddressEntry(&address) == NO_ERROR && address.DadState == IpDadStatePreferred
      && address.OnLinkPrefixLength == 64 && !address.SkipAsSource;
}
}
VpnService::VpnService() = default;
VpnService::~VpnService() { Shutdown(); }
bool VpnService::Start(const std::string& config, const flutter_vless::NativeOptions& options,
    flutter_vless::asset_location::Root assets,
    std::optional<flutter_vless::native_routing::NativeRoutingIntent> routing, std::function<void()> admitted,
    flutter_vless::preparation::StartupOutcome* outcome, flutter_vless::preparation::Report changes) {
  using namespace flutter_vless;
  if (outcome) outcome->Fail(preparation::Stage::prepare);
  if (!asset_location::Valid(assets)) return false;
  // Validate before retiring an existing session. No setup failure is reported
  // as connected, and reconnect never releases the independent WFP barrier.
  auto xray = native::FindBundledFile(L"xray.exe");
  auto tun = native::FindBundledFile(L"tun2socks.exe");
  auto wintun = native::FindBundledFile(L"wintun.dll");
  if (!native::IsAdministrator() || !xray || !tun || !wintun || wintun->parent_path() != tun->parent_path()) {
    Event("VPN requires administrator rights and bundled native executables"); return false;
  }
  if (!protection_.Inspect()) { Event(("Windows traffic protection is unavailable, code=" + std::to_string(protection_.Error())).c_str()); return false; }
  if (native_routing::NativeRoutingSpec::ValidateSource(config, routing) != native_routing::NativeRoutingError::none) {
    Event("Native VPN routing selection rejected; active session preserved"); return false;
  }
  auto underlay = Underlay();
  if (!underlay) underlay = Underlay(nullptr, AF_INET6); // preparation only; checked candidate chooses its required family
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
  xray_config::VpnRoutingProvenance provenance;
  auto prepared = underlay ? xray_config::PrepareProtectedVpn(config, user, password, *underlay, resolve,
      &provenance, native::TcpPortAvailable, &changes) : std::nullopt;
  if (!prepared) {
    Event("VPN configuration rejected or endpoint bootstrap unavailable");
    if (!protection_.Active()) protection_.Release();
    return false;
  }
  if (routing && routing->source_inbound_index && (*routing->source_inbound_index < 0
      || static_cast<uint64_t>(*routing->source_inbound_index) >= provenance.original_inbound_count)) {
    Event("Native VPN routing source selection rejected; active session preserved"); return false;
  }
  const auto owned_api_port = xray_config::OwnedApiPort(config, *prepared).value_or(0);
  auto runtime = std::make_unique<native::ProtectedRuntime>();
  if (outcome) outcome->Fail(preparation::Stage::persist);
  if (!runtime->Create(*xray, !assets.has_value())) {
    Event("Cannot create private administrator-owned VPN runtime");
    if (!protection_.Active()) protection_.Release();
    return false;
  }
  const auto managed_port = xray_config::Port(xray_config::Parse(*prepared)["inbounds"][0]);
  auto failure = preparation::Stage::prepare;
  auto candidate = managed_port ? PrepareWorkerCandidate(*prepared, *managed_port, *runtime, assets, routing, provenance, user, nullptr, changes, &failure) : nullptr;
  if (!candidate) {
    if (outcome) outcome->Fail(failure);
    Event("Xray configuration check rejected final VPN document; active session preserved");
    return false;
  }
  if (admitted) admitted();
  if (requested_.load()) StopSession(false);
  bootstrap_cache_ = std::move(cache);
  private_runtime_ = std::move(runtime);
  pending_candidate_ = std::move(candidate);
  routing_intent_ = std::move(routing); routing_provenance_ = std::move(provenance);
  xray_executable_path_ = private_runtime_->Executable(); tun2socks_executable_path_ = *tun;
  options_ = options;
  current_config_ = *prepared; username_ = user; password_ = password;
  asset_directory_ = std::move(assets);
  socks_port_ = *managed_port;
  api_port_ = owned_api_port;
  if (outcome) outcome->Fail(preparation::Stage::start);
  underlay_family_ = routing_provenance_.ipv6_tcp_endpoints.empty() ? AF_INET : AF_INET6;
  underlay_name_ = pending_candidate_->Underlay(); underlay_luid_ = pending_candidate_->Identity();
  ipv6_tcp_scope_.reset();
  if (underlay_family_ == AF_INET6) ipv6_tcp_scope_ = flutter_vless::Ipv6TcpScope{underlay_luid_, routing_provenance_.ipv6_tcp_endpoints};
  // WFP must exist before native workers, resolver configuration or capture.
  if (!protection_.Install(xray_executable_path_, nullptr, ipv6_tcp_scope_ ? &*ipv6_tcp_scope_ : nullptr)) {
    Event(("Could not install mandatory Windows traffic protection, code=" + std::to_string(protection_.Error())).c_str());
    pending_candidate_.reset(); private_runtime_.reset();
    return false;
  }
  Event("Mandatory Windows traffic protection installed");
  requested_.store(true); ready_.store(false);
  auto startup = std::make_shared<preparation::StartupCompletion>();
  vpn_thread_ = std::thread(&VpnService::RunVpn, this, startup);
  std::unique_lock<std::mutex> lock(state_mutex_);
  state_changed_.wait_for(lock, std::chrono::seconds(40), [&] { return startup->finished; });
  const bool ready = startup->finished && startup->ready && ready_.load();
  if (outcome) { if (ready) outcome->Succeed(startup->report); else outcome->Fail(startup->stage); }
  return ready;
}
void VpnService::StopSession(bool release) {
  {
    // Pair the predicate change with the worker's wait lock: even an exhausted
    // retry policy must never miss Stop's notification and hang during join.
    std::lock_guard<std::mutex> lock(state_mutex_);
    requested_.store(false); ready_.store(false);
  }
  state_changed_.notify_all();
  if (vpn_thread_.joinable()) vpn_thread_.join();
  StopWorkers();
  private_runtime_.reset();
  if (release && !protection_.Release()) Event("Traffic protection cleanup failed; restart as administrator and stop again");
  username_.clear(); password_.clear(); current_config_.clear(); api_port_ = 0;
  routing_intent_.reset(); routing_provenance_ = {};
  asset_directory_.reset();
  ipv6_tcp_scope_.reset(); underlay_luid_ = 0; underlay_name_.clear(); underlay_family_ = AF_INET;
  if (release) bootstrap_cache_.clear();
  std::lock_guard<std::mutex> lock(stats_mutex_); traffic_sample_ = {};
}
void VpnService::Stop() { StopSession(true); }
void VpnService::Shutdown() { StopSession(false); }
bool VpnService::IsRunning() const { return ready_.load(); }
void VpnService::RunVpn(std::shared_ptr<flutter_vless::preparation::StartupCompletion> startup) {
  int failures = 0;
  while (requested_.load()) {
    bool started = false;
    flutter_vless::preparation::Report report;
    auto failure = flutter_vless::preparation::Stage::start;
    try { started = StartWorkers(&report, &failure); } catch (...) { Event("Native VPN setup failed"); }
    ready_.store(started && requested_.load());
    {
      std::lock_guard<std::mutex> lock(state_mutex_);
      if (!startup->finished) {
        startup->ready = ready_.load(); startup->report = report; startup->stage = failure; startup->finished = true;
      }
    }
    state_changed_.notify_all();
    if (started) { failures = 0; Event("Protected VPN forwarding ready"); }
    unsigned ticks = 0;
    while (ready_.load() && requested_.load()) {
      UINT64 identity = 0;
      const auto current_interface = Underlay(&identity, underlay_family_);
      if (!current_interface || *current_interface != underlay_name_ || identity != underlay_luid_) {
        Event("Outbound interface changed; rebuilding the protected VPN path");
        break;
      }
      if (!xray_process_->IsRunning() || !tun2socks_process_->IsRunning()
          || !worker_candidate_ || !worker_candidate_->PacketProbe().Check(
              flutter_vless::PacketPathProbe::address, [this] { return !requested_.load(); })) break;
      if (++ticks % 2 == 0) UpdateTrafficStats();
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    ready_.store(false);
    StopWorkers();
    if (requested_.load()) Event("VPN forwarding unavailable; traffic remains blocked during recovery");
    std::unique_lock<std::mutex> lock(state_mutex_);
    if (!options_.MayRetry(failures)) {
      Event("Native retry limit reached; traffic protection remains active until explicit Stop");
      state_changed_.wait(lock, [this] { return !requested_.load(); });
    } else {
      const auto delay = options_.RetryDelay(failures++);
      state_changed_.wait_for(lock, std::chrono::milliseconds(delay), [this] { return !requested_.load(); });
    }
  }
}
std::unique_ptr<VpnService::WorkerCandidate> VpnService::PrepareWorkerCandidate(
    const std::string& base, uint16_t managed_port, flutter_vless::native::ProtectedRuntime& runtime,
    const flutter_vless::asset_location::Root& assets,
    const std::optional<flutter_vless::native_routing::NativeRoutingIntent>& routing,
    const flutter_vless::xray_config::VpnRoutingProvenance& provenance, const std::string& auth_user,
    const flutter_vless::Ipv6TcpScope* retained_scope,
    flutter_vless::preparation::Report changes, flutter_vless::preparation::Stage* failure) {
  if (failure) *failure = flutter_vless::preparation::Stage::prepare;
  if (routing && !flutter_vless::native::RoutingCapability(runtime, assets)) {
    Event("Bundled runtime does not support native VPN routing"); return nullptr;
  }
  UINT64 identity = 0;
  const auto family = provenance.ipv6_tcp_endpoints.empty() ? AF_INET : AF_INET6;
  const auto underlay = Underlay(&identity, static_cast<ADDRESS_FAMILY>(family));
  if (!underlay || (retained_scope && identity != retained_scope->interface_luid)) return nullptr; // no IPv6 handover in this increment
  const auto excluded = flutter_vless::xray_config::ListenerPortExclusions(flutter_vless::xray_config::Parse(base));
  if (!excluded) return nullptr;
  auto candidate = WorkerCandidate::Prepare(base, *underlay, identity, managed_port,
      [ports = *excluded] { return std::make_unique<flutter_vless::PacketPathProbe>(ports); },
      [&](const std::string& bytes, fs::path& path, std::string& metadata, fs::path& metadata_path,
          const std::vector<int64_t>& probe_guards) {
        if (!routing) return flutter_vless::native::CheckPreparedConfig(bytes, runtime, path, assets, failure);
        std::vector<int64_t> guards = probe_guards;
        // PacketPathProbe owns one prepended rule; provenance comes from its
        // actual Configure call, and from the protected preparer's insertions.
        for (const auto index : provenance.guard_rule_indices)
          guards.push_back(index + static_cast<int64_t>(probe_guards.size()));
        const auto mapped = routing->source_inbound_index
            ? std::optional<int64_t>{*routing->source_inbound_index + 1} : std::nullopt;
        auto frozen = flutter_vless::native_routing::NativeRoutingSpec::Freeze(bytes, 0,
            provenance.managed_tag, auth_user, routing, mapped, guards);
        if (frozen.error != flutter_vless::native_routing::NativeRoutingError::none || !frozen.envelope) return false;
        metadata = frozen.envelope->metadata_data();
        return flutter_vless::native::CheckRoutingPreparedConfig(bytes, metadata, runtime, path, metadata_path, assets, failure);
      }, flutter_vless::native::RemovePrivateConfig, changes);
  // A slow check must not admit a snapshot whose adapter already changed.
  UINT64 current_identity = 0;
  const auto current = Underlay(&current_identity, static_cast<ADDRESS_FAMILY>(family));
  if (!candidate || !current || *current != candidate->Underlay()
      || current_identity != candidate->Identity()) return nullptr;
  return candidate;
}
bool VpnService::StartWorkers(flutter_vless::preparation::Report* report, flutter_vless::preparation::Stage* failure) {
  using namespace flutter_vless;
  if (failure) *failure = preparation::Stage::start;
  auto fail = [](const char* stage) { Event(stage); return false; };
  // A previous adapter can outlive its child. Keep cleanup ownership and deny
  // a replacement until its exact address is retired or verified absent.
  if (!RetireIPv6Address()) return fail("Previous owned Wintun IPv6 address cleanup remains pending");
  if (!private_runtime_) return fail("Private VPN runtime is unavailable");
  worker_candidate_ = pending_candidate_ ? std::move(pending_candidate_)
      : PrepareWorkerCandidate(current_config_, socks_port_, *private_runtime_, asset_directory_, routing_intent_, routing_provenance_, username_, ipv6_tcp_scope_ ? &*ipv6_tcp_scope_ : nullptr);
  if (!worker_candidate_) return fail("Final VPN recovery configuration check failed");
  UINT64 current_identity = 0;
  const auto current_underlay = Underlay(&current_identity, underlay_family_);
  if (!current_underlay || *current_underlay != worker_candidate_->Underlay()
      || current_identity != worker_candidate_->Identity()) return fail("Checked VPN underlay changed before launch");
  underlay_name_ = worker_candidate_->Underlay();
  underlay_luid_ = worker_candidate_->Identity();
  const auto command = worker_candidate_->Routing()
      ? std::vector<std::wstring>{L"native-routing", L"run", L"--parent-stdin", L"--config", worker_candidate_->Path().wstring(),
          L"--spec", worker_candidate_->MetadataPath().wstring()}
      : std::vector<std::wstring>{L"run", L"-config", worker_candidate_->Path().wstring()};
  if (!requested_.load()) return fail("VPN startup cancelled");
  xray_process_ = native::Launch(xray_executable_path_, command, false, asset_directory_, worker_candidate_->Routing());
  if (!xray_process_) return fail("Cannot launch the protected Xray process");
  const native::SocksReadinessBudget readiness_budget(std::chrono::milliseconds(6000), [this] { return !requested_.load(); });
  bool listening = false;
  for (int i = 0; i < 60 && readiness_budget.CanContinue() && requested_.load() && xray_process_->IsRunning(); ++i) {
    if (native::SocksReady(socks_port_, username_, password_, &readiness_budget)) { listening = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!requested_.load() || !readiness_budget.CanContinue()) return fail("VPN startup cancelled");
  if (!listening) {
    DWORD code = 0; GetExitCodeProcess(reinterpret_cast<HANDLE>(xray_process_->hProcess), &code);
    Event(("Authenticated Xray listener unavailable, process code=" + std::to_string(code)).c_str());
    return false;
  }
  Event("Authenticated Xray listener ready");
  // Credentials live only in a private file, never in the process command line.
  // The bundled tun2socks uses the "tun" driver on Windows too; Wintun is
  // the implementation, not a supported URI scheme.
  std::string tun = "device: tun://flutter_vless_tun\nproxy: socks5://" + username_ + ":" + password_
      + "@127.0.0.1:" + std::to_string(socks_port_) + "\nloglevel: silent\nmtu: 1500\n";
  if (!private_runtime_->WriteConfig(tun, tun_config_path_)) return fail("Cannot write the private tun2socks configuration");
  if (!requested_.load()) return fail("VPN startup cancelled");
  tun2socks_process_ = native::Launch(tun2socks_executable_path_, {L"-config", tun_config_path_.wstring()});
  if (!tun2socks_process_) return fail("Cannot launch tun2socks");
  NET_LUID luid{};
  bool adapter_ready = false;
  for (int i = 0; i < 100 && requested_.load(); ++i) {
    if (!tun2socks_process_->IsRunning()) return fail("tun2socks exited before creating its adapter");
    if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &luid) == NO_ERROR) {
      MIB_IF_ROW2 adapter{}; adapter.InterfaceLuid = luid;
      if (GetIfEntry2(&adapter) == NO_ERROR && adapter.OperStatus == IfOperStatusUp) {
        adapter_ready = true; break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!adapter_ready || !requested_.load()) return fail("Wintun adapter unavailable or startup cancelled");
  // Wintun can retain its address after a worker crash. netsh may reject a
  // repeated assignment; the IP Helper state is the authoritative readiness
  // check, including DAD, the exact address and its prefix length.
  const bool assigned = native::SystemCommand(L"netsh.exe", {L"interface", L"ipv4", L"set", L"address",
      L"name=flutter_vless_tun", L"source=static", L"address=10.0.85.2", L"mask=255.255.255.0", L"gateway=none"});
  bool addressed = false;
  for (int i = 0; i < 150 && requested_.load(); ++i) {
    if (TunnelReady(luid)) { addressed = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!addressed) return fail("Wintun IPv4 address did not become ready");
  if (!assigned) Event("Reusing the existing ready Wintun IPv4 address");
  MIB_UNICASTIPADDRESS_ROW ipv6{}; InitializeUnicastIpAddressEntry(&ipv6);
  ipv6.InterfaceLuid = luid; ipv6.Address.Ipv6.sin6_family = AF_INET6;
  if (InetPtonA(AF_INET6, "fd00:198:18::2", &ipv6.Address.Ipv6.sin6_addr) != 1) return fail("Invalid owned Wintun IPv6 address");
  ipv6.OnLinkPrefixLength = 64;
  ipv6.PrefixOrigin = IpPrefixOriginManual; ipv6.SuffixOrigin = IpSuffixOriginManual;
  ipv6.ValidLifetime = ipv6.PreferredLifetime = 0xffffffff;
  ipv6.SkipAsSource = FALSE;
  const auto ipv6_status = CreateUnicastIpAddressEntry(&ipv6);
  if (ipv6_status == NO_ERROR) ipv6_address_ = ipv6;
  else if (ipv6_status != ERROR_OBJECT_ALREADY_EXISTS) {
    Event(("Cannot assign the owned Wintun IPv6 address, code=" + std::to_string(ipv6_status)).c_str()); return false;
  }
  bool ipv6_ready = false;
  for (int i = 0; i < 50 && requested_.load() && tun2socks_process_->IsRunning(); ++i) {
    if (TunnelIPv6Ready(luid)) { ipv6_ready = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!ipv6_ready) return fail("Wintun IPv6 address did not become ready");
  if (ipv6_status == ERROR_OBJECT_ALREADY_EXISTS) Event("Reusing the existing ready Wintun IPv6 address");
  if (!native::SystemCommand(L"netsh.exe", {L"interface", L"ipv4", L"set", L"dnsservers",
      L"name=flutter_vless_tun", L"source=static", native::Wide(std::string("address=") + xray_config::kVirtualDns), L"validate=no"})) return fail("Wintun address or virtual DNS did not become ready");
  for (auto prefix : {std::pair<const char*, UINT8>{"0.0.0.0", UINT8{1}}, {"128.0.0.0", UINT8{1}}, {xray_config::kVirtualDns, UINT8{32}}}) {
    MIB_IPFORWARD_ROW2 row{}; InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid; row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.PrefixLength = prefix.second;
    InetPtonA(AF_INET, prefix.first, &row.DestinationPrefix.Prefix.Ipv4.sin_addr);
    row.NextHop.Ipv4.sin_family = AF_INET;
    InetPtonA(AF_INET, "10.0.85.1", &row.NextHop.Ipv4.sin_addr);
    row.Metric = 0; row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    // Never delete or claim an existing administrator/other-session route.
    const auto status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR) { Event(("Cannot install an owned capture route, code=" + std::to_string(status)).c_str()); return false; }
    capture_routes_.push_back(row);
  }
  for (const auto* prefix : {"::", "8000::"}) {
    MIB_IPFORWARD_ROW2 row{}; InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid; row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    row.DestinationPrefix.PrefixLength = 1;
    if (InetPtonA(AF_INET6, prefix, &row.DestinationPrefix.Prefix.Ipv6.sin6_addr) != 1) return fail("Invalid owned IPv6 capture prefix");
    // On-link L3 route: the Wintun worker receives the original IPv6 packet.
    // Never replace a physical IPv6 default or permit physical Xray IPv6.
    row.NextHop.Ipv6.sin6_family = AF_INET6;
    row.Metric = 0; row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    const auto status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR) { Event(("Cannot install an owned IPv6 capture route, code=" + std::to_string(status)).c_str()); return false; }
    capture_routes_.push_back(row);
  }
  if (!protection_.Install(xray_executable_path_, &luid, ipv6_tcp_scope_ ? &*ipv6_tcp_scope_ : nullptr)) { Event(("Cannot authorize the Wintun interface, code=" + std::to_string(protection_.Error())).c_str()); return false; }
  Event("Wintun capture and virtual DNS ready; checking packet forwarding");
  worker_candidate_->RemoveFile();
  native::RemovePrivateConfig(tun_config_path_);
  for (int i = 0; i < 10 && requested_.load() && xray_process_->IsRunning() && tun2socks_process_->IsRunning(); ++i) {
    if (worker_candidate_->PacketProbe().Check(PacketPathProbe::address, [this] { return !requested_.load(); })) {
      if (report) *report = worker_candidate_->PreparationReport();
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return fail("Private packet-path challenge did not complete");
}
void VpnService::StopWorkers() {
  { std::lock_guard<std::mutex> lock(stats_mutex_); traffic_sample_ = {}; }
  // The separate WFP barrier remains installed, including during route removal.
  for (const auto& route : capture_routes_) DeleteIpForwardEntry2(&route);
  capture_routes_.clear();
  const bool ipv6_retired = RetireIPv6Address();
  tun2socks_process_.reset(); xray_process_.reset();
  if (!ipv6_retired) RetireIPv6Address(); // adapter teardown can complete a pending deletion
  worker_candidate_.reset();
  pending_candidate_.reset();
  flutter_vless::native::RemovePrivateConfig(tun_config_path_);
}
bool VpnService::RetireIPv6Address() {
  return flutter_vless::native::RetireOwnedAddress(ipv6_address_, [](const MIB_UNICASTIPADDRESS_ROW& address) {
    const auto status = DeleteUnicastIpAddressEntry(&address);
    if (status == NO_ERROR || status == ERROR_NOT_FOUND) return true;
    Event(("Owned Wintun IPv6 address cleanup failed, code=" + std::to_string(status)).c_str());
    return false;
  });
}
void VpnService::UpdateTrafficStats() {
  flutter_vless::traffic::Sample sample;
  flutter_vless::traffic::Stats stats;
  std::string output;
  if (api_port_ && !routing_provenance_.managed_tag.empty()
      && flutter_vless::native::Command(xray_executable_path_, {L"api", L"statsquery", L"-server=127.0.0.1:" + std::to_wstring(api_port_)}, output)
      && flutter_vless::traffic::ParseStats(output, stats))
    sample = flutter_vless::traffic::Select(stats, routing_provenance_.managed_tag);
  std::lock_guard<std::mutex> lock(stats_mutex_); traffic_sample_ = sample;
}
flutter_vless::traffic::Sample VpnService::GetTrafficSample() {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  return ready_.load() ? traffic_sample_ : flutter_vless::traffic::Sample{};
}
void VpnService::GetTrafficStats(int64_t& upload, int64_t& download) {
  const auto sample = GetTrafficSample();
  upload = sample.upload.value_or(0); download = sample.download.value_or(0);
}
