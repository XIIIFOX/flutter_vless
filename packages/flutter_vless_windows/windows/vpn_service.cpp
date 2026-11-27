#include "vpn_service.h"
#include "native_runtime.h"
#include "balancer_selection_protocol.h"
#include "diagnostics_log.h"
#include "xray_config.h"
#include "owned_address.h"
#include "windows_underlay.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <string_view>
#include <ws2tcpip.h>
#include <iphlpapi.h>

namespace {
void Event(const char* message) { flutter_vless::DiagnosticsLog::Instance().Append("vpn", message); }

class StartupTiming {
 public:
  using Clock = std::chrono::steady_clock;

  void Mark(const char* stage) {
    const auto now = Clock::now();
    Record(stage, previous_, now);
    previous_ = now;
  }

  void Record(const char* stage, Clock::time_point start, Clock::time_point end) {
    Record(stage, std::chrono::duration_cast<std::chrono::milliseconds>(end - start));
  }

  void Record(const char* stage, std::chrono::milliseconds elapsed) {
    if (published_) Append(stage, elapsed.count());
    else pending_.emplace_back(stage, elapsed.count());
  }

  void RecordSnapshot(const flutter_vless::native::RuntimeSnapshotTiming& snapshot) {
    Record("runtime_directory", snapshot.directory);
    const auto record_file = [this](const auto& file, const char* opened, const char* copied,
        const char* flushed, const char* closed) {
      if (!file.copied) return;
      Record(opened, file.open);
      Record(copied, file.copy);
      Record(flushed, file.flush);
      Record(closed, file.close);
    };
    record_file(snapshot.xray, "runtime_xray_open", "runtime_xray_copy",
        "runtime_xray_flush", "runtime_xray_close");
    record_file(snapshot.geoip, "runtime_geoip_open", "runtime_geoip_copy",
        "runtime_geoip_flush", "runtime_geoip_close");
    record_file(snapshot.geosite, "runtime_geosite_open", "runtime_geosite_copy",
        "runtime_geosite_flush", "runtime_geosite_close");
  }

  void Publish() {
    published_ = true;
    for (const auto& [stage, elapsed] : pending_) Append(stage, elapsed);
    pending_.clear();
  }

 private:
  static void Append(const char* stage, std::chrono::milliseconds::rep elapsed) {
    flutter_vless::DiagnosticsLog::Instance().Append(
        "vpn", std::string("startup timing ") + stage + " " + std::to_string(elapsed) + " ms");
  }

  Clock::time_point previous_ = Clock::now();
  std::vector<std::pair<const char*, std::chrono::milliseconds::rep>> pending_;
  bool published_ = false;
};

enum class ListenerState { missing, owned, unavailable };

ListenerState OwnedListenerState(DWORD pid, uint16_t port, std::vector<DWORD>& buffer) {
  if (!pid) return ListenerState::unavailable;
  constexpr DWORD max_bytes = 1024 * 1024;
  constexpr auto header_size = offsetof(MIB_TCPTABLE_OWNER_PID, table);
  const auto query = [&buffer](DWORD& bytes) {
    return GetExtendedTcpTable(buffer.data(), &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
  };
  auto bytes = static_cast<DWORD>(buffer.size() * sizeof(DWORD));
  auto status = query(bytes);
  if (status == ERROR_INSUFFICIENT_BUFFER && bytes <= max_bytes) {
    buffer.resize((bytes + sizeof(DWORD) - 1) / sizeof(DWORD));
    bytes = static_cast<DWORD>(buffer.size() * sizeof(DWORD));
    status = query(bytes);
  }
  if (status != NO_ERROR || bytes < header_size || bytes > buffer.size() * sizeof(DWORD)) {
    return ListenerState::unavailable;
  }
  const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
  if (table->dwNumEntries > (bytes - header_size) / sizeof(MIB_TCPROW_OWNER_PID)) return ListenerState::unavailable;
  const auto loopback = htonl(INADDR_LOOPBACK);
  const auto net_port = htons(port);
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const auto& row = table->table[i];
    if (row.dwState == MIB_TCP_STATE_LISTEN && row.dwOwningPid == pid && row.dwLocalAddr == loopback &&
        (row.dwLocalPort & 0xffff) == net_port) return ListenerState::owned;
  }
  return ListenerState::missing;
}

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
MIB_UNICASTIPADDRESS_ROW TunnelIPv4Address(const NET_LUID& luid) {
  MIB_UNICASTIPADDRESS_ROW address{}; InitializeUnicastIpAddressEntry(&address);
  address.InterfaceLuid = luid; address.Address.Ipv4.sin_family = AF_INET;
  InetPtonA(AF_INET, "10.0.85.2", &address.Address.Ipv4.sin_addr);
  address.OnLinkPrefixLength = 24;
  address.PrefixOrigin = IpPrefixOriginManual; address.SuffixOrigin = IpSuffixOriginManual;
  address.ValidLifetime = address.PreferredLifetime = 0xffffffff;
  address.SkipAsSource = FALSE;
  return address;
}

std::string NewTunnelIPv6Address() {
  const auto iid = flutter_vless::native::RandomHex(8);
  if (iid.size() != 16 || iid == "0000000000000000") return {};
  return "fd00:198:18:0:" + iid.substr(0, 4) + ":" + iid.substr(4, 4) + ":" +
      iid.substr(8, 4) + ":" + iid.substr(12, 4);
}

bool IsTun2socksDescription(std::wstring_view description) {
  constexpr std::wstring_view name = L"tun2socks Tunnel";
  if (description.size() < name.size() || _wcsnicmp(description.data(), name.data(), name.size()) != 0) return false;
  const auto suffix = description.substr(name.size());
  // Windows can number otherwise identical device descriptions on recreation.
  return suffix.empty() || (suffix.size() > 2 && suffix.substr(0, 2) == L" #" && suffix[2] >= L'1' &&
      std::all_of(suffix.begin() + 2, suffix.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; }));
}

bool IsTun2socksAdapter(const MIB_IF_ROW2& adapter) {
  return adapter.Type == IF_TYPE_PROP_VIRTUAL && adapter.MediaType == NdisMediumIP &&
      !adapter.InterfaceAndOperStatusFlags.HardwareInterface && IsTun2socksDescription(adapter.Description);
}

bool CanUseOptimisticDad(const MIB_IF_ROW2& adapter, const MIB_UNICASTIPADDRESS_ROW& address) {
  // The newly created raw-IP Wintun is owned by tun2socks. Its SOCKS path
  // forwards traffic rather than bridging neighbor discovery to another link.
  const bool ipv6 = address.Address.si_family == AF_INET6;
  if (!IsTun2socksAdapter(adapter)) {
    Event(ipv6 ? "Unrecognized tunnel adapter; using synchronous IPv6 DAD"
               : "Unrecognized tunnel adapter; using synchronous IPv4 DAD");
    return false;
  }
  PMIB_UNICASTIPADDRESS_TABLE addresses = nullptr;
  if (GetUnicastIpAddressTable(address.Address.si_family, &addresses) != NO_ERROR || !addresses) {
    Event(ipv6 ? "Local IPv6 address inventory unavailable; using synchronous IPv6 DAD"
               : "Local IPv4 address inventory unavailable; using synchronous IPv4 DAD");
    return false;
  }
  bool available = true;
  for (ULONG i = 0; i < addresses->NumEntries; ++i) {
    const auto& entry = addresses->Table[i].Address;
    const bool matches = ipv6
        ? std::memcmp(&entry.Ipv6.sin6_addr, &address.Address.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0
        : entry.Ipv4.sin_addr.S_un.S_addr == address.Address.Ipv4.sin_addr.S_un.S_addr;
    if (matches) {
      available = false;
      break;
    }
  }
  FreeMibTable(addresses);
  if (!available) Event(ipv6 ? "Tunnel IPv6 address already present locally; using synchronous IPv6 DAD"
                            : "Tunnel IPv4 address already present locally; using synchronous IPv4 DAD");
  return available;
}

ULONG CreateTunnelAddress(MIB_UNICASTIPADDRESS_ROW& address, bool optimistic) {
  const auto previous_state = address.DadState;
  if (optimistic) address.DadState = IpDadStatePreferred;
  const auto status = CreateUnicastIpAddressEntry(&address);
  if (!optimistic || status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS) return status;
  address.DadState = previous_state;
  Event(address.Address.si_family == AF_INET6
      ? "Optimistic IPv6 assignment was rejected; using synchronous IPv6 DAD"
      : "Optimistic IPv4 assignment was rejected; using synchronous IPv4 DAD");
  return CreateUnicastIpAddressEntry(&address);
}

bool TunnelReady(MIB_UNICASTIPADDRESS_ROW address) {
  const auto prefix = address.OnLinkPrefixLength;
  return GetUnicastIpAddressEntry(&address) == NO_ERROR && address.DadState == IpDadStatePreferred
      && address.OnLinkPrefixLength == prefix && !address.SkipAsSource;
}

bool SetTunnelDns(const NET_LUID& luid) {
  auto server = flutter_vless::native::Wide(flutter_vless::xray_config::kVirtualDns);
#ifdef DNS_INTERFACE_SETTINGS_VERSION1
  // The function is exported on Windows 10 2004 and later. Loading it at
  // runtime keeps the existing netsh path available on older Windows builds.
  using Setter = decltype(&SetInterfaceDnsSettings);
  static const auto set = [] {
    const auto module = GetModuleHandleW(L"iphlpapi.dll");
    const auto symbol = module ? GetProcAddress(module, "SetInterfaceDnsSettings") : nullptr;
    Setter setter = nullptr;
    static_assert(sizeof(setter) == sizeof(symbol));
    std::memcpy(&setter, &symbol, sizeof(setter));
    return setter;
  }();
  GUID adapter{};
  if (set && ConvertInterfaceLuidToGuid(&luid, &adapter) == NO_ERROR) {
    DNS_INTERFACE_SETTINGS settings{};
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER;
    settings.NameServer = server.data();
    if (set(adapter, &settings) == NO_ERROR) {
      Event("Wintun IPv4 DNS configured via IP Helper");
      return true;
    }
  }
#endif
  NET_LUID current{};
  if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &current) != NO_ERROR || current.Value != luid.Value) return false;
  if (!flutter_vless::native::SystemCommand(L"netsh.exe", {L"interface", L"ipv4", L"set", L"dnsservers",
      L"name=flutter_vless_tun", L"source=static", L"address=" + server, L"validate=no"})) return false;
  Event("Wintun IPv4 DNS configured via netsh");
  return true;
}

bool RetireTunnelAddress(std::optional<MIB_UNICASTIPADDRESS_ROW>& owned, const char* family) {
  return flutter_vless::native::RetireOwnedAddress(owned, [family](const MIB_UNICASTIPADDRESS_ROW& address) {
    const auto status = DeleteUnicastIpAddressEntry(&address);
    if (status == NO_ERROR || status == ERROR_NOT_FOUND) return true;
    Event((std::string("Owned Wintun ") + family + " address cleanup failed, code=" + std::to_string(status)).c_str());
    return false;
  });
}
}
VpnService::VpnService() = default;
VpnService::~VpnService() { Shutdown(); }
bool VpnService::Start(const std::string& config, const flutter_vless::NativeOptions& options,
    flutter_vless::asset_location::Root assets,
    std::optional<flutter_vless::native_routing::NativeRoutingIntent> routing, std::function<void()> admitted,
    flutter_vless::preparation::StartupOutcome* outcome, flutter_vless::preparation::Report changes) {
  using namespace flutter_vless;
  StartupTiming timing;
  const auto prepare_started = StartupTiming::Clock::now();
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
  if (native_routing::NativeRoutingSpec::ValidateSource(config, routing) != native_routing::NativeRoutingError::none) {
    Event("Native VPN routing selection rejected; active session preserved"); return false;
  }
  auto authored = xray_config::Parse(config);
  if (!xray_config::Normalize(authored)) return false;
  if (outcome) outcome->Fail(preparation::Stage::persist);
  const auto runtime_started = StartupTiming::Clock::now();
  native::RuntimeSnapshotTiming runtime_timing;
  auto runtime = std::make_unique<native::ProtectedRuntime>();
  if (!runtime->Create(*xray, !assets.has_value(), &runtime_timing)) {
    Event("Cannot create private administrator-owned VPN runtime"); return false;
  }
  const auto runtime_finished = StartupTiming::Clock::now();
  timing.Mark("prepare_runtime");
  timing.Record("runtime_preflight", prepare_started, runtime_started);
  timing.Record("runtime_snapshot", runtime_started, runtime_finished);
  timing.RecordSnapshot(runtime_timing);
  // Both Core checks use this one administrator-owned snapshot. Reject an
  // invalid authored profile before endpoint bootstrap or session replacement.
  fs::path authored_path;
  auto authored_failure = preparation::Stage::prepare;
  const bool authored_valid = native::CheckPreparedConfig(authored.dump(), *runtime, authored_path, assets, &authored_failure);
  native::RemovePrivateConfig(authored_path);
  if (!authored_valid || !authored_path.empty()) {
    if (outcome) outcome->Fail(authored_valid ? preparation::Stage::persist : authored_failure);
    Event("Xray configuration check rejected authored VPN document; active session preserved"); return false;
  }
  timing.Mark("authored_config");
  if (outcome) outcome->Fail(preparation::Stage::prepare);
  if (!protection_.Inspect()) { Event(("Windows traffic protection is unavailable, code=" + std::to_string(protection_.Error())).c_str()); return false; }
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
  timing.Mark("prepare_config");
  const auto managed_port = xray_config::Port(xray_config::Parse(*prepared)["inbounds"][0]);
  auto failure = preparation::Stage::prepare;
  auto candidate = managed_port ? PrepareWorkerCandidate(*prepared, *managed_port, *runtime, assets, routing, provenance, user, nullptr, changes, &failure) : nullptr;
  if (!candidate) {
    if (outcome) outcome->Fail(failure);
    Event("Xray configuration check rejected final VPN document; active session preserved");
    return false;
  }
  const bool record_balancer = options.RecordsBalancerSelections() && !provenance.managed_tag.empty()
      && native::BalancerCapability(*runtime, assets);
  timing.Mark("validate_core");
  if (admitted) admitted();
  // Admission resets diagnostics only after the replacement is checked.
  timing.Publish();
  if (requested_.load()) StopSession(false);
  bootstrap_cache_ = std::move(cache);
  private_runtime_ = std::move(runtime);
  pending_candidate_ = std::move(candidate);
  routing_intent_ = std::move(routing); routing_provenance_ = std::move(provenance);
  xray_executable_path_ = private_runtime_->Executable(); tun2socks_executable_path_ = *tun;
  options_ = options;
  record_balancer_selections_.store(record_balancer);
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
  timing.Mark("install_wfp");
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
  DisableBalancerSelections();
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
      if (ipv4_address_ && ipv4_address_->DadState == IpDadStatePreferred && !TunnelReady(*ipv4_address_)) {
        Event("Optimistic Wintun IPv4 address lost readiness; retaining traffic protection");
        break;
      }
      if (ipv6_address_ && !TunnelReady(*ipv6_address_)) {
        Event("Wintun IPv6 address lost readiness; retaining traffic protection");
        break;
      }
      if (!xray_process_->IsRunning() || !tun2socks_process_->IsRunning()
          || !worker_candidate_ || !worker_candidate_->PacketProbe().Check(
              flutter_vless::PacketPathProbe::address, [this] { return !requested_.load(); })) break;
      if (++ticks % 2 == 0) {
        UpdateBalancerSelections();
        UpdateTrafficStats();
      } else if (!record_balancer_selections_.load()) UpdateBalancerSelections();
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
  StartupTiming timing;
  timing.Publish();
  if (failure) *failure = preparation::Stage::start;
  auto fail = [](const char* stage) { Event(stage); return false; };
  // A previous adapter can outlive its child. Keep cleanup ownership and deny
  // a replacement until its exact address is retired or verified absent.
  const bool ipv4_retired = RetireIPv4Address();
  if (!RetireIPv6Address() || !ipv4_retired) return fail("Previous owned Wintun address cleanup remains pending");
  if (!private_runtime_) return fail("Private VPN runtime is unavailable");
  // Only Start's admitted candidate follows a committed WFP transaction
  // with no tunnel permit. Recovery can still have the prior LUID's permit.
  const bool fresh_candidate = static_cast<bool>(pending_candidate_);
  worker_candidate_ = pending_candidate_ ? std::move(pending_candidate_)
      : PrepareWorkerCandidate(current_config_, socks_port_, *private_runtime_, asset_directory_, routing_intent_, routing_provenance_, username_, ipv6_tcp_scope_ ? &*ipv6_tcp_scope_ : nullptr);
  if (!worker_candidate_) return fail("Final VPN recovery configuration check failed");
  UINT64 current_identity = 0;
  const auto current_underlay = Underlay(&current_identity, underlay_family_);
  if (!current_underlay || *current_underlay != worker_candidate_->Underlay()
      || current_identity != worker_candidate_->Identity()) return fail("Checked VPN underlay changed before launch");
  underlay_name_ = worker_candidate_->Underlay();
  underlay_luid_ = worker_candidate_->Identity();
  const bool use_balancer_pipe = record_balancer_selections_.load();
  const bool use_native_routing = worker_candidate_->Routing();
  auto command = use_native_routing
      ? std::vector<std::wstring>{L"native-routing", L"run", L"--parent-stdin", L"--config", worker_candidate_->Path().wstring(),
          L"--spec", worker_candidate_->MetadataPath().wstring()}
      : std::vector<std::wstring>{L"run", L"-config", worker_candidate_->Path().wstring()};
  if (use_balancer_pipe) {
    command = {L"native-balancer", L"run", L"--config", worker_candidate_->Path().wstring(),
        L"--managed-inbound", native::Wide(routing_provenance_.managed_tag),
        L"--max-lines", std::to_wstring(options_.diagnostics_lines)};
    if (use_native_routing) {
      command.push_back(L"--spec");
      command.push_back(worker_candidate_->MetadataPath().wstring());
    }
  }
  using Clock = StartupTiming::Clock;
  NET_LUID previous_adapter{};
  DWORD previous_status = ERROR_NOT_FOUND;
  MIB_IF_ROW2 previous_row{};
  bool previous_identified = false;
  Clock::time_point tun_started{};
  const auto launch_tun = [&] {
    if (!requested_.load()) return fail("VPN startup cancelled");
    const auto config_started = Clock::now();
    // Credentials live only in a private file, never in the process command line.
    // The bundled tun2socks uses the "tun" driver on Windows too.
    std::string tun = "device: tun://flutter_vless_tun\nproxy: socks5://" + username_ + ":" + password_
        + "@127.0.0.1:" + std::to_string(socks_port_) + "\nloglevel: silent\nmtu: 1500\n";
    if (!private_runtime_->WriteConfig(tun, tun_config_path_)) return fail("Cannot write the private tun2socks configuration");
    previous_status = ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &previous_adapter);
    previous_row.InterfaceLuid = previous_adapter;
    previous_identified = previous_status == NO_ERROR && GetIfEntry2(&previous_row) == NO_ERROR;
    if (!requested_.load()) return fail("VPN startup cancelled");
    const auto spawn_started = Clock::now();
    tun2socks_process_ = native::Launch(tun2socks_executable_path_, {L"-config", tun_config_path_.wstring()});
    if (!tun2socks_process_) return fail("Cannot launch tun2socks");
    tun_started = Clock::now();
    timing.Record("tun_config", config_started, spawn_started);
    timing.Record("tun_spawn", spawn_started, tun_started);
    return true;
  };
  NET_LUID luid{};
  MIB_IF_ROW2 adapter{};
  std::optional<Clock::time_point> alias_seen, link_up;
  NET_LUID observed_luid{};
  const auto observe_adapter = [&] {
    if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &luid) != NO_ERROR) return false;
    if (!alias_seen || observed_luid.Value != luid.Value) {
      observed_luid = luid;
      alias_seen = Clock::now();
      link_up.reset();
    }
    adapter = {};
    adapter.InterfaceLuid = luid;
    if (GetIfEntry2(&adapter) != NO_ERROR || adapter.OperStatus != IfOperStatusUp) {
      link_up.reset();
      return false;
    }
    if (!link_up) link_up = Clock::now();
    return true;
  };
  if (!requested_.load()) return fail("VPN startup cancelled");
  timing.Mark("prepare_worker");
  xray_process_ = native::Launch(xray_executable_path_, command, use_balancer_pipe, asset_directory_,
      use_balancer_pipe || use_native_routing, use_balancer_pipe ? balancer_selection::kPipeBufferBytes : 0);
  if (!xray_process_) return fail("Cannot launch the protected Xray process");
  if (use_balancer_pipe) balancer_pipe_ = BalancerPipe::starting;
  timing.Mark("xray_spawn");
  const native::SocksReadinessBudget readiness_budget(std::chrono::milliseconds(6000), [this] { return !requested_.load(); });
  // Overlap adapter creation with Xray authentication on an admitted Start.
  // Under the no-tunnel WFP policy this worker only creates the private
  // device and rings. Address, DNS, routes and WFP admission stay below auth.
  if (fresh_candidate) {
    if (!protection_.Active()) return fail("Traffic protection is unavailable before Wintun launch");
    if (!launch_tun()) return false;
  }
  const auto xray_pid = GetProcessId(reinterpret_cast<HANDLE>(xray_process_->hProcess));
  std::vector<DWORD> listeners(1024);
  bool listening = false;
  while (readiness_budget.CanContinue() && requested_.load() && xray_process_->IsRunning()) {
    if (fresh_candidate) {
      if (!tun2socks_process_->IsRunning()) return fail("tun2socks exited before creating its adapter");
      observe_adapter();
    }
    // An early connect can idle inside Winsock before Xray has bound the
    // loopback port. Discover the listener first, then require SOCKS auth.
    if (OwnedListenerState(xray_pid, socks_port_, listeners) != ListenerState::missing &&
        readiness_budget.CanContinue() &&
        native::SocksReady(socks_port_, username_, password_, &readiness_budget)) {
      listening = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(20L, readiness_budget.PollMilliseconds())));
  }
  if (!requested_.load() || !readiness_budget.CanContinue()) return fail("VPN startup cancelled");
  if (!listening) {
    DWORD code = 0; GetExitCodeProcess(reinterpret_cast<HANDLE>(xray_process_->hProcess), &code);
    Event(("Authenticated Xray listener unavailable, process code=" + std::to_string(code)).c_str());
    return false;
  }
  Event("Authenticated Xray listener ready");
  timing.Mark("xray_listener");
  // Automatic recovery keeps adapter creation after authentication.
  if (!fresh_candidate && !launch_tun()) return false;
  bool adapter_ready = false;
  const auto adapter_deadline = tun_started + std::chrono::seconds(10);
  while (requested_.load() && Clock::now() < adapter_deadline) {
    if (!tun2socks_process_->IsRunning()) return fail("tun2socks exited before creating its adapter");
    if (observe_adapter()) { adapter_ready = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (!adapter_ready || !requested_.load()) return fail("Wintun adapter unavailable or startup cancelled");
  timing.Record("wintun_alias", tun_started, *alias_seen);
  timing.Record("wintun_link_up", *alias_seen, *link_up);
  timing.Mark("wintun_adapter");
  // Windows may reuse a recently retired adapter's LUID. A different
  // nonempty device GUID still identifies a distinct adapter instance.
  constexpr GUID empty_guid{};
  const bool changed_guid = previous_identified && !IsEqualGUID(previous_row.InterfaceGuid, empty_guid) &&
      !IsEqualGUID(adapter.InterfaceGuid, empty_guid) && !IsEqualGUID(previous_row.InterfaceGuid, adapter.InterfaceGuid);
  const bool new_adapter = previous_status == NO_ERROR
      ? previous_adapter.Value != luid.Value || changed_guid
      : (previous_status == ERROR_INVALID_PARAMETER || previous_status == ERROR_INVALID_NAME ||
         previous_status == ERROR_NOT_FOUND || previous_status == ERROR_FILE_NOT_FOUND);
  // Start IPv6 duplicate-address detection before configuring IPv4. Both
  // addresses must still reach Preferred on this exact adapter before capture.
  MIB_UNICASTIPADDRESS_ROW ipv6{}; InitializeUnicastIpAddressEntry(&ipv6);
  ipv6.InterfaceLuid = luid; ipv6.Address.Ipv6.sin6_family = AF_INET6;
  ipv6.OnLinkPrefixLength = 64;
  ipv6.PrefixOrigin = IpPrefixOriginManual; ipv6.SuffixOrigin = IpSuffixOriginManual;
  ipv6.ValidLifetime = ipv6.PreferredLifetime = 0xffffffff;
  ipv6.SkipAsSource = FALSE;
  // RFC 4429 recommends an address with a likely unique interface identifier.
  // Keep the conventional address and synchronous DAD on an unverified TUN.
  if (!new_adapter) Event("Tunnel adapter was reused or its identity was unknown; using synchronous IPv6 DAD");
  auto ipv6_source = new_adapter ? NewTunnelIPv6Address() : std::string();
  const bool fast_ipv6 = !ipv6_source.empty() &&
      InetPtonA(AF_INET6, ipv6_source.c_str(), &ipv6.Address.Ipv6.sin6_addr) == 1 && CanUseOptimisticDad(adapter, ipv6);
  const auto set_conventional_ipv6 = [&] {
    ipv6_source = "fd00:198:18::2";
    return InetPtonA(AF_INET6, ipv6_source.c_str(), &ipv6.Address.Ipv6.sin6_addr) == 1;
  };
  if (!fast_ipv6 && !set_conventional_ipv6()) return fail("Invalid owned Wintun IPv6 address");
  const auto default_ipv6_dad = ipv6.DadState;
  auto ipv6_status = CreateTunnelAddress(ipv6, fast_ipv6);
  if (fast_ipv6 && ipv6_status == ERROR_OBJECT_ALREADY_EXISTS) {
    // Another owner claimed the randomly selected address after inventory.
    // Leave it alone and fall back to the original synchronous address.
    ipv6.DadState = default_ipv6_dad;
    if (!set_conventional_ipv6()) return fail("Invalid owned Wintun IPv6 address");
    ipv6_status = CreateTunnelAddress(ipv6, false);
  }
  const bool optimistic_ipv6 = ipv6_status == NO_ERROR && ipv6.DadState == IpDadStatePreferred;
  if (ipv6_status == NO_ERROR) {
    ipv6_address_ = ipv6;
    Event(optimistic_ipv6 ? "Wintun IPv6 address configured with optimistic DAD"
                          : "Wintun IPv6 address configured via IP Helper");
  } else if (ipv6_status != ERROR_OBJECT_ALREADY_EXISTS) {
    Event(("Cannot assign the owned Wintun IPv6 address, code=" + std::to_string(ipv6_status)).c_str()); return false;
  }
  timing.Mark("ipv6_configure");
  if (!requested_.load() || !tun2socks_process_->IsRunning()) return fail("Wintun IPv4 setup cancelled");
  auto ipv4 = TunnelIPv4Address(luid);
  if (!new_adapter) Event("Tunnel adapter was reused or its identity was unknown; using synchronous IPv4 DAD");
  const auto ipv4_status = CreateTunnelAddress(ipv4, new_adapter && CanUseOptimisticDad(adapter, ipv4));
  if (ipv4_status == NO_ERROR) {
    ipv4_address_ = ipv4;
    Event(ipv4.DadState == IpDadStatePreferred
        ? "Wintun IPv4 address configured with optimistic DAD"
        : "Wintun IPv4 address configured via IP Helper");
  } else if (ipv4_status == ERROR_OBJECT_ALREADY_EXISTS) {
    Event("Reusing an existing Wintun IPv4 address");
  } else {
    // Keep the legacy path for a stack that rejects the temporary IP Helper
    // address. Ensure the alias still identifies the adapter we checked.
    NET_LUID current{};
    if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &current) != NO_ERROR || current.Value != luid.Value) {
      return fail("Wintun adapter changed during IPv4 setup");
    }
    Event("Wintun IPv4 address configuration falling back to netsh");
    native::SystemCommand(L"netsh.exe", {L"interface", L"ipv4", L"set", L"address",
        L"name=flutter_vless_tun", L"source=static", L"address=10.0.85.2", L"mask=255.255.255.0", L"gateway=none"});
  }
  timing.Mark("ipv4_configure");
  bool addressed = false;
  for (int i = 0; i < 150 && requested_.load() && tun2socks_process_->IsRunning(); ++i) {
    if (TunnelReady(ipv4)) { addressed = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!addressed) return fail("Wintun IPv4 address did not become ready");
  timing.Mark("ipv4_address");
  bool ipv6_ready = false;
  for (int i = 0; i < 50 && requested_.load() && tun2socks_process_->IsRunning(); ++i) {
    if (TunnelReady(ipv6)) { ipv6_ready = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!ipv6_ready) return fail("Wintun IPv6 address did not become ready");
  if (ipv6_status == ERROR_OBJECT_ALREADY_EXISTS) Event("Reusing the existing ready Wintun IPv6 address");
  timing.Mark("ipv6_address");
  if (!TunnelReady(ipv4)) return fail("Wintun IPv4 address lost readiness before installing routes");
  if (!SetTunnelDns(luid)) return fail("Wintun virtual DNS did not become ready");
  timing.Mark("adapter_dns");
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
  timing.Mark("routes_and_wfp");
  worker_candidate_->RemoveFile();
  native::RemovePrivateConfig(tun_config_path_);
  for (int i = 0; i < 10 && requested_.load() && xray_process_->IsRunning() && tun2socks_process_->IsRunning(); ++i) {
    if (worker_candidate_->PacketProbe().Check(PacketPathProbe::address, [this] { return !requested_.load(); }) &&
        (!optimistic_ipv6 || worker_candidate_->PacketProbe().Check(
            PacketPathProbe::ipv6_address, [this] { return !requested_.load(); }, ipv6_source.c_str()))) {
      if (!TunnelReady(ipv4) || !TunnelReady(ipv6)) return fail("Wintun address lost readiness during the packet check");
      timing.Mark("packet_path");
      if (report) *report = worker_candidate_->PreparationReport();
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return fail("Private packet-path challenge did not complete");
}
void VpnService::StopWorkers() {
  { std::lock_guard<std::mutex> lock(stats_mutex_); traffic_sample_ = {}; }
  { std::lock_guard<std::mutex> lock(balancer_mutex_); balancer_selections_.clear(); }
  balancer_pipe_ = BalancerPipe::none;
  // The separate WFP barrier remains installed, including during route removal.
  for (const auto& route : capture_routes_) DeleteIpForwardEntry2(&route);
  capture_routes_.clear();
  const bool ipv4_retired = RetireIPv4Address();
  const bool ipv6_retired = RetireIPv6Address();
  tun2socks_process_.reset(); xray_process_.reset();
  if (!ipv4_retired) RetireIPv4Address();
  if (!ipv6_retired) RetireIPv6Address(); // adapter teardown can complete a pending deletion
  worker_candidate_.reset();
  pending_candidate_.reset();
  flutter_vless::native::RemovePrivateConfig(tun_config_path_);
}
bool VpnService::RetireIPv6Address() {
  return RetireTunnelAddress(ipv6_address_, "IPv6");
}
bool VpnService::RetireIPv4Address() {
  return RetireTunnelAddress(ipv4_address_, "IPv4");
}
void VpnService::UpdateTrafficStats() {
  flutter_vless::traffic::Sample sample;
  flutter_vless::traffic::Stats stats;
  std::string output;
  if (api_port_ && !routing_provenance_.managed_tag.empty()
      && flutter_vless::native::Command(xray_executable_path_, {L"api", L"statsquery", L"-server=127.0.0.1:" + std::to_wstring(api_port_)}, output)
      && flutter_vless::traffic::ParseStats(output, stats))
    sample = flutter_vless::traffic::Select(stats, routing_provenance_.managed_tag);
  sample.observed_at = std::chrono::steady_clock::now();
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

void VpnService::UpdateBalancerSelections() {
  if (!xray_process_ || balancer_pipe_ == BalancerPipe::none) return;
  if (!record_balancer_selections_.load()) {
    flutter_vless::native::DisableBalancerSelections(*xray_process_);
    balancer_pipe_ = BalancerPipe::none;
    return;
  }
  if (balancer_pipe_ == BalancerPipe::unavailable) return;
  std::optional<std::string> rows;
  try {
    rows = flutter_vless::native::ReadBalancerSelections(*xray_process_, balancer_pipe_ == BalancerPipe::starting,
        static_cast<size_t>(options_.diagnostics_lines), static_cast<size_t>(options_.diagnostics_bytes),
        [this] { return !requested_.load(); });
  } catch (...) {} // An optional diagnostic must not affect VPN forwarding.
  balancer_pipe_ = rows ? BalancerPipe::active : BalancerPipe::unavailable;
  std::lock_guard<std::mutex> lock(balancer_mutex_);
  if (rows && record_balancer_selections_.load()) balancer_selections_ = std::move(*rows);
  else balancer_selections_.clear();
}

std::string VpnService::GetBalancerSelections() {
  std::lock_guard<std::mutex> lock(balancer_mutex_);
  return ready_.load() && record_balancer_selections_.load() ? balancer_selections_ : std::string{};
}

void VpnService::DisableBalancerSelections() {
  record_balancer_selections_.store(false);
  std::lock_guard<std::mutex> lock(balancer_mutex_);
  balancer_selections_.clear();
}
