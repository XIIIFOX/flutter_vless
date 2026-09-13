#include "traffic_protection.h"
#include <fwpmu.h>
#include <fwpmtypes.h>
#include "wfp_compat.h"
#include <vector>
#include <sddl.h>

namespace flutter_vless {
namespace {
const GUID provider = {0x258726c7,0x1b37,0x4524,{0xb4,0x53,0x80,0x7a,0xe3,0x17,0x39,0x06}};
const GUID sublayer = {0x8e68fa20,0x8c47,0x452d,{0xb5,0x16,0x82,0x25,0x13,0x38,0x80,0x7d}};
std::wstring DhcpServiceSid() {
  DWORD bytes = 0, domain_chars = 0; SID_NAME_USE use{};
  LookupAccountNameW(nullptr, L"NT SERVICE\\Dhcp", nullptr, &bytes, nullptr, &domain_chars, &use);
  if (!bytes) return {};
  std::vector<unsigned char> sid(bytes); std::vector<wchar_t> domain(domain_chars);
  if (!LookupAccountNameW(nullptr, L"NT SERVICE\\Dhcp", sid.data(), &bytes, domain.data(), &domain_chars, &use)) return {};
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(sid.data(), &text)) return {};
  std::wstring result(text); LocalFree(text); return result;
}
}
bool TrafficProtection::Open() {
  if (engine_) return true;
  owner_ = CreateEventW(nullptr, TRUE, FALSE, L"Global\\FlutterVlessProtectedVpn");
  if (!owner_) { last_error_.store(GetLastError()); return false; }
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    last_error_.store(ERROR_ALREADY_EXISTS); CloseHandle(owner_); owner_ = nullptr; return false;
  }
  if (!Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine_))) {
    CloseHandle(owner_); owner_ = nullptr; return false;
  }
  return true;
}
TrafficProtection::~TrafficProtection() {
  // No implicit release on failure/unwind: WFP must outlive the native workers.
  if (engine_) FwpmEngineClose0(engine_);
  if (owner_) { CloseHandle(owner_); }
}
bool TrafficProtection::OwnedFilterIds(std::vector<UINT64>& ids) {
  // A null enumeration template covers all layers/actions and also works on a
  // first launch, when our provider does not exist. Only our exact provider
  // GUID is retained; no foreign filter can be removed by cleanup.
  ids.clear();
  HANDLE enumeration = nullptr;
  if (!Check(FwpmFilterCreateEnumHandle0(engine_, nullptr, &enumeration))) return false;
  bool ok = true;
  for (;;) {
    FWPM_FILTER0** entries = nullptr; UINT32 count = 0;
    if (!Check(FwpmFilterEnum0(engine_, enumeration, 256, &entries, &count))) { ok = false; break; }
    for (UINT32 i = 0; i < count; ++i) {
      if (entries[i]->providerKey && IsEqualGUID(*entries[i]->providerKey, provider)) ids.push_back(entries[i]->filterId);
    }
    if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
    if (count == 0) break;
  }
  FwpmFilterDestroyEnumHandle0(engine_, enumeration);
  return ok;
}
bool TrafficProtection::Inspect() {
  if (!Open()) return false;
  std::vector<UINT64> ids;
  if (!OwnedFilterIds(ids)) return false;
  active_ = !ids.empty();
  return true;
}
bool TrafficProtection::DeleteFilters() {
  std::vector<UINT64> ids;
  if (!OwnedFilterIds(ids)) return false;
  for (auto id : ids) if (!Check(FwpmFilterDeleteById0(engine_, id))) return false;
  return true;
}
bool TrafficProtection::Install(const std::filesystem::path& xray, const NET_LUID* tunnel) {
  if (!Open() || !Check(FwpmTransactionBegin0(engine_, 0))) return false;
  FWPM_PROVIDER0 p{}; p.providerKey = provider;
  p.displayData.name = const_cast<wchar_t*>(L"Flutter Vless traffic protection");
  p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
  auto status = FwpmProviderAdd0(engine_, &p, nullptr);
  bool ok = status == FWP_E_ALREADY_EXISTS || Check(status);
  FWPM_SUBLAYER0 layer{}; layer.subLayerKey = sublayer;
  layer.providerKey = const_cast<GUID*>(&provider);
  layer.displayData.name = p.displayData.name;
  layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT; layer.weight = 0xffff;
  status = FwpmSubLayerAdd0(engine_, &layer, nullptr);
  ok = ok && (status == FWP_E_ALREADY_EXISTS || Check(status)) && DeleteFilters();
  FWP_BYTE_BLOB* app = nullptr;
  ok = ok && Check(FwpmGetAppIdFromFileName0(xray.c_str(), &app));
  PSECURITY_DESCRIPTOR administrator = nullptr, dhcp = nullptr;
  FWP_BYTE_BLOB administrator_blob{}, dhcp_blob{};
  ULONG administrator_size = 0, dhcp_size = 0;
  // MATCH_FILTER is bit 1. Filtered UAC tokens have Administrators deny-only,
  // so launching the same image unelevated does not satisfy this descriptor.
  ok = ok && ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;CC;;;BA)(A;;CC;;;SY)",
      SDDL_REVISION_1, &administrator, &administrator_size);
  administrator_blob.size = administrator_size;
  administrator_blob.data = static_cast<UINT8*>(administrator);
  const auto dhcp_sid = dhcp_sid_ ? dhcp_sid_() : DhcpServiceSid();
  FWP_BYTE_BLOB* service_app = nullptr;
  wchar_t system[MAX_PATH + 1]{};
  bool allow_dhcp = !dhcp_sid.empty() && GetSystemDirectoryW(system, MAX_PATH)
      && ConvertStringSecurityDescriptorToSecurityDescriptorW((L"D:(A;;CC;;;" + dhcp_sid + L")").c_str(),
          SDDL_REVISION_1, &dhcp, &dhcp_size)
      && FwpmGetAppIdFromFileName0((std::filesystem::path(system) / L"svchost.exe").c_str(), &service_app) == ERROR_SUCCESS;
  dhcp_blob.data = static_cast<UINT8*>(dhcp);
  dhcp_blob.size = dhcp_size;
  auto add = [&](const GUID& where, FWP_ACTION_TYPE action, UINT64 weight,
                 std::vector<FWPM_FILTER_CONDITION0> conditions) {
    if (!ok) return;
    FWPM_FILTER0 filter{};
    filter.displayData.name = p.displayData.name;
    filter.providerKey = const_cast<GUID*>(&provider);
    filter.layerKey = where; filter.subLayerKey = sublayer;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.weight.type = FWP_UINT64; filter.weight.uint64 = &weight;
    filter.action.type = action;
    filter.numFilterConditions = static_cast<UINT32>(conditions.size());
    filter.filterCondition = conditions.data();
    ok = Check(FwpmFilterAdd0(engine_, &filter, nullptr, nullptr));
  };
  FWPM_FILTER_CONDITION0 loop{};
  loop.fieldKey = FWPM_CONDITION_FLAGS; loop.matchType = FWP_MATCH_FLAGS_ALL_SET;
  loop.conditionValue.type = FWP_UINT32; loop.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
  FWPM_FILTER_CONDITION0 application{};
  application.fieldKey = FWPM_CONDITION_ALE_APP_ID; application.matchType = FWP_MATCH_EQUAL;
  application.conditionValue.type = FWP_BYTE_BLOB_TYPE; application.conditionValue.byteBlob = app;
  FWPM_FILTER_CONDITION0 elevated{}, service{}, service_image = application;
  elevated.fieldKey = FWPM_CONDITION_ALE_USER_ID; elevated.matchType = FWP_MATCH_EQUAL;
  elevated.conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE; elevated.conditionValue.sd = &administrator_blob;
  service = elevated; service.conditionValue.sd = &dhcp_blob;
  service_image.conditionValue.byteBlob = service_app;
  UINT64 luid = tunnel ? tunnel->Value : 0;
  FWPM_FILTER_CONDITION0 interface_{};
  interface_.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE; interface_.matchType = FWP_MATCH_EQUAL;
  interface_.conditionValue.type = FWP_UINT64; interface_.conditionValue.uint64 = &luid;
  for (auto where : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
    add(where, FWP_ACTION_PERMIT, 100, {loop});
    // Only Xray may leave via the underlay. It carries the VPN transport and
    // user-selected direct rules; all its listeners require session auth.
    add(where, FWP_ACTION_PERMIT, 90, {application, elevated});
    if (tunnel) add(where, FWP_ACTION_PERMIT, 80, {interface_});
    // DHCP renewals are network maintenance, never general DNS exceptions.
    FWPM_FILTER_CONDITION0 protocol{}, local{}, remote{};
    protocol.fieldKey = FWPM_CONDITION_IP_PROTOCOL; protocol.matchType = FWP_MATCH_EQUAL;
    protocol.conditionValue.type = FWP_UINT8; protocol.conditionValue.uint8 = IPPROTO_UDP;
    local.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT; local.matchType = FWP_MATCH_EQUAL;
    local.conditionValue.type = FWP_UINT16; local.conditionValue.uint16 = 68;
    remote.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT; remote.matchType = FWP_MATCH_EQUAL;
    remote.conditionValue.type = FWP_UINT16; remote.conditionValue.uint16 = 67;
    if (allow_dhcp) add(where, FWP_ACTION_PERMIT, 70, {protocol, local, remote, service_image, service});
    add(where, FWP_ACTION_BLOCK, 1, {});
  }
  // No physical IPv6 exception for Xray, sniffed names, applications binding
  // their own interface, or a newly attached adapter. IPv4 VPN works normally.
  for (auto where : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    add(where, FWP_ACTION_PERMIT, 100, {loop});
    add(where, FWP_ACTION_BLOCK, 1, {});
  }
  if (app) FwpmFreeMemory0(reinterpret_cast<void**>(&app));
  if (service_app) FwpmFreeMemory0(reinterpret_cast<void**>(&service_app));
  if (administrator) LocalFree(administrator);
  if (dhcp) LocalFree(dhcp);
  if (!ok) { FwpmTransactionAbort0(engine_); return false; }
  if (!Check(FwpmTransactionCommit0(engine_))) return false;
  active_ = true;
  return true;
}
bool TrafficProtection::Release() {
  // Also recovers this policy after a previous application crash.
  if (!Open() || !Check(FwpmTransactionBegin0(engine_, 0))) return false;
  if (!DeleteFilters()) { FwpmTransactionAbort0(engine_); return false; }
  auto result = FwpmTransactionCommit0(engine_);
  if (!Check(result)) return false;
  active_ = false;
  FwpmEngineClose0(engine_); engine_ = nullptr;
  CloseHandle(owner_); owner_ = nullptr;
  return true;
}
}  // namespace flutter_vless
