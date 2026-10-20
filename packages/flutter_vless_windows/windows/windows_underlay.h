#pragma once
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <optional>
#include <string>
#include <cstdint>

namespace flutter_vless::native {
inline std::optional<std::string> SelectUnderlay(ADDRESS_FAMILY family, UINT64* identity = nullptr) {
  if (identity) *identity = 0;
  if (family != AF_INET && family != AF_INET6) return std::nullopt;

  // Select a usable default without allowing our own more-specific capture
  // routes to become the next transport's underlay. Include adapter metrics.
  MIB_IPFORWARD_TABLE2* routes = nullptr;
  if (GetIpForwardTable2(family, &routes) != NO_ERROR) return std::nullopt;
  std::optional<std::string> result;
  uint64_t best = UINT64_MAX;
  for (ULONG i = 0; i < routes->NumEntries; ++i) {
    const auto& route = routes->Table[i];
    if (route.DestinationPrefix.PrefixLength != 0) continue;
    MIB_IF_ROW2 row{}; row.InterfaceLuid = route.InterfaceLuid;
    if (GetIfEntry2(&row) != NO_ERROR || row.OperStatus != IfOperStatusUp
        || std::wstring(row.Alias) == L"flutter_vless_tun") continue;
    MIB_IPINTERFACE_ROW ip{}; InitializeIpInterfaceEntry(&ip);
    ip.Family = family; ip.InterfaceLuid = row.InterfaceLuid;
    if (GetIpInterfaceEntry(&ip) != NO_ERROR) continue;
    const uint64_t metric = static_cast<uint64_t>(route.Metric) + ip.Metric;
    if (metric >= best) continue;
    int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) continue;
    std::string name(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, name.data(), size, nullptr, nullptr);
    name.pop_back(); result = name; best = metric;
    if (identity) *identity = row.InterfaceLuid.Value;
  }
  FreeMibTable(routes);
  return result;

}
}  // namespace flutter_vless::native
