// Actual selector with IP Helper calls recorded; no interfaces or sockets.
#define IPHLPAPI_DLL_LINKAGE
#include "windows_underlay.h"
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>

namespace {
struct Adapter { UINT64 luid; ULONG route_metric, interface_metric; std::wstring alias; bool up = true; };
std::map<ADDRESS_FAMILY, std::vector<Adapter>> tables;
ADDRESS_FAMILY requested = AF_UNSPEC;
unsigned allocations = 0, releases = 0;
const Adapter* adapter(UINT64 luid) {
  for (const auto& item : tables[requested]) if (item.luid == luid) return &item;
  return nullptr;
}
}
extern "C" {
NETIO_STATUS WINAPI GetIpForwardTable2(ADDRESS_FAMILY family, PMIB_IPFORWARD_TABLE2* out) {
  requested = family;
  const auto& rows = tables[family];
  const auto bytes = offsetof(MIB_IPFORWARD_TABLE2, Table) + rows.size() * sizeof(MIB_IPFORWARD_ROW2);
  *out = static_cast<PMIB_IPFORWARD_TABLE2>(std::calloc(1, std::max(bytes, sizeof(MIB_IPFORWARD_TABLE2))));
  ++allocations; (*out)->NumEntries = static_cast<ULONG>(rows.size());
  for (size_t i = 0; i < rows.size(); ++i) {
    auto& row = (*out)->Table[i]; row.InterfaceLuid.Value = rows[i].luid;
    row.DestinationPrefix.Prefix.si_family = family; row.DestinationPrefix.PrefixLength = 0;
    row.Metric = rows[i].route_metric;
  }
  return NO_ERROR;
}
NETIO_STATUS WINAPI GetIfEntry2(PMIB_IF_ROW2 row) {
  const auto* value = adapter(row->InterfaceLuid.Value); if (!value) return ERROR_NOT_FOUND;
  row->OperStatus = value->up ? IfOperStatusUp : IfOperStatusDown;
  std::copy(value->alias.begin(), value->alias.end(), row->Alias);
  row->Alias[value->alias.size()] = 0;
  return NO_ERROR;
}
NETIO_STATUS WINAPI GetIpInterfaceEntry(PMIB_IPINTERFACE_ROW row) {
  assert(row->Family == requested);
  const auto* value = adapter(row->InterfaceLuid.Value); if (!value) return ERROR_NOT_FOUND;
  row->Metric = value->interface_metric; return NO_ERROR;
}
VOID WINAPI InitializeIpInterfaceEntry(PMIB_IPINTERFACE_ROW row) { std::memset(row, 0, sizeof(*row)); }
VOID WINAPI FreeMibTable(PVOID memory) { ++releases; std::free(memory); }
}
int main() {
  using flutter_vless::native::SelectUnderlay;
  tables[AF_INET6] = {{21, 5, 30, L"v6 slow"}, {22, 15, 2, L"v6 selected"},
      {23, 0, 0, L"flutter_vless_tun"}, {24, 0, 0, L"v6 down", false}};
  UINT64 identity = 0;
  const auto first = SelectUnderlay(AF_INET6, &identity);
  assert(first && *first == "v6 selected" && identity == 22 && requested == AF_INET6);
  assert(allocations == releases);
  tables[AF_INET] = {{31, 1, 1, L"IPv4 retained"}};
  assert(SelectUnderlay(AF_INET, &identity) == "IPv4 retained" && identity == 31);
  tables[AF_INET6].erase(tables[AF_INET6].begin() + 1);
  assert(SelectUnderlay(AF_INET6, &identity) == "v6 slow" && identity != 22); // caller must reject stale checked LUID
  tables[AF_INET6].clear(); identity = 999;
  assert(!SelectUnderlay(AF_INET6, &identity) && identity == 0 && allocations == releases);
  const auto before = allocations;
  assert(!SelectUnderlay(AF_UNSPEC, &identity) && allocations == before);
  std::cout << "WINDOWS_NUMERIC_IPV6_UNDERLAY_PASS=1\n";
}
