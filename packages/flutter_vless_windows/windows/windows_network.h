#ifndef FLUTTER_VLESS_WINDOWS_NETWORK_H_
#define FLUTTER_VLESS_WINDOWS_NETWORK_H_

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <string>

namespace flutter_vless {
// Use the route selected by Windows, independently of display language and
// adapter ordering in ipconfig. Match the pre-tunnel interface selection.
inline std::string DefaultIpv4Gateway() {
  MIB_IPFORWARDROW route{};
  if (GetBestRoute(0x08080808, 0, &route) != NO_ERROR || route.dwForwardNextHop == 0) {
    return {};
  }
  char address[INET_ADDRSTRLEN]{};
  if (!InetNtopA(AF_INET, &route.dwForwardNextHop, address, sizeof(address))) return {};
  return address;
}
}  // namespace flutter_vless
#endif
