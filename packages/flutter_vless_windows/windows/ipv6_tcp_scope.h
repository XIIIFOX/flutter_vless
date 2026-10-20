#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace flutter_vless {
struct Ipv6TcpEndpoint {
  std::array<uint8_t, 16> address{};
  uint16_t port = 0;
  bool operator==(const Ipv6TcpEndpoint& other) const { return address == other.address && port == other.port; }
};
struct Ipv6TcpScope {
  uint64_t interface_luid = 0;
  std::vector<Ipv6TcpEndpoint> endpoints;
};
// A finite underlay TCP exception, never a wildcard, scoped literal, mapped-v4,
// local listener, multicast or link-local claim. ULA is allowed for owned CI.
inline bool ValidOuterIpv6(const std::array<uint8_t, 16>& address) {
  bool first_ten_zero = true, first_fifteen_zero = true;
  for (std::size_t i = 0; i < 10; ++i) first_ten_zero = first_ten_zero && address[i] == 0;
  for (std::size_t i = 0; i < 15; ++i) first_fifteen_zero = first_fifteen_zero && address[i] == 0;
  return !(first_fifteen_zero && address[15] <= 1)
      && !(first_ten_zero && address[10] == 0xff && address[11] == 0xff)
      && address[0] != 0xff && !(address[0] == 0xfe && (address[1] & 0xc0) == 0x80);
}
}  // namespace flutter_vless
