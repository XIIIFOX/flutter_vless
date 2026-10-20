#include "xray_config.h"

#include <fstream>
#include <iostream>
#include <iterator>

// Actual production preparation only. Every allocation/lookup boundary is fake;
// no Core, socket, DNS resolver or Windows service is linked or started here.
int main(int argc, char** argv) {
  using namespace flutter_vless::xray_config;
  if (argc != 3 || std::string(argv[1]) == argv[2]) return 2;
  std::ifstream input(argv[1], std::ios::binary);
  if (!input.good()) return 2;
  const std::string source{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  unsigned resolver_calls = 0, availability_calls = 0;
  const auto prepared = PrepareProtectedVpn(source, "inert-user", "inert-password", "inert-interface",
      [&](const std::string&) { ++resolver_calls; return std::string(); }, nullptr,
      [&](uint16_t) { ++availability_calls; return true; });
  bool dns_equal = false;
  if (prepared) {
    dns_equal = Parse(source)["dns"] == Parse(*prepared)["dns"];
    std::ofstream output(argv[2], std::ios::binary);
    output << *prepared;
    if (!output.good()) return 4;
  }
  std::cout << Json{{"accepted", prepared.has_value()}, {"resolver_calls", resolver_calls},
      {"availability_calls", availability_calls}, {"dns_equal", dns_equal}}.dump() << '\n';
  return prepared ? 0 : 3;
}
