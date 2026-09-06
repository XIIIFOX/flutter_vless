#include "xray_config.h"
#include <iostream>
#include <stdexcept>

using namespace flutter_vless::xray_config;
void Check(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
int main() {
  const std::string original = R"({
    "outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":18582}]},"tag":"proxy"},{"tag":"direct","protocol":"freedom"}],
    "inbounds":[{"port":18580,"settings":{"nested":{"port":18582}},"protocol":"socks","tag":"socks-in"}],
    "routing":{"domainStrategy":"AsIs","rules":[{"domain":["domain:ru","domain:io"],"outboundTag":"direct"}]},
    "dns":{"queryStrategy":"UseIPv4"},
    "policy":{"levels":{"8":{"bufferSize":3}}},
    "remarks":"Escaped braces { } and a quote: \""
  })";
  Check(SocksPort(original) == 18580, "inbound order must not select outbound port");
  std::string prepared = original;
  int allocations = 0;
  Check(PrepareProxy(prepared, [](uint16_t p) { return p != 18582; },
      [&]() { ++allocations; return uint16_t{19000}; }), "proxy preparation");
  Check(allocations == 0, "occupied remote and nested ports must not be probed");
  auto before = Parse(original); auto after = Parse(prepared);
  Check(after["outbounds"] == before["outbounds"], "outbound preservation");
  Check(after["routing"] == before["routing"], "routing preservation");
  Check(after["policy"]["levels"] == before["policy"]["levels"], "policy preservation");
  Check(after["api"]["listen"] == "127.0.0.1:10085", "API without log section");
  Check(PrepareProxy(prepared, [](uint16_t p) { return p != 18580; },
      []() { return uint16_t{19000}; }), "inbound conflict preparation");
  Check(SocksPort(prepared) == 19000, "occupied inbound remapped");
  Check(Parse(prepared)["outbounds"] == before["outbounds"], "server untouched after remap");
  auto vpn = PrepareVpn(original);
  Check(vpn.has_value(), "VPN preparation");
  after = Parse(*vpn);
  Check(after["routing"] == before["routing"], "VPN domain rules preserved");
  Check(after["dns"] == before["dns"], "VPN DNS preserved");
  Check(after["outbounds"] == before["outbounds"], "VPN outbounds preserved");
  Check(after["api"]["listen"] == "127.0.0.1:10086", "VPN API listener");
  Check(PrepareVpn(*vpn) == vpn, "VPN preparation is idempotent");
  Check(!SocksPort(R"({"outbounds":[{"protocol":"socks","port":443}]})"), "missing inbound");
  Check(!PrepareVpn("{bad json}"), "invalid JSON rejected");
  Check(!PrepareVpn(R"({"inbounds":[{"protocol":"socks","port":65536}]})"), "invalid port rejected");
  std::cout << "Windows Xray configuration regression tests passed\n";
}
