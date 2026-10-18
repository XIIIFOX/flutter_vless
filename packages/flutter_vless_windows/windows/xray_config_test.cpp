#include "xray_config.h"
#include <iostream>
#include <stdexcept>
#include <fstream>

using namespace flutter_vless::xray_config;
void Check(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
int main() {
  std::ifstream api_input("tool/fixtures/compatibility/api-listeners.json");
  Check(api_input.good(), "shared API listener corpus is required");
  Json api_cases; api_input >> api_cases;
  for (const auto& item : api_cases) {
    const auto before = item["config"].dump();
    Check(ApiListenerPorts(item["config"]) == item["ports"].get<std::set<unsigned>>(), item["name"].get<std::string>().c_str());
    Check(item["config"].dump() == before, "API reservation mutated source");
  }
  auto api_profile = Parse(R"({"api":{"listen":"127.0.0.1:10808"},"inbounds":[{"protocol":"http","port":"10809-10810"}]})");
  Check(AvailablePort(api_profile, 10808) == 10811, "private port collided with API/ranges");
  std::ifstream metrics_input("tool/fixtures/compatibility/metrics-listeners.json");
  Check(metrics_input.good(), "shared metrics listener corpus is required");
  Json metrics_cases; metrics_input >> metrics_cases;
  for (const auto& item : metrics_cases) {
    const auto before = item["config"].dump();
    Check(ServiceListenerPorts(item["config"]) == item["ports"].get<std::set<unsigned>>(), item["name"].get<std::string>().c_str());
    Check(item["config"].dump() == before, "service listener reservation mutated source");
  }
  auto metrics_profile = Parse(u8R"({"api":{"listen":"127.0.0.1:10807"},"Metricſ":{"Liſten":"127.0.0.1:10811"},"inbounds":[{"protocol":"http","port":"10808-10810"}]})");
  const auto metrics_before = metrics_profile.dump();
  Check(AvailablePort(metrics_profile, 10807) == 10812, "private port collided with metrics/API/ranges");
  Check(metrics_profile.dump() == metrics_before, "private allocation mutated metrics config");
  std::ifstream tag_input("tool/fixtures/compatibility/tags.json");
  Check(tag_input.good(), "shared tag corpus is required");
  Json tag_cases; tag_input >> tag_cases;
  for (const auto& item : tag_cases) {
    const auto before = item["config"].dump();
    ServiceTags tags(item["config"]);
    for (size_t i = 0; i < item["requests"].size(); ++i)
      Check(tags.Next(item["requests"][i].get<std::string>()) == item["expected"][i], item["name"].get<std::string>().c_str());
    Check(item["config"].dump() == before, "tag allocation mutated user config");
  }
  std::ifstream input("tool/fixtures/compatibility/ports.json");
  Check(input.good(), "shared port corpus is required");
  Json cases; input >> cases;
  for (const auto& item : cases) {
    auto environment = item.value("environment", Json::object());
    auto ports = ReservedPorts(item["value"], [&](const std::string& name) -> std::optional<std::string> {
      return environment.contains(name) ? std::optional<std::string>{environment[name].get<std::string>()} : std::nullopt;
    });
    if (item.value("invalid", false)) Check(!ports, item["name"].get<std::string>().c_str());
    else Check(ports && *ports == item["ports"].get<std::set<unsigned>>(), item["name"].get<std::string>().c_str());
  }
  auto unix_profile = Parse(R"({"inbounds":[{"protocol":"http","listen":"@flutter-vless-port-corpus","port":"0-65535"}]})");
  Check(AvailablePort(unix_profile, 10808) == 10808, "Unix PortList must not reserve TCP ports");
#ifdef _WIN32
  auto unicode_unix_profile = Parse(u8R"({"inbounds":[{"protocol":"http","listen":"C:\\тест\\socket","port":"0-65535"}]})");
  Check(AvailablePort(unicode_unix_profile, 10808) == 10808, "UTF-8 Windows Unix path must be classified without opening it");
#endif
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
  auto metrics_proxy = before;
  metrics_proxy[u8"Metricſ"] = {{u8"Liſten", "127.0.0.1:10085"}, {"tag", "caller-metrics"}};
  auto metrics_text = metrics_proxy.dump();
  Check(PrepareProxy(metrics_text, [](uint16_t) { return true; }, []() { return uint16_t{19000}; }), "proxy metrics reservation");
  Check(ApiPort(metrics_text) == 10086, "proxy stats API collided with caller metrics");
  Check(Parse(metrics_text)[u8"Metricſ"] == metrics_proxy[u8"Metricſ"], "proxy preparation changed metrics");
  metrics_text = metrics_proxy.dump();
  int attempts = 0;
  Check(!PrepareProxy(metrics_text, [](uint16_t p) { return p != 10086; }, [&]() { ++attempts; return uint16_t{10085}; }), "declared metrics port accepted as OS-free fallback");
  Check(attempts == 32 && metrics_text == metrics_proxy.dump(), "proxy allocation retry was unbounded or changed rejected source");
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
  std::string bound = *vpn;
  Check(BindDirectOutbounds(bound, "Ethernet"), "bind direct transport");
  after = Parse(bound);
  Check(after["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "direct uses underlay");
  Check(after["outbounds"][0] == before["outbounds"][0], "proxy transport preserved");
  Check(after["routing"] == before["routing"], "binding preserves domain rules");
  Check(BindDirectOutbounds(bound, "Wi-Fi"), "preserve explicit interface");
  Check(Parse(bound)["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "explicit binding respected");
  Check(!BindDirectOutbounds(bound, ""), "missing underlay rejected");
  Check(!SocksPort(R"({"outbounds":[{"protocol":"socks","port":443}]})"), "missing inbound");
  Check(!PrepareVpn("{bad json}"), "invalid JSON rejected");
  Check(!PrepareVpn(R"({"inbounds":[{"protocol":"socks","port":65536}]})"), "invalid port rejected");
  for (unsigned occupied : {10807u, 10086u}) {
    auto with_metrics = before;
    with_metrics[u8"Metricſ"] = {{u8"Liſten", "127.0.0.1:" + std::to_string(occupied)}, {"tag", "caller-metrics"}};
    const auto result = PrepareProtectedVpn(with_metrics.dump(), "native-user", "native-password", "Ethernet",
        [](const std::string&) { return std::string(); });
    Check(result.has_value(), "protected VPN rejected imported metrics listener");
    const auto effective = Parse(*result);
    Check(effective[u8"Metricſ"] == with_metrics[u8"Metricſ"], "protected VPN changed caller metrics listener");
    Check(effective["inbounds"][0]["port"] == (occupied == 10807 ? 10808 : 10807), "managed VPN input collided with metrics");
    Check(ApiPort(*result) == (occupied == 10086 ? 10087 : 10086), "managed VPN stats API collided with metrics");
  }
  std::cout << "Windows Xray configuration regression tests passed\n";
}
