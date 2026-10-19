// Pure configuration and fake-kernel tests; no sockets or Core instance.
#include "xray_config.h"
#include <iostream>
#include <stdexcept>

namespace {
using namespace flutter_vless::xray_config;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
Json Source() {
  return Parse(R"({"inbounds":[{"listen":"127.0.0.1","port":18080,"protocol":"http","tag":"caller"}],"outbounds":[{"protocol":"freedom","tag":"direct"}],"dns":{"servers":["1.1.1.1"]},"routing":{"rules":[]}})");
}
std::optional<std::string> Prepare(const Json& source,
    const std::function<bool(uint16_t)>& available = {}, VpnRoutingProvenance* provenance = nullptr) {
  return PrepareProtectedVpn(source.dump(), "synthetic-user", "synthetic-password", "synthetic-underlay",
      [](const std::string&) { return std::string(); }, provenance, available);
}
void Tests() {
  const auto source = Source(); const auto original = source.dump();
  auto output = Prepare(source);
  Require(output && Port(Parse(*output)["inbounds"][0]) == 10807 && ApiPort(*output) == 10086,
      "file-only default changed");

  std::vector<uint16_t> checks;
  Require(AvailablePort(source, 10807, PortEnvironment, [&](uint16_t port) {
    checks.push_back(port); return port != 10807;
  }) == 10808 && checks == std::vector<uint16_t>{10807, 10808}, "occupied TCP candidate not skipped");

  checks.clear();
  output = Prepare(source, [&](uint16_t port) { checks.push_back(port); return port != 10807 && port != 10086; });
  Require(output && Port(Parse(*output)["inbounds"][0]) == 10808 && ApiPort(*output) == 10087
      && checks == std::vector<uint16_t>{10807, 10808, 10086, 10087}, "generated listeners ignored kernel policy");

  auto ranges = source; ranges["inbounds"][0]["port"] = "10807-10809";
  ranges["metrics"] = {{"listen", "127.0.0.1:10086"}, {"tag", "CallerMetrics"}};
  checks.clear();
  output = Prepare(ranges, [&](uint16_t port) { checks.push_back(port); return true; });
  Require(output && Port(Parse(*output)["inbounds"][0]) == 10810 && ApiPort(*output) == 10087
      && checks == std::vector<uint16_t>{10810, 10087}
      && Parse(*output)["inbounds"][1] == ranges["inbounds"][0] && Parse(*output)["metrics"] == ranges["metrics"],
      "caller ranges/metrics consumed callbacks or changed");
  const auto excluded = ListenerPortExclusions(Parse(*output));
  Require(excluded && *excluded == std::set<unsigned>{10086, 10087, 10807, 10808, 10809, 10810},
      "probe exclusions must contain caller ranges, metrics and both generated listeners");

  ranges["api"] = {{"tag", "caller-api"}, {"listen", "127.0.0.1:10088"}, {"services", Json::array({"StatsService"})}};
  checks.clear();
  output = Prepare(ranges, [&](uint16_t port) { checks.push_back(port); return true; });
  Require(output && Parse(*output)["api"] == ranges["api"] && checks == std::vector<uint16_t>{10810},
      "caller API caused a private API probe");

  checks.clear();
  Require(AvailablePort(source, 65535, PortEnvironment, [&](uint16_t port) {
    checks.push_back(port); return port == 1024;
  }) == 1024 && checks == std::vector<uint16_t>{65535, 1024}, "port traversal failed to wrap");

  auto exhausted = source; exhausted["inbounds"][0]["port"] = "10807-10816";
  VpnRoutingProvenance provenance; provenance.managed_tag = "prior-owner";
  checks.clear();
  output = Prepare(exhausted, [&](uint16_t port) { checks.push_back(port); return false; }, &provenance);
  Require(!output && checks.size() == 32 && checks.front() == 10817 && checks.back() == 10848
      && provenance.managed_tag == "prior-owner", "exhaustion exceeded32 or published candidate provenance");

  checks.clear();
  output = Prepare(source, [&](uint16_t port) { checks.push_back(port); return port >= 10807; });
  Require(!output && checks.size() == 33 && checks[0] == 10807 && checks[1] == 10086 && checks.back() == 10117,
      "private API exhaustion ignored its independent32-candidate bound");
  Require(source.dump() == original, "caller source changed");
}
}
int main() try { Tests(); std::cout << "WINDOWS_PRIVATE_PORT_ADMISSION_PURE_PASS=8\n"; }
catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
