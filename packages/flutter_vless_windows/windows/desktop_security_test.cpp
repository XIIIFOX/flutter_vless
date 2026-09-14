#include "xray_config.h"
#include <iostream>
#include <stdexcept>
using namespace flutter_vless::xray_config;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main() {
  const auto source = Parse(R"({
    "log":{"access":"private-canary.log","error":"secret.log","loglevel":"debug","dnsLog":true},
    "inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":18580,"tag":"socks-in","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":false}}],
    "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"endpoint.invalid","port":443,"users":[{"id":"private-remote-credential","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"remote-public-key","serverName":"sni.invalid","show":true},"tlsSettings":{"masterKeyLog":"tls-canary.log"}}},{"tag":"direct","protocol":"freedom"}],
    "routing":{"rules":[{"type":"field","domain":["domain:ru","domain:io"],"outboundTag":"direct"},{"type":"field","domain":["domain:myip.com"],"outboundTag":"proxy"}]},
    "dns":{"servers":["localhost","8.8.8.8"]}
  })");
  unsigned lookups = 0;
  auto prepare = [&](const Json& json) {
    return PrepareProtectedVpn(json.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      ++lookups; return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  auto result = prepare(source); Require(result.has_value(), "valid Reality profile rejected");
  auto config = Parse(*result);
  Require(lookups == 1, "bootstrap queried something other than endpoint");
  Require(config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"], "remote credentials/domain were changed");
  Require(config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] == "sni.invalid", "SNI changed");
  Require(config["log"]["access"] == "none" && config["log"]["error"] == "none" && config["log"]["dnsLog"] == false, "file log escape");
  Require(config["outbounds"][0]["streamSettings"]["realitySettings"]["show"] == false, "Reality debug escape");
  Require(config["outbounds"][0]["streamSettings"]["tlsSettings"]["masterKeyLog"] == "", "TLS key log escape");
  Require(config["dns"]["servers"] == Json::array({"tcp://1.1.1.1"}) && config["dns"]["disableFallback"] == true, "physical resolver fallback");
  Require(config["dns"]["hosts"]["endpoint.invalid"] == "192.0.2.5", "bootstrap pin missing");
  Require(config["inbounds"][0]["settings"]["auth"] == "password", "unauthenticated VPN listener");
  Require(config["inbounds"][0]["sniffing"]["routeOnly"] == true, "IPv6 sniffing replaces target");
  auto rules = config["routing"]["rules"];
  Require(rules[0]["ip"] == Json::array({"::/0"}), "IPv6 does not precede bypass rules");
  Require(rules[1]["inboundTag"] == Json::array({kDnsUpstream}) && rules[1]["outboundTag"] == "proxy", "internal DNS not proxied");
  Require(rules[2]["outboundTag"] == kDnsRelay, "system DNS not relayed");
  const auto relay = std::find_if(config["outbounds"].begin(), config["outbounds"].end(),
      [](const Json& outbound) { return outbound.value("tag", "") == kDnsRelay; });
  Require(relay != config["outbounds"].end(), "missing DNS relay");
  Require(!relay->contains("proxySettings"), "removed proxySettings emitted");
  Require((*relay)["streamSettings"]["sockopt"]["dialerProxy"] == "proxy", "DNS relay chain missing");
  Require((*relay)["settings"]["rules"] == Json::array({
      {{"action", "return"}, {"qType", "28"}, {"rCode", 0}}, {{"action", "direct"}}}),
      "IPv4-only DNS must return AAAA NODATA before relaying other query types");
  Require(rules[3] == source["routing"]["rules"][0] && rules[4] == source["routing"]["rules"][1], "domain bypass rules reordered or removed");
  Require(config["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "direct sockets reenter capture");
  for (const auto& key : {"FakeDNS", "fakedns", "fakeDnS"}) {
    auto bad = source; bad[key] = Json::array(); Require(!prepare(bad), "FakeDNS alias bypassed IPv6 policy");
  }
  for (const auto& key : {"Listen", "Li\xC5\xBFten"}) {
    auto bad = source; bad["inbounds"][0][key] = "0.0.0.0"; Require(!prepare(bad), "ambiguous listen accepted");
  }
  auto bad = source; bad["inbounds"].push_back(bad["inbounds"][0]); Require(!prepare(bad), "extra listener accepted");
  bad = source; bad["outbounds"][0]["tag"] = kDnsRelay; Require(!prepare(bad), "reserved tag accepted");
  bad = source; bad["outbounds"][0]["settings"]["vnext"][0]["address"] = "2001:db8::1"; Require(!prepare(bad), "unsupported IPv6 endpoint accepted");
  bad = source; bad["outbounds"][0]["streamSettings"]["sockopt"] = {{"addressPortStrategy", "srv"}}; Require(!prepare(bad), "system SRV resolver accepted");
  auto aliases = source;
  aliases["INBOUNDS"] = aliases["inbounds"]; aliases.erase("inbounds");
  aliases["OUTBOUNDS"] = aliases["outbounds"]; aliases.erase("outbounds");
  Require(prepare(aliases).has_value(), "unambiguous Go field aliases rejected");
  Require(Parse(R"({"a":1,"a":2})").is_discarded(), "duplicate JSON field accepted");
  for (const auto& invalid : {"::/0", "1.2.3.4/33", "1.2.3.4/24/0", "1.2.3.4", "1.2.3.4/-1"})
    Require(!ApplyBypass(source.dump(), {invalid}), "invalid bypass CIDR accepted");
  auto bypass = ApplyBypass(source.dump(), {"0.0.0.0/0", "192.168.0.0/16"});
  Require(bypass.has_value(), "valid CIDRs rejected");
  auto protected_bypass = prepare(Parse(*bypass));
  Require(protected_bypass.has_value(), "bypass preparation failed");
  auto bypass_rules = Parse(*protected_bypass)["routing"]["rules"];
  Require(bypass_rules[2]["outboundTag"] == kDnsRelay && bypass_rules[3]["ip"][0] == "0.0.0.0/0", "subnet bypass overrides DNS protection");
  std::cout << "PASS desktop DNS, IPv6, privacy, auth, aliases and domain-routing security boundaries\n";
}
