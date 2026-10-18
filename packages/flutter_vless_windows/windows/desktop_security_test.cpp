#include "xray_config.h"
#include <iostream>
#include <stdexcept>
#include <fstream>
using namespace flutter_vless::xray_config;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv) try {
  if (argc != 1) {
    if (argc != 7 || std::string(argv[1]) != "--prepare-dns-fixture") return 2;
    std::ifstream input(argv[2]);
    if (!input.good()) return 2;
    const std::string source{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    auto result = PrepareProtectedVpn(source, "session-user", "session-password", argv[4], [&](const std::string& host) {
      return host == argv[5] ? std::string(argv[6]) : std::string();
    });
    if (!result) return 3;
    std::ofstream output(argv[3], std::ios::binary);
    output << *result;
    return output.good() ? 0 : 4;
  }
  const auto source = Parse(R"({
    "log":{"access":"private-canary.log","error":"secret.log","loglevel":"debug","dnsLog":true},
    "inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":18580,"tag":"socks-in","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":false}}],
    "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"endpoint.invalid","port":443,"users":[{"id":"private-remote-credential","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"remote-public-key","serverName":"sni.invalid","show":true},"tlsSettings":{"masterKeyLog":"tls-canary.log"}}},{"tag":"direct","protocol":"freedom"}],
    "routing":{"rules":[{"type":"field","domain":["domain:ru","domain:io"],"outboundTag":"direct"},{"type":"field","domain":["domain:myip.com"],"outboundTag":"proxy"}]},
    "dns":{"hosts":{"endpoint.invalid":"203.0.113.99","dns.example":["203.0.113.53"],"domain:static.invalid":["203.0.113.10","203.0.113.11"]},"servers":[{"address":"tcp://9.9.9.9","domains":["domain:internal.invalid"],"queryStrategy":"UseIPv4","tag":"caller-dns-tcp","skipFallback":true},{"address":"https://dns.example/dns-query","domains":["domain:external.invalid"],"tag":"caller-dns-doh"}],"tag":"caller-dns","queryStrategy":"UseIPv4","disableCache":true,"disableFallbackIfMatch":true}
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
  Require(config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"], "bootstrap changed the logical endpoint or credentials");
  Require(config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] == "sni.invalid", "SNI changed");
  Require(config["log"]["access"] == "none" && config["log"]["error"] == "none" && config["log"]["dnsLog"] == false, "file log escape");
  Require(config["outbounds"][0]["streamSettings"]["realitySettings"]["show"] == false, "Reality debug escape");
  Require(config["outbounds"][0]["streamSettings"]["tlsSettings"]["masterKeyLog"] == "", "TLS key log escape");
  Require(config["dns"] == source["dns"], "caller DNS hosts/servers/domain policy/tags were replaced or polluted by physical bootstrap");
  Require(config["inbounds"][0]["settings"]["auth"] == "password", "unauthenticated VPN listener");
  Require(config["inbounds"][0]["sniffing"]["routeOnly"] == true, "IPv6 sniffing replaces target");
  auto rules = config["routing"]["rules"];
  Require(rules[0]["ip"] == Json::array({"::/0"}), "IPv6 does not precede bypass rules");
  Require(rules[1]["inboundTag"] == Json::array({kManagedInbound}) && rules[1]["ip"] == Json::array({std::string(kVirtualDns) + "/32"})
      && rules[1]["port"] == "53" && rules[1]["network"] == "tcp,udp" && rules[1]["outboundTag"] == kDnsRelay,
      "system DNS adapter is not scoped to the private input and exact virtual DNS destination");
  const auto relay = std::find_if(config["outbounds"].begin(), config["outbounds"].end(),
      [](const Json& outbound) { return outbound.value("tag", "") == kDnsRelay; });
  Require(relay != config["outbounds"].end(), "missing DNS relay");
  Require(!relay->contains("proxySettings"), "removed proxySettings emitted");
  Require(!relay->contains("streamSettings"), "root DNS adapter must not create a raw relay transport");
  Require((*relay)["settings"]["rules"] == Json::array({
      {{"action", "return"}, {"qType", "28"}, {"rCode", 0}}, {{"action", "hijack"}, {"qType", "1"}},
      {{"action", "return"}, {"rCode", 5}}}),
      "system A must use caller Core DNS; AAAA is NODATA and unsupported records are explicitly refused");
  Require(rules[rules.size()-2] == source["routing"]["rules"][0] && rules.back() == source["routing"]["rules"][1], "domain bypass rules reordered or removed");
  Require(config["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "direct sockets reenter capture");
  const auto& stream = config["outbounds"][0]["streamSettings"];
  Require(stream["sockopt"]["domainStrategy"] == "AsIs", "transport bootstrap first recurses through caller DNS");
  auto find_outbound = [](const Json& value, const std::string& tag) -> const Json& {
    for (const auto& item : value["outbounds"]) if (item.value("tag", "") == tag) return item;
    throw std::runtime_error("referenced bootstrap outbound missing");
  };
  const auto& loopback = find_outbound(config, stream["sockopt"]["dialerProxy"].get<std::string>());
  Require(loopback["protocol"] == "loopback", "bootstrap is not isolated through Core dispatcher");
  const auto pin_input = loopback["settings"]["inboundTag"].get<std::string>();
  Require(pin_input != "caller-dns" && pin_input != "caller-dns-tcp" && pin_input != "caller-dns-doh", "bootstrap inherited DNS client identity");
  Require(rules[2]["inboundTag"] == Json::array({pin_input}) && rules[2]["domain"] == Json::array({"full:endpoint.invalid"})
      && rules[2]["port"] == "443", "physical pin must require exact private context, hostname and port");
  const auto& pin_egress = find_outbound(config, rules[2]["outboundTag"].get<std::string>());
  Require(pin_egress["protocol"] == "freedom" && pin_egress["settings"]["redirect"] == "192.0.2.5:0"
      && pin_egress["streamSettings"]["sockopt"]["interface"] == "Ethernet", "pin lost numeric destination, original port or underlay binding");
  Require(rules[3]["inboundTag"] == Json::array({pin_input}) && rules[3]["outboundTag"] == kIpv6Block
      && rules[3].size() == 3, "unmatched bootstrap context can fall through to caller routing");
  auto physical_options = source;
  physical_options["outbounds"][0]["sendThrough"] = "192.0.2.25";
  physical_options["outbounds"][0]["streamSettings"]["sockopt"] = {{"tcpFastOpen", true}, {"tcpKeepAliveIdle", 30}, {"mark", 7}};
  auto options_prepared = prepare(physical_options); Require(options_prepared.has_value(), "physical socket option profile rejected");
  auto options_config = Parse(*options_prepared);
  const auto& options_leaf = find_outbound(options_config, options_config["routing"]["rules"][2]["outboundTag"].get<std::string>());
  Require(options_leaf["sendThrough"] == "192.0.2.25" && options_leaf["streamSettings"]["sockopt"] == Json{{"tcpFastOpen", true},
      {"tcpKeepAliveIdle", 30}, {"mark", 7}, {"domainStrategy", "ForceIPv4"}, {"interface", "Ethernet"}}, "private leaf discarded caller physical socket options/gateway");

  for (int empty_kind = 0; empty_kind < 4; ++empty_kind) {
    auto profile = source;
    if (empty_kind == 0) profile.erase("dns");
    if (empty_kind == 1) profile["dns"] = nullptr;
    if (empty_kind == 2) profile["dns"] = Json::object();
    if (empty_kind == 3) profile["dns"] = {{"hosts", {{"local.invalid", "203.0.113.11"}}}, {"queryStrategy", "UseIPv4"}, {"servers", Json::array()}};
    auto prepared = prepare(profile); Require(prepared.has_value(), "native missing/empty DNS policy rejected");
    const auto effective = Parse(*prepared);
    const auto& server = effective["dns"]["servers"][0];
    Require(server["address"] == "tcp://1.1.1.1" && server["tag"] == kDnsUpstream, "missing DNS can use captured OS resolver");
    Require(effective["routing"]["rules"][2] == Json{{"type", "field"}, {"inboundTag", Json::array({kDnsUpstream})},
        {"ip", Json::array({"1.1.1.1/32"})}, {"port", "53"}, {"network", "tcp"}, {"outboundTag", "proxy"}}, "native default DNS is not scoped and proxied");
    if (empty_kind == 3) Require(effective["dns"]["hosts"] == profile["dns"]["hosts"] && effective["dns"]["queryStrategy"] == "UseIPv4", "empty DNS policy discarded caller hosts/strategy");
  }
  auto local = source;
  local["dns"]["servers"].insert(local["dns"]["servers"].begin(), Json{{"Address", "localhost"}, {"Tag", "caller-local"},
      {"domains", Json::array({"domain:private.invalid"})}, {"queryStrategy", "UseIPv4"}, {"skipFallback", true}, {"timeoutMs", 1200}});
  auto local_prepared = prepare(local); Require(local_prepared.has_value(), "explicit localhost native default rejected");
  auto expected_local = local["dns"]; expected_local["servers"][0]["Address"] = "tcp://1.1.1.1";
  Require(Parse(*local_prepared)["dns"] == expected_local, "localhost adaptation discarded source entry policy/tag");
  Require(Parse(*local_prepared)["routing"]["rules"][2]["inboundTag"] == Json::array({"caller-local"}), "localhost native policy lost its effective client tag");
  local["dns"]["servers"][0]["Tag"] = "";
  auto empty_tag = prepare(local); Require(empty_tag.has_value() && !Parse(*empty_tag)["dns"]["servers"][0].contains("tag"), "native DNS added a duplicate folded tag alias");
  for (const auto& address : {"fakedns", "tcp+local://1.1.1.1", "https+local://dns.example/dns-query", "quic+local://1.1.1.1", "tls://1.1.1.1", "tcp://[2001:db8::1]", "unknown://1.1.1.1"}) {
    auto unsupported = source; unsupported["dns"]["servers"] = Json::array({address});
    Require(!prepare(unsupported), "unsupported local/DoT/QUIC/FakeDNS/IPv6 path silently admitted");
  }
  for (const auto& strategy : {"UseSystem", "use_sys", "use-system"}) {
    auto unsupported = source; unsupported["dns"]["queryStrategy"] = strategy;
    Require(!prepare(unsupported), "unqualified system-family root strategy admitted");
    unsupported = source; unsupported["dns"]["servers"][0]["queryStrategy"] = strategy;
    Require(!prepare(unsupported), "unqualified system-family per-server strategy admitted");
  }
  auto dns_script = source; dns_script["dns"]["script"] = "return true";
  Require(!prepare(dns_script), "unqualified DNS script admitted");
  auto no_resolver_pin = source; no_resolver_pin["dns"]["hosts"].erase("dns.example");
  Require(!prepare(no_resolver_pin), "named remote DNS can enter a root resolver cycle");
  for (const auto& mapping : {Json("alias.invalid"), Json::array(), Json::array({"203.0.113.53", "2001:db8::53"}), Json{{"address", "203.0.113.53"}}}) {
    auto unsafe = source; unsafe["dns"]["hosts"]["dns.example"] = mapping;
    Require(!prepare(unsafe), "unqualified resolver static host mapping admitted");
  }
  auto single_resolver_pin = source; single_resolver_pin["dns"]["hosts"]["dns.example"] = "203.0.113.53";
  auto single_prepared = prepare(single_resolver_pin); Require(single_prepared.has_value() && Parse(*single_prepared)["dns"] == single_resolver_pin["dns"], "exact IPv4 resolver host mapping was changed");
  auto fqdn_resolver = source; fqdn_resolver["dns"]["servers"][1]["address"] = "https://DNS.EXAMPLE./dns-query";
  Require(prepare(fqdn_resolver).has_value(), "root resolver's case folding/FQDN normalization was ignored");
  auto false_fqdn_mapping = fqdn_resolver;
  false_fqdn_mapping["dns"]["hosts"].erase("dns.example");
  false_fqdn_mapping["dns"]["hosts"]["DNS.EXAMPLE."] = "203.0.113.53";
  Require(!prepare(false_fqdn_mapping), "FQDN key that root LookupIP cannot match admitted as protected resolver bootstrap");
  auto dns_alias = source; dns_alias["dns"]["Servers"] = dns_alias["dns"]["servers"]; dns_alias["dns"].erase("servers");
  auto alias_prepared = prepare(dns_alias); Require(alias_prepared.has_value() && Parse(*alias_prepared)["dns"] == dns_alias["dns"], "safe DNS field spelling was rewritten");
  dns_alias["dns"]["servers"] = Json::array(); Require(!prepare(dns_alias), "ambiguous folded DNS server fields admitted");

  auto chained = source;
  chained["outbounds"][0]["settings"]["vnext"][0]["address"] = "logical-target.invalid";
  chained["outbounds"][0]["streamSettings"]["sockopt"] = {{"dialerProxy", "front"}};
  chained["outbounds"].push_back({{"tag", "front"}, {"protocol", "socks"},
      {"settings", {{"servers", Json::array({{{"address", "endpoint.invalid"}, {"port", 8443}}})}}}});
  auto chained_prepared = prepare(chained); Require(chained_prepared.has_value(), "chained transport incorrectly bootstrapped logical target");
  auto chained_config = Parse(*chained_prepared);
  Require(chained_config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "front"
      && chained_config["outbounds"][0]["settings"] == chained["outbounds"][0]["settings"], "caller chain/logical address changed");
  for (const auto& target : {"missing-handler", "proxy"}) {
    auto invalid_chain = source;
    invalid_chain["outbounds"][0]["streamSettings"]["sockopt"] = {{"dialerProxy", target}};
    Require(!prepare(invalid_chain), "missing/self-referential transport chain admitted");
  }
  auto cycle = chained;
  cycle["outbounds"][2]["streamSettings"] = {{"sockopt", {{"dialerProxy", "proxy"}}}};
  Require(!prepare(cycle), "cyclic handler transport chain admitted");
  auto multi_endpoint = source;
  multi_endpoint["outbounds"][0]["settings"]["vnext"].push_back({{"address", "192.0.2.9"}, {"port", 8443}, {"users", source["outbounds"][0]["settings"]["vnext"][0]["users"]}});
  auto multi_prepared = prepare(multi_endpoint); Require(multi_prepared.has_value(), "multi-endpoint bootstrap rejected");
  auto multi_config = Parse(*multi_prepared);
  Require(multi_config["outbounds"][0]["settings"] == multi_endpoint["outbounds"][0]["settings"], "multi-endpoint logical hosts/credentials changed");
  Require(multi_config["routing"]["rules"][3]["ip"] == Json::array({"192.0.2.9/32"}) && multi_config["routing"]["rules"][3]["port"] == "8443", "multi-endpoint numeric pin lacks exact address/port");
  auto dormant_address = source;
  dormant_address["outbounds"][0]["streamSettings"]["address"] = "ignored.invalid";
  dormant_address["outbounds"][0]["streamSettings"]["port"] = 444;
  Require(prepare(dormant_address).has_value(), "ordinary RAW stream.address incorrectly replaced protocol endpoint");
  auto downloads = source;
  downloads["outbounds"][0]["streamSettings"]["network"] = "xhttp";
  downloads["outbounds"][0]["streamSettings"]["xhttpSettings"] = {{"downloadSettings", {{"address", "dormant.invalid"}, {"port", 444}}},
      {"extra", {{"downloadSettings", {{"address", "endpoint.invalid"}, {"port", 8443}, {"network", "tcp"}}}}}};
  auto download_prepared = prepare(downloads); Require(download_prepared.has_value(), "effective XHTTP download bootstrap rejected");
  auto download_config = Parse(*download_prepared);
  Require(download_config["outbounds"][0]["streamSettings"]["xhttpSettings"]["downloadSettings"] == downloads["outbounds"][0]["streamSettings"]["xhttpSettings"]["downloadSettings"], "dormant XHTTP download changed");
  bool download_rule = false;
  for (const auto& rule : download_config["routing"]["rules"]) if (rule.value("port", "") == "8443" && rule.contains("domain")) download_rule = true;
  Require(download_rule, "XHTTP download used upload endpoint port");
  auto broken_download_chain = downloads;
  broken_download_chain["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["sockopt"] = {{"dialerProxy", "missing-download-handler"}};
  Require(!prepare(broken_download_chain), "effective XHTTP download references a missing handler");
  downloads["outbounds"][0]["streamSettings"]["sockopt"] = {{"penetrate", true}};
  Require(!prepare(downloads), "download sockopt overwrite bypassed isolated pin scope");
  auto tag_collision = source;
  tag_collision["dns"]["tag"] = kManagedInbound;
  tag_collision["dns"]["servers"][0]["tag"] = "flutter-vless-bootstrap-input";
  auto tags_prepared = prepare(tag_collision); Require(tags_prepared.has_value(), "DNS namespace collision rejected instead of isolated");
  auto isolated_dns = Parse(*tags_prepared);
  Require(isolated_dns["inbounds"][0]["tag"] == std::string(kManagedInbound) + "-1" && isolated_dns["dns"] == tag_collision["dns"], "managed DNS inherited root own-link identity");
  Require(find_outbound(isolated_dns, isolated_dns["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"].get<std::string>())["settings"]["inboundTag"] == "flutter-vless-bootstrap-input-1", "private physical pin inherited caller DNS own-link tag");
  for (const auto& key : {"FakeDNS", "fakedns", "fakeDnS"}) {
    auto bad = source; bad[key] = Json::array(); Require(!prepare(bad), "FakeDNS alias bypassed IPv6 policy");
  }
  for (const auto& key : {"Listen", "Li\xC5\xBFten"}) {
    auto bad = source; bad["inbounds"][0][key] = "0.0.0.0"; Require(!prepare(bad), "ambiguous listen accepted");
  }
  Require(config["inbounds"][1] == source["inbounds"][0], "user listener/auth/sniffing were rewritten");
  Require(rules[0]["inboundTag"] == Json::array({kManagedInbound}), "IPv6 policy must scope to private adapter");
  auto extra = source;
  extra["inbounds"].push_back({{"tag", "socks-direct"}, {"protocol", "socks"}, {"listen", "127.0.0.1"}, {"port", 10820}, {"settings", {{"auth", "noauth"}}}});
  extra["inbounds"].push_back({{"tag", "custom-http"}, {"protocol", "http"}, {"listen", "127.0.0.1"}, {"port", "10807-10810"}, {"settings", {{"accounts", Json::array({{{"user", "app"}, {"pass", "app-secret"}}})}}}});
  extra["routing"]["rules"].insert(extra["routing"]["rules"].begin(), Json{{"inboundTag", Json::array({"socks-direct"})}, {"outboundTag", "direct"}});
  auto multiple = prepare(extra); Require(multiple.has_value(), "full multi-listener profile rejected");
  auto multi = Parse(*multiple);
  Require(Port(multi["inbounds"][0]) == 10811, "private adapter collided with user port range");
  for (size_t i = 0; i < extra["inbounds"].size(); ++i) Require(multi["inbounds"][i+1] == extra["inbounds"][i], "imported listener changed");
  Require(multi["routing"]["rules"][multi["routing"]["rules"].size()-extra["routing"]["rules"].size()] == extra["routing"]["rules"][0], "socks-direct route lost");
  extra["inbounds"].push_back({{"tag", "stats-port"}, {"protocol", "http"}, {"port", 10086}});
  auto shifted_api = prepare(extra); Require(shifted_api && ApiPort(*shifted_api) == 10087, "stats port collided with caller listener");
  extra["inbounds"][0]["tag"] = kManagedInbound;
  auto collided = prepare(extra); Require(collided.has_value(), "private inbound tag collision rejected");
  Require(Parse(*collided)["inbounds"][0]["tag"] == std::string(kManagedInbound) + "-1", "private inbound tag was not isolated");
  auto bad = source; bad["outbounds"][0]["tag"] = kDnsRelay;
  auto reserved = prepare(bad); Require(reserved.has_value(), "caller DNS tag rejected");
  Require(Parse(*reserved)["outbounds"][2]["tag"] == std::string(kDnsRelay) + "-1", "DNS relay overwrote caller tag");
  auto service_references = source;
  service_references["api"] = {{"tag", kManagedInbound}};
  service_references["reverse"] = {{"portals", Json::array({{{"tag", kIpv6Block}}})}};
  service_references["routing"]["rules"].insert(service_references["routing"]["rules"].begin(),
      Json{{"type", "field"}, {"inboundTag", Json::array({std::string(kManagedInbound) + "-1"})}, {"outboundTag", kDnsRelay}});
  auto isolated = prepare(service_references); Require(isolated.has_value(), "service references rejected");
  auto protected_references = Parse(*isolated);
  Require(protected_references["inbounds"][0]["tag"] == std::string(kManagedInbound) + "-2", "adapter inherited user reference/API tag");
  Require(protected_references["routing"]["rules"][0]["outboundTag"] == std::string(kIpv6Block) + "-1", "IPv6 service inherited reverse tag");
  Require(protected_references["routing"]["rules"][1]["outboundTag"] == std::string(kDnsRelay) + "-1", "DNS service inherited user reference");
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
  Require(bypass_rules[1]["outboundTag"] == kDnsRelay && bypass_rules[bypass_rules.size()-Parse(*bypass)["routing"]["rules"].size()]["ip"][0] == "0.0.0.0/0", "subnet bypass overrides DNS protection");
  std::cout << "PASS desktop DNS, IPv6, privacy, auth, aliases and domain-routing security boundaries\n";
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
