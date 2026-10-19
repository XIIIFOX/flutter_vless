#include "xray_config.h"
#include <iostream>
#include <stdexcept>
#include <fstream>
using namespace flutter_vless::xray_config;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void DirectOnlyCases(const std::string& only = "") {
  for (const auto* protocol : {"freedom", "direct"}) {
    if (!only.empty() && only != protocol) continue;
    Json source = {
        {"log", {{"loglevel", "none"}}},
        {"outbounds", Json::array({
            {{"protocol", protocol}, {"tag", "direct"}, {"settings", {{"domainStrategy", "AsIs"}}}},
            {{"protocol", "blackhole"}, {"tag", "blocked"}}})},
        {"dns", {{"tag", "caller-direct-dns"}, {"queryStrategy", "UseIPv4"},
            {"hosts", {{"direct-only.invalid", "127.0.0.1"}, {"blocked.invalid", "192.0.2.80"}}},
            {"servers", Json::array({"tcp://9.9.9.9"})}}},
        {"routing", {{"domainStrategy", "AsIs"}, {"rules", Json::array({
            {{"type", "field"}, {"domain", Json::array({"full:blocked.invalid"})}, {"outboundTag", "blocked"}}})}}}};
    const size_t direct_index = std::string(protocol) == "direct" ? 1 : 0;
    if (direct_index == 1) {
      std::swap(source["outbounds"][0], source["outbounds"][1]);
      source["outbounds"][0]["protocol"] = "block";
      source["dns"]["queryStrategy"] = "UseIP";
      source["routing"]["rules"] = Json::array({
          {{"type", "field"}, {"inboundTag", Json::array({"caller-direct-dns"})}, {"outboundTag", "direct"}},
          {{"type", "field"}, {"domain", Json::array({"full:direct-only.invalid"})}, {"outboundTag", "direct"}}});
    }
    size_t bootstrap_calls = 0;
    const auto output = PrepareProtectedVpn(source.dump(), "session-user", "session-password", "Ethernet",
        [&](const std::string&) { ++bootstrap_calls; return std::string(); });
    Require(output.has_value(), "valid direct-only profile rejected because it has no proxy endpoint");
    const auto config = Parse(*output);
    Require(bootstrap_calls == 0, "direct-only profile attempted physical endpoint bootstrap");
    Require(config["dns"] == source["dns"], "direct-only adaptation changed caller DNS policy or static hosts");
    const auto& direct = config["outbounds"][direct_index];
    Require(direct["protocol"] == protocol && direct["tag"] == "direct"
        && config["outbounds"][1 - direct_index] == source["outbounds"][1 - direct_index],
        "direct-only adaptation changed caller default handler/order/alias");
    Require(direct["settings"]["domainStrategy"] == "ForceIPv4"
        && direct["streamSettings"]["sockopt"]["domainStrategy"] == "ForceIPv4"
        && direct["streamSettings"]["sockopt"]["interface"] == "Ethernet"
        && !direct["streamSettings"]["sockopt"].contains("dialerProxy"), "direct-only physical dialer lost its protected IPv4 underlay binding");
    Require(config["inbounds"][0]["settings"]["auth"] == "password"
        && config["inbounds"][0]["settings"]["accounts"][0] == Json{{"user", "session-user"}, {"pass", "session-password"}},
        "direct-only adapter lost native session authentication");
    const auto& rules = config["routing"]["rules"];
    Require(rules.size() >= source["routing"]["rules"].size(), "direct-only adaptation lost caller routing rules");
    const auto offset = rules.size() - source["routing"]["rules"].size();
    for (size_t i = 0; i < source["routing"]["rules"].size(); ++i)
      Require(rules[offset + i] == source["routing"]["rules"][i], "direct-only adaptation changed caller routing order");
    Require(rules[0]["inboundTag"] == Json::array({config["inbounds"][0]["tag"]})
        && rules[0]["ip"] == Json::array({std::string(kVirtualDns) + "/32"})
        && rules[0]["port"] == "53" && rules[0]["network"] == "tcp,udp", "direct-only system DNS is not isolated to the native virtual destination");
    const auto relay_tag = rules[0]["outboundTag"];
    bool relay_found = false;
    for (const auto& outbound : config["outbounds"]) {
      if (outbound.value("tag", Json()) == relay_tag) {
        relay_found = outbound["protocol"] == "dns" && outbound["settings"]["rules"] == Json::array({
            {{"action", "hijack"}, {"qType", "1,28"}}, {{"action", "return"}, {"rCode", 5}}});
      }
      Require(outbound.value("protocol", "") != "socks" && outbound.value("protocol", "") != "vless",
          "direct-only adaptation synthesized an external proxy endpoint");
    }
    Require(relay_found, "direct-only system A/AAAA does not use the caller Core DNS client");
    for (int variant = 0; variant < 4; ++variant) {
      auto implicit = source;
      if (variant == 0) implicit.erase("dns");
      if (variant == 1) implicit["dns"] = Json::object();
      if (variant == 2) implicit["dns"]["servers"] = Json::array();
      if (variant == 3) implicit["dns"]["servers"] = Json::array({{{"address", "localhost"}, {"tag", "caller-local"}}});
      Require(!PrepareProtectedVpn(implicit.dump(), "session-user", "session-password", "Ethernet",
          [](const std::string&) { return std::string(); }), "direct-only native DNS replacement guessed an egress or emitted an empty tag");
    }
  }
  Require(only.empty() || only == "freedom" || only == "direct", "unknown direct-only test case");
}
void IPv6PayloadCases(const std::string& only = "") {
  const auto source = Parse(R"({"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"endpoint.invalid","port":443}]}},{"tag":"direct","protocol":"freedom"}],"dns":{"queryStrategy":"UseIP","hosts":{"payload.invalid":["198.51.100.7","2001:db8::7"]},"servers":["tcp://1.1.1.1"]},"routing":{"rules":[{"type":"field","ip":["2001:db8::/32"],"network":"tcp,udp","outboundTag":"proxy"}]}})");
  auto prepare = [](const Json& value) {
    return PrepareProtectedVpn(value.dump(), "session-user", "session-password", "Ethernet",
        [](const std::string& host) { return host == "endpoint.invalid" ? "192.0.2.5" : ""; });
  };
  std::map<std::string, std::function<void()>> cases;
  cases["captured-payload"] = [&] {
    const auto output = prepare(source); Require(output.has_value(), "IPv4 proxy with IPv6 payload profile rejected");
    const auto config = Parse(*output);
    Require(config["routing"]["rules"].back() == source["routing"]["rules"][0], "caller IPv6 TCP/UDP routing changed");
    for (const auto& rule : config["routing"]["rules"]) {
      Require(!(rule.value("inboundTag", Json::array()) == Json::array({kManagedInbound})
          && rule.value("ip", Json::array()) == Json::array({"::/0"})), "captured IPv6 payload is still blocked before caller routing");
    }
    // Enabling an inner IPv6 destination must not enable an outer physical
    // IPv6 socket, change the caller endpoint, or open the private pin scope.
    Require(config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"], "IPv6 payload changed the outer proxy endpoint");
    Require(config["outbounds"][1]["settings"]["domainStrategy"] == "ForceIPv4", "physical direct egress lost its IPv4-only boundary");
    bool closed_pin = false;
    for (const auto& rule : config["routing"]["rules"]) {
      if (rule.value("outboundTag", "") == kIpv6Block && rule.contains("inboundTag")
          && rule["inboundTag"] != Json::array({kManagedInbound}) && rule.size() == 3) closed_pin = true;
    }
    Require(closed_pin, "unmatched private transport bootstrap can fall through to caller routing");
  };
  cases["dns-aaaa"] = [&] {
    const auto output = prepare(source); Require(output.has_value(), "dual-family caller DNS profile rejected");
    const auto config = Parse(*output);
    Require(config["dns"] == source["dns"], "IPv6 adaptation rewrote caller DNS hosts/strategy/servers");
    const auto relay = std::find_if(config["outbounds"].begin(), config["outbounds"].end(),
        [](const Json& value) { return value.value("tag", "") == kDnsRelay; });
    Require(relay != config["outbounds"].end(), "IPv6 payload lost protected system DNS relay");
    Require((*relay)["settings"]["rules"] == Json::array({
        {{"action", "hijack"}, {"qType", "1,28"}}, {{"action", "return"}, {"rCode", 5}}}),
        "system AAAA must use caller Core DNS rather than unconditional NODATA or a raw relay");
    Require(!relay->contains("streamSettings") && !relay->contains("proxySettings"), "system IPv6 DNS bypassed the root client");
  };
  cases["caller-ipv4-policy"] = [&] {
    auto profile = source; profile["dns"]["queryStrategy"] = "UseIPv4";
    profile["dns"]["servers"][0] = {{"address", "tcp://1.1.1.1"}, {"queryStrategy", "UseIPv4"}, {"tag", "caller-dns"}};
    const auto output = prepare(profile); Require(output.has_value(), "caller IPv4-only DNS policy rejected");
    Require(Parse(*output)["dns"] == profile["dns"], "IPv6 payload adaptation widened caller IPv4 DNS policy");
  };
  if (!only.empty()) {
    const auto found = cases.find(only); Require(found != cases.end(), "unknown IPv6 test case"); found->second();
  } else for (const auto& item : cases) item.second();
}
void ProtocolCompatibilityCases(const std::string& only = "") {
  const auto source = Parse(R"({"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"endpoint.invalid","port":443}]}},{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"dns":{"queryStrategy":"UseIPv4","servers":["tcp://1.1.1.1"]},"routing":{"rules":[]}})");
  auto prepare = [](const Json& value) {
    return PrepareProtectedVpn(value.dump(), "session-user", "session-password", "Ethernet",
        [](const std::string& host) { return host == "endpoint.invalid" ? "192.0.2.5" : ""; });
  };
  auto tagged = [](const Json& config, const std::string& tag) -> const Json& {
    for (const auto& outbound : config["outbounds"]) if (outbound.value("tag", "") == tag) return outbound;
    throw std::runtime_error("protocol case references missing handler");
  };
  std::map<std::string, std::function<void()>> cases;
  cases["null-direct-tag"] = [&] {
    auto profile = source;
    profile["outbounds"].erase(profile["outbounds"].begin());
    profile["outbounds"][0]["tag"] = nullptr;
    const auto output = prepare(profile);
    Require(output.has_value(), "Core-valid null tag on the default direct handler rejected");
    const auto config = Parse(*output);
    Require(config["outbounds"][0]["protocol"] == "freedom" && config["outbounds"][0]["tag"].is_null()
        && config["outbounds"][1] == profile["outbounds"][1] && config["dns"] == profile["dns"],
        "null direct tag, caller default/order or DNS changed");
  };
  cases["null-remote-tag"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["tag"] = nullptr;
    const auto output = prepare(profile);
    Require(output.has_value(), "Core-valid null remote tag was not treated like an absent tag");
    const auto config = Parse(*output);
    Require(config["outbounds"][0]["tag"] == "flutter-vless-proxy"
        && config["outbounds"][0]["protocol"] == profile["outbounds"][0]["protocol"]
        && config["outbounds"][0]["settings"] == profile["outbounds"][0]["settings"]
        && config["outbounds"][1]["tag"] == profile["outbounds"][1]["tag"]
        && profile["outbounds"][0]["tag"].is_null(), "null remote tag changed logical endpoint, source or handler order");
  };
  cases["invalid-outbound-tag"] = [&] {
    for (const auto& invalid : {Json(false), Json(true), Json(7), Json::array(), Json::object()}) {
      auto profile = source;
      profile["outbounds"][0]["tag"] = invalid;
      Require(!prepare(profile), "invalid non-null outbound tag admitted");
      profile["outbounds"].erase(profile["outbounds"].begin());
      profile["outbounds"][0]["tag"] = invalid;
      Require(!prepare(profile), "invalid non-null direct tag admitted");
    }
  };
  cases["loopback"] = [&] {
    auto profile = source;
    const Json loop = {{"tag", "caller-loop"}, {"protocol", "loopback"}, {"settings", {{"inboundTag", "caller-loop-context"},
        {"sniffing", {{"enabled", true}, {"destOverride", Json::array({"http"})}, {"routeOnly", true}}}}}};
    profile["outbounds"].insert(profile["outbounds"].begin(), loop);
    profile["routing"]["rules"].push_back({{"type", "field"}, {"inboundTag", Json::array({"caller-loop-context"})}, {"outboundTag", "proxy"}});
    auto output = prepare(profile); Require(output.has_value(), "valid caller loopback was rejected as an endpoint");
    auto config = Parse(*output);
    Require(config["outbounds"][0] == loop && config["outbounds"][1]["settings"] == source["outbounds"][0]["settings"], "dispatch-only caller loopback or endpoint order changed");
    Require(config["routing"]["rules"].back() == profile["routing"]["rules"].back(), "caller loopback routing lost");
    profile["outbounds"][0]["streamSettings"] = {{"sockopt", {{"dialerProxy", "unused-loopback-socket-handler"}}}};
    output = prepare(profile); Require(output.has_value(), "dispatch-only loopback inspected its unused socket chain");
    Require(Parse(*output)["outbounds"][0] == profile["outbounds"][0], "caller loopback dormant stream was rewritten");
  };
  cases["dns"] = [&] {
    auto profile = source;
    const Json settings = {{"rewriteNetwork", "tcp"}, {"rewriteAddress", "caller-resolver.invalid"}, {"rewritePort", 5353},
        {"rules", Json::array({{{"action", "direct"}}})}};
    profile["dns"]["hosts"] = {{"caller-resolver.invalid", "203.0.113.53"}};
    profile["outbounds"].push_back({{"tag", "caller-dns-adapter"}, {"protocol", "dns"}, {"settings", settings},
        {"streamSettings", {{"sockopt", {{"tcpKeepAliveIdle", 31}}}}}});
    auto output = prepare(profile); Require(output.has_value(), "valid caller DNS outbound was rejected as an endpoint");
    auto config = Parse(*output); const auto& dns = tagged(config, "caller-dns-adapter");
    Require(dns["settings"] == settings && config["dns"] == profile["dns"], "caller DNS outbound policy or root hosts changed");
    Require(dns["streamSettings"]["sockopt"] == Json{{"tcpKeepAliveIdle", 31}, {"domainStrategy", "ForceIPv4"}, {"interface", "Ethernet"}}, "DNS raw dial path lost its physical protection/options");
  };
  cases["masque"] = [&] {
    for (const auto& alpn : {"h2", "h3"}) {
      auto profile = source;
      const Json settings = {{"address", "endpoint.invalid"}, {"port", 443}, {"remoteDNS", Json::array({"1.1.1.1"})}};
      profile["outbounds"][0] = {{"tag", "proxy"}, {"protocol", "masque"}, {"settings", settings},
          {"streamSettings", {{"network", "masque"}, {"security", "tls"}, {"tlsSettings", {{"serverName", "masque-origin.invalid"}, {"alpn", Json::array({alpn})}}},
              {"masqueSettings", {{"path", "/masque"}, {"headers", {{"X-Test", "source-header"}}}}}}}};
      auto output = prepare(profile); Require(output.has_value(), "valid flat MASQUE endpoint was rejected");
      auto config = Parse(*output); const auto& remote = config["outbounds"][0];
      Require(remote["settings"] == settings && remote["streamSettings"]["tlsSettings"]["serverName"] == "masque-origin.invalid"
          && remote["streamSettings"]["tlsSettings"]["alpn"] == Json::array({alpn})
          && remote["streamSettings"]["masqueSettings"] == profile["outbounds"][0]["streamSettings"]["masqueSettings"], "MASQUE identity, logical endpoint or transport metadata changed");
      const auto& loop = tagged(config, remote["streamSettings"]["sockopt"]["dialerProxy"].get<std::string>());
      Require(loop["protocol"] == "loopback" && remote["streamSettings"]["sockopt"]["domainStrategy"] == "AsIs", "MASQUE physical endpoint escaped private bootstrap");
      const auto input = loop["settings"]["inboundTag"];
      bool bound = false;
      for (const auto& rule : config["routing"]["rules"]) if (rule.value("inboundTag", Json::array()) == Json::array({input}) && rule.value("port", "") == "443") {
        const auto& leaf = tagged(config, rule["outboundTag"].get<std::string>());
        bound = leaf["settings"]["redirect"] == "192.0.2.5:0" && leaf["streamSettings"]["sockopt"]["interface"] == "Ethernet";
      }
      Require(bound, "MASQUE pin did not preserve underlay binding");
    }
  };
  cases["aliases"] = [&] {
    auto profile = source;
    profile["outbounds"][1]["protocol"] = "direct";
    profile["outbounds"][2]["protocol"] = "block";
    auto output = prepare(profile); Require(output.has_value(), "registered Core direct/block aliases were rejected");
    auto config = Parse(*output);
    Require(config["outbounds"][1]["protocol"] == "direct" && config["outbounds"][2] == profile["outbounds"][2], "source alias protocol strings changed");
    Require(config["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet"
        && config["outbounds"][1]["settings"]["domainStrategy"] == "ForceIPv4", "direct alias bypassed physical protection");
  };
  cases["nullable-flat-address"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["protocol"] = "shadowsocks";
    auto& settings = profile["outbounds"][0]["settings"];
    settings = {{"address", nullptr}, {"servers", Json::array({{{"address", "endpoint.invalid"}, {"port", 443},
        {"method", "2022-blake3-aes-128-gcm"}, {"password", "AAAAAAAAAAAAAAAAAAAAAA=="}}})}};
    auto output = prepare(profile); Require(output.has_value(), "Core null flat address did not fall back to the legacy server");
    Require(Parse(*output)["outbounds"][0]["settings"] == settings, "null flat address adaptation changed source Shadowsocks settings");
    for (const auto& invalid : {Json(7), Json(true), Json::object(), Json("")}) {
      settings["address"] = invalid;
      Require(!prepare(profile), "invalid nonnull flat address fell back to a dormant legacy server");
    }
    settings["address"] = "endpoint.invalid"; settings["port"] = 8443;
    settings["method"] = "2022-blake3-aes-128-gcm"; settings["password"] = "AAAAAAAAAAAAAAAAAAAAAA==";
    settings["servers"][0]["address"] = "dormant.invalid";
    output = prepare(profile); Require(output.has_value(), "nonnull flat address lost precedence over a dormant legacy server");
    const auto config = Parse(*output);
    Require(config["outbounds"][0]["settings"] == settings, "nonnull flat priority changed source settings");
    bool flat_pin = false;
    for (const auto& rule : config["routing"]["rules"]) {
      Require(rule.value("port", "") != "443", "dormant legacy server received a transport pin");
      if (rule.value("port", "") == "8443") flat_pin = true;
    }
    Require(flat_pin, "effective nonnull flat endpoint did not receive its exact port pin");
  };
  cases["null-stream-fields"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["streamSettings"] = {{"method", nullptr}, {"network", "xhttp"}, {"sockopt", {{"dialerProxy", nullptr}}},
        {"xhttpSettings", {{"downloadSettings", {{"address", "endpoint.invalid"}, {"port", 8443}, {"network", "tcp"}}}}}};
    auto output = prepare(profile); Require(output.has_value(), "Core nullable stream fields were rejected");
    auto config = Parse(*output);
    Require(config["outbounds"][0]["streamSettings"]["method"].is_null(), "source nullable method was rewritten");
    bool download = false;
    for (const auto& rule : config["routing"]["rules"]) if (rule.value("port", "") == "8443" && rule.contains("domain")) download = true;
    Require(download, "null method failed to fall back to effective XHTTP network");
    profile["outbounds"][0]["streamSettings"]["method"] = "raw";
    profile["outbounds"][0]["streamSettings"]["network"] = nullptr;
    profile["outbounds"][0]["streamSettings"]["xhttpSettings"]["downloadSettings"]["address"] = "unused.invalid";
    Require(prepare(profile).has_value(), "nonnull method did not override null network/dormant download");
  };
  cases["xhttp-null-extra"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["streamSettings"] = {{"network", "xhttp"}, {"xhttpSettings", {{"extra", nullptr},
        {"downloadSettings", {{"address", "unused.invalid"}, {"port", 8443}, {"sockopt", {{"dialerProxy", "unused-handler"}}}}}}}};
    auto output = prepare(profile); Require(output.has_value(), "extra:null failed to suppress dormant outer download/chain");
    auto config = Parse(*output);
    Require(config["outbounds"][0]["streamSettings"]["xhttpSettings"] == profile["outbounds"][0]["streamSettings"]["xhttpSettings"], "dormant extra:null transport data changed");
    for (const auto& rule : config["routing"]["rules"]) Require(rule.value("port", "") != "8443", "ignored extra:null outer download received physical pins");
  };
  if (!only.empty()) {
    const auto found = cases.find(only); Require(found != cases.end(), "unknown protocol test case"); found->second();
  } else for (const auto& item : cases) item.second();
}
int main(int argc, char** argv) try {
  if (argc == 4 && std::string(argv[1]) == "--allocate-service-tags-fixture") {
    std::ifstream file(argv[2], std::ios::binary);
    if (!file.good()) return 2;
    const auto input = Parse(std::string{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()});
    if (!input.is_object() || !input.contains("config") || !input.contains("requests") || !input["requests"].is_array()) return 3;
    ServiceTags allocator(input["config"]);
    auto tags = Json::array();
    for (const auto& request : input["requests"]) {
      if (!request.is_string()) return 3;
      tags.push_back(allocator.Next(request.get<std::string>()));
    }
    std::ofstream output(argv[3], std::ios::binary); output << tags.dump();
    return output.good() ? 0 : 4;
  }
  if (argc == 3 && std::string(argv[1]) == "--direct-only-case") { DirectOnlyCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--ipv6-case") { IPv6PayloadCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--protocol-case") { ProtocolCompatibilityCases(argv[2]); return 0; }
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
  IPv6PayloadCases();
  DirectOnlyCases();
  ProtocolCompatibilityCases();
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
  Require(rules[0]["inboundTag"] == Json::array({kManagedInbound}) && rules[0]["ip"] == Json::array({std::string(kVirtualDns) + "/32"})
      && rules[0]["port"] == "53" && rules[0]["network"] == "tcp,udp" && rules[0]["outboundTag"] == kDnsRelay,
      "system DNS adapter is not scoped to the private input and exact virtual DNS destination");
  const auto relay = std::find_if(config["outbounds"].begin(), config["outbounds"].end(),
      [](const Json& outbound) { return outbound.value("tag", "") == kDnsRelay; });
  Require(relay != config["outbounds"].end(), "missing DNS relay");
  Require(!relay->contains("proxySettings"), "removed proxySettings emitted");
  Require(!relay->contains("streamSettings"), "root DNS adapter must not create a raw relay transport");
  Require((*relay)["settings"]["rules"] == Json::array({
      {{"action", "hijack"}, {"qType", "1,28"}},
      {{"action", "return"}, {"rCode", 5}}}),
      "system A/AAAA must use caller Core DNS and unsupported records must be explicitly refused");
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
  Require(rules[1]["inboundTag"] == Json::array({pin_input}) && rules[1]["domain"] == Json::array({"full:endpoint.invalid"})
      && rules[1]["port"] == "443", "physical pin must require exact private context, hostname and port");
  const auto& pin_egress = find_outbound(config, rules[1]["outboundTag"].get<std::string>());
  Require(pin_egress["protocol"] == "freedom" && pin_egress["settings"]["redirect"] == "192.0.2.5:0"
      && pin_egress["streamSettings"]["sockopt"]["interface"] == "Ethernet", "pin lost numeric destination, original port or underlay binding");
  Require(rules[2]["inboundTag"] == Json::array({pin_input}) && rules[2]["outboundTag"] == kIpv6Block
      && rules[2].size() == 3, "unmatched bootstrap context can fall through to caller routing");
  auto physical_options = source;
  physical_options["outbounds"][0]["sendThrough"] = "192.0.2.25";
  physical_options["outbounds"][0]["streamSettings"]["sockopt"] = {{"tcpFastOpen", true}, {"tcpKeepAliveIdle", 30}, {"mark", 7}};
  auto options_prepared = prepare(physical_options); Require(options_prepared.has_value(), "physical socket option profile rejected");
  auto options_config = Parse(*options_prepared);
  const auto& options_leaf = find_outbound(options_config, options_config["routing"]["rules"][1]["outboundTag"].get<std::string>());
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
    Require(effective["routing"]["rules"][1] == Json{{"type", "field"}, {"inboundTag", Json::array({kDnsUpstream})},
        {"ip", Json::array({"1.1.1.1/32"})}, {"port", "53"}, {"network", "tcp"}, {"outboundTag", "proxy"}}, "native default DNS is not scoped and proxied");
    if (empty_kind == 3) Require(effective["dns"]["hosts"] == profile["dns"]["hosts"] && effective["dns"]["queryStrategy"] == "UseIPv4", "empty DNS policy discarded caller hosts/strategy");
  }
  auto local = source;
  local["dns"]["servers"].insert(local["dns"]["servers"].begin(), Json{{"Address", "localhost"}, {"Tag", "caller-local"},
      {"domains", Json::array({"domain:private.invalid"})}, {"queryStrategy", "UseIPv4"}, {"skipFallback", true}, {"timeoutMs", 1200}});
  auto local_prepared = prepare(local); Require(local_prepared.has_value(), "explicit localhost native default rejected");
  auto expected_local = local["dns"]; expected_local["servers"][0]["Address"] = "tcp://1.1.1.1";
  Require(Parse(*local_prepared)["dns"] == expected_local, "localhost adaptation discarded source entry policy/tag");
  Require(Parse(*local_prepared)["routing"]["rules"][1]["inboundTag"] == Json::array({"caller-local"}), "localhost native policy lost its effective client tag");
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
  auto multi_outbound = source;
  auto backup = source["outbounds"][0]; backup["tag"] = "proxy-backup"; backup["settings"]["vnext"][0]["port"] = 8443;
  multi_outbound["outbounds"].push_back(backup);
  auto multi_prepared = prepare(multi_outbound); Require(multi_prepared.has_value(), "multiple independent outbounds rejected");
  auto multi_config = Parse(*multi_prepared);
  Require(multi_config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"]
      && find_outbound(multi_config, "proxy-backup")["settings"] == backup["settings"], "independent outbound identities/settings changed");
  Require(multi_config["routing"]["rules"][3]["domain"] == Json::array({"full:endpoint.invalid"}) && multi_config["routing"]["rules"][3]["port"] == "8443", "same-host second outbound pin lost its independent port");
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
  Require(rules[0]["inboundTag"] == Json::array({kManagedInbound}), "system DNS policy must scope to private adapter");
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
  Require(protected_references["routing"]["rules"][2]["outboundTag"] == std::string(kIpv6Block) + "-1", "closed bootstrap service inherited reverse tag");
  Require(protected_references["routing"]["rules"][0]["outboundTag"] == std::string(kDnsRelay) + "-1", "DNS service inherited user reference");
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
  Require(bypass_rules[0]["outboundTag"] == kDnsRelay && bypass_rules[bypass_rules.size()-Parse(*bypass)["routing"]["rules"].size()]["ip"][0] == "0.0.0.0/0", "subnet bypass overrides DNS protection");
  std::cout << "PASS desktop DNS, IPv6, privacy, auth, aliases and domain-routing security boundaries\n";
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
