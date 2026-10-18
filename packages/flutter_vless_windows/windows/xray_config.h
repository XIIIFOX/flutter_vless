#ifndef FLUTTER_VLESS_XRAY_CONFIG_H_
#define FLUTTER_VLESS_XRAY_CONFIG_H_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <set>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include "third_party/nlohmann/json.hpp"

namespace flutter_vless::xray_config {
using Json = nlohmann::ordered_json;

inline Json Parse(const std::string& text) {
  bool duplicate = false;
  std::vector<std::set<std::string>> keys;
  auto result = Json::parse(text, [&](int, Json::parse_event_t event, Json& value) {
    if (event == Json::parse_event_t::object_start) keys.emplace_back();
    if (event == Json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second) duplicate = true;
    if (event == Json::parse_event_t::object_end) keys.pop_back();
    return true;
  }, false, true);
  return duplicate ? Json(Json::value_t::discarded) : result;
}

// Match Go encoding/json's simple folding for schema fields, including long S
// and Kelvin sign. Never fold keys in user maps such as headers or DNS hosts.
inline std::string Fold(std::string value) {
  for (const auto& pair : {std::pair<std::string, std::string>{"\xC5\xBF", "s"}, {"\xE2\x84\xAA", "k"}}) {
    size_t offset = 0;
    while ((offset = value.find(pair.first, offset)) != std::string::npos) value.replace(offset, pair.first.size(), pair.second);
  }
  for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return value;
}
inline bool Fields(Json& object, std::initializer_list<const char*> names) {
  if (!object.is_object()) return false;
  for (const auto* name : names) {
    std::vector<std::string> matches;
    for (auto it = object.begin(); it != object.end(); ++it) if (Fold(it.key()) == Fold(name)) matches.push_back(it.key());
    if (matches.size() > 1) return false;
    if (matches.size() == 1 && matches[0] != name) { object[name] = object[matches[0]]; object.erase(matches[0]); }
  }
  return true;
}
inline bool Object(Json& parent, const char* key) {
  if (!parent.contains(key) || parent[key].is_null()) parent[key] = Json::object();
  return parent[key].is_object();
}
inline bool PrivateStream(Json& stream) {
  if (!Fields(stream, {"tlsSettings", "realitySettings", "xhttpSettings", "splithttpSettings", "finalmask"})) return false;
  for (const auto* key : {"tlsSettings", "realitySettings"}) {
    if (!stream.contains(key) || stream[key].is_null()) continue;
    auto& settings = stream[key];
    if (!Fields(settings, {"masterKeyLog", "show"})) return false;
    settings["masterKeyLog"] = "";
    if (std::string(key) == "realitySettings") settings["show"] = false;
  }
  if (stream.contains("finalmask") && !stream["finalmask"].is_null()) {
    auto& mask = stream["finalmask"];
    if (!Fields(mask, {"tcp", "udp", "quicParams"})) return false;
    if (mask.contains("quicParams") && !mask["quicParams"].is_null()) {
      if (!Fields(mask["quicParams"], {"debug"})) return false;
      mask["quicParams"]["debug"] = false;
    }
    for (const auto* key : {"tcp", "udp"}) {
      if (!mask.contains(key) || mask[key].is_null()) continue;
      if (!mask[key].is_array()) return false;
      for (auto& entry : mask[key]) {
        if (!Fields(entry, {"type", "settings"})) return false;
        if (!entry.contains("type") || !entry["type"].is_string()) return false;
        if (Fold(entry["type"].get<std::string>()) != "realm") continue;
        if (!Object(entry, "settings") || !Fields(entry["settings"], {"tlsConfig"})) return false;
        auto& settings = entry["settings"];
        if (!Object(settings, "tlsConfig") || !Fields(settings["tlsConfig"], {"masterKeyLog"})) return false;
        settings["tlsConfig"]["masterKeyLog"] = "";
      }
    }
  }
  for (const auto* key : {"xhttpSettings", "splithttpSettings"}) {
    if (!stream.contains(key) || stream[key].is_null()) continue;
    auto& settings = stream[key];
    if (!Fields(settings, {"extra", "downloadSettings"})) return false;
    for (auto* container : {&settings, settings.contains("extra") && !settings["extra"].is_null() ? &settings["extra"] : &settings}) {
      if (!Fields(*container, {"downloadSettings"})) return false;
      if (container->contains("downloadSettings") && !(*container)["downloadSettings"].is_null()
          && !PrivateStream((*container)["downloadSettings"])) return false;
    }
  }
  return true;
}
inline bool Normalize(Json& config) {
  if (!Fields(config, {"inbounds", "outbounds", "dns", "routing", "log", "api", "policy", "stats", "fakeDns", "fakedns"})) return false;
  for (const auto* key : {"inbounds", "outbounds"}) {
    if (std::string(key) == "inbounds" && !config.contains(key)) config[key] = Json::array();
    if (!config.contains(key) || !config[key].is_array()) return false;
    for (auto& entry : config[key]) {
      if (!Fields(entry, {"protocol", "tag", "port", "listen", "settings", "streamSettings", "sniffing", "proxySettings"})) return false;
      if (!entry.contains("protocol") || !entry["protocol"].is_string()) return false;
      entry["protocol"] = Fold(entry["protocol"].get<std::string>());
      if (entry.contains("streamSettings") && !entry["streamSettings"].is_null() && !PrivateStream(entry["streamSettings"])) return false;
    }
  }
  // No imported filenames, core stdout, DNS questions, TLS keys or Reality dumps.
  config["log"] = {{"access", "none"}, {"error", "none"}, {"loglevel", "none"}, {"dnsLog", false}};
  return true;
}

inline std::optional<uint16_t> Port(const Json& object) {
  if (!object.is_object() || !object.contains("port")) return std::nullopt;
  const auto& value = object["port"];
  if (!value.is_number_integer()) return std::nullopt;
  const auto port = value.get<int64_t>();
  if (port < 1 || port > 65535) return std::nullopt;
  return static_cast<uint16_t>(port);
}

// Only inspect inbound objects. Property order, nested settings, and outbound
// protocols must never affect the local listener selected by the service.
inline std::optional<uint16_t> SocksPort(const std::string& text) {
  const auto config = Parse(text);
  if (!config.is_object() || !config.contains("inbounds") ||
      !config["inbounds"].is_array()) return std::nullopt;
  std::optional<uint16_t> first;
  for (const auto& inbound : config["inbounds"]) {
    if (!inbound.is_object() || !inbound.contains("protocol") ||
        inbound["protocol"] != "socks") continue;
    const auto port = Port(inbound);
    if (!port) continue;
    if (!first) first = port;
    if (inbound.contains("tag") && (inbound["tag"] == "in_proxy" ||
        inbound["tag"] == "socks-in" || inbound["tag"] == "socks")) return port;
  }
  return first;
}

// Reserve references as well as definitions so adding an adapter cannot make a
// previously dangling user rule, chain, API, DNS or reverse tag target a service.
class ServiceTags {
 public:
  explicit ServiceTags(const Json& config) { Collect(config); }
  std::string Next(const std::string& preferred) {
    auto candidate = preferred;
    for (unsigned suffix = 1; used_.count(candidate); ++suffix) candidate = preferred + "-" + std::to_string(suffix);
    used_.insert(candidate);
    return candidate;
  }
 private:
  std::set<std::string> used_;
  void Collect(const Json& value) {
    if (value.is_object()) for (auto it = value.begin(); it != value.end(); ++it) {
      const auto field = Fold(it.key());
      if (field == "tag" || field == "inboundtag" || field == "outboundtag" ||
          field == "balancertag" || field == "dialerproxy" || field == "fallbacktag") {
        if (it->is_string()) used_.insert(it->get<std::string>());
        if (it->is_array()) for (const auto& tag : *it) if (tag.is_string()) used_.insert(tag.get<std::string>());
      }
      Collect(*it);
    } else if (value.is_array()) for (const auto& child : value) Collect(child);
  }
};

inline bool AddApi(Json& config, uint16_t api_port) {
  if (!config.is_object()) return false;
  if (!config.contains("stats")) config["stats"] = Json::object();
  if (!config.contains("policy")) config["policy"] = Json::object();
  if (!config["policy"].is_object()) return false;
  auto& policy = config["policy"];
  if (!policy.contains("system")) policy["system"] = Json::object();
  if (!policy["system"].is_object()) return false;
  for (const auto* key : {"statsInboundUplink", "statsInboundDownlink",
                          "statsOutboundUplink", "statsOutboundDownlink"}) {
    policy["system"][key] = true;
  }
  // Xray's API listen creates its own listener. No duplicate routing block,
  // synthetic catch-all rule, or tag-dependent inbound is needed.
  if (!config.contains("api")) {
    config["api"] = {{"tag", ServiceTags(config).Next("api")},
      {"listen", "127.0.0.1:" + std::to_string(api_port)},
      {"services", Json::array({"StatsService"})}};
  }
  return true;
}

inline bool PrepareProxy(std::string& text,
                         const std::function<bool(uint16_t)>& is_free,
                         const std::function<uint16_t()>& free_port) {
  auto config = Parse(text);
  if (!Normalize(config) || !config.contains("inbounds") ||
      !config["inbounds"].is_array()) return false;
  for (auto& inbound : config["inbounds"]) {
    const auto port = Port(inbound);
    if (port && !is_free(*port)) {
      const auto replacement = free_port();
      if (replacement == 0) return false;
      inbound["port"] = replacement;
    }
  }
  config.erase("api");
  uint16_t api_port = is_free(10085) ? 10085 : free_port();
  if (!api_port || !AddApi(config, api_port)) return false;
  text = config.dump();
  return SocksPort(text).has_value();
}

// Freedom sockets must use the interface selected before installing the TUN
// default route; otherwise a direct domain recursively re-enters tun2socks.
inline bool BindDirectOutbounds(std::string& text, const std::string& interface_name) {
  auto config = Parse(text);
  if (interface_name.empty() || !config.is_object() ||
      !config.contains("outbounds") || !config["outbounds"].is_array()) return false;
  for (auto& outbound : config["outbounds"]) {
    if (!outbound.is_object() || !outbound.contains("protocol") ||
        outbound["protocol"] != "freedom") continue;
    if (!outbound.contains("streamSettings") || outbound["streamSettings"].is_null()) {
      outbound["streamSettings"] = Json::object();
    }
    if (!outbound["streamSettings"].is_object()) return false;
    auto& stream = outbound["streamSettings"];
    if (!stream.contains("sockopt") || stream["sockopt"].is_null()) stream["sockopt"] = Json::object();
    if (!stream["sockopt"].is_object()) return false;
    auto& options = stream["sockopt"];
    if (!options.contains("interface") || options["interface"].is_null() ||
        options["interface"] == "") options["interface"] = interface_name;
    if (!options["interface"].is_string()) return false;
  }
  text = config.dump();
  return true;
}

inline std::optional<std::string> PrepareVpn(const std::string& text) {
  auto config = Parse(text);
  if (!SocksPort(text) || !AddApi(config, 10086)) return std::nullopt;
  for (auto& inbound : config["inbounds"]) {
    if (inbound.is_object() && inbound.contains("listen") &&
        (inbound["listen"] == "[::1]" || inbound["listen"] == "::1")) {
      inbound["listen"] = "127.0.0.1";
    }
  }
  // Routing rules, their order, DNS choices and outbound settings belong to
  // the caller. OS transport bypass must not overwrite Xray domain routing.
  return config.dump();
}

inline constexpr const char* kVirtualDns = "198.18.0.2";
inline constexpr const char* kDnsRelay = "flutter-vless-system-dns";
inline constexpr const char* kDnsUpstream = "flutter-vless-dns-upstream";
inline constexpr const char* kIpv6Block = "flutter-vless-ipv6-block";
inline constexpr const char* kManagedInbound = "flutter-vless-tun";

inline std::string UniqueTag(const Json& config, const std::string& preferred) {
  return ServiceTags(config).Next(preferred);
}

inline std::optional<std::string> PortEnvironment(const std::string& name) {
#ifdef _WIN32
  char* value = nullptr; size_t size = 0;
  if (_dupenv_s(&value, &size, name.c_str()) != 0 || !value) return std::nullopt;
  std::string result(value); std::free(value); return result;
#else
  const auto* value = std::getenv(name.c_str());
  return value ? std::optional<std::string>{value} : std::nullopt;
#endif
}

inline std::string PortTrimSpace(std::string text) {
  // Unicode White_Space, matching Go strings.TrimSpace for valid UTF-8.
  for (;;) {
    bool changed = false;
    for (const std::string space : {"\t", "\n", "\v", "\f", "\r", " ", "\xc2\x85", "\xc2\xa0",
        "\xe1\x9a\x80", "\xe2\x80\x80", "\xe2\x80\x81", "\xe2\x80\x82", "\xe2\x80\x83", "\xe2\x80\x84",
        "\xe2\x80\x85", "\xe2\x80\x86", "\xe2\x80\x87", "\xe2\x80\x88", "\xe2\x80\x89", "\xe2\x80\x8a",
        "\xe2\x80\xa8", "\xe2\x80\xa9", "\xe2\x80\xaf", "\xe2\x81\x9f", "\xe3\x80\x80"}) {
      if (text.size() >= space.size() && text.compare(0, space.size(), space) == 0) { text.erase(0, space.size()); changed = true; }
      if (text.size() >= space.size() && text.compare(text.size()-space.size(), space.size(), space) == 0) { text.resize(text.size()-space.size()); changed = true; }
    }
    if (!changed) return text;
  }
}

using PortEnvironmentReader = std::function<std::optional<std::string>(const std::string&)>;
inline std::optional<std::set<unsigned>> ReservedPorts(const Json& value,
    const PortEnvironmentReader& read_environment = PortEnvironment) {
  std::set<unsigned> occupied;
  if (value.is_number_unsigned()) {
    auto port = value.get<uint64_t>(); if (port > 65535) return std::nullopt;
    if (port) occupied.insert(static_cast<unsigned>(port)); return occupied;
  }
  if (value.is_number_integer()) {
    auto port = value.get<int64_t>(); if (port < 0 || port > 65535) return std::nullopt;
    if (port) occupied.insert(static_cast<unsigned>(port)); return occupied;
  }
  if (!value.is_string()) return std::nullopt;
  const auto text = value.get<std::string>();
  size_t offset = 0;
  while (offset < text.size()) {
    auto comma = text.find(',', offset);
    auto part = PortTrimSpace(text.substr(offset, comma == std::string::npos ? comma : comma - offset));
    if (!part.empty()) {
      bool environment = part.rfind("env:", 0) == 0;
      if (environment) {
        auto name = part.substr(4); auto resolved = read_environment(name);
        if (!resolved) {
          auto alternate = PortTrimSpace(name);
          for (auto& c : alternate) { if (c == '.') c = '_'; else if (c >= 'a' && c <= 'z') c = static_cast<char>(c-'a'+'A'); }
          resolved = read_environment(alternate);
        }
        if (!resolved) return std::nullopt;
        part = *resolved;
      }
      auto dash = part.find('-');
      auto number = [&](const std::string& digits) -> std::optional<unsigned> {
        if (digits.empty() || digits.find_first_not_of("0123456789") != std::string::npos ||
            (!environment && dash == std::string::npos && digits.size() > 1 && digits[0] == '0')) return std::nullopt;
        unsigned result = 0;
        for (char c : digits) { result = result*10+static_cast<unsigned>(c-'0'); if (result > 65535) return std::nullopt; }
        return result;
      };
      auto first = number(part.substr(0, dash));
      auto last = dash == std::string::npos ? first : number(part.substr(dash + 1));
      if (!first || !last) return std::nullopt;
      for (unsigned port = *first; port <= *last; ++port) if (port) occupied.insert(port);
    }
    if (comma == std::string::npos) break;
    offset = comma + 1;
  }
  return occupied;
}

inline std::optional<uint16_t> AvailablePort(const Json& config, uint16_t preferred) {
  std::set<unsigned> occupied;
  if (config.contains("inbounds") && config["inbounds"].is_array()) for (const auto& inbound : config["inbounds"]) {
    if (inbound.contains("listen") && inbound["listen"].is_string()) {
      const auto listen = inbound["listen"].get<std::string>();
      if ((!listen.empty() && listen[0] == '@') || std::filesystem::u8path(listen).is_absolute()) continue;
    }
    if (!inbound.contains("port")) continue;
    const auto ports = ReservedPorts(inbound["port"]);
    if (!ports) return std::nullopt;
    occupied.insert(ports->begin(), ports->end());
  }
  for (unsigned port = preferred; port <= 65535; ++port) if (!occupied.count(port)) return static_cast<uint16_t>(port);
  for (unsigned port = 1024; port < preferred; ++port) if (!occupied.count(port)) return static_cast<uint16_t>(port);
  return std::nullopt;
}

inline std::optional<uint16_t> ApiPort(const std::string& text) {
  auto config = Parse(text);
  if (!config.is_object() || !config.contains("api") || !config["api"].is_object() || !config["api"].contains("listen") || !config["api"]["listen"].is_string()) return std::nullopt;
  auto listen = config["api"]["listen"].get<std::string>();
  if (listen.rfind("127.0.0.1:", 0) != 0) return std::nullopt;
  auto value = listen.substr(10);
  if (value.empty() || value.size() > 5 || value.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
  return Port(Json{{"port", std::stoi(value)}});
}

inline bool Literal4(const std::string& value) {
  size_t start = 0;
  for (int part = 0; part < 4; ++part) {
    size_t end = value.find('.', start);
    if ((part == 3) != (end == std::string::npos)) return false;
    auto field = value.substr(start, end == std::string::npos ? end : end - start);
    if (field.empty() || field.size() > 3 || (field.size() > 1 && field[0] == '0')) return false;
    int n = 0; for (char c : field) { if (c < '0' || c > '9') return false; n = n * 10 + c - '0'; }
    if (n > 255) return false;
    start = end + 1;
  }
  return true;
}
inline bool BootstrapStream(Json& stream, Json& hosts, const std::string& interface_name,
                            const std::function<std::string(const std::string&)>& resolve) {
  if (!Fields(stream, {"address", "sockopt", "xhttpSettings", "splithttpSettings"}) || !Object(stream, "sockopt")) return false;
  auto& options = stream["sockopt"];
  if (!Fields(options, {"interface", "domainStrategy", "addressPortStrategy"})) return false;
  if (options.contains("addressPortStrategy") && options["addressPortStrategy"] != "none") return false;
  options["domainStrategy"] = "ForceIPv4";
  // Bind every dialer to the selected underlay; no endpoint /32 route can expose
  // unrelated application traffic to the same server address.
  options["interface"] = interface_name;
  if (stream.contains("address")) {
    if (!stream["address"].is_string()) return false;
    const auto host = stream["address"].get<std::string>();
    if (!host.empty() && !Literal4(host)) {
      auto ip = resolve(host); if (!Literal4(ip)) return false;
      hosts[Fold(host.back() == '.' ? host.substr(0, host.size()-1) : host)] = ip;
    }
  }
  for (const auto* key : {"xhttpSettings", "splithttpSettings"}) {
    if (!stream.contains(key) || stream[key].is_null()) continue;
    auto& settings = stream[key];
    if (!Fields(settings, {"extra", "downloadSettings"})) return false;
    auto* container = &settings;
    if (settings.contains("extra") && !settings["extra"].is_null()) container = &settings["extra"];
    if (!Fields(*container, {"downloadSettings"})) return false;
    if (container->contains("downloadSettings") && !(*container)["downloadSettings"].is_null()
        && !BootstrapStream((*container)["downloadSettings"], hosts, interface_name, resolve)) return false;
  }
  return true;
}

inline std::optional<std::string> PrepareProtectedVpn(const std::string& text,
    const std::string& username, const std::string& password, const std::string& interface_name,
    const std::function<std::string(const std::string&)>& resolve) {
  auto config = Parse(text);
  if (username.empty() || password.empty() || username.size() > 255 || password.size() > 255 || interface_name.empty()
      || !Normalize(config) || config.contains("fakeDns") || config.contains("fakedns")) return std::nullopt;
  ServiceTags service_tags(config);
  auto& inbounds = config["inbounds"];
  // Keep every imported listener intact. tun2socks gets a separate loopback
  // listener with native session authentication, never a caller's public input.
  auto port = AvailablePort(config, 10807);
  if (!port) return std::nullopt;
  auto managed_tag = service_tags.Next(kManagedInbound);
  Json inbound = {{"tag", managed_tag}, {"protocol", "socks"}, {"listen", "127.0.0.1"}, {"port", *port},
      {"settings", {{"auth", "password"}, {"accounts", Json::array({{{"user", username}, {"pass", password}}})}, {"udp", true}, {"ip", "127.0.0.1"}}},
      {"sniffing", {{"enabled", true}, {"routeOnly", true}, {"destOverride", Json::array({"http", "tls", "quic"})}}}};
  inbounds.insert(inbounds.begin(), inbound);
  const auto relay_tag = service_tags.Next(kDnsRelay);
  const auto upstream_tag = service_tags.Next(kDnsUpstream);
  const auto ipv6_tag = service_tags.Next(kIpv6Block);
  std::string proxy;
  Json hosts = Json::object();
  for (auto& outbound : config["outbounds"]) {
    const auto protocol = outbound["protocol"].get<std::string>();
    if (protocol == "blackhole") continue;
    if (!Object(outbound, "streamSettings") || !BootstrapStream(outbound["streamSettings"], hosts, interface_name, resolve)) return std::nullopt;
    if (protocol == "freedom") {
      if (!Object(outbound, "settings") || !Fields(outbound["settings"], {"domainStrategy", "targetStrategy"})) return std::nullopt;
      outbound["settings"]["domainStrategy"] = "ForceIPv4";
      outbound["settings"].erase("targetStrategy");
      continue;
    }
    if (!std::set<std::string>{"vless","vmess","trojan","shadowsocks","socks","http","hysteria","wireguard"}.count(protocol)) return std::nullopt;
    if (!outbound.contains("tag") || outbound["tag"] == "") {
      outbound["tag"] = service_tags.Next("flutter-vless-proxy");
    }
    if (proxy.empty() || outbound["tag"] == "proxy") proxy = outbound["tag"].get<std::string>();
    if (!Object(outbound, "settings") || !Fields(outbound["settings"], {"address", "vnext", "servers", "peers"})) return std::nullopt;
    auto& settings = outbound["settings"];
    std::vector<Json*> endpoints;
    if (settings.contains("address")) endpoints.push_back(&settings);
    else {
      const auto key = protocol == "wireguard" ? "peers" : (protocol == "vless" || protocol == "vmess" ? "vnext" : "servers");
      if (!settings.contains(key) || !settings[key].is_array()) return std::nullopt;
      for (auto& entry : settings[key]) endpoints.push_back(&entry);
    }
    if (endpoints.empty()) return std::nullopt;
    for (auto* entry : endpoints) {
      if (!Fields(*entry, {"address", "endpoint"})) return std::nullopt;
      const char* key = protocol == "wireguard" ? "endpoint" : "address";
      if (!entry->contains(key) || !(*entry)[key].is_string()) return std::nullopt;
      std::string host = (*entry)[key].get<std::string>();
      if (protocol == "wireguard") {
        auto colon = host.rfind(':'); if (colon == std::string::npos) return std::nullopt;
        host = host.substr(0, colon);
      }
      if (!Literal4(host)) {
        // IPv6 endpoints cannot be reached under the explicit IPv4-only policy.
        if (host.empty() || host.find(':') != std::string::npos) return std::nullopt;
        auto ip = resolve(host); if (!Literal4(ip)) return std::nullopt;
        hosts[Fold(host.back() == '.' ? host.substr(0, host.size()-1) : host)] = ip;
      }
    }
  }
  if (proxy.empty()) return std::nullopt;
  config["outbounds"].push_back({{"tag", relay_tag}, {"protocol", "dns"},
      {"settings", {{"rewriteNetwork", "tcp"}, {"rewriteAddress", "1.1.1.1"}, {"rewritePort", 53},
          // Raw relay ignores dns.queryStrategy. Return AAAA NODATA so clients
          // do not choose IPv6 destinations blocked by the VPN policy.
          {"rules", Json::array({{{"action", "return"}, {"qType", "28"}, {"rCode", 0}},
                                {{"action", "direct"}}})}}}, {"streamSettings", {{"sockopt", {{"dialerProxy", proxy}}}}}});
  config["outbounds"].push_back({{"tag", ipv6_tag}, {"protocol", "blackhole"}});
  config["dns"] = {{"hosts", hosts}, {"servers", Json::array({"tcp://1.1.1.1"})}, {"tag", upstream_tag},
      {"queryStrategy", "UseIPv4"}, {"disableFallback", true}};
  if (!Object(config, "routing") || !Fields(config["routing"], {"rules", "domainStrategy"})) return std::nullopt;
  auto& routing = config["routing"];
  if (!routing.contains("rules")) routing["rules"] = Json::array();
  if (!routing["rules"].is_array()) return std::nullopt;
  Json rules = Json::array({
      {{"type", "field"}, {"inboundTag", Json::array({managed_tag})}, {"ip", Json::array({"::/0"})}, {"outboundTag", ipv6_tag}},
      {{"type", "field"}, {"inboundTag", Json::array({upstream_tag})}, {"outboundTag", proxy}},
      {{"type", "field"}, {"inboundTag", Json::array({managed_tag})}, {"ip", Json::array({std::string(kVirtualDns) + "/32"})}, {"port", "53"}, {"network", "tcp,udp"}, {"outboundTag", relay_tag}}
  });
  for (const auto& rule : routing["rules"]) rules.push_back(rule);
  routing["rules"] = rules;
  // Replace imported API listeners; only statistics are exposed on loopback.
  config.erase("api");
  auto api_port = AvailablePort(config, 10086);
  if (!api_port || !AddApi(config, *api_port)) return std::nullopt;
  config["api"]["tag"] = service_tags.Next("flutter-vless-stats");
  return config.dump();
}

// Explicit subnet bypass stays inside the authenticated proxy and below the
// mandatory DNS/IPv6 rules, never as physical adapter route exceptions.
inline std::optional<std::string> ApplyBypass(const std::string& text, const std::vector<std::string>& cidrs) try {
  for (const auto& cidr : cidrs) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos || !Literal4(cidr.substr(0, slash))) return std::nullopt;
    const auto bits = cidr.substr(slash + 1);
    if (bits.empty() || bits.size() > 2 || bits.find_first_not_of("0123456789") != std::string::npos
        || std::stoi(bits) > 32) return std::nullopt;
  }
  if (cidrs.empty()) return text;
  auto config = Parse(text);
  if (!Normalize(config) || !Object(config, "routing") || !Fields(config["routing"], {"rules"})) return std::nullopt;
  auto& routing = config["routing"];
  if (!routing.contains("rules")) routing["rules"] = Json::array();
  if (!routing["rules"].is_array()) return std::nullopt;
  const auto tag = UniqueTag(config, "flutter-vless-subnet-direct");
  config["outbounds"].push_back({{"tag", tag}, {"protocol", "freedom"}});
  routing["rules"].insert(routing["rules"].begin(), Json{{"type", "field"}, {"ip", cidrs}, {"outboundTag", tag}});
  return config.dump();
} catch (...) { return std::nullopt; }
}  // namespace flutter_vless::xray_config
#endif
