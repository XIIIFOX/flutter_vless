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
#include <map>
#include <vector>
#include "third_party/nlohmann/json.hpp"
#include "asset_location.h"

namespace flutter_vless::xray_config {
using Json = nlohmann::ordered_json;
using PortEnvironmentReader = std::function<std::optional<std::string>(const std::string&)>;
inline std::optional<std::string> PortEnvironment(const std::string& name);
inline std::string PortTrimSpace(std::string text);
inline std::optional<std::string> ResolveInboundListen(const std::string& text, const PortEnvironmentReader& read_environment);
inline bool UnixInboundListen(std::string resolved);
inline bool BindDnsAddresses(Json& config, const PortEnvironmentReader& read_environment);
inline bool BindLogicalAddresses(Json& config, const PortEnvironmentReader& read_environment);

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

// Freeze only file fields actually consumed by Core's StreamConfig.Build.
// The explicit root is a resolution base, not a filesystem sandbox. Referenced
// files and their contents are validated by Core before session replacement.
inline bool BindCertificatePaths(std::string& text, const asset_location::Root& directory) {
  if (!directory) return true;
  if (!asset_location::Valid(directory)) return false;
  auto config = Parse(text);
  if (!config.is_object()) return false;
  const auto field = [](Json& object, const char* name, Json*& result) {
    if (!object.is_object()) return false;
    result = nullptr;
    for (auto it = object.begin(); it != object.end(); ++it) {
      if (Fold(it.key()) != Fold(name)) continue;
      if (result) return false;
      result = &it.value();
    }
    return true;
  };
  std::function<bool(Json&)> stream;
  stream = [&](Json& value) {
    Json *security = nullptr, *tls = nullptr;
    if (!field(value, "security", security)) return false;
    if (security && !security->is_null() && !security->is_string()) return false;
    if (security && security->is_string() && Fold(security->get<std::string>()) == "tls") {
      if (!field(value, "tlsSettings", tls)) return false;
      if (tls && !tls->is_null()) {
        Json* certificates = nullptr;
        if (!field(*tls, "certificates", certificates)) return false;
        if (certificates && !certificates->is_null()) {
          if (!certificates->is_array()) return false;
          for (auto& certificate : *certificates) {
            for (const auto* name : {"certificateFile", "keyFile"}) {
              Json* path = nullptr;
              if (!field(certificate, name, path)) return false;
              if (!path || path->is_null()) continue;
              if (!path->is_string()) return false;
              const auto raw = path->get<std::string>();
              if (raw.find('\0') != std::string::npos) return false;
              if (raw.empty()) continue;
              const auto file = std::filesystem::u8path(raw);
              if (!file.is_absolute()) {
                // Go Join appends nonabsolute file text before Clean. On
                // Windows operator/ would replace the base for \file.pem
                // or another drive-relative root name instead.
                auto joined = *directory;
                joined += std::filesystem::path::preferred_separator;
                joined += file.native();
                *path = joined.lexically_normal().u8string();
              }
            }
          }
        }
      }
    }
    Json *preferred = nullptr, *legacy = nullptr;
    if (!field(value, "xhttpSettings", preferred) || !field(value, "splithttpSettings", legacy)) return false;
    Json* transport = preferred && !preferred->is_null() ? preferred : legacy;
    if (!transport || transport->is_null()) return true;
    Json* extra = nullptr;
    if (!field(*transport, "extra", extra)) return false;
    // A present extra, even JSON null, replaces the outer download settings.
    Json* effective = extra ? extra : transport;
    if (effective->is_null()) return true;
    Json* download = nullptr;
    if (!field(*effective, "downloadSettings", download)) return false;
    return !download || download->is_null() || stream(*download);
  };
  try {
    for (const auto* direction : {"inbounds", "outbounds"}) {
      Json* entries = nullptr;
      if (!field(config, direction, entries)) return false;
      if (!entries || entries->is_null()) continue;
      if (!entries->is_array()) return false;
      for (auto& entry : *entries) {
        Json* settings = nullptr;
        if (!field(entry, "streamSettings", settings)) return false;
        if (settings && !settings->is_null() && !stream(*settings)) return false;
      }
    }
    text = config.dump();
    return true;
  } catch (const std::exception&) {
    return false;
  }
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
inline bool Normalize(Json& config, const PortEnvironmentReader& read_environment = PortEnvironment) {
  if (!Fields(config, {"inbounds", "outbounds", "dns", "routing", "log", "api", "policy", "stats", "fakeDns", "fakedns"})) return false;
  for (const auto* key : {"inbounds", "outbounds"}) {
    if (std::string(key) == "inbounds" && !config.contains(key)) config[key] = Json::array();
    if (!config.contains(key) || !config[key].is_array()) return false;
    for (auto& entry : config[key]) {
      if (!Fields(entry, {"protocol", "tag", "port", "listen", "settings", "streamSettings", "sniffing", "proxySettings"})) return false;
      if (!entry.contains("protocol") || !entry["protocol"].is_string()) return false;
      entry["protocol"] = Fold(entry["protocol"].get<std::string>());
      // Freeze this Address field before the child environment is sanitized.
      // Other strings and caller endpoint fields have their own semantics.
      if (std::string(key) == "inbounds" && entry.contains("listen") && entry["listen"].is_string()) {
        const auto resolved = ResolveInboundListen(entry["listen"].get<std::string>(), read_environment);
        if (!resolved) return false;
        entry["listen"] = *resolved;
      }
      if (entry.contains("streamSettings") && !entry["streamSettings"].is_null() && !PrivateStream(entry["streamSettings"])) return false;
    }
  }
  if (!BindDnsAddresses(config, read_environment) || !BindLogicalAddresses(config, read_environment)) return false;
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
  explicit ServiceTags(const Json& config) { Collect(config); CollectSelectors(config); }
  std::string Next(const std::string& preferred) {
    auto candidate = Unique(preferred);
    // A suffix can itself enter a selector ("private" -> "private-1").
    // Escape the original stem once; a safe first scalar also covers suffixes.
    if (Covered(candidate)) if (const auto scalar = EscapeScalar()) candidate = Unique(*scalar + preferred);
    used_.insert(candidate);
    return candidate;
  }
 private:
  std::set<std::string> used_;
  std::set<std::string> prefixes_, first_scalars_;
  bool escape_scanned_ = false;
  std::optional<std::string> escape_scalar_;
  std::string Unique(const std::string& stem) const {
    auto candidate = stem;
    for (size_t suffix = 1; used_.count(candidate); ++suffix) candidate = stem + "-" + std::to_string(suffix);
    return candidate;
  }
  bool Covered(const std::string& tag) const {
    for (const auto& prefix : prefixes_) if (tag.compare(0, prefix.size(), prefix) == 0) return true;
    return false;
  }
  static std::string Scalar(uint32_t value) {
    std::string text;
    if (value <= 0x7f) text += static_cast<char>(value);
    else if (value <= 0x7ff) {
      text += static_cast<char>(0xc0 | (value >> 6)); text += static_cast<char>(0x80 | (value & 0x3f));
    } else if (value <= 0xffff) {
      text += static_cast<char>(0xe0 | (value >> 12)); text += static_cast<char>(0x80 | ((value >> 6) & 0x3f));
      text += static_cast<char>(0x80 | (value & 0x3f));
    } else {
      text += static_cast<char>(0xf0 | (value >> 18)); text += static_cast<char>(0x80 | ((value >> 12) & 0x3f));
      text += static_cast<char>(0x80 | ((value >> 6) & 0x3f)); text += static_cast<char>(0x80 | (value & 0x3f));
    }
    return text;
  }
  std::optional<std::string> EscapeScalar() {
    if (escape_scanned_) return escape_scalar_;
    escape_scanned_ = true;
    auto choose = [&](uint32_t value) {
      auto scalar = Scalar(value);
      if (first_scalars_.count(scalar)) return false;
      escape_scalar_ = std::move(scalar); return true;
    };
    for (const unsigned char value : std::string("_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"))
      if (choose(value)) return escape_scalar_;
    for (const auto& range : {std::pair<uint32_t, uint32_t>{0xe000, 0xf8ff}, {0xf0000, 0xffffd}, {0x100000, 0x10fffd}})
      for (auto value = range.first; value <= range.second; ++value) if (choose(value)) return escape_scalar_;
    for (uint32_t value = 0; value <= 0x10ffff; ++value)
      if ((value < 0xd800 || value > 0xdfff) && choose(value)) return escape_scalar_;
    // Empty selectors and collective universal coverage require Core handler
    // provenance. Keep the old exact allocator; never reject a valid profile.
    return std::nullopt;
  }
  void AddPrefix(const std::string& prefix) {
    if (prefix.empty()) return; // Universal selection remains an explicit open boundary.
    prefixes_.insert(prefix);
    // Parsed JSON contains valid UTF-8; compare encoded scalars/bytes as Go does.
    const auto first = static_cast<unsigned char>(prefix[0]);
    const size_t width = first < 0x80 ? 1 : first < 0xe0 ? 2 : first < 0xf0 ? 3 : 4;
    first_scalars_.insert(prefix.substr(0, width));
  }
  void AddSelectors(const Json& value, bool string_list) {
    if (value.is_array()) {
      for (const auto& item : value) if (item.is_string()) AddPrefix(item.get<std::string>());
    } else if (string_list && value.is_string()) {
      const auto text = value.get<std::string>();
      size_t start = 0;
      for (;;) {
        const auto comma = text.find(',', start);
        AddPrefix(text.substr(start, comma == std::string::npos ? comma : comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
      }
    }
  }
  static void Field(const Json& object, const char* name, const std::function<void(const Json&)>& visit) {
    if (!object.is_object()) return;
    for (auto it = object.begin(); it != object.end(); ++it) if (Fold(it.key()) == name) visit(*it);
  }
  void CollectSelectors(const Json& config) {
    Field(config, "routing", [&](const Json& routing) {
      Field(routing, "balancers", [&](const Json& balancers) {
        if (balancers.is_array()) for (const auto& balancer : balancers)
          Field(balancer, "selector", [&](const Json& value) { AddSelectors(value, true); });
      });
    });
    for (const auto* name : {"observatory", "burstobservatory"}) Field(config, name, [&](const Json& observer) {
      Field(observer, "subjectselector", [&](const Json& value) { AddSelectors(value, false); });
    });
  }
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
  // Explicit roots, including null and disabled flags, belong to the caller.
  // Enabling counters is a default only when the entire policy is absent.
  if (!config.contains("policy")) config["policy"] = {{"system", {
      {"statsInboundUplink", true}, {"statsInboundDownlink", true},
      {"statsOutboundUplink", true}, {"statsOutboundDownlink", true}}}};
  // Xray's API listen creates its own listener. No duplicate routing block,
  // synthetic catch-all rule, or tag-dependent inbound is needed.
  if (!config.contains("api")) {
    if (!api_port) return false;
    config["api"] = {{"tag", ServiceTags(config).Next("api")},
      {"listen", "127.0.0.1:" + std::to_string(api_port)},
      {"services", Json::array({"StatsService"})}};
  }
  return true;
}

inline std::optional<uint16_t> AvailablePort(const Json& config, uint16_t preferred,
    const PortEnvironmentReader& read_environment = PortEnvironment);

inline bool PrepareProxy(std::string& text,
                         const std::function<bool(uint16_t)>& is_free,
                         const std::function<uint16_t()>& free_port) {
  auto config = Parse(text);
  if (!Normalize(config) || !config.contains("inbounds") ||
      !config["inbounds"].is_array()) return false;
  for (auto& inbound : config["inbounds"]) {
    if (inbound.contains("listen") && inbound["listen"].is_string()
        && UnixInboundListen(inbound["listen"].get<std::string>())) continue;
    const auto port = Port(inbound);
    if (port && !is_free(*port)) {
      const auto replacement = free_port();
      if (replacement == 0) return false;
      inbound["port"] = replacement;
    }
  }
  uint16_t owned_api_port = 0;
  if (!config.contains("api")) {
    auto api_port = AvailablePort(config, 10085);
    if (!api_port) return false;
    if (!is_free(*api_port)) {
      api_port.reset();
      // An OS-free ephemeral port can still be declared by this not-yet-started
      // document. Bound retries and fail if neither boundary can be satisfied.
      for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto candidate = free_port();
        if (!candidate) return false;
        const auto available = AvailablePort(config, candidate);
        if (available && *available == candidate && is_free(candidate)) { api_port = candidate; break; }
      }
    }
    if (!api_port) return false;
    owned_api_port = *api_port;
  }
  if (!AddApi(config, owned_api_port)) return false;
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
  if (!Normalize(config) || !SocksPort(config.dump()) || !AddApi(config, 10086)) return std::nullopt;
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

// Core's Address env lookup is exact-first, then its normalized alias, once.
// Alias folding here covers ASCII environment names. Refuse an unqualified
// Unicode alias instead of converting a missing lookup to an AnyIP listener.
// Exact UTF-8 names are passed unchanged to the platform reader.
inline std::optional<std::string> ResolveAddress(const std::string& text, const PortEnvironmentReader& read_environment) {
  if (text.rfind("env:", 0) != 0) return text;
  const auto name = text.substr(4);
  auto resolved = read_environment(name);
  if (!resolved) {
    auto alternate = PortTrimSpace(name);
    if (std::any_of(alternate.begin(), alternate.end(), [](unsigned char c) { return c >= 0x80; })) return std::nullopt;
    for (auto& c : alternate) { if (c == '.') c = '_'; else if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A'); }
    if (!alternate.empty()) resolved = read_environment(alternate);
  }
  if (!resolved) resolved = "";
  // Writing a nested env: value would make the child's JSON decoder resolve a
  // second time, whereas the source Address decoder resolves only once.
  if (resolved->rfind("env:", 0) == 0) return std::nullopt;
  return resolved;
}
inline std::optional<std::string> ResolveInboundListen(const std::string& text, const PortEnvironmentReader& read_environment) {
  return ResolveAddress(text, read_environment);
}
inline std::string ParsedAddressText(std::string text) {
  // Core ParseAddress removes brackets before trimming. Keep this parsed view
  // separate from the raw expanded Address frozen in the candidate document.
  if (text.size() >= 2 && text.front() == '[' && text.back() == ']') text = text.substr(1, text.size() - 2);
  return PortTrimSpace(text);
}
// Only these root-DNS values are conf.Address fields. Keep caller matcher
// keys, case, alias/array order, URLs and non-Address strings exactly as supplied.
inline bool BindDnsAddresses(Json& config, const PortEnvironmentReader& read_environment) {
  if (!config.contains("dns") || config["dns"].is_null()) return true;
  auto dns = config["dns"];
  if (!dns.is_object()) return false;
  std::map<std::string, std::optional<std::string>> environment;
  const PortEnvironmentReader snapshot = [&](const std::string& name) {
    auto found = environment.find(name);
    if (found == environment.end()) found = environment.emplace(name, read_environment(name)).first;
    return found->second;
  };
  auto field = [](Json& object, const char* name, Json*& result) {
    result = nullptr;
    if (!object.is_object()) return false;
    for (auto it = object.begin(); it != object.end(); ++it) if (Fold(it.key()) == Fold(name)) {
      if (result) return false;
      result = &it.value();
    }
    return true;
  };
  auto bind = [&](Json& address) {
    if (address.is_null()) return true;
    if (!address.is_string()) return false;
    const auto expanded = ResolveAddress(address.get<std::string>(), snapshot);
    if (!expanded) return false;
    address = *expanded;
    return true;
  };
  Json *client = nullptr, *servers = nullptr, *hosts = nullptr;
  if (!field(dns, "clientIp", client) || !field(dns, "servers", servers) || !field(dns, "hosts", hosts)) return false;
  if (client && !bind(*client)) return false;
  if (servers && !servers->is_null()) {
    if (!servers->is_array()) return false;
    for (auto& server : *servers) {
      if (!server.is_object()) { if (!bind(server)) return false; continue; }
      Json *address = nullptr, *ecs = nullptr;
      if (!field(server, "address", address) || !field(server, "clientIp", ecs)) return false;
      if ((address && !bind(*address)) || (ecs && !bind(*ecs))) return false;
    }
  }
  if (hosts && !hosts->is_null()) {
    if (!hosts->is_object()) return false;
    for (auto& value : *hosts) {
      if (value.is_array()) { for (auto& address : value) if (!bind(address)) return false; }
      else if (!bind(value)) return false;
    }
  }
  // Commit only after every inspected field has passed; never leave a partial
  // binding in a candidate rejected for an ambiguous field or nested env value.
  config["dns"] = std::move(dns);
  return true;
}
// These targets are logical destinations of existing handlers, not physical
// server endpoints. Core gives a nonnull legacy address precedence over
// rewriteAddress; leave the dormant field and all forwarding policy untouched.
inline bool BindLogicalAddresses(Json& config, const PortEnvironmentReader& read_environment) {
  std::vector<std::pair<Json*, Json>> pending;
  std::map<std::string, std::optional<std::string>> environment;
  const PortEnvironmentReader snapshot = [&](const std::string& name) {
    auto found = environment.find(name);
    if (found == environment.end()) found = environment.emplace(name, read_environment(name)).first;
    return found->second;
  };
  for (const auto* direction : {"inbounds", "outbounds"}) {
    for (auto& handler : config[direction]) {
      const auto protocol = handler["protocol"].get<std::string>();
      const bool selected = std::string(direction) == "inbounds"
          ? protocol == "dokodemo-door" || protocol == "tunnel" : protocol == "dns";
      if (!selected || !handler.contains("settings") || handler["settings"].is_null()) continue;
      auto settings = handler["settings"];
      auto canonical = settings;
      if (!Fields(canonical, {"address", "rewriteAddress"})) return false;
      for (const auto* key : {"address", "rewriteAddress"})
        if (canonical.contains(key) && !canonical[key].is_null() && !canonical[key].is_string()) return false;
      const auto* key = canonical.contains("address") && !canonical["address"].is_null() ? "address" : "rewriteAddress";
      if (!canonical.contains(key) || canonical[key].is_null()) continue;
      const auto expanded = ResolveAddress(canonical[key].get<std::string>(), snapshot);
      if (!expanded) return false;
      for (auto it = settings.begin(); it != settings.end(); ++it)
        if (Fold(it.key()) == Fold(key)) { it.value() = *expanded; break; }
      pending.push_back({&handler["settings"], std::move(settings)});
    }
  }
  for (auto& update : pending) *update.first = std::move(update.second);
  return true;
}
inline bool UnixInboundListen(std::string resolved) {
  // Match ParseAddress's bracket-removal-before-trim order for classification;
  // preserve the raw resolved string in the generated document.
  resolved = ParsedAddressText(resolved);
  return (!resolved.empty() && resolved[0] == '@') || std::filesystem::u8path(resolved).is_absolute();
}

inline std::optional<std::set<unsigned>> ReservedPorts(const Json& value,
    const PortEnvironmentReader& read_environment = PortEnvironment) {
  std::set<unsigned> occupied;
  if (value.is_number_unsigned()) {
    auto port = value.get<uint64_t>(); if (port > 65535) return std::nullopt;
    if (port) occupied.insert(static_cast<unsigned>(port));
    return occupied;
  }
  if (value.is_number_integer()) {
    auto port = value.get<int64_t>(); if (port < 0 || port > 65535) return std::nullopt;
    if (port) occupied.insert(static_cast<unsigned>(port));
    return occupied;
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

// Reserve numeric API/metrics listen ports too. Hostnames are not resolved here;
// service names and Unix addresses remain untouched for Core/OS validation.
inline std::set<unsigned> ListenerPorts(const Json& config, const std::set<std::string>& services) {
  std::set<unsigned> ports;
  if (!config.is_object()) return ports;
  for (auto service = config.begin(); service != config.end(); ++service) {
    if (!services.count(Fold(service.key())) || !service->is_object()) continue;
    for (auto listen = service->begin(); listen != service->end(); ++listen) {
      if (Fold(listen.key()) != "listen" || !listen->is_string()) continue;
      const auto address = listen->get<std::string>();
      if (address.empty() || address[0] == '/' || address[0] == '@') continue;
      const auto colon = address.rfind(':');
      if (colon == std::string::npos || colon + 1 == address.size()) continue;
      auto digits = address.substr(colon + 1);
      if (!digits.empty() && digits[0] == '+') digits.erase(0, 1);
      if (digits.empty()) continue;
      if (digits.find_first_not_of("0123456789") != std::string::npos) continue;
      unsigned port = 0;
      for (char c : digits) { port = port * 10 + static_cast<unsigned>(c - '0'); if (port > 65535) break; }
      if (port && port <= 65535) ports.insert(port);
    }
  }
  return ports;
}
inline std::set<unsigned> ApiListenerPorts(const Json& config) { return ListenerPorts(config, {"api"}); }
inline std::set<unsigned> ServiceListenerPorts(const Json& config) { return ListenerPorts(config, {"api", "metrics"}); }

inline std::optional<uint16_t> AvailablePort(const Json& config, uint16_t preferred,
    const PortEnvironmentReader& read_environment) {
  auto occupied = ServiceListenerPorts(config);
  if (config.contains("inbounds") && config["inbounds"].is_array()) for (auto inbound : config["inbounds"]) {
    if (inbound.is_object() && !Fields(inbound, {"listen", "port"})) return std::nullopt;
    if (inbound.contains("listen") && inbound["listen"].is_string()) {
      const auto listen = ResolveInboundListen(inbound["listen"].get<std::string>(), read_environment);
      if (!listen) return std::nullopt;
      if (UnixInboundListen(*listen)) continue;
    }
    if (!inbound.contains("port")) continue;
    const auto ports = ReservedPorts(inbound["port"], read_environment);
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

// The prepared document is generated by our preparer, but a loopback listen or
// StatsService alone does not make a caller's API ours. Presence in the original
// source (including null and folded spelling) always disables plugin queries.
inline std::optional<uint16_t> OwnedApiPort(const std::string& source, const std::string& prepared) {
  auto original = Parse(source);
  auto result = Parse(prepared);
  if (!Fields(original, {"api"}) || original.contains("api") || !Fields(result, {"api"})
      || !result.contains("api") || !result["api"].is_object()) return std::nullopt;
  const auto& api = result["api"];
  if (api.size() != 3 || !api.contains("tag") || !api["tag"].is_string() || api["tag"].get<std::string>().empty()
      || !api.contains("services") || api["services"] != Json::array({"StatsService"})) return std::nullopt;
  return ApiPort(result.dump());
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
struct BootstrapEndpoint { std::string host; uint16_t port; };
struct BootstrapGraph {
  Json outbounds = Json::array();
  Json rules = Json::array();
  std::map<std::string, std::string> addresses;
};

inline std::string EffectiveStreamNetwork(const Json& stream) {
  // Core's method/network fields are pointers: JSON null means absent, and a
  // nonnull method wins without inspecting a dormant network value.
  for (const auto* key : {"method", "network"})
    if (stream.contains(key) && !stream[key].is_null()) return Fold(stream[key].get<std::string>());
  return "tcp";
}

inline bool EndpointProtocol(const std::string& protocol) {
  return std::set<std::string>{"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "masque", "wireguard"}.count(protocol) != 0;
}
inline std::optional<std::vector<Json*>> EndpointEntries(Json& outbound, const std::string& protocol) {
  if (!Object(outbound, "settings") || !Fields(outbound["settings"], {"address", "vnext", "servers", "peers"})) return std::nullopt;
  auto& settings = outbound["settings"];
  std::vector<Json*> entries;
  if (settings.contains("address") && !settings["address"].is_null()) entries.push_back(&settings);
  else {
    const auto* key = protocol == "vless" || protocol == "vmess" ? "vnext" : "servers";
    if (!settings.contains(key) || !settings[key].is_array()) return std::nullopt;
    for (auto& entry : settings[key]) entries.push_back(&entry);
  }
  if (entries.empty()) return std::nullopt;
  for (auto* entry : entries) if (!Fields(*entry, {"address", "endpoint"})) return std::nullopt;
  return entries;
}
inline Json* EndpointField(Json& object, const char* name) {
  for (auto it = object.begin(); it != object.end(); ++it) if (Fold(it.key()) == Fold(name)) return &it.value();
  return nullptr;
}
inline bool BindEndpointAddress(Json& object) {
  auto canonical = object;
  if (!Fields(canonical, {"address"}) || !canonical.contains("address") || !canonical["address"].is_string()) return false;
  const auto expanded = ResolveAddress(canonical["address"].get<std::string>(), PortEnvironment);
  if (!expanded) return false;
  *EndpointField(object, "address") = *expanded;
  return true;
}
inline bool BindStreamEndpointAddress(Json& stream) {
  if (stream.is_null()) return true;
  auto canonical = stream;
  if (!Fields(canonical, {"network", "method", "xhttpSettings", "splithttpSettings"})) return false;
  const auto network = EffectiveStreamNetwork(canonical);
  if (network != "xhttp" && network != "splithttp") return true;
  const auto* key = canonical.contains("xhttpSettings") && !canonical["xhttpSettings"].is_null() ? "xhttpSettings" : "splithttpSettings";
  auto* settings = EndpointField(stream, key);
  if (!settings || settings->is_null()) return true;
  auto effective = *settings;
  if (!Fields(effective, {"extra", "downloadSettings"})) return false;
  if (effective.contains("extra")) {
    if (effective["extra"].is_null()) return true;
    settings = EndpointField(*settings, "extra");
    effective = *settings;
    if (!Fields(effective, {"downloadSettings"})) return false;
  }
  auto* download = EndpointField(*settings, "downloadSettings");
  // The immediate client's Address is decoded even when parent sockopt is
  // inherited. getHTTPClient does not recursively dial its nested download.
  return !download || download->is_null() || BindEndpointAddress(*download);
}
inline bool BindEndpointAddresses(Json& config) {
  for (auto& outbound : config["outbounds"]) {
    const auto protocol = outbound["protocol"].get<std::string>();
    if (protocol == "blackhole" || protocol == "block" || protocol == "loopback" || protocol == "wireguard") continue;
    if (EndpointProtocol(protocol)) {
      auto entries = EndpointEntries(outbound, protocol);
      if (!entries) return false;
      for (auto* entry : *entries) if (!BindEndpointAddress(*entry)) return false;
    }
    // Freedom/direct and DNS may also dial an active XHTTP download through a
    // caller chain. Freeze it before any outbound's physical resolve callback.
    if (auto* stream = EndpointField(outbound, "streamSettings")) if (!BindStreamEndpointAddress(*stream)) return false;
  }
  return true;
}

inline bool EffectiveBootstrapChains(Json stream, std::vector<std::string>& chains) {
  if (stream.is_null()) return true;
  if (!Fields(stream, {"sockopt", "network", "method", "xhttpSettings", "splithttpSettings"})) return false;
  bool penetrate = false;
  if (stream.contains("sockopt") && !stream["sockopt"].is_null()) {
    auto options = stream["sockopt"];
    if (!Fields(options, {"dialerProxy", "penetrate"})) return false;
    if (options.contains("penetrate") && !options["penetrate"].is_null()) {
      if (!options["penetrate"].is_boolean()) return false;
      penetrate = options["penetrate"].get<bool>();
    }
    if (options.contains("dialerProxy") && !options["dialerProxy"].is_null()) {
      if (!options["dialerProxy"].is_string()) return false;
      if (!options["dialerProxy"].get<std::string>().empty()) chains.push_back(options["dialerProxy"].get<std::string>());
    }
  }
  const auto network = EffectiveStreamNetwork(stream);
  const auto* key = stream.contains("xhttpSettings") && !stream["xhttpSettings"].is_null() ? "xhttpSettings" : "splithttpSettings";
  if ((network == "xhttp" || network == "splithttp") && stream.contains(key) && !stream[key].is_null()) {
    auto settings = stream[key];
    if (!Fields(settings, {"extra", "downloadSettings"})) return false;
    // A present RawMessage extra:null decodes to a fresh zero extra in Core;
    // it still suppresses the outer download settings.
    auto effective = settings.contains("extra") ? (settings["extra"].is_null() ? Json::object() : settings["extra"]) : settings;
    if (!Fields(effective, {"downloadSettings"})) return false;
    // Core replaces this immediate child's entire socket policy with the
    // parent object. A dormant child chain must not become a dependency.
    if (effective.contains("downloadSettings") && !effective["downloadSettings"].is_null() && !penetrate)
      return EffectiveBootstrapChains(effective["downloadSettings"], chains);
  }
  return true;
}

inline bool ValidBootstrapChains(const Json& outbounds) {
  std::map<std::string, size_t> names;
  for (size_t i = 0; i < outbounds.size(); ++i) {
    if (!outbounds[i].contains("tag") || outbounds[i]["tag"].is_null()) continue;
    if (!outbounds[i]["tag"].is_string()) return false;
    const auto tag = outbounds[i]["tag"].get<std::string>();
    if (!tag.empty() && !names.emplace(tag, i).second) return false;
  }
  std::vector<std::vector<size_t>> edges(outbounds.size());
  std::vector<size_t> incoming(outbounds.size(), 0), ready;
  for (size_t i = 0; i < outbounds.size(); ++i) {
    // A loopback handler never calls its socket dialer; dormant stream socket
    // references must not turn into physical chain dependencies.
    if (outbounds[i].value("protocol", "") == "loopback") continue;
    std::vector<std::string> chains;
    if (!EffectiveBootstrapChains(outbounds[i].value("streamSettings", Json()), chains)) return false;
    for (const auto& chain : chains) {
      const auto target = names.find(chain);
      if (target == names.end()) return false;
      edges[i].push_back(target->second);
      ++incoming[target->second];
    }
  }
  for (size_t i = 0; i < incoming.size(); ++i) if (!incoming[i]) ready.push_back(i);
  for (size_t cursor = 0; cursor < ready.size(); ++cursor)
    for (auto target : edges[ready[cursor]]) if (!--incoming[target]) ready.push_back(target);
  return ready.size() == outbounds.size();
}

// Preserve the transport's logical destination (including implicit SNI/Host).
// Only this private loopback context can reach its exact host+port pins. An
// unmatched destination is blocked before imported routing rules are examined.
inline bool BootstrapStream(Json& stream, const std::vector<BootstrapEndpoint>& endpoints,
    const std::string& interface_name, const std::function<std::string(const std::string&)>& resolve,
    ServiceTags& tags, const std::string& reject_tag, BootstrapGraph& graph, const Json& send_through = nullptr,
    bool independent_destination = false) {
  if (!Fields(stream, {"address", "port", "sockopt", "xhttpSettings", "splithttpSettings", "network", "method"}) || !Object(stream, "sockopt")) return false;
  auto& options = stream["sockopt"];
  if (!Fields(options, {"interface", "domainStrategy", "addressPortStrategy", "dialerProxy", "penetrate"})) return false;
  if (options.contains("addressPortStrategy") && !options["addressPortStrategy"].is_null()) {
    if (!options["addressPortStrategy"].is_string()) return false;
    const auto strategy = Fold(options["addressPortStrategy"].get<std::string>());
    if (!strategy.empty() && strategy != "none") return false;
  }
  if (options.contains("penetrate") && !options["penetrate"].is_null() && !options["penetrate"].is_boolean()) return false;
  const bool penetrate = options.contains("penetrate") && options["penetrate"].is_boolean() && options["penetrate"].get<bool>();
  options["domainStrategy"] = "ForceIPv4";
  // Bind every dialer to the selected underlay; no endpoint /32 route can expose
  // unrelated application traffic to the same server address.
  options["interface"] = interface_name;
  std::vector<BootstrapEndpoint> physical = endpoints;
  const auto network = EffectiveStreamNetwork(stream);
  if (Fold(network) == "xdrive") return false; // Independent fronting/storage paths need their own qualification.
  if (independent_destination) {
    const auto port = Port(stream);
    if (!stream.contains("address") || !stream["address"].is_string() || !port) return false;
    physical = {{stream["address"].get<std::string>(), *port}};
  }
  if (options.contains("dialerProxy") && !options["dialerProxy"].is_null() && !options["dialerProxy"].is_string()) return false;
  const bool chained = options.contains("dialerProxy") && !options["dialerProxy"].is_null() && !options["dialerProxy"].get<std::string>().empty();
  // Discover the effective immediate download before allocating a pin graph:
  // penetrate makes both HTTP clients use the same parent SocketSettings.
  Json* download = nullptr;
  Json null_extra = Json::object();
  const auto* key = stream.contains("xhttpSettings") && !stream["xhttpSettings"].is_null() ? "xhttpSettings" : "splithttpSettings";
  if ((network == "xhttp" || network == "splithttp") && stream.contains(key) && !stream[key].is_null()) {
    auto& settings = stream[key];
    if (!Fields(settings, {"extra", "downloadSettings"})) return false;
    auto* container = &settings;
    if (settings.contains("extra")) container = settings["extra"].is_null() ? &null_extra : &settings["extra"];
    if (!Fields(*container, {"downloadSettings"})) return false;
    if (container->contains("downloadSettings") && !(*container)["downloadSettings"].is_null()) download = &(*container)["downloadSettings"];
  }
  if (download && penetrate) {
    auto child = *download;
    if (!Fields(child, {"address", "port", "network", "method", "tlsSettings"})) return false;
    const auto child_network = EffectiveStreamNetwork(child);
    const auto port = Port(child);
    // Core casts the download's ProtocolSettings directly to XHTTP Config.
    if ((child_network != "xhttp" && child_network != "splithttp") || !child.contains("address")
        || !child["address"].is_string() || child["address"].get<std::string>().empty() || !port) return false;
    if (child.contains("tlsSettings") && !child["tlsSettings"].is_null()) {
      auto tls = child["tlsSettings"];
      if (!Fields(tls, {"echConfigList"})) return false;
      const auto ech = tls.value("echConfigList", Json());
      if (!ech.is_null() && (!ech.is_string() || ech.get<std::string>().find("://") != std::string::npos)) return false;
    }
    // A dynamic freedom/DNS upload has no finite closed endpoint set. Do not
    // accidentally replace it with a graph containing only the download.
    if (!chained && physical.empty()) return false;
    physical.push_back({child["address"].get<std::string>(), *port});
  }
  if (chained) {
    // A chained endpoint is a logical target of that handler. Its physical
    // transport is prepared separately; never bootstrap the logical target.
    options["domainStrategy"] = "AsIs";
  } else {
    bool needs_pins = false;
    for (auto& endpoint : physical) {
      endpoint.host = ParsedAddressText(endpoint.host);
      if (endpoint.host.empty() || endpoint.host.find(':') != std::string::npos || !endpoint.port) return false;
      needs_pins = needs_pins || !Literal4(endpoint.host);
    }
    if (needs_pins) {
      const auto loopback = tags.Next("flutter-vless-bootstrap-loopback");
      const auto input = tags.Next("flutter-vless-bootstrap-input");
      graph.outbounds.push_back({{"tag", loopback}, {"protocol", "loopback"}, {"settings", {{"inboundTag", input}}}});
      std::set<std::pair<std::string, uint16_t>> seen;
      for (const auto& endpoint : physical) {
        if (!seen.insert({endpoint.host, endpoint.port}).second) continue;
        auto ip = endpoint.host;
        if (!Literal4(ip)) {
          auto found = graph.addresses.find(endpoint.host);
          if (found == graph.addresses.end()) {
            ip = resolve(endpoint.host);
            if (!Literal4(ip)) return false;
            graph.addresses[endpoint.host] = ip;
          } else ip = found->second;
        }
        const auto egress = tags.Next("flutter-vless-bootstrap-egress");
        auto physical_options = options;
        physical_options.erase("dialerProxy");
        Json physical_outbound = {{"tag", egress}, {"protocol", "freedom"},
            {"settings", {{"redirect", ip + ":0"}, {"domainStrategy", "AsIs"}}},
            {"streamSettings", {{"sockopt", physical_options}}}};
        if (!send_through.is_null()) physical_outbound["sendThrough"] = send_through;
        graph.outbounds.push_back(physical_outbound);
        Json rule = {{"type", "field"}, {"inboundTag", Json::array({input})}, {"port", std::to_string(endpoint.port)}, {"outboundTag", egress}};
        if (Literal4(endpoint.host)) rule["ip"] = Json::array({endpoint.host + "/32"});
        else rule["domain"] = Json::array({"full:" + endpoint.host});
        graph.rules.push_back(rule);
      }
      graph.rules.push_back({{"type", "field"}, {"inboundTag", Json::array({input})}, {"outboundTag", reject_tag}});
      // DialSystem resolves a non-AsIs socket destination before applying a
      // dialerProxy. The loopback itself suppresses router/target DNS lookup.
      options["domainStrategy"] = "AsIs";
      options["dialerProxy"] = loopback;
    }
  }
  // The penetrating child's sockopt and nested download settings stay intact:
  // getHTTPClient consumes this immediate client without another XHTTP Dial.
  if (download && !penetrate && (!download->is_object() || !download->contains("address")
      || !BootstrapStream(*download, {}, interface_name, resolve, tags, reject_tag, graph, send_through, true))) return false;
  return true;
}

inline std::string DnsDomainLower(std::string value) {
  // Resolver names admitted below are ASCII. These are the only non-ASCII
  // scalars which strings.ToLower in pinned Go lowers to ASCII. Schema Fold
  // also equates long S with s, which Core DNS domain matching does not.
  for (const auto& pair : {std::pair<std::string, std::string>{"\xC4\xB0", "i"}, {"\xE2\x84\xAA", "k"}}) {
    size_t offset = 0;
    while ((offset = value.find(pair.first, offset)) != std::string::npos) value.replace(offset, pair.first.size(), pair.second);
  }
  for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return value;
}

// The caller supplies Core's already-parsed Address view. Recognize only
// IPv4 or the exact IPv4-mapped IPv6 prefix which Core IPAddress collapses;
// other IPv6 families stay outside this protected IPv4 DNS policy.
inline std::optional<std::string> DnsIPv4(const std::string& value) {
  if (Literal4(value)) return value;
  const auto compression = value.find("::");
  if (value.find(':') == std::string::npos ||
      (compression != std::string::npos && value.find("::", compression + 2) != std::string::npos)) return std::nullopt;
  auto parse = [](const std::string& half, std::vector<unsigned>& words, bool last) {
    if (half.empty()) return true;
    size_t offset = 0;
    for (;;) {
      const auto colon = half.find(':', offset);
      const auto word = half.substr(offset, colon == std::string::npos ? colon : colon - offset);
      if (word.empty()) return false;
      if (word.find('.') != std::string::npos) {
        if (!last || colon != std::string::npos || !Literal4(word)) return false;
        unsigned bytes[4]{}; size_t start = 0;
        for (int i = 0; i < 4; ++i) {
          const auto dot = word.find('.', start);
          bytes[i] = static_cast<unsigned>(std::stoul(word.substr(start, dot == std::string::npos ? dot : dot - start)));
          start = dot + 1;
        }
        words.push_back((bytes[0] << 8) | bytes[1]); words.push_back((bytes[2] << 8) | bytes[3]);
      } else {
        if (word.size() > 4) return false;
        unsigned number = 0;
        for (const char digit : word) {
          number <<= 4;
          if (digit >= '0' && digit <= '9') number += digit - '0';
          else if (digit >= 'a' && digit <= 'f') number += digit - 'a' + 10;
          else if (digit >= 'A' && digit <= 'F') number += digit - 'A' + 10;
          else return false;
        }
        words.push_back(number);
      }
      if (words.size() > 8) return false;
      if (colon == std::string::npos) return true;
      offset = colon + 1;
    }
  };
  std::vector<unsigned> left, right;
  if (!parse(value.substr(0, compression), left, compression == std::string::npos)) return std::nullopt;
  if (compression != std::string::npos && !parse(value.substr(compression + 2), right, true)) return std::nullopt;
  if ((compression == std::string::npos && left.size() != 8) ||
      (compression != std::string::npos && left.size() + right.size() >= 8)) return std::nullopt;
  left.resize(8 - right.size(), 0); left.insert(left.end(), right.begin(), right.end());
  for (size_t i = 0; i < 5; ++i) if (left[i] != 0) return std::nullopt;
  if (left[5] != 0xffff) return std::nullopt;
  return std::to_string(left[6] >> 8) + "." + std::to_string(left[6] & 255) + "." +
      std::to_string(left[7] >> 8) + "." + std::to_string(left[7] & 255);
}

inline bool ProtectedDnsAddress(const std::string& address, const Json& hosts) {
  auto host = ParsedAddressText(address);
  const auto scheme = host.find("://");
  if (scheme != std::string::npos) {
    const auto protocol = Fold(host.substr(0, scheme));
    if (protocol != "tcp" && protocol != "https" && protocol != "h2c") return false;
    host = host.substr(scheme + 3);
    host = host.substr(0, host.find_first_of("/?#"));
    std::optional<std::string> port;
    if (!host.empty() && host.front() == '[') {
      const auto close = host.find(']');
      if (close == std::string::npos) return false;
      const auto suffix = host.substr(close + 1);
      if (!suffix.empty()) {
        if (suffix.front() != ':') return false;
        port = suffix.substr(1);
      }
      host = host.substr(1, close - 1);
      // URL authority brackets belong to the URL parser, not a second pass
      // over the root Address. Only numeric IPv4/mapped hosts are qualified.
      if (!DnsIPv4(host)) return false;
    } else if (const auto colon = host.find(':'); colon != std::string::npos) {
      port = host.substr(colon + 1);
      host = host.substr(0, colon);
    }
    if (port && (port->empty() || port->size() > 5 || port->find_first_not_of("0123456789") != std::string::npos
        || std::stoul(*port) == 0 || std::stoul(*port) > 65535)) return false;
  }
  if (DnsIPv4(host)) return true;
  if (host.empty() || host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != std::string::npos) return false;
  // Named remote resolvers need a caller-owned static bootstrap. No native
  // endpoint mapping is added to this map; URLs/TLS names remain unchanged.
  host = DnsDomainLower(host);
  if (!host.empty() && host.back() == '.') host.pop_back(); // Root LookupIP trims the FQDN suffix.
  if (!hosts.is_object()) return false;
  bool found = false;
  for (auto it = hosts.begin(); it != hosts.end(); ++it) {
    auto domain = it.key();
    // Core recognizes the prefix case-sensitively, then lowercases only its
    // domain value. A mapping's terminal dot is not stripped by the matcher.
    if (domain.rfind("full:", 0) == 0) domain.erase(0, 5);
    if (DnsDomainLower(domain) != host) continue;
    found = true;
    if (it->is_string()) { if (!DnsIPv4(ParsedAddressText(it->get<std::string>()))) return false; }
    else {
      if (!it->is_array() || it->empty()) return false;
      for (const auto& entry : *it) if (!entry.is_string() || !DnsIPv4(ParsedAddressText(entry.get<std::string>()))) return false;
    }
  }
  return found;
}

inline bool ProtectedDns(Json& config, ServiceTags& tags, const std::string& proxy, Json& rules) {
  if (!Object(config, "dns")) return false;
  auto& original = config["dns"];
  auto dns = original;
  if (!Fields(dns, {"servers", "queryStrategy", "script", "hosts"})) return false;
  if (dns.contains("script") && dns["script"] != "" && !dns["script"].is_null()) return false;
  auto strategy = [](const Json& object) {
    if (!object.contains("queryStrategy") || object["queryStrategy"].is_null()) return true;
    if (!object["queryStrategy"].is_string()) return false;
    auto value = Fold(object["queryStrategy"].get<std::string>());
    value.erase(std::remove_if(value.begin(), value.end(), [](char c) { return c == '_' || c == '-'; }), value.end());
    return value != "usesys" && value != "usesystem";
  };
  if (!strategy(dns)) return false;
  std::string servers_key = "servers";
  for (auto it = original.begin(); it != original.end(); ++it) if (Fold(it.key()) == "servers") servers_key = it.key();
  if (!dns.contains("servers") || dns["servers"].is_null() || (dns["servers"].is_array() && dns["servers"].empty())) original[servers_key] = Json::array({"localhost"});
  if (!original[servers_key].is_array()) return false;
  for (auto& server : original[servers_key]) {
    auto canonical = server;
    if (server.is_object() && !Fields(canonical, {"address", "queryStrategy", "tag", "port"})) return false;
    if (server.is_object() && !strategy(canonical)) return false;
    auto address = server.is_string() ? server : canonical.value("address", Json());
    if (!address.is_string()) return false;
    const auto value = Fold(ParsedAddressText(address.get<std::string>()));
    if (value == "localhost") {
      if (proxy.empty()) return false; // No implicit direct/default selection for a native DNS replacement.
      if (server.is_string()) server = {{"address", "tcp://1.1.1.1"}};
      else {
        for (auto it = server.begin(); it != server.end(); ++it) if (Fold(it.key()) == "address") { it.value() = "tcp://1.1.1.1"; break; }
      }
      std::string tag;
      if (canonical.is_object() && canonical.contains("tag") && !canonical["tag"].is_null()) {
        if (!canonical["tag"].is_string()) return false;
        tag = canonical["tag"].get<std::string>();
      }
      if (tag.empty()) {
        tag = tags.Next(kDnsUpstream);
        std::string tag_key = "tag";
        for (auto it = server.begin(); it != server.end(); ++it) if (Fold(it.key()) == "tag") tag_key = it.key();
        server[tag_key] = tag;
      }
      // Only the native replacement endpoint is forced through the selected
      // proxy. Imported remote-server tags and routing remain authoritative.
      rules.push_back({{"type", "field"}, {"inboundTag", Json::array({tag})}, {"ip", Json::array({"1.1.1.1/32"})},
          {"port", "53"}, {"network", "tcp"}, {"outboundTag", proxy}});
    } else {
      // Local/QUIC clients bypass ordinary dispatcher/socket binding. DoT is
      // not implemented by this pinned Core. Keep explicit remote clients as
      // supplied, rather than silently replacing an unsupported protocol.
      if (value == "fakedns" || value.find("+local") != std::string::npos || value.rfind("quic:", 0) == 0
          || value.rfind("tls:", 0) == 0 || value.rfind("localhost", 0) == 0) return false;
      if (!ProtectedDnsAddress(address.get<std::string>(), dns.value("hosts", Json()))) return false;
    }
  }
  return true;
}

struct VpnRoutingProvenance {
  size_t original_inbound_count = 0;
  std::string managed_tag;
  std::vector<int64_t> guard_rule_indices;
};
inline std::optional<std::string> PrepareProtectedVpn(const std::string& text,
    const std::string& username, const std::string& password, const std::string& interface_name,
    const std::function<std::string(const std::string&)>& resolve,
    VpnRoutingProvenance* provenance = nullptr) try {
  auto config = Parse(text);
  if (username.empty() || password.empty() || username.size() > 255 || password.size() > 255 || interface_name.empty()
      || !Normalize(config) || config.contains("fakeDns") || config.contains("fakedns")) return std::nullopt;
  if (!BindEndpointAddresses(config)) return std::nullopt;
  if (!ValidBootstrapChains(config["outbounds"])) return std::nullopt;
  ServiceTags service_tags(config);
  auto& inbounds = config["inbounds"];
  VpnRoutingProvenance generated;
  generated.original_inbound_count = inbounds.size();
  // Keep every imported listener intact. tun2socks gets a separate loopback
  // listener with native session authentication, never a caller's public input.
  auto port = AvailablePort(config, 10807);
  if (!port) return std::nullopt;
  auto managed_tag = service_tags.Next(kManagedInbound);
  generated.managed_tag = managed_tag;
  Json inbound = {{"tag", managed_tag}, {"protocol", "socks"}, {"listen", "127.0.0.1"}, {"port", *port},
      {"settings", {{"auth", "password"}, {"accounts", Json::array({{{"user", username}, {"pass", password}}})}, {"udp", true}, {"ip", "127.0.0.1"}}},
      {"sniffing", {{"enabled", true}, {"routeOnly", true}, {"destOverride", Json::array({"http", "tls", "quic"})}}}};
  inbounds.insert(inbounds.begin(), inbound);
  const auto relay_tag = service_tags.Next(kDnsRelay);
  const auto ipv6_tag = service_tags.Next(kIpv6Block);
  std::string proxy;
  BootstrapGraph bootstrap;
  for (auto& outbound : config["outbounds"]) {
    auto protocol = outbound["protocol"].get<std::string>();
    // Registered Core aliases share a policy role; keep the source protocol
    // string so routing/handler metadata is not rewritten by adaptation.
    if (protocol == "direct") protocol = "freedom";
    if (protocol == "block") protocol = "blackhole";
    // Loopback redispatches through the caller's rules and does not dial a
    // physical socket. Its source settings/order/identity stay untouched.
    if (protocol == "blackhole" || protocol == "loopback") continue;
    if (!Fields(outbound, {"sendThrough"}) || !Object(outbound, "streamSettings")) return std::nullopt;
    const auto send_through = outbound.value("sendThrough", Json());
    if (protocol == "dns") {
      // The DNS outbound's optional raw forwarding uses the normal dialer.
      // Its target is dynamic: keep caller rewrite/rules unchanged and resolve
      // names through Core while binding actual sockets to the underlay.
      if (!BootstrapStream(outbound["streamSettings"], {}, interface_name, resolve, service_tags, ipv6_tag, bootstrap, send_through)) return std::nullopt;
      continue;
    }
    if (protocol == "freedom") {
      if (!Object(outbound, "settings") || !Fields(outbound["settings"], {"domainStrategy", "targetStrategy"})) return std::nullopt;
      outbound["settings"]["domainStrategy"] = "ForceIPv4";
      outbound["settings"].erase("targetStrategy");
      if (!BootstrapStream(outbound["streamSettings"], {}, interface_name, resolve, service_tags, ipv6_tag, bootstrap, send_through)) return std::nullopt;
      continue;
    }
    if (!EndpointProtocol(protocol)) return std::nullopt;
    if (!outbound.contains("tag") || outbound["tag"].is_null() || outbound["tag"] == "") {
      outbound["tag"] = service_tags.Next("flutter-vless-proxy");
    }
    if (proxy.empty() || outbound["tag"] == "proxy") proxy = outbound["tag"].get<std::string>();
    // WireGuard's endpoint is a plain string and its own resolver/socket path
    // does not use this graph. Do not expand it or broaden admission here.
    if (protocol == "wireguard") return std::nullopt;
    auto endpoints = EndpointEntries(outbound, protocol);
    if (!endpoints) return std::nullopt;
    std::vector<BootstrapEndpoint> physical;
    for (auto* entry : *endpoints) {
      const char* key = "address";
      if (!entry->contains(key) || !(*entry)[key].is_string()) return std::nullopt;
      auto remote_port = Port(*entry);
      if (!remote_port) return std::nullopt;
      physical.push_back({(*entry)[key].get<std::string>(), *remote_port});
    }
    if (!BootstrapStream(outbound["streamSettings"], physical, interface_name, resolve, service_tags, ipv6_tag, bootstrap, send_through)) return std::nullopt;
  }
  Json dns_rules = Json::array();
  if (!ProtectedDns(config, service_tags, proxy, dns_rules)) return std::nullopt;
  config["outbounds"].push_back({{"tag", relay_tag}, {"protocol", "dns"},
      {"settings", {{"rules", Json::array({{{"action", "hijack"}, {"qType", "1,28"}},
                                         {{"action", "return"}, {"rCode", 5}}})}}}});
  config["outbounds"].push_back({{"tag", ipv6_tag}, {"protocol", "blackhole"}});
  for (const auto& outbound : bootstrap.outbounds) config["outbounds"].push_back(outbound);
  if (!Object(config, "routing") || !Fields(config["routing"], {"rules", "domainStrategy"})) return std::nullopt;
  auto& routing = config["routing"];
  if (!routing.contains("rules")) routing["rules"] = Json::array();
  if (!routing["rules"].is_array()) return std::nullopt;
  Json rules = Json::array({
      {{"type", "field"}, {"inboundTag", Json::array({managed_tag})}, {"ip", Json::array({std::string(kVirtualDns) + "/32"})}, {"port", "53"}, {"network", "tcp,udp"}, {"outboundTag", relay_tag}}
  });
  generated.guard_rule_indices.push_back(0);
  for (const auto& rule : dns_rules) {
    generated.guard_rule_indices.push_back(static_cast<int64_t>(rules.size())); rules.push_back(rule);
  }
  for (const auto& rule : bootstrap.rules) {
    generated.guard_rule_indices.push_back(static_cast<int64_t>(rules.size())); rules.push_back(rule);
  }
  for (const auto& rule : routing["rules"]) rules.push_back(rule);
  routing["rules"] = rules;
  const bool owned_api = !config.contains("api");
  const auto api_port = owned_api ? AvailablePort(config, 10086) : std::optional<uint16_t>{uint16_t{0}};
  if (!api_port || !AddApi(config, *api_port)) return std::nullopt;
  if (owned_api) config["api"]["tag"] = service_tags.Next("flutter-vless-stats");
  if (provenance) *provenance = std::move(generated);
  return config.dump();
} catch (...) { return std::nullopt; }

// Explicit subnet bypass stays inside the authenticated proxy and below the
// mandatory DNS rules, never as physical adapter route exceptions.
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
