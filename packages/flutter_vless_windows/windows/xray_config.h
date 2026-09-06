#ifndef FLUTTER_VLESS_XRAY_CONFIG_H_
#define FLUTTER_VLESS_XRAY_CONFIG_H_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include "third_party/nlohmann/json.hpp"

namespace flutter_vless::xray_config {
using Json = nlohmann::ordered_json;

inline Json Parse(const std::string& text) {
  return Json::parse(text, nullptr, false, true);
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
    config["api"] = {{"tag", "api"},
      {"listen", "127.0.0.1:" + std::to_string(api_port)},
      {"services", Json::array({"StatsService"})}};
  }
  return true;
}

inline bool PrepareProxy(std::string& text,
                         const std::function<bool(uint16_t)>& is_free,
                         const std::function<uint16_t()>& free_port) {
  auto config = Parse(text);
  if (!config.is_object() || !config.contains("inbounds") ||
      !config["inbounds"].is_array()) return false;
  for (auto& inbound : config["inbounds"]) {
    const auto port = Port(inbound);
    if (port && !is_free(*port)) {
      const auto replacement = free_port();
      if (replacement == 0) return false;
      inbound["port"] = replacement;
    }
  }
  uint16_t api_port = is_free(10085) ? 10085 : free_port();
  if (!api_port || !AddApi(config, api_port)) return false;
  text = config.dump();
  return SocksPort(text).has_value();
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
}  // namespace flutter_vless::xray_config
#endif
