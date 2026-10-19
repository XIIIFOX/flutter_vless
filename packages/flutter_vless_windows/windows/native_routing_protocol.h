#pragma once
#include "third_party/nlohmann/json.hpp"
#include <set>
#include <string>

namespace flutter_vless::native_routing {
// The private CLI has a closed response vocabulary; a stock or partially
// compatible executable must never be mistaken for the optional factory.
inline bool SuccessfulReply(const std::string& text, const std::string& stage, bool capability = false) {
  if (text.size() > 4096) return false;
  bool duplicate = false;
  std::set<std::string> keys;
  auto value = nlohmann::json::parse(text, [&](int, nlohmann::json::parse_event_t event, nlohmann::json& entry) {
    if (event == nlohmann::json::parse_event_t::key && !keys.insert(entry.get<std::string>()).second) duplicate = true;
    return true;
  }, false);
  if (duplicate || !value.is_object() || value.size() != (capability ? 3u : 2u)
      || !value.contains("stage") || value["stage"] != stage
      || !value.contains("code") || !value["code"].is_number_integer() || value["code"] != 0) return false;
  return !capability || (value.contains("capability") && value["capability"].is_number_integer() && value["capability"] == 1);
}
}  // namespace flutter_vless::native_routing
