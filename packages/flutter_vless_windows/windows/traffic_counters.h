#pragma once
#include "xray_config.h"
#include <chrono>
#include <limits>
#include <map>
#include <optional>
#include <string>

namespace flutter_vless::traffic {
struct Sample {
  std::optional<int64_t> upload, download;
  // Timestamp the completed query, not each later read of this cached sample.
  std::optional<std::chrono::steady_clock::time_point> observed_at = std::nullopt;
};
using Stats = std::map<std::string, std::optional<int64_t>>;

inline bool ParseStats(const std::string& text, Stats& output) {
  output.clear();
  const auto root = xray_config::Json::parse(text, nullptr, false);
  if (!root.is_object() || !root.contains("stat") || !root["stat"].is_array()) return false;
  for (const auto& row : root["stat"]) {
    if (!row.is_object() || !row.contains("name") || !row["name"].is_string()) continue;
    const auto name = row["name"].get<std::string>();
    std::optional<int64_t> value;
    if (!row.contains("value")) value = 0;  // Core's int64 zero uses omitempty.
    else if (row["value"].is_number_unsigned()) {
      const auto number = row["value"].get<uint64_t>();
      if (number <= static_cast<uint64_t>(INT64_MAX)) value = static_cast<int64_t>(number);
    } else if (row["value"].is_number_integer()) {
      const auto number = row["value"].get<int64_t>();
      if (number >= 0) value = number;
    }
    const auto inserted = output.emplace(name, value);
    if (!inserted.second) inserted.first->second.reset();  // No duplicate overwrite.
  }
  return true;
}

inline Sample Select(const Stats& stats, const std::string& tag) {
  if (tag.empty()) return {};
  const auto get = [&](const char* direction) -> std::optional<int64_t> {
    const auto row = stats.find("inbound>>>" + tag + ">>>traffic>>>" + direction);
    return row == stats.end() ? std::nullopt : row->second;
  };
  return {get("uplink"), get("downlink")};
}

// Follow the same selected prepared SOCKS port as readiness/system-proxy setup.
// Untagged or ambiguous input identities cannot supply an owned stats namespace.
inline std::string ProxyTag(const std::string& prepared) {
  const auto port = xray_config::SocksPort(prepared);
  const auto config = xray_config::Parse(prepared);
  if (!port || !config.is_object() || !config.contains("inbounds") || !config["inbounds"].is_array()) return {};
  std::string tag;
  unsigned matches = 0;
  for (const auto& input : config["inbounds"]) {
    if (!input.is_object() || !input.contains("protocol") || input["protocol"] != "socks" || xray_config::Port(input) != port) continue;
    ++matches;
    if (input.contains("tag") && input["tag"].is_string()) tag = input["tag"].get<std::string>();
  }
  if (matches != 1 || tag.empty()) return {};
  unsigned identities = 0;
  for (const auto& input : config["inbounds"])
    if (input.is_object() && input.contains("tag") && input["tag"].is_string() && input["tag"] == tag) ++identities;
  return identities == 1 ? tag : std::string();
}

struct Baseline {
  std::optional<int64_t> previous;
  int64_t Advance(std::optional<int64_t> value) {
    const auto speed = value && previous && *value >= *previous ? *value - *previous : int64_t{0};
    previous = value;
    return speed;
  }
  void Reset() { previous.reset(); }
};

// Exact floor(delta * 1e9 / elapsed), saturating at the public int64 limit.
// The fractional long division is portable to MSVC without a 128-bit type.
inline int64_t BytesPerSecond(int64_t delta, uint64_t elapsed_nanoseconds) {
  if (delta <= 0 || elapsed_nanoseconds == 0) return 0;
  constexpr uint64_t scale = 1000000000;
  constexpr auto maximum = static_cast<uint64_t>(INT64_MAX);
  const auto bytes = static_cast<uint64_t>(delta);
  const auto whole = bytes / elapsed_nanoseconds;
  if (whole > maximum / scale) return INT64_MAX;
  const auto integer = whole * scale;
  const auto remainder = bytes % elapsed_nanoseconds;
  uint64_t fraction = 0, rest = 0;
  for (int bit = 29; bit >= 0; --bit) {
    fraction *= 2;
    if (rest >= elapsed_nanoseconds - rest) {
      rest -= elapsed_nanoseconds - rest;
      ++fraction;
    } else {
      rest *= 2;
    }
    if ((scale >> bit) & 1) {
      if (rest >= elapsed_nanoseconds - remainder) {
        rest -= elapsed_nanoseconds - remainder;
        ++fraction;
      } else {
        rest += remainder;
      }
    }
  }
  return integer > maximum - fraction ? INT64_MAX : static_cast<int64_t>(integer + fraction);
}
}  // namespace flutter_vless::traffic
