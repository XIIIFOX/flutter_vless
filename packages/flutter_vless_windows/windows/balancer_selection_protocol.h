#pragma once
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace flutter_vless::balancer_selection {
inline constexpr size_t kMaxRows = 300;
inline constexpr size_t kMaxPayloadBytes = 18000;
inline constexpr size_t kMaxReplyBytes = 18432;
inline constexpr unsigned kPipeBufferBytes = 32768;
inline constexpr std::string_view kSnapshotCommand = "snapshot\n";
inline constexpr std::string_view kDisableCommand = "disable\n";

// Filter the entire snapshot before applying privacy limits. A malformed old
// row must not be hidden by truncation, even if a valid suffix would fit.
inline std::optional<std::string> BoundedRows(std::string_view rows, size_t max_rows, size_t max_bytes) {
  if (rows.size() > kMaxPayloadBytes || !max_rows || !max_bytes) return std::nullopt;
  if (rows.empty()) return std::string{};
  std::vector<size_t> offsets;
  int64_t previous = 0;
  for (size_t start = 0;;) {
    if (offsets.size() == kMaxRows) return std::nullopt;
    offsets.push_back(start);
    const auto newline = rows.find('\n', start);
    const auto end = newline == std::string_view::npos ? rows.size() : newline;
    const char* position = rows.data() + start;
    const char* stop = rows.data() + end;
    for (int column = 0; column < 3; ++column) {
      if (position == stop || *position < '1' || *position > '9') return std::nullopt;
      int64_t value = 0;
      const auto conversion = std::from_chars(position, stop, value);
      if (conversion.ec != std::errc{} || value <= 0) return std::nullopt;
      if (column == 0) {
        if (value <= previous) return std::nullopt;
        previous = value;
      }
      position = conversion.ptr;
      if (column < 2) {
        if (position == stop || *position != ',') return std::nullopt;
        ++position;
      } else if (position != stop) return std::nullopt;
    }
    if (newline == std::string_view::npos) break;
    start = newline + 1;
  }
  const auto first = offsets.size() - std::min(max_rows, offsets.size());
  const auto required_offset = rows.size() - std::min(max_bytes, rows.size());
  const auto offset = std::lower_bound(offsets.begin() + static_cast<std::ptrdiff_t>(first), offsets.end(), required_offset);
  return offset == offsets.end() ? std::string{} : std::string(rows.substr(*offset));
}

inline std::optional<std::string> ParseReply(const std::string& text, size_t max_rows, size_t max_bytes) {
  if (text.size() > kMaxReplyBytes) return std::nullopt;
  bool duplicate = false;
  std::set<std::string> keys;
  const auto value = nlohmann::json::parse(text, [&](int, nlohmann::json::parse_event_t event, nlohmann::json& entry) {
    if (event == nlohmann::json::parse_event_t::key && !keys.insert(entry.get<std::string>()).second) duplicate = true;
    return true;
  }, false);
  if (duplicate || !value.is_object() || value.size() != 3 || !value.contains("stage") || value["stage"] != "selections"
      || !value.contains("code") || !value["code"].is_number_integer() || value["code"] != 0
      || !value.contains("rows") || !value["rows"].is_string()) return std::nullopt;
  return BoundedRows(value["rows"].get_ref<const std::string&>(), max_rows, max_bytes);
}
}  // namespace flutter_vless::balancer_selection
