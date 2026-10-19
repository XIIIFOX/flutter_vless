#ifndef FLUTTER_VLESS_ASSET_LOCATION_H_
#define FLUTTER_VLESS_ASSET_LOCATION_H_

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace flutter_vless::asset_location {
using Root = std::optional<std::filesystem::path>;

inline bool Valid(const Root& root) {
  if (!root) return true;
  const auto& value = root->native();
  if (value.empty() || value.find(std::filesystem::path::value_type{0}) != std::filesystem::path::string_type::npos || !root->is_absolute()) return false;
  std::error_code error;
  return std::filesystem::is_directory(*root, error) && !error;
}

// Build a private child block. Never alter the parent's environment or use an
// inherited Xray root; an explicit trusted asset directory is the only opt-in.
inline std::vector<wchar_t> ChildEnvironment(const std::vector<std::wstring>& inherited,
    const std::wstring& system_directory, const Root& root) {
  std::vector<std::wstring> values;
  for (const auto& item : inherited) {
    auto key = item.substr(0, item.find(L'='));
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
    if (key.rfind(L"XRAY", 0) == 0 || key == L"SSLKEYLOGFILE" || key == L"GODEBUG"
        || key == L"GOTRACEBACK" || key == L"HTTP_PROXY" || key == L"HTTPS_PROXY"
        || key == L"ALL_PROXY" || key == L"NO_PROXY" || key == L"PATH") continue;
    values.push_back(item);
  }
  if (!system_directory.empty()) values.push_back(L"PATH=" + system_directory);
  if (root) {
    values.push_back(L"xray.location.asset=" + root->wstring());
    values.push_back(L"XRAY_LOCATION_ASSET=" + root->wstring());
  }
  std::vector<wchar_t> block;
  for (const auto& value : values) {
    block.insert(block.end(), value.begin(), value.end()); block.push_back(0);
  }
  block.push_back(0);
  if (block.size() == 1) block.push_back(0);
  return block;
}
}  // namespace flutter_vless::asset_location
#endif
