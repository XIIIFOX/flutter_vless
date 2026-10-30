#ifndef FLUTTER_VLESS_MANAGED_SERVICE_CAPABILITIES_H_
#define FLUTTER_VLESS_MANAGED_SERVICE_CAPABILITIES_H_
#include "xray_config.h"
#include "geodata_assets.h"

namespace flutter_vless::managed_services {
constexpr unsigned kGeodata = 1, kXdrive = 2;
inline unsigned ParseCapabilities(const std::string& bytes) {
  if (bytes.empty() || bytes.size() > 4096) return 0;
  bool duplicate = false; std::set<std::string> seen;
  auto value = xray_config::Json::parse(bytes, [&](int, xray_config::Json::parse_event_t event, xray_config::Json& item) {
    if (event == xray_config::Json::parse_event_t::key && !seen.insert(item.get<std::string>()).second) duplicate = true;
    return true;
  }, false);
  if (duplicate || !value.is_object() || value.size() != 3 || value.value("stage", xray_config::Json()) != "capabilities"
      || !value.contains("code") || !value["code"].is_number_integer() || value["code"] != 0
      || !value.contains("managed_service_lifetimes") || !value["managed_service_lifetimes"].is_number_integer()) return 0;
  const auto result = value["managed_service_lifetimes"].get<int64_t>();
  return result >= 0 && result <= 3 ? static_cast<unsigned>(result) : 0;
}
inline unsigned Required(const xray_config::Json& config) {
  return (geodata_assets::HasSchedule(config) ? kGeodata : 0) |
      (xray_config::RequiresXdriveLifetime(config) ? kXdrive : 0);
}
inline bool Allows(const xray_config::Json& config, unsigned capabilities) {
  const auto required = Required(config);
  return (required & capabilities) == required;
}
}  // namespace flutter_vless::managed_services
#endif
