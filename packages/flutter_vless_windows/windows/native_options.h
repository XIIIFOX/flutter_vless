#ifndef FLUTTER_VLESS_NATIVE_OPTIONS_H_
#define FLUTTER_VLESS_NATIVE_OPTIONS_H_
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <regex>
#include <stdexcept>
#include <string>

namespace flutter_vless {
struct NativeOptions {
  using Json = nlohmann::json;
  std::string icon_type = "mipmap", icon_name = "ic_launcher", button_label = "DISCONNECT", notification_action = "disconnect";
  bool quick_enabled = false, require_unlock = true;
  std::string surface = "platformDefault", label = "VPN", quick_action = "toggle", android_icon = "flutter_vless_ic_quick_tile", apple_symbol = "network", windows_icon;
  bool reconnect_enabled = true, diagnostics_enabled = true;
  int initial_delay_ms = 1000, max_delay_ms = 60000, max_attempts = 0, diagnostics_bytes = 131072, diagnostics_lines = 300;
  std::string kill_switch = "required", on_demand = "platformDefault", always_on = "system";
  bool MayRetry(int failures) const { return reconnect_enabled && (max_attempts == 0 || failures < max_attempts); }
  int RetryDelay(int failures) const { return static_cast<int>(std::min<int64_t>(max_delay_ms, int64_t(initial_delay_ms) << std::clamp(failures, 0, 23))); }
  void ValidateWindows() const {
    if (quick_enabled && surface != "platformDefault" && surface != "systemTray") throw std::invalid_argument("quickAccess.surface");
    if (on_demand == "enabled" || always_on == "requireEnabled") throw std::invalid_argument("Unsupported system-managed protection option");
  }
  static NativeOptions Parse(const Json& raw = Json::object()) {
    if (!raw.is_object()) throw std::invalid_argument("options");
    auto section = [&](const char* key) { auto value = raw.value(key, Json::object()); if (!value.is_object()) throw std::invalid_argument(key); return value; };
    auto text = [](const Json& map, const char* key, const std::string& fallback, size_t limit = 128) {
      if (!map.contains(key)) return fallback;
      if (!map[key].is_string()) throw std::invalid_argument(key);
      const auto value = map[key].get<std::string>(); size_t units = 0; bool nonspace = false;
      for (unsigned char c : value) { if (c < 32 || c == 127) throw std::invalid_argument(key); if ((c & 0xc0) != 0x80) units += c >= 0xf0 ? 2 : 1; if (c > 32) nonspace = true; }
      if (!nonspace || units > limit) throw std::invalid_argument(key);
      return value;
    };
    auto flag = [](const Json& map, const char* key, bool fallback) { if (!map.contains(key)) return fallback; if (!map[key].is_boolean()) throw std::invalid_argument(key); return map[key].get<bool>(); };
    auto number = [](const Json& map, const char* key, int fallback) {
      if (!map.contains(key)) return fallback;
      if (!map[key].is_number()) throw std::invalid_argument(key);
      const double value = map[key].get<double>();
      if (!std::isfinite(value) || value != std::floor(value) || value < -1000000000 || value > 1000000000) throw std::invalid_argument(key);
      return static_cast<int>(value);
    };
    auto choice = [](const std::string& value, std::initializer_list<const char*> choices) {
      for (auto* candidate : choices) if (value == candidate) return value;
      throw std::invalid_argument("Unknown option value");
    };
    auto resource = [](const std::string& value) { if (!std::regex_match(value, std::regex("[a-zA-Z_][a-zA-Z0-9_]*"))) throw std::invalid_argument("resource"); return value; };
    if (number(raw,"version",1) != 1) throw std::invalid_argument("options.version");
    const auto n=section("notification"),q=section("quickAccess"),r=section("reconnect"),p=section("protection"),d=section("diagnostics");
    NativeOptions out;
    out.icon_type=choice(text(n,"iconResourceType",out.icon_type),{"mipmap","drawable"});
    out.icon_name=resource(text(n,"iconResourceName",out.icon_name)); out.button_label=text(n,"buttonLabel",out.button_label,80);
    out.notification_action=choice(text(n,"action",out.notification_action),{"disconnect","openApp","none"});
    out.quick_enabled=flag(q,"enabled",false); out.require_unlock=flag(q,"requireUnlock",true);
    out.surface=choice(text(q,"surface",out.surface),{"platformDefault","quickTile","menuBar","systemTray","controlCenter"});
    out.label=text(q,"label",out.label,80); out.quick_action=choice(text(q,"action",out.quick_action),{"toggle","openApp"});
    out.android_icon=resource(text(q,"androidIconResourceName",out.android_icon)); out.apple_symbol=text(q,"appleSymbol",out.apple_symbol);
    if (q.contains("windowsIconPath")) {
      if (!q["windowsIconPath"].is_string()) throw std::invalid_argument("windowsIconPath");
      out.windows_icon=q["windowsIconPath"].get<std::string>(); auto lower=out.windows_icon;
      std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (lower.size()<5 || lower.substr(lower.size()-4)!=".ico" || lower.find('\0')!=std::string::npos || !std::regex_search(lower,std::regex(R"(^([a-z]:[\\/]|\\\\))"))) throw std::invalid_argument("windowsIconPath");
    }
    out.reconnect_enabled=flag(r,"enabled",true); out.initial_delay_ms=number(r,"initialDelayMs",1000); out.max_delay_ms=number(r,"maxDelayMs",60000); out.max_attempts=number(r,"maxAttempts",0);
    if (out.initial_delay_ms<100 || out.max_delay_ms<out.initial_delay_ms || out.max_delay_ms>600000 || out.max_attempts<0 || out.max_attempts>1000) throw std::invalid_argument("reconnect");
    out.kill_switch=choice(text(p,"killSwitch",out.kill_switch),{"required","platformDefault"});
    out.on_demand=choice(text(p,"onDemand",out.on_demand),{"platformDefault","enabled","disabled"});
    out.always_on=choice(text(p,"alwaysOn",out.always_on),{"system","requireEnabled"});
    if (!out.reconnect_enabled && out.on_demand=="enabled") throw std::invalid_argument("onDemand/reconnect");
    out.diagnostics_enabled=flag(d,"enabled",true); out.diagnostics_bytes=number(d,"maxBytes",131072); out.diagnostics_lines=number(d,"maxLines",300);
    if (out.diagnostics_bytes<4096 || out.diagnostics_bytes>131072 || out.diagnostics_lines<1 || out.diagnostics_lines>300) throw std::invalid_argument("diagnostics");
    return out;
  }
};
}
#endif
