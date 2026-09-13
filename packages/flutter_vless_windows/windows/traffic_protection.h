#ifndef FLUTTER_VLESS_TRAFFIC_PROTECTION_H_
#define FLUTTER_VLESS_TRAFFIC_PROTECTION_H_
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <filesystem>
#include <atomic>
#include <functional>

namespace flutter_vless {
// A non-dynamic WFP policy survives worker/application crashes. Only an explicit
// stop removes it; reconnect replaces its filters atomically in a transaction.
// This plugin controls one machine-wide VPN session at a time.
class TrafficProtection {
 public:
  explicit TrafficProtection(std::function<std::wstring()> dhcp_sid = {}) : dhcp_sid_(std::move(dhcp_sid)) {}
  ~TrafficProtection();
  bool Install(const std::filesystem::path& xray, const NET_LUID* tunnel = nullptr);
  bool Inspect();
  bool Release();
  bool Active() const { return active_.load(); }
 private:
  bool Open();
  bool DeleteFilters();
  HANDLE engine_ = nullptr;
  HANDLE owner_ = nullptr;
  std::atomic<bool> active_{false};
  std::function<std::wstring()> dhcp_sid_;
};
}  // namespace flutter_vless
#endif
