#pragma once
#include <winsock2.h>
#include <windows.h>
#include <functional>
#include "native_runtime.h"
#include "xray_config.h"

namespace flutter_vless {
class PacketPathProbe {
 public:
  static constexpr const char* address = "10.0.85.54";
  static constexpr const char* tag = "flutter-vless-packet-probe";
  explicit PacketPathProbe(std::set<unsigned> excluded_ports = {})
      : excluded_ports_(std::move(excluded_ports)) {}
  ~PacketPathProbe();
  bool Start();
  bool Configure(xray_config::Json& config, uint16_t managed_port,
      std::vector<int64_t>* generated_guards = nullptr) const;
  // The synchronous callback is not retained after this exchange.
  bool Check(const char* destination = address,
      const std::function<bool()>& is_cancelled = {}) const;
 private:
  void Serve();
  SOCKET listener_ = INVALID_SOCKET;
  bool winsock_ = false;
  uint16_t port_ = 0;
  std::string challenge_;
  std::atomic<bool> running_{false};
  std::thread worker_;
  std::set<unsigned> excluded_ports_;
};
}  // namespace flutter_vless
