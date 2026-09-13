#pragma once
#include <winsock2.h>
#include <windows.h>
#include "native_runtime.h"
#include "xray_config.h"

namespace flutter_vless {
class PacketPathProbe {
 public:
  static constexpr const char* address = "198.18.0.3";
  static constexpr const char* tag = "flutter-vless-packet-probe";
  ~PacketPathProbe();
  bool Start();
  bool Configure(xray_config::Json& config) const;
  bool Check(const char* destination = address) const;
 private:
  void Serve();
  SOCKET listener_ = INVALID_SOCKET;
  bool winsock_ = false;
  uint16_t port_ = 0;
  std::string challenge_;
  std::atomic<bool> running_{false};
  std::thread worker_;
};
}  // namespace flutter_vless
