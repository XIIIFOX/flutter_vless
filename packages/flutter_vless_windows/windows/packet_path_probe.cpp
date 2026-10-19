#include "packet_path_probe.h"
#include <ws2tcpip.h>

namespace flutter_vless {
namespace {
void Timeout(SOCKET socket_) {
  DWORD timeout = 750;
  setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
  setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
}
bool Send(SOCKET socket_, const std::string& bytes) {
  size_t sent = 0;
  while (sent < bytes.size()) {
    int count = send(socket_, bytes.data() + sent, static_cast<int>(bytes.size() - sent), 0);
    if (count <= 0) return false;
    sent += count;
  }
  return true;
}
bool Receive(SOCKET socket_, const std::string& expected) {
  std::string bytes(expected.size(), 0); size_t received = 0;
  while (received < bytes.size()) {
    int count = recv(socket_, bytes.data() + received, static_cast<int>(bytes.size() - received), 0);
    if (count <= 0) return false;
    received += count;
  }
  return bytes == expected;
}
}
PacketPathProbe::~PacketPathProbe() {
  running_.store(false);
  if (worker_.joinable()) worker_.join();
  if (listener_ != INVALID_SOCKET) closesocket(listener_);
  if (winsock_) WSACleanup();
}
bool PacketPathProbe::Start() {
  if (winsock_ || listener_ != INVALID_SOCKET || worker_.joinable()) return false;
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data)) return false;
  winsock_ = true;
  auto refuse = [&] {
    running_.store(false); port_ = 0;
    if (listener_ != INVALID_SOCKET) { closesocket(listener_); listener_ = INVALID_SOCKET; }
    if (winsock_) { WSACleanup(); winsock_ = false; }
    return false;
  };
  challenge_ = native::RandomHex(32);
  if (challenge_.empty()) return refuse();
  for (unsigned attempt = 0; attempt < 32; ++attempt) {
    listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener_ == INVALID_SOCKET) return refuse();
    BOOL exclusive = TRUE;
    sockaddr_in local{}; local.sin_family = AF_INET;
    if (setsockopt(listener_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<char*>(&exclusive), sizeof(exclusive))
        || InetPtonA(AF_INET, "127.0.0.1", &local.sin_addr) != 1
        || bind(listener_, reinterpret_cast<sockaddr*>(&local), sizeof(local))) return refuse();
    int size = sizeof(local);
    if (getsockname(listener_, reinterpret_cast<sockaddr*>(&local), &size)) return refuse();
    const auto port = ntohs(local.sin_port);
    if (!port) return refuse();
    if (excluded_ports_.count(port)) {
      closesocket(listener_); listener_ = INVALID_SOCKET;
      continue;
    }
    if (listen(listener_, 4)) return refuse();
    port_ = port; running_.store(true);
    try { worker_ = std::thread(&PacketPathProbe::Serve, this); }
    catch (...) { return refuse(); }
    return true;
  }
  return refuse();
}
void PacketPathProbe::Serve() {
  while (running_.load()) {
    fd_set readable; FD_ZERO(&readable); FD_SET(listener_, &readable);
    timeval wait{0, 100000};
    if (select(0, &readable, nullptr, nullptr, &wait) <= 0) continue;
    SOCKET client = accept(listener_, nullptr, nullptr);
    if (client == INVALID_SOCKET) continue;
    Timeout(client);
    if (Receive(client, challenge_)) Send(client, challenge_ + "-ok");
    closesocket(client);
  }
}
bool PacketPathProbe::Configure(xray_config::Json& config, uint16_t managed_port,
    std::vector<int64_t>* generated_guards) const {
  if (!running_.load() || !config["inbounds"].is_array() || !config["outbounds"].is_array() || !config["routing"]["rules"].is_array()) return false;
  std::string managed_tag;
  for (const auto& inbound : config["inbounds"]) {
    if (inbound.value("protocol", "") != "socks" || inbound.value("listen", "") != "127.0.0.1" ||
        xray_config::Port(inbound) != managed_port) continue;
    if (!managed_tag.empty()) return false;
    managed_tag = inbound.value("tag", "");
    if (managed_tag.empty()) return false;
  }
  if (managed_tag.empty()) return false;
  const auto probe_tag = xray_config::UniqueTag(config, tag);
  config["outbounds"].push_back({{"tag", probe_tag}, {"protocol", "freedom"},
      {"settings", {{"redirect", "127.0.0.1:" + std::to_string(port_)}, {"domainStrategy", "ForceIPv4"}}}});
  config["routing"]["rules"].insert(config["routing"]["rules"].begin(), xray_config::Json{
      {"type", "field"}, {"inboundTag", xray_config::Json::array({managed_tag})},
      {"ip", xray_config::Json::array({std::string(address) + "/32"})},
      {"port", std::to_string(port_)}, {"network", "tcp"}, {"outboundTag", probe_tag}});
  if (generated_guards) *generated_guards = {0};
  return true;
}
bool PacketPathProbe::Check(const char* destination) const {
  if (!running_.load()) return false;
  SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (client == INVALID_SOCKET) return false;
  sockaddr_in target{}; target.sin_family = AF_INET; target.sin_port = htons(port_);
  bool ok = InetPtonA(AF_INET, destination, &target.sin_addr) == 1;
  u_long nonblocking = 1;
  ok = ok && ioctlsocket(client, FIONBIO, &nonblocking) == 0;
  if (ok && connect(client, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) {
    ok = WSAGetLastError() == WSAEWOULDBLOCK;
    fd_set writable; FD_ZERO(&writable); FD_SET(client, &writable);
    timeval wait{0, 750000}; int error = 0, length = sizeof(error);
    ok = ok && select(0, nullptr, &writable, nullptr, &wait) > 0
        && getsockopt(client, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && error == 0;
  }
  nonblocking = 0; ioctlsocket(client, FIONBIO, &nonblocking); Timeout(client);
  ok = ok && Send(client, challenge_) && Receive(client, challenge_ + "-ok");
  closesocket(client);
  return ok;
}
}  // namespace flutter_vless
