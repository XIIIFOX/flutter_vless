#include "packet_path_probe.h"
#include <ws2tcpip.h>
#include <chrono>

namespace flutter_vless {
namespace {
using ProbeClock = std::chrono::steady_clock;
class ExchangeBudget {
 public:
  ExchangeBudget(const std::atomic<bool>& running, std::chrono::milliseconds duration,
      std::function<bool()> is_cancelled = {})
      : running_(running), deadline_(ProbeClock::now() + duration), is_cancelled_(std::move(is_cancelled)) {}
  bool CanContinue() const {
    return running_.load() && (!is_cancelled_ || !is_cancelled_()) && ProbeClock::now() < deadline_;
  }
  long PollMilliseconds() const {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - ProbeClock::now()).count();
    return remaining >= 50 ? 50 : static_cast<long>(remaining > 0 ? remaining : 1);
  }
 private:
  const std::atomic<bool>& running_;
  ProbeClock::time_point deadline_;
  std::function<bool()> is_cancelled_;
};
bool WaitReady(SOCKET socket_, bool writing, const ExchangeBudget& budget) {
  while (budget.CanContinue()) {
    fd_set ready; FD_ZERO(&ready); FD_SET(socket_, &ready);
    timeval wait{0, budget.PollMilliseconds() * 1000};
    const int count = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, nullptr, &wait);
    if (count > 0) return budget.CanContinue();
    if (count < 0 && WSAGetLastError() != WSAEINTR) return false;
  }
  return false;
}
bool Send(SOCKET socket_, const std::string& bytes, const ExchangeBudget& budget) {
  size_t sent = 0;
  while (sent < bytes.size() && budget.CanContinue()) {
    if (!WaitReady(socket_, true, budget)) return false;
    int count = send(socket_, bytes.data() + sent, static_cast<int>(bytes.size() - sent), 0);
    if (count == SOCKET_ERROR && (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR)) continue;
    if (count <= 0) return false;
    sent += count;
  }
  return sent == bytes.size() && budget.CanContinue();
}
bool Receive(SOCKET socket_, const std::string& expected, const ExchangeBudget& budget) {
  std::string bytes(expected.size(), 0); size_t received = 0;
  while (received < bytes.size() && budget.CanContinue()) {
    if (!WaitReady(socket_, false, budget)) return false;
    int count = recv(socket_, bytes.data() + received, static_cast<int>(bytes.size() - received), 0);
    if (count == SOCKET_ERROR && (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR)) continue;
    if (count <= 0) return false;
    received += count;
  }
  return received == bytes.size() && budget.CanContinue() && bytes == expected;
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
    // select can race an aborted connection; accept must never block Stop.
    u_long nonblocking = 1;
    if (ioctlsocket(listener_, FIONBIO, &nonblocking)) return refuse();
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
    u_long nonblocking = 1;
    if (ioctlsocket(client, FIONBIO, &nonblocking) == 0) {
      // One exchange budget, not a fresh timeout per partial challenge byte.
      const ExchangeBudget budget(running_, std::chrono::milliseconds(1500));
      if (Receive(client, challenge_, budget)) Send(client, challenge_ + "-ok", budget);
    }
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
bool PacketPathProbe::Check(const char* destination, const std::function<bool()>& is_cancelled) const {
  // Preserve the old nominal connect/send/receive allowance as one total.
  const ExchangeBudget budget(running_, std::chrono::milliseconds(2250), is_cancelled);
  if (!budget.CanContinue()) return false;
  SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (client == INVALID_SOCKET) return false;
  sockaddr_in target{}; target.sin_family = AF_INET; target.sin_port = htons(port_);
  bool ok = InetPtonA(AF_INET, destination, &target.sin_addr) == 1;
  u_long nonblocking = 1;
  ok = ok && ioctlsocket(client, FIONBIO, &nonblocking) == 0;
  if (ok && connect(client, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) {
    const auto error_code = WSAGetLastError();
    ok = error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS || error_code == WSAEINTR;
    int error = 0, length = sizeof(error);
    ok = ok && WaitReady(client, true, budget)
        && getsockopt(client, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && error == 0;
  }
  ok = ok && Send(client, challenge_, budget) && Receive(client, challenge_ + "-ok", budget);
  closesocket(client);
  return ok;
}
}  // namespace flutter_vless
