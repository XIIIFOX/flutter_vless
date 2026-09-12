#include "diagnostics_log.h"

#include <cassert>
#include <string>

int main() {
  auto &log = flutter_vless::DiagnosticsLog::Instance();
  const auto first_generation = log.Reset();
  assert(log.Snapshot().empty());

  log.Append("xray-stdout", "started\ntransport ready\n");
  log.Append("tun2socks-stderr", "TUN fd received");
  std::string snapshot = log.Snapshot();
  assert(snapshot.find("[xray-stdout] started") != std::string::npos);
  assert(snapshot.find("[tun2socks-stderr] TUN fd received") !=
         std::string::npos);

  for (int index = 0; index < 100; ++index) {
    log.Append("xray", "message-" + std::to_string(index) + " " +
                           std::string(4096, 'x'));
  }
  snapshot = log.Snapshot();
  assert(snapshot.find("message-99") != std::string::npos);
  assert(snapshot.find("message-0 ") == std::string::npos);
  assert(snapshot.size() < 64 * 1024);

  const auto second_generation = log.Reset();
  log.Append(first_generation, "stale", "old reader completed");
  log.Append(second_generation, "xray", std::string(20000, 'z') + u8"готово");
  snapshot = log.Snapshot();
  assert(snapshot.find("old reader") == std::string::npos);
  assert(snapshot.find(u8"готово") != std::string::npos);

  const auto third_generation = log.Reset();
  std::string incomplete_utf8 = "partial";
  incomplete_utf8.push_back(static_cast<char>(0xD0));
  log.Append(third_generation, "xray", incomplete_utf8);
  snapshot = log.Snapshot();
  assert(snapshot.find("[xray] partial") != std::string::npos);
  assert(snapshot.find(incomplete_utf8) == std::string::npos);
  assert(snapshot.find(static_cast<char>(0xD0)) == std::string::npos);
  assert(snapshot.back() == '\n');

  std::string malformed_utf8 = "before";
  malformed_utf8.push_back(static_cast<char>(0xFF));
  malformed_utf8 += "after";
  log.Append(third_generation, "xray", malformed_utf8);
  snapshot = log.Snapshot();
  assert(snapshot.find("beforeafter") != std::string::npos);
  assert(snapshot.find(static_cast<char>(0xFF)) == std::string::npos);
  return 0;
}
