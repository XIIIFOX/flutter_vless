#ifndef FLUTTER_VLESS_DIAGNOSTICS_LOG_H_
#define FLUTTER_VLESS_DIAGNOSTICS_LOG_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>

namespace flutter_vless {

// Thread-safe bounded log shared by the Windows Xray and tun2socks readers.
// The buffer survives Stop() and is reset only when a new runtime starts so a
// failed session remains available to the Dart diagnostics API.
class DiagnosticsLog {
public:
  using Generation = std::uint64_t;

  static DiagnosticsLog &Instance();

  Generation Reset();
  Generation CurrentGeneration() const;
  void Append(const std::string &source, const std::string &message);
  void Append(Generation generation, const std::string &source,
              const std::string &message);
  std::string Snapshot() const;

private:
  DiagnosticsLog() = default;

  static constexpr std::size_t kMaxStoredBytes = 128 * 1024;
  static constexpr std::size_t kMaxSnapshotBytes = 64 * 1024 - 64;
  static constexpr std::size_t kMaxSnapshotLines = 300;
  static constexpr std::size_t kMaxLineBytes = 16 * 1024;

  mutable std::mutex mutex_;
  std::deque<std::string> lines_;
  std::size_t stored_bytes_ = 0;
  Generation generation_ = 0;
};

} // namespace flutter_vless

#endif // FLUTTER_VLESS_DIAGNOSTICS_LOG_H_
