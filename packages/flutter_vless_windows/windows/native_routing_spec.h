#ifndef FLUTTER_VLESS_NATIVE_ROUTING_SPEC_H_
#define FLUTTER_VLESS_NATIVE_ROUTING_SPEC_H_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace flutter_vless::native_routing {

// Native-only choices. The source index addresses ORIGINAL caller inbounds;
// its final index must be supplied explicitly by the owning preparer.
struct NativeRoutingIntent {
  std::optional<int64_t> source_inbound_index;
  std::optional<std::string> default_outbound_tag;
};

enum class NativeRoutingError {
  none, invalid_intent, malformed_configuration, invalid_managed_inbound,
  invalid_source_inbound, invalid_default_outbound, invalid_guard_rules,
  hash_unavailable
};
const char* NativeRoutingErrorMessage(NativeRoutingError error) noexcept;

class NativeRoutingEnvelope {
 public:
  const std::string& configuration_data() const noexcept { return configuration_data_; }
  const std::string& metadata_data() const noexcept { return metadata_data_; }
  const std::string& source_sha256() const noexcept { return source_sha256_; }
  const char* DebugDescription() const noexcept { return "NativeRoutingEnvelope(<private>)"; }

 private:
  friend class NativeRoutingSpec;
  NativeRoutingEnvelope(std::string configuration, std::string metadata, std::string digest);
  std::string configuration_data_, metadata_data_, source_sha256_;
};

struct NativeRoutingResult {
  std::optional<NativeRoutingEnvelope> envelope;
  NativeRoutingError error = NativeRoutingError::none;
};

// BCrypt on Windows. There is no non-Windows production hash fallback.
std::optional<std::string> SHA256Exact(std::string_view bytes) noexcept;

class NativeRoutingSpec {
 public:
  // Metadata only: no config rewriting, Core construction or process state.
  // Go preflight remains authoritative for the complete compiled Core shape.
  // Nil intent returns the ordinary path without even parsing or hashing JSON.
  static NativeRoutingResult Freeze(std::string_view final_data, int64_t managed_inbound_index,
      const std::string& managed_inbound_tag, const std::string& auth_user,
      const std::optional<NativeRoutingIntent>& intent,
      std::optional<int64_t> source_inbound_final_index = std::nullopt,
      const std::vector<int64_t>& guard_rule_indices = {});
};
}  // namespace flutter_vless::native_routing
#endif
