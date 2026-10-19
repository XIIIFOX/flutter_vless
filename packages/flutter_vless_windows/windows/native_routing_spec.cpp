#include "native_routing_spec.h"
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <set>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(FLUTTER_VLESS_ROUTING_SPEC_TEST_HASH)
namespace flutter_vless::native_routing::testing {
std::optional<std::string> SHA256(std::string_view bytes);
}
#endif

namespace flutter_vless::native_routing {
namespace {
using Json = nlohmann::ordered_json;
// Same Go schema-key folding as xray_config::Fold; user values stay byte-exact.
std::string Fold(std::string value) {
  for (const auto& pair : {std::pair<std::string, std::string>{"\xc5\xbf", "s"}, {"\xe2\x84\xaa", "k"}}) {
    size_t offset = 0;
    while ((offset = value.find(pair.first, offset)) != std::string::npos) value.replace(offset, pair.first.size(), pair.second);
  }
  for (auto& value_byte : value) if (value_byte >= 'A' && value_byte <= 'Z') value_byte = static_cast<char>(value_byte + ('a' - 'A'));
  return value;
}
Json Parse(const std::string& source) {
  bool duplicate = false;
  std::vector<std::set<std::string>> keys;
  auto result = Json::parse(source, [&](int, Json::parse_event_t event, Json& value) {
    if (event == Json::parse_event_t::object_start) keys.emplace_back();
    if (event == Json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second) duplicate = true;
    if (event == Json::parse_event_t::object_end) keys.pop_back();
    return true;
  }, false, true);
  return duplicate ? Json(Json::value_t::discarded) : result;
}
void Fail(NativeRoutingError error) { throw error; }
const Json* Field(const Json& object, const char* name) {
  if (!object.is_object()) Fail(NativeRoutingError::malformed_configuration);
  const Json* found = nullptr;
  for (auto it = object.begin(); it != object.end(); ++it) {
    if (Fold(it.key()) != Fold(name)) continue;
    if (found) Fail(NativeRoutingError::malformed_configuration);
    found = &it.value();
  }
  return found;
}
bool Objects(const Json* array) {
  return array && array->is_array() && std::all_of(array->begin(), array->end(), [](const Json& value) { return value.is_object(); });
}
std::string Tag(const Json& object) {
  const auto value = Field(object, "tag");
  if (!value || value->is_null()) return {};
  if (!value->is_string()) Fail(NativeRoutingError::malformed_configuration);
  return value->get<std::string>();
}
bool StringIs(const Json* value, const std::string& expected) {
  return value && value->is_string() && value->get_ref<const std::string&>() == expected;
}
bool InRange(int64_t index, size_t count) {
  return index >= 0 && static_cast<uint64_t>(index) < static_cast<uint64_t>(count);
}
bool PrivateInput(const Json& input, const std::string& tag, const std::string& user) {
  if (Tag(input) != tag || !StringIs(Field(input, "protocol"), "socks")) return false;
  const auto listen = Field(input, "listen"), port = Field(input, "port"), settings = Field(input, "settings");
  if ((!StringIs(listen, "127.0.0.1") && !StringIs(listen, "::1")) || !port || !port->is_number() || !settings || !settings->is_object()) return false;
  const auto number = port->get<double>();
  if (!std::isfinite(number) || number < 1 || number > 65535 || std::trunc(number) != number) return false;
  if (!StringIs(Field(*settings, "auth"), "password")) return false;
  const auto accounts = Field(*settings, "accounts");
  if (!Objects(accounts) || accounts->size() != 1) return false;
  const auto& account = accounts->at(0);
  const auto password = Field(account, "pass");
  return StringIs(Field(account, "user"), user) && password && password->is_string() && !password->get_ref<const std::string&>().empty();
}
bool GuardRule(const Json& rule) {
  const auto target = Field(rule, "outboundTag"), balancing = Field(rule, "balancerTag"), webhook = Field(rule, "webhook");
  if (!target || !target->is_string() || target->get_ref<const std::string&>().empty()) return false;
  if (balancing && !balancing->is_null() && !StringIs(balancing, "")) return false;
  if (webhook && !webhook->is_null()) return false;
  const auto input = Field(rule, "inboundTag");
  if (!input) return false;
  if (input->is_array()) return !input->empty() && std::all_of(input->begin(), input->end(), [](const Json& value) {
    return value.is_string() && !value.get_ref<const std::string&>().empty();
  });
  if (!input->is_string()) return false;
  const auto& values = input->get_ref<const std::string&>();
  return !values.empty() && values.front() != ',' && values.back() != ',' && values.find(",,") == std::string::npos;
}
bool DigestValid(const std::string& digest) {
  return digest.size() == 64 && std::all_of(digest.begin(), digest.end(), [](char value) {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
  });
}
#ifdef _WIN32
std::optional<std::string> WindowsSHA256(std::string_view bytes) {
  struct Handles {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    // BCrypt retains this backing buffer until DestroyHash completes.
    std::vector<unsigned char> object;
    ~Handles() {
      if (hash) BCryptDestroyHash(hash);
      if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
  } handles;
  if (BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return std::nullopt;
  DWORD object_bytes = 0, hash_bytes = 0, received = 0;
  if (BCryptGetProperty(handles.algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &received, 0) != 0 || received != sizeof(object_bytes)) return std::nullopt;
  if (BCryptGetProperty(handles.algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_bytes), sizeof(hash_bytes), &received, 0) != 0 || received != sizeof(hash_bytes) || hash_bytes != 32) return std::nullopt;
  handles.object.resize(object_bytes);
  std::vector<unsigned char> hash(hash_bytes);
  if (BCryptCreateHash(handles.algorithm, &handles.hash, handles.object.data(), object_bytes, nullptr, 0, 0) != 0) return std::nullopt;
  size_t offset = 0;
  while (offset < bytes.size()) {
    const auto length = static_cast<ULONG>(std::min(bytes.size() - offset, static_cast<size_t>(std::numeric_limits<ULONG>::max())));
    const auto chunk = reinterpret_cast<const unsigned char*>(bytes.data() + offset);
    if (BCryptHashData(handles.hash, const_cast<PUCHAR>(chunk), length, 0) != 0) return std::nullopt;
    offset += length;
  }
  if (BCryptFinishHash(handles.hash, hash.data(), hash_bytes, 0) != 0) return std::nullopt;
  static constexpr char hex[] = "0123456789abcdef";
  std::string result;
  result.reserve(64);
  for (const auto byte : hash) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  return result;
}
#endif
}  // namespace

const char* NativeRoutingErrorMessage(NativeRoutingError error) noexcept {
  switch (error) {
    case NativeRoutingError::none: return "";
    case NativeRoutingError::invalid_intent: return "Invalid native routing intent.";
    case NativeRoutingError::malformed_configuration: return "Invalid final native routing configuration.";
    case NativeRoutingError::invalid_managed_inbound: return "Invalid private native routing adapter.";
    case NativeRoutingError::invalid_source_inbound: return "Invalid native routing source selection.";
    case NativeRoutingError::invalid_default_outbound: return "Invalid native routing default selection.";
    case NativeRoutingError::invalid_guard_rules: return "Invalid native routing guard selection.";
    case NativeRoutingError::hash_unavailable: return "Native routing digest is unavailable.";
  }
  return "Native routing metadata is unavailable.";
}

NativeRoutingEnvelope::NativeRoutingEnvelope(std::string configuration, std::string metadata, std::string digest)
    : configuration_data_(std::move(configuration)), metadata_data_(std::move(metadata)), source_sha256_(std::move(digest)) {}

std::optional<std::string> SHA256Exact(std::string_view bytes) noexcept {
  try {
#ifdef _WIN32
    return WindowsSHA256(bytes);
#elif defined(FLUTTER_VLESS_ROUTING_SPEC_TEST_HASH)
    return testing::SHA256(bytes);
#else
    (void)bytes;
    return std::nullopt;
#endif
  } catch (...) { return std::nullopt; }
}

NativeRoutingIntentResult NativeRoutingSpec::ParseIntent(std::string_view json) try {
  const auto value = Parse(std::string(json));
  if (value.is_null()) return {};
  if (!value.is_object()) return {std::nullopt, NativeRoutingError::invalid_intent};
  NativeRoutingIntent intent;
  for (auto it = value.begin(); it != value.end(); ++it) {
    if (it.key() == "sourceInboundIndex") {
      if (!it->is_number_integer() || (it->is_number_unsigned() && it->get<uint64_t>() > static_cast<uint64_t>(INT64_MAX)))
        return {std::nullopt, NativeRoutingError::invalid_intent};
      const auto index = it->get<int64_t>();
      if (index < 0) return {std::nullopt, NativeRoutingError::invalid_intent};
      intent.source_inbound_index = index;
    } else if (it.key() == "defaultOutboundTag") {
      if (!it->is_null() && !it->is_string()) return {std::nullopt, NativeRoutingError::invalid_intent};
      if (it->is_string()) intent.default_outbound_tag = it->get<std::string>();
    } else return {std::nullopt, NativeRoutingError::invalid_intent};
  }
  return {intent, NativeRoutingError::none};
} catch (...) { return {std::nullopt, NativeRoutingError::invalid_intent}; }

NativeRoutingError NativeRoutingSpec::ValidateSource(std::string_view configuration,
    const std::optional<NativeRoutingIntent>& intent) try {
  if (!intent) return NativeRoutingError::none;
  const auto root = Parse(std::string(configuration));
  if (!root.is_object()) return NativeRoutingError::malformed_configuration;
  if (intent->source_inbound_index) {
    const auto inputs = Field(root, "inbounds");
    if (!Objects(inputs) || !InRange(*intent->source_inbound_index, inputs->size())) return NativeRoutingError::invalid_source_inbound;
  }
  if (intent->default_outbound_tag && !intent->default_outbound_tag->empty()) {
    const auto outputs = Field(root, "outbounds");
    if (!Objects(outputs)) return NativeRoutingError::invalid_default_outbound;
    size_t matches = 0;
    for (const auto& output : *outputs) if (Tag(output) == *intent->default_outbound_tag) ++matches;
    if (matches != 1) return NativeRoutingError::invalid_default_outbound;
  }
  return NativeRoutingError::none;
} catch (NativeRoutingError error) { return error; }
catch (...) { return NativeRoutingError::malformed_configuration; }

NativeRoutingResult NativeRoutingSpec::Freeze(std::string_view final_data, int64_t managed_index,
    const std::string& managed_tag, const std::string& user, const std::optional<NativeRoutingIntent>& intent,
    std::optional<int64_t> mapped, const std::vector<int64_t>& guards) {
  if (!intent) return {};
  try {
    if (intent->source_inbound_index && *intent->source_inbound_index < 0) Fail(NativeRoutingError::invalid_intent);
    std::string frozen(final_data);
    const auto root = Parse(frozen);
    if (!root.is_object()) Fail(NativeRoutingError::malformed_configuration);
    const auto inbounds = Field(root, "inbounds");
    if (!Objects(inbounds)) Fail(NativeRoutingError::malformed_configuration);
    if (managed_tag.empty() || user.empty() || !InRange(managed_index, inbounds->size()) ||
        !PrivateInput(inbounds->at(static_cast<size_t>(managed_index)), managed_tag, user)) Fail(NativeRoutingError::invalid_managed_inbound);
    size_t managed_matches = 0;
    for (const auto& input : *inbounds) if (Tag(input) == managed_tag) ++managed_matches;
    if (managed_matches != 1) Fail(NativeRoutingError::invalid_managed_inbound);
    if (intent->source_inbound_index) {
      if (!mapped || !InRange(*mapped, inbounds->size()) || *mapped == managed_index) Fail(NativeRoutingError::invalid_source_inbound);
    } else if (mapped) Fail(NativeRoutingError::invalid_source_inbound);
    const std::string default_tag = intent->default_outbound_tag.value_or("");
    if (!default_tag.empty()) {
      const auto outbounds = Field(root, "outbounds");
      if (!Objects(outbounds)) Fail(NativeRoutingError::invalid_default_outbound);
      size_t matches = 0;
      for (const auto& output : *outbounds) if (Tag(output) == default_tag) ++matches;
      if (matches != 1) Fail(NativeRoutingError::invalid_default_outbound);
    }
    if (!guards.empty()) {
      const auto routing = Field(root, "routing");
      const auto rules = routing && routing->is_object() ? Field(*routing, "rules") : nullptr;
      if (!Objects(rules)) Fail(NativeRoutingError::invalid_guard_rules);
      std::set<int64_t> seen;
      for (const auto index : guards) if (!InRange(index, rules->size()) || !seen.insert(index).second ||
          !GuardRule(rules->at(static_cast<size_t>(index)))) Fail(NativeRoutingError::invalid_guard_rules);
    }
    const auto digest = SHA256Exact(frozen);
    if (!digest || !DigestValid(*digest)) Fail(NativeRoutingError::hash_unavailable);
    Json metadata = {{"version", 1}, {"source_sha256", *digest}, {"managed_inbound_index", managed_index},
        {"managed_inbound_tag", managed_tag}, {"auth_user", user}, {"guard_rule_indices", guards}};
    if (mapped) metadata["source_inbound_index"] = *mapped;
    if (!default_tag.empty()) metadata["default_outbound_tag"] = default_tag;
    return {NativeRoutingEnvelope(std::move(frozen), metadata.dump(), *digest), NativeRoutingError::none};
  } catch (NativeRoutingError error) { return {std::nullopt, error}; }
    catch (...) { return {std::nullopt, NativeRoutingError::malformed_configuration}; }
}
}  // namespace flutter_vless::native_routing
