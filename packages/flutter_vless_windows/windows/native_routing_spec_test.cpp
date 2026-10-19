#include "native_routing_spec.h"
#include "third_party/nlohmann/json.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <type_traits>

#if defined(FLUTTER_VLESS_ROUTING_SPEC_TEST_HASH) && !defined(_WIN32)
#include <CommonCrypto/CommonDigest.h>
#include <limits>
namespace flutter_vless::native_routing::testing {
std::string last_hash_input;
bool fail_hash = false;
std::optional<std::string> SHA256(const std::string_view bytes) {
  last_hash_input.assign(bytes.data(), bytes.size());
  if (fail_hash || bytes.size() > std::numeric_limits<CC_LONG>::max()) return std::nullopt;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH]{};
  if (!CC_SHA256(bytes.data(), static_cast<CC_LONG>(bytes.size()), digest)) return std::nullopt;
  static constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (const auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  return result;
}
}  // namespace flutter_vless::native_routing::testing
#endif

namespace {
using namespace flutter_vless::native_routing;
using Json = nlohmann::ordered_json;
static_assert(!std::is_constructible_v<NativeRoutingEnvelope, std::string, std::string, std::string>, "Only the codec can mint a pair");
static_assert(std::is_same_v<decltype(std::declval<const NativeRoutingEnvelope&>().configuration_data()), const std::string&>, "Envelope bytes must be read-only");
constexpr auto kTag = "managed-private-canary";
constexpr auto kUser = "session-user-canary";
size_t checks = 0;
void Require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
Json Document() {
  return Json{{"inbounds", Json::array({
      {{"tag", kTag}, {"listen", "127.0.0.1"}, {"port", 19891}, {"protocol", "socks"},
       {"settings", {{"auth", "password"}, {"accounts", Json::array({{{"user", kUser}, {"pass", "synthetic-password-canary"}}})}, {"udp", true}}}},
      {{"tag", "caller"}, {"protocol", "socks"}, {"port", 19892}},
      {{"protocol", "socks"}, {"port", 19893}}})},
      {"outbounds", Json::array({{{"tag", "blocked"}, {"protocol", "blackhole"}}, {{"tag", "selected"}, {"protocol", "freedom"}}})},
      {"routing", {{"rules", Json::array({
          {{"type", "field"}, {"inboundTag", Json::array({kTag})}, {"ip", Json::array({"198.18.0.2/32"})}, {"outboundTag", "selected"}},
          {{"type", "field"}, {"inboundTag", Json::array({"caller"})}, {"outboundTag", "blocked"}},
          {{"type", "field"}, {"inboundTag", Json::array({"private-bootstrap"})}, {"outboundTag", "blocked"}}})}}},
      {"dns", {{"hosts", {{"source-canary.invalid", "192.0.2.1"}}}, {"servers", Json::array({"tcp://1.1.1.1"})}}},
      {"api", {{"tag", "caller-api"}, {"listen", "127.0.0.1:19894"}, {"services", Json::array({"StatsService"})}}}};
}
NativeRoutingResult Freeze(const std::string& source,
    const std::optional<NativeRoutingIntent>& intent = NativeRoutingIntent{0, "selected"},
    std::optional<int64_t> mapped = 1, int64_t managed = 0, std::vector<int64_t> guards = {0, 2},
    const std::string& tag = kTag, const std::string& user = kUser) {
  return NativeRoutingSpec::Freeze(source, managed, tag, user, intent, mapped, guards);
}
void Rejected(const NativeRoutingResult& result, NativeRoutingError expected) {
  Require(!result.envelope && result.error == expected, "wrong closed metadata refusal");
  Require(std::string(NativeRoutingErrorMessage(result.error)).find("canary") == std::string::npos, "private error escaped");
  ++checks;
}
void Tests() {
  Require(SHA256Exact("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty SHA256 vector mismatch");
  Require(SHA256Exact("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 vector mismatch");
  Require(SHA256Exact(std::string("a\0b", 3)) == "59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138", "binary SHA256 vector mismatch");
  ++checks;
  std::string source = Document().dump(2), original = source;
  const auto result = Freeze(source);
  Require(result.error == NativeRoutingError::none && result.envelope, "valid metadata refused");
  const auto& envelope = *result.envelope;
  auto metadata = Json::parse(envelope.metadata_data());
  Require(envelope.configuration_data() == source && envelope.source_sha256() == SHA256Exact(source), "exact frozen data mismatch");
  Require(metadata.size() == 8 && metadata["version"] == 1 && metadata["source_sha256"] == *SHA256Exact(source), "schema or digest mismatch");
  Require(metadata["managed_inbound_index"] == 0 && metadata["managed_inbound_tag"] == kTag && metadata["auth_user"] == kUser, "private identity changed");
  Require(metadata["source_inbound_index"] == 1 && metadata["default_outbound_tag"] == "selected" && metadata["guard_rule_indices"] == Json::array({0, 2}), "explicit selections changed");
  Require(std::string(envelope.DebugDescription()).find("canary") == std::string::npos, "envelope description escaped");
  ++checks;
  const auto changed = Freeze(source + " \n");
  Require(changed.envelope && changed.envelope->source_sha256() != envelope.source_sha256() && changed.envelope->configuration_data() == source + " \n", "JSON was reserialized before hashing");
  source[0] = 'x';
  Require(envelope.configuration_data() == original, "borrowed configuration changed frozen envelope");
  auto public_copy = envelope.metadata_data(); public_copy[0] = 'x';
  Require(envelope.metadata_data()[0] == '{', "metadata copy changed envelope");
  ++checks;
#if defined(FLUTTER_VLESS_ROUTING_SPEC_TEST_HASH) && !defined(_WIN32)
  Require(testing::last_hash_input == original + " \n", "hash provider did not receive exact bytes");
  testing::fail_hash = true;
  Rejected(Freeze(original), NativeRoutingError::hash_unavailable);
  Require(!Freeze("not-json", std::nullopt, std::nullopt).envelope && Freeze("not-json", std::nullopt, std::nullopt).error == NativeRoutingError::none, "ordinary path hashed or parsed source");
  testing::fail_hash = false;
#endif
  auto self_enabled = Document(); self_enabled["nativeRoutingSpec"] = metadata; self_enabled["source_inbound_index"] = 2;
  const auto ordinary = Freeze(self_enabled.dump(), std::nullopt, std::nullopt);
  Require(ordinary.error == NativeRoutingError::none && !ordinary.envelope, "caller JSON enabled metadata");
  const auto trusted = Freeze(self_enabled.dump());
  Require(trusted.envelope && Json::parse(trusted.envelope->metadata_data())["source_inbound_index"] == 1, "caller JSON overrode trusted selection");
  ++checks;
  for (const auto& tag : {std::optional<std::string>{}, std::optional<std::string>{""}}) {
    const auto empty = Freeze(original, NativeRoutingIntent{std::nullopt, tag}, std::nullopt);
    Require(empty.envelope.has_value(), "empty opt-in refused");
    const auto fields = Json::parse(empty.envelope->metadata_data());
    Require(!fields.contains("source_inbound_index") && !fields.contains("default_outbound_tag") && fields["guard_rule_indices"] == Json::array({0, 2}), "disabled choices did not omit optional metadata");
    ++checks;
  }
  const auto untagged = Freeze(original, NativeRoutingIntent{0, "selected"}, 2);
  Require(untagged.envelope && Json::parse(untagged.envelope->metadata_data())["source_inbound_index"] == 2, "untagged source collapsed into absent choice");
  ++checks;
  Rejected(Freeze(original, NativeRoutingIntent{-1, {}}), NativeRoutingError::invalid_intent);
  for (const int64_t index : {-1, 0, 3}) Rejected(Freeze(original, NativeRoutingIntent{0, "selected"}, index), NativeRoutingError::invalid_source_inbound);
  Rejected(Freeze(original, NativeRoutingIntent{0, "selected"}, std::nullopt), NativeRoutingError::invalid_source_inbound);
  Rejected(Freeze(original, NativeRoutingIntent{}, 1), NativeRoutingError::invalid_source_inbound);
  for (const int64_t index : {-1, 3}) Rejected(Freeze(original, NativeRoutingIntent{}, std::nullopt, index), NativeRoutingError::invalid_managed_inbound);
  Rejected(Freeze(original, NativeRoutingIntent{}, std::nullopt, 0, {}, "foreign-canary"), NativeRoutingError::invalid_managed_inbound);
  Rejected(Freeze(original, NativeRoutingIntent{}, std::nullopt, 0, {}, kTag, "foreign-canary"), NativeRoutingError::invalid_managed_inbound);
  Rejected(Freeze("not-json"), NativeRoutingError::malformed_configuration);
  Rejected(Freeze("[]"), NativeRoutingError::malformed_configuration);
  for (const auto& guards : {std::vector<int64_t>{-1}, {3}, {0, 0}}) Rejected(Freeze(original, NativeRoutingIntent{}, std::nullopt, 0, guards), NativeRoutingError::invalid_guard_rules);
  Rejected(Freeze(original, NativeRoutingIntent{{}, "missing-canary"}, std::nullopt), NativeRoutingError::invalid_default_outbound);
  auto duplicate = Document(); duplicate["inbounds"][1]["tag"] = kTag;
  Rejected(Freeze(duplicate.dump()), NativeRoutingError::invalid_managed_inbound);
  duplicate = Document(); duplicate["outbounds"].push_back(duplicate["outbounds"][1]);
  Rejected(Freeze(duplicate.dump()), NativeRoutingError::invalid_default_outbound);
  for (const auto& field : std::vector<std::pair<std::string, Json>>{{"protocol", "http"}, {"listen", "0.0.0.0"}, {"port", true}, {"port", 0}, {"port", "19891-19892"}, {"settings", {{"auth", "noauth"}}}}) {
    auto bad = Document(); bad["inbounds"][0][field.first] = field.second;
    Rejected(Freeze(bad.dump()), NativeRoutingError::invalid_managed_inbound);
  }
  for (const auto& field : std::vector<std::pair<std::string, Json>>{{"inboundTag", Json::array()}, {"inboundTag", Json::array({""})}, {"inboundTag", Json::array({nullptr})}, {"outboundTag", ""}, {"balancerTag", "caller"}, {"webhook", Json::object()}}) {
    auto bad = Document(); bad["routing"]["rules"][0][field.first] = field.second;
    Rejected(Freeze(bad.dump()), NativeRoutingError::invalid_guard_rules);
  }
  const std::string composed = "native-\xc3\xa9", decomposed = "native-e\xcc\x81";
  auto unicode = Document(); unicode["outbounds"][1]["tag"] = composed;
  Rejected(Freeze(unicode.dump(), NativeRoutingIntent{{}, decomposed}, std::nullopt), NativeRoutingError::invalid_default_outbound);
  unicode = Document(); unicode["inbounds"][0]["tag"] = composed;
  Rejected(Freeze(unicode.dump(), NativeRoutingIntent{}, std::nullopt, 0, {}, decomposed), NativeRoutingError::invalid_managed_inbound);
  auto folded = Document(); folded["INBOUNDS"] = folded["inbounds"]; folded.erase("inbounds");
  Require(Freeze(folded.dump()).envelope.has_value(), "Go-folded root field refused");
  folded["inbounds"] = Json::array();
  Rejected(Freeze(folded.dump()), NativeRoutingError::malformed_configuration);
  auto unicode_field = Document(); unicode_field["INBOUND\xc5\xbf"] = unicode_field["inbounds"]; unicode_field.erase("inbounds");
  Require(Freeze(unicode_field.dump()).envelope.has_value(), "Go long-S schema fold refused");
  auto string_scope = Document(); string_scope["routing"]["rules"][2]["inboundTag"] = "private-bootstrap,private-dns";
  Require(Freeze(string_scope.dump()).envelope.has_value(), "Core string-list guard scope refused");
  string_scope["routing"]["rules"][2]["inboundTag"] = "private-bootstrap,";
  Rejected(Freeze(string_scope.dump()), NativeRoutingError::invalid_guard_rules);
  ++checks;
}
void Export(const std::filesystem::path& directory) {
  Require(directory.is_absolute() && !std::filesystem::exists(directory), "synthetic export requires a new absolute directory");
  const auto result = Freeze(Document().dump(2));
  Require(result.envelope.has_value(), "synthetic export refused");
  Require(std::filesystem::create_directories(directory), "synthetic export directory failed");
  for (const auto& item : {std::pair<const char*, const std::string&>{"config.json", result.envelope->configuration_data()}, {"spec.json", result.envelope->metadata_data()}}) {
    std::ofstream file(directory / item.first, std::ios::binary | std::ios::out);
    file.write(item.second.data(), static_cast<std::streamsize>(item.second.size()));
    file.close(); Require(!file.fail(), "synthetic pair write failed");
  }
}
}  // namespace
int main(int argc, char** argv) {
  try {
    Tests();
    if (argc == 3 && std::string(argv[1]) == "--export-pair") Export(std::filesystem::u8path(argv[2]));
    else Require(argc == 1, "unknown synthetic test argument");
    std::cout << "NATIVE_ROUTING_SPEC_PURE_PASS=" << checks << '\n';
    return 0;
  } catch (const std::exception&) {
    std::cerr << "Native routing metadata test failed\n";
    return 1;
  }
}
