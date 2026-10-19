#include "native_routing_protocol.h"
#include "native_routing_spec.h"
#include "vpn_worker_candidate.h"
#include <iostream>
#include <stdexcept>
#if defined(FLUTTER_VLESS_ROUTING_SPEC_TEST_HASH) && !defined(_WIN32)
#include <CommonCrypto/CommonDigest.h>
namespace flutter_vless::native_routing::testing {
std::optional<std::string> SHA256(std::string_view value) {
  unsigned char bytes[CC_SHA256_DIGEST_LENGTH]{};
  if (value.size() > UINT32_MAX || !CC_SHA256(value.data(), static_cast<CC_LONG>(value.size()), bytes)) return std::nullopt;
  std::string result; const char* hex = "0123456789abcdef";
  for (const auto byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  return result;
}
}
#endif
namespace {
using namespace flutter_vless;
using namespace flutter_vless::native_routing;
using Json = xray_config::Json;
unsigned checks = 0;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Probe {
  unsigned& live;
  explicit Probe(unsigned& count) : live(count) { ++live; }
  ~Probe() { --live; }
  bool Start() const { return true; }
  bool Configure(Json& json, uint16_t, std::vector<int64_t>* guards) const {
    const auto tag = json["inbounds"][0]["tag"];
    json["outbounds"].push_back({{"tag", "synthetic-owned-probe"}, {"protocol", "freedom"}});
    json["routing"]["rules"].insert(json["routing"]["rules"].begin(), Json{
        {"type", "field"}, {"inboundTag", Json::array({tag})}, {"ip", Json::array({"10.0.85.54/32"})},
        {"outboundTag", "synthetic-owned-probe"}});
    *guards = {0}; return true;
  }
};
using Candidate = native::VpnWorkerCandidate<Probe>;
void Tests() {
  Require(NativeRoutingSpec::ParseIntent("null").error == NativeRoutingError::none
      && !NativeRoutingSpec::ParseIntent("null").intent, "null enabled routing"); ++checks;
  const auto empty = NativeRoutingSpec::ParseIntent("{}");
  Require(empty.intent && !empty.intent->source_inbound_index && !empty.intent->default_outbound_tag, "empty opt-in disabled"); ++checks;
  const auto zero = NativeRoutingSpec::ParseIntent(R"({"sourceInboundIndex":0,"defaultOutboundTag":" direct "})");
  Require(zero.intent && zero.intent->source_inbound_index == 0 && zero.intent->default_outbound_tag == " direct ", "intent index/tag changed"); ++checks;
  for (const auto* value : {"null", "\"\""}) {
    const auto parsed = NativeRoutingSpec::ParseIntent(std::string("{\"defaultOutboundTag\":") + value + "}");
    Require(parsed.intent && (!parsed.intent->default_outbound_tag || parsed.intent->default_outbound_tag->empty()), "Core default tag refused"); ++checks;
  }
  for (const auto* value : {"false", "3", "[]", R"({"sourceInboundIndex":null})", R"({"sourceInboundIndex":true})",
      R"({"sourceInboundIndex":0.0})", R"({"sourceInboundIndex":-1})", R"({"sourceInboundIndex":18446744073709551615})",
      R"({"defaultOutboundTag":1})", R"({"unknown":0})", R"({"sourceInboundIndex":0,"sourceInboundIndex":1})"}) {
    const auto parsed = NativeRoutingSpec::ParseIntent(value);
    Require(!parsed.intent && parsed.error == NativeRoutingError::invalid_intent, "invalid channel routing shape accepted"); ++checks;
  }
  Require(SuccessfulReply("{\"stage\":\"capabilities\",\"code\":0,\"capability\":1}\n", "capabilities", true), "real capability reply refused"); ++checks;
  for (const auto* value : {R"({"stage":"capabilities","code":0,"capability":0})", R"({"stage":"capabilities","code":0,"capability":2})",
      R"({"stage":"capabilities","code":0,"capability":true})", R"({"stage":"capabilities","code":0.0,"capability":1})",
      R"({"stage":"capabilities","code":32,"capability":1})", R"({"stage":"capabilities","code":0})",
      R"({"stage":"capabilities","code":0,"capability":1,"unknown":0})", R"({"stage":"capabilities","code":0,"capability":1,"capability":0})",
      "not-json", R"({"stage":"capabilities","code":0,"capability":1}{})"}) {
    Require(!SuccessfulReply(value, "capabilities", true), "legacy/partial/unknown capability accepted"); ++checks;
  }
  Require(SuccessfulReply(R"({"stage":"check","code":0})", "check")
      && !SuccessfulReply(R"({"stage":"check","code":3})", "check")
      && !SuccessfulReply(R"({"stage":"started","code":0})", "check"), "private check stage not strict"); ++checks;

  const std::string source = R"({"inbounds":[{"tag":"source-input","protocol":"socks","listen":"127.0.0.1","port":18580}],"outbounds":[{"tag":"blocked","protocol":"blackhole"},{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"vless","settings":{"address":"endpoint.invalid","port":443,"id":"11111111-1111-4111-8111-111111111111","encryption":"none"},"streamSettings":{"network":"tcp"}}],"dns":{"servers":["localhost"]},"routing":{"rules":[{"type":"field","inboundTag":["flutter-vless-tun"],"port":"53","outboundTag":"blocked"}]}})";
  Require(NativeRoutingSpec::ValidateSource("not-json", std::nullopt) == NativeRoutingError::none, "ordinary source was parsed"); ++checks;
  Require(NativeRoutingSpec::ValidateSource(source, NativeRoutingIntent{0, "direct"}) == NativeRoutingError::none, "original source index zero refused"); ++checks;
  Require(NativeRoutingSpec::ValidateSource(source, NativeRoutingIntent{1, "direct"}) == NativeRoutingError::invalid_source_inbound, "out-of-range original index accepted"); ++checks;
  Require(NativeRoutingSpec::ValidateSource(source, NativeRoutingIntent{0, "synthetic-owned-probe"}) == NativeRoutingError::invalid_default_outbound, "generated/private tag accepted as caller default"); ++checks;
  xray_config::VpnRoutingProvenance provenance;
  unsigned resolves = 0;
  const auto prepared = xray_config::PrepareProtectedVpn(source, "synthetic-user", "synthetic-password", "fixture-adapter",
      [&](const std::string& name) { Require(name == "endpoint.invalid", "unexpected endpoint"); ++resolves; return "192.0.2.1"; }, &provenance);
  Require(prepared && resolves == 1 && provenance.original_inbound_count == 1 && !provenance.managed_tag.empty(), "actual protected preparer lost provenance");
  const auto prepared_json = xray_config::Parse(*prepared);
  const auto& prepared_rules = prepared_json["routing"]["rules"];
  Require(provenance.guard_rule_indices.size() + 1 == prepared_rules.size(), "caller rule entered private guard set");
  for (size_t i = 0; i < provenance.guard_rule_indices.size(); ++i)
    Require(provenance.guard_rule_indices[i] == static_cast<int64_t>(i), "generated prefix indices shifted");
  Require(prepared_rules.back() == xray_config::Parse(source)["routing"]["rules"][0], "caller lookalike rule changed"); ++checks;

  unsigned live = 0, removed = 0;
  std::string checked_config, checked_spec;
  const auto intent = NativeRoutingIntent{0, "direct"};
  auto create = [&](bool accept) {
    return Candidate::Prepare(*prepared, "rebound-adapter", 99, 10807,
        [&] { return std::make_unique<Probe>(live); },
        [&](const std::string& bytes, std::filesystem::path& config_path, std::string& spec,
            std::filesystem::path& spec_path, const std::vector<int64_t>& probe_guards) {
          std::vector<int64_t> guards = probe_guards;
          for (const auto index : provenance.guard_rule_indices) guards.push_back(index + static_cast<int64_t>(probe_guards.size()));
          auto result = NativeRoutingSpec::Freeze(bytes, 0, provenance.managed_tag, "synthetic-user", intent, 1, guards);
          Require(result.envelope && result.error == NativeRoutingError::none, "final candidate pair refused");
          checked_config = bytes; checked_spec = result.envelope->metadata_data(); spec = checked_spec;
          config_path = "synthetic-owned-config"; spec_path = "synthetic-owned-spec";
          return accept;
        }, [&](std::filesystem::path& path) { ++removed; path.clear(); });
  };
  auto candidate = create(true);
  Require(candidate && candidate->Routing() && candidate->Bytes() == checked_config && candidate->Metadata() == checked_spec,
      "checked config/spec bytes not retained together");
  const auto spec = Json::parse(checked_spec);
  Require(spec["source_sha256"] == *SHA256Exact(checked_config) && spec["source_inbound_index"] == 1
      && spec["default_outbound_tag"] == "direct" && spec["guard_rule_indices"].size() == provenance.guard_rule_indices.size() + 1,
      "mapped source/default/digest/guard provenance lost"); ++checks;
  auto refused = create(false);
  Require(!refused && live == 1 && removed == 2, "rejected private pair leaked or retired active probe"); ++checks;
  candidate->RemoveFile(); candidate->RemoveFile(); candidate.reset();
  Require(live == 0 && removed == 4, "accepted private pair was not cleaned exactly once"); ++checks;
}
}
int main() try { Tests(); std::cout << "WINDOWS_ROUTING_ADOPTION_PURE_PASS=" << checks << '\n'; }
catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
