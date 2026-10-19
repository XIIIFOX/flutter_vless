#include "preparation_report.h"
#include "vpn_worker_candidate.h"
#include <iostream>
#include <stdexcept>

namespace {
using namespace flutter_vless;
using Json = xray_config::Json;
void Require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
const std::string source = R"({"inbounds":[],"outbounds":[{"tag":"caller-secret","protocol":"freedom"}],"dns":{"servers":["9.9.9.9"]},"routing":{"rules":[]},"custom":{"network":"secret-host.invalid","allowInsecure":"secret-token","path":"/secret/private"}})";
preparation::Report Prepare(const std::string& bytes) {
  preparation::Report report;
  const auto final = xray_config::PrepareProtectedVpn(bytes, "secret-user", "secret-password", "secret-interface",
      [](const std::string&) -> std::string { throw std::runtime_error("Numeric fixture must not resolve"); },
      nullptr, [](uint16_t) { return true; }, &report);
  Require(final.has_value(), "actual protected preparation failed");
  return report;
}
struct Probe {
  bool Start() const { return true; }
  bool Configure(Json& config, uint16_t, std::vector<int64_t>* guards) const {
    config["routing"]["rules"].insert(config["routing"]["rules"].begin(),
        Json{{"type", "field"}, {"outboundTag", "private-probe-canary"}});
    if (guards) *guards = {0};
    return true;
  }
};
void CandidateCases() {
  using Candidate = native::VpnWorkerCandidate<Probe>;
  std::string checked;
  unsigned removed = 0;
  const auto prepare = [&](bool accepted, preparation::Report changes) {
    return Candidate::Prepare(source, "synthetic-underlay", 1, 19000,
        [] { return std::make_unique<Probe>(); },
        [&](const std::string& bytes, std::filesystem::path& path) {
          checked = bytes; path = "private-file-canary"; return accepted;
        }, [&](std::filesystem::path& path) { ++removed; path.clear(); }, changes);
  };
  preparation::Report certificate;
  certificate.Add(preparation::Change::certificate_refs_bound);
  auto active = prepare(true, certificate);
  Require(active && active->Bytes() == checked && !active->Path().empty()
      && active->PreparationReport().Json()["scope"] == "runtimeFinal"
      && active->PreparationReport().Json()["coreCheck"] == "passed", "candidate report detached from checked bytes/file");
  const auto accepted_bytes = active->Bytes(), accepted_report = active->PreparationReport().Json().dump();
  auto refused = prepare(false, {});
  Require(!refused && active->Bytes() == accepted_bytes && active->PreparationReport().Json().dump() == accepted_report && removed == 1,
      "refused candidate replaced working owner/report or leaked file");
  auto replacement = prepare(true, {});
  Require(replacement && replacement->PreparationReport().Json()["changes"].empty()
      && active->PreparationReport().Json()["changes"] == Json::array({"certificate_refs_bound"}), "candidate reports shared mutable operation state");
  active.reset(); replacement.reset();
  Require(removed == 3, "candidate cleanup count changed");
}
void Tests() {
  const auto report = Prepare(source);
  Require(report.Json()["changes"] == Json::array({"private_listener_added", "system_dns_guard_added", "private_logging_applied"}),
      "actual typed preparation did not record closed changes");
  auto opaque = xray_config::Parse(source); opaque["custom"] = {{"other-secret", "different-private-value"}};
  Require(Prepare(opaque.dump()).Json() == report.Json(), "opaque metadata influenced public summary");
  auto clean = xray_config::Parse(source);
  clean["log"] = {{"access", "none"}, {"error", "none"}, {"loglevel", "none"}, {"dnsLog", false}};
  Require(Prepare(clean.dump()).Json()["changes"] == Json::array({"private_listener_added", "system_dns_guard_added"}),
      "unchanged private logging was reported as a transformation");
  clean["log"]["unknown-private-metadata"] = "another-secret";
  Require(Prepare(clean.dump()).Json()["changes"] == Json::array({"private_listener_added", "system_dns_guard_added"}),
      "unknown log metadata was treated as a known logging operation");
  for (const auto& value : {Json(nullptr), Json(""), Json("half"), Json(false)}) {
    clean["log"]["MaSkAdDrEsS"] = value;
    Require(Prepare(clean.dump()).Json()["changes"] == Json::array({"private_listener_added", "system_dns_guard_added", "private_logging_applied"}),
        "actual known log maskAddress removal was not reported");
  }
  const auto wire = report.Json().dump();
  for (const auto* secret : {"secret", "caller", "9.9.9.9", "10807", "invalid", "private-value"})
    Require(wire.find(secret) == std::string::npos, "report disclosed caller data");
  preparation::Report legacy;
  Require(legacy.Json()["scope"] == "host" && legacy.Json()["coreCheck"] == "unavailable", "unchecked legacy report claimed success");
  preparation::StartupOutcome outcome; outcome.Succeed(report); outcome.Fail(preparation::Stage::core_check);
  Require(!outcome.report && outcome.Details() == Json({{"version", 1}, {"stage", "core-check"}}), "refusal retained stale report or unsafe details");
  auto environment = xray_config::Parse(source);
  environment["inbounds"] = Json::array({{{"protocol", "socks"}, {"listen", "env:secret-listen"}, {"port", 18080}}});
  environment["dns"]["servers"] = Json::array({"env:secret-dns"});
  environment["custom"]["address"] = "env:opaque-untouched";
  preparation::Report bound;
  Require(xray_config::Normalize(environment, [](const std::string& name) -> std::optional<std::string> {
    if (name == "secret-listen") return "127.0.0.1";
    if (name == "secret-dns") return "tcp://192.0.2.53";
    throw std::runtime_error("Opaque metadata triggered environment reader");
  }, &bound) && environment["inbounds"][0]["listen"] == "127.0.0.1"
      && bound.Json()["changes"] == Json::array({"private_logging_applied", "address_environment_bound"}), "typed Address binding report missing");
  preparation::Report unchanged;
  Require(xray_config::Normalize(environment, [](const std::string&) -> std::optional<std::string> {
    throw std::runtime_error("Already bound config read environment twice");
  }, &unchanged) && unchanged.Json()["changes"].empty(), "idempotent preparation reported another change");
  auto nested = environment;
  nested["dns"]["servers"] = Json::array({"env:self-same"});
  preparation::Report rejected_binding;
  Require(!xray_config::Normalize(nested, [](const std::string& name) -> std::optional<std::string> {
    return "env:" + name;
  }, &rejected_binding) && rejected_binding.Json()["changes"].empty(),
      "self-same nested env refusal reported a successful binding");
  auto certificate = xray_config::Parse(source);
  certificate["outbounds"][0]["streamSettings"] = {{"security", "tls"}, {"tlsSettings", {
      {"certificates", Json::array({{{"certificateFile", "secret-certificate.pem"}}})}}}};
  auto text = certificate.dump(); preparation::Report files;
  Require(xray_config::BindCertificatePaths(text, std::filesystem::absolute("tool/fixtures/compatibility"), &files)
      && files.Json()["changes"] == Json::array({"certificate_refs_bound"}), "actual relative certificate binding not recorded");
  preparation::Report absolute;
  Require(xray_config::BindCertificatePaths(text, std::filesystem::absolute("tool/fixtures/compatibility"), &absolute)
      && absolute.Json()["changes"].empty(), "already absolute certificate reported bound");
  auto invalid = xray_config::Parse(source); invalid["outbounds"][0]["protocol"] = "invalid-private-canary";
  preparation::Report retained; retained.Add(preparation::Change::certificate_refs_bound);
  const auto before = retained.Json();
  Require(!xray_config::PrepareProtectedVpn(invalid.dump(), "user", "pass", "interface",
      [](const std::string&) { return std::string(); }, nullptr, {}, &retained) && retained.Json() == before,
      "rejected preparation published partial operation flags");
  auto proxy = xray_config::Parse(source);
  proxy["inbounds"] = Json::array({{{"protocol", "socks"}, {"listen", "127.0.0.1"}, {"port", 18080}}});
  auto proxy_text = proxy.dump(); preparation::Report proxy_report;
  Require(xray_config::PrepareProxy(proxy_text, [](uint16_t) { return true; }, [] { return uint16_t{0}; }, &proxy_report)
      && proxy_report.Json()["changes"] == Json::array({"private_listener_added", "private_logging_applied"}),
      "actual generated proxy API listener not reported");
  CandidateCases();
}
}
int main() try { Tests(); std::cout << "WINDOWS_PREPARATION_REPORT_PURE_PASS=18\n"; }
catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
