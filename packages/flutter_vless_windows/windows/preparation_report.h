#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include "third_party/nlohmann/json.hpp"

namespace flutter_vless::preparation {
enum class Change : unsigned {
  certificate_refs_bound, private_listener_added, system_dns_guard_added,
  private_logging_applied, port_environment_bound, address_environment_bound
};
enum class Stage { prepare, core_check, persist, start };

// Only typed producer operations can add a code. No caller JSON is stored or
// inspected by the serializer, including unknown metadata or configuration IDs.
class Report {
 public:
  void Add(Change change) { changes_ |= uint32_t{1} << static_cast<unsigned>(change); }
  void Merge(const Report& other) { changes_ |= other.changes_; }
  void CheckedHost() { checked_ = true; final_ = false; }
  void CheckedFinal() { checked_ = true; final_ = true; }
  nlohmann::ordered_json Json() const {
    static constexpr std::array<const char*, 6> codes = {{"certificate_refs_bound", "private_listener_added",
        "system_dns_guard_added", "private_logging_applied", "port_environment_bound", "address_environment_bound"}};
    auto changes = nlohmann::ordered_json::array();
    for (unsigned i = 0; i < codes.size(); ++i) if (changes_ & (uint32_t{1} << i)) changes.push_back(codes[i]);
    return {{"version", 1}, {"scope", final_ ? "runtimeFinal" : "host"},
        {"coreCheck", checked_ ? "passed" : "unavailable"}, {"changes", changes}};
  }
 private:
  uint32_t changes_ = 0;
  bool checked_ = false, final_ = false;
};

// Owned by one Start call and its worker only, under the service startup mutex.
struct StartupCompletion {
  bool finished = false, ready = false;
  Report report;
  Stage stage = Stage::start;
};

struct StartupOutcome {
  std::optional<Report> report;
  Stage stage = Stage::prepare;
  void Fail(Stage failure) { report.reset(); stage = failure; }
  void Succeed(const Report& value) { report = value; }
  nlohmann::ordered_json Details() const {
    const char* name = "prepare";
    switch (stage) {
      case Stage::prepare: break;
      case Stage::core_check: name = "core-check"; break;
      case Stage::persist: name = "persist"; break;
      case Stage::start: name = "start"; break;
    }
    return {{"version", 1}, {"stage", name}};
  }
};
}  // namespace flutter_vless::preparation
