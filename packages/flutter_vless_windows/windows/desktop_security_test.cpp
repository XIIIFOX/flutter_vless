#include "xray_config.h"
#include <iostream>
#include <stdexcept>
#include <fstream>
using namespace flutter_vless::xray_config;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
class EndpointEnvironment {
 public:
  explicit EndpointEnvironment(const Json& values) {
    for (auto it = values.begin(); it != values.end(); ++it) {
      previous_.push_back({it.key(), PortEnvironment(it.key())});
#ifdef _WIN32
      const auto name = Wide(it.key()), value = Wide(it->get<std::string>());
      Require(SetEnvironmentVariableW(name.c_str(), value.c_str()) != 0, "cannot set fixture endpoint environment");
#else
      Require(setenv(it.key().c_str(), it->get<std::string>().c_str(), 1) == 0, "cannot set fixture endpoint environment");
#endif
      Require(PortEnvironment(it.key()) == it->get<std::string>(), "fixture endpoint environment did not roundtrip raw UTF-8");
    }
  }
  ~EndpointEnvironment() {
    for (const auto& entry : previous_) {
#ifdef _WIN32
      const auto name = Wide(entry.first);
      const auto value = entry.second ? Wide(*entry.second) : std::wstring();
      SetEnvironmentVariableW(name.c_str(), entry.second ? value.c_str() : nullptr);
#else
      if (entry.second) setenv(entry.first.c_str(), entry.second->c_str(), 1);
      else unsetenv(entry.first.c_str());
#endif
    }
  }
 private:
#ifdef _WIN32
  static std::wstring Wide(const std::string& text) {
    Require(text.find('\0') == std::string::npos && text.size() <= static_cast<size_t>(INT_MAX), "invalid fixture environment UTF-8");
    if (text.empty()) return {};
    const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    Require(length != 0, "invalid fixture environment UTF-8");
    std::wstring result(static_cast<size_t>(length), L'\0');
    Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length) == length,
        "cannot convert fixture environment UTF-8");
    return result;
  }
#endif
  std::vector<std::pair<std::string, std::optional<std::string>>> previous_;
};
Json& EndpointPath(Json& value, const std::string& path) {
  auto* current = &value;
  size_t offset = 0;
  while (offset < path.size()) {
    const auto end = path.find('.', offset);
    const auto key = path.substr(offset, end == std::string::npos ? path.size() - offset : end - offset);
    current = current->is_array() ? &(*current)[std::stoul(key)] : &(*current)[key];
    if (end == std::string::npos) break;
    offset = end + 1;
  }
  return *current;
}
Json& DnsAddressPath(Json& value, const Json& path) {
  auto* current = &value;
  for (const auto& component : path) {
    const auto key = component.get<std::string>();
    current = current->is_array() ? &current->at(std::stoul(key)) : &current->at(key);
  }
  return *current;
}
void TransportNoneCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/transport-none.json");
  Require(input.good(), "shared disabled transport strategy corpus required");
  Json corpus; input >> corpus;
  Require(corpus["profiles"].size() == 2 && corpus["equivalentValues"].size() == 5 && corpus["refusalValues"].size() == 3,
      "shared disabled transport strategy corpus changed");
  auto prepare = [](const Json& source, unsigned& calls) {
    return PrepareProtectedVpn(source.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      ++calls; return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  // Compare the complete prepared policy while allowing only this option's raw
  // spelling to differ, including copies on the private physical pin leaves.
  auto without_strategy = [](Json value) {
    std::function<void(Json&)> strip = [&](Json& stream) {
      if (stream.contains("sockopt") && stream["sockopt"].is_object()) stream["sockopt"].erase("addressPortStrategy");
      const auto network = EffectiveStreamNetwork(stream);
      if (network != "xhttp" && network != "splithttp") return;
      const auto* key = stream.contains("xhttpSettings") && !stream["xhttpSettings"].is_null() ? "xhttpSettings" : "splithttpSettings";
      if (!stream.contains(key) || !stream[key].is_object()) return;
      auto* settings = &stream[key];
      if (settings->contains("extra")) {
        if (!(*settings)["extra"].is_object()) return;
        settings = &(*settings)["extra"];
      }
      if (settings->contains("downloadSettings") && (*settings)["downloadSettings"].is_object()) strip((*settings)["downloadSettings"]);
    };
    for (auto& outbound : value["outbounds"])
      if (outbound.contains("streamSettings") && outbound["streamSettings"].is_object()) strip(outbound["streamSettings"]);
    return value;
  };
  bool selected = only.empty();
  for (const auto& profile : corpus["profiles"]) {
    auto baseline = profile["config"];
    for (const auto& path : profile["sockoptPaths"]) DnsAddressPath(baseline, path).erase("addressPortStrategy");
    unsigned baseline_calls = 0; const auto expected = prepare(baseline, baseline_calls);
    Require(expected.has_value() && baseline_calls == 1, "missing transport strategy baseline rejected or resolved a dormant endpoint");
    for (const auto* group : {"equivalentValues", "refusalValues"}) for (const auto& variant : corpus[group]) {
      const auto name = profile["name"].get<std::string>() + "/" + variant["name"].get<std::string>();
      if (!only.empty() && only != name) continue;
      selected = true;
      auto source = baseline;
      const bool primary_only = variant.value("applyTo", std::string()) == "primary";
      size_t index = 0;
      for (const auto& path : profile["sockoptPaths"]) {
        auto& options = DnsAddressPath(source, path);
        if ((!primary_only || index == 0) && variant["present"].get<bool>()) options["addressPortStrategy"] = variant["value"];
        else options.erase("addressPortStrategy");
        ++index;
      }
      const auto original = source.dump(); unsigned calls = 0;
      const auto result = prepare(source, calls);
      if (std::string(group) == "refusalValues") Require(!result, "active/invalid transport strategy was admitted");
      else {
        Require(result.has_value(), "Core-equivalent disabled transport strategy rejected");
        auto candidate = Parse(*result);
        Require(without_strategy(candidate) == without_strategy(Parse(*expected)) && calls == baseline_calls,
            "disabled transport strategy changed protected pins, metadata, or bootstrap lookup");
        for (const auto& path : profile["sockoptPaths"]) {
          const auto& options = DnsAddressPath(candidate, path);
          Require(options.contains("addressPortStrategy") == variant["present"].get<bool>(), "raw strategy presence changed");
          if (variant["present"].get<bool>()) Require(options["addressPortStrategy"] == variant["value"], "raw strategy value changed");
        }
      }
      Require(source.dump() == original, "transport strategy preparation mutated caller source");
    }
  }
  Require(selected, "unknown disabled transport strategy case");
}
void MappedDnsCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/dns-mapped-addresses.json");
  Require(input.good(), "shared mapped DNS Address corpus required");
  Json corpus; input >> corpus;
  Require(corpus["positiveCases"].size() == 3 && corpus["nativeRefusalControls"].size() == 2, "shared mapped DNS corpus changed");
  auto prepare = [](const Json& source, unsigned& calls) {
    return PrepareProtectedVpn(source.dump(), "session-user", "session-password", "Ethernet", [&](const std::string&) { ++calls; return ""; });
  };
  bool selected = only.empty();
  for (const auto* group : {"positiveCases", "nativeRefusalControls"}) for (const auto& fixture : corpus[group]) {
    const auto name = fixture["name"].get<std::string>();
    if (!only.empty() && only != name) continue;
    selected = true;
    const auto source = fixture["config"]; const auto original = source.dump(); unsigned calls = 0;
    const auto result = prepare(source, calls);
    if (std::string(group) == "nativeRefusalControls") Require(!result, "true/nonmapped IPv6 DNS was admitted");
    else {
      auto literal = source;
      for (const auto& binding : fixture["bindings"]) DnsAddressPath(literal, binding["path"]) = binding["value"];
      unsigned literal_calls = 0; const auto expected = prepare(literal, literal_calls);
      Require(expected.has_value(), "dotted IPv4 DNS control rejected");
      Require(result.has_value(), "Core-canonical mapped IPv4 DNS rejected");
      auto equivalent = Parse(*result);
      Require(equivalent["dns"] == source["dns"] && equivalent["remarks"] == source["remarks"] && equivalent["custom"] == source["custom"], "mapped DNS admission changed raw caller JSON");
      for (const auto& binding : fixture["bindings"]) DnsAddressPath(equivalent, binding["path"]) = binding["value"];
      Require(equivalent == Parse(*expected) && literal_calls == 0, "mapped DNS used a different policy or bootstrap than IPv4");
    }
    Require(calls == 0 && source.dump() == original, "mapped DNS attempted physical bootstrap or mutated source");
  }
  if (only.empty() || only == "family-boundary") {
    selected = true;
    auto source = corpus["positiveCases"][0]["config"];
    for (const auto* address : {"::ffff:192.0.2.1", "[ \t::ffff:c000:0201 ]", "0:0:0:0:0:FFFF:C000:201"}) {
      source["dns"]["servers"][0] = address; unsigned calls = 0;
      Require(prepare(source, calls).has_value() && calls == 0, "valid mapped IPv4 syntax did not canonicalize for DNS policy");
    }
    for (const auto* address : {"::ffff:192.000.2.1", "::ffff:192.0.2.1:1", "::ffff::192.0.2.1", "0:0:0:0:0:ffff:0:0:1", "::1", "64:ff9b::192.0.2.1", "::192.0.2.1"}) {
      source["dns"]["servers"][0] = address; unsigned calls = 0;
      Require(!prepare(source, calls) && calls == 0, "invalid/nonmapped IPv6 DNS crossed the IPv4 policy boundary");
    }
    source = corpus["positiveCases"][2]["config"];
    source["dns"]["hosts"]["full:resolver.invalid"] = Json::array({"[::ffff:127.0.0.1]", "2001:db8::53"}); unsigned calls = 0;
    Require(!prepare(source, calls) && calls == 0, "mixed actual-IPv6 caller DNS hosts were admitted");
  }
  if (only.empty() || only == "url-authority") {
    selected = true;
    auto source = corpus["positiveCases"][0]["config"];
    for (const auto* address : {"tcp://[::ffff:127.0.0.1]:5353", "https://[::ffff:0101:0101]/dns-query", "h2c://[0:0:0:0:0:FFFF:7f00:1]:8053/dns-query", "tcp://127.0.0.1:5353"}) {
      source["dns"]["servers"][0] = address; unsigned calls = 0; const auto result = prepare(source, calls);
      Require(result && calls == 0 && Parse(*result)["dns"] == source["dns"], "mapped IPv4 DNS URL authority was rejected or rewritten");
    }
    for (const auto* address : {"tcp://[2001:db8::53]:5353", "tcp://[::192.0.2.53]:5353", "tcp://[::ffff:127.0.0.1:5353", "tcp://[::ffff:127.0.0.1]]:53", "tcp://[::ffff:127.0.0.1]:", "tcp://[::ffff:127.0.0.1]:bad", "tcp://[::ffff:127.0.0.1]:0", "tcp://[::ffff:127.0.0.1]:65536", "tcp://[::ffff:127.0.0.1]:-1", "tcp://127.0.0.1:65536"}) {
      source["dns"]["servers"][0] = address; unsigned calls = 0;
      Require(!prepare(source, calls) && calls == 0, "invalid port/authority or actual IPv6 DNS URL admitted");
    }
  }
  Require(selected, "unknown mapped DNS case");
}
void LogicalAddressCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/logical-addresses.json");
  Require(input.good(), "shared logical Address corpus is required");
  Json fixtures; input >> fixtures; Require(fixtures.size() == 4, "shared logical Address corpus changed");
  auto prepare = [](const Json& profile, std::vector<std::string>& calls) {
    return PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host); return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  bool selected = only.empty();
  for (const auto& fixture : fixtures) {
    const auto name = fixture["name"].get<std::string>();
    if (!only.empty() && only != name) continue;
    selected = true;
    const auto source = fixture["config"]; const auto original = source.dump();
    EndpointEnvironment environment(fixture["environment"]);
    std::vector<std::string> calls; const auto result = prepare(source, calls);
    auto literal = source;
    for (const auto& binding : fixture["bindings"]) DnsAddressPath(literal, binding["path"]) = binding["value"];
    std::vector<std::string> literal_calls; const auto expected = prepare(literal, literal_calls);
    Require(expected.has_value(), "literal logical Address control rejected");
    Require(result && Parse(*result) == Parse(*expected), "logical env Address differs from literal candidate");
    Require(calls.empty() && literal_calls.empty(), "logical target was physically bootstrapped");
    Require(source.dump() == original, "logical Address preparation mutated caller source");
  }
  if (only.empty() || only == "precedence-and-scope") {
    selected = true;
    for (const auto& fixture : fixtures) {
      auto source = fixture["config"];
      const bool input_target = fixture["bindings"][0]["path"][0] == "inbounds";
      auto& settings = input_target ? source["inbounds"][0]["settings"] : source["outbounds"][1]["settings"];
      settings["address"] = "env:PRIMARY"; settings["rewriteAddress"] = "env:DORMANT";
      settings["custom"] = {{"address", "env:PRIMARY"}};
      settings["portMap"] = {{"80", "env:PRIMARY:80"}};
      std::vector<std::string> reads;
      Require(Normalize(source, [&](const std::string& name) -> std::optional<std::string> {
        reads.push_back(name); return name == "PRIMARY" ? "logical.invalid" : "env:SHOULD_NOT_EXPAND";
      }) && reads == std::vector<std::string>{"PRIMARY"} && settings["address"] == "logical.invalid"
          && settings["rewriteAddress"] == "env:DORMANT" && settings["custom"]["address"] == "env:PRIMARY"
          && settings["portMap"]["80"] == "env:PRIMARY:80", "logical target precedence expanded dormant/opaque settings");
      settings["address"] = ""; reads.clear();
      Require(Normalize(source, [&](const std::string& name) -> std::optional<std::string> { reads.push_back(name); return "unexpected.invalid"; })
          && reads.empty() && settings["address"] == "" && settings["rewriteAddress"] == "env:DORMANT", "empty nonnull logical primary fell back to rewriteAddress");
    }
    auto source = fixtures[1]["config"]; auto& settings = source["outbounds"][1]["settings"];
    settings.erase("address"); settings["RewriteAddress"] = settings["rewriteAddress"]; settings.erase("rewriteAddress");
    const auto original = source;
    Require(Normalize(source, [](const std::string&) -> std::optional<std::string> { return "127.0.0.2"; })
        && settings["RewriteAddress"] == "127.0.0.2" && !settings.contains("rewriteAddress")
        && source["dns"] == original["dns"], "absent logical primary or folded rewrite field was not bound in place");
  }
  if (only.empty() || only == "before-bootstrap") {
    selected = true;
    auto source = fixtures[0]["config"];
    source["inbounds"] = fixtures[2]["config"]["inbounds"];
    source["inbounds"][0]["settings"]["address"] = "env:FLUTTER_VLESS_FIXTURE_LOGICAL_SECOND";
    source["outbounds"].push_back({{"tag", "proxy"}, {"protocol", "vless"}, {"settings", {{"address", "endpoint.invalid"}, {"port", 443}}}});
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET", "127.0.0.1"}, {"FLUTTER_VLESS_FIXTURE_LOGICAL_SECOND", "127.0.0.2"}});
    std::vector<std::string> calls;
    const auto result = PrepareProtectedVpn(source.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host);
#ifdef _WIN32
      Require(_putenv_s("FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET", "unreachable.invalid") == 0
          && _putenv_s("FLUTTER_VLESS_FIXTURE_LOGICAL_SECOND", "unreachable.invalid") == 0, "cannot alter logical target environment");
#else
      Require(setenv("FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET", "unreachable.invalid", 1) == 0
          && setenv("FLUTTER_VLESS_FIXTURE_LOGICAL_SECOND", "unreachable.invalid", 1) == 0, "cannot alter logical target environment");
#endif
      return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
    source["outbounds"][1]["settings"]["address"] = "127.0.0.1";
    source["inbounds"][0]["settings"]["address"] = "127.0.0.2";
    std::vector<std::string> literal_calls; const auto expected = prepare(source, literal_calls);
    Require(result && expected && Parse(*result) == Parse(*expected) && calls == std::vector<std::string>{"endpoint.invalid"}, "logical targets were bound after physical bootstrap");
  }
  if (only.empty() || only == "invalid-and-once") {
    selected = true;
    for (const auto& invalid : {Json(true), Json(7), Json::array(), Json::object()}) {
      auto source = fixtures[1]["config"];
      source["outbounds"][1]["settings"]["address"] = invalid;
      std::vector<std::string> calls; Require(!prepare(source, calls), "invalid nonnull logical primary fell back to rewriteAddress");
    }
    auto source = fixtures[0]["config"]; source["outbounds"][1]["settings"]["ADDRESS"] = "127.0.0.2";
    Require(!Normalize(source), "ambiguous logical Address field was admitted");
    source = fixtures[0]["config"];
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET", "env:SECOND"}, {"SECOND", "127.0.0.1"}});
    const auto original = source.dump(); std::vector<std::string> calls;
    Require(!prepare(source, calls) && source.dump() == original, "nested logical env target was resolved twice or caller mutated");
    source["outbounds"][1]["settings"]["address"] = " env:FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET";
    const auto result = prepare(source, calls);
    Require(result && calls.empty() && Parse(*result)["outbounds"][1]["settings"]["address"] == " env:FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET", "logical env prefix was eagerly trimmed or physically resolved");
  }
  Require(selected, "unknown logical Address case");
}
void DnsAddressCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/dns-addresses.json");
  Require(input.good(), "shared root DNS Address corpus is required");
  Json fixtures; input >> fixtures; Require(fixtures.size() == 3, "shared root DNS Address corpus changed");
  auto prepare = [](const Json& profile, std::vector<std::string>& calls) {
    return PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host); return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  bool selected = only.empty();
  for (const auto& fixture : fixtures) {
    const auto name = fixture["name"].get<std::string>();
    if (!only.empty() && only != name) continue;
    selected = true;
    const auto source = fixture["config"]; const auto original = source.dump();
    EndpointEnvironment environment(fixture["environment"]);
    std::vector<std::string> calls;
    const auto result = prepare(source, calls);
    auto literal = source;
    for (const auto& binding : fixture["bindings"]) DnsAddressPath(literal, binding["path"]) = binding["value"];
    std::vector<std::string> literal_calls;
    const auto expected = prepare(literal, literal_calls);
    Require(expected.has_value(), "literal root DNS Address control rejected");
    Require(result && Parse(*result) == Parse(*expected), "root DNS env Address differs from the literal candidate");
    Require(calls.empty() && literal_calls.empty(), "root DNS Address reached physical bootstrap");
    Require(Parse(*result)["dns"] == literal["dns"], "caller DNS fields, host aliases or array order changed");
    Require(source.dump() == original, "root DNS Address preparation mutated caller source");
  }
  if (only.empty() || only == "before-bootstrap") {
    selected = true;
    auto profile = fixtures[1]["config"];
    profile["outbounds"].insert(profile["outbounds"].begin(), Json{{"tag", "proxy"}, {"protocol", "vless"},
        {"settings", {{"address", "endpoint.invalid"}, {"port", 443}}}});
    EndpointEnvironment environment(fixtures[1]["environment"]);
    std::vector<std::string> calls;
    const auto result = PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host);
#ifdef _WIN32
      Require(_putenv_s("FLUTTER_VLESS_FIXTURE_DNS_ROOT_ECS", "203.0.113.99") == 0
          && _putenv_s("FLUTTER_VLESS_FIXTURE_DNS_SERVER_ECS", "203.0.113.98") == 0, "cannot change DNS environment");
#else
      Require(setenv("FLUTTER_VLESS_FIXTURE_DNS_ROOT_ECS", "203.0.113.99", 1) == 0
          && setenv("FLUTTER_VLESS_FIXTURE_DNS_SERVER_ECS", "203.0.113.98", 1) == 0, "cannot change DNS environment");
#endif
      return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
    auto literal = profile;
    for (const auto& binding : fixtures[1]["bindings"]) DnsAddressPath(literal, binding["path"]) = binding["value"];
    std::vector<std::string> literal_calls; const auto expected = prepare(literal, literal_calls);
    Require(result && expected && Parse(*result) == Parse(*expected) && calls == std::vector<std::string>{"endpoint.invalid"},
        "root DNS env was not bound before physical bootstrap");
  }
  if (only.empty() || only == "schema-scope") {
    selected = true;
    auto source = fixtures[1]["config"];
    source["dns"] = {{"ClientIP", "env:root.ecs"}, {"SERVERS", Json::array({
        {{"Address", "env:server.address"}, {"CLIENTIP", "env:server.ecs"}, {"tag", "env:opaque"}}})},
        {"HOSTS", {{"full:Mixed.Key.invalid", Json::array({"127.0.0.7", "env:alias", "env:last", "second.invalid"})},
                   {"full:mixed.key.invalid", "127.0.0.9"}}}, {"opaque", {{"address", "env:opaque"}}}};
    auto literal = source;
    literal["dns"]["ClientIP"] = "198.51.100.1";
    literal["dns"]["SERVERS"][0]["Address"] = "tcp://127.0.0.1:5353";
    literal["dns"]["SERVERS"][0]["CLIENTIP"] = "203.0.113.1";
    literal["dns"]["HOSTS"]["full:Mixed.Key.invalid"][1] = "first.invalid";
    literal["dns"]["HOSTS"]["full:Mixed.Key.invalid"][2] = "127.0.0.8";
    const std::map<std::string, std::string> values{{"root.ecs", "198.51.100.1"}, {"server.address", "tcp://127.0.0.1:5353"},
        {"server.ecs", "203.0.113.1"}, {"alias", "first.invalid"}, {"last", "127.0.0.8"}};
    std::vector<std::string> reads;
    Require(Normalize(source, [&](const std::string& name) -> std::optional<std::string> {
      reads.push_back(name); const auto found = values.find(name); return found == values.end() ? std::nullopt : std::optional<std::string>{found->second};
    }) && Normalize(literal) && source == literal, "root DNS schema binding changed casing, aliases, order or opaque fields");
    Require(reads == std::vector<std::string>{"root.ecs", "server.address", "server.ecs", "alias", "last"}, "root DNS Address binding inspected a non-Address field");
    auto repeated = fixtures[1]["config"];
    repeated["dns"]["clientIp"] = "env:same"; repeated["dns"]["servers"][1]["clientIp"] = "env:same";
    unsigned count = 0;
    Require(Normalize(repeated, [&](const std::string&) -> std::optional<std::string> { return ++count == 1 ? "198.51.100.2" : "203.0.113.99"; })
        && count == 1 && repeated["dns"]["clientIp"] == "198.51.100.2" && repeated["dns"]["servers"][1]["clientIp"] == "198.51.100.2",
        "one preparation re-read a shared DNS Address environment variable");
  }
  if (only.empty() || only == "parsed-view") {
    selected = true;
    auto profile = fixtures[0]["config"];
    profile["dns"]["servers"] = Json::array({"env:FLUTTER_VLESS_FIXTURE_DNS_PARSED"});
    for (const auto& raw : {"[ tcp://127.0.0.1:5353 ]", "\xc2\xa0" "https://dns.example/dns-query\xe3\x80\x80"}) {
      EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_DNS_PARSED", raw}});
      profile["dns"]["hosts"] = {{"full:dns.example", Json::array({"[ 127.0.0.1 ]", "\xc2\xa0" "127.0.0.2\xe3\x80\x80"})}};
      std::vector<std::string> calls;
      const auto result = prepare(profile, calls);
      Require(result && calls.empty() && Parse(*result)["dns"]["servers"][0] == raw
          && Parse(*result)["dns"]["hosts"] == profile["dns"]["hosts"], "root DNS parsed Address view changed raw JSON or refused Core-equivalent numeric/static remote DNS");
    }
    for (const auto& raw : {"[ quic://127.0.0.1 ]", "[ https+local://127.0.0.1/dns-query ]", "[ tls://127.0.0.1 ]"}) {
      EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_DNS_PARSED", raw}});
      std::vector<std::string> calls;
      Require(!prepare(profile, calls), "parsed env DNS Address bypassed unsupported-client refusal");
    }
    profile["dns"]["servers"] = Json::array({"https://dns.example/dns-query"});
    profile["dns"]["hosts"] = {{"full:dns.example", Json::array({"127.0.0.1", "[ ::1 ]"})}};
    std::vector<std::string> calls;
    Require(!prepare(profile, calls), "parsed mixed IPv6 static DNS mapping was admitted");
  }
  if (only.empty() || only == "localhost-and-refusal") {
    selected = true;
    auto profile = fixtures[0]["config"];
    profile["outbounds"].insert(profile["outbounds"].begin(), Json{{"tag", "proxy"}, {"protocol", "vless"},
        {"settings", {{"address", "endpoint.invalid"}, {"port", 443}}}});
    profile["dns"]["servers"] = Json::array({{{"address", "env:FLUTTER_VLESS_FIXTURE_DNS_DEFAULT"}, {"tag", nullptr}, {"domains", Json::array({"full:chosen.invalid"})}}});
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_DNS_DEFAULT", "localhost"}});
    auto literal = profile; literal["dns"]["servers"][0]["address"] = "localhost";
    std::vector<std::string> calls, literal_calls;
    const auto result = prepare(profile, calls), expected = prepare(literal, literal_calls);
    Require(result && expected && Parse(*result) == Parse(*expected), "env localhost did not use the protected native DNS replacement");
    {
      EndpointEnvironment changed({{"FLUTTER_VLESS_FIXTURE_DNS_DEFAULT", "fakedns"}});
      calls.clear(); const auto fake = prepare(profile, calls);
      Require(fake && Parse(*fake)["dns"]["servers"][0]["address"] == "fakedns", "bound FakeDNS sentinel rejected or replaced");
    }
    for (const auto& unsafe : {"env:OTHER"}) {
      EndpointEnvironment changed({{"FLUTTER_VLESS_FIXTURE_DNS_DEFAULT", unsafe}});
      calls.clear(); Require(!prepare(profile, calls), "env default DNS bypassed unsupported/nested Address refusal");
    }
  }
  if (only.empty() || only == "empty-and-invalid") {
    selected = true;
    auto source = fixtures[2]["config"];
    source["dns"]["hosts"]["full:scalar.invalid"] = "env: exact.name ";
    std::vector<std::string> reads;
    Require(Normalize(source, [&](const std::string& name) -> std::optional<std::string> {
      reads.push_back(name); if (name == " exact.name ") return ""; return "127.0.0.99";
    }) && source["dns"]["hosts"]["full:scalar.invalid"] == "" && reads.front() == " exact.name "
        && std::find(reads.begin(), reads.end(), "EXACT_NAME") == reads.end(), "exact empty DNS Address did not win over alias lookup");
    for (const auto& location : {"root", "server", "hosts"}) {
      auto nested = fixtures[1]["config"];
      if (std::string(location) == "root") nested["dns"]["clientIp"] = "env:BAD";
      else if (std::string(location) == "server") nested["dns"]["servers"][0] = "env:BAD";
      else nested["dns"]["hosts"] = {{"full:alias.invalid", Json::array({"127.0.0.1", "env:BAD"})}};
      const auto original = nested.dump();
      EndpointEnvironment bad({{"BAD", "env:SECOND"}, {"SECOND", "127.0.0.1"}});
      std::vector<std::string> calls;
      Require(!prepare(nested, calls) && nested.dump() == original, "nested root DNS Address was re-decoded or source mutated");
    }
    for (const auto& duplicate : {"root-client", "root-servers", "root-hosts", "server-address", "server-client"}) {
      auto invalid = fixtures[1]["config"];
      if (std::string(duplicate) == "root-client") invalid["dns"]["CLIENTIP"] = "127.0.0.1";
      else if (std::string(duplicate) == "root-servers") invalid["dns"]["SERVERS"] = Json::array({"tcp://127.0.0.1"});
      else if (std::string(duplicate) == "root-hosts") { invalid["dns"]["hosts"] = Json::object(); invalid["dns"]["HOSTS"] = Json::object(); }
      else if (std::string(duplicate) == "server-address") invalid["dns"]["servers"][1]["ADDRESS"] = "tcp://127.0.0.1";
      else invalid["dns"]["servers"][1]["CLIENTIP"] = "127.0.0.1";
      Require(!Normalize(invalid), "duplicate inspected root DNS schema field was accepted");
    }
  }
  Require(selected, "unknown root DNS Address case");
}
void EndpointAddressCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/endpoint-addresses.json");
  Require(input.good(), "shared endpoint Address corpus is required");
  Json fixtures; input >> fixtures; Require(fixtures.size() == 3, "shared endpoint Address corpus changed");
  auto prepare = [](const Json& profile, std::vector<std::string>& calls) {
    return PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host); return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  bool selected = only.empty();
  for (const auto& fixture : fixtures) {
    const auto name = fixture["name"].get<std::string>();
    if (!only.empty() && only != name) continue;
    selected = true;
    const auto source = fixture["config"]; const auto original = source.dump();
    EndpointEnvironment environment(fixture["environment"]);
    std::vector<std::string> calls;
    const auto result = prepare(source, calls);
    Require(result.has_value(), "Core-valid typed endpoint env Address rejected");
    auto literal = source;
    for (auto it = fixture["resolvedAddresses"].begin(); it != fixture["resolvedAddresses"].end(); ++it) EndpointPath(literal, it.key()) = it.value();
    std::vector<std::string> literal_calls;
    const auto expected = prepare(literal, literal_calls);
    Require(expected && Parse(*result) == Parse(*expected), "endpoint env expansion differs from the exact literal candidate");
    Require(calls == std::vector<std::string>{"endpoint.invalid"} && calls == literal_calls, "physical bootstrap received raw env text or resolved a dormant field");
    Require(source.dump() == original, "endpoint env preparation mutated caller JSON");
  }
  if (only.empty() || only == "parse-view") {
    selected = true;
    auto profile = fixtures[0]["config"];
    for (const auto& address : {std::string("[ \tendpoint.invalid\n]"), std::string("\xc2\xa0" "endpoint.invalid\xe3\x80\x80")}) {
      EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_ENDPOINT", address}});
      std::vector<std::string> calls;
      const auto result = prepare(profile, calls);
      Require(result && Parse(*result)["outbounds"][0]["settings"]["address"] == address
          && calls == std::vector<std::string>{"endpoint.invalid"}, "endpoint raw Address was not frozen with a Core-parsed pin view");
    }
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_ENDPOINT", "[ 192.0.2.5 ]"}});
    std::vector<std::string> calls;
    const auto numeric = prepare(profile, calls);
    Require(numeric && calls.empty() && Parse(*numeric)["outbounds"][0]["settings"]["address"] == "[ 192.0.2.5 ]", "numeric expanded Address attempted OS bootstrap or changed raw text");
  }
  if (only.empty() || only == "caller-chain") {
    selected = true;
    auto profile = fixtures[2]["config"];
    profile["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = "front";
    profile["outbounds"][0]["settings"]["address"] = "env:FLUTTER_VLESS_FIXTURE_UPLOAD";
    profile["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["address"] = "env:FLUTTER_VLESS_FIXTURE_DOWNLOAD";
    profile["outbounds"].push_back({{"tag", "front"}, {"protocol", "socks"}, {"settings", {{"address", "env:FLUTTER_VLESS_FIXTURE_ENDPOINT"}, {"port", 10443}}}});
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_UPLOAD", "logical-upload.invalid"}, {"FLUTTER_VLESS_FIXTURE_DOWNLOAD", "logical-download.invalid"}, {"FLUTTER_VLESS_FIXTURE_ENDPOINT", "endpoint.invalid"}});
    std::vector<std::string> calls;
    const auto result = prepare(profile, calls);
    Require(result.has_value(), "chained env endpoint profile rejected"); const auto config = Parse(*result);
    Require(calls == std::vector<std::string>{"endpoint.invalid"} && config["outbounds"][0]["settings"]["address"] == "logical-upload.invalid"
        && config["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["address"] == "logical-download.invalid"
        && config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "front", "caller chain resolved logical targets or retained raw env tokens");
    for (const auto* role : {"freedom", "direct", "dns"}) {
      auto dynamic = profile;
      dynamic["outbounds"][0]["protocol"] = role;
      dynamic["outbounds"][0]["settings"] = Json::object();
      calls.clear();
      const auto dynamic_result = prepare(dynamic, calls);
      auto literal = dynamic;
      literal["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["address"] = "logical-download.invalid";
      literal["outbounds"].back()["settings"]["address"] = "endpoint.invalid";
      std::vector<std::string> literal_calls;
      const auto expected = prepare(literal, literal_calls);
      Require(dynamic_result && expected && Parse(*dynamic_result) == Parse(*expected)
          && calls == std::vector<std::string>{"endpoint.invalid"}, "dynamic chained outbound did not freeze its active download Address");
    }
  }
  if (only.empty() || only == "download-scope") {
    selected = true;
    for (const bool penetrate : {false, true}) {
      auto profile = fixtures[2]["config"];
      auto& stream = profile["outbounds"][0]["streamSettings"];
      stream["sockopt"]["penetrate"] = penetrate;
      auto& child = stream["xhttpSettings"]["extra"]["downloadSettings"];
      if (!penetrate) child["sockopt"] = Json::object();
      else child["xhttpSettings"]["downloadSettings"] = {{"address", "env:FLUTTER_VLESS_FIXTURE_DORMANT"}, {"port", 9443}};
      stream["xhttpSettings"]["downloadSettings"] = {{"address", "env:FLUTTER_VLESS_FIXTURE_DORMANT"}, {"port", 9443}};
      stream["splithttpSettings"]["downloadSettings"]["address"] = "env:FLUTTER_VLESS_FIXTURE_DORMANT";
      stream["tlsSettings"]["serverName"] = "env:FLUTTER_VLESS_FIXTURE_ENDPOINT";
      stream["xhttpSettings"]["host"] = "env:FLUTTER_VLESS_FIXTURE_ENDPOINT";
      EndpointEnvironment environment(fixtures[2]["environment"]);
      std::vector<std::string> calls;
      const auto result = prepare(profile, calls);
      auto literal = profile;
      for (auto it = fixtures[2]["resolvedAddresses"].begin(); it != fixtures[2]["resolvedAddresses"].end(); ++it) EndpointPath(literal, it.key()) = it.value();
      std::vector<std::string> literal_calls;
      const auto expected = prepare(literal, literal_calls);
      Require(result && expected && Parse(*result) == Parse(*expected) && calls == std::vector<std::string>{"endpoint.invalid"},
          "active download env was not frozen or inactive download/Host/SNI was expanded");
    }
  }
  if (only.empty() || only == "before-bootstrap") {
    selected = true;
    auto profile = fixtures[0]["config"];
    auto second = profile["outbounds"][0]; second["tag"] = "backup";
    second["settings"]["address"] = "env:FLUTTER_VLESS_FIXTURE_SECOND";
    profile["outbounds"].push_back(second);
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_ENDPOINT", "endpoint.invalid"}, {"FLUTTER_VLESS_FIXTURE_SECOND", "endpoint.invalid"}});
    std::vector<std::string> calls;
    const auto result = PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host);
#ifdef _WIN32
      Require(_putenv_s("FLUTTER_VLESS_FIXTURE_SECOND", "unreachable.invalid") == 0, "cannot alter fixture endpoint environment");
#else
      Require(setenv("FLUTTER_VLESS_FIXTURE_SECOND", "unreachable.invalid", 1) == 0, "cannot alter fixture endpoint environment");
#endif
      return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
    profile["outbounds"][0]["settings"]["address"] = "endpoint.invalid";
    profile["outbounds"].back()["settings"]["address"] = "endpoint.invalid";
    std::vector<std::string> literal_calls;
    const auto expected = prepare(profile, literal_calls);
    Require(result && expected && Parse(*result) == Parse(*expected) && calls == std::vector<std::string>{"endpoint.invalid"},
        "later endpoint env was read after a physical bootstrap callback");
  }
  if (only.empty() || only == "refused-expansion") {
    selected = true;
    for (const auto& value : {"env:FLUTTER_VLESS_FIXTURE_OTHER", "", " env:FLUTTER_VLESS_FIXTURE_OTHER"}) {
      EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_ENDPOINT", value}, {"FLUTTER_VLESS_FIXTURE_OTHER", "endpoint.invalid"}});
      auto profile = fixtures[0]["config"]; std::vector<std::string> calls;
      Require(!prepare(profile, calls), "nested/missing endpoint env was recursively expanded");
    }
    auto profile = fixtures[0]["config"];
    profile["outbounds"][0]["settings"]["address"] = " env:FLUTTER_VLESS_FIXTURE_ENDPOINT";
    EndpointEnvironment environment({{"FLUTTER_VLESS_FIXTURE_ENDPOINT", "endpoint.invalid"}});
    std::vector<std::string> calls;
    Require(!prepare(profile, calls), "endpoint env prefix was eagerly trimmed before expansion");
  }
  Require(selected, "unknown endpoint Address case");
}
void DirectOnlyCases(const std::string& only = "") {
  for (const auto* protocol : {"freedom", "direct"}) {
    if (!only.empty() && only != protocol) continue;
    Json source = {
        {"log", {{"loglevel", "none"}}},
        {"outbounds", Json::array({
            {{"protocol", protocol}, {"tag", "direct"}, {"settings", {{"domainStrategy", "AsIs"}}}},
            {{"protocol", "blackhole"}, {"tag", "blocked"}}})},
        {"dns", {{"tag", "caller-direct-dns"}, {"queryStrategy", "UseIPv4"},
            {"hosts", {{"direct-only.invalid", "127.0.0.1"}, {"blocked.invalid", "192.0.2.80"}}},
            {"servers", Json::array({"tcp://9.9.9.9"})}}},
        {"routing", {{"domainStrategy", "AsIs"}, {"rules", Json::array({
            {{"type", "field"}, {"domain", Json::array({"full:blocked.invalid"})}, {"outboundTag", "blocked"}}})}}}};
    const size_t direct_index = std::string(protocol) == "direct" ? 1 : 0;
    if (direct_index == 1) {
      std::swap(source["outbounds"][0], source["outbounds"][1]);
      source["outbounds"][0]["protocol"] = "block";
      source["dns"]["queryStrategy"] = "UseIP";
      source["routing"]["rules"] = Json::array({
          {{"type", "field"}, {"inboundTag", Json::array({"caller-direct-dns"})}, {"outboundTag", "direct"}},
          {{"type", "field"}, {"domain", Json::array({"full:direct-only.invalid"})}, {"outboundTag", "direct"}}});
    }
    size_t bootstrap_calls = 0;
    const auto output = PrepareProtectedVpn(source.dump(), "session-user", "session-password", "Ethernet",
        [&](const std::string&) { ++bootstrap_calls; return std::string(); });
    Require(output.has_value(), "valid direct-only profile rejected because it has no proxy endpoint");
    const auto config = Parse(*output);
    Require(bootstrap_calls == 0, "direct-only profile attempted physical endpoint bootstrap");
    Require(config["dns"] == source["dns"], "direct-only adaptation changed caller DNS policy or static hosts");
    const auto& direct = config["outbounds"][direct_index];
    Require(direct["protocol"] == protocol && direct["tag"] == "direct"
        && config["outbounds"][1 - direct_index] == source["outbounds"][1 - direct_index],
        "direct-only adaptation changed caller default handler/order/alias");
    Require(direct["settings"]["domainStrategy"] == "ForceIPv4"
        && direct["streamSettings"]["sockopt"]["domainStrategy"] == "ForceIPv4"
        && direct["streamSettings"]["sockopt"]["interface"] == "Ethernet"
        && !direct["streamSettings"]["sockopt"].contains("dialerProxy"), "direct-only physical dialer lost its protected IPv4 underlay binding");
    Require(config["inbounds"][0]["settings"]["auth"] == "password"
        && config["inbounds"][0]["settings"]["accounts"][0] == Json{{"user", "session-user"}, {"pass", "session-password"}},
        "direct-only adapter lost native session authentication");
    const auto& rules = config["routing"]["rules"];
    Require(rules.size() >= source["routing"]["rules"].size(), "direct-only adaptation lost caller routing rules");
    const auto offset = rules.size() - source["routing"]["rules"].size();
    for (size_t i = 0; i < source["routing"]["rules"].size(); ++i)
      Require(rules[offset + i] == source["routing"]["rules"][i], "direct-only adaptation changed caller routing order");
    Require(rules[0]["inboundTag"] == Json::array({config["inbounds"][0]["tag"]})
        && rules[0]["ip"] == Json::array({std::string(kVirtualDns) + "/32"})
        && rules[0]["port"] == "53" && rules[0]["network"] == "tcp,udp", "direct-only system DNS is not isolated to the native virtual destination");
    const auto relay_tag = rules[0]["outboundTag"];
    bool relay_found = false;
    for (const auto& outbound : config["outbounds"]) {
      if (outbound.value("tag", Json()) == relay_tag) {
        relay_found = outbound["protocol"] == "dns" && outbound["settings"]["rules"] == Json::array({
            {{"action", "hijack"}, {"qType", "1,28"}}, {{"action", "return"}, {"rCode", 5}}});
      }
      Require(outbound.value("protocol", "") != "socks" && outbound.value("protocol", "") != "vless",
          "direct-only adaptation synthesized an external proxy endpoint");
    }
    Require(relay_found, "direct-only system A/AAAA does not use the caller Core DNS client");
    for (int variant = 0; variant < 4; ++variant) {
      auto implicit = source;
      if (variant == 0) implicit.erase("dns");
      if (variant == 1) implicit["dns"] = Json::object();
      if (variant == 2) implicit["dns"]["servers"] = Json::array();
      if (variant == 3) implicit["dns"]["servers"] = Json::array({{{"address", "localhost"}, {"tag", "caller-local"}}});
      Require(!PrepareProtectedVpn(implicit.dump(), "session-user", "session-password", "Ethernet",
          [](const std::string&) { return std::string(); }), "direct-only native DNS replacement guessed an egress or emitted an empty tag");
    }
  }
  Require(only.empty() || only == "freedom" || only == "direct", "unknown direct-only test case");
}
void IPv6PayloadCases(const std::string& only = "") {
  const auto source = Parse(R"({"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"endpoint.invalid","port":443}]}},{"tag":"direct","protocol":"freedom"}],"dns":{"queryStrategy":"UseIP","hosts":{"payload.invalid":["198.51.100.7","2001:db8::7"]},"servers":["tcp://1.1.1.1"]},"routing":{"rules":[{"type":"field","ip":["2001:db8::/32"],"network":"tcp,udp","outboundTag":"proxy"}]}})");
  auto prepare = [](const Json& value) {
    return PrepareProtectedVpn(value.dump(), "session-user", "session-password", "Ethernet",
        [](const std::string& host) { return host == "endpoint.invalid" ? "192.0.2.5" : ""; });
  };
  std::map<std::string, std::function<void()>> cases;
  cases["captured-payload"] = [&] {
    const auto output = prepare(source); Require(output.has_value(), "IPv4 proxy with IPv6 payload profile rejected");
    const auto config = Parse(*output);
    Require(config["routing"]["rules"].back() == source["routing"]["rules"][0], "caller IPv6 TCP/UDP routing changed");
    for (const auto& rule : config["routing"]["rules"]) {
      Require(!(rule.value("inboundTag", Json::array()) == Json::array({kManagedInbound})
          && rule.value("ip", Json::array()) == Json::array({"::/0"})), "captured IPv6 payload is still blocked before caller routing");
    }
    // Enabling an inner IPv6 destination must not enable an outer physical
    // IPv6 socket, change the caller endpoint, or open the private pin scope.
    Require(config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"], "IPv6 payload changed the outer proxy endpoint");
    Require(config["outbounds"][1]["settings"]["domainStrategy"] == "ForceIPv4", "physical direct egress lost its IPv4-only boundary");
    bool closed_pin = false;
    for (const auto& rule : config["routing"]["rules"]) {
      if (rule.value("outboundTag", "") == kIpv6Block && rule.contains("inboundTag")
          && rule["inboundTag"] != Json::array({kManagedInbound}) && rule.size() == 3) closed_pin = true;
    }
    Require(closed_pin, "unmatched private transport bootstrap can fall through to caller routing");
  };
  cases["dns-aaaa"] = [&] {
    const auto output = prepare(source); Require(output.has_value(), "dual-family caller DNS profile rejected");
    const auto config = Parse(*output);
    Require(config["dns"] == source["dns"], "IPv6 adaptation rewrote caller DNS hosts/strategy/servers");
    const auto relay = std::find_if(config["outbounds"].begin(), config["outbounds"].end(),
        [](const Json& value) { return value.value("tag", "") == kDnsRelay; });
    Require(relay != config["outbounds"].end(), "IPv6 payload lost protected system DNS relay");
    Require((*relay)["settings"]["rules"] == Json::array({
        {{"action", "hijack"}, {"qType", "1,28"}}, {{"action", "return"}, {"rCode", 5}}}),
        "system AAAA must use caller Core DNS rather than unconditional NODATA or a raw relay");
    Require(!relay->contains("streamSettings") && !relay->contains("proxySettings"), "system IPv6 DNS bypassed the root client");
  };
  cases["caller-ipv4-policy"] = [&] {
    auto profile = source; profile["dns"]["queryStrategy"] = "UseIPv4";
    profile["dns"]["servers"][0] = {{"address", "tcp://1.1.1.1"}, {"queryStrategy", "UseIPv4"}, {"tag", "caller-dns"}};
    const auto output = prepare(profile); Require(output.has_value(), "caller IPv4-only DNS policy rejected");
    Require(Parse(*output)["dns"] == profile["dns"], "IPv6 payload adaptation widened caller IPv4 DNS policy");
  };
  if (!only.empty()) {
    const auto found = cases.find(only); Require(found != cases.end(), "unknown IPv6 test case"); found->second();
  } else for (const auto& item : cases) item.second();
}
void ProtocolCompatibilityCases(const std::string& only = "") {
  const auto source = Parse(R"({"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"endpoint.invalid","port":443}]}},{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"dns":{"queryStrategy":"UseIPv4","servers":["tcp://1.1.1.1"]},"routing":{"rules":[]}})");
  auto prepare = [](const Json& value) {
    return PrepareProtectedVpn(value.dump(), "session-user", "session-password", "Ethernet",
        [](const std::string& host) { return host == "endpoint.invalid" ? "192.0.2.5" : ""; });
  };
  auto tagged = [](const Json& config, const std::string& tag) -> const Json& {
    for (const auto& outbound : config["outbounds"]) if (outbound.value("tag", "") == tag) return outbound;
    throw std::runtime_error("protocol case references missing handler");
  };
  auto penetrating = [&] {
    auto profile = source;
    profile["outbounds"][0]["sendThrough"] = "192.0.2.25";
    profile["outbounds"][0]["streamSettings"] = {
        {"network", "xhttp"}, {"sockopt", {{"penetrate", true}, {"tcpKeepAliveIdle", 30}, {"mark", 7}}},
        {"security", "tls"}, {"tlsSettings", {{"serverName", "upload.invalid"}}},
        {"xhttpSettings", {{"host", "upload-http.invalid"}, {"path", "/upload"}, {"extra", {{"downloadSettings", {
            {"address", "endpoint.invalid"}, {"port", 8443}, {"network", "xhttp"},
            {"sockopt", {{"tcpKeepAliveIdle", 7}}}, {"security", "tls"},
            {"tlsSettings", {{"serverName", "download.invalid"}, {"masterKeyLog", "private-download.log"}}},
            {"xhttpSettings", {{"host", "download-http.invalid"}, {"path", "/download"}}}}}}}}}};
    return profile;
  };
  auto download = [](Json& profile) -> Json& { return profile["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]; };
  auto scoped_rules = [&](const Json& config) {
    const auto loop = config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"].get<std::string>();
    const auto scope = tagged(config, loop)["settings"]["inboundTag"];
    auto rules = Json::array();
    for (const auto& rule : config["routing"]["rules"])
      if (rule.value("inboundTag", Json::array()) == Json::array({scope})) rules.push_back(rule);
    return rules;
  };
  auto loop_count = [](const Json& config) { return std::count_if(config["outbounds"].begin(), config["outbounds"].end(),
      [](const Json& outbound) { return outbound.value("protocol", "") == "loopback"; }); };
  std::map<std::string, std::function<void()>> cases;
  cases["xhttp-download-effective-type"] = [&] {
    for (const bool penetrate : {false, true}) {
      for (const auto& fields : {Json{{"network", "tcp"}}, Json{{"network", "xhttp"}, {"method", "tcp"}},
          Json::object(), Json{{"network", "tcp"}, {"method", nullptr}}}) {
        auto profile = penetrating();
        profile["outbounds"][0]["streamSettings"]["sockopt"]["penetrate"] = penetrate;
        download(profile) = {{"address", "endpoint.invalid"}, {"port", 8443}};
        download(profile).update(fields);
        unsigned calls = 0;
        const auto result = PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet",
            [&](const std::string&) { ++calls; return "192.0.2.5"; });
        Require(!result && calls == 0, "non-XHTTP effective download reached endpoint bootstrap");
      }
      for (const auto& fields : {Json{{"network", "tcp"}, {"method", "xhttp"}},
          Json{{"network", "xhttp"}, {"method", nullptr}}, Json{{"network", "splithttp"}}}) {
        auto profile = penetrating();
        profile["outbounds"][0]["streamSettings"]["sockopt"]["penetrate"] = penetrate;
        download(profile) = {{"address", "endpoint.invalid"}, {"port", 8443}, {"xhttpSettings", Json::object()}};
        download(profile).update(fields);
        const auto result = prepare(profile);
        Require(result.has_value(), "valid method-aware XHTTP download rejected");
        auto effective = Parse(*result);
        for (auto field = fields.begin(); field != fields.end(); ++field)
          Require(download(effective)[field.key()] == field.value(), "caller child transport field changed");
      }
      for (const bool null_extra : {false, true}) {
        auto profile = penetrating(); auto& parent = profile["outbounds"][0]["streamSettings"];
        parent["sockopt"]["penetrate"] = penetrate;
        const Json dormant = {{"address", "unresolved.invalid"}, {"port", 8443}, {"network", "tcp"}};
        if (null_extra) parent["xhttpSettings"] = {{"extra", nullptr}, {"downloadSettings", dormant}};
        else { parent["xhttpSettings"] = Json::object(); parent["splithttpSettings"] = {{"downloadSettings", dormant}}; }
        const auto result = prepare(profile);
        Require(result.has_value(), "inactive non-XHTTP download constrained the active transport");
        const auto actual = Parse(*result)["outbounds"][0]["streamSettings"];
        Require(actual["xhttpSettings"] == parent["xhttpSettings"] && actual.value("splithttpSettings", Json()) == parent.value("splithttpSettings", Json()),
            "inactive download JSON changed");
      }
    }
  };
  cases["xhttp-download-inactive-grandchild"] = [&] {
    auto profile = penetrating();
    profile["outbounds"][0]["streamSettings"]["sockopt"]["penetrate"] = false;
    const Json dormant = {{"address", "127.0.0.1"}, {"port", 9443}, {"network", "tcp"}};
    download(profile)["xhttpSettings"]["downloadSettings"] = dormant;
    const auto output = prepare(profile);
    Require(output.has_value(), "immediate XHTTP client's inactive TCP download constrained bootstrap");
    auto actual = Parse(*output);
    Require(download(actual)["xhttpSettings"]["downloadSettings"] == dormant,
        "inactive grandchild JSON changed");
  };
  cases["xhttp-penetrate-union"] = [&] {
    auto profile = penetrating(); std::vector<std::string> calls;
    const auto output = PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      calls.push_back(host); return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
    Require(output.has_value(), "valid XHTTP penetrating download rejected");
    auto config = Parse(*output); const auto& parent = config["outbounds"][0]["streamSettings"];
    Require(calls == std::vector<std::string>{"endpoint.invalid"} && loop_count(config) == 1,
        "penetrating download did not share one resolved parent context");
    const auto rules = scoped_rules(config); Require(rules.size() == 3, "upload/download ports lost their separate exact pins");
    std::set<std::string> ports;
    for (size_t index = 0; index < 2; ++index) {
      const auto& rule = rules[index]; ports.insert(rule["port"].get<std::string>());
      Require(rule["domain"] == Json::array({"full:endpoint.invalid"}) && (!rule.contains("network") || rule["network"] == "tcp,udp"),
          "penetrating pin changed host identity or excluded HTTP/3 UDP");
      const auto& leaf = tagged(config, rule["outboundTag"].get<std::string>());
      const auto& options = leaf["streamSettings"]["sockopt"];
      Require(leaf["settings"]["redirect"] == "192.0.2.5:0" && leaf["sendThrough"] == "192.0.2.25"
          && options["tcpKeepAliveIdle"] == 30 && options["mark"] == 7 && options["interface"] == "Ethernet"
          && options["domainStrategy"] == "ForceIPv4" && !options.contains("dialerProxy"), "download leaf used child options or lost physical binding");
    }
    Require(ports == std::set<std::string>{"443", "8443"} && rules.back().size() == 3
        && rules.back()["outboundTag"] == kIpv6Block && !rules.back().contains("port"), "shared pin context is not closed after exact ports");
    Require(parent["sockopt"]["penetrate"] == true && parent["sockopt"]["domainStrategy"] == "AsIs"
        && parent["tlsSettings"]["serverName"] == "upload.invalid" && parent["xhttpSettings"]["host"] == "upload-http.invalid",
        "parent transport identity or pre-redirect DNS policy changed");
    const auto& child = download(config);
    Require(child["sockopt"] == download(profile)["sockopt"] && child["tlsSettings"]["serverName"] == "download.invalid"
        && child["tlsSettings"]["masterKeyLog"] == "" && child["xhttpSettings"] == download(profile)["xhttpSettings"]
        && config["dns"] == profile["dns"] && config["outbounds"][0]["settings"] == profile["outbounds"][0]["settings"],
        "penetrating adaptation changed ignored child sockopt, logical metadata, privacy or caller DNS");
  };
  cases["xhttp-penetrate-endpoint-sets"] = [&] {
    for (int variant = 0; variant < 5; ++variant) {
      auto profile = penetrating();
      if (variant == 0) download(profile)["port"] = 443;
      if (variant == 1) download(profile)["address"] = "download-endpoint.invalid";
      if (variant == 2) download(profile)["address"] = "203.0.113.8";
      if (variant >= 3) profile["outbounds"][0]["settings"]["servers"][0]["address"] = "192.0.2.5";
      if (variant == 4) download(profile)["address"] = "203.0.113.8";
      std::vector<std::string> calls;
      const auto output = PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
        calls.push_back(host); return host == "endpoint.invalid" ? "192.0.2.5" : host == "download-endpoint.invalid" ? "203.0.113.8" : "";
      });
      Require(output.has_value(), "valid penetrating endpoint union rejected"); auto config = Parse(*output);
      Require(calls.size() == (variant == 1 ? 2u : variant == 4 ? 0u : 1u), "endpoint cache resolved numeric addresses or repeated a same-host pin");
      if (variant == 4) Require(loop_count(config) == 0 && config["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"] == "ForceIPv4", "numeric endpoints unnecessarily gained a redirect");
      else {
        const auto rules = scoped_rules(config);
        Require(loop_count(config) == 1 && rules.size() == (variant == 0 ? 2u : 3u), "exact pair deduplication or union scope is wrong");
        bool child_pin = false;
        for (const auto& rule : rules) if (rule.value("port", "") == "8443") {
          const auto& target = download(profile)["address"];
          child_pin = target == "203.0.113.8" ? rule.value("ip", Json()) == Json::array({"203.0.113.8/32"})
              : rule.value("domain", Json()) == Json::array({"full:" + target.get<std::string>()});
        }
        Require(variant == 0 || child_pin, "download endpoint missing from the parent closed graph");
      }
    }
  };
  cases["xhttp-penetrate-ignored-child"] = [&] {
    auto profile = penetrating();
    download(profile)["sockopt"] = {{"dialerProxy", "dormant-download-handler"}, {"addressPortStrategy", "srv"},
        {"domainStrategy", "ForceIPv6"}, {"interface", "unused-interface"}, {"tcpKeepAliveIdle", 7}};
    auto output = prepare(profile); Require(output.has_value(), "overwritten child socket policy incorrectly constrained parent transport");
    auto config = Parse(*output); Require(download(config)["sockopt"] == download(profile)["sockopt"], "ignored child socket policy was rewritten");
    profile["outbounds"][0]["streamSettings"]["sockopt"]["penetrate"] = false;
    Require(!prepare(profile), "independent active child chain or address strategy stopped being checked");
  };
  cases["xhttp-penetrate-parent-chain"] = [&] {
    auto profile = penetrating();
    profile["outbounds"][0]["settings"]["servers"][0]["address"] = "logical-upload.invalid";
    profile["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = "front";
    download(profile)["address"] = "logical-download.invalid";
    download(profile)["sockopt"]["dialerProxy"] = "dormant-child";
    profile["outbounds"].push_back({{"tag", "front"}, {"protocol", "socks"}, {"settings", {{"servers", Json::array({{{"address", "endpoint.invalid"}, {"port", 10443}}})}}}});
    std::vector<std::string> calls;
    const auto output = PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) { calls.push_back(host); return host == "endpoint.invalid" ? "192.0.2.5" : ""; });
    Require(output.has_value() && calls == std::vector<std::string>{"endpoint.invalid"}, "caller chain bootstrapped upload/download logical targets");
    auto config = Parse(*output);
    Require(config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "front"
        && config["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"] == "AsIs"
        && download(config)["sockopt"] == download(profile)["sockopt"] && loop_count(config) == 1, "parent chain was not inherited by both targets");
    for (const auto* target : {"missing-front", "proxy"}) {
      auto invalid = profile; invalid["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = target;
      Require(!prepare(invalid), "missing/self parent transport chain admitted");
    }
    profile["outbounds"][3]["streamSettings"] = {{"sockopt", {{"dialerProxy", "proxy"}}}};
    Require(!prepare(profile), "cyclic parent transport chain admitted");
  };
  cases["xhttp-penetrate-boundaries"] = [&] {
    auto profile = penetrating(); download(profile)["address"] = "unresolved.invalid";
    Require(!prepare(profile), "unresolved penetrating download gained fallback resolution");
    profile = penetrating(); download(profile)["network"] = "tcp";
    Require(!prepare(profile), "non-XHTTP download reached Core's XHTTP config cast");
    profile = penetrating(); download(profile)["tlsSettings"]["echConfigList"] = "https://ech.invalid/config";
    Require(!prepare(profile), "active download ECH resolver escaped its endpoint pin scope");
    profile = penetrating(); profile["outbounds"][0] = {{"tag", "dynamic"}, {"protocol", "freedom"}, {"streamSettings", profile["outbounds"][0]["streamSettings"]}};
    Require(!prepare(profile), "dynamic upload gained a download-only closed graph");
    profile = penetrating(); profile["outbounds"][0]["streamSettings"]["sockopt"]["penetrate"] = false;
    const auto output = prepare(profile); Require(output.has_value(), "independent download regressed"); auto config = Parse(*output);
    Require(loop_count(config) == 2 && download(config)["sockopt"]["dialerProxy"] != config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "nonpenetrating socket policies were combined");
    const auto loop = tagged(config, download(config)["sockopt"]["dialerProxy"].get<std::string>());
    bool independent = false;
    for (const auto& rule : config["routing"]["rules"]) if (rule.value("inboundTag", Json::array()) == Json::array({loop["settings"]["inboundTag"]}) && rule.contains("port"))
      independent = tagged(config, rule["outboundTag"].get<std::string>())["streamSettings"]["sockopt"]["tcpKeepAliveIdle"] == 7;
    Require(independent, "nonpenetrating download lost its own socket options");
  };
  cases["localhost-tag-defaults"] = [&] {
    auto profile = source;
    profile["dns"] = {{"tag", "caller-root-dns"}, {"queryStrategy", "UseIPv4"}, {"hosts", {{"static.invalid", "192.0.2.14"}}},
        {"servers", Json::array({{{"address", "localhost"}, {"domains", Json::array({"full:private.invalid"})},
            {"queryStrategy", "UseIPv4"}, {"skipFallback", true}, {"timeoutMs", 900}, {"disableCache", true}}})}};
    nlohmann::json baseline;
    for (int variant = 0; variant < 3; ++variant) {
      auto candidate = profile;
      if (variant == 1) candidate["dns"]["servers"][0]["tag"] = nullptr;
      if (variant == 2) candidate["dns"]["servers"][0]["tag"] = "";
      const auto before = candidate.dump();
      const auto output = prepare(candidate);
      Require(output.has_value(), "Core-valid missing/null/empty localhost DNS tag rejected");
      const auto effective = nlohmann::json::parse(*output);
      auto expected_dns = candidate["dns"];
      expected_dns["servers"][0]["address"] = "tcp://1.1.1.1";
      expected_dns["servers"][0]["tag"] = kDnsUpstream;
      Require(effective["dns"] == nlohmann::json::parse(expected_dns.dump()), "localhost DNS adaptation changed other caller fields");
      if (variant == 0) baseline = effective;
      else Require(effective == baseline, "null/empty localhost DNS tag differs from the missing-tag baseline");
      Require(candidate.dump() == before, "localhost DNS tag adaptation mutated the caller document");
    }
  };
  cases["localhost-tag-invalid"] = [&] {
    for (const auto& value : {Json(false), Json(true), Json(0), Json(7), Json::array(), Json::object()}) {
      auto profile = source;
      profile["dns"]["servers"] = Json::array({{{"address", "localhost"}, {"tag", value}}});
      Require(!prepare(profile), "invalid non-null localhost DNS tag admitted");
    }
  };
  cases["dns-full-host-map"] = [&] {
    for (const auto* scheme : {"https", "h2c"}) for (const auto* key : {"full:dns.example", "full:DNS.EXAMPLE"}) {
      auto profile = source;
      profile["dns"]["hosts"] = {{key, Json::array({"203.0.113.53"})}};
      profile["dns"]["servers"] = Json::array({{{"address", std::string(scheme) + "://DNS.EXAMPLE./dns-query"}, {"tag", "caller-doh"}}});
      const auto output = prepare(profile);
      Require(output.has_value(), "Core full: IPv4 resolver hosts mapping rejected");
      Require(Parse(*output)["dns"] == profile["dns"], "full: resolver mapping, URL or caller tag changed");
    }
  };
  cases["dns-domain-unicode-case"] = [&] {
    for (const auto& mapping : {std::pair<std::string, std::string>{"\xE2\x84\xAA.EXAMPLE", "k.example"},
                               {"\xC4\xB0.EXAMPLE", "i.example"}}) {
      auto profile = source;
      profile["dns"]["hosts"] = {{mapping.first, "203.0.113.53"}};
      profile["dns"]["servers"] = Json::array({"https://" + mapping.second + "/dns-query"});
      const auto output = prepare(profile);
      Require(output.has_value() && Parse(*output)["dns"] == profile["dns"], "Core domain lowercase-to-ASCII mapping rejected or rewritten");
    }
  };
  cases["dns-long-s-not-case"] = [&] {
    for (const auto* key : {"dn\xC5\xBF.example", "full:dn\xC5\xBF.example"}) {
      auto profile = source;
      profile["dns"]["hosts"] = {{key, "203.0.113.53"}};
      profile["dns"]["servers"] = Json::array({"https://dns.example/dns-query"});
      Require(!prepare(profile), "schema long-S folding admitted a nonmatching Core DNS hosts key");
    }
  };
  cases["dns-full-host-negatives"] = [&] {
    for (const auto* key : {"FULL:dns.example", "Full:dns.example", "full:dns.example."}) {
      auto profile = source;
      profile["dns"]["hosts"] = {{key, "203.0.113.53"}};
      profile["dns"]["servers"] = Json::array({"https://dns.example/dns-query"});
      Require(!prepare(profile), "unrecognized full: prefix or nonmatching trailing-dot key admitted");
    }
    for (const auto& mapping : {Json("alias.invalid"), Json::array(), Json::array({"203.0.113.53", "2001:db8::53"})}) {
      auto profile = source;
      profile["dns"]["hosts"] = {{"full:dns.example", mapping}};
      profile["dns"]["servers"] = Json::array({"https://dns.example/dns-query"});
      Require(!prepare(profile), "unqualified full: resolver address/alias/family admitted");
    }
  };
  cases["null-direct-tag"] = [&] {
    auto profile = source;
    profile["outbounds"].erase(profile["outbounds"].begin());
    profile["outbounds"][0]["tag"] = nullptr;
    const auto output = prepare(profile);
    Require(output.has_value(), "Core-valid null tag on the default direct handler rejected");
    const auto config = Parse(*output);
    Require(config["outbounds"][0]["protocol"] == "freedom" && config["outbounds"][0]["tag"].is_null()
        && config["outbounds"][1] == profile["outbounds"][1] && config["dns"] == profile["dns"],
        "null direct tag, caller default/order or DNS changed");
  };
  cases["null-remote-tag"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["tag"] = nullptr;
    const auto output = prepare(profile);
    Require(output.has_value(), "Core-valid null remote tag was not treated like an absent tag");
    const auto config = Parse(*output);
    Require(config["outbounds"][0]["tag"] == "flutter-vless-proxy"
        && config["outbounds"][0]["protocol"] == profile["outbounds"][0]["protocol"]
        && config["outbounds"][0]["settings"] == profile["outbounds"][0]["settings"]
        && config["outbounds"][1]["tag"] == profile["outbounds"][1]["tag"]
        && profile["outbounds"][0]["tag"].is_null(), "null remote tag changed logical endpoint, source or handler order");
  };
  cases["invalid-outbound-tag"] = [&] {
    for (const auto& invalid : {Json(false), Json(true), Json(7), Json::array(), Json::object()}) {
      auto profile = source;
      profile["outbounds"][0]["tag"] = invalid;
      Require(!prepare(profile), "invalid non-null outbound tag admitted");
      profile["outbounds"].erase(profile["outbounds"].begin());
      profile["outbounds"][0]["tag"] = invalid;
      Require(!prepare(profile), "invalid non-null direct tag admitted");
    }
  };
  cases["loopback"] = [&] {
    auto profile = source;
    const Json loop = {{"tag", "caller-loop"}, {"protocol", "loopback"}, {"settings", {{"inboundTag", "caller-loop-context"},
        {"sniffing", {{"enabled", true}, {"destOverride", Json::array({"http"})}, {"routeOnly", true}}}}}};
    profile["outbounds"].insert(profile["outbounds"].begin(), loop);
    profile["routing"]["rules"].push_back({{"type", "field"}, {"inboundTag", Json::array({"caller-loop-context"})}, {"outboundTag", "proxy"}});
    auto output = prepare(profile); Require(output.has_value(), "valid caller loopback was rejected as an endpoint");
    auto config = Parse(*output);
    Require(config["outbounds"][0] == loop && config["outbounds"][1]["settings"] == source["outbounds"][0]["settings"], "dispatch-only caller loopback or endpoint order changed");
    Require(config["routing"]["rules"].back() == profile["routing"]["rules"].back(), "caller loopback routing lost");
    profile["outbounds"][0]["streamSettings"] = {{"sockopt", {{"dialerProxy", "unused-loopback-socket-handler"}}}};
    output = prepare(profile); Require(output.has_value(), "dispatch-only loopback inspected its unused socket chain");
    Require(Parse(*output)["outbounds"][0] == profile["outbounds"][0], "caller loopback dormant stream was rewritten");
  };
  cases["dns"] = [&] {
    auto profile = source;
    const Json settings = {{"rewriteNetwork", "tcp"}, {"rewriteAddress", "caller-resolver.invalid"}, {"rewritePort", 5353},
        {"rules", Json::array({{{"action", "direct"}}})}};
    profile["dns"]["hosts"] = {{"caller-resolver.invalid", "203.0.113.53"}};
    profile["outbounds"].push_back({{"tag", "caller-dns-adapter"}, {"protocol", "dns"}, {"settings", settings},
        {"streamSettings", {{"sockopt", {{"tcpKeepAliveIdle", 31}}}}}});
    auto output = prepare(profile); Require(output.has_value(), "valid caller DNS outbound was rejected as an endpoint");
    auto config = Parse(*output); const auto& dns = tagged(config, "caller-dns-adapter");
    Require(dns["settings"] == settings && config["dns"] == profile["dns"], "caller DNS outbound policy or root hosts changed");
    Require(dns["streamSettings"]["sockopt"] == Json{{"tcpKeepAliveIdle", 31}, {"domainStrategy", "ForceIPv4"}, {"interface", "Ethernet"}}, "DNS raw dial path lost its physical protection/options");
  };
  cases["masque"] = [&] {
    for (const auto& alpn : {"h2", "h3"}) {
      auto profile = source;
      const Json settings = {{"address", "endpoint.invalid"}, {"port", 443}, {"remoteDNS", Json::array({"1.1.1.1"})}};
      profile["outbounds"][0] = {{"tag", "proxy"}, {"protocol", "masque"}, {"settings", settings},
          {"streamSettings", {{"network", "masque"}, {"security", "tls"}, {"tlsSettings", {{"serverName", "masque-origin.invalid"}, {"alpn", Json::array({alpn})}}},
              {"masqueSettings", {{"path", "/masque"}, {"headers", {{"X-Test", "source-header"}}}}}}}};
      auto output = prepare(profile); Require(output.has_value(), "valid flat MASQUE endpoint was rejected");
      auto config = Parse(*output); const auto& remote = config["outbounds"][0];
      Require(remote["settings"] == settings && remote["streamSettings"]["tlsSettings"]["serverName"] == "masque-origin.invalid"
          && remote["streamSettings"]["tlsSettings"]["alpn"] == Json::array({alpn})
          && remote["streamSettings"]["masqueSettings"] == profile["outbounds"][0]["streamSettings"]["masqueSettings"], "MASQUE identity, logical endpoint or transport metadata changed");
      const auto& loop = tagged(config, remote["streamSettings"]["sockopt"]["dialerProxy"].get<std::string>());
      Require(loop["protocol"] == "loopback" && remote["streamSettings"]["sockopt"]["domainStrategy"] == "AsIs", "MASQUE physical endpoint escaped private bootstrap");
      const auto input = loop["settings"]["inboundTag"];
      bool bound = false;
      for (const auto& rule : config["routing"]["rules"]) if (rule.value("inboundTag", Json::array()) == Json::array({input}) && rule.value("port", "") == "443") {
        const auto& leaf = tagged(config, rule["outboundTag"].get<std::string>());
        bound = leaf["settings"]["redirect"] == "192.0.2.5:0" && leaf["streamSettings"]["sockopt"]["interface"] == "Ethernet";
      }
      Require(bound, "MASQUE pin did not preserve underlay binding");
    }
  };
  cases["aliases"] = [&] {
    auto profile = source;
    profile["outbounds"][1]["protocol"] = "direct";
    profile["outbounds"][2]["protocol"] = "block";
    auto output = prepare(profile); Require(output.has_value(), "registered Core direct/block aliases were rejected");
    auto config = Parse(*output);
    Require(config["outbounds"][1]["protocol"] == "direct" && config["outbounds"][2] == profile["outbounds"][2], "source alias protocol strings changed");
    Require(config["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet"
        && config["outbounds"][1]["settings"]["domainStrategy"] == "ForceIPv4", "direct alias bypassed physical protection");
  };
  cases["nullable-flat-address"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["protocol"] = "shadowsocks";
    auto& settings = profile["outbounds"][0]["settings"];
    settings = {{"address", nullptr}, {"servers", Json::array({{{"address", "endpoint.invalid"}, {"port", 443},
        {"method", "2022-blake3-aes-128-gcm"}, {"password", "AAAAAAAAAAAAAAAAAAAAAA=="}}})}};
    auto output = prepare(profile); Require(output.has_value(), "Core null flat address did not fall back to the legacy server");
    Require(Parse(*output)["outbounds"][0]["settings"] == settings, "null flat address adaptation changed source Shadowsocks settings");
    for (const auto& invalid : {Json(7), Json(true), Json::object(), Json("")}) {
      settings["address"] = invalid;
      Require(!prepare(profile), "invalid nonnull flat address fell back to a dormant legacy server");
    }
    settings["address"] = "endpoint.invalid"; settings["port"] = 8443;
    settings["method"] = "2022-blake3-aes-128-gcm"; settings["password"] = "AAAAAAAAAAAAAAAAAAAAAA==";
    settings["servers"][0]["address"] = "dormant.invalid";
    output = prepare(profile); Require(output.has_value(), "nonnull flat address lost precedence over a dormant legacy server");
    const auto config = Parse(*output);
    Require(config["outbounds"][0]["settings"] == settings, "nonnull flat priority changed source settings");
    bool flat_pin = false;
    for (const auto& rule : config["routing"]["rules"]) {
      Require(rule.value("port", "") != "443", "dormant legacy server received a transport pin");
      if (rule.value("port", "") == "8443") flat_pin = true;
    }
    Require(flat_pin, "effective nonnull flat endpoint did not receive its exact port pin");
  };
  cases["null-stream-fields"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["streamSettings"] = {{"method", nullptr}, {"network", "xhttp"}, {"sockopt", {{"dialerProxy", nullptr}}},
        {"xhttpSettings", {{"downloadSettings", {{"address", "endpoint.invalid"}, {"port", 8443}, {"network", "xhttp"}}}}}};
    auto output = prepare(profile); Require(output.has_value(), "Core nullable stream fields were rejected");
    auto config = Parse(*output);
    Require(config["outbounds"][0]["streamSettings"]["method"].is_null(), "source nullable method was rewritten");
    bool download = false;
    for (const auto& rule : config["routing"]["rules"]) if (rule.value("port", "") == "8443" && rule.contains("domain")) download = true;
    Require(download, "null method failed to fall back to effective XHTTP network");
    profile["outbounds"][0]["streamSettings"]["method"] = "raw";
    profile["outbounds"][0]["streamSettings"]["network"] = nullptr;
    profile["outbounds"][0]["streamSettings"]["xhttpSettings"]["downloadSettings"]["address"] = "unused.invalid";
    Require(prepare(profile).has_value(), "nonnull method did not override null network/dormant download");
  };
  cases["xhttp-null-extra"] = [&] {
    auto profile = source;
    profile["outbounds"][0]["streamSettings"] = {{"network", "xhttp"}, {"xhttpSettings", {{"extra", nullptr},
        {"downloadSettings", {{"address", "unused.invalid"}, {"port", 8443}, {"sockopt", {{"dialerProxy", "unused-handler"}}}}}}}};
    auto output = prepare(profile); Require(output.has_value(), "extra:null failed to suppress dormant outer download/chain");
    auto config = Parse(*output);
    Require(config["outbounds"][0]["streamSettings"]["xhttpSettings"] == profile["outbounds"][0]["streamSettings"]["xhttpSettings"], "dormant extra:null transport data changed");
    for (const auto& rule : config["routing"]["rules"]) Require(rule.value("port", "") != "8443", "ignored extra:null outer download received physical pins");
  };
  if (!only.empty()) {
    const auto found = cases.find(only); Require(found != cases.end(), "unknown protocol test case"); found->second();
  } else for (const auto& item : cases) item.second();
}
void FakeDnsCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/fakedns.json");
  Require(input.good(), "shared FakeDNS corpus required");
  Json corpus; input >> corpus;
  Require(corpus.size() == 5, "shared FakeDNS case count changed");
  bool selected = only.empty();
  auto prepare = [](const Json& source, unsigned& calls) {
    return PrepareProtectedVpn(source.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      ++calls; return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  for (const auto& fixture : corpus) {
    const auto name = fixture["name"].get<std::string>();
    if (!only.empty() && only != name) continue;
    selected = true;
    const auto source = fixture["config"], original = source;
    unsigned calls = 0;
    const auto result = prepare(source, calls);
    Require(result.has_value(), "valid FakeDNS profile rejected by native preparation");
    const auto effective = Parse(*result);
    Require(calls == 1 && source == original, "FakeDNS queried an extra physical name or mutated source");
    Require(effective["dns"] == source["dns"] && effective["policy"] == source["policy"], "caller DNS or policy changed");
    for (auto it = source.begin(); it != source.end(); ++it) if (Fold(it.key()) == "fakedns") {
      bool found = false;
      for (auto actual = effective.begin(); actual != effective.end(); ++actual) if (Fold(actual.key()) == "fakedns") {
        Require(*actual == *it, "caller FakeDNS engine/pools changed"); found = true;
      }
      Require(found, "caller FakeDNS root dropped");
    }
    Require(effective["inbounds"][1] == source["inbounds"][0], "caller listener/sniffing changed");
    const auto& sniffing = effective["inbounds"][0]["sniffing"];
    Require(sniffing["enabled"] == true && sniffing["routeOnly"] == true
        && sniffing["destOverride"] == Json::array({"http", "tls", "quic", "fakedns"}), "private FakeDNS restoration missing");
    Require(std::string(kVirtualDns) == "10.0.85.53", "virtual DNS still overlaps Core's default FakeDNS pool");
  }
  if (only.empty() || only == "refusals") {
    selected = true;
    for (const auto& pool : {
        Json{{"ipPool", "10.0.85.0/24"}, {"poolSize", 128}},
        Json{{"ipPool", "26.26.26.0/30"}, {"poolSize", 2}},
        Json{{"ipPool", "fd26:26:26::/126"}, {"poolSize", 2}},
        Json{{"ipPool", "fd00:198:18::/64"}, {"poolSize", 1024}},
        Json{{"ipPool", "::ffff:10.0.85.0/120"}, {"poolSize", 128}},
        Json{{"ipPool", "::ffff:0:0/80"}, {"poolSize", 1024}},
        Json{{"ipPool", "0.0.0.0/0"}, {"poolSize", 1024}},
        Json{{"ipPool", "::/0"}, {"poolSize", 1024}},
        Json{{"ipPool", "invalid/16"}, {"poolSize", 1024}},
        Json{{"ipPool", "198.19.0.0/16"}, {"poolSize", 0}},
        Json{{"ipPool", "198.19.0.0/24"}, {"poolSize", 256}},
        Json{{"ipPool", "198.19.0.0/16"}, {"poolSize", 1024.0}},
        Json{{"ipPool", "198.19.0.0/16"}, {"poolSize", true}},
        Json{{"ipPool", "198.19.0.0/16"}, {"poolSize", "1024"}}}) {
      auto source = corpus[0]["config"]; source["fakedns"] = pool;
      const auto original = source; unsigned calls = 0;
      Require(!prepare(source, calls) && calls == 0 && source == original,
          "unsafe/malformed FakeDNS pool admitted or bootstrapped before refusal");
    }
    auto duplicate = corpus[0]["config"];
    duplicate["fakedns"] = Json{{"ipPool", "198.19.0.0/16"}, {"IPPOOL", "10.0.85.0/24"}, {"poolSize", 1024}};
    unsigned calls = 0; Require(!prepare(duplicate, calls) && calls == 0, "ambiguous FakeDNS pool admitted");
  }
  Require(selected, "unknown FakeDNS case");
}

void DnsDataMapCases(const std::string& only = "") {
  std::ifstream input("tool/fixtures/compatibility/dns-data-maps.json");
  Require(input.good(), "shared DNS data/map corpus required");
  Json corpus; input >> corpus;
  Require(corpus.is_array() && corpus.size() == 5, "shared DNS data/map corpus changed");
  auto prepare = [](const Json& profile, unsigned& calls) {
    return PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string&) {
      ++calls; return std::string();
    });
  };
  bool selected = only.empty();
  for (const auto& fixture : corpus) {
    if (!only.empty() && fixture["name"] != only) continue;
    selected = true;
    const auto source = fixture["config"], original = source;
    const Json* source_dns = nullptr;
    for (auto it = source.begin(); it != source.end(); ++it) if (Fold(it.key()) == "dns") source_dns = &it.value();
    Require(source_dns != nullptr, "shared DNS data/map profile has no DNS object");
    unsigned calls = 0;
    const auto prepared = prepare(source, calls);
    Require(prepared.has_value(), "valid DNS data/map profile rejected");
    Require(Parse(*prepared)["dns"] == *source_dns, "caller DNS keys, URL data or policy changed");
    Require(calls == 0 && source == original, "numeric DNS data/map profile resolved or mutated source");
  }
  if (only.empty() || only == "refusals") {
    selected = true;
    for (const auto* address : {"https+local://192.0.2.53/dns-query", "h2c+local://192.0.2.53/dns-query",
                               "tcp+local://192.0.2.53", "quic+local://192.0.2.53"}) {
      auto source = corpus[0]["config"];
      source["dns"]["servers"] = Json::array({address});
      const auto original = source;
      unsigned calls = 0;
      Require(!prepare(source, calls) && calls == 0 && source == original, "actual local DNS scheme admitted or mutated source");
    }
  }
  Require(selected, "unknown DNS data/map case");
}

void OpaqueFieldCases() {
  std::ifstream input("tool/fixtures/compatibility/opaque-fields.json");
  Require(input.good(), "shared opaque-field corpus required");
  Json corpus; input >> corpus;
  Require(corpus.is_array() && corpus.size() == 6, "shared opaque-field corpus changed");
  auto prepare = [](const Json& profile, unsigned& calls) {
    return PrepareProtectedVpn(profile.dump(), "session-user", "session-password", "Ethernet", [&](const std::string&) {
      ++calls; return std::string();
    });
  };
  size_t paths = 0;
  for (const auto& fixture : corpus) {
    const auto source = fixture["config"], original = source;
    unsigned calls = 0;
    const auto prepared = prepare(source, calls);
    Require(prepared.has_value(), "opaque metadata was treated as an active feature");
    auto caller_view = Parse(*prepared);
    Require(caller_view["inbounds"].size() == source["inbounds"].size() + 1, "managed inbound insertion changed");
    caller_view["inbounds"].erase(caller_view["inbounds"].begin());
    // Private rules are prepended; compare each imported rule at its retained
    // caller position without confusing it with a generated guard.
    if (source.contains("routing") && source["routing"].contains("rules")) {
      auto& rules = caller_view["routing"]["rules"];
      const auto count = source["routing"]["rules"].size();
      Require(rules.size() >= count, "imported routing rules were lost");
      rules.erase(rules.begin(), rules.end() - static_cast<Json::difference_type>(count));
    }
    auto expected = source;
    for (const auto& path : fixture["opaquePaths"]) {
      Require(DnsAddressPath(caller_view, path) == DnsAddressPath(expected, path), "opaque subtree was normalized, rebound or removed");
      ++paths;
    }
    Require(calls == 0 && source == original, "numeric opaque-field profile resolved or mutated source");
  }
  Require(paths == 18, "shared opaque-field path coverage changed");
  auto source = corpus[0]["config"];
  source["outbounds"][0]["streamSettings"]["security"] = "tls";
  source["outbounds"][0]["streamSettings"]["tlsSettings"] = {{"masterKeyLog", "private-key.log"}, {"serverName", "tls.invalid"}};
  const auto original = source;
  unsigned calls = 0;
  const auto prepared = prepare(source, calls);
  Require(prepared.has_value(), "real TLS privacy control rejected");
  const auto output = Parse(*prepared);
  Require(output["outbounds"][0]["streamSettings"]["tlsSettings"]["masterKeyLog"] == ""
      && output["log"]["access"] == "none" && output["custom"] == source["custom"], "opaque preservation bypassed real privacy edits");
  Require(source == original && calls == 0, "TLS privacy control mutated or resolved source");
  source["dns"]["servers"] = Json::array({"quic+local://9.9.9.9"});
  const auto unsafe = source;
  Require(!prepare(source, calls) && calls == 0 && source == unsafe, "actual local QUIC DNS was admitted or mutated source");
}

int main(int argc, char** argv) try {
  if (argc == 2 && std::string(argv[1]) == "--opaque-fields") { OpaqueFieldCases(); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--dns-data-maps-case") { DnsDataMapCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--fakedns-case") { FakeDnsCases(argv[2]); return 0; }
  if (argc == 5 && std::string(argv[1]) == "--bind-certificate-fixture") {
    std::ifstream input(argv[2], std::ios::binary);
    if (!input.good()) return 4;
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (!BindCertificatePaths(text, std::filesystem::u8path(argv[4]))) return 3;
    std::ofstream output(argv[3], std::ios::binary); output << text;
    return output.good() ? 0 : 4;
  }
  if (argc == 4 && std::string(argv[1]) == "--allocate-service-tags-fixture") {
    std::ifstream file(argv[2], std::ios::binary);
    if (!file.good()) return 2;
    const auto input = Parse(std::string{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()});
    if (!input.is_object() || !input.contains("config") || !input.contains("requests") || !input["requests"].is_array()) return 3;
    ServiceTags allocator(input["config"]);
    auto tags = Json::array();
    for (const auto& request : input["requests"]) {
      if (!request.is_string()) return 3;
      tags.push_back(allocator.Next(request.get<std::string>()));
    }
    std::ofstream output(argv[3], std::ios::binary); output << tags.dump();
    return output.good() ? 0 : 4;
  }
  if (argc == 3 && std::string(argv[1]) == "--direct-only-case") { DirectOnlyCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--ipv6-case") { IPv6PayloadCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--protocol-case") { ProtocolCompatibilityCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--transport-none-case") { TransportNoneCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--mapped-dns-case") { MappedDnsCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--logical-address-case") { LogicalAddressCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--dns-address-case") { DnsAddressCases(argv[2]); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--endpoint-address-case") { EndpointAddressCases(argv[2]); return 0; }
  if (argc != 1) {
    if (argc != 7 || std::string(argv[1]) != "--prepare-dns-fixture") return 2;
    std::ifstream input(argv[2]);
    if (!input.good()) return 2;
    const std::string source{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    auto result = PrepareProtectedVpn(source, "session-user", "session-password", argv[4], [&](const std::string& host) {
      return host == argv[5] ? std::string(argv[6]) : std::string();
    });
    if (!result) return 3;
    std::ofstream output(argv[3], std::ios::binary);
    output << *result;
    return output.good() ? 0 : 4;
  }
  IPv6PayloadCases();
  DirectOnlyCases();
  ProtocolCompatibilityCases();
  EndpointAddressCases();
  DnsAddressCases();
  DnsDataMapCases();
  OpaqueFieldCases();
  FakeDnsCases();
  LogicalAddressCases();
  MappedDnsCases();
  TransportNoneCases();
  const auto source = Parse(R"({
    "log":{"access":"private-canary.log","error":"secret.log","loglevel":"debug","dnsLog":true},
    "inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":18580,"tag":"socks-in","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":false}}],
    "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"endpoint.invalid","port":443,"users":[{"id":"private-remote-credential","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"remote-public-key","serverName":"sni.invalid","show":true},"tlsSettings":{"masterKeyLog":"tls-canary.log"}}},{"tag":"direct","protocol":"freedom"}],
    "routing":{"rules":[{"type":"field","domain":["domain:ru","domain:io"],"outboundTag":"direct"},{"type":"field","domain":["domain:myip.com"],"outboundTag":"proxy"}]},
    "dns":{"hosts":{"endpoint.invalid":"203.0.113.99","dns.example":["203.0.113.53"],"domain:static.invalid":["203.0.113.10","203.0.113.11"]},"servers":[{"address":"tcp://9.9.9.9","domains":["domain:internal.invalid"],"queryStrategy":"UseIPv4","tag":"caller-dns-tcp","skipFallback":true},{"address":"https://dns.example/dns-query","domains":["domain:external.invalid"],"tag":"caller-dns-doh"}],"tag":"caller-dns","queryStrategy":"UseIPv4","disableCache":true,"disableFallbackIfMatch":true}
  })");
  unsigned lookups = 0;
  auto prepare = [&](const Json& json) {
    return PrepareProtectedVpn(json.dump(), "session-user", "session-password", "Ethernet", [&](const std::string& host) {
      ++lookups; return host == "endpoint.invalid" ? "192.0.2.5" : "";
    });
  };
  auto result = prepare(source); Require(result.has_value(), "valid Reality profile rejected");
  auto config = Parse(*result);
  Require(lookups == 1, "bootstrap queried something other than endpoint");
  Require(config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"], "bootstrap changed the logical endpoint or credentials");
  Require(config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] == "sni.invalid", "SNI changed");
  Require(config["log"]["access"] == "none" && config["log"]["error"] == "none" && config["log"]["dnsLog"] == false, "file log escape");
  Require(config["outbounds"][0]["streamSettings"]["realitySettings"]["show"] == false, "Reality debug escape");
  Require(config["outbounds"][0]["streamSettings"]["tlsSettings"]["masterKeyLog"] == "", "TLS key log escape");
  Require(config["dns"] == source["dns"], "caller DNS hosts/servers/domain policy/tags were replaced or polluted by physical bootstrap");
  Require(config["inbounds"][0]["settings"]["auth"] == "password", "unauthenticated VPN listener");
  Require(config["inbounds"][0]["sniffing"]["routeOnly"] == true, "IPv6 sniffing replaces target");
  auto rules = config["routing"]["rules"];
  Require(rules[0]["inboundTag"] == Json::array({kManagedInbound}) && rules[0]["ip"] == Json::array({std::string(kVirtualDns) + "/32"})
      && rules[0]["port"] == "53" && rules[0]["network"] == "tcp,udp" && rules[0]["outboundTag"] == kDnsRelay,
      "system DNS adapter is not scoped to the private input and exact virtual DNS destination");
  const auto relay = std::find_if(config["outbounds"].begin(), config["outbounds"].end(),
      [](const Json& outbound) { return outbound.value("tag", "") == kDnsRelay; });
  Require(relay != config["outbounds"].end(), "missing DNS relay");
  Require(!relay->contains("proxySettings"), "removed proxySettings emitted");
  Require(!relay->contains("streamSettings"), "root DNS adapter must not create a raw relay transport");
  Require((*relay)["settings"]["rules"] == Json::array({
      {{"action", "hijack"}, {"qType", "1,28"}},
      {{"action", "return"}, {"rCode", 5}}}),
      "system A/AAAA must use caller Core DNS and unsupported records must be explicitly refused");
  Require(rules[rules.size()-2] == source["routing"]["rules"][0] && rules.back() == source["routing"]["rules"][1], "domain bypass rules reordered or removed");
  Require(config["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "direct sockets reenter capture");
  const auto& stream = config["outbounds"][0]["streamSettings"];
  Require(stream["sockopt"]["domainStrategy"] == "AsIs", "transport bootstrap first recurses through caller DNS");
  auto find_outbound = [](const Json& value, const std::string& tag) -> const Json& {
    for (const auto& item : value["outbounds"]) if (item.value("tag", "") == tag) return item;
    throw std::runtime_error("referenced bootstrap outbound missing");
  };
  const auto& loopback = find_outbound(config, stream["sockopt"]["dialerProxy"].get<std::string>());
  Require(loopback["protocol"] == "loopback", "bootstrap is not isolated through Core dispatcher");
  const auto pin_input = loopback["settings"]["inboundTag"].get<std::string>();
  Require(pin_input != "caller-dns" && pin_input != "caller-dns-tcp" && pin_input != "caller-dns-doh", "bootstrap inherited DNS client identity");
  Require(rules[1]["inboundTag"] == Json::array({pin_input}) && rules[1]["domain"] == Json::array({"full:endpoint.invalid"})
      && rules[1]["port"] == "443", "physical pin must require exact private context, hostname and port");
  const auto& pin_egress = find_outbound(config, rules[1]["outboundTag"].get<std::string>());
  Require(pin_egress["protocol"] == "freedom" && pin_egress["settings"]["redirect"] == "192.0.2.5:0"
      && pin_egress["streamSettings"]["sockopt"]["interface"] == "Ethernet", "pin lost numeric destination, original port or underlay binding");
  Require(rules[2]["inboundTag"] == Json::array({pin_input}) && rules[2]["outboundTag"] == kIpv6Block
      && rules[2].size() == 3, "unmatched bootstrap context can fall through to caller routing");
  auto physical_options = source;
  physical_options["outbounds"][0]["sendThrough"] = "192.0.2.25";
  physical_options["outbounds"][0]["streamSettings"]["sockopt"] = {{"tcpFastOpen", true}, {"tcpKeepAliveIdle", 30}, {"mark", 7}};
  auto options_prepared = prepare(physical_options); Require(options_prepared.has_value(), "physical socket option profile rejected");
  auto options_config = Parse(*options_prepared);
  const auto& options_leaf = find_outbound(options_config, options_config["routing"]["rules"][1]["outboundTag"].get<std::string>());
  Require(options_leaf["sendThrough"] == "192.0.2.25" && options_leaf["streamSettings"]["sockopt"] == Json{{"tcpFastOpen", true},
      {"tcpKeepAliveIdle", 30}, {"mark", 7}, {"domainStrategy", "ForceIPv4"}, {"interface", "Ethernet"}}, "private leaf discarded caller physical socket options/gateway");

  for (int empty_kind = 0; empty_kind < 4; ++empty_kind) {
    auto profile = source;
    if (empty_kind == 0) profile.erase("dns");
    if (empty_kind == 1) profile["dns"] = nullptr;
    if (empty_kind == 2) profile["dns"] = Json::object();
    if (empty_kind == 3) profile["dns"] = {{"hosts", {{"local.invalid", "203.0.113.11"}}}, {"queryStrategy", "UseIPv4"}, {"servers", Json::array()}};
    auto prepared = prepare(profile); Require(prepared.has_value(), "native missing/empty DNS policy rejected");
    const auto effective = Parse(*prepared);
    const auto& server = effective["dns"]["servers"][0];
    Require(server["address"] == "tcp://1.1.1.1" && server["tag"] == kDnsUpstream, "missing DNS can use captured OS resolver");
    Require(effective["routing"]["rules"][1] == Json{{"type", "field"}, {"inboundTag", Json::array({kDnsUpstream})},
        {"ip", Json::array({"1.1.1.1/32"})}, {"port", "53"}, {"network", "tcp"}, {"outboundTag", "proxy"}}, "native default DNS is not scoped and proxied");
    if (empty_kind == 3) Require(effective["dns"]["hosts"] == profile["dns"]["hosts"] && effective["dns"]["queryStrategy"] == "UseIPv4", "empty DNS policy discarded caller hosts/strategy");
  }
  auto local = source;
  local["dns"]["servers"].insert(local["dns"]["servers"].begin(), Json{{"Address", "localhost"}, {"Tag", "caller-local"},
      {"domains", Json::array({"domain:private.invalid"})}, {"queryStrategy", "UseIPv4"}, {"skipFallback", true}, {"timeoutMs", 1200}});
  auto local_prepared = prepare(local); Require(local_prepared.has_value(), "explicit localhost native default rejected");
  auto expected_local = local["dns"]; expected_local["servers"][0]["Address"] = "tcp://1.1.1.1";
  Require(Parse(*local_prepared)["dns"] == expected_local, "localhost adaptation discarded source entry policy/tag");
  Require(Parse(*local_prepared)["routing"]["rules"][1]["inboundTag"] == Json::array({"caller-local"}), "localhost native policy lost its effective client tag");
  local["dns"]["servers"][0]["Tag"] = "";
  auto empty_tag = prepare(local); Require(empty_tag.has_value() && !Parse(*empty_tag)["dns"]["servers"][0].contains("tag"), "native DNS added a duplicate folded tag alias");
  for (const auto& address : {"tcp+local://1.1.1.1", "https+local://dns.example/dns-query", "quic+local://1.1.1.1", "tls://1.1.1.1", "tcp://[2001:db8::1]", "unknown://1.1.1.1"}) {
    auto unsupported = source; unsupported["dns"]["servers"] = Json::array({address});
    Require(!prepare(unsupported), "unsupported local/DoT/QUIC/IPv6 path silently admitted");
  }
  for (const auto& strategy : {"UseSystem", "use_sys", "use-system"}) {
    auto unsupported = source; unsupported["dns"]["queryStrategy"] = strategy;
    Require(!prepare(unsupported), "unqualified system-family root strategy admitted");
    unsupported = source; unsupported["dns"]["servers"][0]["queryStrategy"] = strategy;
    Require(!prepare(unsupported), "unqualified system-family per-server strategy admitted");
  }
  auto dns_script = source; dns_script["dns"]["script"] = "return true";
  Require(!prepare(dns_script), "unqualified DNS script admitted");
  auto no_resolver_pin = source; no_resolver_pin["dns"]["hosts"].erase("dns.example");
  Require(!prepare(no_resolver_pin), "named remote DNS can enter a root resolver cycle");
  for (const auto& mapping : {Json("alias.invalid"), Json::array(), Json::array({"203.0.113.53", "2001:db8::53"}), Json{{"address", "203.0.113.53"}}}) {
    auto unsafe = source; unsafe["dns"]["hosts"]["dns.example"] = mapping;
    Require(!prepare(unsafe), "unqualified resolver static host mapping admitted");
  }
  auto single_resolver_pin = source; single_resolver_pin["dns"]["hosts"]["dns.example"] = "203.0.113.53";
  auto single_prepared = prepare(single_resolver_pin); Require(single_prepared.has_value() && Parse(*single_prepared)["dns"] == single_resolver_pin["dns"], "exact IPv4 resolver host mapping was changed");
  auto fqdn_resolver = source; fqdn_resolver["dns"]["servers"][1]["address"] = "https://DNS.EXAMPLE./dns-query";
  Require(prepare(fqdn_resolver).has_value(), "root resolver's case folding/FQDN normalization was ignored");
  auto false_fqdn_mapping = fqdn_resolver;
  false_fqdn_mapping["dns"]["hosts"].erase("dns.example");
  false_fqdn_mapping["dns"]["hosts"]["DNS.EXAMPLE."] = "203.0.113.53";
  Require(!prepare(false_fqdn_mapping), "FQDN key that root LookupIP cannot match admitted as protected resolver bootstrap");
  auto dns_alias = source; dns_alias["dns"]["Servers"] = dns_alias["dns"]["servers"]; dns_alias["dns"].erase("servers");
  auto alias_prepared = prepare(dns_alias); Require(alias_prepared.has_value() && Parse(*alias_prepared)["dns"] == dns_alias["dns"], "safe DNS field spelling was rewritten");
  dns_alias["dns"]["servers"] = Json::array(); Require(!prepare(dns_alias), "ambiguous folded DNS server fields admitted");

  auto chained = source;
  chained["outbounds"][0]["settings"]["vnext"][0]["address"] = "logical-target.invalid";
  chained["outbounds"][0]["streamSettings"]["sockopt"] = {{"dialerProxy", "front"}};
  chained["outbounds"].push_back({{"tag", "front"}, {"protocol", "socks"},
      {"settings", {{"servers", Json::array({{{"address", "endpoint.invalid"}, {"port", 8443}}})}}}});
  auto chained_prepared = prepare(chained); Require(chained_prepared.has_value(), "chained transport incorrectly bootstrapped logical target");
  auto chained_config = Parse(*chained_prepared);
  Require(chained_config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "front"
      && chained_config["outbounds"][0]["settings"] == chained["outbounds"][0]["settings"], "caller chain/logical address changed");
  for (const auto& target : {"missing-handler", "proxy"}) {
    auto invalid_chain = source;
    invalid_chain["outbounds"][0]["streamSettings"]["sockopt"] = {{"dialerProxy", target}};
    Require(!prepare(invalid_chain), "missing/self-referential transport chain admitted");
  }
  auto cycle = chained;
  cycle["outbounds"][2]["streamSettings"] = {{"sockopt", {{"dialerProxy", "proxy"}}}};
  Require(!prepare(cycle), "cyclic handler transport chain admitted");
  auto multi_outbound = source;
  auto backup = source["outbounds"][0]; backup["tag"] = "proxy-backup"; backup["settings"]["vnext"][0]["port"] = 8443;
  multi_outbound["outbounds"].push_back(backup);
  auto multi_prepared = prepare(multi_outbound); Require(multi_prepared.has_value(), "multiple independent outbounds rejected");
  auto multi_config = Parse(*multi_prepared);
  Require(multi_config["outbounds"][0]["settings"] == source["outbounds"][0]["settings"]
      && find_outbound(multi_config, "proxy-backup")["settings"] == backup["settings"], "independent outbound identities/settings changed");
  Require(multi_config["routing"]["rules"][3]["domain"] == Json::array({"full:endpoint.invalid"}) && multi_config["routing"]["rules"][3]["port"] == "8443", "same-host second outbound pin lost its independent port");
  auto dormant_address = source;
  dormant_address["outbounds"][0]["streamSettings"]["address"] = "ignored.invalid";
  dormant_address["outbounds"][0]["streamSettings"]["port"] = 444;
  Require(prepare(dormant_address).has_value(), "ordinary RAW stream.address incorrectly replaced protocol endpoint");
  auto downloads = source;
  downloads["outbounds"][0]["streamSettings"]["network"] = "xhttp";
  downloads["outbounds"][0]["streamSettings"]["xhttpSettings"] = {{"downloadSettings", {{"address", "dormant.invalid"}, {"port", 444}}},
      {"extra", {{"downloadSettings", {{"address", "endpoint.invalid"}, {"port", 8443}, {"network", "xhttp"}}}}}};
  auto download_prepared = prepare(downloads); Require(download_prepared.has_value(), "effective XHTTP download bootstrap rejected");
  auto download_config = Parse(*download_prepared);
  Require(download_config["outbounds"][0]["streamSettings"]["xhttpSettings"]["downloadSettings"] == downloads["outbounds"][0]["streamSettings"]["xhttpSettings"]["downloadSettings"], "dormant XHTTP download changed");
  bool download_rule = false;
  for (const auto& rule : download_config["routing"]["rules"]) if (rule.value("port", "") == "8443" && rule.contains("domain")) download_rule = true;
  Require(download_rule, "XHTTP download used upload endpoint port");
  auto broken_download_chain = downloads;
  broken_download_chain["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["sockopt"] = {{"dialerProxy", "missing-download-handler"}};
  Require(!prepare(broken_download_chain), "effective XHTTP download references a missing handler");
  downloads["outbounds"][0]["streamSettings"]["sockopt"] = {{"penetrate", true}};
  downloads["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["network"] = "tcp";
  Require(!prepare(downloads), "non-XHTTP penetrating download admitted");
  downloads["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["network"] = "xhttp";
  Require(prepare(downloads).has_value(), "explicit XHTTP penetrating download rejected");
  auto tag_collision = source;
  tag_collision["dns"]["tag"] = kManagedInbound;
  tag_collision["dns"]["servers"][0]["tag"] = "flutter-vless-bootstrap-input";
  auto tags_prepared = prepare(tag_collision); Require(tags_prepared.has_value(), "DNS namespace collision rejected instead of isolated");
  auto isolated_dns = Parse(*tags_prepared);
  Require(isolated_dns["inbounds"][0]["tag"] == std::string(kManagedInbound) + "-1" && isolated_dns["dns"] == tag_collision["dns"], "managed DNS inherited root own-link identity");
  Require(find_outbound(isolated_dns, isolated_dns["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"].get<std::string>())["settings"]["inboundTag"] == "flutter-vless-bootstrap-input-1", "private physical pin inherited caller DNS own-link tag");
  for (const auto& key : {"FakeDNS", "fakedns", "fakeDnS"}) {
    auto allowed = source; allowed[key] = Json::array();
    const auto fake = prepare(allowed); Require(fake.has_value(), "valid empty FakeDNS engine alias refused");
    Require(Parse(*fake)["fakedns"] == Json::array(), "empty FakeDNS engine changed");
  }
  for (const auto& key : {"Listen", "Li\xC5\xBFten"}) {
    auto bad = source; bad["inbounds"][0][key] = "0.0.0.0"; Require(!prepare(bad), "ambiguous listen accepted");
  }
  Require(config["inbounds"][1] == source["inbounds"][0], "user listener/auth/sniffing were rewritten");
  Require(rules[0]["inboundTag"] == Json::array({kManagedInbound}), "system DNS policy must scope to private adapter");
  auto extra = source;
  extra["inbounds"].push_back({{"tag", "socks-direct"}, {"protocol", "socks"}, {"listen", "127.0.0.1"}, {"port", 10820}, {"settings", {{"auth", "noauth"}}}});
  extra["inbounds"].push_back({{"tag", "custom-http"}, {"protocol", "http"}, {"listen", "127.0.0.1"}, {"port", "10807-10810"}, {"settings", {{"accounts", Json::array({{{"user", "app"}, {"pass", "app-secret"}}})}}}});
  extra["routing"]["rules"].insert(extra["routing"]["rules"].begin(), Json{{"inboundTag", Json::array({"socks-direct"})}, {"outboundTag", "direct"}});
  auto multiple = prepare(extra); Require(multiple.has_value(), "full multi-listener profile rejected");
  auto multi = Parse(*multiple);
  Require(Port(multi["inbounds"][0]) == 10811, "private adapter collided with user port range");
  for (size_t i = 0; i < extra["inbounds"].size(); ++i) Require(multi["inbounds"][i+1] == extra["inbounds"][i], "imported listener changed");
  Require(multi["routing"]["rules"][multi["routing"]["rules"].size()-extra["routing"]["rules"].size()] == extra["routing"]["rules"][0], "socks-direct route lost");
  extra["inbounds"].push_back({{"tag", "stats-port"}, {"protocol", "http"}, {"port", 10086}});
  auto shifted_api = prepare(extra); Require(shifted_api && ApiPort(*shifted_api) == 10087, "stats port collided with caller listener");
  extra["inbounds"][0]["tag"] = kManagedInbound;
  auto collided = prepare(extra); Require(collided.has_value(), "private inbound tag collision rejected");
  Require(Parse(*collided)["inbounds"][0]["tag"] == std::string(kManagedInbound) + "-1", "private inbound tag was not isolated");
  auto bad = source; bad["outbounds"][0]["tag"] = kDnsRelay;
  auto reserved = prepare(bad); Require(reserved.has_value(), "caller DNS tag rejected");
  Require(Parse(*reserved)["outbounds"][2]["tag"] == std::string(kDnsRelay) + "-1", "DNS relay overwrote caller tag");
  auto service_references = source;
  service_references["api"] = {{"tag", kManagedInbound}};
  service_references["reverse"] = {{"portals", Json::array({{{"tag", kIpv6Block}}})}};
  service_references["routing"]["rules"].insert(service_references["routing"]["rules"].begin(),
      Json{{"type", "field"}, {"inboundTag", Json::array({std::string(kManagedInbound) + "-1"})}, {"outboundTag", kDnsRelay}});
  auto isolated = prepare(service_references); Require(isolated.has_value(), "service references rejected");
  auto protected_references = Parse(*isolated);
  Require(protected_references["inbounds"][0]["tag"] == std::string(kManagedInbound) + "-2", "adapter inherited user reference/API tag");
  Require(protected_references["routing"]["rules"][2]["outboundTag"] == std::string(kIpv6Block) + "-1", "closed bootstrap service inherited reverse tag");
  Require(protected_references["routing"]["rules"][0]["outboundTag"] == std::string(kDnsRelay) + "-1", "DNS service inherited user reference");
  bad = source; bad["outbounds"][0]["settings"]["vnext"][0]["address"] = "2001:db8::1"; Require(!prepare(bad), "unsupported IPv6 endpoint accepted");
  bad = source; bad["outbounds"][0]["streamSettings"]["sockopt"] = {{"addressPortStrategy", "srv"}}; Require(!prepare(bad), "system SRV resolver accepted");
  auto aliases = source;
  aliases["INBOUNDS"] = aliases["inbounds"]; aliases.erase("inbounds");
  aliases["OUTBOUNDS"] = aliases["outbounds"]; aliases.erase("outbounds");
  Require(prepare(aliases).has_value(), "unambiguous Go field aliases rejected");
  Require(Parse(R"({"a":1,"a":2})").is_discarded(), "duplicate JSON field accepted");
  for (const auto& invalid : {"::/0", "1.2.3.4/33", "1.2.3.4/24/0", "1.2.3.4", "1.2.3.4/-1"})
    Require(!ApplyBypass(source.dump(), {invalid}), "invalid bypass CIDR accepted");
  auto bypass = ApplyBypass(source.dump(), {"0.0.0.0/0", "192.168.0.0/16"});
  Require(bypass.has_value(), "valid CIDRs rejected");
  auto protected_bypass = prepare(Parse(*bypass));
  Require(protected_bypass.has_value(), "bypass preparation failed");
  auto bypass_rules = Parse(*protected_bypass)["routing"]["rules"];
  Require(bypass_rules[0]["outboundTag"] == kDnsRelay && bypass_rules[bypass_rules.size()-Parse(*bypass)["routing"]["rules"].size()]["ip"][0] == "0.0.0.0/0", "subnet bypass overrides DNS protection");
  std::cout << "PASS desktop DNS, IPv6, privacy, auth, aliases and domain-routing security boundaries\n";
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
