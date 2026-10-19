#include "xray_config.h"
#include "asset_location.h"
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <chrono>

using namespace flutter_vless::xray_config;
void Check(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
void CallerServicePreservationCases() {
  std::ifstream input("tool/fixtures/compatibility/full-config.json");
  Check(input.good(), "shared full-config corpus is required");
  Json cases; input >> cases;
  const auto base = Parse(R"({"inbounds":[{"protocol":"socks","port":18580}],"outbounds":[{"protocol":"socks","tag":"proxy","settings":{"servers":[{"address":"127.0.0.1","port":18582}]}}]})");
  for (const auto& api : {Json::object(), Json{{"tag", "caller"}, {"listen", "0.0.0.0:19001"}, {"services", Json::array({"HandlerService"})}}, Json(nullptr)}) {
    auto profile = base; profile["api"] = api;
    cases.push_back({{"name", "supplied_api_without_library_roots"}, {"config", profile}});
  }
  for (const auto& policy : {Json::object(), Json{{"system", nullptr}}, Json{{"system", {{"statsInboundUplink", false}}}}, Json(nullptr)}) {
    auto profile = base; profile["policy"] = policy; profile["stats"] = nullptr;
    cases.push_back({{"name", "private_api_retains_explicit_roots"}, {"config", profile}});
  }
  cases.push_back({{"name", "library_defaults_only_for_absent_roots"}, {"config", base}});
  for (const auto& item : cases) {
    auto source = item["config"];
    if (source["inbounds"].empty()) source["inbounds"].push_back({{"protocol", "socks"}, {"port", 18580}});
    const auto original = source.dump();
    Check(Fields(source, {"api", "stats", "policy"}), "invalid full-config corpus roots");
    auto verify = [&](const std::string& prepared) {
      const auto result = Parse(prepared);
      for (const auto* key : {"api", "stats", "policy"}) {
        if (source.contains(key)) Check(result.contains(key) && result[key] == source[key], "caller API/stats/policy subtree changed");
      }
      if (!source.contains("api")) Check(ApiPort(prepared).has_value(), "absent caller API lost the library-owned listener");
      Check(OwnedApiPort(original, prepared).has_value() == !source.contains("api"), "caller API was treated as a plugin-owned statistics endpoint");
      if (!source.contains("stats")) Check(result["stats"] == Json::object(), "absent stats default missing");
      if (!source.contains("policy")) Check(result["policy"] == Json{{"system", {{"statsInboundUplink", true}, {"statsInboundDownlink", true},
          {"statsOutboundUplink", true}, {"statsOutboundDownlink", true}}}}, "absent policy default missing");
    };
    auto proxy = original;
    unsigned api_probes = 0, allocations = 0;
    Check(PrepareProxy(proxy, [&](uint16_t port) { if (port != 18580) ++api_probes; return true; },
        [&] { ++allocations; return uint16_t{19000}; }), item["name"].get<std::string>().c_str());
    verify(proxy);
    Check(allocations == 0 && (!source.contains("api") || api_probes == 0), "supplied caller API triggered private listener allocation/probing");
    auto vpn = PrepareVpn(original); Check(vpn.has_value(), "caller service roots rejected by VPN preparer"); verify(*vpn);
    auto protected_vpn = PrepareProtectedVpn(original, "session-user", "session-password", "Ethernet",
        [](const std::string& host) { return host == "endpoint.invalid" ? "192.0.2.5" : ""; });
    Check(protected_vpn.has_value(), "caller service roots rejected by protected VPN preparer"); verify(*protected_vpn);
  }
  // Normalize only schema root names; nested service/policy spelling is caller data.
  auto folded = base;
  folded["API"] = {{"Tag", "caller"}, {"Liſten", "127.0.0.1:10085"}, {"Services", Json::array({"StatsService", "HandlerService"})}};
  folded[u8"Statſ"] = nullptr; folded["Policy"] = {{"System", {{"StatsInboundUplink", false}}}};
  auto text = folded.dump();
  Check(PrepareProxy(text, [](uint16_t) { return true; }, [] { return uint16_t{0}; }), "folded caller service roots rejected");
  auto normalized = Parse(text);
  Check(normalized["api"] == folded["API"] && normalized["stats"].is_null() && normalized["policy"] == folded["Policy"], "folded root normalization changed nested service fields");
}
void OwnedApiPortCases() {
  const auto source = Parse(R"({"inbounds":[{"protocol":"socks","port":18580}],"outbounds":[{"protocol":"freedom"}]})");
  auto prepared = source.dump();
  Check(PrepareProxy(prepared, [](uint16_t) { return true; }, [] { return uint16_t{0}; }), "owned API fixture preparation");
  Check(OwnedApiPort(source.dump(), prepared) == 10085, "generated private API was not selected");
  for (const auto& key : {"api", "API", "aPi"}) for (const auto& value : {Json(nullptr), Json::object(), Parse(prepared)["api"]}) {
    auto caller = source; caller[key] = value;
    Check(!OwnedApiPort(caller.dump(), prepared), "supplied API presence, even null, acquired a generated endpoint");
  }
  for (const auto& invalid : {"{bad json}", "null", "[]", R"({"api":null,"API":null})", R"({"api":null,"api":null})"})
    Check(!OwnedApiPort(invalid, prepared), "unqualified source acquired statistics endpoint ownership");
  for (const auto& listen : {"0.0.0.0:10085", "[::1]:10085", "localhost:10085", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:10085suffix", "127.0.0.1:"}) {
    auto changed = Parse(prepared); changed["api"]["listen"] = listen;
    Check(!OwnedApiPort(source.dump(), changed.dump()), "invalid or caller-facing statistics listen accepted");
  }
  for (const auto& services : {Json(nullptr), Json::array(), Json::array({"HandlerService"}), Json::array({"StatsService", "HandlerService"})}) {
    auto changed = Parse(prepared); changed["api"]["services"] = services;
    Check(!OwnedApiPort(source.dump(), changed.dump()), "foreign API service graph treated as generated");
  }
  for (const auto& tag : {Json(nullptr), Json(12), Json("")}) {
    auto changed = Parse(prepared); changed["api"]["tag"] = tag;
    Check(!OwnedApiPort(source.dump(), changed.dump()), "invalid private API tag accepted");
  }
  auto changed = Parse(prepared); changed["api"]["foreign"] = true;
  Check(!OwnedApiPort(source.dump(), changed.dump()), "foreign private API shape accepted");
  Check(!OwnedApiPort(source.dump(), "{bad json}"), "invalid prepared document accepted");
}
void UnixInputProxyPreparationCases() {
  for (const auto& listen : {std::string("@flutter-vless-unix-fixture"), std::string(" \t@flutter-vless-unix-fixture\n")}) {
    auto profile = Parse(R"({"inbounds":[{"protocol":"http","port":18582},{"protocol":"socks","port":18580}],"outbounds":[{"protocol":"freedom"}]})");
    profile["inbounds"][0]["listen"] = listen;
    auto text = profile.dump(); unsigned unix_probes = 0, allocations = 0;
    Check(PrepareProxy(text, [&](uint16_t port) { if (port == 18582) { ++unix_probes; return false; } return true; },
        [&] { ++allocations; return uint16_t{0}; }), "Unix source listener was probed/remapped as a TCP port");
    Check(unix_probes == 0 && allocations == 0, "Unix PortList triggered OS port allocation");
    Check(Parse(text)["inbounds"][0] == profile["inbounds"][0], "Unix caller listener or ignored PortList changed");
  }
}
void ListenAddressCases() {
  std::ifstream input("tool/fixtures/compatibility/listen-addresses.json");
  Check(input.good(), "shared listen address corpus is required");
  Json cases; input >> cases;
  Check(cases.size() == 6, "shared listen address corpus changed");
  for (const auto& item : cases) {
    auto environment = item["environment"];
    auto expected = item["resolved"];
#ifdef _WIN32
    if (item.contains("windowsEnvironment")) environment = item["windowsEnvironment"];
    if (item.contains("windowsResolved")) expected = item["windowsResolved"];
#endif
    std::vector<std::string> lookups;
    PortEnvironmentReader read = [&](const std::string& name) -> std::optional<std::string> {
      lookups.push_back(name);
      return environment.contains(name) ? std::optional<std::string>{environment[name].get<std::string>()} : std::nullopt;
    };
    Json profile = {{"inbounds", Json::array({{{"protocol", "http"}, {"listen", item["listen"]}, {"port", item["port"]}, {"settings", {{"sentinel", "env:CALLER_SETTING"}}}}})},
        {"outbounds", Json::array({{{"protocol", "freedom"}, {"settings", {{"redirect", "env:CALLER_ENDPOINT"}}}}})},
        {"api", {{"listen", "env:CALLER_API"}}}};
    const auto original = profile.dump();
    const auto available = AvailablePort(profile, 10807, read);
    auto normalized = profile;
    lookups.clear();
    const bool accepted = Normalize(normalized, read);
    Check(profile.dump() == original, "resolved port view mutated the source document");
    if (item.value("invalid", false)) {
      Check(!accepted && !available, "nested env listener was reinterpreted instead of refused");
      Check(lookups == std::vector<std::string>{"FLUTTER_VLESS_FIXTURE_LISTEN"}, "nested env lookup was recursive");
      continue;
    }
    Check(accepted, item["name"].get<std::string>().c_str());
    Check(available == (item["unix"].get<bool>() ? 10807 : 10810), "effective Unix/numeric listen PortList classification differs from Core");
    Check(normalized["inbounds"][0]["listen"] == expected, "listen env value was not frozen exactly");
    Check(normalized["inbounds"][0]["port"] == item["port"] && normalized["inbounds"][0]["settings"] == profile["inbounds"][0]["settings"]
        && normalized["outbounds"] == profile["outbounds"] && normalized["api"] == profile["api"], "listen preparation changed an unrelated caller field");
    if (item["name"] == "present_empty_wins_over_alias") Check(lookups == std::vector<std::string>{"flutter.vless.fixture.listen"}, "present empty exact env lost to its alias");
    const auto frozen = normalized.dump();
    unsigned later_lookups = 0;
    Check(Normalize(normalized, [&](const std::string&) -> std::optional<std::string> { ++later_lookups; return "127.0.0.2"; })
        && normalized.dump() == frozen && later_lookups == 0, "frozen listen depended on later child environment");
  }
  for (const auto& listen : {std::string(" \t@flutter-vless-listen-fixture\n"), std::string(u8"\u2003@flutter-vless-listen-fixture\u2003"), std::string("[ @flutter-vless-listen-fixture ]")})
    Check(UnixInboundListen(listen), "Core address whitespace/bracket Unix classification mismatch");
  auto folded = Parse(u8R"({"inbounds":[{"protocol":"http","Liſten":"env:fixture.listen","port":"0-65535"}],"outbounds":[{"protocol":"freedom"}]})");
  const auto untouched = folded.dump();
  PortEnvironmentReader read = [](const std::string& name) -> std::optional<std::string> { return name == "FIXTURE_LISTEN" ? std::optional<std::string>{"@fixture"} : std::nullopt; };
  Check(AvailablePort(folded, 10807, read) == 10807 && folded.dump() == untouched, "folded listen view did not preserve source or reserve correctly");
  Check(Normalize(folded, read) && folded["inbounds"][0]["listen"] == "@fixture", "folded listen env was not materialized");
  Check(ResolveInboundListen(" ENV:fixture", read) == " ENV:fixture", "listen env prefix was made case/whitespace insensitive");
  for (const auto& name : {std::string(u8"ß"), std::string(u8" ß ")}) {
    std::vector<std::string> lookups;
    PortEnvironmentReader unsupported = [&](const std::string& key) -> std::optional<std::string> {
      lookups.push_back(key);
      return key == "SS" ? std::optional<std::string>{"@foreign-alias"} : std::nullopt;
    };
    auto profile = Parse(R"({"inbounds":[{"protocol":"http","port":"10807-10809"}],"outbounds":[{"protocol":"freedom"}]})");
    profile["inbounds"][0]["listen"] = "env:" + name;
    Check(!AvailablePort(profile, 10807, unsupported), "unqualified Unicode env alias silently acquired a bind address");
    Check(lookups == std::vector<std::string>{name}, "unqualified Unicode alias was looked up approximately");
    lookups.clear();
    Check(!Normalize(profile, unsupported), "unqualified Unicode env alias became an AnyIP listener");
    Check(lookups == std::vector<std::string>{name}, "Unicode normalization performed an alias lookup");
  }
  PortEnvironmentReader exact_unicode = [](const std::string& name) -> std::optional<std::string> {
    return name == u8"ß" ? std::optional<std::string>{"@exact-unicode-key"} : std::nullopt;
  };
  Check(ResolveInboundListen(u8"env:ß", exact_unicode) == "@exact-unicode-key", "exact Unicode env lookup was refused");
  auto exact_profile = Parse(u8R"({"inbounds":[{"protocol":"http","listen":"env:ß","port":"0-65535"}],"outbounds":[{"protocol":"freedom"}]})");
  Check(AvailablePort(exact_profile, 10807, exact_unicode) == 10807 && Normalize(exact_profile, exact_unicode)
      && exact_profile["inbounds"][0]["listen"] == "@exact-unicode-key", "exact Unicode env binding did not preserve its value");
}
void AssetLocationCases() {
  namespace assets = flutter_vless::asset_location;
  namespace fs = std::filesystem;
  const auto directory = fs::temp_directory_path() / ("flutter-vless-assets-pure-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  Check(fs::create_directory(directory), "cannot create owned asset fixture directory");
  struct Cleanup { fs::path path; ~Cleanup() { std::error_code error; fs::remove_all(path, error); } } cleanup{directory};
  const auto root = directory / fs::u8path(u8"Caller Assets Ω");
  Check(fs::create_directory(root), "cannot create explicit Unicode asset directory");
  std::ofstream(root / "caller-only.dat") << "synthetic asset";
  Check(assets::Valid(std::nullopt) && assets::Valid(root), "optional/existing asset directory rejected");
  Check(!fs::exists(root / "geoip.dat") && !fs::exists(root / "geosite.dat"), "asset fixture accidentally needs standard filenames");
  for (const auto& invalid : {fs::path(), fs::path("relative-assets"), root / "missing", root / "caller-only.dat"})
    Check(!assets::Valid(invalid), "empty/relative/missing/non-directory asset root admitted");
  auto embedded_zero = root.u8string(); embedded_zero.push_back('\0'); embedded_zero += "ignored";
  Check(!assets::Valid(fs::u8path(embedded_zero)), "embedded NUL asset root admitted");
  const std::vector<std::wstring> inherited = {L"KEEP=caller-value", L"=C:=C:\\working", L"xray.location.asset=untrusted-dotted",
      L"XRAY_LOCATION_ASSET=untrusted-alias", L"XRAY_LOCATION_CERT=untrusted-cert", L"SSLKEYLOGFILE=untrusted-log",
      L"XRAY_BROWSER_DIALER=untrusted-dialer", L"GODEBUG=untrusted-debug", L"GOTRACEBACK=untrusted-trace",
      L"http_proxy=untrusted-proxy", L"HTTPS_PROXY=untrusted-proxy", L"ALL_PROXY=untrusted-proxy", L"NO_PROXY=untrusted-proxy", L"Path=untrusted-path"};
  const auto before = inherited;
  auto entries = [](const std::vector<wchar_t>& block) {
    Check(block.size() >= 2 && block[block.size()-1] == 0 && block[block.size()-2] == 0, "child environment is not double NUL terminated");
    std::vector<std::wstring> result;
    for (size_t offset = 0; offset < block.size() && block[offset];) {
      const std::wstring value(block.data() + offset); result.push_back(value); offset += value.size() + 1;
    }
    return result;
  };
  const auto legacy = entries(assets::ChildEnvironment(inherited, L"C:\\Windows\\System32", std::nullopt));
  Check(legacy == std::vector<std::wstring>{L"KEEP=caller-value", L"=C:=C:\\working", L"PATH=C:\\Windows\\System32"}, "legacy child privacy filtering changed");
  const auto selected = entries(assets::ChildEnvironment(inherited, L"C:\\Windows\\System32", root));
  Check(std::count(selected.begin(), selected.end(), L"xray.location.asset=" + root.wstring()) == 1
      && std::count(selected.begin(), selected.end(), L"XRAY_LOCATION_ASSET=" + root.wstring()) == 1, "explicit asset root was ignored or did not override both Core aliases");
  Check(selected.size() == legacy.size() + 2 && inherited == before, "explicit assets leaked CERT/debug/proxy values or mutated the parent environment");
  Check(entries(assets::ChildEnvironment({}, L"", std::nullopt)).empty(), "empty environment block is not valid");
}
int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--caller-services") { CallerServicePreservationCases(); return 0; }
  if (argc == 2 && std::string(argv[1]) == "--owned-api") { OwnedApiPortCases(); return 0; }
  if (argc == 2 && std::string(argv[1]) == "--unix-inputs") { UnixInputProxyPreparationCases(); return 0; }
  if (argc == 2 && std::string(argv[1]) == "--listen-addresses") { ListenAddressCases(); return 0; }
  if (argc == 2 && std::string(argv[1]) == "--asset-location") { AssetLocationCases(); return 0; }
  CallerServicePreservationCases();
  OwnedApiPortCases();
  UnixInputProxyPreparationCases();
  ListenAddressCases();
  AssetLocationCases();
  std::ifstream api_input("tool/fixtures/compatibility/api-listeners.json");
  Check(api_input.good(), "shared API listener corpus is required");
  Json api_cases; api_input >> api_cases;
  for (const auto& item : api_cases) {
    const auto before = item["config"].dump();
    Check(ApiListenerPorts(item["config"]) == item["ports"].get<std::set<unsigned>>(), item["name"].get<std::string>().c_str());
    Check(item["config"].dump() == before, "API reservation mutated source");
  }
  auto api_profile = Parse(R"({"api":{"listen":"127.0.0.1:10808"},"inbounds":[{"protocol":"http","port":"10809-10810"}]})");
  Check(AvailablePort(api_profile, 10808) == 10811, "private port collided with API/ranges");
  std::ifstream metrics_input("tool/fixtures/compatibility/metrics-listeners.json");
  Check(metrics_input.good(), "shared metrics listener corpus is required");
  Json metrics_cases; metrics_input >> metrics_cases;
  for (const auto& item : metrics_cases) {
    const auto before = item["config"].dump();
    Check(ServiceListenerPorts(item["config"]) == item["ports"].get<std::set<unsigned>>(), item["name"].get<std::string>().c_str());
    Check(item["config"].dump() == before, "service listener reservation mutated source");
  }
  auto metrics_profile = Parse(u8R"({"api":{"listen":"127.0.0.1:+10807"},"Metricſ":{"Liſten":"127.0.0.1:+10811"},"inbounds":[{"protocol":"http","port":"10808-10810"}]})");
  const auto metrics_before = metrics_profile.dump();
  Check(AvailablePort(metrics_profile, 10807) == 10812, "private port collided with metrics/API/ranges");
  Check(metrics_profile.dump() == metrics_before, "private allocation mutated metrics config");
  std::ifstream tag_input("tool/fixtures/compatibility/tags.json");
  Check(tag_input.good(), "shared tag corpus is required");
  Json tag_cases; tag_input >> tag_cases;
  for (const auto& item : tag_cases) {
    const auto before = item["config"].dump();
    ServiceTags tags(item["config"]);
    for (size_t i = 0; i < item["requests"].size(); ++i)
      Check(tags.Next(item["requests"][i].get<std::string>()) == item["expected"][i], item["name"].get<std::string>().c_str());
    Check(item["config"].dump() == before, "tag allocation mutated user config");
  }
  std::ifstream input("tool/fixtures/compatibility/ports.json");
  Check(input.good(), "shared port corpus is required");
  Json cases; input >> cases;
  for (const auto& item : cases) {
    auto environment = item.value("environment", Json::object());
    auto ports = ReservedPorts(item["value"], [&](const std::string& name) -> std::optional<std::string> {
      return environment.contains(name) ? std::optional<std::string>{environment[name].get<std::string>()} : std::nullopt;
    });
    if (item.value("invalid", false)) Check(!ports, item["name"].get<std::string>().c_str());
    else Check(ports && *ports == item["ports"].get<std::set<unsigned>>(), item["name"].get<std::string>().c_str());
  }
  auto unix_profile = Parse(R"({"inbounds":[{"protocol":"http","listen":"@flutter-vless-port-corpus","port":"0-65535"}]})");
  Check(AvailablePort(unix_profile, 10808) == 10808, "Unix PortList must not reserve TCP ports");
#ifdef _WIN32
  auto unicode_unix_profile = Parse(u8R"({"inbounds":[{"protocol":"http","listen":"C:\\тест\\socket","port":"0-65535"}]})");
  Check(AvailablePort(unicode_unix_profile, 10808) == 10808, "UTF-8 Windows Unix path must be classified without opening it");
#endif
  const std::string original = R"({
    "outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":18582}]},"tag":"proxy"},{"tag":"direct","protocol":"freedom"}],
    "inbounds":[{"port":18580,"settings":{"nested":{"port":18582}},"protocol":"socks","tag":"socks-in"}],
    "routing":{"domainStrategy":"AsIs","rules":[{"domain":["domain:ru","domain:io"],"outboundTag":"direct"}]},
    "dns":{"queryStrategy":"UseIPv4"},
    "policy":{"levels":{"8":{"bufferSize":3}}},
    "remarks":"Escaped braces { } and a quote: \""
  })";
  Check(SocksPort(original) == 18580, "inbound order must not select outbound port");
  std::string prepared = original;
  int allocations = 0;
  Check(PrepareProxy(prepared, [](uint16_t p) { return p != 18582; },
      [&]() { ++allocations; return uint16_t{19000}; }), "proxy preparation");
  Check(allocations == 0, "occupied remote and nested ports must not be probed");
  auto before = Parse(original); auto after = Parse(prepared);
  Check(after["outbounds"] == before["outbounds"], "outbound preservation");
  Check(after["routing"] == before["routing"], "routing preservation");
  Check(after["policy"]["levels"] == before["policy"]["levels"], "policy preservation");
  Check(after["api"]["listen"] == "127.0.0.1:10085", "API without log section");
  auto metrics_proxy = before;
  metrics_proxy[u8"Metricſ"] = {{u8"Liſten", "127.0.0.1:+10085"}, {"tag", "caller-metrics"}};
  auto metrics_text = metrics_proxy.dump();
  Check(PrepareProxy(metrics_text, [](uint16_t) { return true; }, []() { return uint16_t{19000}; }), "proxy metrics reservation");
  Check(ApiPort(metrics_text) == 10086, "proxy stats API collided with caller metrics");
  Check(Parse(metrics_text)[u8"Metricſ"] == metrics_proxy[u8"Metricſ"], "proxy preparation changed metrics");
  metrics_text = metrics_proxy.dump();
  int attempts = 0;
  Check(!PrepareProxy(metrics_text, [](uint16_t p) { return p != 10086; }, [&]() { ++attempts; return uint16_t{10085}; }), "declared metrics port accepted as OS-free fallback");
  Check(attempts == 32 && metrics_text == metrics_proxy.dump(), "proxy allocation retry was unbounded or changed rejected source");
  Check(PrepareProxy(prepared, [](uint16_t p) { return p != 18580; },
      []() { return uint16_t{19000}; }), "inbound conflict preparation");
  Check(SocksPort(prepared) == 19000, "occupied inbound remapped");
  Check(Parse(prepared)["outbounds"] == before["outbounds"], "server untouched after remap");
  auto vpn = PrepareVpn(original);
  Check(vpn.has_value(), "VPN preparation");
  after = Parse(*vpn);
  Check(after["routing"] == before["routing"], "VPN domain rules preserved");
  Check(after["dns"] == before["dns"], "VPN DNS preserved");
  Check(after["outbounds"] == before["outbounds"], "VPN outbounds preserved");
  Check(after["api"]["listen"] == "127.0.0.1:10086", "VPN API listener");
  Check(PrepareVpn(*vpn) == vpn, "VPN preparation is idempotent");
  std::string bound = *vpn;
  Check(BindDirectOutbounds(bound, "Ethernet"), "bind direct transport");
  after = Parse(bound);
  Check(after["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "direct uses underlay");
  Check(after["outbounds"][0] == before["outbounds"][0], "proxy transport preserved");
  Check(after["routing"] == before["routing"], "binding preserves domain rules");
  Check(BindDirectOutbounds(bound, "Wi-Fi"), "preserve explicit interface");
  Check(Parse(bound)["outbounds"][1]["streamSettings"]["sockopt"]["interface"] == "Ethernet", "explicit binding respected");
  Check(!BindDirectOutbounds(bound, ""), "missing underlay rejected");
  Check(!SocksPort(R"({"outbounds":[{"protocol":"socks","port":443}]})"), "missing inbound");
  Check(!PrepareVpn("{bad json}"), "invalid JSON rejected");
  Check(!PrepareVpn(R"({"inbounds":[{"protocol":"socks","port":65536}]})"), "invalid port rejected");
  for (unsigned occupied : {10807u, 10086u}) {
    auto with_metrics = before;
    with_metrics[u8"Metricſ"] = {{u8"Liſten", "127.0.0.1:+" + std::to_string(occupied)}, {"tag", "caller-metrics"}};
    const auto result = PrepareProtectedVpn(with_metrics.dump(), "native-user", "native-password", "Ethernet",
        [](const std::string&) { return std::string(); });
    Check(result.has_value(), "protected VPN rejected imported metrics listener");
    const auto effective = Parse(*result);
    Check(effective[u8"Metricſ"] == with_metrics[u8"Metricſ"], "protected VPN changed caller metrics listener");
    Check(effective["inbounds"][0]["port"] == (occupied == 10807 ? 10808 : 10807), "managed VPN input collided with metrics");
    Check(ApiPort(*result) == (occupied == 10086 ? 10087 : 10086), "managed VPN stats API collided with metrics");
  }
  std::cout << "Windows Xray configuration regression tests passed\n";
}
