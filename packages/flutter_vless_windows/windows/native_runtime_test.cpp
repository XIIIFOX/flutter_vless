// Runs only child processes and private temporary files; no network settings.
#include <winsock2.h>
#include "native_runtime.h"
#include "protected_runtime.h"
#include "packet_path_probe.h"
#include <aclapi.h>
#include <cassert>
#include <iostream>
#include <fstream>
#include <iterator>
#include <set>
#include <chrono>

int main(int argc, char** argv) {
  using namespace flutter_vless::native;
  if (argc == 2 && std::string(argv[1]) == "child-assets") {
    wchar_t dotted[32768]{}, alternate[32768]{};
    const bool selected = GetEnvironmentVariableW(L"xray.location.asset", dotted, 32768)
        && GetEnvironmentVariableW(L"XRAY_LOCATION_ASSET", alternate, 32768)
        && std::wstring(dotted) == alternate && fs::is_directory(dotted)
        && fs::is_regular_file(fs::path(dotted) / L"caller-only.dat")
        && !fs::exists(fs::path(dotted) / L"geoip.dat") && !fs::exists(fs::path(dotted) / L"geosite.dat");
    const bool private_environment = !GetEnvironmentVariableW(L"xray.location.cert", nullptr, 0)
        && !GetEnvironmentVariableW(L"XRAY_LOCATION_CERT", nullptr, 0)
        && !GetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr, 0)
        && !GetEnvironmentVariableW(L"XRAY_BROWSER_DIALER", nullptr, 0);
    std::cout << (selected && private_environment ? "CHILD_ASSETS_OK" : "CHILD_ASSETS_FAILED");
    return selected && private_environment ? 0 : 1;
  }
  if (argc > 1 && std::string(argv[1]) == "capture-hang") {
    std::cout << "READY:" << GetCurrentProcessId() << std::flush;
    Sleep(60000);
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "capture-overflow") {
    std::cout << std::string(129 * 1024, 'x') << std::flush;
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "capture-failure") {
    std::cout << "unsuccessful-command";
    return 7;
  }
  if (argc > 1 && std::string(argv[1]) == "child") {
    wchar_t system_directory[MAX_PATH + 1]{}, child_path[32768]{};
    const bool trusted_path = GetSystemDirectoryW(system_directory, MAX_PATH)
        && GetEnvironmentVariableW(L"PATH", child_path, 32768)
        && std::wstring(child_path) == system_directory;
    const bool arguments = argc == 5 && std::string(argv[2]) == "space quote\" slash\\"
        && std::string(argv[3]).empty() && std::string(argv[4]) == "trailing\\";
    const bool environment = trusted_path && !GetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr, 0)
        && !GetEnvironmentVariableW(L"xray.location.asset", nullptr, 0)
        && !GetEnvironmentVariableW(L"XRAY_BROWSER_DIALER", nullptr, 0);
    std::cerr << "private-stderr-canary";
    std::cout << (arguments && environment ? "CHILD_OK" : "CHILD_FAILED");
    return arguments && environment ? 0 : 1;
  }
  wchar_t path[32768]{};
  assert(GetModuleFileNameW(nullptr, path, 32768));
  const std::filesystem::path self(path);
  std::string output;
  SetEnvironmentVariableW(L"SSLKEYLOGFILE", L"private-key-canary");
  SetEnvironmentVariableW(L"xray.location.asset", L"untrusted-assets");
  SetEnvironmentVariableW(L"XRAY_BROWSER_DIALER", L"untrusted-dialer");
  assert(Command(self, {L"child", L"space quote\" slash\\", L"", L"trailing\\"}, output, 10000));
  assert(output == "CHILD_OK");
  assert(GetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr, 0)); // parent unchanged
  const auto asset_directory = fs::temp_directory_path() / (L"flutter-vless-assets-" + Wide(RandomHex(16))) / L"Caller Assets Ω";
  assert(fs::create_directories(asset_directory));
  std::ofstream(asset_directory / L"caller-only.dat") << "synthetic asset";
  SetEnvironmentVariableW(L"XRAY_LOCATION_ASSET", L"untrusted-alias");
  SetEnvironmentVariableW(L"xray.location.cert", L"untrusted-cert");
  assert(Command(self, {L"child-assets"}, output, 10000, asset_directory));
  assert(output == "CHILD_ASSETS_OK");
  wchar_t parent_asset[64]{};
  assert(GetEnvironmentVariableW(L"xray.location.asset", parent_asset, 64)
      && std::wstring(parent_asset) == L"untrusted-assets");
  assert(!Command(self, {L"child-assets"}, output, 10000, asset_directory / L"missing"));
  assert(output.empty());
  SetEnvironmentVariableW(L"XRAY_LOCATION_ASSET", nullptr);
  SetEnvironmentVariableW(L"xray.location.cert", nullptr);
  fs::remove_all(asset_directory.parent_path());
  SetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr);
  SetEnvironmentVariableW(L"xray.location.asset", nullptr);
  SetEnvironmentVariableW(L"XRAY_BROWSER_DIALER", nullptr);
  std::cout << "PASS explicit child asset root overrides both aliases, requires no standard geo names, isolates CERT and leaves parent unchanged\n";

  const auto capture_start = std::chrono::steady_clock::now();
  assert(!Command(self, {L"capture-hang"}, output, 1000));
  const auto capture_elapsed = std::chrono::steady_clock::now() - capture_start;
  assert(output.rfind("READY:", 0) == 0); // Child actually entered the stalled stage.
  assert(capture_elapsed < std::chrono::seconds(5)); // Cannot be the 60-second natural exit.
  const DWORD stalled_pid = static_cast<DWORD>(std::stoul(output.substr(6)));
  if (HANDLE stalled = OpenProcess(SYNCHRONIZE, FALSE, stalled_pid)) {
    assert(WaitForSingleObject(stalled, 1000) == WAIT_OBJECT_0);
    CloseHandle(stalled);
  } else assert(GetLastError() == ERROR_INVALID_PARAMETER);
  assert(!Command(self, {L"capture-overflow"}, output, 10000));
  assert(output.size() <= 128 * 1024);
  assert(!Command(self, {L"capture-failure"}, output, 10000));
  std::cout << "PASS bounded command output, actual stalled-child termination and nonzero exit\n";
  // CrossOver can run this process-only subset without Core, listeners, WFP,
  // TUN, administrator changes, system proxy or any VPN configuration.
#ifdef FLUTTER_VLESS_PROCESS_CAPTURE_ONLY
  std::cout << "PASS process-only build boundary\n";
  return 0;
#else
  if (argc == 2 && std::string(argv[1]) == "--process-capture-only") return 0;
#endif

  std::filesystem::path first, second;
  assert(WritePrivateConfig("private-config-canary", first));
  assert(WritePrivateConfig("private-config-canary", second));
  assert(first != second);
  std::ifstream input(first); std::string content; input >> content; input.close();
  assert(content == "private-config-canary");
  const bool wine = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version") != nullptr;
  if (!wine) {
    PSECURITY_DESCRIPTOR descriptor = nullptr; PACL acl = nullptr;
    assert(GetNamedSecurityInfoW(const_cast<wchar_t*>(first.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl, nullptr, &descriptor) == ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    assert(GetSecurityDescriptorControl(descriptor, &control, &revision));
    assert((control & SE_DACL_PROTECTED) && acl && acl->AceCount == 2);
    HANDLE token = nullptr; assert(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> buffer(size);
    assert(GetTokenInformation(token, TokenUser, buffer.data(), size, &size)); CloseHandle(token);
    auto user = reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
      void* raw = nullptr; assert(GetAce(acl, i, &raw));
      auto* ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(raw);
      auto* sid = reinterpret_cast<PSID>(&ace->SidStart);
      assert(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !(ace->Header.AceFlags & INHERITED_ACE));
      assert(EqualSid(sid, user) || IsWellKnownSid(sid, WinLocalSystemSid));
    }
    LocalFree(descriptor);
  } else std::cout << "SKIP Windows ACL enforcement (Wine)\n";
  RemovePrivateConfig(first); RemovePrivateConfig(second);
  assert(first.empty() && second.empty());

  if (!wine && IsAdministrator()) {
    ProtectedRuntime protected_runtime;
    assert(protected_runtime.Create(self));
    std::filesystem::path secret;
    assert(protected_runtime.WriteConfig("administrator-only-config", secret));
    assert(Command(protected_runtime.Executable(), {L"child", L"space quote\" slash\\", L"", L"trailing\\"}, output));
    HANDLE elevated = nullptr, filtered = nullptr;
    assert(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &elevated));
    BYTE admin[SECURITY_MAX_SID_SIZE]{}; DWORD admin_size = sizeof(admin);
    assert(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin, &admin_size));
    SID_AND_ATTRIBUTES disabled{admin, 0};
    assert(CreateRestrictedToken(elevated, DISABLE_MAX_PRIVILEGE, 1, &disabled, 0, nullptr, 0, nullptr, &filtered));
    assert(ImpersonateLoggedOnUser(filtered));
    for (const auto& target : {secret, protected_runtime.Executable()}) {
      for (DWORD access : {static_cast<DWORD>(GENERIC_READ), static_cast<DWORD>(GENERIC_EXECUTE), static_cast<DWORD>(WRITE_DAC)}) {
        HANDLE denied = CreateFileW(target.c_str(), access, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        assert(denied == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
      }
    }
    assert(RevertToSelf()); CloseHandle(filtered); CloseHandle(elevated);
    RemovePrivateConfig(secret);
    std::cout << "PASS administrator-owned runtime/config deny filtered same-user read, execute and DACL replacement\n";
  } else std::cout << "SKIP elevated/filtered-token enforcement (requires native elevated Windows)\n";

  {
    flutter_vless::PacketPathProbe probe;
    assert(probe.Start());
    assert(probe.Check("127.0.0.1")); // test backend only; no TUN or external packet
    auto config = flutter_vless::xray_config::Parse(R"({"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":19000,"tag":"fixture-tun"}],"outbounds":[],"routing":{"rules":[]}})");
    assert(!probe.Configure(config, 19001));
    assert(probe.Configure(config, 19000));
    assert(config["routing"]["rules"][0]["ip"][0] == "198.18.0.3/32");
    assert(config["routing"]["rules"][0]["inboundTag"][0] == "fixture-tun");
    assert(config["outbounds"][0]["settings"]["redirect"].get<std::string>().rfind("127.0.0.1:", 0) == 0);
    auto collision = flutter_vless::xray_config::Parse(R"({"outbounds":[{"protocol":"blackhole","tag":"flutter-vless-packet-probe"}],"routing":{"rules":[]}})");
    collision["inbounds"] = config["inbounds"];
    assert(probe.Configure(collision, 19000));
    assert(collision["outbounds"][0]["protocol"] == "blackhole");
    assert(collision["outbounds"][1]["tag"] == "flutter-vless-packet-probe-1");
    assert(collision["routing"]["rules"][0]["outboundTag"] == "flutter-vless-packet-probe-1");
    assert(probe.Check("127.0.0.1"));
    std::cout << "PASS local challenge-response and virtual-path probe configuration (TUN acceptance separate)\n";
  }

  const auto trusted = FindBundledFile(L"xray.exe");
  if (trusted) {
    constexpr auto owner = ConfigCheckStorage::currentUser;
    constexpr auto administrator = ConfigCheckStorage::administrators;
    const auto temporary_documents = [] {
      std::set<fs::path> paths;
      for (const auto& entry : fs::directory_iterator(fs::temp_directory_path())) {
        if (entry.path().filename().wstring().rfind(L"flutter-vless-", 0) == 0
            && entry.path().extension() == L".json") paths.insert(entry.path());
      }
      return paths;
    };
    const auto documents_before = temporary_documents();
    WSADATA sockets{}; assert(WSAStartup(MAKEWORD(2,2), &sockets) == 0);
    SOCKET occupied = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(occupied != INVALID_SOCKET);
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(occupied, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    int size = sizeof(address);
    assert(getsockname(occupied, reinterpret_cast<sockaddr*>(&address), &size) == 0);
    assert(listen(occupied, 1) == 0);
    const auto configuration = std::string("{\"inbounds\":[{\"listen\":\"127.0.0.1\",\"protocol\":\"socks\",\"port\":")
        + std::to_string(ntohs(address.sin_port)) + "}],\"outbounds\":[{\"protocol\":\"freedom\"}]}";
    assert(CheckConfig(configuration, *trusted, owner)); // Core must not bind the occupied listener.
    assert(!CheckConfig("{\"outbounds\":[{\"protocol\":\"private-preflight-canary\"}]}", *trusted, owner));
    assert(!CheckConfig("not-json-private-canary", *trusted, owner));
    if (!wine && IsAdministrator()) {
      const auto protected_directories = [] {
        wchar_t windows[32768]{}; assert(GetWindowsDirectoryW(windows, 32768));
        std::set<fs::path> paths;
        for (const auto& entry : fs::directory_iterator(fs::path(windows) / L"Temp")) {
          if (entry.path().filename().wstring().rfind(L"flutter-vless-protected-", 0) == 0) paths.insert(entry.path());
        }
        return paths;
      };
      const auto directories_before = protected_directories();
      // Same administrator-owned factory whose filtered-token file/image
      // denial is exercised above; checks must clean up after either result.
      assert(CheckConfig(configuration, *trusted, administrator));
      assert(!CheckConfig("{\"outbounds\":[{\"protocol\":\"private-preflight-canary\"}]}", *trusted, administrator));
      assert(protected_directories() == directories_before);
      std::cout << "PASS administrator-only Core preflight and private directory cleanup\n";
      {
        ProtectedRuntime owned;
        assert(owned.Create(*trusted));
        const auto image = owned.Executable();
        const auto owned_directories = protected_directories();
        const std::string final_bytes = " \n\t" + configuration + "\r\n ";
        fs::path final_path;
        assert(CheckPreparedConfig(final_bytes, owned, final_path));
        assert(owned.Executable() == image && final_path.parent_path() == owned.Directory());
        std::ifstream final_input(final_path, std::ios::binary);
        const std::string retained((std::istreambuf_iterator<char>(final_input)), std::istreambuf_iterator<char>());
        final_input.close();
        assert(retained == final_bytes && protected_directories() == owned_directories);
        assert(!CheckPreparedConfig(configuration, owned, final_path)); // Never replace an already-owned check file.
        RemovePrivateConfig(final_path); assert(final_path.empty());
        fs::path rejected_path;
        assert(!CheckPreparedConfig("{\"outbounds\":[{\"protocol\":\"private-preflight-canary\"}]}", owned, rejected_path));
        assert(!rejected_path.empty() && fs::is_regular_file(rejected_path));
        const auto rejected_file = rejected_path;
        RemovePrivateConfig(rejected_path);
        assert(rejected_path.empty() && !fs::exists(rejected_file));
        assert(owned.Executable() == image && protected_directories() == owned_directories);
        std::cout << "WINDOWS_FINAL_CONFIG_PREFLIGHT_PASS=2\n";
      }
      assert(protected_directories() == directories_before);
    }
    const auto missing = trusted->parent_path() / L"missing-preflight-runtime.exe";
    assert(!fs::exists(missing) && !CheckConfig(configuration, missing, owner));
    assert(temporary_documents() == documents_before);
    closesocket(occupied); WSACleanup();
    std::cout << "PASS pinned Core preflight, occupied listener and closed candidate errors\n";
  }
  const auto original = std::filesystem::current_path();
  const auto decoy = std::filesystem::temp_directory_path() / Wide(RandomHex(16));
  std::filesystem::create_directory(decoy);
  std::ofstream(decoy / L"xray.exe") << "not an executable";
  std::filesystem::current_path(decoy);
  assert(FindBundledFile(L"xray.exe") == trusted);
  std::filesystem::current_path(original);
  std::filesystem::remove_all(decoy);
  std::cout << "PASS exact child arguments, environment isolation, stderr privacy, unique private files, cleanup and CWD hijack rejection\n";
}
