// Runs only child processes and private temporary files; no network settings.
#include "native_runtime.h"
#include "protected_runtime.h"
#include "packet_path_probe.h"
#include <aclapi.h>
#include <cassert>
#include <iostream>
#include <fstream>

int main(int argc, char** argv) {
  using namespace flutter_vless::native;
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
  SetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr);
  SetEnvironmentVariableW(L"xray.location.asset", nullptr);
  SetEnvironmentVariableW(L"XRAY_BROWSER_DIALER", nullptr);

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
    auto config = flutter_vless::xray_config::Parse(R"({"outbounds":[],"routing":{"rules":[]}})");
    assert(probe.Configure(config));
    assert(config["routing"]["rules"][0]["ip"][0] == "198.18.0.3/32");
    assert(config["outbounds"][0]["settings"]["redirect"].get<std::string>().rfind("127.0.0.1:", 0) == 0);
    assert(probe.Check("127.0.0.1"));
    std::cout << "PASS local challenge-response and virtual-path probe configuration (TUN acceptance separate)\n";
  }

  const auto trusted = FindBundledFile(L"xray.exe");
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
