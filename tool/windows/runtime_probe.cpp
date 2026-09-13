#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
#include <filesystem>
#include <chrono>
#include <future>
#include <map>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>
#include "v2ray_manager.h"
#include "diagnostics_log.h"
#include <windows.h>
#include <shellapi.h>
#include <fwpmu.h>
#include "traffic_protection.h"
#include "native_runtime.h"
#include "windows_network.h"
int main(int argc,char** argv) {
  int wide_count = 0;
  auto wide = CommandLineToArgvW(GetCommandLineW(), &wide_count);
  if (!wide) return 2;
  std::vector<std::wstring> arguments(wide, wide + wide_count);
  LocalFree(wide);
  if(argc<2)return 2;
  std::string action=argv[1];
  const bool isolated = [] { wchar_t value[16]{}; return GetEnvironmentVariableW(L"GITHUB_ACTIONS", value, 16) && std::wstring(value) == L"true"; }();
  if (action == "release-protection") {
    if (!isolated) return 20;
    flutter_vless::TrafficProtection protection;
    const bool released = protection.Inspect() && (!protection.Active() || protection.Release());
    std::cout << "PROTECTION_RELEASED=" << released << std::endl;
    return released ? 0 : 21;
  }
  if (action == "policy-count") {
    if (!isolated) return 20;
    HANDLE engine = nullptr, enumeration = nullptr;
    if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine)) return 22;
    GUID provider = {0x258726c7,0x1b37,0x4524,{0xb4,0x53,0x80,0x7a,0xe3,0x17,0x39,0x06}};
    const auto created = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration);
    UINT32 count = 0; DWORD enumerated = created;
    while (!enumerated) {
      UINT32 batch = 0; FWPM_FILTER0** filters = nullptr;
      enumerated = FwpmFilterEnum0(engine, enumeration, 256, &filters, &batch);
      if (!enumerated) for (UINT32 i=0;i<batch;++i) {
        if (filters[i]->providerKey && IsEqualGUID(*filters[i]->providerKey, provider)) ++count;
      }
      if (filters) FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
      if (!batch) break;
    }
    if (enumeration) FwpmFilterDestroyEnumHandle0(engine, enumeration);
    FwpmEngineClose0(engine);
    if (enumerated && enumerated != FWP_E_PROVIDER_NOT_FOUND) return 23;
    std::cout << count << std::endl;
    return 0;
  }
  if (action == "guard") {
    if (!isolated || arguments.size() < 5) return 20;
    HANDLE target = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, std::stoul(arguments[2]));
    const auto stop = std::filesystem::path(arguments[4]);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(arguments[3]));
    while (std::chrono::steady_clock::now() < deadline && !std::filesystem::exists(stop)) Sleep(250);
    if (std::filesystem::exists(stop)) { if(target) CloseHandle(target); return 0; }
    if (target) { TerminateProcess(target, 98); WaitForSingleObject(target, 5000); CloseHandle(target); }
    for (int retry=0; retry<10; ++retry) {
      flutter_vless::TrafficProtection protection;
      if (protection.Inspect() && (!protection.Active() || protection.Release())) return 0;
      Sleep(500);
    }
    return 24;
  }
  if(action=="gateway") {
    const auto gateway = flutter_vless::DefaultIpv4Gateway();
    std::cout << gateway << std::endl;
    return gateway.empty() ? 5 : 0;
  }
  if (action == "adapter") {
    if (!isolated || arguments.size() < 5) return 20;
    const auto path = flutter_vless::native::FindBundledFile(L"wintun.dll");
    HMODULE dll = path ? LoadLibraryExW(path->c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) : nullptr;
    if (!dll) return 30;
    using Create = void* (WINAPI*)(LPCWSTR,LPCWSTR,const GUID*);
    using Close = void (WINAPI*)(void*);
    using Start = void* (WINAPI*)(void*,DWORD);
    using Luid = void (WINAPI*)(void*,NET_LUID*);
    auto create = reinterpret_cast<Create>(GetProcAddress(dll,"WintunCreateAdapter"));
    auto close = reinterpret_cast<Close>(GetProcAddress(dll,"WintunCloseAdapter"));
    auto start = reinterpret_cast<Start>(GetProcAddress(dll,"WintunStartSession"));
    auto end = reinterpret_cast<Close>(GetProcAddress(dll,"WintunEndSession"));
    auto get_luid = reinterpret_cast<Luid>(GetProcAddress(dll,"WintunGetAdapterLUID"));
    if (!create || !close || !start || !end || !get_luid) return 31;
    void* adapter = create(arguments[2].c_str(), L"FlutterVlessValidation", nullptr);
    if (!adapter) return 32;
    void* session = start(adapter, 0x400000);
    if (!session) { close(adapter); return 33; }
    NET_LUID luid{}; get_luid(adapter, &luid);
    const auto subnet = std::stoi(arguments[3]);
    if (subnet != 2 && subnet != 3) { end(session); close(adapter); return 34; }
    bool ok = true;
    for (auto family : {AF_INET, AF_INET6}) {
      MIB_UNICASTIPADDRESS_ROW row{}; InitializeUnicastIpAddressEntry(&row);
      row.InterfaceLuid = luid; row.Address.si_family = static_cast<ADDRESS_FAMILY>(family);
      row.OnLinkPrefixLength = family == AF_INET ? 24 : 64;
      row.PrefixOrigin = IpPrefixOriginManual; row.SuffixOrigin = IpSuffixOriginManual;
      row.ValidLifetime = row.PreferredLifetime = 0xffffffff;
      const auto ip = family == AF_INET ? "100.64." + std::to_string(subnet) + ".1" : "fd00:85:" + std::to_string(subnet) + "::1";
      if (family == AF_INET) InetPtonA(AF_INET, ip.c_str(), &row.Address.Ipv4.sin_addr);
      else InetPtonA(AF_INET6, ip.c_str(), &row.Address.Ipv6.sin6_addr);
      const auto code = CreateUnicastIpAddressEntry(&row);
      if (code != NO_ERROR) { std::cout << "ADAPTER_ADDRESS_ERROR=" << code << std::endl; ok = false; break; }
      bool ready = false;
      for (int retry=0; retry<30; ++retry) {
        if (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred) { ready = true; break; }
        Sleep(500);
      }
      if (!ready) { std::cout << "ADAPTER_DAD_NOT_READY=" << family << std::endl; ok = false; break; }
    }
    if (ok) {
      std::cout << "ADAPTER_READY=" << luid.Value << std::endl;
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
      while (!std::filesystem::exists(std::filesystem::path(arguments[4])) && std::chrono::steady_clock::now() < deadline) Sleep(250);
    }
    end(session); close(adapter); FreeLibrary(dll);
    return ok ? 0 : 35;
  }
  if(action=="wintun") {
    if (!isolated) return 20;
    const auto path = flutter_vless::native::FindBundledFile(L"wintun.dll");
    HMODULE dll=path ? LoadLibraryExW(path->c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) : nullptr;
    if(!dll){std::cout<<"WINTUN_LOAD_ERROR="<<GetLastError()<<std::endl;return 10;}
    using Create=void* (WINAPI*)(LPCWSTR,LPCWSTR,const GUID*);
    using Close=void (WINAPI*)(void*);
    auto create=reinterpret_cast<Create>(GetProcAddress(dll,"WintunCreateAdapter"));
    auto close=reinterpret_cast<Close>(GetProcAddress(dll,"WintunCloseAdapter"));
    if(!create||!close)return 11;
    void* adapter=create(L"FlutterVlessValidation",L"FlutterVlessValidation",nullptr);
    DWORD error=GetLastError();
    if(adapter)close(adapter);
    std::cout<<"WINTUN_ADAPTER_CREATED="<<(adapter?1:0)<<" ERROR="<<error<<std::endl;
    FreeLibrary(dll);return adapter?0:12;
  }
  if(argc<3)return 2;
  std::ifstream input{std::filesystem::path(arguments[2])};std::string config((std::istreambuf_iterator<char>(input)),{});
  bool vpn=action=="run-vpn";
  if(!vpn && action!="run-proxy")return 2;
  if(vpn && !isolated)return 20;
  auto& manager=V2rayManager::GetInstance();
  bool started=manager.Start(config,!vpn);std::cout<<"START_RETURN="<<started<<std::endl;
  if(!started){std::cout<<manager.GetProviderDebugSnapshot()<<std::endl;manager.Stop();return 3;}
  int seconds=argc>3?std::stoi(argv[3]):20;
  const std::filesystem::path stop_file = arguments.size() > 4 ? arguments[4] : L"";
  const std::filesystem::path state_file = arguments.size() > 5 ? arguments[5] : L"";
  for(int i=0;i<seconds;i++){
    if (!stop_file.empty() && std::filesystem::exists(stop_file)) break;
    if (!state_file.empty()) {
      std::ofstream state(state_file);
      state << "{\"running\":" << (manager.IsRunning()?"true":"false")
            << ",\"protecting\":" << (manager.IsProtecting()?"true":"false") << "}";
    }
    std::cout<<"RUNNING="<<manager.IsRunning()<<" SECOND="<<i+1<<std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  const bool healthy = manager.IsRunning();
  std::string control;
  if (!stop_file.empty()) { std::ifstream signal(stop_file); signal >> control; }
  if (control == "shutdown") { manager.Shutdown(); std::cout << "SHUTDOWN_PROTECTING=" << manager.IsProtecting() << std::endl; return 0; }
  manager.Stop();std::cout<<"STOPPED="<<!manager.IsRunning()<<std::endl;
  std::cout<<manager.GetProviderDebugSnapshot()<<std::endl;
  return healthy?0:4;
}
