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
#include "windows_underlay.h"
#include "ipv6_tcp_challenge_peer.h"
#include <algorithm>
#include <cstring>
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
  if (action == "policy-count" || action == "policy-ids") {
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
        if (filters[i]->providerKey && IsEqualGUID(*filters[i]->providerKey, provider)) {
          ++count;
          if (action == "policy-ids") std::cout << filters[i]->filterId << std::endl;
        }
      }
      if (filters) FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
      if (!batch) break;
    }
    if (enumeration) FwpmFilterDestroyEnumHandle0(engine, enumeration);
    FwpmEngineClose0(engine);
    if (enumerated && enumerated != FWP_E_PROVIDER_NOT_FOUND) return 23;
    if (action == "policy-count") std::cout << count << std::endl;
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
  if (action == "cleanup-peer-default") {
    if (!isolated || arguments.size()!=4) return 20;
    NET_LUID luid{}; luid.Value=std::stoull(arguments[2]);
    if (!luid.Value || arguments[3].rfind(L"FlutterVlessNumericIPv6-",0)!=0) return 20;
    MIB_IF_ROW2 adapter{}; adapter.InterfaceLuid=luid;
    const auto lookup=GetIfEntry2(&adapter);
    if (lookup!=NO_ERROR && lookup!=ERROR_NOT_FOUND && lookup!=ERROR_FILE_NOT_FOUND) return 25;
    if (lookup==NO_ERROR && arguments[3]!=adapter.Alias) return 25;
    MIB_IPFORWARD_ROW2 row{}; InitializeIpForwardEntry(&row); row.InterfaceLuid=luid;
    row.DestinationPrefix.Prefix.si_family=AF_INET6; row.DestinationPrefix.PrefixLength=0; row.NextHop.si_family=AF_INET6;
    const auto found=GetIpForwardEntry2(&row);
    if (found!=NO_ERROR && found!=ERROR_NOT_FOUND) return 25;
    if (found==NO_ERROR && DeleteIpForwardEntry2(&row)!=NO_ERROR) return 25;
    return GetIpForwardEntry2(&row)==ERROR_NOT_FOUND ? 0 : 25;
  }
  if (action == "underlay-v6") {
    if (!isolated) return 20;
    UINT64 luid=0; const auto selected=flutter_vless::native::SelectUnderlay(AF_INET6, &luid);
    if (!selected || !luid) return 25;
    std::cout<<luid<<std::endl; return 0;
  }
  if (action == "source-interface") {
    if (arguments.size() < 3) return 2;
    MIB_UNICASTIPADDRESS_TABLE* table = nullptr;
    if (GetUnicastIpAddressTable(AF_UNSPEC, &table) != NO_ERROR) return 25;
    const std::string expected(arguments[2].begin(), arguments[2].end());
    NET_IFINDEX index = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
      const auto& row = table->Table[i];
      char address[INET6_ADDRSTRLEN]{};
      const auto family = row.Address.si_family;
      const void* bytes = family == AF_INET ? static_cast<const void*>(&row.Address.Ipv4.sin_addr)
          : static_cast<const void*>(&row.Address.Ipv6.sin6_addr);
      if (InetNtopA(family, bytes, address, sizeof(address)) && expected == address) { index = row.InterfaceIndex; break; }
    }
    FreeMibTable(table);
    if (!index) return 25;
    std::cout << index << std::endl;
    return 0;
  }
  const bool ipv6_peer_mode = action == "adapter-v6-peer";
  if (action == "adapter" || ipv6_peer_mode) {
    if (!isolated || arguments.size() < 5 || (ipv6_peer_mode && arguments.size() != 7)) return 20;
    if (ipv6_peer_mode) {
      const std::string nonce(arguments[5].begin(), arguments[5].end());
      if (nonce.size()!=32 || nonce.find_first_not_of("0123456789abcdef")!=std::string::npos
          || std::filesystem::exists(std::filesystem::path(arguments[6]))) return 20;
    }
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
    using Receive = BYTE* (WINAPI*)(void*,DWORD*);
    using Release = void (WINAPI*)(void*,const BYTE*);
    auto receive = reinterpret_cast<Receive>(GetProcAddress(dll,"WintunReceivePacket"));
    auto release = reinterpret_cast<Release>(GetProcAddress(dll,"WintunReleaseReceivePacket"));
    using Allocate = BYTE* (WINAPI*)(void*, DWORD);
    using Send = void (WINAPI*)(void*, const BYTE*);
    const auto allocate = reinterpret_cast<Allocate>(GetProcAddress(dll,"WintunAllocateSendPacket"));
    const auto send = reinterpret_cast<Send>(GetProcAddress(dll,"WintunSendPacket"));
    if (!create || !close || !start || !end || !get_luid || !receive || !release
        || (ipv6_peer_mode && (!allocate || !send))) return 31;
    void* adapter = create(arguments[2].c_str(), L"FlutterVlessValidation", nullptr);
    if (!adapter) return 32;
    void* session = start(adapter, 0x400000);
    if (!session) { close(adapter); return 33; }
    NET_LUID luid{}; get_luid(adapter, &luid);
    if (ipv6_peer_mode) std::cout << "PEER_ADAPTER_CREATED=" << luid.Value << std::endl;
    const auto subnet = std::stoi(arguments[3]);
    if ((subnet != 2 && subnet != 3) || (ipv6_peer_mode && subnet != 2)) { end(session); close(adapter); return 34; }
    bool ok = true;
    MIB_IPFORWARD_ROW2 peer_default{}; bool owned_default = false;
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
      MIB_IPFORWARD_ROW2 route{}; InitializeIpForwardEntry(&route);
      route.InterfaceLuid = luid;
      route.DestinationPrefix.Prefix.si_family = static_cast<ADDRESS_FAMILY>(family);
      route.NextHop.si_family = static_cast<ADDRESS_FAMILY>(family);
      route.DestinationPrefix.PrefixLength = family == AF_INET ? 24 : 64;
      const auto network = family == AF_INET ? "100.64." + std::to_string(subnet) + ".0" : "fd00:85:" + std::to_string(subnet) + "::";
      if (family == AF_INET) InetPtonA(AF_INET, network.c_str(), &route.DestinationPrefix.Prefix.Ipv4.sin_addr);
      else InetPtonA(AF_INET6, network.c_str(), &route.DestinationPrefix.Prefix.Ipv6.sin6_addr);
      route.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
      const auto route_code = CreateIpForwardEntry2(&route);
      if (route_code != NO_ERROR && route_code != ERROR_OBJECT_ALREADY_EXISTS) { ok = false; break; }
      bool ready = false;
      for (int retry=0; retry<30; ++retry) {
        if (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred) { ready = true; break; }
        Sleep(500);
      }
      if (!ready) { std::cout << "ADAPTER_DAD_NOT_READY=" << family << std::endl; ok = false; break; }
    }
    if (ok && ipv6_peer_mode) {
      // Both local-address ownership and absence of the synthetic remote are
      // verified before the codec may be armed. This is never a loopback peer.
      MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
      bool source_owned = false, remote_absent = true, no_duplicate_source = true;
      if (GetUnicastIpAddressTable(AF_INET6, &addresses) != NO_ERROR) ok = false;
      if (addresses) {
        for (ULONG i=0; i<addresses->NumEntries; ++i) {
          const auto& row = addresses->Table[i];
          const auto* bytes = reinterpret_cast<const uint8_t*>(&row.Address.Ipv6.sin6_addr);
          if (std::equal(flutter_vless::wireproof::server_address.begin(), flutter_vless::wireproof::server_address.end(), bytes)) remote_absent = false;
          if (std::equal(flutter_vless::wireproof::client_address.begin(), flutter_vless::wireproof::client_address.end(), bytes)) {
            if (row.InterfaceLuid.Value == luid.Value && row.DadState == IpDadStatePreferred) source_owned = true;
            else no_duplicate_source = false;
          }
        }
        FreeMibTable(addresses);
      }
      ok = ok && source_owned && remote_absent && no_duplicate_source;
      MIB_IPINTERFACE_ROW ip{}; InitializeIpInterfaceEntry(&ip); ip.Family=AF_INET6; ip.InterfaceLuid=luid;
      if (ok) {
        ok = GetIpInterfaceEntry(&ip) == NO_ERROR;
        ip.UseAutomaticMetric = FALSE; ip.Metric = 1;
        if (ok) ok = SetIpInterfaceEntry(&ip) == NO_ERROR;
      }
      InitializeIpForwardEntry(&peer_default); peer_default.InterfaceLuid=luid;
      peer_default.DestinationPrefix.Prefix.si_family=AF_INET6;
      peer_default.DestinationPrefix.PrefixLength=0; peer_default.NextHop.si_family=AF_INET6;
      peer_default.Metric=0; peer_default.Protocol=static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
      if (ok) {
        const auto status=CreateIpForwardEntry2(&peer_default);
        owned_default=status==NO_ERROR; ok=owned_default; // never delete a pre-existing row
      }
      if (ok) std::cout << "IPV6_PEER_OWNERSHIP=source-owned,remote-unassigned,default-owned" << std::endl;
    }
    if (ok) {
      std::cout << "ADAPTER_READY=" << luid.Value << std::endl;
      const auto deadline = std::chrono::steady_clock::now() + (ipv6_peer_mode ? std::chrono::seconds(90) : std::chrono::seconds(600));
      const std::string nonce = ipv6_peer_mode ? std::string(arguments[5].begin(), arguments[5].end()) : std::string();
      const auto arm_file = ipv6_peer_mode ? std::filesystem::path(arguments[6]) : std::filesystem::path();
      std::optional<flutter_vless::wireproof::Peer> peer;
      bool peer_complete=false, peer_error=false, peer_ready=false; unsigned controlled=0;
      const auto now_ms=[] { return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count()); };
      auto inject = [&](flutter_vless::wireproof::Result result) {
        if (!result.packet.empty()) {
          auto* target=allocate(session, static_cast<DWORD>(result.packet.size()));
          if (!target) { ok=false; return; }
          std::copy(result.packet.begin(), result.packet.end(), target); send(session,target);
        }
        if (result.error != flutter_vless::wireproof::Error::none && !peer_error) {
          peer_error=true; ok=false; std::cout<<"IPV6_TCP_PEER_ERROR="<<static_cast<int>(result.error)<<std::endl;
        }
        const auto stats=peer->Inspect();
        if (stats.connect_count == 1 && !peer_ready) {
          peer_ready=true; std::cout<<"IPV6_TCP_PEER_READY="<<stats.client_port<<std::endl;
        }
        if (result.complete && !peer_complete) {
          peer_complete=true;
          std::cout<<"IPV6_TCP_PEER_COMPLETE="<<nonce<<","<<stats.syn_count<<","<<stats.authentication_count
              <<","<<stats.connect_count<<","<<stats.challenge_count<<","<<stats.client_port<<","<<static_cast<int>(stats.error)<<std::endl;
        }
      };
      while (!std::filesystem::exists(std::filesystem::path(arguments[4])) && std::chrono::steady_clock::now() < deadline) {
        if (ipv6_peer_mode && !peer && std::filesystem::exists(arm_file)) {
          std::ifstream arm(arm_file, std::ios::binary); std::array<char,33> input{};
          arm.read(input.data(),static_cast<std::streamsize>(input.size()));
          const std::string bytes(input.data(),static_cast<size_t>(arm.gcount()));
          if (bytes != nonce) { ok=false; break; }
          peer.emplace(nonce); std::cout<<"IPV6_TCP_PEER_ARMED="<<nonce<<std::endl;
        }
        if (peer) inject(peer->Poll(now_ms()));
        DWORD size = 0;
        BYTE* packet = receive(session, &size);
        if (!packet) { Sleep(10); continue; }
        // Observe only the owned synthetic prefix/ports, BEFORE Peer filtering.
        // Metadata only: no arbitrary packet payload or user traffic is logged.
        if (ipv6_peer_mode && size>=48 && (packet[0]>>4)==6 && (packet[6]==6 || packet[6]==17)
            && std::equal(flutter_vless::wireproof::client_address.begin(), flutter_vless::wireproof::client_address.end(), packet+8)
            && std::equal(flutter_vless::wireproof::server_address.begin(), flutter_vless::wireproof::server_address.end()-1, packet+24)
            && (packet[39]==2 || packet[39]==3)) {
          const auto port=static_cast<unsigned>((static_cast<unsigned>(packet[42])<<8)|packet[43]);
          const auto source=static_cast<unsigned>((static_cast<unsigned>(packet[40])<<8)|packet[41]);
          if (port==18443 || port==18444) {
            if (++controlled>128) ok=false;
            else std::cout<<"IPV6_SCOPE_PACKET="<<static_cast<unsigned>(packet[6])<<","<<static_cast<unsigned>(packet[39])
                <<","<<port<<","<<source<<","<<(packet[6]==6 && size>=60 ? static_cast<unsigned>(packet[53]) : 0)<<std::endl;
          }
        }
        std::optional<flutter_vless::wireproof::Result> reply;
        if (peer) reply=peer->Receive(packet,size,now_ms());
        // Record only our random control marker, never unrelated packet data.
        const std::string bytes(reinterpret_cast<char*>(packet), size);
        const std::string prefix = "wfp-adapter-control-";
        const auto at = bytes.find(prefix);
        if (at != std::string::npos && bytes.size() >= at + prefix.size() + 32) {
          const auto token = bytes.substr(at + prefix.size(), 32);
          if (token.find_first_not_of("0123456789abcdef") == std::string::npos)
            std::cout << "CONTROL_PACKET=" << token << std::endl;
        }
        release(session, packet); // release receive allocation BEFORE injecting a response
        if (reply) inject(std::move(*reply));
      }
      if (ipv6_peer_mode && !peer_complete) ok=false;
    }
    if (owned_default) {
      const auto status=DeleteIpForwardEntry2(&peer_default);
      auto verify=peer_default;
      const bool removed=(status==NO_ERROR || status==ERROR_NOT_FOUND) && GetIpForwardEntry2(&verify)==ERROR_NOT_FOUND;
      ok=ok && removed; std::cout<<"IPV6_DEFAULT_REMOVED="<<removed<<std::endl;
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
  const bool no_reconnect = action == "run-vpn-no-reconnect";
  const bool routing_requested = action == "run-vpn-routing";
  bool vpn=action=="run-vpn" || no_reconnect || routing_requested;
  if(!vpn && action!="run-proxy")return 2;
  if(vpn && !isolated)return 20;
  auto& manager=V2rayManager::GetInstance();
  flutter_vless::asset_location::Root assets;
  if (arguments.size() > 6) assets = std::filesystem::path(arguments[6]);
  flutter_vless::NativeOptions options; options.reconnect_enabled = !no_reconnect;
  std::optional<flutter_vless::native_routing::NativeRoutingIntent> routing;
  if (routing_requested) routing = flutter_vless::native_routing::NativeRoutingIntent{0, "selected-default"};
  bool started=manager.Start(config,!vpn,options,assets,routing);std::cout<<"START_RETURN="<<started<<std::endl;
  if(!started){manager.Stop();std::cout<<manager.GetProviderDebugSnapshot()<<std::endl;return 3;}
  int seconds=argc>3?std::stoi(argv[3]):20;
  const std::filesystem::path stop_file = arguments.size() > 4 ? arguments[4] : L"";
  const std::filesystem::path state_file = arguments.size() > 5 ? arguments[5] : L"";
  const std::filesystem::path reject_file = state_file.empty() ? L"" : state_file.wstring() + L".reject";
  const std::filesystem::path reject_routing = state_file.empty() ? L"" : state_file.wstring() + L".reject-routing";
  for(int i=0;i<seconds;i++){
    if (!stop_file.empty() && std::filesystem::exists(stop_file)) break;
    if (!reject_file.empty() && std::filesystem::exists(reject_file)) {
      std::ifstream candidate(reject_file);
      const std::string invalid((std::istreambuf_iterator<char>(candidate)), {});
      candidate.close();
      const bool rejected = !manager.Start(invalid, !vpn, options, assets, routing) && manager.IsRunning();
      std::filesystem::remove(reject_file);
      std::cout << "REJECTED_REPLACEMENT_PRESERVED=" << rejected << std::endl;
      if (!rejected) { manager.Stop(); return 26; }
      if (assets) {
        const bool invalid_root_rejected = !manager.Start(config, !vpn, options, *assets / L"missing-asset-root") && manager.IsRunning();
        std::cout << "REJECTED_ASSET_ROOT_PRESERVED=" << invalid_root_rejected << std::endl;
        if (!invalid_root_rejected) { manager.Stop(); return 27; }
      }
    }
    if (routing_requested && !reject_routing.empty() && std::filesystem::exists(reject_routing)) {
      const auto invalid = flutter_vless::native_routing::NativeRoutingIntent{0, "missing-default"};
      const bool rejected = !manager.Start(config, false, options, assets, invalid) && manager.IsRunning();
      std::filesystem::remove(reject_routing);
      std::cout << "REJECTED_ROUTING_PRESERVED=" << rejected << std::endl;
      if (!rejected) { manager.Stop(); return 28; }
    }
    if (!state_file.empty()) {
      const auto traffic = manager.GetTrafficSample();
      std::ofstream state(state_file);
      state << "{\"running\":" << (manager.IsRunning()?"true":"false")
            << ",\"protecting\":" << (manager.IsProtecting()?"true":"false")
            << ",\"tick\":" << i + 1
            << ",\"upload\":" << traffic.upload.value_or(0)
            << ",\"download\":" << traffic.download.value_or(0)
            << ",\"upload_available\":" << (traffic.upload.has_value()?"true":"false")
            << ",\"download_available\":" << (traffic.download.has_value()?"true":"false") << "}";
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
  return (healthy || no_reconnect)?0:4;
}
