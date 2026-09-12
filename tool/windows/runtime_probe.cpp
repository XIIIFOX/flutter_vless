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
#include "windows_network.h"
int main(int argc,char** argv) {
  if(argc<2)return 2;
  std::string action=argv[1];
  if(action=="gateway") {
    const auto gateway = flutter_vless::DefaultIpv4Gateway();
    std::cout << gateway << std::endl;
    return gateway.empty() ? 5 : 0;
  }
  if(action=="wintun") {
    HMODULE dll=LoadLibraryW(L"wintun.dll");
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
  std::ifstream input(argv[2]);std::string config((std::istreambuf_iterator<char>(input)),{});
  bool vpn=action=="run-vpn";
  if(!vpn && action!="run-proxy")return 2;
  auto& manager=V2rayManager::GetInstance();
  bool started=manager.Start(config,!vpn);std::cout<<"START_RETURN="<<started<<std::endl;
  if(!started)return 3;
  int seconds=argc>3?std::stoi(argv[3]):20;
  bool healthy=true;
  const std::filesystem::path stop_file = argc > 4 ? argv[4] : "";
  for(int i=0;i<seconds;i++){
    if (!stop_file.empty() && std::filesystem::exists(stop_file)) break;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if(i>=3 && !manager.IsRunning()){healthy=false;break;}
    std::cout<<"RUNNING="<<manager.IsRunning()<<" SECOND="<<i+1<<std::endl;
  }
  manager.Stop();std::cout<<"STOPPED="<<!manager.IsRunning()<<std::endl;
  std::cout<<manager.GetProviderDebugSnapshot()<<std::endl;
  return healthy?0:4;
}
