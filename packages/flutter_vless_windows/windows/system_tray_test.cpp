#include "system_tray.h"
#include <cassert>
#include <iostream>
int main() {
  HWND window=CreateWindowExW(0,L"STATIC",L"Vless control fixture",WS_OVERLAPPEDWINDOW,0,0,320,200,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
  assert(window); int toggles=0, opens=0;
  {
    flutter_vless::SystemTray tray(window,[&] { ++toggles; },[&] { ++opens; });
    flutter_vless::NativeOptions options; options.quick_enabled=true;
    assert(tray.Configure(options));
    const auto callback=RegisterWindowMessageW(L"flutter_vless.tray.v1");
    assert(tray.Handle(callback,NIN_SELECT)); assert(toggles==1);
    tray.Refresh(true,true); tray.Handle(callback,NIN_SELECT); assert(toggles==1);
    tray.Refresh(true,false); tray.Handle(callback,NIN_KEYSELECT); assert(toggles==2);
    options.quick_action="openApp"; assert(tray.Configure(options)); tray.Handle(callback,NIN_SELECT); assert(opens==1);
    auto invalid=options; invalid.windows_icon="C:\\missing-vless-icon.ico"; assert(!tray.Configure(invalid));
    tray.Handle(callback,NIN_SELECT); assert(opens==2);
    tray.Handle(RegisterWindowMessageW(L"TaskbarCreated"),0);
    options.quick_enabled=false; assert(tray.Configure(options));
  }
  DestroyWindow(window);
  std::cout << "PASS native Windows tray: Shell notification icon, toggle/open callbacks, pending action, icon error, Explorer recovery and cleanup\n";
}
