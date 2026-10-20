#include <windows.h>
#include <functional>
static std::function<BOOL()> menu_selection;
static BOOL SelectMenu(HMENU, UINT, int, int, int, HWND, const RECT*) {
  return menu_selection ? menu_selection() : 0;
}
// Exercise the real tray body with deterministic nested-message reentry.
#define TrackPopupMenu SelectMenu
#include "system_tray.h"
#undef TrackPopupMenu
#include <cassert>
#include <iostream>
int main() {
  HWND window=CreateWindowExW(0,L"STATIC",L"Vless control fixture",WS_OVERLAPPEDWINDOW,0,0,320,200,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
  assert(window); int toggles=0, opens=0;
  {
    flutter_vless::SystemTray tray(window,[&](bool) { ++toggles; },[&] { ++opens; });
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
  {
    int toggles=0, opens=0; std::uint64_t profile_revision=0; bool expected_active=false;
    flutter_vless::SystemTray tray(window,[&](bool active) { ++toggles; expected_active=active; },
        [&] { ++opens; },[&] { return profile_revision; });
    flutter_vless::NativeOptions options; options.quick_enabled=true;
    assert(tray.Configure(options)); const auto callback=RegisterWindowMessageW(L"flutter_vless.tray.v1");
    auto popup=[&] { tray.Handle(callback,WM_CONTEXTMENU); };
    menu_selection=[] { return 1; }; popup(); assert(toggles==1 && !expected_active);
    options.quick_action="openApp"; assert(tray.Configure(options));
    menu_selection=[&] { options.quick_action="toggle"; assert(tray.Configure(options)); return 1; };
    popup(); assert(toggles==1 && opens==0); // Displayed Open app never becomes toggle.
    menu_selection=[&] { options.quick_enabled=false; assert(tray.Configure(options)); return 1; };
    popup(); assert(toggles==1);
    options.quick_enabled=true; assert(tray.Configure(options));
    menu_selection=[&] { options.quick_enabled=false; assert(tray.Configure(options)); return 2; };
    popup(); assert(opens==0);
    options.quick_enabled=true; assert(tray.Configure(options));
    menu_selection=[&] { options.require_unlock=!options.require_unlock; assert(tray.Configure(options)); return 1; };
    popup(); assert(toggles==1);
    menu_selection=[&] { options.quick_action="openApp"; assert(tray.Configure(options)); options.quick_action="toggle"; assert(tray.Configure(options)); return 1; };
    popup(); assert(toggles==1); // An A-to-B-to-A policy change also revokes the menu.
    menu_selection=[&] { ++profile_revision; return 1; }; popup(); assert(toggles==1);
    menu_selection=[&] { tray.Refresh(true); return 1; }; popup(); assert(toggles==1);
    menu_selection=[&] { options.label="Updated label"; assert(tray.Configure(options)); return 1; };
    popup(); assert(toggles==2 && expected_active); // Unrelated presentation writes remain valid.
    tray.Refresh(true,true); menu_selection=[] { return 2; }; popup(); assert(opens==1);
    menu_selection={};
    std::cout << "WINDOWS_TRAY_REVISION_PASS=10\n";
  }
  DestroyWindow(window);
  std::cout << "PASS native Windows tray: Shell notification icon, toggle/open callbacks, pending action, icon error, Explorer recovery and cleanup\n";
}
