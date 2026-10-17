#ifndef FLUTTER_VLESS_SYSTEM_TRAY_H_
#define FLUTTER_VLESS_SYSTEM_TRAY_H_
#include <windows.h>
#include <shellapi.h>
#include <functional>
#include <string>
#include "native_options.h"
#include "native_runtime.h"

namespace flutter_vless {
/// UI-thread owner of a single notification-area icon. No network work here.
class SystemTray {
 public:
  SystemTray(HWND window, std::function<void()> toggle, std::function<void()> open)
      : window_(window), toggle_(std::move(toggle)), open_(std::move(open)) {
    callback_ = RegisterWindowMessageW(L"flutter_vless.tray.v1");
    taskbar_created_ = RegisterWindowMessageW(L"TaskbarCreated");
  }
  ~SystemTray() { Remove(); if (owned_icon_) DestroyIcon(owned_icon_); }
  bool Configure(const NativeOptions& options) {
    HICON custom = nullptr;
    if (options.quick_enabled && !options.windows_icon.empty()) {
      custom = static_cast<HICON>(LoadImageW(nullptr, native::Wide(options.windows_icon).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE));
      if (!custom) return false;
    }
    Remove(); if (owned_icon_) DestroyIcon(owned_icon_);
    owned_icon_ = custom; options_ = options;
    return !options_.quick_enabled || Add();
  }
  void Refresh(bool active, bool pending = false) {
    active_ = active; pending_ = pending;
    if (!added_) return;
    auto data = Data(); Shell_NotifyIconW(NIM_MODIFY, &data);
  }
  bool Handle(UINT message, LPARAM parameter) {
    if (message == taskbar_created_) { if (options_.quick_enabled) { Remove(); Add(); } return false; }
    if (message != callback_) return false;
    if (!options_.quick_enabled) return true;
    const auto event = LOWORD(parameter);
    if (event == NIN_SELECT || event == NIN_KEYSELECT) {
      if (!pending_) { if (options_.quick_action == "openApp") open_(); else toggle_(); }
    } else if (event == WM_CONTEXTMENU) {
      HMENU menu = CreatePopupMenu(); if (!menu) return true;
      AppendMenuW(menu, MF_STRING | (pending_ ? MF_GRAYED : 0), 1,
          options_.quick_action == "openApp" ? L"Open app" : (active_ ? L"Disconnect" : L"Connect"));
      AppendMenuW(menu, MF_STRING, 2, L"Open app");
      POINT point{}; GetCursorPos(&point); SetForegroundWindow(window_);
      const auto choice = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, point.x, point.y, 0, window_, nullptr);
      DestroyMenu(menu); PostMessageW(window_, WM_NULL, 0, 0);
      if (choice == 1 && !pending_) { if (options_.quick_action == "openApp") open_(); else toggle_(); }
      else if (choice == 2) open_();
    }
    return true;
  }
 private:
  NOTIFYICONDATAW Data() const {
    NOTIFYICONDATAW data{}; data.cbSize = sizeof(data); data.hWnd = window_; data.uID = 0x766c6573;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP; data.uCallbackMessage = callback_;
    data.hIcon = owned_icon_ ? owned_icon_ : reinterpret_cast<HICON>(GetClassLongPtrW(window_, GCLP_HICONSM));
    if (!data.hIcon) data.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    const auto tip = native::Wide(options_.label) + (pending_ ? L": Working" : (active_ ? L": Active" : L": Disconnected"));
    wcsncpy_s(data.szTip, tip.c_str(), _TRUNCATE);
    return data;
  }
  bool Add() {
    if (!window_ || !callback_) return false;
    auto data = Data(); added_ = Shell_NotifyIconW(NIM_ADD, &data) != FALSE;
    if (added_) { data.uVersion = NOTIFYICON_VERSION_4; Shell_NotifyIconW(NIM_SETVERSION, &data); }
    return added_;
  }
  void Remove() { if (added_) { auto data = Data(); Shell_NotifyIconW(NIM_DELETE, &data); added_ = false; } }
  HWND window_; UINT callback_ = 0, taskbar_created_ = 0;
  HICON owned_icon_ = nullptr; bool added_ = false, active_ = false, pending_ = false;
  NativeOptions options_; std::function<void()> toggle_, open_;
};
}
#endif
