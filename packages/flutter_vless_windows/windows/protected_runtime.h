#pragma once
#include <winsock2.h>
#include <windows.h>
#include "native_runtime.h"

namespace flutter_vless::native {
// WFP application identity is a path, not a process id. Use a per-session image
// that unelevated processes cannot execute, replace, or take ownership of.
class ProtectedRuntime {
 public:
  ~ProtectedRuntime();
  bool Create(const fs::path& bundled_xray);
  bool WriteConfig(const std::string& data, fs::path& path);
  fs::path Executable() const { return directory_ / L"xray.exe"; }
  fs::path Directory() const { return directory_; }
 private:
  fs::path directory_;
  HANDLE directory_handle_ = INVALID_HANDLE_VALUE;
};
}  // namespace flutter_vless::native
