#include "protected_runtime.h"
#include <sddl.h>
#include <array>

namespace flutter_vless::native {
namespace {
class AdministratorDescriptor {
 public:
  AdministratorDescriptor() {
    // The owner must be Administrators too: a TokenUser owner could rewrite the
    // DACL from its filtered token even without an explicit access ACE.
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &value_, nullptr);
  }
  ~AdministratorDescriptor() { if (value_) LocalFree(value_); }
  PSECURITY_DESCRIPTOR Get() const { return value_; }
 private:
  PSECURITY_DESCRIPTOR value_ = nullptr;
};
HANDLE NewFile(const fs::path& path) {
  AdministratorDescriptor descriptor;
  if (!descriptor.Get()) return INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor.Get(), FALSE};
  return CreateFileW(path.c_str(), GENERIC_WRITE, 0, &security, CREATE_NEW,
      FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
}
bool CopyImage(const fs::path& source, const fs::path& destination) {
  HANDLE input = CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (input == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(input, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle(input); return false;
  }
  HANDLE output = NewFile(destination);
  if (output == INVALID_HANDLE_VALUE) { CloseHandle(input); return false; }
  std::array<char, 64 * 1024> bytes{};
  DWORD count = 0, written = 0;
  bool ok = true;
  while (ok) {
    if (!ReadFile(input, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)) { ok = false; break; }
    if (!count) break;
    ok = WriteFile(output, bytes.data(), count, &written, nullptr) && written == count;
  }
  ok = ok && FlushFileBuffers(output);
  CloseHandle(output); CloseHandle(input);
  return ok;
}
}
ProtectedRuntime::~ProtectedRuntime() {
  if (directory_handle_ != INVALID_HANDLE_VALUE) CloseHandle(directory_handle_);
  if (!directory_.empty()) { std::error_code error; fs::remove_all(directory_, error); }
}
bool ProtectedRuntime::Create(const fs::path& bundled_xray) {
  if (!directory_.empty() || !IsAdministrator()) return false;
  wchar_t windows[32768]{};
  if (!GetWindowsDirectoryW(windows, 32768)) return false;
  const auto random = RandomHex(32);
  AdministratorDescriptor descriptor;
  if (random.empty() || !descriptor.Get()) return false;
  auto directory = fs::path(windows) / L"Temp" / (L"flutter-vless-protected-" + Wide(random));
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor.Get(), FALSE};
  if (!CreateDirectoryW(directory.c_str(), &security)) return false;
  directory_ = directory;
  directory_handle_ = CreateFileW(directory_.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (directory_handle_ == INVALID_HANDLE_VALUE) return false;
  if (!CopyImage(bundled_xray, Executable())) return false;
  for (const auto* asset : {L"geoip.dat", L"geosite.dat"}) {
    auto source = bundled_xray.parent_path() / asset;
    std::error_code error;
    if (fs::exists(source, error) && !CopyImage(source, directory_ / asset)) return false;
  }
  return true;
}
bool ProtectedRuntime::WriteConfig(const std::string& data, fs::path& path) {
  if (directory_.empty() || data.size() > 16 * 1024 * 1024) return false;
  const auto random = RandomHex(32);
  if (random.empty()) return false;
  path = directory_ / (Wide(random) + L".json");
  HANDLE file = NewFile(path);
  if (file == INVALID_HANDLE_VALUE) { path.clear(); return false; }
  DWORD written = 0;
  const bool ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr)
      && written == data.size() && FlushFileBuffers(file);
  CloseHandle(file);
  if (!ok) RemovePrivateConfig(path);
  return ok;
}
}  // namespace flutter_vless::native
