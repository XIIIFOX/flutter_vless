#include "protected_runtime.h"
#include <sddl.h>
#include <array>
#include <future>

namespace flutter_vless::native {
namespace {
using Clock = std::chrono::steady_clock;
std::chrono::milliseconds Milliseconds(Clock::duration duration) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(duration);
}

bool UsesProcessToken() {
  // A copy thread would otherwise use the process identity in place of an
  // impersonating caller's token. Keep those calls on the calling thread.
  HANDLE token = nullptr;
  if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    return GetLastError() == ERROR_NO_TOKEN;
  }
  CloseHandle(token);
  return false;
}

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
bool CopyImage(const fs::path& source, const fs::path& destination, RuntimeFileTiming* timing) {
  const auto started = Clock::now();
  HANDLE input = CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (input == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(input, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle(input); return false;
  }
  HANDLE output = NewFile(destination);
  if (output == INVALID_HANDLE_VALUE) { CloseHandle(input); return false; }
  const auto opened = Clock::now();
  std::array<char, 256 * 1024> bytes;
  DWORD count = 0, written = 0;
  bool ok = true;
  while (ok) {
    if (!ReadFile(input, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)) { ok = false; break; }
    if (!count) break;
    ok = WriteFile(output, bytes.data(), count, &written, nullptr) && written == count;
  }
  const auto copied = Clock::now();
  ok = ok && FlushFileBuffers(output);
  const auto flushed = Clock::now();
  CloseHandle(output); CloseHandle(input);
  if (timing) {
    *timing = {Milliseconds(opened - started), Milliseconds(copied - opened),
        Milliseconds(flushed - copied), Milliseconds(Clock::now() - flushed), ok};
  }
  return ok;
}
}
ProtectedRuntime::~ProtectedRuntime() {
  if (directory_handle_ != INVALID_HANDLE_VALUE) CloseHandle(directory_handle_);
  if (!directory_.empty()) { std::error_code error; fs::remove_all(directory_, error); }
}
bool ProtectedRuntime::Create(const fs::path& bundled_xray, bool copy_geo_assets,
    RuntimeSnapshotTiming* timing) {
  const auto started = Clock::now();
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
  if (timing) timing->directory = Milliseconds(Clock::now() - started);
  const auto copy_xray = [&] {
    return CopyImage(bundled_xray, Executable(), timing ? &timing->xray : nullptr);
  };
  if (!copy_geo_assets) return copy_xray();
  const auto copy_asset = [&](const wchar_t* asset, RuntimeFileTiming* asset_timing) {
    const auto source = bundled_xray.parent_path() / asset;
    std::error_code error;
    return !fs::exists(source, error) || CopyImage(source, directory_ / asset, asset_timing);
  };
  if (!UsesProcessToken()) {
    return copy_xray() && copy_asset(L"geoip.dat", timing ? &timing->geoip : nullptr) &&
        copy_asset(L"geosite.dat", timing ? &timing->geosite : nullptr);
  }

  // Each file still has its own protected destination and flush. Wait for
  // both GeoDAT copies even if another copy fails, before validation or cleanup.
  const auto policy = std::launch::async | std::launch::deferred;
  auto geoip = std::async(policy, copy_asset, L"geoip.dat", timing ? &timing->geoip : nullptr);
  auto geosite = std::async(policy, copy_asset, L"geosite.dat", timing ? &timing->geosite : nullptr);
  const bool xray_ready = copy_xray();
  const bool geoip_ready = geoip.get();
  const bool geosite_ready = geosite.get();
  return xray_ready && geoip_ready && geosite_ready;
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
