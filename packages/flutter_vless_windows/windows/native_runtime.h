#ifndef FLUTTER_VLESS_NATIVE_RUNTIME_H_
#define FLUTTER_VLESS_NATIVE_RUNTIME_H_
#include "proxy_service.h"
#include <functional>

namespace flutter_vless::native {
std::optional<fs::path> FindBundledFile(const wchar_t* name);
std::wstring Quote(const std::wstring& value);
std::wstring Wide(const std::string& value);
std::string RandomHex(size_t bytes);
bool IsAdministrator();
// No shell, search path, global environment changes or inherited host handles.
// Long-lived workers discard raw output; only fixed lifecycle events are logged.
std::unique_ptr<ProcessHandle> Launch(const fs::path& executable,
    const std::vector<std::wstring>& arguments, bool capture = false);
bool Command(const fs::path& executable, const std::vector<std::wstring>& arguments,
    std::string& output, unsigned timeout_ms = 3000);
bool SystemCommand(const wchar_t* name, const std::vector<std::wstring>& arguments);
bool WritePrivateConfig(const std::string& config, fs::path& path);
void RemovePrivateConfig(fs::path& path);
bool SocksReady(uint16_t port, const std::string& user = {}, const std::string& password = {});
}  // namespace flutter_vless::native
#endif
