#ifndef FLUTTER_VLESS_NATIVE_RUNTIME_H_
#define FLUTTER_VLESS_NATIVE_RUNTIME_H_
#include "proxy_service.h"
#include "asset_location.h"
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
    const std::vector<std::wstring>& arguments, bool capture = false,
    const asset_location::Root& assets = std::nullopt);
bool Command(const fs::path& executable, const std::vector<std::wstring>& arguments,
    std::string& output, unsigned timeout_ms = 3000, const asset_location::Root& assets = std::nullopt);
bool SystemCommand(const wchar_t* name, const std::vector<std::wstring>& arguments);
bool WritePrivateConfig(const std::string& config, fs::path& path);
void RemovePrivateConfig(fs::path& path);
// Pinned Core decode/build/creation check, without starting listeners or routes.
// The temporary document is privacy-normalized and always removed. VPN checks
// require the administrator-owned runtime directory, including against a
// filtered token belonging to the same signed-in Windows user.
// Raw child output is discarded. No active service is stopped by this function.
enum class ConfigCheckStorage { currentUser, administrators };
bool CheckConfig(const std::string& config, const fs::path& executable,
    ConfigCheckStorage storage, const asset_location::Root& assets = std::nullopt);
// Final VPN check: no normalization, reserialization or executable copy.
// The caller owns the returned private file on both success and failure and
// launches this same file with this same protected executable after success.
class ProtectedRuntime;
bool CheckPreparedConfig(const std::string& config, ProtectedRuntime& runtime,
    fs::path& path, const asset_location::Root& assets = std::nullopt);
bool SocksReady(uint16_t port, const std::string& user = {}, const std::string& password = {});
}  // namespace flutter_vless::native
#endif
