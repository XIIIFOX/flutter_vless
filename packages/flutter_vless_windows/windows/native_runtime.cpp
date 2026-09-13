#include "native_runtime.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <algorithm>

namespace flutter_vless::native {
std::wstring Wide(const std::string& s) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (n <= 0) return {};
  std::wstring r(n, 0);
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), r.data(), n);
  return r;
}
std::wstring Quote(const std::wstring& s) {
  std::wstring r = L"\"";
  size_t slashes = 0;
  for (wchar_t c : s) {
    if (c == L'\\') { ++slashes; continue; }
    r.append(slashes * (c == L'"' ? 2 : 1), L'\\');
    slashes = 0;
    if (c == L'"') r += L'\\';
    r += c;
  }
  r.append(slashes * 2, L'\\');
  return r + L'"';
}
std::string RandomHex(size_t count) {
  if (count > 1024) return {};
  std::vector<unsigned char> bytes(count);
  if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(count), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
  const char* hex = "0123456789abcdef";
  std::string s;
  for (auto c : bytes) { s += hex[c >> 4]; s += hex[c & 15]; }
  return s;
}
bool IsAdministrator() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{}; DWORD size = 0;
  bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated;
  CloseHandle(token);
  return ok;
}
static fs::path ApplicationDirectory() {
  std::vector<wchar_t> path(32768);
  DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  return n && n < path.size() ? fs::path(std::wstring(path.data(), n)).parent_path() : fs::path();
}
std::optional<fs::path> FindBundledFile(const wchar_t* name) {
  const auto directory = ApplicationDirectory();
  if (directory.empty()) return std::nullopt;
  // All supported layouts are rooted in the loaded application, never CWD,
  // PATH, AppData or a parent of the application installation.
  for (const auto* suffix : {L"", L"xray", L"data/flutter_assets/xray", L"data/flutter_assets/windows/xray"}) {
    auto candidate = directory / suffix / name;
    std::error_code error;
    if (!fs::is_regular_file(candidate, error)) continue;
    bool safe = true;
    for (auto part = candidate; part != directory; part = part.parent_path()) {
      auto attributes = GetFileAttributesW(part.c_str());
      if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { safe = false; break; }
    }
    if (safe) return candidate;
  }
  return std::nullopt;
}

std::unique_ptr<ProcessHandle> Launch(const fs::path& exe,
    const std::vector<std::wstring>& arguments, bool capture) {
  if (exe.empty() || !exe.is_absolute()) return nullptr;
  // Refuse replacement of the image until CreateProcess has opened it.
  HANDLE image = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (image == INVALID_HANDLE_VALUE) return nullptr;
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(image, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle(image); return nullptr;
  }
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  HANDLE read = nullptr, write = nullptr;
  HANDLE null = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
  if (null == INVALID_HANDLE_VALUE || (capture && !CreatePipe(&read, &write, &security, 0))) {
    if (null != INVALID_HANDLE_VALUE) CloseHandle(null);
    CloseHandle(image); return nullptr;
  }
  if (read) SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = null;
  startup.StartupInfo.hStdOutput = capture ? write : null;
  startup.StartupInfo.hStdError = null;
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<unsigned char> storage(size);
  startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  HANDLE inherited[] = {null, write};
  bool initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size) != FALSE;
  bool attributes = initialized && UpdateProcThreadAttribute(startup.lpAttributeList, 0,
      PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(HANDLE) * (capture ? 2 : 1), nullptr, nullptr);
  std::wstring command = Quote(exe.wstring());
  for (const auto& arg : arguments) command += L" " + Quote(arg);
  PROCESS_INFORMATION process{};
  auto directory = exe.parent_path().wstring();
  // Child jobs also close descendants after an app crash. No raw worker output
  // is forwarded even if the runtime fails before its logging policy is loaded.
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  bool job_ready = job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
  // Imported process environment must not enable runtime key logging, browser
  // dialers, alternate assets, debug traces or an additional HTTP proxy.
  std::vector<wchar_t> environment;
  LPWCH inherited_environment = GetEnvironmentStringsW();
  if (inherited_environment) {
    for (const wchar_t* entry = inherited_environment; *entry; entry += wcslen(entry) + 1) {
      std::wstring item(entry), key = item.substr(0, item.find(L'='));
      std::transform(key.begin(), key.end(), key.begin(), towupper);
      if (key.rfind(L"XRAY", 0) == 0 || key == L"SSLKEYLOGFILE" || key == L"GODEBUG"
          || key == L"GOTRACEBACK" || key == L"HTTP_PROXY" || key == L"HTTPS_PROXY"
          || key == L"ALL_PROXY" || key == L"NO_PROXY" || key == L"PATH") continue;
      environment.insert(environment.end(), item.begin(), item.end()); environment.push_back(0);
    }
    FreeEnvironmentStringsW(inherited_environment);
  }
  wchar_t system_directory[MAX_PATH + 1]{};
  if (GetSystemDirectoryW(system_directory, MAX_PATH)) {
    const std::wstring path = L"PATH=" + std::wstring(system_directory);
    environment.insert(environment.end(), path.begin(), path.end()); environment.push_back(0);
  }
  environment.push_back(0);
  if (environment.size() == 1) environment.push_back(0);
  bool ok = attributes && job_ready && CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
      environment.data(), directory.c_str(),
      &startup.StartupInfo, &process);
  if (ok && !AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 1);
    CloseHandle(process.hProcess); CloseHandle(process.hThread); ok = false;
  }
  if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
  CloseHandle(image); CloseHandle(null);
  if (write) CloseHandle(write);
  if (!ok) { if (read) CloseHandle(read); if (job) CloseHandle(job); return nullptr; }
  auto result = std::make_unique<ProcessHandle>();
  result->hProcess = reinterpret_cast<std::uintptr_t>(process.hProcess);
  result->hThread = reinterpret_cast<std::uintptr_t>(process.hThread);
  result->hJob = reinterpret_cast<std::uintptr_t>(job);
  result->hStdOutRead = reinterpret_cast<std::uintptr_t>(read);
  if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) return nullptr;
  return result;
}
bool Command(const fs::path& exe, const std::vector<std::wstring>& arguments,
             std::string& output, unsigned timeout) {
  output.clear();
  auto process = Launch(exe, arguments, true);
  if (!process) return false;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
  HANDLE read = reinterpret_cast<HANDLE>(process->hStdOutRead);
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(read, nullptr, 0, nullptr, &available, nullptr) && available) {
      char buffer[4096]; DWORD count = 0;
      if (!ReadFile(read, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr)) return false;
      if (output.size() + count > 128 * 1024) return false;
      output.append(buffer, count);
      continue;
    }
    if (!process->IsRunning()) {
      DWORD code = 1; GetExitCodeProcess(reinterpret_cast<HANDLE>(process->hProcess), &code);
      return code == 0;
    }
    if (std::chrono::steady_clock::now() >= deadline) return false;
    Sleep(10);
  }
}
bool SystemCommand(const wchar_t* name, const std::vector<std::wstring>& arguments) {
  wchar_t directory[MAX_PATH + 1]{};
  UINT n = GetSystemDirectoryW(directory, MAX_PATH);
  if (!n || n >= MAX_PATH) return false;
  std::string ignored;
  return Command(fs::path(directory) / name, arguments, ignored, 15000);
}
bool WritePrivateConfig(const std::string& config, fs::path& path) {
  // Protected DACL grants the current logon owner and LocalSystem access only.
  // CREATE_NEW prevents link/truncation attacks and random names avoid clashes.
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<unsigned char> storage(size);
  bool ok = GetTokenInformation(token, TokenUser, storage.data(), size, &size) != FALSE;
  CloseHandle(token);
  LPWSTR sid = nullptr;
  if (!ok || !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid, &sid)) return false;
  std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  const auto random = RandomHex(32);
  if (random.empty()) { LocalFree(descriptor); return false; }
  try { path = fs::temp_directory_path() / (L"flutter-vless-" + Wide(random) + L".json"); }
  catch (...) { LocalFree(descriptor); return false; }
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &security, CREATE_NEW,
      FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  LocalFree(descriptor);
  if (file == INVALID_HANDLE_VALUE) { path.clear(); return false; }
  DWORD written = 0;
  ok = config.size() <= 16 * 1024 * 1024 && WriteFile(file, config.data(), static_cast<DWORD>(config.size()), &written, nullptr)
      && written == config.size() && FlushFileBuffers(file);
  CloseHandle(file);
  if (!ok) RemovePrivateConfig(path);
  return ok;
}
void RemovePrivateConfig(fs::path& path) {
  if (path.empty()) return;
  if (DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND) path.clear();
}
bool SocksReady(uint16_t port, const std::string& user, const std::string& password) {
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2,2), &data)) return false;
  SOCKET socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_ == INVALID_SOCKET) { WSACleanup(); return false; }
  DWORD timeout = 500;
  setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
  setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
  sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
  InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr);
  bool ok = connect(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
  auto exchange = [&](const std::string& request, unsigned char expected0, unsigned char expected1) {
    if (!ok || send(socket_, request.data(), static_cast<int>(request.size()), 0) != static_cast<int>(request.size())) return false;
    unsigned char reply[2]{}; size_t got = 0;
    while (got < 2) { int n = recv(socket_, reinterpret_cast<char*>(reply) + got, static_cast<int>(2-got), 0); if (n <= 0) return false; got += n; }
    return reply[0] == expected0 && reply[1] == expected1;
  };
  const unsigned char method = user.empty() ? 0 : 2;
  ok = exchange(std::string({5, 1, static_cast<char>(method)}), 5, method);
  if (ok && method == 2) {
    if (user.size() > 255 || password.size() > 255) ok = false;
    else ok = exchange(std::string({1, static_cast<char>(user.size())}) + user + static_cast<char>(password.size()) + password, 1, 0);
  }
  closesocket(socket_); WSACleanup(); return ok;
}
}  // namespace flutter_vless::native
