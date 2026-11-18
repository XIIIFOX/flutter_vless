#include "native_runtime.h"
#include "protected_runtime.h"
#include "xray_config.h"
#include "native_routing_protocol.h"
#include "balancer_selection_protocol.h"
#include "managed_service_capabilities.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <algorithm>
#include <regex>

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
    const std::vector<std::wstring>& arguments, bool capture, const asset_location::Root& assets,
    bool parent_stdin, unsigned stdout_buffer_bytes) {
  if (exe.empty() || !exe.is_absolute() || !asset_location::Valid(assets)) return nullptr;
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
  HANDLE input_read = nullptr, input_write = nullptr;
  HANDLE null = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
  if (null == INVALID_HANDLE_VALUE || (capture && !CreatePipe(&read, &write, &security, stdout_buffer_bytes))) {
    if (null != INVALID_HANDLE_VALUE) CloseHandle(null);
    CloseHandle(image); return nullptr;
  }
  if (read && !SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle(read); CloseHandle(write); CloseHandle(null); CloseHandle(image); return nullptr;
  }
  if (parent_stdin && (!CreatePipe(&input_read, &input_write, &security, 0)
      || !SetHandleInformation(input_write, HANDLE_FLAG_INHERIT, 0))) {
    if (input_read) CloseHandle(input_read);
    if (input_write) CloseHandle(input_write);
    if (read) CloseHandle(read);
    if (write) CloseHandle(write);
    CloseHandle(null); CloseHandle(image); return nullptr;
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = parent_stdin ? input_read : null;
  startup.StartupInfo.hStdOutput = capture ? write : null;
  startup.StartupInfo.hStdError = null;
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<unsigned char> storage(size);
  startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  std::vector<HANDLE> inherited{null};
  if (capture) inherited.push_back(write);
  if (parent_stdin) inherited.push_back(input_read);
  bool initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size) != FALSE;
  bool attributes = initialized && UpdateProcThreadAttribute(startup.lpAttributeList, 0,
      PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(HANDLE) * inherited.size(), nullptr, nullptr);
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
  std::vector<std::wstring> inherited_values;
  LPWCH inherited_environment = GetEnvironmentStringsW();
  if (inherited_environment) {
    for (const wchar_t* entry = inherited_environment; *entry; entry += wcslen(entry) + 1) {
      inherited_values.emplace_back(entry);
    }
    FreeEnvironmentStringsW(inherited_environment);
  }
  wchar_t system_directory[MAX_PATH + 1]{};
  const auto trusted_system = GetSystemDirectoryW(system_directory, MAX_PATH) ? std::wstring(system_directory) : L"";
  auto environment = asset_location::ChildEnvironment(inherited_values, trusted_system, assets);
  bool ok = attributes && job_ready && CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
      environment.data(), directory.c_str(),
      &startup.StartupInfo, &process);
  if (ok && !AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, 3000);
    CloseHandle(process.hProcess); CloseHandle(process.hThread); ok = false;
  }
  if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
  CloseHandle(image); CloseHandle(null);
  if (write) CloseHandle(write);
  if (input_read) CloseHandle(input_read);
  if (!ok) {
    if (input_write) CloseHandle(input_write);
    if (read) CloseHandle(read);
    if (job) CloseHandle(job);
    return nullptr;
  }
  auto result = std::make_unique<ProcessHandle>();
  result->hProcess = reinterpret_cast<std::uintptr_t>(process.hProcess);
  result->hThread = reinterpret_cast<std::uintptr_t>(process.hThread);
  result->hJob = reinterpret_cast<std::uintptr_t>(job);
  result->hStdOutRead = reinterpret_cast<std::uintptr_t>(read);
  result->hStdInWrite = reinterpret_cast<std::uintptr_t>(input_write);
  if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) return nullptr;
  return result;
}
bool Command(const fs::path& exe, const std::vector<std::wstring>& arguments,
    std::string& output, unsigned timeout, const asset_location::Root& assets) {
  output.clear();
  auto process = Launch(exe, arguments, true, assets);
  if (!process) return false;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
  HANDLE read = reinterpret_cast<HANDLE>(process->hStdOutRead);
  for (;;) {
    // Continuous output must not postpone the same command deadline.
    if (std::chrono::steady_clock::now() >= deadline) return false;
    // Check process state first so a just-exited capability probe cannot
    // lose bytes written between peeking its pipe and observing its exit.
    const bool running = process->IsRunning();
    DWORD available = 0;
    if (PeekNamedPipe(read, nullptr, 0, nullptr, &available, nullptr) && available) {
      char buffer[4096]; DWORD count = 0;
      if (!ReadFile(read, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr)) return false;
      if (output.size() + count > 128 * 1024) return false;
      output.append(buffer, count);
      continue;
    }
    if (!running) {
      DWORD code = 1; GetExitCodeProcess(reinterpret_cast<HANDLE>(process->hProcess), &code);
      return code == 0;
    }
    Sleep(10);
  }
}

static bool CommandCapability(const fs::path& image, const wchar_t* command,
    const asset_location::Root& assets = std::nullopt) {
  std::string output;
  return Command(image, {command, L"capabilities"}, output, 3000, assets)
      && native_routing::SuccessfulReply(output, "capabilities", true);
}

bool BalancerCapability(const ProtectedRuntime& runtime, const asset_location::Root& assets) {
  return CommandCapability(runtime.Executable(), L"native-balancer", assets);
}

bool BundledBalancerCapability() try {
  if (!IsAdministrator()) return false; // This capability belongs to VPN mode.
  const auto executable = FindBundledFile(L"xray.exe");
  ProtectedRuntime runtime;
  return executable && runtime.Create(*executable, false) && BalancerCapability(runtime);
} catch (...) { return false; }

namespace {
bool SendBalancerCommand(const ProcessHandle& process, std::string_view command) {
  if (!process.hStdInWrite || !process.hStdOutRead || !process.IsRunning()) return false;
  DWORD written = 0;
  return WriteFile(reinterpret_cast<HANDLE>(process.hStdInWrite), command.data(),
      static_cast<DWORD>(command.size()), &written, nullptr) && written == command.size();
}

std::optional<std::string> ReadBalancerLine(const ProcessHandle& process, size_t limit,
    std::chrono::steady_clock::time_point deadline, const std::function<bool()>& cancelled) {
  if (!process.hStdOutRead) return std::nullopt;
  const auto handle = reinterpret_cast<HANDLE>(process.hStdOutRead);
  std::string frame;
  while (std::chrono::steady_clock::now() < deadline && (!cancelled || !cancelled()) && process.IsRunning()) {
    DWORD available = 0;
    if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr)) return std::nullopt;
    if (!available) { Sleep(5); continue; }
    char buffer[4096]; DWORD count = 0;
    if (!ReadFile(handle, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr)
        || !count || frame.size() + count > limit) return std::nullopt;
    frame.append(buffer, count);
    const auto newline = frame.find('\n');
    if (newline == std::string::npos) continue;
    if (newline + 1 != frame.size()) return std::nullopt;
    frame.pop_back();
    return frame;
  }
  return std::nullopt;
}
}  // namespace

std::optional<std::string> ReadBalancerSelections(const ProcessHandle& process,
    bool expect_started, size_t max_rows, size_t max_bytes, const std::function<bool()>& cancelled,
    std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  if (expect_started) {
    const auto response = ReadBalancerLine(process, 128, deadline, cancelled);
    if (!response || !native_routing::SuccessfulReply(*response, "started")) return std::nullopt;
  }
  if ((cancelled && cancelled()) || std::chrono::steady_clock::now() >= deadline
      || !SendBalancerCommand(process, balancer_selection::kSnapshotCommand)) return std::nullopt;
  const auto response = ReadBalancerLine(process, balancer_selection::kMaxReplyBytes, deadline, cancelled);
  return response ? balancer_selection::ParseReply(*response, max_rows, max_bytes) : std::nullopt;
}

void DisableBalancerSelections(const ProcessHandle& process) {
  // Even after a failed snapshot there can be only one preceding request.
  // Send one small opt-out without waiting on an unpublished response.
  SendBalancerCommand(process, balancer_selection::kDisableCommand);
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
static unsigned ManagedServiceBits(const fs::path& image, const asset_location::Root& assets = std::nullopt) {
  std::string output;
  return Command(image, {L"native-services", L"capabilities"}, output, 3000, assets)
      ? managed_services::ParseCapabilities(output) : 0;
}

static bool ManagedServicesAllowed(const xray_config::Json& config, const fs::path& executable, const asset_location::Root& assets) {
  const auto required = managed_services::Required(config);
  if (!required) return true;
  if ((required & ManagedServiceBits(executable, assets)) != required) return false;
  return !(required & managed_services::kGeodata) || geodata_assets::ValidateWritable(config, assets.value_or(executable.parent_path()));
}

static bool IsLocalInspectionPath(const fs::path& input) {
  // Inspect only local files. A UNC path, mapped drive or directory reparse
  // point can otherwise cause network I/O even during a filesystem check.
  const auto path = input.lexically_normal();
  const auto name = path.root_name().native();
  if (!path.is_absolute() || name.size() != 2 || name[1] != L':'
      || path.native().find(L'\0') != std::wstring::npos) return false;
  const auto drive = GetDriveTypeW(path.root_path().c_str());
  if (drive == DRIVE_UNKNOWN || drive == DRIVE_NO_ROOT_DIR || drive == DRIVE_REMOTE) return false;
  auto part = path.root_path();
  for (const auto& component : path.relative_path()) {
    if (component.native().find(L':') != std::wstring::npos) return false;
    part /= component;
    const auto flags = GetFileAttributesW(part.c_str());
    if (flags == INVALID_FILE_ATTRIBUTES) {
      const auto error = GetLastError();
      return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    if (flags & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) return false;
  }
  return true;
}

static bool HasProfileCompiler(const fs::path& image) {
  std::string help;
  return Command(image, {L"help", L"convert", L"pb"}, help)
      && help.find("-debug") != std::string::npos;
}

CoreCapabilities InspectBundledCore() try {
  const auto executable = FindBundledFile(L"xray.exe");
  if (!executable || !IsLocalInspectionPath(*executable)) return {};
  ProtectedRuntime isolated;
  auto image = *executable;
  if (IsAdministrator()) {
    if (!isolated.Create(image, false)) return {};
    image = isolated.Executable();
  }

  std::string output;
  std::smatch version;
  static const std::regex version_format(R"(^Xray ([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})(\s|$))");
  if (!Command(image, {L"version"}, output) || !std::regex_search(output, version, version_format)) return {};

  CoreCapabilities capabilities;
  capabilities.version = version[1].str();
  capabilities.profile_validation = HasProfileCompiler(image);
  const auto service_bits = ManagedServiceBits(image);
  capabilities.geodata_updates = (service_bits & managed_services::kGeodata) != 0;
  capabilities.xdrive = (service_bits & managed_services::kXdrive) == managed_services::kXdrive;
  capabilities.vpn_routing = CommandCapability(image, L"native-routing");
  capabilities.balancer_selections = CommandCapability(image, L"native-balancer");
  return capabilities;
} catch (...) { return {}; }

ProfileCheck ValidateBundledProfile(std::string config, const asset_location::Root& assets,
    const asset_location::Root& certificates) try {
  using Status = ProfileCheckStatus;
  const auto valid_root = [](const asset_location::Root& root) {
    return !root || (IsLocalInspectionPath(*root) && asset_location::Valid(root));
  };
  if (config.size() > 16 * 1024 * 1024 || !valid_root(assets) || !valid_root(certificates)) return {Status::invalid};
  auto document = xray_config::Parse(config);
  if (!xray_config::Fields(document, {"env", "log"})) return {Status::invalid};
  // Configuration Build can apply authored Env process-wide. Match the private
  // Apple preflight policy and keep the isolated child's asset policy intact.
  const auto environment = document.value("env", xray_config::Json());
  if (!environment.is_null() && !environment.is_object()) return {Status::invalid};
  if (environment.is_object() && !environment.empty()) {
    for (const auto& value : environment) {
      if (!value.is_string() && !value.is_null()) return {Status::invalid};
    }
    return {Status::unsupported};
  }
  document["log"] = {{"access", "none"}, {"error", "none"}, {"loglevel", "none"}, {"dnsLog", false}};
  const auto required = managed_services::Required(document);

  const auto executable = FindBundledFile(L"xray.exe");
  if (!executable || !IsLocalInspectionPath(*executable)) return {Status::unavailable};
  ProtectedRuntime isolated;
  auto image = *executable;
  const bool elevated = IsAdministrator();
  if (elevated) {
    if (!isolated.Create(image, !assets.has_value())) return {Status::unavailable};
    image = isolated.Executable();
  }
  if (required && (required & ManagedServiceBits(image, assets)) != required) return {Status::unsupported};
  if ((required & managed_services::kGeodata)
      && !geodata_assets::ValidateWritable(document, assets.value_or(image.parent_path()), false, IsLocalInspectionPath))
    return {Status::invalid};
  config = document.dump();
  const auto check_certificate = [&](const fs::path& path) {
    const auto& name = path.native();
    const auto slash = [](wchar_t c) { return c == L'\\' || c == L'/'; };
    if (name.size() > 1 && slash(name[0]) && slash(name[1])) return false;
    if (path.is_absolute()) return IsLocalInspectionPath(path);
    if (path.has_root_name()) return false;
    auto joined = certificates.value_or(image.parent_path());
    joined += fs::path::preferred_separator;
    joined += path.native();
    return IsLocalInspectionPath(joined);
  };
  if (!xray_config::BindCertificatePaths(config, certificates, nullptr, check_certificate)) return {Status::invalid};

  struct PrivateDocument {
    fs::path path;
    ~PrivateDocument() { RemovePrivateConfig(path); }
  } candidate;
  const bool persisted = elevated ? isolated.WriteConfig(config, candidate.path)
                                  : WritePrivateConfig(config, candidate.path);
  if (!persisted) return {Status::unavailable};

  // Conversion builds the authored profile without constructing a live Core.
  // Debug mode uses the inherited null stdout handle instead of opening an
  // output file. Both output streams go directly to NUL.
  auto process = Launch(image, {L"convert", L"pb", L"-debug", candidate.path.wstring()}, false, assets);
  if (!process) return {Status::unavailable};
  const auto handle = reinterpret_cast<HANDLE>(process->hProcess);
  DWORD code = 0;
  if (WaitForSingleObject(handle, 10000) != WAIT_OBJECT_0 || !GetExitCodeProcess(handle, &code)) return {Status::unavailable};
  switch (code) {
    case 0: return {Status::valid};
    case 1: return {Status::invalid, preparation::Stage::core_check};
    case 2: return {HasProfileCompiler(image) ? Status::unavailable : Status::unsupported};
    default: return {Status::unavailable};
  }
} catch (const std::invalid_argument&) { return {ProfileCheckStatus::invalid}; }
  catch (const nlohmann::json::exception&) { return {ProfileCheckStatus::invalid}; }
  catch (...) { return {ProfileCheckStatus::unavailable}; }

bool CheckConfig(const std::string& config, const fs::path& executable, ConfigCheckStorage storage,
    const asset_location::Root& assets, preparation::Stage* failure) try {
  if (failure) *failure = preparation::Stage::prepare;
  if (!asset_location::Valid(assets)) return false;
  auto document = xray_config::Parse(config);
  if (!xray_config::Normalize(document)) return false;
  ProtectedRuntime protected_runtime;
  struct PrivateDocument {
    fs::path path;
    ~PrivateDocument() { RemovePrivateConfig(path); }
  } candidate;
  fs::path image = executable;
  if (failure) *failure = preparation::Stage::persist;
  if (storage == ConfigCheckStorage::administrators) {
    if (!protected_runtime.Create(executable, !assets.has_value())) return false;
    image = protected_runtime.Executable();
    if (!ManagedServicesAllowed(document, image, assets) || !protected_runtime.WriteConfig(document.dump(), candidate.path)) return false;
  } else {
    if (!ManagedServicesAllowed(document, image, assets) || !WritePrivateConfig(document.dump(), candidate.path)) return false;
  }
  if (failure) *failure = preparation::Stage::core_check;
  auto process = Launch(image, {L"run", L"-test", L"-config", candidate.path.wstring()}, false, assets);
  if (!process) return false;
  const HANDLE handle = reinterpret_cast<HANDLE>(process->hProcess);
  if (WaitForSingleObject(handle, 10000) != WAIT_OBJECT_0) return false;
  DWORD code = 1;
  return GetExitCodeProcess(handle, &code) && code == 0;
} catch (...) { return false; }
bool CheckPreparedConfig(const std::string& config, ProtectedRuntime& runtime,
    fs::path& path, const asset_location::Root& assets, preparation::Stage* failure) try {
  if (failure) *failure = preparation::Stage::prepare;
  if (!path.empty() || !asset_location::Valid(assets) || !xray_config::Parse(config).is_object()) return false;
  if (!ManagedServicesAllowed(xray_config::Parse(config), runtime.Executable(), assets)) return false;
  if (failure) *failure = preparation::Stage::persist;
  if (!runtime.WriteConfig(config, path)) return false;
  if (failure) *failure = preparation::Stage::core_check;
  auto process = Launch(runtime.Executable(), {L"run", L"-test", L"-config", path.wstring()}, false, assets);
  if (!process) return false;
  const HANDLE handle = reinterpret_cast<HANDLE>(process->hProcess);
  if (WaitForSingleObject(handle, 10000) != WAIT_OBJECT_0) return false;
  DWORD code = 1;
  return GetExitCodeProcess(handle, &code) && code == 0;
} catch (...) { return false; }
bool RoutingCapability(const ProtectedRuntime& runtime, const asset_location::Root& assets) {
  return CommandCapability(runtime.Executable(), L"native-routing", assets);
}
bool CheckRoutingPreparedConfig(const std::string& config, const std::string& metadata,
    ProtectedRuntime& runtime, fs::path& config_path, fs::path& metadata_path,
    const asset_location::Root& assets, preparation::Stage* failure) try {
  if (failure) *failure = preparation::Stage::prepare;
  if (!config_path.empty() || !metadata_path.empty() || !asset_location::Valid(assets)
      || !xray_config::Parse(config).is_object() || !xray_config::Parse(metadata).is_object()) return false;
  if (!ManagedServicesAllowed(xray_config::Parse(config), runtime.Executable(), assets)) return false;
  if (failure) *failure = preparation::Stage::persist;
  if (!runtime.WriteConfig(config, config_path) || !runtime.WriteConfig(metadata, metadata_path)) return false;
  if (failure) *failure = preparation::Stage::core_check;
  std::string output;
  return Command(runtime.Executable(), {L"native-routing", L"check", L"--config", config_path.wstring(),
      L"--spec", metadata_path.wstring()}, output, 10000, assets) && native_routing::SuccessfulReply(output, "check");
} catch (...) { return false; }
bool TcpPortAvailable(uint16_t port) {
  if (!port) return false;
  WSADATA sockets{};
  if (WSAStartup(MAKEWORD(2, 2), &sockets)) return false;
  SOCKET candidate = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  bool available = false;
  if (candidate != INVALID_SOCKET) {
    BOOL exclusive = TRUE;
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
    available = setsockopt(candidate, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0
        && bind(candidate, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
    closesocket(candidate);
  }
  WSACleanup();
  return available;
}
bool SocksReady(uint16_t port, const std::string& user, const std::string& password,
    const SocksReadinessBudget* parent) {
  const auto deadline = SocksReadinessBudget::Clock::now() + std::chrono::milliseconds(3000);
  const SocksReadinessBudget budget(parent ? std::min(deadline, parent->Deadline()) : deadline,
      [parent] { return parent && !parent->CanContinue(); });
  if (!port || (!user.empty() && (user.size() > 255 || password.size() > 255)) || !budget.CanContinue()) return false;
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2,2), &data)) return false;
  struct OwnedSocket {
    SOCKET value = INVALID_SOCKET;
    bool winsock = true;
    void Close() {
      if (value != INVALID_SOCKET) { closesocket(value); value = INVALID_SOCKET; }
      if (winsock) { WSACleanup(); winsock = false; }
    }
    ~OwnedSocket() { Close(); }
  } owned;
  if (!budget.CanContinue()) return false;
  const SOCKET socket_ = owned.value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_ == INVALID_SOCKET) return false;
  u_long nonblocking = 1;
  if (ioctlsocket(socket_, FIONBIO, &nonblocking)) return false;
  auto wait_ready = [&](bool writing, bool connecting = false) {
    while (budget.CanContinue()) {
      fd_set ready, errors; FD_ZERO(&ready); FD_SET(socket_, &ready);
      FD_ZERO(&errors); FD_SET(socket_, &errors);
      timeval wait{0, budget.PollMilliseconds() * 1000};
      const int count = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr,
          connecting ? &errors : nullptr, &wait);
      if (count > 0) return budget.CanContinue();
      if (count < 0 && WSAGetLastError() != WSAEINTR) return false;
    }
    return false;
  };
  sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
  if (InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr) != 1 || !budget.CanContinue()) return false;
  if (connect(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    const int error = WSAGetLastError();
    if ((error != WSAEWOULDBLOCK && error != WSAEINPROGRESS) || !wait_ready(true, true)) return false;
    int result = 0, size = sizeof(result);
    if (getsockopt(socket_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&result), &size) || result) return false;
  }
  if (!budget.CanContinue()) return false;
  auto exchange = [&](const std::string& request, unsigned char expected0, unsigned char expected1) {
    size_t sent = 0;
    while (sent < request.size() && budget.CanContinue()) {
      if (!wait_ready(true)) return false;
      const int count = send(socket_, request.data() + sent, static_cast<int>(request.size() - sent), 0);
      if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
      if (count <= 0) return false;
      sent += count;
    }
    if (sent != request.size() || !budget.CanContinue()) return false;
    unsigned char reply[2]{}; size_t got = 0;
    while (got < 2 && budget.CanContinue()) {
      if (!wait_ready(false)) return false;
      const int count = recv(socket_, reinterpret_cast<char*>(reply) + got, static_cast<int>(2-got), 0);
      if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
      if (count <= 0) return false;
      got += count;
    }
    return got == 2 && budget.CanContinue() && reply[0] == expected0 && reply[1] == expected1;
  };
  const unsigned char method = user.empty() ? 0 : 2;
  bool ok = exchange(std::string({5, 1, static_cast<char>(method)}), 5, method);
  if (ok && method == 2) {
    ok = exchange(std::string({1, static_cast<char>(user.size())}) + user + static_cast<char>(password.size()) + password, 1, 0);
  }
  owned.Close();
  return ok && budget.CanContinue();
}
}  // namespace flutter_vless::native
