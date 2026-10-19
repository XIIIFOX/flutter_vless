// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

#include "include/flutter_vless/flutter_vless_plugin.h"

#include <flutter/method_channel.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <windows.h>
#include <memory>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <functional>
#include <vector>

#include "v2ray_manager.h"
#include "native_runtime.h"
#include "xray_config.h"
#include "native_task_queue.h"
#include "native_options.h"
#include "diagnostics_log.h"
#include "system_tray.h"
#include <iostream>

namespace {
flutter_vless::NativeOptions::Json OptionJson(const flutter::EncodableValue& value) {
  using Json = flutter_vless::NativeOptions::Json;
  if (value.IsNull()) return nullptr;
  if (const auto* v = std::get_if<bool>(&value)) return *v;
  if (const auto* v = std::get_if<int32_t>(&value)) return *v;
  if (const auto* v = std::get_if<int64_t>(&value)) return *v;
  if (const auto* v = std::get_if<double>(&value)) return *v;
  if (const auto* v = std::get_if<std::string>(&value)) return *v;
  if (const auto* v = std::get_if<flutter::EncodableMap>(&value)) {
    auto out = Json::object();
    for (const auto& entry : *v) { const auto* key = std::get_if<std::string>(&entry.first); if (!key) throw std::invalid_argument("Option key"); out[*key] = OptionJson(entry.second); }
    return out;
  }
  throw std::invalid_argument("Option type");
}

/**
 * @brief Helper function to log messages to console and Windows debug output.
 * 
 * @param msg Message string to log.
 * 
 * @details Output:
 * - Writes to std::cout for console output
 * - Writes to OutputDebugStringA for Windows debugger (visible in Visual Studio)
 */
inline void LogMessage(const std::string& msg) {
  std::cout << "[FlutterVless] " << msg << std::endl;
  OutputDebugStringA(("[FlutterVless] " + msg + "\n").c_str());
}

/**
 * @brief Flutter plugin for managing Xray/VLESS connections on Windows.
 * 
 * @details Platform Channel Communication:
 * This plugin provides bidirectional communication between Flutter Dart code
 * and native Windows C++ code through:
 * - MethodChannel: For method calls from Flutter to native (start/stop/status)
 * - EventChannel: For streaming status updates from native to Flutter
 * 
 * @details Platform channel callbacks and status delivery run on the platform
 * thread. Worker threads enqueue copied status payloads through the window
 * message dispatcher.
 *
 * @note Status Update Format:
 * Status updates are sent as EncodableList with 6 elements:
 * [0] = connection duration (seconds as string)
 * [1] = upload speed (bytes/second as string)
 * [2] = download speed (bytes/second as string)
 * [3] = total upload (bytes as string)
 * [4] = total download (bytes as string)
 * [5] = connection status ("CONNECTED" or "DISCONNECTED")
 */
class FlutterVlessPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  FlutterVlessPlugin(flutter::PluginRegistrarWindows *registrar);
  virtual ~FlutterVlessPlugin();

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  void StartStatusTimer();
  void StopStatusTimer();
  void UpdateStatus();
  // Copies worker status updates to the platform thread before EventSink use.
  void SendStatusToUI(const flutter::EncodableList& status);

  // Flutter platform integration
  flutter::PluginRegistrarWindows *registrar_;  ///< Flutter Windows registrar
  std::unique_ptr<flutter::EventChannel<flutter::EncodableValue>> status_channel_;  ///< EventChannel for status streaming
  std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> status_sink_;  ///< EventSink for sending status updates (protected by sink_mutex_)
  
  // Xray management - now uses singleton pattern via GetInstance()
  
  // Status update thread
  std::thread status_thread_;  ///< Thread that periodically updates and sends status
  std::atomic<bool> is_running_{false};  ///< Flag indicating if Xray is running
  std::atomic<bool> should_stop_{false};  ///< Flag to stop status update thread
  
  // Thread synchronization
  std::mutex status_mutex_;  ///< Protects traffic statistics (total_upload_, total_download_, etc.)
  std::mutex sink_mutex_;    ///< Protects status_sink_ lifetime
  
  // Traffic statistics (protected by status_mutex_)
  std::chrono::steady_clock::time_point start_time_;  ///< When connection was established
  int64_t total_upload_ = 0;    ///< Cumulative bytes uploaded
  int64_t total_download_ = 0;   ///< Cumulative bytes downloaded
  int64_t upload_speed_ = 0;     ///< Current upload speed (bytes/second)
  int64_t download_speed_ = 0;   ///< Current download speed (bytes/second)
  flutter_vless::traffic::Baseline upload_baseline_, download_baseline_;
  
  // Platform-thread callback dispatcher for status, method results and controls
  HWND main_window_handle_ = nullptr;  ///< Main window handle for PostMessage
  const DWORD platform_thread_id_ = GetCurrentThreadId();
  int window_proc_delegate_id_ = 0;      ///< ID of registered window proc delegate
  UINT ui_callback_message_id_ = 0;      ///< Registered window message ID for UI callbacks
  std::mutex ui_callbacks_mutex_;        ///< Protects ui_callbacks_ vector
  std::vector<std::function<void()>> ui_callbacks_;  ///< Queue of callbacks to execute on UI thread

  // Mutex to serialize Start/Stop operations to prevent race conditions
  std::mutex lifecycle_mutex_;
  NativeTaskQueue operations_;
  flutter_vless::NativeOptions native_options_;
  std::unique_ptr<flutter_vless::SystemTray> tray_;
  struct QuickProfile {
    std::string config; flutter_vless::asset_location::Root assets;
    std::optional<flutter_vless::native_routing::NativeRoutingIntent> routing;
  };
  std::optional<QuickProfile> quick_profile_; // Access only on operations_. Never persisted in plaintext.
  std::atomic<unsigned> options_generation_{0};
  std::atomic<int> last_tray_state_{-1};
  bool tray_pending_ = false;
  void OpenApp() { if (main_window_handle_) { ShowWindow(main_window_handle_, SW_RESTORE); SetForegroundWindow(main_window_handle_); } }
  void RefreshTray() { const auto& manager = V2rayManager::GetInstance(); if (tray_) tray_->Refresh((manager.IsRunning() && !manager.IsProxyOnly()) || manager.IsProtecting(), tray_pending_); }
  void ToggleFromTray() {
    if (tray_pending_ || !native_options_.quick_enabled) return;
    if (V2rayManager::GetInstance().IsProxyOnly() && V2rayManager::GetInstance().IsRunning()) { OpenApp(); return; }
    tray_pending_ = true; RefreshTray();
    const auto options = native_options_; const auto generation = options_generation_.load();
    operations_.Submit([this, options, generation] {
      std::lock_guard<std::mutex> lock(lifecycle_mutex_);
      bool available = generation == options_generation_.load() && !(V2rayManager::GetInstance().IsProxyOnly() && V2rayManager::GetInstance().IsRunning());
      if (available && (V2rayManager::GetInstance().IsRunning() || V2rayManager::GetInstance().IsProtecting())) {
        StopStatusTimer(); V2rayManager::GetInstance().Stop(); is_running_ = false;
        SendStatusToUI(flutter::EncodableList{flutter::EncodableValue("0"), flutter::EncodableValue("0"), flutter::EncodableValue("0"), flutter::EncodableValue("0"), flutter::EncodableValue("0"), flutter::EncodableValue("DISCONNECTED")});
      } else if (available && quick_profile_) {
        const bool ready = V2rayManager::GetInstance().Start(quick_profile_->config, false, options, quick_profile_->assets, quick_profile_->routing);
        is_running_ = ready || V2rayManager::GetInstance().IsProtecting();
        if (is_running_) { start_time_ = std::chrono::steady_clock::now(); StartStatusTimer(); }
        available = is_running_.load();
      } else { available = false; }
      RunOnUIThread([this, available] { tray_pending_ = false; RefreshTray(); UpdateStatus(); if (!available) OpenApp(); });
    });
  }


  /**
   * @brief Schedules a callback to be executed on the UI thread.
   * 
   * @param callback The function to execute.
   */
  void RunOnUIThread(std::function<void()> callback) {
    {
      std::lock_guard<std::mutex> lock(ui_callbacks_mutex_);
      ui_callbacks_.push_back(std::move(callback));
    }
    if (main_window_handle_ && ui_callback_message_id_ != 0) {
      if (!PostMessage(main_window_handle_, ui_callback_message_id_, 0, 0)) {
        LogMessage("Error: PostMessage failed with error: " + std::to_string(GetLastError()));
      }
    } else {
      LogMessage("Warning: Cannot post to UI thread, window handle or message ID invalid");
    }
  }};

void FlutterVlessPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto plugin = std::make_unique<FlutterVlessPlugin>(registrar);
  registrar->AddPlugin(std::move(plugin));
}

FlutterVlessPlugin::FlutterVlessPlugin(flutter::PluginRegistrarWindows *registrar)
    : registrar_(registrar) {
  auto method_channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "flutter_vless",
          &flutter::StandardMethodCodec::GetInstance());

  method_channel->SetMethodCallHandler(
      [this](const auto &call, auto result) {
        HandleMethodCall(call, std::move(result));
      });

  status_channel_ =
      std::make_unique<flutter::EventChannel<flutter::EncodableValue>>(
          registrar->messenger(), "flutter_vless/status",
          &flutter::StandardMethodCodec::GetInstance());

  /**
   * @brief EventChannel stream handler for status updates.
   * 
   * @details EventChannel Lifecycle:
   * Flutter EventChannel provides a stream of events from native to Dart.
   * The handler has two callbacks:
   * - onListen: Called when Flutter subscribes to the stream (Dart: listen())
   * - onCancel: Called when Flutter unsubscribes (Dart: cancel())
   * 
   * @details Thread Safety:
   * - onListen callback is invoked on the Flutter platform (UI) thread
   * - This makes it safe to call EventSink->Success() directly
   * - The status_sink_ is protected by sink_mutex_ for thread-safe access
   * 
   * @details Initial Status:
   * When Flutter first subscribes, we immediately send a DISCONNECTED status
   * to ensure the UI has a known initial state. This happens synchronously
   * on the UI thread, so it's safe to call EventSink directly.
   * 
   * @warning DO NOT MODIFY:
   * The EventChannel handler logic is critical for UI communication. Changing
   * the connection/disconnection logic or status format may break Flutter UI.
   * The current implementation works correctly and should not be modified.
   */
  auto status_handler = std::make_unique<
      flutter::StreamHandlerFunctions<flutter::EncodableValue>>(
      [this](const flutter::EncodableValue *arguments,
             std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> &&events)
          -> std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>> {
        LogMessage("EventChannel listener connected");
        {
          std::lock_guard<std::mutex> lock(sink_mutex_);
          status_sink_ = std::move(events);
        }
        
        // Send initial DISCONNECTED status immediately (on UI thread)
        // This callback is invoked on the Flutter platform (UI) thread,
        // so it's safe to call EventSink->Success() directly without
        // additional thread synchronization.
        if (status_sink_) {
          flutter::EncodableList initial_status;
          initial_status.push_back(flutter::EncodableValue("0"));  // duration
          initial_status.push_back(flutter::EncodableValue("0"));  // upload speed
          initial_status.push_back(flutter::EncodableValue("0"));  // download speed
          initial_status.push_back(flutter::EncodableValue("0"));  // total upload
          initial_status.push_back(flutter::EncodableValue("0"));  // total download
          initial_status.push_back(flutter::EncodableValue("DISCONNECTED"));  // status
          
          LogMessage("Sending initial DISCONNECTED status");
          // This callback is already on UI thread, safe to call directly
          std::lock_guard<std::mutex> lock(sink_mutex_);
          if (status_sink_) {
            status_sink_->Success(flutter::EncodableValue(initial_status));
          }
        }
        
        return nullptr;
      },
      [this](const flutter::EncodableValue *arguments)
          -> std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>> {
        LogMessage("EventChannel listener disconnected");
        {
          std::lock_guard<std::mutex> lock(sink_mutex_);
          status_sink_.reset();
        }
        return nullptr;
      });

  status_channel_->SetStreamHandler(std::move(status_handler));

  // Deliver queued callbacks through the top-level window's platform thread.
  // Setup UI thread invocation mechanism using window proc delegate
  if (registrar_) {
    auto view = registrar_->GetView();
    if (view) {
      // The registrar's delegate receives messages for the top-level window,
      // while Flutter's view can be a child HWND.
      const HWND view_window = view->GetNativeWindow();
      main_window_handle_ = view_window ? GetAncestor(view_window, GA_ROOT) : nullptr;
      if (main_window_handle_) {
        LogMessage("Main window handle obtained: " + std::to_string(reinterpret_cast<uintptr_t>(main_window_handle_)));
      } else {
        LogMessage("Warning: GetNativeWindow returned null");
      }
    } else {
      LogMessage("Warning: GetView returned null");
    }
    
    // Register window message ID once
    ui_callback_message_id_ = RegisterWindowMessageA("FLUTTER_VLESS_INVOKE_UI_CALLBACK");
    if (ui_callback_message_id_ == 0) {
      LogMessage("Error: Failed to register window message");
    } else {
      LogMessage("Window message ID registered: " + std::to_string(ui_callback_message_id_));
    }
    
    window_proc_delegate_id_ = registrar_->RegisterTopLevelWindowProcDelegate(
        [this](HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
            -> std::optional<LRESULT> {
          if (tray_ && tray_->Handle(message, lparam)) return std::optional<LRESULT>(0);
          if (message == ui_callback_message_id_) {
            std::vector<std::function<void()>> tasks;
            {
              std::lock_guard<std::mutex> lock(ui_callbacks_mutex_);
              tasks.swap(ui_callbacks_);
            }
            LogMessage("Window proc delegate called for message " + std::to_string(message) + ", executing " + std::to_string(tasks.size()) + " tasks");
            for (auto &t : tasks) {
              try {
                t();
              } catch (const std::exception& e) {
                LogMessage("Exception in UI callback: " + std::string(e.what()));
              } catch (...) {
                LogMessage("Unknown exception in UI callback");
              }
            }
            return std::optional<LRESULT>(0);
          }
          return std::nullopt;
        });
    
    if (window_proc_delegate_id_ != 0) {
      LogMessage("Window proc delegate registered successfully");
    } else {
      LogMessage("Warning: Failed to register window proc delegate");
    }
  }
  
  LogMessage("Plugin initialized");
}

FlutterVlessPlugin::~FlutterVlessPlugin() {
  operations_.Stop();
  tray_.reset();
  StopStatusTimer();
  V2rayManager::GetInstance().Shutdown();
  
  // Unregister window proc delegate
  if (registrar_ && window_proc_delegate_id_ != 0) {
    registrar_->UnregisterTopLevelWindowProcDelegate(window_proc_delegate_id_);
    window_proc_delegate_id_ = 0;
  }
  // Clear status sink
  {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    status_sink_.reset();
  }
}

void FlutterVlessPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  if (method_call.method_name() == "getSecurityCapabilities") {
    result->Success(flutter::EncodableValue(flutter::EncodableMap{
      {flutter::EncodableValue("certificateAssetsDirectory"), flutter::EncodableValue(true)},
      {flutter::EncodableValue("vpnRouting"), flutter::EncodableValue(true)}}));
  } else if (method_call.method_name() == "getCapabilities") {
    result->Success(flutter::EncodableValue(flutter::EncodableMap{
      {flutter::EncodableValue("optionsVersion"), flutter::EncodableValue(1)},
      {flutter::EncodableValue("quickAccessSurfaces"), flutter::EncodableValue(flutter::EncodableList{flutter::EncodableValue("systemTray")})},
      {flutter::EncodableValue("customReconnectBackoff"), flutter::EncodableValue(true)},
      {flutter::EncodableValue("killSwitch"), flutter::EncodableValue(true)}}));
  } else if (method_call.method_name() == "requestAddQuickTile") {
    result->Success(flutter::EncodableValue("unsupported"));
  } else if (method_call.method_name() == "clearQuickAccessProfile") {
    std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> reply = std::move(result);
    operations_.Submit([this, reply] { quick_profile_.reset(); RunOnUIThread([reply] { reply->Success(); }); });
  } else if (method_call.method_name().compare("requestPermission") == 0) {
    // VPN requires elevation for Wintun and mandatory WFP containment.
    result->Success(flutter::EncodableValue(flutter_vless::native::IsAdministrator()));
  } else if (method_call.method_name().compare("initializeVless") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      LogMessage("initializeVless called");
      try {
        const auto found = arguments->find(flutter::EncodableValue("options"));
        auto parsed = flutter_vless::NativeOptions::Parse(found == arguments->end() ? flutter_vless::NativeOptions::Json::object() : OptionJson(found->second));
        parsed.ValidateWindows();
        if (!tray_) tray_ = std::make_unique<flutter_vless::SystemTray>(main_window_handle_, [this] { ToggleFromTray(); }, [this] { OpenApp(); });
        if (!tray_->Configure(parsed)) { result->Error("QUICK_ACCESS_UNAVAILABLE", "Cannot create the system tray icon; check the .ico path and desktop session"); return; }
        native_options_ = parsed; ++options_generation_;
        flutter_vless::DiagnosticsLog::Instance().Configure(parsed.diagnostics_enabled, parsed.diagnostics_bytes, parsed.diagnostics_lines);
        if (!parsed.quick_enabled) operations_.Submit([this] { quick_profile_.reset(); });
        RefreshTray(); result->Success(flutter::EncodableValue(nullptr));
      } catch (const std::exception&) { result->Error("INVALID_OPTIONS", "Unsupported or invalid Windows options"); }
    } else {
      result->Error("INVALID_ARGUMENTS", "Invalid arguments for initializeVless");
    }
  } else if (method_call.method_name().compare("startVless") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto remark_it = arguments->find(flutter::EncodableValue("remark"));
      auto config_it = arguments->find(flutter::EncodableValue("config"));
      auto proxy_only_it = arguments->find(flutter::EncodableValue("proxy_only"));
      
      if (remark_it != arguments->end() && config_it != arguments->end()) {
        std::string remark = std::get<std::string>(remark_it->second);
        std::string config = std::get<std::string>(config_it->second);
        bool proxy_only = false;
        flutter_vless::asset_location::Root assets;
        const auto assets_it = arguments->find(flutter::EncodableValue("geo_assets_directory"));
        if (assets_it != arguments->end() && !assets_it->second.IsNull()) {
          const auto* value = std::get_if<std::string>(&assets_it->second);
          const auto wide = value ? flutter_vless::native::Wide(*value) : std::wstring();
          if (!value || wide.empty()) { result->Error("INVALID_ARGUMENTS", "geoAssetsDirectory must be an existing absolute directory"); return; }
          assets = fs::path(wide);
        }
        const auto certificates_it = arguments->find(flutter::EncodableValue("certificate_assets_directory"));
        if (certificates_it != arguments->end() && !certificates_it->second.IsNull()) {
          const auto* value = std::get_if<std::string>(&certificates_it->second);
          const auto wide = value ? flutter_vless::native::Wide(*value) : std::wstring();
          if (!value || wide.empty() || !flutter_vless::xray_config::BindCertificatePaths(config, fs::path(wide))) {
            result->Error("INVALID_ARGUMENTS", "Invalid certificate asset directory or TLS file configuration"); return;
          }
        }
        
        if (proxy_only_it != arguments->end()) {
          const auto* proxy_only_value = std::get_if<bool>(&proxy_only_it->second);
          if (proxy_only_value) {
            proxy_only = *proxy_only_value;
          }
        }

        std::optional<flutter_vless::native_routing::NativeRoutingIntent> routing;
        try {
          const auto found = arguments->find(flutter::EncodableValue("vpn_routing"));
          if (found != arguments->end() && !found->second.IsNull()) {
            const auto* map = std::get_if<flutter::EncodableMap>(&found->second);
            if (!map || proxy_only) throw std::invalid_argument("routing");
            for (const auto& entry : *map) {
              const auto* key = std::get_if<std::string>(&entry.first);
              if (!key) throw std::invalid_argument("routing");
              if (*key == "sourceInboundIndex") {
                if (!std::get_if<int32_t>(&entry.second) && !std::get_if<int64_t>(&entry.second))
                  throw std::invalid_argument("routing");
              } else if (*key == "defaultOutboundTag") {
                if (!entry.second.IsNull() && !std::get_if<std::string>(&entry.second)) throw std::invalid_argument("routing");
              } else throw std::invalid_argument("routing");
            }
            auto parsed = flutter_vless::native_routing::NativeRoutingSpec::ParseIntent(OptionJson(found->second).dump());
            if (parsed.error != flutter_vless::native_routing::NativeRoutingError::none || !parsed.intent)
              throw std::invalid_argument("routing");
            routing = std::move(parsed.intent);
          }
        } catch (...) { result->Error("INVALID_ROUTING", "Invalid VPN routing options"); return; }

        if (!proxy_only) {
          std::vector<std::string> cidrs;
          auto bypass = arguments->find(flutter::EncodableValue("bypass_subnets"));
          if (bypass != arguments->end() && !bypass->second.IsNull()) {
            const auto* values = std::get_if<flutter::EncodableList>(&bypass->second);
            if (!values) { result->Error("INCOMPATIBLE_ROUTING", "bypassSubnets must be IPv4 CIDRs"); return; }
            for (const auto& value : *values) {
              const auto* cidr = std::get_if<std::string>(&value);
              if (!cidr) { result->Error("INCOMPATIBLE_ROUTING", "bypassSubnets must be IPv4 CIDRs"); return; }
              cidrs.push_back(*cidr);
            }
          }
          const auto routed = flutter_vless::xray_config::ApplyBypass(config, cidrs);
          if (!routed) { result->Error("INCOMPATIBLE_ROUTING", "Invalid VPN routing configuration or IPv4 bypass CIDRs"); return; }
          config = *routed;
        }
        // Convert unique_ptr to shared_ptr to allow capturing in std::function (which requires CopyConstructible)
        std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);
        
        const auto options = native_options_;
        const auto generation = options_generation_.load();
        operations_.Submit([this, config, proxy_only, assets, routing, shared_result, options, generation]() {
          std::lock_guard<std::mutex> lock(lifecycle_mutex_);
          LogMessage("Starting Xray...");
          const bool ready = V2rayManager::GetInstance().Start(config, proxy_only, options, assets, routing);
          const bool protecting = V2rayManager::GetInstance().IsProtecting();
          is_running_ = V2rayManager::GetInstance().IsRunning() || protecting;
          if (ready && proxy_only) quick_profile_.reset();
          if (ready && !proxy_only && options.quick_enabled && generation == options_generation_.load()) quick_profile_ = QuickProfile{config, assets, routing};
          if (ready) {
            start_time_ = std::chrono::steady_clock::now();
            StartStatusTimer();
          }
          RunOnUIThread([this, shared_result, ready, protecting]() {
            RefreshTray();
            if (ready) shared_result->Success(flutter::EncodableValue(nullptr));
            else shared_result->Error("VPN_START_FAILED", protecting
                ? "VPN forwarding is unavailable; traffic protection remains active. Check diagnostics, retry or explicitly stop."
                : "VPN setup failed. Check configuration, administrator rights and bundled runtime files.");
          });
        });

      } else {
        result->Error("INVALID_ARGUMENTS", "Missing remark or config");
      }
    } else {
      result->Error("INVALID_ARGUMENTS", "Invalid arguments for startVless");
    }
  } else if (method_call.method_name().compare("stopVless") == 0) {
    LogMessage("stopVless called");
    
    // Move stop logic to background thread to avoid freezing UI
    // Convert unique_ptr to shared_ptr to allow capturing in std::function
    std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);

    operations_.Submit([this, shared_result]() {
      std::lock_guard<std::mutex> lock(lifecycle_mutex_);
      
      StopStatusTimer();
      V2rayManager::GetInstance().Stop();
      is_running_ = false;
      total_upload_ = 0;
      total_download_ = 0;
      upload_speed_ = 0;
      download_speed_ = 0;
      
      // Send DISCONNECTED status to Flutter UI
      flutter::EncodableList status;
      status.push_back(flutter::EncodableValue("0"));  // duration
      status.push_back(flutter::EncodableValue("0"));  // upload speed
      status.push_back(flutter::EncodableValue("0"));  // download speed
      status.push_back(flutter::EncodableValue("0"));  // total upload
      status.push_back(flutter::EncodableValue("0"));  // total download
      status.push_back(flutter::EncodableValue("DISCONNECTED"));  // status
      
      SendStatusToUI(status);
      
      // Return result on UI thread
      RunOnUIThread([this, shared_result]() {
        RefreshTray();
        shared_result->Success(flutter::EncodableValue(nullptr));
      });
    });

  } else if (method_call.method_name().compare("getServerDelay") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto config_it = arguments->find(flutter::EncodableValue("config"));
      auto url_it = arguments->find(flutter::EncodableValue("url"));
      
      if (config_it != arguments->end() && url_it != arguments->end()) {
        std::string config = std::get<std::string>(config_it->second);
        std::string url = std::get<std::string>(url_it->second);
        const auto certificates_it = arguments->find(flutter::EncodableValue("certificate_assets_directory"));
        if (certificates_it != arguments->end() && !certificates_it->second.IsNull()) {
          const auto* value = std::get_if<std::string>(&certificates_it->second);
          const auto wide = value ? flutter_vless::native::Wide(*value) : std::wstring();
          if (!value || wide.empty() || !flutter_vless::xray_config::BindCertificatePaths(config, fs::path(wide))) {
            result->Error("INVALID_ARGUMENTS", "Invalid certificate asset directory or TLS file configuration"); return;
          }
        }
        
        std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);
        operations_.Submit([this, config, url, shared_result]() {
          int delay = V2rayManager::GetInstance().GetServerDelay(config, url);
          RunOnUIThread([shared_result, delay]() { shared_result->Success(flutter::EncodableValue(delay)); });
        });
        return;
      }
    }
    result->Error("INVALID_ARGUMENTS", "Invalid arguments for getServerDelay");
  } else if (method_call.method_name().compare("getConnectedServerDelay") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto url_it = arguments->find(flutter::EncodableValue("url"));
      if (url_it != arguments->end()) {
        std::string url = std::get<std::string>(url_it->second);
        
        std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);
        operations_.Submit([this, url, shared_result]() {
          int delay = V2rayManager::GetInstance().GetConnectedServerDelay(url);
          RunOnUIThread([shared_result, delay]() { shared_result->Success(flutter::EncodableValue(delay)); });
        });
        return;
      }
    }
    result->Error("INVALID_ARGUMENTS", "Invalid arguments for getConnectedServerDelay");
  } else if (method_call.method_name().compare("getCoreVersion") == 0) {
    std::string version = V2rayManager::GetInstance().GetCoreVersion();
    LogMessage("getCoreVersion: " + version);
    result->Success(flutter::EncodableValue(version));
  } else if (method_call.method_name().compare("getProviderDebugSnapshot") == 0) {
    result->Success(flutter::EncodableValue(
        V2rayManager::GetInstance().GetProviderDebugSnapshot()));
  } else {
    result->NotImplemented();
  }
}

void FlutterVlessPlugin::StartStatusTimer() {
  { std::lock_guard<std::mutex> lock(status_mutex_); upload_baseline_.Reset(); download_baseline_.Reset(); }
  should_stop_ = false;
  status_thread_ = std::thread([this]() {
    while (!should_stop_ && is_running_) {
      UpdateStatus();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  });
}

void FlutterVlessPlugin::StopStatusTimer() {
  should_stop_ = true;
  if (status_thread_.joinable()) {
    status_thread_.join();
  }
  std::lock_guard<std::mutex> lock(status_mutex_); upload_baseline_.Reset(); download_baseline_.Reset();
}


/**
 * @brief Updates connection status and sends it to Flutter UI.
 * 
 * @details Execution Context:
 * This function runs in a background thread (status_thread_) and is called
 * periodically (every 1 second) while Xray is running.
 * 
 * @details Status Calculation:
 * 1. Calculates connection duration from start_time_
 * 2. Retrieves current traffic statistics from V2rayManager
 * 3. Calculates speed as difference from previous total
 * 4. Updates cumulative totals
 * 5. Builds status EncodableList with 6 elements
 * 6. Sends status to UI via SendStatusToUI()
 * 
 * @details Status Format:
 * The status EncodableList contains (all as strings):
 * [0] = connection duration in seconds
 * [1] = current upload speed (bytes/second)
 * [2] = current download speed (bytes/second)
 * [3] = total bytes uploaded (cumulative)
 * [4] = total bytes downloaded (cumulative)
 * [5] = "CONNECTED" (connection status string)
 * 
 * @warning DO NOT MODIFY:
 * The six-field status format must remain unchanged. The Flutter
 * UI expects this exact format. Changing the order or format of status elements
 * will break UI updates.
 * 
 * @note Thread Safety:
 * Uses status_mutex_ to protect traffic statistics and sink_mutex_ to protect
 * status_sink_ access. The function is called from status_thread_ (background
 * thread); SendStatusToUI() dispatches sink delivery to the platform thread.
 */
void FlutterVlessPlugin::UpdateStatus() {
  const int state = V2rayManager::GetInstance().IsRunning() ? 2 : (V2rayManager::GetInstance().IsProtecting() ? 1 : 0);
  if (last_tray_state_.exchange(state) != state) RunOnUIThread([this] { RefreshTray(); });

  {
    std::lock_guard<std::mutex> sink_lock(sink_mutex_);
    if (!status_sink_ || !is_running_) {
      return;
    }
  }

  std::lock_guard<std::mutex> status_lock(status_mutex_);
  
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::seconds>(
      now - start_time_).count();

  // Get traffic stats from v2ray manager
  const auto sample = V2rayManager::GetInstance().GetTrafficSample();
  upload_speed_ = upload_baseline_.Advance(sample.upload);
  download_speed_ = download_baseline_.Advance(sample.download);
  total_upload_ = sample.upload.value_or(0);
  total_download_ = sample.download.value_or(0);

  flutter::EncodableList status;
  status.push_back(flutter::EncodableValue(std::to_string(duration)));
  status.push_back(flutter::EncodableValue(std::to_string(upload_speed_)));
  status.push_back(flutter::EncodableValue(std::to_string(download_speed_)));
  status.push_back(flutter::EncodableValue(std::to_string(total_upload_)));
  status.push_back(flutter::EncodableValue(std::to_string(total_download_)));
  const auto& manager = V2rayManager::GetInstance();
  status.push_back(flutter::EncodableValue(manager.IsRunning() ? "CONNECTED"
      : (manager.IsProtecting() ? "CONNECTING" : "DISCONNECTED")));

  LogMessage("UpdateStatus: duration=" + std::to_string(duration) + " up=" + 
            std::to_string(upload_speed_) + " down=" + std::to_string(download_speed_));

  // Send status to UI thread
  SendStatusToUI(status);
}


// EventSink delivery belongs to the thread that registered the plugin. A mutex
// protects the sink lifetime; it does not make platform channel calls thread-safe.
void FlutterVlessPlugin::SendStatusToUI(const flutter::EncodableList& status) {
  if (GetCurrentThreadId() != platform_thread_id_) {
    RunOnUIThread([this, status] { SendStatusToUI(status); });
    return;
  }
  std::lock_guard<std::mutex> sink_lock(sink_mutex_);
  if (status_sink_) {
    try {
      // Build status string for logging
      std::string status_str = "[";
      for (size_t i = 0; i < status.size(); ++i) {
        if (i > 0) status_str += ", ";
        const auto& val = status[i];
        if (auto str_val = std::get_if<std::string>(&val)) {
          status_str += *str_val;
        } else {
          status_str += "?";
        }
      }
      status_str += "]";
      
      status_sink_->Success(flutter::EncodableValue(status));
      LogMessage("Status sent successfully: " + status_str);
    } catch (const std::exception& e) {
      LogMessage("Error sending status: " + std::string(e.what()));
    } catch (...) {
      LogMessage("Unknown error sending status");
    }
  } else {
    LogMessage("Warning: status_sink_ is null, cannot send status");
  }
}

}  // namespace

// C++ registration entry point called by the generated plugin registrant.
void FlutterVlessPluginRegisterWithRegistrar(
  flutter::PluginRegistrar* registrar) {
  // The generated registrant passes a generic flutter::PluginRegistrar*.
  // Cast to the Windows-specific registrar and forward to the plugin
  // registration method.
  FlutterVlessPlugin::RegisterWithRegistrar(
    reinterpret_cast<flutter::PluginRegistrarWindows*>(registrar));
}

// Also provide the C-style registrar overload (used by some Flutter toolchains)
// to support builds that pass a FlutterDesktopPluginRegistrarRef.
void FlutterVlessPluginRegisterWithRegistrar(
  FlutterDesktopPluginRegistrarRef registrar) {
  FlutterVlessPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarManager::GetInstance()
      ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
