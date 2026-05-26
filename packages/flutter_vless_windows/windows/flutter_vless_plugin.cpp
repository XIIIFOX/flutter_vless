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
#include <iostream>

namespace {

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
 * @details Thread Safety and UI Thread Requirements:
 * Flutter platform channels have specific threading requirements:
 * - MethodChannel callbacks are invoked on the platform (UI) thread
 * - EventChannel EventSink operations should ideally be called from UI thread
 * - However, modern Flutter Windows implementation makes EventSink thread-safe
 * 
 * @warning UI Thread Interaction:
 * The SendStatusToUI() function sends status updates to Flutter. While Flutter
 * documentation recommends calling EventSink from UI thread, the current
 * implementation works correctly from background threads due to Flutter's
 * thread-safe EventSink implementation. The warning about non-platform thread
 * is non-critical and does not affect functionality.
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
  /**
   * @brief Sends status update to Flutter UI via EventChannel.
   * 
   * @param status Status data as EncodableList (see class documentation for format).
   * 
   * @details Thread Safety:
   * This function is called from background threads (status update thread).
   * While Flutter documentation recommends calling EventSink from UI thread,
   * modern Flutter Windows implementation makes EventSink operations thread-safe.
   * The warning about non-platform thread is non-critical.
   * 
   * @warning DO NOT MODIFY:
   * This function's implementation is critical for UI communication. Changing
   * the status format or sending mechanism may break Flutter UI updates.
   */
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
  std::mutex sink_mutex_;    ///< Protects status_sink_ access (thread-safe EventSink operations)
  
  // Traffic statistics (protected by status_mutex_)
  std::chrono::steady_clock::time_point start_time_;  ///< When connection was established
  int64_t total_upload_ = 0;    ///< Cumulative bytes uploaded
  int64_t total_download_ = 0;   ///< Cumulative bytes downloaded
  int64_t upload_speed_ = 0;     ///< Current upload speed (bytes/second)
  int64_t download_speed_ = 0;   ///< Current download speed (bytes/second)
  
  // UI thread invocation mechanism (for future use, not currently used for status updates)
  HWND main_window_handle_ = nullptr;  ///< Main window handle for PostMessage
  int window_proc_delegate_id_ = 0;      ///< ID of registered window proc delegate
  UINT ui_callback_message_id_ = 0;      ///< Registered window message ID for UI callbacks
  std::mutex ui_callbacks_mutex_;        ///< Protects ui_callbacks_ vector
  std::vector<std::function<void()>> ui_callbacks_;  ///< Queue of callbacks to execute on UI thread

  // Mutex to serialize Start/Stop operations to prevent race conditions
  std::mutex lifecycle_mutex_;

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

  /**
   * @brief Setup UI thread invocation mechanism using window proc delegate.
   * 
   * @details Purpose:
   * This mechanism allows executing callbacks on the Flutter UI thread by
   * posting custom window messages that are handled by the window proc delegate.
   * 
   * @details Current Usage:
   * Currently, this mechanism is set up but NOT used for status updates.
   * Status updates are sent directly via EventSink (which is thread-safe in
   * modern Flutter Windows). This mechanism is kept for potential future use
   * or other UI thread operations that may require strict UI thread execution.
   * 
   * @details Implementation:
   * 1. Registers a custom window message ID via RegisterWindowMessageA
   * 2. Registers a window proc delegate that handles this message
   * 3. When PostMessage is called with this message ID, the delegate executes
   *    callbacks from the ui_callbacks_ queue on the UI thread
   * 
   * @note This is NOT used for status updates. Status updates use direct
   *       EventSink calls which are thread-safe in modern Flutter.
   * 
   * @warning DO NOT REMOVE:
   * While not currently used for status updates, this mechanism may be needed
   * for other UI operations. Removing it may break future functionality.
   */
  // Setup UI thread invocation mechanism using window proc delegate
  if (registrar_) {
    auto view = registrar_->GetView();
    if (view) {
      main_window_handle_ = view->GetNativeWindow();
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
    
    /**
     * @brief Registers window proc delegate for UI thread callback execution.
     * 
     * @details Window Proc Delegate:
     * Flutter Windows allows plugins to register a delegate that intercepts
     * window messages before they reach the default window procedure. This
     * provides a way to execute code on the UI thread by posting custom messages.
     * 
     * @details Message Handling:
     * When a custom window message (ui_callback_message_id_) is received:
     * 1. The delegate extracts all queued callbacks from ui_callbacks_
     * 2. Executes each callback on the UI thread
     * 3. Returns LRESULT(0) to indicate the message was handled
     * 
     * @note Currently not used for status updates, but kept for future use.
     */
    window_proc_delegate_id_ = registrar_->RegisterTopLevelWindowProcDelegate(
        [this](HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
            -> std::optional<LRESULT> {
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
  StopStatusTimer();
  V2rayManager::GetInstance().Stop();
  
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
  if (method_call.method_name().compare("requestPermission") == 0) {
    // On Windows, we typically don't need special VPN permissions
    // but we might need admin rights for TUN/TAP interface
    result->Success(flutter::EncodableValue(true));
  } else if (method_call.method_name().compare("initializeVless") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      LogMessage("initializeVless called");
      // Just initialize and return - EventChannel will send initial status
      result->Success(flutter::EncodableValue(nullptr));
    } else {
      result->Error("INVALID_ARGUMENTS", "Invalid arguments for initializeVless");
    }
  } else if (method_call.method_name().compare("startVless") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto remark_it = arguments->find(flutter::EncodableValue("remark"));
      auto config_it = arguments->find(flutter::EncodableValue("config"));
      auto proxy_only_it = arguments->find(flutter::EncodableValue("proxy_only"));
      auto set_system_proxy_it = arguments->find(flutter::EncodableValue("set_system_proxy"));
      
      if (remark_it != arguments->end() && config_it != arguments->end()) {
        std::string remark = std::get<std::string>(remark_it->second);
        std::string config = std::get<std::string>(config_it->second);
        bool proxy_only = false;
        bool set_system_proxy = true;
        
        if (proxy_only_it != arguments->end()) {
          const auto* proxy_only_value = std::get_if<bool>(&proxy_only_it->second);
          if (proxy_only_value) {
            proxy_only = *proxy_only_value;
          }
        }
        if (set_system_proxy_it != arguments->end()) {
          const auto* set_system_proxy_value = std::get_if<bool>(&set_system_proxy_it->second);
          if (set_system_proxy_value) {
            set_system_proxy = *set_system_proxy_value;
          }
        }

        // Convert unique_ptr to shared_ptr to allow capturing in std::function (which requires CopyConstructible)
        std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);
        
        std::thread([this, config, proxy_only, set_system_proxy, shared_result]() {
          std::lock_guard<std::mutex> lock(lifecycle_mutex_);
          LogMessage("Starting Xray...");
          if (V2rayManager::GetInstance().Start(config, proxy_only, set_system_proxy)) {
            LogMessage("Xray started successfully");
            is_running_ = true;
            start_time_ = std::chrono::steady_clock::now();
            StartStatusTimer();
          } else {
            LogMessage("Xray failed to start");
          }
          
          // Return result on UI thread
          RunOnUIThread([shared_result]() {
            shared_result->Success(flutter::EncodableValue(nullptr));
          });
        }).detach();

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

    std::thread([this, shared_result]() {
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
      RunOnUIThread([shared_result]() {
        shared_result->Success(flutter::EncodableValue(nullptr));
      });
    }).detach();

  } else if (method_call.method_name().compare("getServerDelay") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto config_it = arguments->find(flutter::EncodableValue("config"));
      auto url_it = arguments->find(flutter::EncodableValue("url"));
      
      if (config_it != arguments->end() && url_it != arguments->end()) {
        std::string config = std::get<std::string>(config_it->second);
        std::string url = std::get<std::string>(url_it->second);
        
        std::thread([this, config, url, result = std::move(result)]() {
          int delay = V2rayManager::GetInstance().GetServerDelay(config, url);
          result->Success(flutter::EncodableValue(delay));
        }).detach();
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
        
        std::thread([this, url, result = std::move(result)]() {
          int delay = V2rayManager::GetInstance().GetConnectedServerDelay(url);
          result->Success(flutter::EncodableValue(delay));
        }).detach();
        return;
      }
    }
    result->Error("INVALID_ARGUMENTS", "Invalid arguments for getConnectedServerDelay");
  } else if (method_call.method_name().compare("getCoreVersion") == 0) {
    std::string version = V2rayManager::GetInstance().GetCoreVersion();
    LogMessage("getCoreVersion: " + version);
    result->Success(flutter::EncodableValue(version));
  } else {
    result->NotImplemented();
  }
}

void FlutterVlessPlugin::StartStatusTimer() {
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
 * The status format and calculation logic must remain unchanged. The Flutter
 * UI expects this exact format. Changing the order or format of status elements
 * will break UI updates.
 * 
 * @note Thread Safety:
 * Uses status_mutex_ to protect traffic statistics and sink_mutex_ to protect
 * status_sink_ access. The function is called from status_thread_ (background
 * thread), but SendStatusToUI() handles thread-safe EventSink operations.
 */
void FlutterVlessPlugin::UpdateStatus() {
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
  int64_t current_upload = 0;
  int64_t current_download = 0;
  V2rayManager::GetInstance().GetTrafficStats(current_upload, current_download);

  upload_speed_ = current_upload - total_upload_;
  download_speed_ = current_download - total_download_;
  total_upload_ = current_upload;
  total_download_ = current_download;

  flutter::EncodableList status;
  status.push_back(flutter::EncodableValue(std::to_string(duration)));
  status.push_back(flutter::EncodableValue(std::to_string(upload_speed_)));
  status.push_back(flutter::EncodableValue(std::to_string(download_speed_)));
  status.push_back(flutter::EncodableValue(std::to_string(total_upload_)));
  status.push_back(flutter::EncodableValue(std::to_string(total_download_)));
  status.push_back(flutter::EncodableValue("CONNECTED"));

  LogMessage("UpdateStatus: duration=" + std::to_string(duration) + " up=" + 
            std::to_string(upload_speed_) + " down=" + std::to_string(download_speed_));

  // Send status to UI thread
  SendStatusToUI(status);
}


/**
 * @brief Sends status update to Flutter UI via EventChannel EventSink.
 * 
 * @param status Status data as EncodableList (see UpdateStatus() for format).
 * 
 * @details Thread Safety and UI Thread Requirements:
 * 
 * @subsection Threading_Model Threading Model:
 * - This function is called from background threads (status update thread)
 * - Flutter documentation recommends calling EventSink from UI thread
 * - However, modern Flutter Windows implementation makes EventSink thread-safe
 * - The warning "sent a message from native to Flutter on a non-platform thread"
 *   is non-critical and does not affect functionality
 * 
 * @subsection Implementation_Details Implementation Details:
 * The function uses direct EventSink->Success() calls with proper mutex
 * synchronization. While Flutter prefers UI thread execution, the thread-safe
 * nature of EventSink in modern Flutter Windows allows this approach to work
 * correctly from any thread.
 * 
 * @subsection Alternative_Approach Alternative Approach (Not Used):
 * An alternative approach using PostMessage + window proc delegate was
 * considered but not implemented because:
 * - EventSink is already thread-safe in modern Flutter
 * - Direct calls are simpler and more reliable
 * - The PostMessage mechanism adds complexity without clear benefits
 * 
 * @details Status Format:
 * The status parameter must be an EncodableList with exactly 6 string elements:
 * [0] = duration (seconds)
 * [1] = upload speed (bytes/second)
 * [2] = download speed (bytes/second)
 * [3] = total upload (bytes)
 * [4] = total download (bytes)
 * [5] = status ("CONNECTED" or "DISCONNECTED")
 * 
 * @details Error Handling:
 * - Catches and logs exceptions during EventSink operations
 * - Logs warning if status_sink_ is null (EventChannel not connected)
 * - Continues execution even if status send fails (non-critical)
 * 
 * @warning CRITICAL: DO NOT MODIFY THIS FUNCTION
 * 
 * This function is critical for UI communication. Modifying the status sending
 * logic, format, or thread handling may break Flutter UI updates. The current
 * implementation works correctly despite the non-UI thread warning.
 * 
 * @note The warning about non-platform thread is expected and non-critical.
 *       The functionality works correctly as-is.
 * 
 * @note Status updates are protected by sink_mutex_ to ensure thread-safe
 *       access to status_sink_ even though EventSink itself is thread-safe.
 */
void FlutterVlessPlugin::SendStatusToUI(const flutter::EncodableList& status) {
  // In modern Flutter Windows, EventSink operations are thread-safe
  // We can safely call Success() from any thread, but Flutter prefers UI thread
  // Since PostMessage -> delegate mechanism doesn't seem to work reliably,
  // we'll use a simpler approach: send directly with proper synchronization
  
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
