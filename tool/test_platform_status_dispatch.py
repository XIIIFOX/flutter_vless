#!/usr/bin/env python3
"""Exercise production status delivery without starting a VPN or changing routes.

Apple probes compile the actual emitStatus methods with an in-process sink.
The Windows probe compiles the actual dispatcher/sender and pumps real HWND
messages, including a child Flutter view and its top-level window.
"""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def method(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    index = opening + 1
    while depth:
        depth += (source[index] == "{") - (source[index] == "}")
        index += 1
    return source[start:index]


def apple(output):
    sources = [
        ("IOSStatusProbe", ROOT / "ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift"),
        ("MacStatusProbe", ROOT / "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift"),
    ]
    code = '''import Foundation
import os
let pluginLog = Logger(subsystem: "dev.tfox.status-test", category: "status")
func pluginDebug(_ text: String) {}
struct FixtureStatus { let rawValue = 3 }
struct FixtureManager { let status: FixtureStatus? = FixtureStatus() }
'''
    for name, path in sources:
        code += f'''final class {name} {{
    var eventSink: (([String]) -> Void)?
    var uploadSpeed = 2, downloadSpeed = 3, totalUpload = 4, totalDownload = 5
    var lastTrafficLogDate = Date()
    var packetTunnelManager: FixtureManager? = FixtureManager()
    func publish(_ duration: Int, _ state: String) {{
        emitStatus(duration: duration, state: state, reason: "fixture")
    }}
{method(path.read_text(), '    private func emitStatus(')}
}}
'''
    code += '''
func awaitDelivery(_ ready: () -> Bool) {
    let deadline = Date().addingTimeInterval(3)
    while !ready() && Date() < deadline {
        RunLoop.main.run(until: Date().addingTimeInterval(0.01))
    }
    precondition(ready(), "Background event was lost or dispatched to the wrong queue")
}
'''
    for name, _ in sources:
        code += f'''
do {{
    let probe = {name}()
    var payloads: [[String]] = []
    probe.eventSink = {{ payload in
        precondition(Thread.isMainThread, "Flutter sink called off the platform thread")
        payloads.append(payload)
    }}
    probe.publish(1, "CONNECTING")
    precondition(payloads == [["1", "2", "3", "4", "5", "CONNECTING"]])
    DispatchQueue.global().async {{ probe.publish(9, "CONNECTED") }}
    awaitDelivery {{ payloads.count == 2 }}
    precondition(payloads[1] == ["9", "2", "3", "4", "5", "CONNECTED"])
    probe.eventSink = nil
    DispatchQueue.global().async {{ probe.publish(0, "DISCONNECTED") }}
    RunLoop.main.run(until: Date().addingTimeInterval(0.05))
    precondition(payloads.count == 2, "Cancelled sink received a late event")
    print("{name}: main/background delivery, payload, cancellation passed")
}}
'''
    source = output / "main.swift"
    source.write_text(code)
    subprocess.run(["xcrun", "swiftc", "-O", str(source), "-o", str(output / "apple_status_probe")], check=True)
    subprocess.run([str(output / "apple_status_probe")], check=True, timeout=15)


def windows(output):
    path = ROOT / "packages/flutter_vless_windows/windows/flutter_vless_plugin.cpp"
    source = path.read_text()
    enqueue = method(source, "  void RunOnUIThread(")
    send = method(source, "void FlutterVlessPlugin::SendStatusToUI(")
    root_assignment = next(line.strip() for line in source.splitlines()
                           if line.strip().startswith("main_window_handle_ = view_window"))
    code = r'''#include <windows.h>
#include <cassert>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <vector>
#include <iostream>
namespace flutter {
using Scalar = std::variant<std::string, int>;
using EncodableList = std::vector<Scalar>;
using EncodableValue = EncodableList;
}
void LogMessage(const std::string&) {}
struct Sink {
  DWORD expected_thread;
  std::vector<flutter::EncodableList> payloads;
  void Success(const flutter::EncodableValue& value) {
    assert(GetCurrentThreadId() == expected_thread);
    payloads.push_back(value);
  }
};
class FlutterVlessPlugin {
 public:
  const DWORD platform_thread_id_ = GetCurrentThreadId();
  HWND main_window_handle_ = nullptr;
  UINT ui_callback_message_id_ = WM_APP + 37;
  std::mutex ui_callbacks_mutex_, sink_mutex_;
  std::vector<std::function<void()>> ui_callbacks_;
  std::unique_ptr<Sink> status_sink_ = std::make_unique<Sink>();
  void SendStatusToUI(const flutter::EncodableList& status);
  void Drain() {
    std::vector<std::function<void()>> tasks;
    { std::lock_guard<std::mutex> lock(ui_callbacks_mutex_); tasks.swap(ui_callbacks_); }
    for (auto& task : tasks) task();
  }
'''+enqueue+r'''
};
'''+send+r'''
FlutterVlessPlugin* active = nullptr;
LRESULT CALLBACK RootProc(HWND window, UINT message, WPARAM w, LPARAM l) {
  if (active && message == active->ui_callback_message_id_) { active->Drain(); return 0; }
  return DefWindowProcW(window, message, w, l);
}
int main() {
  FlutterVlessPlugin plugin;
  active = &plugin;
  plugin.status_sink_->expected_thread = GetCurrentThreadId();
  WNDCLASSW root_class{};
  root_class.lpfnWndProc = RootProc;
  root_class.hInstance = GetModuleHandleW(nullptr);
  root_class.lpszClassName = L"FlutterVlessStatusRoot";
  assert(RegisterClassW(&root_class));
  HWND root = CreateWindowW(root_class.lpszClassName, L"fixture", WS_OVERLAPPED,
                           0, 0, 100, 100, nullptr, nullptr, root_class.hInstance, nullptr);
  assert(root);
  HWND view_window = CreateWindowW(L"STATIC", L"view", WS_CHILD, 0, 0, 50, 50,
                                  root, nullptr, root_class.hInstance, nullptr);
  assert(view_window && view_window != root);
  HWND& main_window_handle_ = plugin.main_window_handle_;
  '''+root_assignment+r'''
  assert(main_window_handle_ == root);
  flutter::EncodableList status{std::string("1"), std::string("2"), std::string("3"),
      std::string("4"), std::string("5"), std::string("CONNECTING")};
  plugin.SendStatusToUI(status);
  assert(plugin.status_sink_->payloads.size() == 1);
  std::thread worker([&] {
    auto copied = status;
    copied[0] = std::string("9"); copied[5] = std::string("CONNECTED");
    plugin.SendStatusToUI(copied);
    copied[0] = std::string("mutated-after-enqueue");
    plugin.SendStatusToUI(status);
  });
  worker.join();
  assert(plugin.status_sink_->payloads.size() == 1);
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (plugin.status_sink_->payloads.size() < 3 && std::chrono::steady_clock::now() < until) {
    MSG message;
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
      TranslateMessage(&message); DispatchMessageW(&message);
    }
    Sleep(1);
  }
  const auto& payloads = plugin.status_sink_->payloads;
  assert(payloads.size() == 3);
  assert(std::get<std::string>(payloads[1][0]) == "9");
  assert(std::get<std::string>(payloads[1][5]) == "CONNECTED");
  assert(payloads[2] == status);
  plugin.status_sink_.reset();
  std::thread cancelled([&] { plugin.SendStatusToUI(status); });
  cancelled.join(); plugin.Drain();
  DestroyWindow(root);
  std::cout << "Windows platform status: child/root routing, thread, copied payload, order, cancellation passed\n";
}
'''
    result = output / "status_dispatch_test.cpp"
    result.write_text(code)
    print(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-windows", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "build/platform-status-dispatch")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.generate_windows:
        windows(args.output)
    elif sys.platform == "darwin":
        apple(args.output)
    else:
        parser.error("Use --generate-windows on a Windows build host")


if __name__ == "__main__":
    main()
