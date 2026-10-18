import Flutter
import UIKit
#if FLUTTER_VLESS_ACCEPTANCE_TESTING
import NetworkExtension
#endif

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
#if FLUTTER_VLESS_ACCEPTANCE_TESTING
  private var acceptanceChannel: FlutterMethodChannel?
  private var acceptanceManager: NETunnelProviderManager?
  private var acceptanceRequestInFlight = false
#endif

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
#if FLUTTER_VLESS_ACCEPTANCE_TESTING
    let channel = FlutterMethodChannel(
      name: "dev.tfox.flutterXrayExample/acceptance",
      binaryMessenger: engineBridge.applicationRegistrar.messenger()
    )
    acceptanceChannel = channel
    channel.setMethodCallHandler { [weak self] call, result in
      guard call.method == "stopCore", call.arguments == nil || call.arguments is NSNull else {
        result(FlutterMethodNotImplemented)
        return
      }
      DispatchQueue.main.async {
        guard let self else {
          result(Self.acceptanceError())
          return
        }
        self.stopAcceptanceCore(result: result)
      }
    }
#endif
  }

#if FLUTTER_VLESS_ACCEPTANCE_TESTING
  private static func acceptanceError() -> FlutterError {
    FlutterError(code: "ACCEPTANCE_UNAVAILABLE", message: "Worker-loss acceptance unavailable.", details: nil)
  }

  private func stopAcceptanceCore(result: @escaping FlutterResult) {
    guard !acceptanceRequestInFlight else {
      result(Self.acceptanceError())
      return
    }
    acceptanceRequestInFlight = true
    // Every completion runs on the main queue. A timeout also invalidates a
    // late preference callback before it can send a destructive test message.
    var completed = false
    func finish(_ value: Any?) {
      guard !completed else { return }
      completed = true
      acceptanceRequestInFlight = false
      acceptanceManager = nil
      result(value)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
      finish(Self.acceptanceError())
    }
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      DispatchQueue.main.async {
        guard !completed else { return }
        let owned = (managers ?? []).filter { manager in
          guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
          return configuration.providerBundleIdentifier == "dev.tfox.flutterXrayExample.XrayTunnel"
            && configuration.providerConfiguration?["groupIdentifier"] as? String == "group.dev.tfox.flutterXray"
        }
        guard error == nil, owned.count == 1, let manager = owned.first,
              manager.isEnabled, !manager.isOnDemandEnabled,
              let session = manager.connection as? NETunnelProviderSession,
              session.status == .connected else {
          finish(Self.acceptanceError())
          return
        }
        self.acceptanceManager = manager
        do {
          try session.sendProviderMessage(Data("acceptance-stop-core".utf8)) { response in
            DispatchQueue.main.async {
              guard response == Data("acceptance-core-stopped".utf8) else {
                finish(Self.acceptanceError())
                return
              }
              finish("acceptance-core-stopped")
            }
          }
        } catch {
          finish(Self.acceptanceError())
        }
      }
    }
  }
#endif
}
