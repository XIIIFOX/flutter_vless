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
  private var acceptanceVMReceiptToken: UUID?
  private var acceptanceVMReceiptObserver: NSObjectProtocol?
  private var acceptanceWebFactory: AcceptanceWebDiagnosticsFactory?
#endif

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
#if FLUTTER_VLESS_ACCEPTANCE_TESTING
    // Also clear a receipt left by an interrupted, explicitly opted-in launch.
    clearAcceptanceVMReceipt()
#endif
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
#if FLUTTER_VLESS_ACCEPTANCE_TESTING
    startAcceptanceVMReceipt(registry: engineBridge.pluginRegistry)
    if ProcessInfo.processInfo.arguments.contains("--flutter-vless-acceptance-web-diagnostics"),
       Bundle.main.bundleIdentifier == "dev.tfox.flutterXrayExample",
       let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "FlutterVlessAcceptanceWeb") {
      let factory = AcceptanceWebDiagnosticsFactory(registrar: registrar)
      acceptanceWebFactory = factory
      registrar.register(factory, withId: "dev.tfox.flutterXrayExample/acceptanceWeb")
    }
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
  private static var acceptanceVMReceiptURL: URL? {
    FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
      .appendingPathComponent("flutter-vless-acceptance", isDirectory: true)
      .appendingPathComponent("vm-service.json", isDirectory: false)
  }

  private func clearAcceptanceVMReceipt() {
    acceptanceVMReceiptToken = nil
    if let observer = acceptanceVMReceiptObserver {
      NotificationCenter.default.removeObserver(observer)
      acceptanceVMReceiptObserver = nil
    }
    if let url = Self.acceptanceVMReceiptURL {
      try? FileManager.default.removeItem(at: url)
      try? FileManager.default.removeItem(at: url.deletingLastPathComponent()
        .appendingPathComponent(".vm-service.tmp"))
    }
  }

  private func startAcceptanceVMReceipt(registry: FlutterPluginRegistry) {
    guard ProcessInfo.processInfo.arguments.contains("--flutter-vless-acceptance-vm-file"),
          Bundle.main.bundleIdentifier == "dev.tfox.flutterXrayExample",
          let registrar = registry.registrar(forPlugin: "FlutterVlessAcceptanceVMReceipt") else { return }
    clearAcceptanceVMReceipt()
    let token = UUID()
    acceptanceVMReceiptToken = token
    acceptanceVMReceiptObserver = NotificationCenter.default.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
    ) { [weak self] _ in
      self?.clearAcceptanceVMReceipt()
    }
    let deadline = ProcessInfo.processInfo.systemUptime + 10
    func poll() {
      guard acceptanceVMReceiptToken == token else { return }
      guard ProcessInfo.processInfo.systemUptime < deadline else {
        clearAcceptanceVMReceipt()
        return
      }
      if let controller = registrar.viewController as? FlutterViewController,
         let url = controller.engine.vmServiceUrl {
        publishAcceptanceVMReceipt(url: url, token: token)
        return
      }
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
        guard self?.acceptanceVMReceiptToken == token else { return }
        poll()
      }
    }
    poll()
  }

  private func publishAcceptanceVMReceipt(url: URL, token: UUID) {
    guard acceptanceVMReceiptToken == token, let destination = Self.acceptanceVMReceiptURL,
          let scheme = url.scheme, ["http", "ws"].contains(scheme),
          let host = url.host, ["127.0.0.1", "::1", "[::1]"].contains(host),
          let port = url.port, (1...65535).contains(port),
          url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
          !url.path.isEmpty, url.path != "/",
          url.absoluteString.utf8.count <= 4096 else {
      clearAcceptanceVMReceipt()
      return
    }
    let manager = FileManager.default
    let temporary = destination.deletingLastPathComponent()
      .appendingPathComponent(".vm-service.tmp")
    defer { try? manager.removeItem(at: temporary) }
    do {
      let data = try JSONSerialization.data(withJSONObject: [
        "schema": 1, "pid": Int(ProcessInfo.processInfo.processIdentifier),
        "bundle": "dev.tfox.flutterXrayExample", "service_uri": url.absoluteString
      ], options: [.sortedKeys])
      guard data.count <= 8192 else { throw CocoaError(.fileWriteUnknown) }
      let attributes: [FileAttributeKey: Any] = [
        .posixPermissions: 0o600, .protectionKey: FileProtectionType.complete
      ]
      try manager.createDirectory(at: destination.deletingLastPathComponent(),
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.complete])
      try manager.setAttributes([.posixPermissions: 0o700, .protectionKey: FileProtectionType.complete],
        ofItemAtPath: destination.deletingLastPathComponent().path)
      guard manager.createFile(atPath: temporary.path, contents: data, attributes: attributes) else {
        throw CocoaError(.fileWriteUnknown)
      }
      try manager.moveItem(at: temporary, to: destination)
      DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self] in
        guard self?.acceptanceVMReceiptToken == token else { return }
        self?.clearAcceptanceVMReceipt()
      }
    } catch {
      clearAcceptanceVMReceipt()
    }
  }

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
