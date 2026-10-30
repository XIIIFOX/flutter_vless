// Only the explicitly opted-in acceptance app can register this view/channel.
// This is an ordinary, visible WebKit view. It never changes Safari storage.
#if FLUTTER_VLESS_ACCEPTANCE_TESTING
import Flutter
import UIKit
import WebKit
import CryptoKit
import flutter_vless_core_compat

final class AcceptanceWebDiagnosticsFactory: NSObject, FlutterPlatformViewFactory {
  static let channelName = "dev.tfox.flutterXrayExample/acceptanceWeb"
  private let registrar: FlutterPluginRegistrar
  private weak var current: AcceptanceWebDiagnosticsView?
  private let channel: FlutterMethodChannel
  private let session = UUID().uuidString

  init(registrar: FlutterPluginRegistrar) {
    self.registrar = registrar
    channel = FlutterMethodChannel(name: Self.channelName, binaryMessenger: registrar.messenger())
    super.init()
    channel.setMethodCallHandler { [weak self] call, result in
      guard let self, self.admitted else { result(Self.unavailable()); return }
      switch call.method {
      case "available" where call.arguments == nil || call.arguments is NSNull:
        result(true)
      case "navigate":
        guard let target = call.arguments as? String,
              ["2ip", "tfox"].contains(target), let current = self.current,
              current.view().window != nil else { result(Self.unavailable()); return }
        current.navigate(target: target)
        result(true)
      case "stop" where call.arguments == nil || call.arguments is NSNull:
        self.current?.stop()
        result(true)
      case "snapshot" where call.arguments == nil || call.arguments is NSNull:
        self.snapshot(result: result)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private var admitted: Bool {
    ProcessInfo.processInfo.arguments.contains("--flutter-vless-acceptance-web-diagnostics") &&
      Bundle.main.bundleIdentifier == "dev.tfox.flutterXrayExample" &&
      UIApplication.shared.applicationState == .active &&
      UIApplication.shared.isProtectedDataAvailable
  }

  private static func unavailable() -> FlutterError {
    FlutterError(code: "ACCEPTANCE_UNAVAILABLE", message: "Web acceptance unavailable.", details: nil)
  }

  func create(withFrame frame: CGRect, viewIdentifier viewId: Int64,
              arguments args: Any?) -> FlutterPlatformView {
    let value = AcceptanceWebDiagnosticsView(frame: frame, session: session)
    current = value
    return value
  }

  private func snapshot(result: @escaping FlutterResult) {
    guard admitted, let root = (registrar.viewController as? FlutterViewController)?.viewIfLoaded,
          root.window != nil, root.bounds.width > 0, root.bounds.height > 0 else {
      result(Self.unavailable()); return
    }
    let pid = Int(ProcessInfo.processInfo.processIdentifier)
    let timestamp = Date().timeIntervalSince1970
    if let current, current.view().window != nil {
      current.capture { [weak self] image, observation in
        guard let self, self.admitted else { result(Self.unavailable()); return }
        if let image {
          self.save(image: image, backend: "WKWebView.takeSnapshot", pid: pid,
                    timestamp: timestamp, observation: observation, result: result)
        } else {
          // A reloading page can reject WebKit snapshots. Keep the HTTP trace
          // and capture the same visible own-app view through UIKit instead.
          var diagnostic = observation
          diagnostic["WebKit_snapshot_unavailable"] = true
          let renderer = UIGraphicsImageRenderer(bounds: root.bounds)
          var rendered = false
          let fallback = renderer.image { _ in
            rendered = root.drawHierarchy(in: root.bounds, afterScreenUpdates: true)
          }
          diagnostic["UIKit_draw_completed"] = rendered
          self.save(image: fallback, backend: "UIView.drawHierarchy-own-application-WK-fallback",
                    pid: pid, timestamp: timestamp, observation: diagnostic, result: result)
        }
      }
    } else {
      let renderer = UIGraphicsImageRenderer(bounds: root.bounds)
      let image = renderer.image { _ in root.drawHierarchy(in: root.bounds, afterScreenUpdates: true) }
      save(image: image, backend: "UIView.drawHierarchy-own-application", pid: pid,
           timestamp: timestamp, observation: [:], result: result)
    }
  }

  private func runtimeCapabilities() -> [String: Int] {
    [
      "geodata_lifetime": Int(FLVlessCoreGeodataLifetimeCapability()),
      "xdrive_lifetime": Int(FLVlessCoreXdriveLifetimeCapability()),
      "vpn_routing": Int(FLVlessCoreRoutingCapability()),
      "darwin_interface_binding": Int(FLVlessCoreDarwinInterfaceBindingCapability())
    ]
  }

  private func save(image: UIImage, backend: String, pid: Int, timestamp: Double,
                    observation: [String: Any], result: @escaping FlutterResult) {
    do {
      guard admitted, let data = image.pngData(), data.count < 12 * 1024 * 1024,
            let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else {
        result(Self.unavailable()); return
      }
      let folder = caches.appendingPathComponent("flutter-vless-acceptance-web", isDirectory: true)
      try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.complete])
      let name = UUID().uuidString
      let imageURL = folder.appendingPathComponent(name + ".png")
      guard FileManager.default.createFile(atPath: imageURL.path, contents: data,
        attributes: [.posixPermissions: 0o600, .protectionKey: FileProtectionType.complete]) else {
        result(Self.unavailable()); return
      }
      let record: [String: Any] = [
        "schema": 1, "pid": pid, "session": session, "timestamp_epoch": timestamp,
        "captured_epoch": Date().timeIntervalSince1970,
        "backend": backend, "app_active_protected_data_available": true,
        "runtime_capabilities": runtimeCapabilities(),
        "image_path": "Library/Caches/flutter-vless-acceptance-web/" + name + ".png",
        "image_sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
        "image_width": Int(image.size.width * image.scale),
        "image_height": Int(image.size.height * image.scale), "observation": observation
      ]
      let json = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
      guard json.count < 96 * 1024 else { result(Self.unavailable()); return }
      guard FileManager.default.createFile(atPath: folder.appendingPathComponent(name + ".json").path,
        contents: json, attributes: [.posixPermissions: 0o600, .protectionKey: FileProtectionType.complete]) else {
        result(Self.unavailable()); return
      }
      result(record)
    } catch { result(Self.unavailable()) }
  }
}

private final class AcceptanceWebDiagnosticsView: NSObject, FlutterPlatformView, WKNavigationDelegate {
  private let web: WKWebView
  private let session: String
  private var events: [[String: Any]] = []
  private var deadline: DispatchWorkItem?
  private var background: NSObjectProtocol?
  private var navigationID = UUID().uuidString
  private var paused = false

  init(frame: CGRect, session: String) {
    let config = WKWebViewConfiguration()
    config.websiteDataStore = .nonPersistent()
    web = WKWebView(frame: frame, configuration: config)
    self.session = session
    super.init()
    web.navigationDelegate = self
    background = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
      object: nil, queue: .main) { [weak self] _ in self?.stop() }
    record("created", ["nonpersistent_store": true, "session": session])
  }

  deinit {
    deadline?.cancel()
    if let background { NotificationCenter.default.removeObserver(background) }
  }

  func view() -> UIView { web }

  func stop(clearDocument: Bool = true) {
    deadline?.cancel(); deadline = nil
    web.stopLoading()
    if clearDocument {
      // Replacing the page also cancels its JavaScript reload timers.
      paused = true
      web.loadHTMLString("<!doctype html><title>QA stopped</title><p>QA navigation stopped.</p>", baseURL: nil)
    }
    record("stopped", [:])
  }

  func navigate(target: String) {
    stop(clearDocument: false)
    paused = false
    navigationID = UUID().uuidString
    let path = target == "2ip" ? "https://2ip.ru/" : "https://tfox.dev/ip/"
    let url = URL(string: path + "?test=ios-web-qa-" + navigationID)!
    record("requested", ["target": target, "navigation": navigationID, "url": safeURL(url)])
    let token = navigationID
    let work = DispatchWorkItem { [weak self] in
      guard let self, self.navigationID == token else { return }
      self.stop(); self.record("navigation_deadline", ["seconds": 25])
    }
    deadline = work
    DispatchQueue.main.asyncAfter(deadline: .now() + 25, execute: work)
    web.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20))
  }

  private func safeURL(_ url: URL?) -> String {
    guard let url, let host = url.host else { return "unavailable" }
    let path = ["", "/", "/ru", "/ru/", "/ip", "/ip/"].contains(url.path) ? url.path : "/<redacted-path>"
    return String(host.lowercased().prefix(160)) + path
  }

  private func allowed(_ url: URL?) -> Bool {
    guard let url, url.scheme == "https", url.user == nil, url.password == nil,
          url.port == nil || url.port == 443, let host = url.host?.lowercased() else { return false }
    return ["2ip.ru", "2ip.io"].contains(host) || (host == "tfox.dev" && ["/ip", "/ip/"].contains(url.path))
  }

  private func record(_ kind: String, _ fields: [String: Any]) {
    events.append(fields.merging(["kind": kind, "epoch": Date().timeIntervalSince1970]) { _, new in new })
    while events.count > 160 || ((try? JSONSerialization.data(withJSONObject: events).count) ?? 0) > 64 * 1024 {
      events.removeFirst()
    }
  }

  func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
               decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    let main = navigationAction.targetFrame?.isMainFrame ?? true
    if paused {
      decisionHandler(navigationAction.request.url?.absoluteString == "about:blank" ? .allow : .cancel)
      return
    }
    guard navigationAction.request.url?.scheme == "https" else {
      decisionHandler(.cancel); return
    }
    if main {
      let ok = allowed(navigationAction.request.url)
      record("action", ["url": safeURL(navigationAction.request.url), "allowed": ok])
      decisionHandler(ok ? .allow : .cancel)
    } else { decisionHandler(.allow) }
  }

  func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
               decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
    if navigationResponse.isForMainFrame {
      let response = navigationResponse.response as? HTTPURLResponse
      record("response", ["url": safeURL(response?.url), "status": response?.statusCode ?? -1,
        "mime": String((response?.mimeType ?? "unknown").prefix(100))])
    }
    decisionHandler(.allow)
  }

  func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
    record("redirect", ["url": safeURL(webView.url)])
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    record("finished", ["url": safeURL(webView.url)])
  }

  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
    recordError(error)
  }

  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
    recordError(error)
  }

  private func recordError(_ error: Error) {
    let value = error as NSError
    record("error", ["domain": String(value.domain.prefix(100)), "code": value.code])
  }

  func capture(_ completion: @escaping (UIImage?, [String: Any]) -> Void) {
    var completed = false
    func finish(_ image: UIImage?, _ observation: [String: Any]) {
      guard !completed else { return }
      completed = true
      completion(image, observation)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 6) { [weak self] in
      guard !completed else { return }
      var observation: [String: Any] = ["snapshot_deadline_seconds": 6]
      if let self {
        observation["events"] = self.events
        observation["url"] = self.safeURL(self.web.url)
        observation["nonpersistent_store"] = true
        observation["navigation"] = self.navigationID
      }
      // Snapshot cancellation must not replace the observed page. Its separate
      // 25-second navigation deadline still cancels page reloads and requests.
      finish(nil, observation)
    }
    // Fixed read-only script: no caller-supplied JavaScript, cookie values or body text.
    let script = #"""
      (() => {
        const text = (document.body?.innerText || '').slice(0,131072);
        const ips = [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].slice(0,16);
        const origins = [...new Set(performance.getEntriesByType('resource').slice(-128).map(x => {
          try { return new URL(x.name).hostname.slice(0,160); } catch (_) { return ''; }
        }).filter(Boolean))].slice(0,32);
        return {ready:document.readyState, title:document.title.slice(0,120), bodyIPs:ips,
          loadingText:/2ip loading|loading\.\.\./i.test(text), resourceHosts:origins,
          cookieNames:document.cookie.split(';').map(x=>x.trim().split('=')[0])
            .filter(x=>/^[A-Za-z0-9_.-]{1,100}$/.test(x)).slice(0,32)};
      })()
      """#
    web.evaluateJavaScript(script) { [weak self] value, error in
      guard !completed else { return }
      guard let self else { finish(nil, [:]); return }
      var observation: [String: Any] = ["url": self.safeURL(self.web.url),
        "events": self.events, "nonpersistent_store": true, "navigation": self.navigationID]
      if let fields = value as? [String: Any] { observation["DOM"] = fields }
      if let error { observation["DOM_error_code"] = (error as NSError).code }
      self.web.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
        guard !completed else { return }
        guard let self else { finish(nil, [:]); return }
        let relevant = cookies.filter { ["2ip.ru", "2ip.io", "tfox.dev"].contains($0.domain.trimmingCharacters(in: CharacterSet(charactersIn: "."))) }
        observation["cookie_count"] = relevant.count
        observation["cookie_names"] = Array(Set(relevant.map { String($0.name.prefix(100)) })).sorted().prefix(32).map { $0 }
        self.web.takeSnapshot(with: nil) { image, error in
          guard !completed else { return }
          if let error { observation["snapshot_error_code"] = (error as NSError).code }
          finish(image, observation)
        }
      }
    }
  }
}
#endif
