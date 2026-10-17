import AppKit
import NetworkExtension
#if canImport(flutter_vless_macos_privacy)
import flutter_vless_macos_privacy
#endif

/// Owns only its status item. Closing it never changes another app's VPN.
final class VlessMenuBarControl: NSObject {
    private let item: NSStatusItem
    private let group: String
    private let provider: String
    private let options: VlessNativeOptions
    private let toggleItem = NSMenuItem()
    private var observer: NSObjectProtocol?
    private var connected = false
    private var pending = false
    private var revision = 0

    init(group: String, provider: String, options: VlessNativeOptions) {
        self.group = group; self.provider = provider; self.options = options
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        super.init()
        item.button?.image = NSImage(systemSymbolName: options.appleSymbol, accessibilityDescription: options.quickAccessLabel)
            ?? NSImage(systemSymbolName: "network", accessibilityDescription: options.quickAccessLabel)
        let menu = NSMenu()
        toggleItem.target = self; toggleItem.action = #selector(toggle)
        menu.addItem(toggleItem)
        let open = NSMenuItem(title: "Open \(options.quickAccessLabel)", action: #selector(openApp), keyEquivalent: "")
        open.target = self; menu.addItem(open)
        item.menu = menu
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in self?.refresh() }
        refresh()
    }
    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        NSStatusBar.system.removeStatusItem(item)
    }
    func refresh() {
        revision += 1; let expected = revision
        Task { @MainActor [weak self] in
            guard let self else { return }
            let active = await VlessSystemControl.isConnected(group: group, provider: provider)
            guard revision == expected else { return }
            connected = active
            toggleItem.title = options.quickAccessAction == "openApp" ? "Open app" : (active ? "Disconnect" : "Connect")
            toggleItem.state = active ? .on : .off
            toggleItem.isEnabled = !pending
            item.button?.toolTip = "\(options.quickAccessLabel): \(active ? "Connected" : "Disconnected")"
        }
    }
    @objc private func openApp() { NSApp.activate(ignoringOtherApps: true); NSApp.windows.first(where: { $0.canBecomeMain })?.makeKeyAndOrderFront(nil) }
    @objc private func toggle() {
        guard !pending else { return }
        if options.quickAccessAction == "openApp" { openApp(); return }
        pending = true; toggleItem.isEnabled = false
        Task { @MainActor [weak self] in
            guard let self else { return }
            do { try await VlessSystemControl.setConnected(!connected, group: group, provider: provider) }
            catch { openApp() }
            pending = false; refresh()
        }
    }
}
