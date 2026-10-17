import AppIntents
import WidgetKit
import LocalAuthentication
#if os(macOS)
import flutter_vless_macos_privacy
#else
import flutter_vless_privacy
#endif

// Include this source in BOTH Runner and VlessControls targets.
@available(iOS 18.0, macOS 26.0, *)
struct VlessControlIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Set VPN connection"
    // Apple requires constant intent metadata. The app checks the current
    // requireUnlock setting with LocalAuthentication before changing the VPN.
    static let authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed
    static let openAppWhenRun = true
    @Parameter(title: "Connected") var value: Bool
    static var group: String { Bundle.main.object(forInfoDictionaryKey: "FlutterVlessControlGroupIdentifier") as? String ?? "" }
    static var provider: String { Bundle.main.object(forInfoDictionaryKey: "FlutterVlessControlProviderIdentifier") as? String ?? "" }
    private func requireHost() throws { throw VlessSystemControl.Failure.unavailable }
    func perform() async throws -> some IntentResult {
        #if FLUTTER_VLESS_WIDGET_EXTENSION
        // Runner owns the Network Extension entitlement and authentication UI.
        try requireHost()
        #else
        try await VlessSystemControl.perform(value, group: Self.group, provider: Self.provider) {
            let context = LAContext()
            let accepted = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Change VPN connection")
            guard accepted else { throw VlessSystemControl.Failure.unavailable }
        }
        ControlCenter.shared.reloadControls(ofKind: "dev.tfox.flutter-vless.control")
        #endif
        return .result()
    }
}
