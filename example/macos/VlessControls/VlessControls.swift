import SwiftUI
import WidgetKit
#if os(macOS)
import flutter_vless_macos_privacy
#else
import flutter_vless_privacy
#endif

@main
struct VlessControlsBundle: WidgetBundle {
    var body: some Widget { VlessConnectionControl() }
}

struct VlessConnectionControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "dev.tfox.flutter-vless.control", provider: ValueProvider()) { connected in
            let options = VlessSystemControl.options(group: VlessControlIntent.group)
            ControlWidgetToggle(isOn: connected, action: VlessControlIntent()) {
                Label(options?.quickAccessLabel ?? "VPN", systemImage: options?.appleSymbol ?? "network")
            }
        }
        .displayName("VPN")
        .description("Connect or disconnect the last VPN profile saved by the app.")
    }
    struct ValueProvider: ControlValueProvider {
        var previewValue: Bool { false }
        func currentValue() async throws -> Bool {
            await VlessSystemControl.isConnected(group: VlessControlIntent.group, provider: VlessControlIntent.provider)
        }
    }
}
