import Foundation
import CoreFoundation

/// Shared by the app and Network Extension. Contains policy/presentation only.
public struct VlessNativeOptions {
    public enum Failure: Error, Equatable { case invalid(String), unsupported(String), setupRequired(String) }
    public let notificationIconType: String
    public let notificationIconName: String
    public let notificationButtonLabel: String
    public let notificationAction: String
    public let quickAccessEnabled: Bool
    public let quickAccessSurface: String
    public let quickAccessLabel: String
    public let quickAccessAction: String
    public let requireUnlock: Bool
    public let androidIconName: String
    public let appleSymbol: String
    public let windowsIconPath: String?
    public let reconnectEnabled: Bool
    public let initialDelayMs: Int
    public let maxDelayMs: Int
    public let maxAttempts: Int
    public let killSwitch: String
    public let onDemand: String
    public let alwaysOn: String
    public let diagnosticsEnabled: Bool
    public let diagnosticsMaxBytes: Int
    public let diagnosticsMaxLines: Int

    public init(_ raw: [String: Any]? = nil) throws {
        let raw = raw ?? [:]
        func section(_ name: String) throws -> [String: Any] {
            guard let value = raw[name] else { return [:] }
            guard let value = value as? [String: Any] else { throw Failure.invalid(name) }
            return value
        }
        func text(_ map: [String: Any], _ name: String, _ fallback: String, limit: Int = 128) throws -> String {
            guard let value = map[name] else { return fallback }
            guard let value = value as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  value.utf16.count <= limit, !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { throw Failure.invalid(name) }
            return value
        }
        func flag(_ map: [String: Any], _ name: String, _ fallback: Bool) throws -> Bool {
            guard let value = map[name] else { return fallback }
            guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { throw Failure.invalid(name) }
            return value.boolValue
        }
        func number(_ map: [String: Any], _ name: String, _ fallback: Int) throws -> Int {
            guard let value = map[name] else { return fallback }
            guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
                  value.doubleValue.isFinite, value.doubleValue >= -1_000_000_000,
                  value.doubleValue <= 1_000_000_000, value.doubleValue == Double(value.intValue) else { throw Failure.invalid(name) }
            return value.intValue
        }
        func choice(_ value: String, _ choices: [String], _ name: String) throws -> String {
            guard choices.contains(value) else { throw Failure.invalid(name) }; return value
        }
        func resource(_ value: String) throws -> String {
            guard value.range(of: #"^[a-zA-Z_][a-zA-Z0-9_]*$"#, options: .regularExpression) != nil else { throw Failure.invalid("resource") }; return value
        }
        guard try number(raw,"version",1) == 1 else { throw Failure.unsupported("version") }
        let n = try section("notification"), q = try section("quickAccess"), r = try section("reconnect")
        let p = try section("protection"), d = try section("diagnostics")
        notificationIconType = try choice(text(n,"iconResourceType","mipmap"),["mipmap","drawable"],"iconResourceType")
        notificationIconName = try resource(text(n,"iconResourceName","ic_launcher"))
        notificationButtonLabel = try text(n,"buttonLabel","DISCONNECT",limit:80)
        notificationAction = try choice(text(n,"action","disconnect"),["disconnect","openApp","none"],"notification.action")
        quickAccessEnabled = try flag(q,"enabled",false)
        quickAccessSurface = try choice(text(q,"surface","platformDefault"),["platformDefault","quickTile","menuBar","systemTray","controlCenter"],"surface")
        quickAccessLabel = try text(q,"label","VPN",limit:80)
        quickAccessAction = try choice(text(q,"action","toggle"),["toggle","openApp"],"quickAccess.action")
        requireUnlock = try flag(q,"requireUnlock",true)
        androidIconName = try resource(text(q,"androidIconResourceName","flutter_vless_ic_quick_tile"))
        appleSymbol = try text(q,"appleSymbol","network")
        if let path = q["windowsIconPath"] {
            guard let path = path as? String, !path.contains("\0"), path.lowercased().hasSuffix(".ico"),
                  path.range(of: #"^(?:[a-zA-Z]:[\\/]|\\\\)"#,options:.regularExpression) != nil else { throw Failure.invalid("windowsIconPath") }
            windowsIconPath = path
        } else { windowsIconPath = nil }
        reconnectEnabled = try flag(r,"enabled",true)
        initialDelayMs = try number(r,"initialDelayMs",1000)
        maxDelayMs = try number(r,"maxDelayMs",60000)
        maxAttempts = try number(r,"maxAttempts",0)
        guard initialDelayMs >= 100, maxDelayMs >= initialDelayMs, maxDelayMs <= 600000,
              maxAttempts >= 0, maxAttempts <= 1000 else { throw Failure.invalid("reconnect") }
        killSwitch = try choice(text(p,"killSwitch","required"),["required","platformDefault"],"killSwitch")
        onDemand = try choice(text(p,"onDemand","platformDefault"),["platformDefault","enabled","disabled"],"onDemand")
        alwaysOn = try choice(text(p,"alwaysOn","system"),["system","requireEnabled"],"alwaysOn")
        guard reconnectEnabled || onDemand != "enabled" else { throw Failure.invalid("onDemand/reconnect") }
        diagnosticsEnabled = try flag(d,"enabled",true)
        diagnosticsMaxBytes = try number(d,"maxBytes",131072)
        diagnosticsMaxLines = try number(d,"maxLines",300)
        guard diagnosticsMaxBytes >= 4096, diagnosticsMaxBytes <= 131072,
              diagnosticsMaxLines >= 1, diagnosticsMaxLines <= 300 else { throw Failure.invalid("diagnostics") }
    }

    public var enableOnDemand: Bool { reconnectEnabled && onDemand != "disabled" }
    public func mayRetry(failures: Int) -> Bool { reconnectEnabled && (maxAttempts == 0 || failures < maxAttempts) }
    public func retryDelay(failures: Int) -> TimeInterval {
        Double(min(maxDelayMs,initialDelayMs * (1 << min(max(0,failures),23)))) / 1000
    }
    public func validateApple(isMac: Bool, controlCenterAvailable: Bool, extensionConfigured: Bool) throws {
        guard alwaysOn != "requireEnabled" else { throw Failure.unsupported("Apple Always On is a managed IKEv2 feature, not a custom Packet Tunnel option") }
        guard !quickAccessEnabled else {
            let surface = quickAccessSurface == "platformDefault" ? (isMac ? "menuBar" : "controlCenter") : quickAccessSurface
            if surface == "menuBar" && isMac { return }
            guard surface == "controlCenter", controlCenterAvailable else { throw Failure.unsupported("quickAccess.surface") }
            guard extensionConfigured else { throw Failure.setupRequired("Install the host Control Widget extension") }
            return
        }
    }
    public var dictionary: [String: Any] {
        var quick: [String: Any] = ["enabled":quickAccessEnabled,"surface":quickAccessSurface,"label":quickAccessLabel,
            "action":quickAccessAction,"requireUnlock":requireUnlock,"androidIconResourceName":androidIconName,"appleSymbol":appleSymbol]
        if let path = windowsIconPath { quick["windowsIconPath"] = path }
        return ["version":1,
            "notification":["iconResourceType":notificationIconType,"iconResourceName":notificationIconName,"buttonLabel":notificationButtonLabel,"action":notificationAction],
            "quickAccess":quick,
            "reconnect":["enabled":reconnectEnabled,"initialDelayMs":initialDelayMs,"maxDelayMs":maxDelayMs,"maxAttempts":maxAttempts],
            "protection":["killSwitch":killSwitch,"onDemand":onDemand,"alwaysOn":alwaysOn],
            "diagnostics":["enabled":diagnosticsEnabled,"maxBytes":diagnosticsMaxBytes,"maxLines":diagnosticsMaxLines]]
    }
}
