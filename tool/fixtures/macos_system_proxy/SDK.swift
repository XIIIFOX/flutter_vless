// In-memory SystemConfiguration/Security boundary for the production helper.
// No calls in this fixture can change the host proxy or VPN.
import Foundation
import flutter_vless_macos_privacy

typealias AuthorizationRef = Int
let errAuthorizationSuccess: Int32 = 0
let kSCNetworkProtocolTypeProxies = "Proxies" as CFString
enum ProxySDK {
    static var saved: [String: [String: Any]] = [:]
    static var active: [String: [String: Any]] = [:]
    static var denyAuthorization = false
    static var denyLock = false
    static var denyCommit = false
    static var denyApply = false
    static var authorizationCount = 0
    static var freeCount = 0
    static var authorizedSessions = 0
    static var applyCount = 0
    static var stageFailureService: String?
}
final class SCPreferences {
    var values = ProxySDK.saved
    let authorized: Bool
    init(authorized: Bool) { self.authorized = authorized }
}
struct SCNetworkService { let prefs: SCPreferences; let id: String }
func AuthorizationCreate(_ rights: Int?, _ environment: Int?, _ flags: [Int], _ value: inout AuthorizationRef?) -> Int32 {
    ProxySDK.authorizationCount += 1
    if ProxySDK.denyAuthorization { return -60006 }
    value = ProxySDK.authorizationCount
    return errAuthorizationSuccess
}
@discardableResult func AuthorizationFree(_ value: AuthorizationRef, _ flags: [Int]) -> Int32 {
    ProxySDK.freeCount += 1
    return 0
}
func SCPreferencesCreate(_ allocator: Int?, _ name: CFString, _ id: CFString?) -> SCPreferences? {
    SCPreferences(authorized: false)
}
func SCPreferencesCreateWithAuthorization(_ allocator: Int?, _ name: CFString, _ id: CFString?, _ authorization: AuthorizationRef?) -> SCPreferences? {
    ProxySDK.authorizedSessions += 1
    return SCPreferences(authorized: authorization != nil)
}
func SCPreferencesLock(_ prefs: SCPreferences, _ wait: Bool) -> Bool { prefs.authorized && !ProxySDK.denyLock }
@discardableResult func SCPreferencesUnlock(_ prefs: SCPreferences) -> Bool { true }
func SCNetworkSetCopyCurrent(_ prefs: SCPreferences) -> SCPreferences? { prefs }
func SCNetworkSetCopyServices(_ prefs: SCPreferences) -> Any? {
    prefs.values.keys.sorted().map { SCNetworkService(prefs: prefs, id: $0) }
}
func SCNetworkServiceCopyAll(_ prefs: SCPreferences) -> Any? { SCNetworkSetCopyServices(prefs) }
func SCNetworkServiceCopyProtocol(_ service: SCNetworkService, _ kind: CFString) -> SCNetworkService? { service }
func SCNetworkServiceGetServiceID(_ service: SCNetworkService) -> CFString? { service.id as CFString }
func SCNetworkProtocolGetConfiguration(_ service: SCNetworkService) -> CFDictionary? {
    service.prefs.values[service.id]! as CFDictionary
}
func SCNetworkProtocolSetConfiguration(_ service: SCNetworkService, _ values: CFDictionary) -> Bool {
    if ProxySDK.stageFailureService == service.id { return false }
    service.prefs.values[service.id] = values as NSDictionary as? [String: Any]
    return true
}
func SCPreferencesCommitChanges(_ prefs: SCPreferences) -> Bool {
    if ProxySDK.denyCommit { return false }
    ProxySDK.saved = prefs.values
    return true
}
func SCPreferencesApplyChanges(_ prefs: SCPreferences) -> Bool {
    ProxySDK.applyCount += 1
    if ProxySDK.denyApply { return false }
    ProxySDK.active = ProxySDK.saved
    return true
}
