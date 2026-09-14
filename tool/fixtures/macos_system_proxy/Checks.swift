func check(_ value: @autoclosure () -> Bool, _ name: String) {
    guard value() else { print("FAIL: \(name)"); exit(1) }
}
let original: [String: [String: Any]] = [
    "wifi": ["ProxyAutoConfigEnable": 1, "ProxyAutoConfigURLString": "https://pac.invalid/proxy.pac", "ExceptionsList": ["*.local"]],
    "ethernet": ["SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": 12000]
]
func equal(_ a: [String: [String: Any]], _ b: [String: [String: Any]]) -> Bool { NSDictionary(dictionary: a).isEqual(to: b) }
func reset() {
    SystemProxyHelper.clearSystemProxy()
    ProxySDK.saved = original; ProxySDK.active = original
}
let profile = #"{"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","tag":"socks-in"},{"listen":"127.0.0.1","port":10820,"protocol":"socks","tag":"socks-direct"}]}"#
do {
    reset()
    try SystemProxyHelper.setSystemProxy(config: profile)
    check(ProxySDK.authorizedSessions == 1, "ordinary user obtains an authorized preference session")
    check(ProxySDK.freeCount == 0, "authorization retained for restoration")
    for service in ProxySDK.saved.values {
        check(service["SOCKSPort"] as? Int == 10808, "primary inbound wins over direct inbound")
        check(service["SOCKSEnable"] as? Int == 1, "SOCKS enabled")
        check(service["ProxyAutoConfigEnable"] as? Int == 0, "old PAC disabled while connected")
    }
    SystemProxyHelper.clearSystemProxy()
    check(equal(ProxySDK.saved, original) && equal(ProxySDK.active, original), "exact restoration of both services")
    check(ProxySDK.authorizationCount == 1 && ProxySDK.freeCount == 1, "restoration reuses and releases authorization")
    print("PASS authorization, primary listener and restoration")

    reset(); ProxySDK.denyAuthorization = true
    do { try SystemProxyHelper.setSystemProxy(config: profile); check(false, "denied authorization must fail") }
    catch { check(NativeLogPrivacy.operationError(error).localizedDescription == "System proxy authorization failed", "safe actionable error") }
    ProxySDK.denyAuthorization = false
    check(equal(ProxySDK.saved, original) && equal(ProxySDK.active, original), "cancel leaves preferences untouched")
    ProxySDK.denyLock = true
    do { try SystemProxyHelper.setSystemProxy(config: profile); check(false, "denied preferences lock must fail") }
    catch { check(NativeLogPrivacy.operationError(error).localizedDescription == "System proxy authorization or preferences lock failed", "lock error stage survives privacy filtering") }
    ProxySDK.denyLock = false
    check(equal(ProxySDK.saved, original) && equal(ProxySDK.active, original), "cancelled system dialog leaves preferences untouched")
    print("PASS authorization cancellation")

    for failCommit in [false, true] {
        reset()
        ProxySDK.stageFailureService = failCommit ? nil : "wifi"
        ProxySDK.denyCommit = failCommit
        do { try SystemProxyHelper.setSystemProxy(config: profile); check(false, "failed transaction must throw") } catch {}
        ProxySDK.stageFailureService = nil; ProxySDK.denyCommit = false
        check(equal(ProxySDK.saved, original), "failed staging/commit changes nothing")
        let changed = ["wifi": ["HTTPEnable": 1, "HTTPPort": 12345]]
        ProxySDK.saved = changed; ProxySDK.active = changed
        try SystemProxyHelper.setSystemProxy(config: profile)
        SystemProxyHelper.clearSystemProxy()
        check(equal(ProxySDK.saved, changed), "failed transaction leaves no stale snapshot")
    }
    print("PASS staging and commit failures")

    reset(); ProxySDK.denyApply = true
    do { try SystemProxyHelper.setSystemProxy(config: profile); check(false, "failed apply must throw") } catch {}
    ProxySDK.denyApply = false
    SystemProxyHelper.clearSystemProxy()
    check(equal(ProxySDK.active, original) && equal(ProxySDK.saved, original), "failed apply rolls back")
    reset(); try SystemProxyHelper.setSystemProxy(config: profile)
    ProxySDK.denyApply = true
    SystemProxyHelper.clearSystemProxy()
    check(!equal(ProxySDK.active, original), "failed cleanup apply needs retry")
    ProxySDK.denyApply = false
    SystemProxyHelper.clearSystemProxy()
    check(equal(ProxySDK.active, original), "cleanup retries committed restoration")
    print("PASS apply failure and cleanup retry")

    reset(); try SystemProxyHelper.setSystemProxy(config: profile)
    let takeover = ["SOCKSEnable": 1, "SOCKSPort": 54321]
    ProxySDK.saved["wifi"] = takeover; ProxySDK.active = ProxySDK.saved
    SystemProxyHelper.clearSystemProxy()
    check(NSDictionary(dictionary: ProxySDK.saved["wifi"]!).isEqual(to: takeover), "another app's changes survive cleanup")
    check(NSDictionary(dictionary: ProxySDK.saved["ethernet"]!).isEqual(to: original["ethernet"]!), "owned service restored")
    print("PASS external proxy ownership")

    reset()
    try SystemProxyHelper.setSystemProxy(config: #"{"inbounds":[{"listen":"::1","port":10810,"protocol":"http"}]}"#)
    check(ProxySDK.saved["wifi"]?["HTTPEnable"] as? Int == 1 && ProxySDK.saved["wifi"]?["HTTPSEnable"] as? Int == 1, "HTTP and HTTPS enabled")
    check(ProxySDK.saved["wifi"]?["HTTPProxy"] as? String == "::1", "IPv6 loopback host preserved")
    SystemProxyHelper.clearSystemProxy()
    print("PASS HTTP and IPv6 loopback configuration")
} catch { print("FAIL: unexpected startup error code=\((error as NSError).code)"); exit(1) }
