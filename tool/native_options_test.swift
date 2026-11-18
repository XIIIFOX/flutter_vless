import Foundation

@main struct NativeOptionsTest {
    static func reject(_ body: () throws -> Void) { do { try body(); fatalError("Expected rejection") } catch {} }
    static func main() throws {
        let defaults = try VlessNativeOptions()
        precondition(defaults.enableOnDemand && defaults.killSwitch == "required" && !defaults.quickAccessEnabled)
        precondition(!defaults.recordBalancerSelections)
        let full: [String: Any] = ["version":1,
            "notification":["iconResourceType":"drawable","iconResourceName":"vpn_icon","buttonLabel":"Stop","action":"openApp"],
            "quickAccess":["enabled":true,"surface":"controlCenter","label":"Private VPN","action":"toggle","requireUnlock":false,"androidIconResourceName":"vpn_tile","appleSymbol":"shield","windowsIconPath":"C:\\icons\\vpn.ico"],
            "reconnect":["enabled":true,"initialDelayMs":200,"maxDelayMs":800,"maxAttempts":3],
            "protection":["killSwitch":"platformDefault","onDemand":"disabled","alwaysOn":"system"],
            "diagnostics":["enabled":false,"maxBytes":4096,"maxLines":7]]
        let options = try VlessNativeOptions(full)
        precondition(NSDictionary(dictionary: options.dictionary).isEqual(to: full))
        precondition(options.notificationIconType == "drawable" && options.notificationIconName == "vpn_icon" && options.notificationButtonLabel == "Stop" && options.notificationAction == "openApp")
        precondition(options.quickAccessEnabled && options.quickAccessSurface == "controlCenter" && options.quickAccessLabel == "Private VPN" && options.quickAccessAction == "toggle" && !options.requireUnlock && options.androidIconName == "vpn_tile" && options.appleSymbol == "shield" && options.windowsIconPath == "C:\\icons\\vpn.ico")
        precondition(!options.diagnosticsEnabled && options.diagnosticsMaxBytes == 4096 && options.diagnosticsMaxLines == 7)
        let balanceOptions = try VlessNativeOptions(["diagnostics":["recordBalancerSelections":true]])
        precondition(balanceOptions.recordBalancerSelections)
        precondition((balanceOptions.dictionary["diagnostics"] as? [String:Any])?["recordBalancerSelections"] as? Bool == true)
        precondition(!options.enableOnDemand && options.reconnectEnabled && options.maxAttempts == 3)
        precondition((0...3).map { options.retryDelay(failures:$0) } == [0.2,0.4,0.8,0.8])
        precondition(options.retryDelay(failures: Int.max) == 0.8 && options.retryDelay(failures:-1) == 0.2)
        precondition(options.mayRetry(failures:2) && !options.mayRetry(failures:3))
        try options.validateApple(isMac:false,controlCenterAvailable:true,extensionConfigured:true)
        reject { try options.validateApple(isMac:false,controlCenterAvailable:false,extensionConfigured:true) }
        reject { try options.validateApple(isMac:false,controlCenterAvailable:true,extensionConfigured:false) }
        reject { try VlessNativeOptions(["protection":["alwaysOn":"requireEnabled"]]).validateApple(isMac:true,controlCenterAvailable:true,extensionConfigured:true) }
        try VlessNativeOptions(["quickAccess":["enabled":true,"surface":"menuBar"]]).validateApple(isMac:true,controlCenterAvailable:false,extensionConfigured:false)
        for (section,key,value) in [
            ("notification","iconResourceType","file" as Any),("notification","iconResourceName","../bad"),("notification","buttonLabel","bad\nlabel"),("notification","action","callback"),
            ("quickAccess","enabled",1),("quickAccess","surface","unknown"),("quickAccess","label"," "),("quickAccess","action","callback"),("quickAccess","requireUnlock",0),("quickAccess","androidIconResourceName","x.svg"),("quickAccess","appleSymbol","\0"),("quickAccess","windowsIconPath","relative.ico"),
            ("reconnect","enabled","true"),("reconnect","initialDelayMs",99),("reconnect","initialDelayMs",1.5),("reconnect","maxDelayMs",600001),("reconnect","maxAttempts",1001),
            ("protection","killSwitch","off"),("protection","onDemand","off"),("protection","alwaysOn","off"),
            ("diagnostics","enabled","false"),("diagnostics","maxBytes",4095),("diagnostics","maxLines",301),
            ("diagnostics","recordBalancerSelections",1)] {
            reject { _ = try VlessNativeOptions([section:[key:value]]) }
        }
        reject { _ = try VlessNativeOptions(["version":2]) }
        reject { _ = try VlessNativeOptions(["notification":"wrong"]) }
        reject { _ = try VlessNativeOptions(["reconnect":["enabled":false],"protection":["onDemand":"enabled"]]) }
        func choices(_ s: String, lines: Int = 300, bytes: Int = 4096) -> String {
            PrivateBalancerDiagnostics.snapshot(Data(s.utf8), maxBytes: bytes, maxLines: lines)
        }
        let sequence = "31,1,2\n32,1,1\n33,1,2"
        precondition(choices(sequence) == sequence)
        precondition(choices(sequence + "\n") == sequence)
        precondition(choices(sequence, lines: 2) == "32,1,1\n33,1,2")
        precondition(choices(sequence, bytes: 6) == "33,1,2")
        for invalid in ["", "1,1,1\n2,1,host.invalid", "1,1,1\n1,1,2", "1,0,1", "1,01,1",
                        "1,1,9223372036854775808", PrivateBalancerDiagnostics.snapshotCommand] {
            precondition(choices(invalid).isEmpty)
        }
        precondition(choices((1...301).map { "\($0),1,1" }.joined(separator: "\n")).isEmpty)
        print("PASS native Apple options: every field, platform gates, retry bounds and invalid inputs")
    }
}
