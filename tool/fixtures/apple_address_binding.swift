import Foundation
import Darwin
#if canImport(flutter_vless_privacy)
import flutter_vless_privacy
#else
import flutter_vless_macos_privacy
#endif

// Calls the binding expression extracted verbatim from the real Runner plugin,
// linked only with its production privacy module. This imports no support,
// Core or HEV module and calls no NetworkExtension, socket or OS settings API.
@main
struct AppAddressBindingProbe {
    static func replace(_ object: Any, path: ArraySlice<String>, value: String) -> Any {
        guard let head = path.first else { return value }
        if var map = object as? [String: Any], let child = map[head] {
            map[head] = replace(child, path: path.dropFirst(), value: value)
            return map
        }
        var list = object as! [Any]
        let index = Int(head)!
        list[index] = replace(list[index], path: path.dropFirst(), value: value)
        return list
    }

    static func main() throws {
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--capture-only" {
            let snapshot = XrayEnvironmentSnapshot.capture()
            precondition(snapshot.value(for: "\u{e9}.port") == "10810")
            precondition(snapshot.value(for: "e\u{301}.port") == "10808")
            let empty = try LocalProxyAccessPolicy.bindingAddressEnvironment("env:e\u{301}.empty", environmentSnapshot: snapshot)
            let alias = try LocalProxyAccessPolicy.bindingAddressEnvironment("env:e\u{301}.endpoint", environmentSnapshot: snapshot)
            precondition(empty == "" && alias == "127.0.0.7")
            precondition(snapshot.description == "XrayEnvironmentSnapshot(<private>)")
            print("ADDRESS_ENVIRONMENT_RAW_CAPTURE_PASS=1")
            return
        }
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        var passed = 0
        for (fixture, count) in [("endpoint-addresses", 3), ("dns-addresses", 3), ("logical-addresses", 4)] {
            let data = try Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/\(fixture).json"))
            let cases = try JSONSerialization.jsonObject(with: data) as! [[String: Any]]
            precondition(cases.count == count)
            for item in cases {
                let environment = item["environment"] as! [String: String]
                let snapshot = XrayEnvironmentSnapshot(environment: environment)
                let original = item["config"] as! [String: Any]
                let source = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
                var expected: Any = original
                if let bindings = item["bindings"] as? [[String: Any]] {
                    for binding in bindings {
                        expected = replace(expected, path: ArraySlice(binding["path"] as! [String]), value: binding["value"] as! String)
                    }
                } else {
                    for (path, value) in item["resolvedAddresses"] as! [String: String] {
                        expected = replace(expected, path: ArraySlice(path.split(separator: ".").map(String.init)), value: value)
                    }
                }
                let frozen = try actualAppBinding(source, environment: snapshot)
                let frozenObject = try JSONSerialization.jsonObject(with: frozen) as! NSDictionary
                precondition(frozenObject == (expected as! NSDictionary))
                let repeated = try actualAppBinding(frozen, environment: XrayEnvironmentSnapshot(rawEntries: []))
                let retained = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
                precondition(repeated == frozen)
                precondition(retained == source)
                passed += 1
            }
        }
        let nested = Data(#"{"outbounds":[{"protocol":"dns","settings":{"address":"env:FLUTTER_VLESS_ADDRESS_BOUNDARY_NESTED"}}]}"#.utf8)
        let nestedEnvironment = XrayEnvironmentSnapshot(environment: ["FLUTTER_VLESS_ADDRESS_BOUNDARY_NESTED": "env:SECOND"])
        do {
            _ = try actualAppBinding(nested, environment: nestedEnvironment)
            preconditionFailure("Nested effective Address references must be rejected")
        } catch {}
        print("ADDRESS_BINDING_MODULE_PASS=\(CommandLine.arguments[2]);CASES=\(passed);REJECTED=1")
    }
}
