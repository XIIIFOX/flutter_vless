import Foundation
import Darwin

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
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        var passed = 0
        for (fixture, count) in [("endpoint-addresses", 3), ("dns-addresses", 3), ("logical-addresses", 4)] {
            let data = try Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/\(fixture).json"))
            let cases = try JSONSerialization.jsonObject(with: data) as! [[String: Any]]
            precondition(cases.count == count)
            for item in cases {
                let environment = item["environment"] as! [String: String]
                let previous = environment.keys.map { ($0, getenv($0).map { String(cString: $0) }) }
                for (key, value) in environment { setenv(key, value, 1) }
                defer { for (key, value) in previous { if let value { setenv(key, value, 1) } else { unsetenv(key) } } }
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
                let frozen = try actualAppBinding(source)
                let frozenObject = try JSONSerialization.jsonObject(with: frozen) as! NSDictionary
                precondition(frozenObject == (expected as! NSDictionary))
                for key in environment.keys { setenv(key, "different.invalid", 1) }
                let repeated = try actualAppBinding(frozen)
                let retained = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
                precondition(repeated == frozen)
                precondition(retained == source)
                passed += 1
            }
        }
        let nested = Data(#"{"outbounds":[{"protocol":"dns","settings":{"address":"env:FLUTTER_VLESS_ADDRESS_BOUNDARY_NESTED"}}]}"#.utf8)
        setenv("FLUTTER_VLESS_ADDRESS_BOUNDARY_NESTED", "env:SECOND", 1)
        defer { unsetenv("FLUTTER_VLESS_ADDRESS_BOUNDARY_NESTED") }
        do {
            _ = try actualAppBinding(nested)
            preconditionFailure("Nested effective Address references must be rejected")
        } catch {}
        print("ADDRESS_BINDING_MODULE_PASS=\(CommandLine.arguments[2]);CASES=\(passed);REJECTED=1")
    }
}
