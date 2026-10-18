import Foundation

@main struct CorePreflightPolicyTest {
    static func main() throws {
        let input = Data("private-configuration-canary".utf8)
        var calls = 0
        let checked = try CorePreflightPolicy.validate(input) { data in
            calls += 1; precondition(data == input); return 0
        }
        precondition(checked && calls == 1)
        let legacy = try CorePreflightPolicy.validate(input) { _ in -1 }
        precondition(!legacy)
        let cases: [(Int64, String, String?, Int?)] = [
            (1, "privacy", nil, nil),
            (2, "decode", nil, nil), (3, "build", nil, nil),
            (3 | 1 << 8 | 1 << 16, "build", "inbounds", 0),
            (3 | 2 << 8 | 8 << 16, "build", "outbounds", 7),
            (4, "internal", nil, nil), (-2, "internal", nil, nil),
            (3 | 7 << 8 | 1 << 16, "build", nil, nil),
            (3 | 2 << 8, "build", nil, nil),
            (Int64.max, "internal", nil, nil)
        ]
        for (code, stage, section, index) in cases {
            do {
                try CorePreflightPolicy.validate(input) { _ in code }
                preconditionFailure("Invalid candidate accepted")
            } catch let error as CorePreflightError {
                precondition(error.stage == stage && error.section == section && error.index == index)
                precondition(!error.localizedDescription.contains("canary"))
                precondition(error.details["stage"] as? String == stage)
            }
        }
        print("PASS: Apple Core preflight result decoding, legacy capability and redacted errors")
    }
}
