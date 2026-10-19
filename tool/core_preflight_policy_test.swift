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
            (5, "environment-policy", nil, nil),
            (5 | 2 << 8 | 8 << 16, "environment-policy", nil, nil),
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
                if stage == "environment-policy" {
                    precondition(error.localizedDescription == "Xray Env configuration cannot be checked safely in this process yet.")
                    precondition(error.details["feature"] as? String == "env")
                    precondition(error.details.count == 2)
                } else {
                    precondition(error.details["feature"] == nil)
                }
            }
        }
        // A cached runtime can expose CheckPrivate while still applying Env
        // process-wide. Canonical native documents must never reach that call.
        for key in ["env", "ENV", "EnV"] {
            for value: Any in ["candidate-private-value", NSNull()] {
                let source = try JSONSerialization.data(withJSONObject: [key: ["PRIVATE_ENV_CANARY": value]])
                let original = source
                var legacyCalls = 0
                do {
                    try CorePreflightPolicy.validate(source) { _ in legacyCalls += 1; return 0 }
                    preconditionFailure("Env reached the cached checker")
                } catch let error as CorePreflightError {
                    precondition(error.stage == "environment-policy")
                    precondition(error.details["feature"] as? String == "env")
                    precondition(!error.localizedDescription.contains("PRIVATE_ENV_CANARY"))
                    precondition(!error.localizedDescription.contains("candidate-private-value"))
                }
                precondition(legacyCalls == 0 && source == original)
            }
        }
        for document: [String: Any] in [[:], ["env": NSNull()], ["ENV": [String: Any]()]] {
            let source = try JSONSerialization.data(withJSONObject: document)
            var legacyCalls = 0
            let success = try CorePreflightPolicy.validate(source) { data in
                precondition(data == source); legacyCalls += 1; return 0
            }
            precondition(success && legacyCalls == 1)
        }
        print("PASS: Apple Core preflight result decoding, legacy capability and redacted errors")
    }
}
