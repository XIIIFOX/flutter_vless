#!/usr/bin/env python3
"""Actual provider startup/policy code with in-memory NetworkExtension and Core."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {
    "ios": ("example/ios/XrayTunnel/PacketTunnelProvider.swift", "ios/flutter_vless/Sources", "flutter_vless"),
    "macos": ("packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/FlutterVlessPacketTunnelProvider.swift", "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources", "flutter_vless_macos"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/apple-cold-start-current")
    parser.add_argument("--receipts", action="store_true")
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    results = {}
    for platform, (provider, base, prefix) in PLATFORMS.items():
        support = ROOT / base / (prefix + "_tunnel_support")
        privacy = ROOT / base / (prefix + "_privacy")
        text = (ROOT / provider).read_text()
        fixture_path = ROOT / "tool/fixtures/apple_cold_start_policy.swift"
        fixture_source = fixture_path.read_bytes()
        plan_path = support / "TunnelEndpointPlanAdmission.swift"
        plan_source = plan_path.read_bytes()
        marker = "    " + ("open override" if platform == "macos" else "override") + " func startTunnel("
        start = text.index(marker)
        end = text.index("\n    }\n", start) + len("\n    }\n")
        entry = text[start:end].replace("open override func", "func", 1).replace("override func", "func", 1)
        def actual_block(marker):
            begin = text.index(marker)
            finish = text.index("\n    }\n", begin) + len("\n    }\n")
            return text[begin:finish].replace("private struct", "struct").replace("private func", "func")
        extras = "\n".join(actual_block(marker) for marker in (
            "    private struct RuntimeSource", "    private struct RuntimeSpec", "    private struct ProtectedSettingsKey",
            "    private func prepareInitialRuntimeSpec", "    private func physicalPathChanged", "    private func prepareEndpointConfig", "    private func checkEndpointPreflight",
            "    private func protectedNetworkSettings", "    private func installProtectedSettings", "    private func onRuntimeQueue"))
        stop_marker = "    " + ("open override" if platform == "macos" else "override") + " func stopTunnel("
        stop = actual_block(stop_marker).replace("open override func", "func", 1).replace("override func", "func", 1)
        helper_path = support / "TunnelOnDemandPolicy.swift"
        helper_source = helper_path.read_bytes()
        helper = helper_source.decode()
        helper = "\n".join(line for line in helper.splitlines() if not line.startswith("import NetworkExtension") and not line.startswith("import flutter_vless"))
        helper = helper.replace("public ", "")  # fake OS types are intentionally internal
        generated = output / (platform + ".swift")
        field_source = (privacy / "LocalProxyAccessPolicy.swift").read_text()
        field_source = field_source[field_source.index("public enum XrayJSONField {"):]
        generated.write_text((ROOT / "tool/fixtures/apple_cold_start_policy.swift").read_text().replace("// ACTUAL_POLICY", helper).replace("// ACTUAL_START", entry).replace("// ACTUAL_PREPARATION_HELPERS", extras).replace("// ACTUAL_STOP", stop) + "\n" + field_source)
        inputs = [privacy / "VlessNativeOptions.swift", privacy / "CorePreflightPolicy.swift", privacy / "XdriveServicePolicy.swift", privacy / "GeoDatAssetPolicy.swift", support / "TunnelSessionAdmission.swift", support / "TunnelEndpointPlanAdmission.swift", generated]
        binary = output / platform
        command = ["xcrun", "swiftc", "-O", "-parse-as-library"]
        if args.receipts:
            command.append("-DARM_RECEIPT_TESTS")
        with (output / (platform + "-compile.log")).open("wb") as log:
            compile_result = subprocess.run([*command, *map(str, inputs), "-o", str(binary)], stdout=log, stderr=subprocess.STDOUT, timeout=100)
        assert compile_result.returncode == 0, (output / (platform + "-compile.log")).read_text()[-5000:]
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=25)
        log = output / (platform + ".log")
        log.write_text(run.stdout + run.stderr)
        assert (ROOT / provider).read_text() == text and helper_path.read_bytes() == helper_source
        assert fixture_path.read_bytes() == fixture_source and plan_path.read_bytes() == plan_source
        results[platform] = {"exit": run.returncode, "fixture_sha256": hashlib.sha256(fixture_source).hexdigest(), "endpoint_plan_sha256": hashlib.sha256(plan_source).hexdigest(), "provider_sha256": hashlib.sha256((ROOT / provider).read_bytes()).hexdigest(), "policy_sha256": hashlib.sha256(helper_path.read_bytes()).hexdigest(), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        print(platform, run.returncode, run.stdout, flush=True)
    (output / "result.json").write_text(json.dumps({"results": results, "fake_only": True, "real_Core_network_preferences_devices": False}, indent=2) + "\n")
    assert all(value["exit"] == 0 for value in results.values()), results


if __name__ == "__main__":
    main()
