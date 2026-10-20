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
        marker = "    " + ("open override" if platform == "macos" else "override") + " func startTunnel("
        start = text.index(marker)
        end = text.index("\n    }\n", start) + len("\n    }\n")
        entry = text[start:end].replace("open override func", "func", 1).replace("override func", "func", 1)
        helper_path = support / "TunnelOnDemandPolicy.swift"
        helper = helper_path.read_text()
        helper = "\n".join(line for line in helper.splitlines() if not line.startswith("import NetworkExtension") and not line.startswith("import flutter_vless"))
        helper = helper.replace("public ", "")  # fake OS types are intentionally internal
        generated = output / (platform + ".swift")
        generated.write_text((ROOT / "tool/fixtures/apple_cold_start_policy.swift").read_text().replace("// ACTUAL_POLICY", helper).replace("// ACTUAL_START", entry))
        inputs = [privacy / "VlessNativeOptions.swift", privacy / "CorePreflightPolicy.swift", support / "TunnelSessionAdmission.swift", generated]
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
        results[platform] = {"exit": run.returncode, "provider_sha256": hashlib.sha256((ROOT / provider).read_bytes()).hexdigest(), "policy_sha256": hashlib.sha256(helper_path.read_bytes()).hexdigest(), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        print(platform, run.returncode, run.stdout, flush=True)
    (output / "result.json").write_text(json.dumps({"results": results, "fake_only": True, "real_Core_network_preferences_devices": False}, indent=2) + "\n")
    assert all(value["exit"] == 0 for value in results.values()), results


if __name__ == "__main__":
    main()
