#!/usr/bin/env python3
"""Compile extracted Apple admission code against inert preferences/Core fakes only."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/apple-start-owner-current"
PLATFORMS = {
    "ios": ROOT / "ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift",
    "macos": ROOT / "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift",
}


def fixture(source: str) -> str:
    start = source.index("        let preparationChanges = Array(changes)", source.index("    private func startVless("))
    end = source.index("\n    }\n", start) + len("\n    }")
    transaction = source[start:end]
    assert transaction.rstrip().endswith("}")
    transaction = transaction.rstrip()[:-1]  # wrapper below owns the function brace
    start = source.index("    private func initializeVless(")
    end = source.index("        self.packetTunnelManager?.nativeOptions = parsed", start)
    end = source.index("\n", end)
    initialization = source[start:end].replace("    private func", "    func", 1) + "\n        result(nil)\n    }"
    template = (ROOT / "tool/fixtures/apple_start_owner.swift").read_text()
    return template.replace("// ACTUAL_START_TRANSACTION", transaction).replace("// ACTUAL_INITIALIZE_ADMISSION", initialization)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    results = {}
    for platform, source_path in PLATFORMS.items():
        support = source_path.parent.parent / ("flutter_vless_privacy" if platform == "ios" else "flutter_vless_macos_privacy")
        generated = OUT / (platform + ".swift")
        generated.write_text(fixture(source_path.read_text()))
        inputs = [source_path.parent / "NativeOperationQueue.swift", support / "VlessNativeOptions.swift", support / "CorePreflightPolicy.swift", generated]
        binary = OUT / platform
        with (OUT / (platform + "-compile.log")).open("wb") as log:
            compilation = subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", *map(str, inputs), "-o", str(binary)], stdout=log, stderr=subprocess.STDOUT, timeout=100)
        assert compilation.returncode == 0, (OUT / (platform + "-compile.log")).read_text()[-5000:]
        execution = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        (OUT / (platform + ".log")).write_text(execution.stdout + execution.stderr)
        print(platform, execution.returncode, execution.stdout, flush=True)
        results[platform] = {"exit": execution.returncode, "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(), "log_sha256": hashlib.sha256((OUT / (platform + ".log")).read_bytes()).hexdigest()}
    (OUT / "result.json").write_text(json.dumps({"results": results, "runtime": "extracted functions; fake Core, preferences, controls and proxy only", "native_Core_network_device_actions": False}, indent=2) + "\n")
    assert all(item["exit"] == 0 for item in results.values()), results


if __name__ == "__main__":
    main()
