#!/usr/bin/env python3
"""Exercise actual host timing admission with inert preferences/provider replies.

No Core, Keychain, NetworkExtension, system preferences, or network is used.
The compile/run mode is reserved for Actions; --prepare-only is safe elsewhere.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources"
HOST = BASE / "flutter_vless_macos/FlutterVlessPlugin.swift"
DIAGNOSTICS = BASE / "flutter_vless_macos_privacy/NativeDiagnostics.swift"
QUEUE = BASE / "flutter_vless_macos/NativeOperationQueue.swift"
FIXTURE = ROOT / "tool/fixtures/macos_startup_timing.swift"


def method(source, marker):
    start = source.index(marker)
    end = source.index("\n    }\n", start) + len("\n    }\n")
    return source[start:end].replace("private func", "func", 1)


def prepare(output):
    source = HOST.read_text()
    diagnostics = DIAGNOSTICS.read_text()
    # Preserve the actual typed interpolation/privacy and monotonic clock code.
    start = diagnostics.index("public struct NativeDiagnosticMessage:")
    end = diagnostics.index("public struct NativePrivacyLogger", start)
    template = FIXTURE.read_text()
    generated = "import Foundation\nimport os\n" + diagnostics[start:end] + template.replace(
        "// ACTUAL_PERMISSION", method(source, "    private func requestPermission(result:")
    ).replace(
        "// ACTUAL_READINESS", method(source, "    @MainActor\n    func refreshForwardingState(")
    )
    output.mkdir(parents=True, exist_ok=True)
    path = output / "probe.swift"
    path.write_text(generated)
    return path, {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (HOST, DIAGNOSTICS, QUEUE, FIXTURE)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/macos-startup-timing-current")
    args = parser.parse_args()
    generated, inputs = prepare(args.output_dir)
    proof = {"source_sha256": inputs, "fixture_only": True,
             "Core_Keychain_NetworkExtension_network_or_devices": False}
    if args.prepare_only:
        proof["prepared_only"] = True
    else:
        if os.environ.get("GITHUB_ACTIONS") != "true":
            parser.error("compile/run is restricted to Actions; use --prepare-only locally")
        with (args.output_dir / "compile.log").open("wb") as log:
            result = subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", str(QUEUE),
                                     str(generated), "-o", str(args.output_dir / "probe")],
                                    stdout=log, stderr=subprocess.STDOUT, timeout=100)
        assert result.returncode == 0, (args.output_dir / "compile.log").read_text()[-5000:]
        run = subprocess.run([str(args.output_dir / "probe")], capture_output=True, text=True, timeout=20)
        (args.output_dir / "runtime.log").write_text(run.stdout + run.stderr)
        proof.update(exit=run.returncode, log_sha256=hashlib.sha256((run.stdout + run.stderr).encode()).hexdigest())
        print(run.stdout, flush=True)
        assert run.returncode == 0, run.stdout + run.stderr
    (args.output_dir / "result.json").write_text(json.dumps(proof, indent=2) + "\n")
    assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == digest for p, digest in inputs.items())
    print(json.dumps({"prepared_only": args.prepare_only, "inert_timing_fixture": True}), flush=True)


if __name__ == "__main__":
    main()
