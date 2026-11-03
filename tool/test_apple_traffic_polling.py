#!/usr/bin/env python3
"""Exercise actual Apple host timer bodies without a VPN, Core or Apple SDK.

Only the asynchronous provider boundary is controlled. Held replies reproduce
overlapping polls, worker resets and stop/replacement races deterministically.
"""

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "IOS": ROOT / "ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift",
    "MACOS": ROOT / "packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift",
}


def main() -> None:
    fixture = (ROOT / "tool/fixtures/apple_traffic_polling.swift").read_text()
    with tempfile.TemporaryDirectory(prefix="flutter-vless-traffic-") as directory:
        output = Path(directory)
        for platform, source in SOURCES.items():
            text = source.read_text()
            start = text.index('    private func startTimer(reason:')
            end = text.index('    private func currentDurationSeconds()', start)
            # Keep the production control flow and parser unchanged. The test
            # wrapper merely makes its private entry points visible to probes.
            methods = text[start:end].replace('    private func ', '    func ')
            rate = text[text.index('private func trafficBytesPerSecond('):text.index('private final class ProxyOnlyRunner {')]
            generated = output / f"{platform.lower()}.swift"
            generated.write_text(fixture.replace("// PRODUCTION_TIMER_METHODS", methods)
                                 .replace("// PRODUCTION_RATE_HELPER", rate))
            binary = output / platform.lower()
            subprocess.run(["swiftc", "-parse-as-library", f"-D{platform}",
                            str(generated), "-o", str(binary)], check=True)
            environment = dict(os.environ, FLVLESS_TRAFFIC_RATE_VECTORS=str(
                ROOT / "tool/fixtures/compatibility/traffic-rate-vectors.json"))
            subprocess.run([str(binary)], check=True, env=environment)


if __name__ == "__main__":
    main()
