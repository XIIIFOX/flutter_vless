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
    parser.add_argument("--provider-ref", help="Immutable provider source commit for the inert negative control.")
    parser.add_argument("--prepare-only", action="store_true", help="Generate sources without executing native tools.")
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    results = {}
    for platform, (provider, base, prefix) in PLATFORMS.items():
        support = ROOT / base / (prefix + "_tunnel_support")
        privacy = ROOT / base / (prefix + "_privacy")
        timer_path = privacy / "NativeDiagnostics.swift"
        timer_source = timer_path.read_bytes()
        diagnostics = timer_source.decode()
        timer_start = diagnostics.index("public struct NativeDiagnosticTimer:")
        timer = diagnostics[timer_start:diagnostics.index("\n}\n", timer_start) + 3]
        unchanged_source = (ROOT / provider).read_text()
        if args.provider_ref:
            assert len(args.provider_ref) == 40 and all(c in "0123456789abcdef" for c in args.provider_ref)
            text = subprocess.check_output(["git", "show", args.provider_ref + ":" + provider], cwd=ROOT, text=True)
        else:
            text = unchanged_source
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
            "    private func protectedNetworkSettings", "    private func installProtectedSettings", "    private func onRuntimeQueue",
            "    private func setStartupPreparation", "    private func setStartupDiscovery",
            "    private func cancelStartupDiscovery", "    private func makeStartupDiscovery",
            "    private func invalidateStartupDiscovery", "    private func endpointSpecIsFresh",
            "    private func setForwardingNotReadyForDNS", "    private func setForwardingReadyFromHealth",
            "    private func beginInitialDiscoveryCorrection", "    private func cancelInitialDiscoveryCorrection",
            "    private func setForwardingReady", "    private func startNativeRuntime", "    private func commitEndpointPlan"))
        extras += "\n" + actual_block("    private func scheduleNativeRecovery").replace("func scheduleNativeRecovery(", "func fixtureScheduleNativeRecovery(", 1)
        extras += "\n" + actual_block("    private func refreshEndpointPlan").replace("func refreshEndpointPlan(", "func fixtureRefreshEndpointPlan(", 1).replace("try await Task.sleep(nanoseconds: UInt64(min(wait, 300) * 1_000_000_000))", "await Task.yield(); try Task.checkCancellation()")
        extras += "\n" + actual_block("    private final class PendingSleep").replace("private final class", "final class")
        extras += "\n" + actual_block("    private func cancelPendingSleep")
        if "    private final class InitialDiscoveryCorrectionPermit" in text:
            extras += "\n" + actual_block("    private final class InitialDiscoveryCorrectionPermit").replace("private final class", "final class")
        stop_marker = "    " + ("open override" if platform == "macos" else "override") + " func stopTunnel("
        stop = actual_block(stop_marker).replace("open override func", "func", 1).replace("override func", "func", 1)
        helper_path = support / "TunnelOnDemandPolicy.swift"
        helper_source = helper_path.read_bytes()
        helper = helper_source.decode()
        helper = "\n".join(line for line in helper.splitlines() if not line.startswith("import NetworkExtension") and not line.startswith("import flutter_vless"))
        helper = helper.replace("public ", "")  # fake OS types are intentionally internal
        dns_path = support / "TunnelDNSPolicy.swift"
        dns_source = dns_path.read_bytes()
        dns_text = dns_source.decode()
        begin = dns_text.index("    public static func requiresPhysicalInterfaceBinding(")
        end = dns_text.index("\n    }\n", begin) + len("\n    }\n")
        dns_binding = dns_text[begin:end]
        generated = output / (platform + ".swift")
        field_source = (privacy / "LocalProxyAccessPolicy.swift").read_text()
        field_source = field_source[field_source.index("public enum XrayJSONField {"):]
        template = (ROOT / "tool/fixtures/apple_cold_start_policy.swift").read_text()
        for placeholder, field in [("// ACTUAL_DISCOVERY_STATE", "startupDiscovery"), ("// ACTUAL_CORRECTION_STATE", "initialDiscoveryCorrection")]:
            declaration = next(line for line in text.splitlines() if line.startswith("    private var " + field + ":"))
            template = template.replace(placeholder, declaration.strip().replace("private var", "var", 1))
        generated.write_text("import Foundation\n" + timer + "\n" + template.replace("// ACTUAL_POLICY", helper).replace("// ACTUAL_START", entry).replace("// ACTUAL_PREPARATION_HELPERS", extras).replace("// ACTUAL_STOP", stop).replace("// ACTUAL_DNS_BINDING_REQUIREMENT", dns_binding) + "\n" + field_source)
        if args.prepare_only:
            print(platform, "prepared inert source only", flush=True)
            continue
        inputs = [privacy / "VlessNativeOptions.swift", privacy / "CorePreflightPolicy.swift", privacy / "XdriveServicePolicy.swift", privacy / "GeoDatAssetPolicy.swift", support / "TunnelSessionAdmission.swift", plan_path, generated]
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
        assert (ROOT / provider).read_text() == unchanged_source and helper_path.read_bytes() == helper_source
        assert fixture_path.read_bytes() == fixture_source and plan_path.read_bytes() == plan_source
        assert dns_path.read_bytes() == dns_source
        assert timer_path.read_bytes() == timer_source
        results[platform] = {"exit": run.returncode, "diagnostic_timer_sha256": hashlib.sha256(timer_source).hexdigest(), "fixture_sha256": hashlib.sha256(fixture_source).hexdigest(), "endpoint_plan_sha256": hashlib.sha256(plan_source).hexdigest(), "provider_sha256": hashlib.sha256(text.encode()).hexdigest(), "provider_ref": args.provider_ref, "policy_sha256": hashlib.sha256(helper_path.read_bytes()).hexdigest(), "dns_policy_sha256": hashlib.sha256(dns_source).hexdigest(), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        print(platform, run.returncode, run.stdout, flush=True)
    (output / "result.json").write_text(json.dumps({"results": results, "fake_only": True, "real_Core_network_preferences_devices": False}, indent=2) + "\n")
    assert all(value["exit"] == 0 for value in results.values()), results


if __name__ == "__main__":
    main()
