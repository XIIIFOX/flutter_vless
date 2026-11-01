#!/usr/bin/env python3
"""SDK-free tests for the development-only, read-only owned-profile observer.

The Swift probe executes the actual record projection and completion lease with
synthetic records. It does not load NetworkExtension preferences or run Xray.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'example/ios/Runner/AcceptanceWebDiagnostics.swift').read_text()


def body(marker):
    start = SOURCE.index(marker)
    opening = SOURCE.index('{', start)
    depth = 1
    for i in range(opening + 1, len(SOURCE)):
        depth += (SOURCE[i] == '{') - (SOURCE[i] == '}')
        if depth == 0:
            return SOURCE[opening + 1:i]
    raise AssertionError('Unterminated source block')


class OwnedManagerSafetyTests(unittest.TestCase):
    def test_zero_argument_fixed_provider_and_existing_optin_admission(self):
        self.assertIn('case "ownedManagerSafety" where call.arguments == nil', SOURCE)
        self.assertLess(SOURCE.index('#if FLUTTER_VLESS_ACCEPTANCE_TESTING'),
                        SOURCE.index('import NetworkExtension'))
        handler = SOURCE[SOURCE.index('channel.setMethodCallHandler'):SOURCE.index('private var admitted')]
        self.assertLess(handler.index('guard let self, self.admitted'), handler.index('case "ownedManagerSafety"'))
        action = body('private func ownedManagerSafety(result:')
        self.assertIn('guard admitted else', action)
        self.assertEqual(action.count('NETunnelProviderManager.loadAllFromPreferences'), 2)
        self.assertIn('"dev.tfox.flutterXrayExample.XrayTunnel"', action)
        self.assertNotRegex(action, r'saveToPreferences|startVPNTunnel|stopVPNTunnel|sendProviderMessage|SecItem|XRay\w*\(')
        self.assertNotIn('call.arguments', action)

    def test_callback_deadline_and_late_owner_fence(self):
        action = body('private func ownedManagerSafety(result:')
        self.assertIn('deadline: .now() + 2', action)
        self.assertIn('deadline: ProcessInfo.processInfo.systemUptime + 2', action)
        self.assertIn('clock: { ProcessInfo.processInfo.systemUptime }', action)
        self.assertIn('lease.finish(admitted:', action)
        self.assertIn('self?.managerSafetyToken == token', action)
        self.assertIn('self?.admitted == true', action)
        self.assertIn('guard !lease.completed else { return }', action)
        self.assertIn('DispatchQueue.main.async', action)
        self.assertIn('timeout?.cancel()', action)
        self.assertIn('timeout = nil', action)
        self.assertIn('SHA256.hash(data:', action)
        self.assertNotRegex(action, r'base64EncodedString|reference\.description|String\(decoding:.*reference')

    def test_actual_projection_and_one_shot_lease(self):
        start = SOURCE.index('// BEGIN OWNED_MANAGER_SAFETY_PURE')
        end = SOURCE.index('// END OWNED_MANAGER_SAFETY_PURE', start)
        actual = SOURCE[start:end]
        probe = 'import Foundation\n' + actual + r'''
private func record(_ ref:Data? = Data([1,2,3]), enabled:Bool = false,
            onDemand:Bool = false, includeAll:Bool = true,
            status:Int = 1) -> AcceptanceOwnedManagerSafetyRecord {
  AcceptanceOwnedManagerSafetyRecord(reference:ref, enabled:enabled,
      onDemand:onDemand, includeAllNetworks:includeAll, status:status)
}
private func project(_ before:[AcceptanceOwnedManagerSafetyRecord],
             _ after:[AcceptanceOwnedManagerSafetyRecord]) -> [String:Any] {
  acceptanceOwnedManagerSafetyProjection(before:before, after:after,
      fingerprint:{ _ in String(repeating:"a",count:64) })
}
let good=project([record()],[record()])
precondition(good["owned_manager_count"] as? Int == 1)
precondition(good["reference_present"] as? Bool == true)
precondition(good["reference_consistent"] as? Bool == true)
precondition(good["safe_off_snapshot"] as? Bool == true)
precondition(good["reference_sha256"] as? String == String(repeating:"a",count:64))
precondition(good["manager_enabled"] as? Bool == false)
precondition(Set(good.keys) == Set(["schema","owned_manager_count","owned_manager_count_before",
  "ambiguous","reference_present","reference_consistent","safe_off_snapshot","manager_enabled",
  "on_demand_enabled","include_all_networks","connection_status","reference_sha256"]))
precondition(good.values.allSatisfy { !($0 is Data) })
precondition(JSONSerialization.isValidJSONObject(good))
for (before,after) in [([],[]),([record()],[record(),record()]),([record(),record()],[record()])] {
  let value=project(before,after)
  precondition(value["ambiguous"] as? Bool == true)
  precondition(value["reference_consistent"] as? Bool == false)
  precondition(value["safe_off_snapshot"] as? Bool == false)
  precondition(value["reference_sha256"] == nil)
}
for ref:Data? in [nil,Data(),Data(repeating:7,count:4097)] {
  let value=project([record(ref)],[record(ref)])
  precondition(value["reference_present"] as? Bool == false)
  precondition(value["reference_consistent"] as? Bool == false)
  precondition(value["safe_off_snapshot"] as? Bool == false)
  precondition(value["reference_sha256"] == nil)
}
let replaced=project([record(Data([4]))],[record(Data([5]))])
precondition(replaced["reference_consistent"] as? Bool == false)
for unsafe in [record(enabled:true),record(onDemand:true),record(includeAll:false),record(status:3)] {
 precondition(project([unsafe],[unsafe])["safe_off_snapshot"] as? Bool == false)
}
private let invalid=record(status:0)
precondition(project([invalid],[invalid])["safe_off_snapshot"] as? Bool == true)
for (admitted,owner) in [(true,true),(false,true),(true,false),(false,false)] {
 let lease=AcceptanceOwnedManagerSafetyLease(deadline:2,clock:{0})
 precondition(lease.finish(admitted:admitted,ownerMatches:owner) ==
     (admitted && owner ? .deliver : .unavailable))
 precondition(lease.completed)
 precondition(lease.finish(admitted:true,ownerMatches:true) == .ignore)
}
private let timeout=AcceptanceOwnedManagerSafetyLease(deadline:2,clock:{0})
precondition(timeout.finish(admitted:true,ownerMatches:true) == .deliver)
precondition(timeout.finish(admitted:true,ownerMatches:true) == .ignore)
for elapsed in [1.999,2.0,2.001,99.0] {
 var now=0.0
 let lease=AcceptanceOwnedManagerSafetyLease(deadline:2,clock:{now})
 now=elapsed // Timer has not executed: callback alone must enforce the bound.
 precondition(lease.finish(admitted:true,ownerMatches:true) ==
     (elapsed < 2 ? .deliver : .unavailable))
 precondition(lease.finish(admitted:true,ownerMatches:true) == .ignore)
}
print("OWNED_MANAGER_PURE_PROJECTION_AND_LATE_FENCE_PASS")
'''
        with tempfile.TemporaryDirectory(prefix='flvless-manager-observer-') as temporary:
            folder = Path(temporary)
            source = folder / 'main.swift'
            binary = folder / 'probe'
            source.write_text(probe)
            build = subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path',
                                    str(folder / 'modules'), str(source), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=45)
            self.assertEqual(build.returncode, 0, build.stderr[-4000:])
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr[-4000:])
            self.assertEqual(run.stdout.strip(), 'OWNED_MANAGER_PURE_PROJECTION_AND_LATE_FENCE_PASS')


if __name__ == '__main__':
    unittest.main()
