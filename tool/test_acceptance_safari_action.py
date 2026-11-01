#!/usr/bin/env python3
"""SDK-free QA Safari allowlist and lifecycle-boundary checks."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--source',type=Path,default=ROOT/'example/ios/Runner/AcceptanceWebDiagnostics.swift')
args,remaining=parser.parse_known_args()
SOURCE=args.source.read_text()

def body(marker):
 start=SOURCE.index(marker);opening=SOURCE.index('{',start);depth=1
 for i in range(opening+1,len(SOURCE)):
  depth+=(SOURCE[i]=='{')-(SOURCE[i]=='}')
  if depth==0:return SOURCE[opening+1:i]
 raise AssertionError('Unterminated source body')

class SafariActionTests(unittest.TestCase):
 def test_fixed_action_is_admitted_and_has_no_arbitrary_url_argument(self):
  self.assertLess(SOURCE.index('#if FLUTTER_VLESS_ACCEPTANCE_TESTING'),SOURCE.index('case "openSafari":'))
  handler=SOURCE[SOURCE.index('case "openSafari":'):SOURCE.index('case "stop"')]
  self.assertIn('call.arguments as? String',handler)
  self.assertIn('self.openSafari(target: target, result: result)',handler)
  action=body('private func openSafari(target: String, result:')
  self.assertIn('guard admitted, let url = safariURL(target), let current,',action)
  self.assertIn('current.view().window != nil',action)
  self.assertNotIn('URL(string:',action)
  self.assertNotRegex(action,r'URLSession|URLRequest|evaluateJavaScript|openURL|canOpenURL')
 def test_ack_precedes_backgrounding_and_deferred_action_rechecks_admission(self):
  action=body('private func openSafari(target: String, result:')
  self.assertLess(action.index('result(true)'),action.index('DispatchQueue.main.asyncAfter'))
  self.assertIn('deadline: .now() + 0.25',action)
  deferred=action[action.index('DispatchQueue.main.asyncAfter'):]
  self.assertIn('[weak self, weak current]',deferred)
  self.assertIn('guard let self, self.admitted, let current,',deferred)
  self.assertLess(deferred.index('current.view().window != nil'),deferred.index('UIApplication.shared.open'))
  self.assertEqual(action.count('UIApplication.shared.open'),1)
  self.assertIn('completionHandler: nil',action)
 def test_actual_swift_url_factory_rejects_non_enum_input(self):
  actual=body('private func safariURL(_ target: String) -> URL?')
  source='import Foundation\nfunc safariURL(_ target:String)->URL? {'+actual+'}\n'
  navigation=body('func navigate(target: String)')
  path=re.search(r'    let path = [^\n]+',navigation).group(0)
  url=re.search(r'    let url = URL\(string: [^\n]+',navigation).group(0)
  source+='func embeddedURL(_ target:String)->URL {\nlet navigationID="fixture-local-only"\n'+path+'\n'+url+'\nreturn url\n}\n'
  source+="""let expected=["2ip":("2ip.ru","/","https://2ip.ru/"),"tfox":("tfox.dev","/ip/","https://tfox.dev/ip/")]
for (target,pair) in expected {
 let first=safariURL(target)!, second=safariURL(target)!
 let parts=URLComponents(url:first,resolvingAgainstBaseURL:false)!
 precondition(parts.scheme=="https" && parts.host==pair.0 && parts.path==pair.1)
 precondition(parts.user==nil && parts.password==nil && parts.port==nil && parts.fragment==nil)
 precondition(parts.query==nil && first.absoluteString==pair.2 && first==second)
 precondition(embeddedURL(target).absoluteString==pair.2)
}
for invalid in ["","2IP","https://2ip.ru/","file:///private/","javascript:alert(1)","2ip?url=other","tfox/../","other"] {
 precondition(safariURL(invalid)==nil)
}
print("PASS: both navigators use exact plain HTTPS targets; eight arbitrary inputs rejected")
"""
  with tempfile.TemporaryDirectory(prefix='flvless-safari-allowlist-') as temporary:
   folder=Path(temporary);p=folder/'main.swift';p.write_text(source);binary=folder/'probe'
   compiler=shutil.which('swiftc');self.assertIsNotNone(compiler)
   r=subprocess.run([compiler,'-swift-version','5','-module-cache-path',str(folder/'modules'),str(p),'-o',str(binary)],capture_output=True,text=True,timeout=45)
   self.assertEqual(r.returncode,0,r.stderr[-4000:])
   r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=5)
   self.assertEqual(r.returncode,0,r.stderr[-4000:])
   self.assertIn('eight arbitrary inputs rejected',r.stdout)
 def test_web_view_keeps_local_navigation_identity_and_reload_policy(self):
  navigation=body('func navigate(target: String)')
  self.assertIn('navigationID = UUID().uuidString',navigation)
  self.assertIn('cachePolicy: .reloadIgnoringLocalCacheData',navigation)
  self.assertNotIn('?test=',SOURCE)
  handler=SOURCE[SOURCE.index('case "navigate":'):SOURCE.index('case "openSafari":')]
  self.assertIn('["2ip", "tfox", "ipify"].contains(target)',handler)

 def test_plain_ipv4_fallback_is_fixed_embedded_only_and_has_no_query(self):
  navigation=body('func navigate(target: String)')
  path=re.search(r'    let path = [^\n]+',navigation).group(0)
  url=re.search(r'    let url = URL\(string: [^\n]+',navigation).group(0)
  source='import Foundation\nfunc embeddedURL(_ target:String)->URL {\n'+path+'\n'+url+'\nreturn url\n}\n'
  source+='func safariURL(_ target:String)->URL? {'+body('private func safariURL(_ target: String) -> URL?')+'}\n'
  source+='func allowed(_ url:URL?)->Bool {'+body('private func allowed(_ url: URL?) -> Bool')+'}\n'
  source+='''
precondition(embeddedURL("ipify").absoluteString=="https://api.ipify.org/")
precondition(safariURL("ipify")==nil)
precondition(allowed(URL(string:"https://api.ipify.org/")))
for invalid in ["http://api.ipify.org/", "https://api.ipify.org:8443/", "https://user:pass@api.ipify.org/", "https://api.ipify.org/?format=json", "https://api.ipify.org/#fragment", "https://api.ipify.org/private", "https://api64.ipify.org/", "https://other.api.ipify.org/", "https://api.ipify.org.evil.invalid/"] {
 precondition(!allowed(URL(string:invalid)))
}
print("PASS: embedded plain IPv4 fallback; Safari unchanged; nine widened requests rejected")
'''
  with tempfile.TemporaryDirectory(prefix='flvless-ipify-allowlist-') as temporary:
   folder=Path(temporary);p=folder/'main.swift';p.write_text(source);binary=folder/'probe'
   compiler=shutil.which('swiftc');self.assertIsNotNone(compiler)
   r=subprocess.run([compiler,'-swift-version','5','-module-cache-path',str(folder/'modules'),str(p),'-o',str(binary)],capture_output=True,text=True,timeout=45)
   self.assertEqual(r.returncode,0,r.stderr[-4000:])
   r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=5)
   self.assertEqual(r.returncode,0,r.stderr[-4000:])
   self.assertIn('nine widened requests rejected',r.stdout)

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*remaining])
