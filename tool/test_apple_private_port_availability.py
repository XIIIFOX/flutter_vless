#!/usr/bin/env python3
"""Execute both actual host allocation gates with an inert TCP availability callback."""
from pathlib import Path
import hashlib,json,subprocess
root=Path(__file__).resolve().parents[1];out=root/"build/apple_private_port_availability";out.mkdir(parents=True,exist_ok=True)
paths={'ios':root/'ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift','macos':root/'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift'}
privacy_paths={'ios':root/'ios/flutter_vless/Sources/flutter_vless_privacy',
 'macos':root/'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy'}
fixture='''
struct FlutterError { let code:String; let message:String; let details:Any? }
func FLVlessCoreRoutingCapability() -> Int64 { 1 }
enum Kernel {
 static var busy=Set<Int>(), exhausted=false, attempts:[Int]=[], entries:[Data]=[], captures=0
 static func available(_ port:Int) -> Bool { attempts.append(port); entries=[]; return !exhausted && !busy.contains(port) }
 static func capture() -> XrayEnvironmentSnapshot { captures += 1; return XrayEnvironmentSnapshot(rawEntries:entries) }
 static func reset() { busy=[]; exhausted=false; attempts=[]; entries=[]; captures=0 }
}
final class Probe {
 var reachedQueue=false, errorCode:String?, source:[String:Any], queuedData:Data?, queuedChanges:[NativePreparationReport.Change]=[]
 var errorDetails:Any?, arguments:[String:Any]
 init(_ source:[String:Any], arguments:[String:Any]=[:]) { self.source=source;self.arguments=arguments }
 func result(_ error:FlutterError) { errorCode=error.code;errorDetails=error.details }
 func start() {
 let tcpPortAvailable: (Int)->Bool = Kernel.available\n let captureEnvironment = Kernel.capture\n let arguments=self.arguments
 let configData=try! JSONSerialization.data(withJSONObject:source)
 // ACTUAL_PREFIX
 queuedData=effectiveConfigData;queuedChanges=preparationChanges; reachedQueue=true
 }
}
@main struct Main {
 static func main() {
  var failures=0
  let ordinary:[String:Any]=["inbounds":[["listen":"127.0.0.1","port":19080,"protocol":"socks"]],"outbounds":[["protocol":"freedom","tag":"direct"]]]
  Kernel.reset(); Kernel.busy=[10808]
  let busy=Probe(ordinary);busy.start()
  let busyOK=busy.reachedQueue && Kernel.attempts == [10808,10809] && busy.queuedChanges.isEmpty
  print("CASE=occupied-private;PASS=\\(busyOK);CALLS=\\(Kernel.attempts.count);QUEUE=\\(busy.reachedQueue)")
  if !busyOK { failures += 1 }
  Kernel.reset();Kernel.exhausted=true
  let exhausted=Probe(ordinary);exhausted.start()
  let exhaustedOK = !exhausted.reachedQueue && Kernel.attempts.count == 32
  print("CASE=exhaustion-before-mutation;PASS=\\(exhaustedOK);CALLS=\\(Kernel.attempts.count);QUEUE=\\(exhausted.reachedQueue)")
  if !exhaustedOK { failures += 1 }
  Kernel.reset()
  var reserved=ordinary
  reserved["inbounds"]=[["listen":"127.0.0.1","port":"10808-10810","protocol":"socks"]]
  reserved["api"]=["tag":"caller-api","listen":"127.0.0.1:10811","services":["StatsService"]]
  reserved["metrics"]=["tag":"caller-metrics","listen":"127.0.0.1:10812"]
  let guarded=Probe(reserved);guarded.start()
  let guardedOK = guarded.reachedQueue && Kernel.attempts == [10813] &&
   (try! JSONSerialization.jsonObject(with:guarded.queuedData!) as! NSDictionary) == reserved as NSDictionary
  print("CASE=caller-range-api-metrics-preserved;PASS=\\(guardedOK);CALLS=\\(Kernel.attempts.count);QUEUE=\\(guarded.reachedQueue)")
  if !guardedOK { failures += 1 }
  Kernel.reset()
  let decomp="e\\u{301}", composed="\\u{e9}"
  Kernel.entries=["\\(composed).port=10810", "\\(decomp).port=10808", "\\(decomp).listen=127.0.0.1",
                  "\\(composed).endpoint=wrong.invalid", "E\\u{301}_ENDPOINT=198.51.100.7", "DNS=tcp://9.9.9.9"].map { Data($0.utf8) }
  let raw:[String:Any]=["inbounds":[["protocol":"socks","listen":"env:\\(decomp).listen","port":"env:\\(decomp).port"]],
   "dns":["servers":["env:DNS"]], "outbounds":[["tag":"proxy","protocol":"socks","settings":["servers":[["address":"env:\\(decomp).endpoint","port":443]]]]]]
  let frozen=Probe(raw);frozen.start()
  let image=(try! JSONSerialization.jsonObject(with:frozen.queuedData!)) as! [String:Any]
  let inputs=image["inbounds"] as! [[String:Any]], outputs=image["outbounds"] as! [[String:Any]]
  let endpoint=(((outputs[0]["settings"] as! [String:Any])["servers"] as! [[String:Any]])[0]["address"] as! String)
  let snapshotOK=frozen.reachedQueue && Kernel.captures == 1 && Kernel.entries.isEmpty && Kernel.attempts == [10809] &&
   inputs[0]["port"] as? String == "10808" && inputs[0]["listen"] as? String == "127.0.0.1" && endpoint == "198.51.100.7" &&
   ((image["dns"] as! [String:Any])["servers"] as! [String]) == ["tcp://9.9.9.9"]
  print("CASE=byte-environment-before-allocation-and-persistence;PASS=\\(snapshotOK);CAPTURES=\\(Kernel.captures)")
  if !snapshotOK { failures += 1 }
  let reported=Set(frozen.queuedChanges)==Set([NativePreparationReport.Change.portEnvironmentBound,.addressEnvironmentBound])
  print("CASE=actual-host-typed-preparation-changes;PASS=\(reported)")
  if !reported { failures += 1 }
  let invalid=Probe(ordinary,arguments:["certificate_assets_directory":"secret-canary-relative"]);invalid.start()
  let rejected = !invalid.reachedQueue && invalid.errorCode == "CERTIFICATE_ASSETS_ERROR" &&
   (invalid.errorDetails as? [String:String]) == ["stage":"certificate-assets"]
  print("CASE=preparation-failure-fixed-redacted-stage;PASS=\(rejected)")
  if !rejected { failures += 1 }
  exit(failures == 0 ? 0 : 7)
 }
}
'''.replace('\\(', '\\(')
results={}
source_hashes={}
for platform,path in paths.items():
 privacy=privacy_paths[platform]
 inputs=[privacy/p for p in ['VlessNativeOptions.swift','NativeRoutingSpec.swift','LocalProxyAccessPolicy.swift','XrayAddressEnvironment.swift','XrayCertificatePaths.swift','XrayConfigKeys.swift','XrayServiceTags.swift','XrayPrivacyConfig.swift','CorePreflightPolicy.swift']]
 if platform=='macos':inputs.append(privacy/'DesktopBypassPolicy.swift')
 s=path.read_text();assert 'manager.xrayConfig = effectiveConfigData' in s
 a=s.index('        let proxyOnly = arguments["proxy_only"]');b=s.index('        // Initialization may replace the manager',a)
 runner=s.index('private final class ProxyOnlyRunner {')
 helper_start=s.index('    fileprivate static func buildProxyOnlyConfigData',runner);helper_end=s.index('\n    }\n',helper_start)+6
 delay_start=s.index('    private static func findDelayEndpoint',runner);delay_end=s.index('\n    }\n',delay_start)+6
 prepared_start=s.index('    struct Prepared {',runner);prepared_end=s.index('    // Direct callers share the host admission order:',prepared_start)
 helper='enum ProxyOnlyRunner {\n'+s[prepared_start:prepared_end]+'\n'+s[delay_start:delay_end]+'\n'+s[helper_start:helper_end]+'\n}\n'
 p=out/(platform+'.swift');p.write_text('import Foundation\n'+helper+fixture.replace(' // ACTUAL_PREFIX',s[a:b]))
 with (out/(platform+'-compile.log')).open('wb') as f:r=subprocess.run(['xcrun','swiftc','-O','-parse-as-library',*map(str,inputs),str(p),'-o',str(out/platform)],stdout=f,stderr=subprocess.STDOUT,timeout=100)
 assert r.returncode==0,(out/(platform+'-compile.log')).read_text()[-4000:]
 r=subprocess.run([str(out/platform)],capture_output=True,text=True,timeout=10);(out/(platform+'.log')).write_text(r.stdout+r.stderr)
 assert r.returncode==0 and 'CASE=exhaustion-before-mutation;PASS=true;CALLS=32;QUEUE=false' in r.stdout,(r.returncode,r.stdout,r.stderr)
 results[platform]={'exit':r.returncode,'actual_host_source_sha256':hashlib.sha256(s.encode()).hexdigest(),'log':r.stdout}
 source_hashes.update({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [path,*inputs]})
 print(platform,r.returncode,r.stdout,flush=True)
(out/'result.json').write_text(json.dumps({'passed':True,'production_edits':False,'actual_sockets_Core_or_devices':False,'results':results,'source_sha256':source_hashes},indent=2)+'\n')
