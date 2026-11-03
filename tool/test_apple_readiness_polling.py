#!/usr/bin/env python3
"""Execute actual host readiness/timer bodies at inert, held provider boundaries."""
import argparse,subprocess,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCES={"IOS":"ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift",
 "MACOS":"packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift"}

def function(text,prefix):
    begin=text.index(prefix);opening=text.rfind('{',begin,text.index('\n',begin));depth=1;end=opening+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[begin:end]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',action='store_true',help='Exercise unchanged HEAD sources as a negative control.')
    args=parser.parse_args();fixture=(ROOT/'tool/fixtures/apple_readiness_polling.swift').read_text()
    failed=False
    with tempfile.TemporaryDirectory(prefix='flutter-vless-ready-')as folder:
        out=Path(folder)
        for platform,name in SOURCES.items():
            text=subprocess.check_output(['git','show','HEAD:'+name],cwd=ROOT,text=True,timeout=10)if args.baseline else(ROOT/name).read_text()
            first=text.index('    private func startTimer(');last=text.index('    private func currentDurationSeconds()',first)
            methods=text[first:last].replace('    private func ','    func ')
            state=function(text,'    private func '+('currentRuntimeState'if platform=='IOS'else'currentWireState')+'(')
            duration=function(text,'    private func currentDurationSeconds(')
            refresh=function(text,'    func refreshForwardingState(')
            if '    @MainActor\n    func refreshForwardingState(' in text: refresh='    @MainActor\n'+refresh
            rate=text[text.index('private func trafficBytesPerSecond('):text.index('private final class ProxyOnlyRunner {')]
            body=fixture.replace('// ACTUAL_TIMER_METHODS',methods).replace('// ACTUAL_STATE_METHOD',state).replace('// ACTUAL_DURATION_METHOD',duration).replace('// ACTUAL_MANAGER_REFRESH',refresh).replace('// ACTUAL_RATE_HELPER',rate)
            source=out/(platform+'.swift');source.write_text(body);binary=out/platform
            flags=['-DOWNER_GUARD'] if 'refreshForwardingState(isCurrent:' in text else []
            subprocess.run(['swiftc','-parse-as-library','-D'+platform,*flags,str(source),'-o',str(binary)],check=True,timeout=60)
            result=subprocess.run([str(binary)],check=False,timeout=15)
            failed=failed or result.returncode!=0
    return 1 if failed else 0

if __name__=='__main__':raise SystemExit(main())
