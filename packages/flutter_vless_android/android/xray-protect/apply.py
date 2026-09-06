#!/usr/bin/env python3
"""Apply the narrowly pinned socket-protection overlay to a disposable Xray tree."""
import pathlib
import shutil
import sys

root = pathlib.Path(sys.argv[1])
overlay = pathlib.Path(__file__).resolve().parent

def replace(path, old, new, count=1):
    target = root / path
    text = target.read_text()
    if text.count(old) != count:
        raise SystemExit(f"Unexpected Xray source in {path}; review overlay before building")
    target.write_text(text.replace(old, new))

replace("transport/internet/system_dialer.go",
        'errors.LogInfoInner(ctx, err, "failed to apply external controller")',
        'return err', 2)
old = '''\t\treturn c.Control(func(fd uintptr) {
\t\t\tfor _, controller := range controllers {
\t\t\t\tif err := controller(network, address, c); err != nil {
\t\t\t\t\terrors.LogInfoInner(ctx, err, "failed to apply external controller")
\t\t\t\t}
\t\t\t}
'''
new = '''\t\tfor _, controller := range controllers {
\t\t\tif err := controller(network, address, c); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t}
\t\treturn c.Control(func(fd uintptr) {
'''
replace("transport/internet/system_listener.go", old, new)
replace("features/dns/localdns/client.go",
        '\t\t\treturn d.DialContext(ctx, network, address)',
        '''\t\t\tif net.DefaultResolver.Dial != nil {
\t\t\t\treturn net.DefaultResolver.Dial(ctx, network, address)
\t\t\t}
\t\t\treturn d.DialContext(ctx, network, address)''')
for path in ["transport/internet/reality/config.go", "proxy/vless/inbound/inbound.go", "proxy/trojan/server.go"]:
    replace(path, 'var dialer net.Dialer', 'dialer := net.Dialer{Control: internet.ApplyExternalControllers}')
    if '"github.com/xtls/xray-core/transport/internet"' not in (root / path).read_text():
        replace(path, 'import (', 'import (\n\t"github.com/xtls/xray-core/transport/internet"')

(root / "transport/internet/android_protect_controller.go").write_text('''package internet
import "syscall"
// ApplyExternalControllers covers direct server fallback dialers as well.
func ApplyExternalControllers(network, address string, c syscall.RawConn) error {
    if network == "unix" || network == "unixpacket" { return nil }
    for _, controller := range Controllers {
        if err := controller(network, address, c); err != nil { return err }
    }
    return nil
}
''')
destination = root / "common/androidprotect"
destination.mkdir()
shutil.copyfile(overlay / "protect.go", destination / "protect.go")
shutil.copyfile(overlay / "main_android.go", root / "main/flutter_vless_protect_android.go")
if (overlay / "protect_test.go").exists():
    shutil.copyfile(overlay / "protect_test.go", destination / "protect_test.go")
