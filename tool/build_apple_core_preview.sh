#!/usr/bin/env bash
# Build-only local artifacts. Never creates or uploads a GitHub release.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
    echo 'Usage: build_apple_core_preview.sh ios|macos OUTPUT_DIRECTORY [--vpn-routing]' >&2
    exit 2
fi
PLATFORM="$1"
OUTPUT="$2"
ROUTING=0
if [[ "$#" == 3 ]]; then
    [[ "$3" == --vpn-routing ]] || { echo 'Expected --vpn-routing as the final argument' >&2; exit 2; }
    ROUTING=1
fi
case "$PLATFORM" in ios|macos) ;; *) echo 'Expected ios or macos' >&2; exit 2 ;; esac
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
test ! -e "$OUTPUT/XRay.xcframework" || { echo 'Output already exists; preserve or remove it explicitly' >&2; exit 2; }
MOBILE="$ROOT/third_party/xray-mobile"
BIND_TAG=""
if true; then
    # gomobile creates its own per-architecture modules. Use a disposable
    # mobile module too, so no ambient -modfile propagation is required.
    unset GOFLAGS
    export GOTOOLCHAIN=local GOWORK=off
    python3 - "$ROOT" "$OUTPUT" "$ROUTING" <<'PY'
from pathlib import Path
import hashlib, importlib.util, json, re, shutil, subprocess, sys
root, output = map(Path, sys.argv[1:3])
routing = sys.argv[3] == '1'
mobile, capability = root/'third_party/xray-mobile', root/'third_party/xray-vpn-routing'
work = output/('routing' if routing else 'classic')
if work.exists() or work.is_symlink():
    raise SystemExit('Routing build directory must be new')
manifest = json.loads((capability/'pin-manifest.json').read_text())
module, version, checksum = (manifest[k] for k in ('module','module_version','module_sum'))
requirement = re.compile(r'^\s*(?:require\s+)?'+re.escape(module)+r'\s+'+re.escape(version)+r'\s*(?://[^\n]*)?$', re.M)
if not requirement.search((mobile/'go.mod').read_text()) or f'{module} {version} {checksum}' not in (mobile/'go.sum').read_text().splitlines():
    raise SystemExit('Routing Core pin differs from mobile module')
metadata = json.loads(subprocess.check_output(['go','mod','download','-json',module+'@'+version], cwd=mobile, text=True, timeout=180))
if metadata.get('Error') or any(metadata.get(k) != v for k,v in [('Path',module),('Version',version),('Sum',checksum)]):
    raise SystemExit('Downloaded Core Version/Sum differs from routing pin')
source = Path(metadata['Dir']).resolve()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def tree(path):
    if path.is_symlink() or not path.is_dir(): raise ValueError('Source must be a real directory')
    entries = sorted(path.rglob('*'))
    if any(p.is_symlink() for p in entries): raise ValueError('Source symlinks are unsupported')
    return {str(p.relative_to(path)):digest(p) for p in entries if p.is_file()}
def inputs():
    paths = [root/'tool/build_apple_core_preview.sh', mobile/'go.mod', mobile/'go.sum', capability/'apply.py', capability/'pin-manifest.json']
    paths += sorted(mobile.glob('*.go')) + sorted((capability/'overlay').rglob('*.go'))
    classic = root/'third_party/xray-native-dns'
    paths += [classic/name for name in ('classic_lifetime_patch.py','h3_lifetime_patch.py','pin-manifest.json','overlay/app/dns/native_classic_lifetime.go','overlay/app/dns/native_classic_lifetime_test.go')]
    if any(p.is_symlink() for p in paths): raise ValueError('Input symlinks are unsupported')
    return {str(p.relative_to(root)):digest(p) for p in paths}
before, cache_before = inputs(), tree(source)
spec = importlib.util.spec_from_file_location('apple_routing_applier', capability/'apply.py')
applier = importlib.util.module_from_spec(spec); spec.loader.exec_module(applier)
work.mkdir()
core = applier.copy_and_apply(source, work/'Core') if routing else applier.copy_and_apply_lifetimes(source, work/'Core', routing=False)
copied = work/'mobile'; copied.mkdir()
for path in [mobile/'go.mod', mobile/'go.sum', *sorted(mobile.glob('*.go'))]:
    shutil.copyfile(path, copied/path.name)
subprocess.run(['go','mod','edit','-modfile='+str(copied/'go.mod'),'-replace='+module+'='+str(core)], cwd=copied, check=True, timeout=30)
state = {'success':False, 'core':version, 'core_module':module, 'core_sum':checksum,
         'core_commit':manifest['core_commit'], 'overlay_capability':manifest['capability'],
         'core_source':str(source), 'core_replacement':str(core), 'source_sha256':before,
         'module_cache_before_sha256':cache_before, 'core_copy_sha256':tree(core),
         'mobile_copy_sha256':tree(copied), 'routing_tag':'flutter_vless_vpn_routing',
         'routing_capability_expected':1 if routing else 0, 'classic_dns_lifetime_applied':True,
         'h3_lifetime_applied':True, 'lifetime_patch_scope':['classic_dns','xhttp_h3_dial'],
         'h3_lifetime_patch_sha256':before['third_party/xray-native-dns/h3_lifetime_patch.py'],
         'runtime_executed':False, 'published':False}
(work/'inputs.json').write_text(json.dumps(state,indent=2)+'\n')
PY
    if [[ "$ROUTING" == 1 ]]; then
        MOBILE="$OUTPUT/routing/mobile"
        BIND_TAG="-tags=flutter_vless_vpn_routing"
    else
        MOBILE="$OUTPUT/classic/mobile"
    fi
fi
cd "$MOBILE"
mkdir -p "$OUTPUT/tools"
go build -mod=readonly -o "$OUTPUT/tools/gomobile" golang.org/x/mobile/cmd/gomobile
go build -mod=readonly -o "$OUTPUT/tools/gobind" golang.org/x/mobile/cmd/gobind
export PATH="$OUTPUT/tools:$PATH"
if [[ "$PLATFORM" == ios ]]; then
    gomobile bind ${BIND_TAG:+"$BIND_TAG"} -target=ios -iosversion=15.0 -ldflags='-s -w -extldflags -lresolv' \
        -o "$OUTPUT/XRay.xcframework" github.com/EbrahimTahernejad/xray-mobile
else
    mkdir -p "$OUTPUT/framework"
    gomobile bind ${BIND_TAG:+"$BIND_TAG"} -target=macos -macosversion=13.0 -ldflags='-s -w -extldflags -lresolv' \
        -o "$OUTPUT/framework/XRay.xcframework" github.com/EbrahimTahernejad/xray-mobile
    FRAMEWORK="$OUTPUT/framework/XRay.xcframework/macos-arm64_x86_64/XRay.framework"
    # Keep the existing static-library XCFramework layout used by CXRay.
    cp -L "$FRAMEWORK/XRay" "$OUTPUT/libXRay.a"
    cp -RL "$FRAMEWORK/Headers" "$OUTPUT/Headers"
    xcodebuild -create-xcframework -library "$OUTPUT/libXRay.a" \
        -headers "$OUTPUT/Headers" -output "$OUTPUT/XRay.xcframework"
fi
python3 - "$OUTPUT" "$PLATFORM" "$ROUTING" "$ROOT" <<'PY'
from pathlib import Path
import hashlib, json, subprocess, sys
output, platform, routing, root = Path(sys.argv[1]), sys.argv[2], sys.argv[3] == '1', Path(sys.argv[4])
pin = subprocess.check_output(['go','list','-m','-f','{{.Version}}','github.com/xtls/xray-core'],text=True).strip()
assert pin.endswith('92ccc939aaf4'), 'Unexpected Xray Core pin'
headers=list((output/'XRay.xcframework').rglob('XRay.objc.h'))
assert headers and all('XRayCheckPrivate' in p.read_text() for p in headers), 'Missing preflight bridge'
if True:
    work = output/('routing' if routing else 'classic')
    state = json.loads((work/'inputs.json').read_text())
    for symbol in (['XRayRoutingCapability','XRayCheckRoutingPrivate','XRayStartRoutingPrivate'] if routing else []):
        assert all(symbol in p.read_text() for p in headers), 'Missing optional routing bridge: '+symbol
    metadata = json.loads(subprocess.check_output(['go','list','-m','-json',state['core_module']],text=True))
    assert Path(metadata.get('Replace',{}).get('Dir','')).resolve() == Path(state['core_replacement']).resolve(), 'Build lost the disposable Core replacement'
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    def tree(path):
        entries = sorted(path.rglob('*'))
        assert not path.is_symlink() and path.is_dir() and not any(p.is_symlink() for p in entries), 'Unexpected copied source shape'
        return {str(p.relative_to(path)):digest(p) for p in entries if p.is_file()}
    mobile, capability = root/'third_party/xray-mobile', root/'third_party/xray-vpn-routing'
    paths = [root/'tool/build_apple_core_preview.sh', mobile/'go.mod', mobile/'go.sum', capability/'apply.py', capability/'pin-manifest.json']
    paths += sorted(mobile.glob('*.go')) + sorted((capability/'overlay').rglob('*.go'))
    classic = root/'third_party/xray-native-dns'
    paths += [classic/name for name in ('classic_lifetime_patch.py','h3_lifetime_patch.py','pin-manifest.json','overlay/app/dns/native_classic_lifetime.go','overlay/app/dns/native_classic_lifetime_test.go')]
    assert not any(p.is_symlink() for p in paths), 'Input became a symlink'
    assert state['source_sha256'] == {str(p.relative_to(root)):digest(p) for p in paths}, 'Build input changed'
    assert state['module_cache_before_sha256'] == tree(Path(state['core_source'])), 'Original Core cache changed'
    assert state['core_copy_sha256'] == tree(Path(state['core_replacement'])) and state['mobile_copy_sha256'] == tree(work/'mobile'), 'Copied source changed during build'
    state.update(success=True, source_unchanged=True, module_cache_source_unchanged=True, copies_unchanged=True)
    (output/('routing-preview.json' if routing else 'classic-preview.json')).write_text(json.dumps(state,indent=2)+'\n')
(output/'preview.json').write_text(json.dumps({'platform':platform,'core':pin,'preflightABI':1,'published':False},indent=2)+'\n')
PY
echo "Built $PLATFORM preview: $OUTPUT/XRay.xcframework"
