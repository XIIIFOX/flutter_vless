#!/bin/bash
set -euo pipefail
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.3}"

# Build the pinned source plus the reviewed Android FD-protection overlay.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
XRAY_VERSION="${XRAY_VERSION:-v26.10.29}"
XRAY_NATIVE_ROUTING="${XRAY_NATIVE_ROUTING:-0}"
case "$XRAY_NATIVE_ROUTING" in 0|1) ;; *) echo 'XRAY_NATIVE_ROUTING must be 0 or 1' >&2; exit 2 ;; esac
if [ "$XRAY_NATIVE_ROUTING" = 1 ] && [ -z "${TARGET_DIR:-}" ]; then
    echo 'The optional routing build requires an explicit TARGET_DIR' >&2
    exit 2
fi
TARGET_DIR="${TARGET_DIR:-../../../android_runtime/xray_android/src/main/jniLibs}"
# Resolve without creating it in either mode; source/cache and selected-ABI
# boundaries must pass before build_xray creates any output directory.
TARGET_DIR="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$TARGET_DIR")"
if [ "$XRAY_VERSION" != "v26.10.29" ]; then
    echo "The protection overlay requires Xray v26.10.29; review before changing core versions." >&2
    exit 1
fi
NDK_PATH="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"

# Check NDK
if [ ! -d "$NDK_PATH" ]; then
    echo "Error: NDK not found at $NDK_PATH"
    echo "Please export ANDROID_NDK_HOME pointing to your NDK installation."
    exit 1
fi

echo "Using NDK at: $NDK_PATH"

# MacOS NDK Toolchain path
case "$(uname -s)" in
    Darwin) TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/darwin-x86_64" ;;
    Linux) TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64" ;;
    *) echo "Error: unsupported host OS $(uname -s)"; exit 1 ;;
esac
if [ ! -d "$TOOLCHAIN" ]; then
    echo "Error: NDK toolchain not found at $TOOLCHAIN"
    echo "Are you on macOS? If not, please edit the script to match your OS."
    exit 1
fi

# Never patch a developer checkout or the shared Go module cache.
BUILD_FLAGS=()
if [ "$XRAY_NATIVE_ROUTING" = 1 ]; then
    unset GOFLAGS
    export GOTOOLCHAIN=local GOWORK=off
    mkdir -p "$SCRIPT_DIR/../../../build"
    ROUTING_WORK="$(mktemp -d "$SCRIPT_DIR/../../../build/security-android-routing.XXXXXXXX")"
    ROUTING_WORK="$(cd "$ROUTING_WORK" && pwd)"
    SOURCE_DIR="$ROUTING_WORK/Core"
    ROUTING_TAGS='flutter_vless_vpn_routing_cli,flutter_vless_vpn_routing,flutter_vless_managed_service_lifetimes'
    BUILD_FLAGS=(-mod=readonly "-tags=$ROUTING_TAGS")
    python3 - "$SCRIPT_DIR/../../.." "$ROUTING_WORK" "$ROUTING_TAGS" "$TARGET_DIR" <<'PY'
from pathlib import Path
import hashlib, importlib.util, json, os, re, shutil, subprocess, sys
root, work, tags, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]).resolve()
mobile, capability, protect = root/'third_party/xray-mobile', root/'third_party/xray-vpn-routing', root/'packages/flutter_vless_android/android/xray-protect'
manifest = json.loads((capability/'pin-manifest.json').read_text())
module, version, checksum = (manifest[k] for k in ('module', 'module_version', 'module_sum'))
mobile_module = 'github.com/EbrahimTahernejad/xray-mobile'
requirement = re.compile(r'^\s*(?:require\s+)?'+re.escape(module)+r'\s+'+re.escape(version)+r'\s*(?://[^\n]*)?$', re.M)
if not requirement.search((mobile/'go.mod').read_text()) or f'{module} {version} {checksum}' not in (mobile/'go.sum').read_text().splitlines():
    raise SystemExit('Routing Core pin differs from mobile module')
metadata = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', module+'@'+version], cwd=mobile, text=True, timeout=180))
if metadata.get('Error') or any(metadata.get(k) != v for k,v in [('Path',module),('Version',version),('Sum',checksum)]):
    raise SystemExit('Downloaded Core Version/Sum differs from routing pin')
source = Path(metadata['Dir']).resolve()
cache_path = subprocess.check_output(['go','env','GOMODCACHE'], cwd=mobile, text=True, timeout=30).strip()
if not cache_path or not Path(cache_path).is_absolute(): raise SystemExit('Cannot determine the Go module cache')
cache_root = Path(cache_path).resolve()
for protected in [cache_root, source, mobile, capability, protect]:
    protected = protected.resolve()
    if output == protected or protected in output.parents:
        raise SystemExit('Routing output must be outside build inputs and the Go module cache')
selected_abis = [arch for arch, key in [('arm64-v8a','XRAY_BUILD_ARM64'),('armeabi-v7a','XRAY_BUILD_ARMV7'),('x86','XRAY_BUILD_X86'),('x86_64','XRAY_BUILD_X86_64')] if os.environ.get(key,'1') == '1']
if not selected_abis: raise SystemExit('Optional routing build requires at least one ABI')
for arch in selected_abis:
    for path in [output/arch, output/arch/'libxray.so']:
        if path.is_symlink() or output not in path.resolve().parents:
            raise SystemExit('Routing ABI output must remain within the admitted output directory without symlinks')
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def tree(path):
    if path.is_symlink() or not path.is_dir(): raise ValueError('Source must be a real directory')
    entries = sorted(path.rglob('*'))
    if any(p.is_symlink() for p in entries): raise ValueError('Source symlinks are unsupported')
    return {str(p.relative_to(path)):digest(p) for p in entries if p.is_file()}
paths = [root/'packages/flutter_vless_android/android/build_xray.sh', mobile/'go.mod', mobile/'go.sum', capability/'apply.py', capability/'pin-manifest.json']
paths += sorted(mobile.glob('*.go')) + sorted((mobile/'nativecli').rglob('*.go')) + sorted((capability/'overlay').rglob('*.go'))
paths += sorted(protect.glob('*.py')) + sorted(protect.glob('*.go'))
classic = root/'third_party/xray-native-dns'
paths += [classic/name for name in ('classic_lifetime_patch.py','h3_lifetime_patch.py','darwin_interface_bind_patch.py','xdrive_lifetime_patch.py','geodata_lifetime_patch.py','pin-manifest.json','overlay/main/native_services_cli.go','overlay/transport/internet/xdrive/native_lifetime.go', 'overlay/transport/internet/native_service_lifetime.go','overlay/app/dns/native_classic_lifetime.go','overlay/app/dns/native_classic_lifetime_test.go')]
paths += sorted((classic/'overlay/transport/internet/xdrive').glob('*_test.go')) + sorted((classic/'overlay/app/geodata').glob('native_*.go')) + sorted((classic/'overlay/core').glob('native_managed_lifetime_test.go'))
if mobile.is_symlink() or any(p.is_symlink() for p in paths): raise ValueError('Build input symlinks are unsupported')
tree(mobile/'nativecli')
before, cache_before = {str(p.relative_to(root)):digest(p) for p in paths}, tree(source)
spec = importlib.util.spec_from_file_location('android_routing_applier', capability/'apply.py')
applier = importlib.util.module_from_spec(spec); spec.loader.exec_module(applier)
core = applier.copy_and_apply(source, work/'Core')
# Protection's pinned replacements must compose before any module-file edits.
subprocess.run([sys.executable, str(protect/'apply.py'), str(core)], check=True, timeout=30)
copied = work/'mobile'; copied.mkdir()
for path in [mobile/'go.mod', mobile/'go.sum', *sorted(mobile.glob('*.go'))]: shutil.copyfile(path, copied/path.name)
shutil.copytree(mobile/'nativecli', copied/'nativecli')
subprocess.run(['go','mod','edit','-require='+mobile_module+'@v0.0.0','-replace='+mobile_module+'='+str(copied)], cwd=core, check=True, timeout=30)
subprocess.run(['go','mod','edit','-replace='+module+'='+str(core)], cwd=copied, check=True, timeout=30)
for name, directory, target in [('core',core,'./main'),('mobile',copied,'./nativecli')]:
    graph_log = work/(name+'-graph-readonly.log')
    try:
        with graph_log.open('wb') as log:
            subprocess.run(['go','list','-mod=readonly','-tags='+tags,'-deps',target], cwd=directory, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
    except subprocess.CalledProcessError as error:
        with graph_log.open('rb') as log:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell()-8192))
            tail = log.read(8192)
        print(f'ROUTING_GRAPH_FAILURE stage={name} exit={error.returncode} tail_bytes={len(tail)}', file=sys.stderr, flush=True)
        sys.stderr.buffer.write(tail + (b'' if tail.endswith(b'\n') else b'\n'))
        sys.stderr.flush()
        raise
for directory, selected_module, selected_version, replacement in [(core,mobile_module,'v0.0.0',copied),(copied,module,version,core)]:
    selected = json.loads(subprocess.check_output(['go','list','-mod=readonly','-m','-json',selected_module], cwd=directory, text=True, timeout=30))
    if selected.get('Path') != selected_module or selected.get('Version') != selected_version or Path(selected.get('Replace',{}).get('Dir','')).resolve() != replacement.resolve():
        raise SystemExit('Routing build lost its intended local module replacement')
state = {'success':False, 'core_module':module, 'core':version, 'core_sum':checksum, 'core_commit':manifest['core_commit'],
         'overlay_capability':manifest['capability'], 'core_source':str(source), 'go_module_cache':str(cache_root),
         'output_directory':str(output), 'core_replacement':str(core), 'mobile_replacement':str(copied),
         'source_sha256':before, 'module_cache_before_sha256':cache_before, 'core_copy_sha256':tree(core), 'mobile_copy_sha256':tree(copied),
         'routing_tags':tags.split(','), 'selected_abis':selected_abis, 'protection_overlay':'ordinary H/P/D',
         'routing_capability_expected':1, 'classic_dns_lifetime_applied':True,
         'h3_lifetime_applied':True, 'xdrive_lifetime_applied':True, 'geodata_lifetime_applied':True, 'lifetime_patch_scope':['classic_dns','xhttp_h3_dial','xdrive_services','geodata_updater'],
         'h3_lifetime_patch_sha256':before['third_party/xray-native-dns/h3_lifetime_patch.py'],
         'xdrive_lifetime_patch_sha256':before['third_party/xray-native-dns/xdrive_lifetime_patch.py'],
         'geodata_lifetime_patch_sha256':before['third_party/xray-native-dns/geodata_lifetime_patch.py'],
         'darwin_interface_binding_source_applied':True,
         'darwin_interface_binding_patch_sha256':before['third_party/xray-native-dns/darwin_interface_bind_patch.py'],
         'runtime_executed':False, 'published':False}
(work/'inputs.json').write_text(json.dumps(state,indent=2)+'\n')
PY
else
mkdir -p "$SCRIPT_DIR/../../../build"
ROUTING_WORK="$(mktemp -d "$SCRIPT_DIR/../../../build/security-android-classic.XXXXXXXX")"
ROUTING_WORK="$(cd "$ROUTING_WORK" && pwd)"
SOURCE_DIR="$ROUTING_WORK/Core"
python3 - "$SCRIPT_DIR/../../.." "$ROUTING_WORK" "$TARGET_DIR" <<'PYCLASSIC'
from pathlib import Path
import hashlib, importlib.util, json, os, subprocess, sys
root, work, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), Path(sys.argv[3]).resolve()
mobile, capability, protect = root/'third_party/xray-mobile', root/'third_party/xray-vpn-routing', root/'packages/flutter_vless_android/android/xray-protect'
manifest = json.loads((capability/'pin-manifest.json').read_text())
module, version, checksum = (manifest[k] for k in ('module','module_version','module_sum'))
metadata = json.loads(subprocess.check_output(['go','mod','download','-json',module+'@'+version],cwd=mobile,text=True,timeout=180))
if metadata.get('Error') or any(metadata.get(k) != v for k,v in [('Path',module),('Version',version),('Sum',checksum)]):
    raise SystemExit('Classic Core pin/checksum mismatch')
source = Path(metadata['Dir']).resolve()
cache = Path(subprocess.check_output(['go','env','GOMODCACHE'],cwd=mobile,text=True,timeout=30).strip())
if not cache.is_absolute(): raise SystemExit('Missing module cache')
for parent in (source,cache,root/'third_party',protect):
    if output == parent.resolve() or parent.resolve() in output.parents: raise SystemExit('Classic output overlaps source/cache')
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def tree(path):
    entries=sorted(path.rglob('*'))
    if path.is_symlink() or any(p.is_symlink() for p in entries): raise ValueError('Classic source symlink')
    return {str(p.relative_to(path)):digest(p) for p in entries if p.is_file()}
paths=[root/'packages/flutter_vless_android/android/build_xray.sh',mobile/'go.mod',mobile/'go.sum',capability/'apply.py',capability/'pin-manifest.json']
paths += sorted(mobile.glob('*.go')) + sorted((mobile/'nativecli').rglob('*.go')) + sorted((capability/'overlay').rglob('*.go'))
paths += sorted(protect.glob('*.py')) + sorted(protect.glob('*.go'))
classic=root/'third_party/xray-native-dns'
paths += [classic/name for name in ('classic_lifetime_patch.py','h3_lifetime_patch.py','darwin_interface_bind_patch.py','xdrive_lifetime_patch.py','geodata_lifetime_patch.py','pin-manifest.json','overlay/main/native_services_cli.go','overlay/transport/internet/xdrive/native_lifetime.go', 'overlay/transport/internet/native_service_lifetime.go','overlay/app/dns/native_classic_lifetime.go','overlay/app/dns/native_classic_lifetime_test.go')]
paths += sorted((classic/'overlay/transport/internet/xdrive').glob('*_test.go')) + sorted((classic/'overlay/app/geodata').glob('native_*.go')) + sorted((classic/'overlay/core').glob('native_managed_lifetime_test.go'))
if any(p.is_symlink() for p in paths): raise ValueError('Classic input symlink')
before,cache_before={str(p.relative_to(root)):digest(p) for p in paths},tree(source)
spec=importlib.util.spec_from_file_location('ordinary_classic_applier',capability/'apply.py')
applier=importlib.util.module_from_spec(spec);spec.loader.exec_module(applier)
core=applier.copy_and_apply_lifetimes(source,work/'Core',caches=[cache],routing=False)
subprocess.run([sys.executable,str(protect/'apply.py'),str(core)],check=True,timeout=30)
abis=[arch for arch,key in [('arm64-v8a','XRAY_BUILD_ARM64'),('armeabi-v7a','XRAY_BUILD_ARMV7'),('x86','XRAY_BUILD_X86'),('x86_64','XRAY_BUILD_X86_64')] if os.environ.get(key,'1')=='1']
if not abis: raise SystemExit('Classic build requires an ABI')
for arch in abis:
    for path in (output/arch, output/arch/'libxray.so'):
        if path.is_symlink() or output not in path.resolve().parents:
            raise SystemExit('Classic ABI output must remain within the admitted output directory without symlinks')
state={'success':False,'core_module':module,'core':version,'core_sum':checksum,'core_commit':manifest['core_commit'],
       'core_source':str(source),'source_sha256':before,'module_cache_before_sha256':cache_before,
       'core_copy_sha256':tree(core),'mobile_copy_sha256':None,'selected_abis':abis,
       'classic_dns_lifetime_applied':True,'routing_capability_expected':0,
       'h3_lifetime_applied':True, 'xdrive_lifetime_applied':True, 'geodata_lifetime_applied':True,'lifetime_patch_scope':['classic_dns','xhttp_h3_dial','xdrive_services','geodata_updater'],
       'h3_lifetime_patch_sha256':before['third_party/xray-native-dns/h3_lifetime_patch.py'],
         'xdrive_lifetime_patch_sha256':before['third_party/xray-native-dns/xdrive_lifetime_patch.py'],
         'geodata_lifetime_patch_sha256':before['third_party/xray-native-dns/geodata_lifetime_patch.py'],
         'darwin_interface_binding_source_applied':True,
         'darwin_interface_binding_patch_sha256':before['third_party/xray-native-dns/darwin_interface_bind_patch.py'],
       'runtime_executed':False,'published':False}
(work/'inputs.json').write_text(json.dumps(state,indent=2)+'\n')
PYCLASSIC
fi

# Build Function
build_xray() {
    local ARCH_NAME=$1
    local GO_ARCH=$2
    local GO_ARM=$3
    local ANDROID_TARGET=$4
    local OUTPUT_DIR="${TARGET_DIR}/${ARCH_NAME}"

    echo "Building for ${ARCH_NAME}..."
    
    mkdir -p "$OUTPUT_DIR"

    export CGO_ENABLED=1
    export GOOS=android
    export GOARCH=$GO_ARCH
    export GOARM=$GO_ARM
    
    export CC="${TOOLCHAIN}/bin/${ANDROID_TARGET}-clang"
    export CXX="${TOOLCHAIN}/bin/${ANDROID_TARGET}-clang++"
    
    # 16KB page size support for Android 15+
    export LDFLAGS="-Wl,-z,max-page-size=16384"
    
    # Verify compiler exists
    if [ ! -f "$CC" ]; then
        echo "Error: Compiler not found at $CC"
        # Try older NDK naming convention if new one fails (API 21 is standard)
        # Some NDKs use specific API levels in clang name
        return 1
    fi

    cd "$SOURCE_DIR"
    
    # Build with 16KB page alignment
    if go build ${BUILD_FLAGS[@]+"${BUILD_FLAGS[@]}"} -v -trimpath -buildvcs=false \
        -gcflags "all=-l=4" \
        -ldflags "-X github.com/xtls/xray-core/core.build=${XRAY_VERSION} -s -w -buildid= -checklinkname=0 -linkmode=external -extldflags=${LDFLAGS}" \
        -buildmode=pie \
        -o "${OUTPUT_DIR}/libxray.so" ./main; then
        echo "Success: ${OUTPUT_DIR}/libxray.so created."
    else
        echo "Failed to build for ${ARCH_NAME}"
        return 1
    fi
    
    cd "$SCRIPT_DIR"
}

# Build for Architectures
# API Level 21 is generally safe for modern Flutter apps (Android 5.0+)

# ARM64
if [ "${XRAY_BUILD_ARM64:-1}" = "1" ]; then
    build_xray "arm64-v8a" "arm64" "" "aarch64-linux-android21"
fi

# ARMv7
if [ "${XRAY_BUILD_ARMV7:-1}" = "1" ]; then
    build_xray "armeabi-v7a" "arm" "7" "armv7a-linux-androideabi21"
fi

# x86 is included in the main runtime AAR.
if [ "${XRAY_BUILD_X86:-1}" = "1" ]; then
    build_xray "x86" "386" "" "i686-linux-android21"
fi

# x86_64 is included in the main runtime AAR.
if [ "${XRAY_BUILD_X86_64:-1}" = "1" ]; then
    build_xray "x86_64" "amd64" "" "x86_64-linux-android21"
fi

if true; then
    python3 - "$SCRIPT_DIR/../../.." "$ROUTING_WORK" "$TARGET_DIR" <<'PY'
from pathlib import Path
import hashlib, json, sys
root, work, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), Path(sys.argv[3])
state = json.loads((work/'inputs.json').read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def tree(path):
    if path.is_symlink() or not path.is_dir(): raise ValueError('Copied source must be a real directory')
    entries = sorted(path.rglob('*'))
    if any(p.is_symlink() for p in entries): raise ValueError('Unexpected copied source symlink')
    return {str(p.relative_to(path)):digest(p) for p in entries if p.is_file()}
mobile, capability, protect = root/'third_party/xray-mobile', root/'third_party/xray-vpn-routing', root/'packages/flutter_vless_android/android/xray-protect'
paths = [root/'packages/flutter_vless_android/android/build_xray.sh', mobile/'go.mod', mobile/'go.sum', capability/'apply.py', capability/'pin-manifest.json']
paths += sorted(mobile.glob('*.go')) + sorted((mobile/'nativecli').rglob('*.go')) + sorted((capability/'overlay').rglob('*.go'))
paths += sorted(protect.glob('*.py')) + sorted(protect.glob('*.go'))
classic = root/'third_party/xray-native-dns'
paths += [classic/name for name in ('classic_lifetime_patch.py','h3_lifetime_patch.py','darwin_interface_bind_patch.py','xdrive_lifetime_patch.py','geodata_lifetime_patch.py','pin-manifest.json','overlay/main/native_services_cli.go','overlay/transport/internet/xdrive/native_lifetime.go', 'overlay/transport/internet/native_service_lifetime.go','overlay/app/dns/native_classic_lifetime.go','overlay/app/dns/native_classic_lifetime_test.go')]
paths += sorted((classic/'overlay/transport/internet/xdrive').glob('*_test.go')) + sorted((classic/'overlay/app/geodata').glob('native_*.go')) + sorted((classic/'overlay/core').glob('native_managed_lifetime_test.go'))
if mobile.is_symlink() or any(p.is_symlink() for p in paths) or {str(p.relative_to(root)):digest(p) for p in paths} != state['source_sha256']:
    raise SystemExit('Routing build input changed')
if tree(Path(state['core_source'])) != state['module_cache_before_sha256']:
    raise SystemExit('Original Core cache changed')
if tree(work/'Core') != state['core_copy_sha256'] or (state['mobile_copy_sha256'] is not None and tree(work/'mobile') != state['mobile_copy_sha256']):
    raise SystemExit('Disposable source changed during build')
artifacts = {}
for arch in state['selected_abis']:
    path = output/arch/'libxray.so'
    if path.is_symlink() or not path.is_file(): raise SystemExit('Missing routing ABI output')
    artifacts[arch+'/libxray.so'] = digest(path)
state.update(success=True, source_unchanged=True, module_cache_source_unchanged=True, copies_unchanged=True, artifacts_sha256=artifacts)
receipt = output/(('routing-preview-' if state['routing_capability_expected'] else 'classic-preview-')+work.name+'.json')
with receipt.open('x') as file: file.write(json.dumps(state,indent=2)+'\n')
print('Optional routing build receipt: '+str(receipt))
PY
fi

echo "Build process finished."
