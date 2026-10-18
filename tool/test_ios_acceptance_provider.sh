#!/usr/bin/env bash
# Compile the actual development-only provider boundary against in-memory
# workers/queues. Never links Xray/HEV or accesses NetworkExtension preferences.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/ios_acceptance_provider_probe"
mkdir -p "$OUT"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root, out = map(Path, sys.argv[1:])
source = (root/'example/ios/XrayTunnel/PacketTunnelProvider.swift').read_text()
fixture = (root/'tool/fixtures/ios_acceptance_provider_test.swift').read_text()

def guarded(marker):
    position = source.index(marker)
    begin = source.rfind('    #if FLUTTER_VLESS_ACCEPTANCE_TESTING\n', 0, position)
    assert begin >= 0, f'Unguarded acceptance boundary: {marker}'
    depth, end = 0, begin
    for line in source[begin:].splitlines(keepends=True):
        directive = line.strip()
        if directive.startswith('#if '):
            depth += 1
        elif directive == '#endif':
            depth -= 1
        end += len(line)
        if depth == 0:
            block = source[begin:end]
            assert marker in block, f'Marker outside its acceptance guard: {marker}'
            return block
    raise AssertionError('Unclosed acceptance guard')

state = guarded('private var acceptanceCoreLossUsed = false')
helper = guarded('private func acceptanceCoreLossIsSafe()')
dispatch = guarded('if messageData == Data("acceptance-stop-core".utf8)')
for marker, body in [('STATE', state), ('HELPER', helper), ('DISPATCH', dispatch)]:
    placeholder = f'    // SOURCE_ACCEPTANCE_{marker}\n'
    assert fixture.count(placeholder) == 1
    fixture = fixture.replace(placeholder, body)
(out/'Probe.swift').write_text(fixture)
PY
for mode in normal acceptance; do
  FLAGS=(-parse-as-library)
  if [[ "$mode" == acceptance ]]; then FLAGS+=(-D FLUTTER_VLESS_ACCEPTANCE_TESTING); fi
  xcrun swiftc -O "${FLAGS[@]}" "$OUT/Probe.swift" -o "$OUT/$mode"
  xcrun swiftc -emit-silgen "${FLAGS[@]}" "$OUT/Probe.swift" -o "$OUT/$mode.sil"
done
python3 - "$OUT" <<'PY'
from pathlib import Path
import subprocess, sys
out = Path(sys.argv[1])
normal = (out/'normal.sil').read_text()
acceptance = (out/'acceptance.sil').read_text()
for symbol in ['acceptanceCoreLossUsed', 'acceptanceCoreLossIsSafe', 'acceptanceStopCore',
               'Acceptance worker-loss injection: Core stopped']:
    assert symbol not in normal, f'Acceptance hook escaped its build guard: {symbol}'
    assert symbol in acceptance, f'Acceptance fixture omitted its source: {symbol}'
for mode in ['normal', 'acceptance']:
    result = subprocess.run([str(out/mode)], capture_output=True, text=True, timeout=15)
    (out/f'{mode}.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
    print(result.stdout.strip())
print('PASS provider acceptance build boundary: hook methods/state/marker absent without explicit compilation flag')
PY
