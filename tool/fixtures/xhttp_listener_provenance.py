"""Tiny file-only source transition for producer/packager unit fixtures.

Uses the real guard implementation with a synthetic full-source checksum. No
Go/native code, compiler, server or socket is executed.
"""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATCH = 'third_party/xray-native-dns/xhttp_listener_lifetime_patch.py'
HUB = 'transport/internet/splithttp/hub.go'


def bind(root, cache, copied, report, sources, *, upstream_key='module_cache_before_sha256'):
    spec = importlib.util.spec_from_file_location('unit_xhttp_listener_guard', ROOT / PATCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    upstream, prepared = Path(cache) / HUB, Path(copied) / HUB
    for path in (upstream, prepared):
        path.parent.mkdir(parents=True, exist_ok=True)
    text = '// inert test fixture, not a compiled Core\n'+module.BEFORE+'\n'
    upstream.write_text(text)
    prepared.write_text(text.replace(module.BEFORE, module.AFTER))
    patch = Path(root) / PATCH
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_text((ROOT / PATCH).read_text().replace(module.UPSTREAM_SHA256[HUB], digest(upstream)))
    sources[PATCH] = digest(patch)
    report.setdefault(upstream_key, {})[HUB] = digest(upstream)
    report.setdefault('core_copy_sha256', {})[HUB] = digest(prepared)
    report.update(xhttp_listener_cleanup_applied=True,
                  xhttp_listener_cleanup_patch_sha256=sources[PATCH],
                  xhttp_listener_cleanup_source_sha256=digest(prepared))
