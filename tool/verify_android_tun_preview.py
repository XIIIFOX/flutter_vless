#!/usr/bin/env python3
"""Verify the separate Android preview forwarder before opt-in packaging."""
import argparse
import hashlib
import json
from pathlib import Path

import build_android_tun_preview as builder
from verify_android_dns_preview import elf_alignment


def verify(directory):
    directory = directory.resolve()
    metadata = json.loads((directory / 'result.json').read_text())
    manifest = json.loads((builder.CAPABILITY / 'pin-manifest.json').read_text())
    if any(metadata.get(k) is not True for k in ('success', 'source_snapshot_unchanged', 'module_cache_targeted_sources_unchanged', 'copied_guarded_sources_unchanged')):
        raise ValueError('Forwarder build evidence is incomplete')
    if any(metadata.get(k) is not False for k in ('published', 'production_enabled', 'host_qualified', 'runtime_executed')):
        raise ValueError('Expected an unpublished unexecuted development forwarder')
    if metadata.get('capability') != manifest['capability'] or metadata.get('forwarder_commit') != manifest['commit'] or metadata.get('module_sum') != manifest['module_sum']:
        raise ValueError('Forwarder capability/pin mismatch')
    if metadata.get('input_sha256') != builder.input_hashes():
        raise ValueError('Forwarder source snapshot differs from checkout')
    patched = metadata.get('patched_source_sha256')
    if not isinstance(patched, dict) or set(patched) != set(manifest['upstream_sha256']):
        raise ValueError('Forwarder guarded source evidence has missing or extra files')
    if patched != builder.guarded_source_hashes(directory / 'Source', manifest):
        raise ValueError('Forwarder copied guarded source checksum differs')
    arch = metadata.get('arch')
    if arch not in builder.common.TARGETS:
        raise ValueError('Forwarder ABI is unsupported')
    jni = directory / 'jniLibs'
    entries = list(jni.rglob('*'))
    if jni.is_symlink() or any(p.is_symlink() for p in entries) or {p.relative_to(jni).as_posix() for p in entries} != {arch, arch + '/libtun2socks_preview.so'}:
        raise ValueError('Forwarder JNI tree contains unverified inputs')
    artifact = jni / arch / 'libtun2socks_preview.so'
    if not artifact.is_file() or Path(metadata.get('artifact', '')).resolve() != artifact.resolve():
        raise ValueError('Forwarder artifact location differs')
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != metadata.get('artifact_sha256'):
        raise ValueError('Forwarder artifact checksum differs')
    return dict(capability=manifest['capability'], forwarder_commit=manifest['commit'], arch=arch,
                artifact=str(artifact), artifact_sha256=digest, load_alignments=elf_alignment(artifact, arch),
                production_enabled=False, host_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.directory)))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Preview forwarder verification failed: {error}\n')
