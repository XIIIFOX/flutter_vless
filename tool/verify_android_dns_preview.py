#!/usr/bin/env python3
"""Verify an unpublished native-entry build before debug-only APK packaging."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import build_android_dns_preview as builder


def elf_alignment(path, arch):
    expected = {'x86_64': (2, 62), 'x86': (1, 3), 'arm64-v8a': (2, 183), 'armeabi-v7a': (1, 40)}
    with path.open('rb') as source:
        header = source.read(64)
        if len(header) < 64 or header[:4] != b'\x7fELF' or header[5] != 1:
            raise ValueError('Preview is not a little-endian ELF executable')
        elf_class, machine = expected[arch]
        if header[4] != elf_class or struct.unpack_from('<HH', header, 16) != (3, machine):
            raise ValueError('Preview ELF target does not match its ABI')
        if elf_class == 2:
            entry, table = struct.unpack_from('<QQ', header, 24)
            entry_size, count = struct.unpack_from('<HH', header, 54)
            minimum, align_offset, value_format = 56, 48, '<Q'
            header_size, address_offset = 64, 8
        else:
            entry, table = struct.unpack_from('<II', header, 24)
            entry_size, count = struct.unpack_from('<HH', header, 42)
            minimum, align_offset, value_format = 32, 28, '<I'
            header_size, address_offset = 52, 4
        if not entry or entry_size < minimum or not 1 <= count <= 128 or table < header_size or table + entry_size * count > path.stat().st_size:
            raise ValueError('Preview ELF program table is invalid')
        alignments = []
        for index in range(count):
            source.seek(table + index * entry_size)
            record = source.read(minimum)
            if struct.unpack_from('<I', record)[0] == 1:
                alignment = struct.unpack_from(value_format, record, align_offset)[0]
                if alignment < 16384 or alignment & (alignment - 1):
                    raise ValueError('Preview LOAD alignment is below 16 KiB')
                offset, address = struct.unpack_from('<QQ' if elf_class == 2 else '<II', record, address_offset)
                if offset % alignment != address % alignment:
                    raise ValueError('Preview LOAD address/offset alignment mismatch')
                alignments.append(alignment)
        if not alignments:
            raise ValueError('Preview ELF has no LOAD segments')
        return alignments


def verify(directory):
    directory = directory.resolve()
    metadata = json.loads((directory / 'result.json').read_text())
    manifest = json.loads((builder.CAPABILITY / 'pin-manifest.json').read_text())
    for key in ('success', 'source_snapshot_unchanged', 'module_cache_targeted_sources_unchanged'):
        if metadata.get(key) is not True:
            raise ValueError('Preview build evidence is incomplete')
    for key in ('published', 'production_enabled', 'host_qualified', 'runtime_executed'):
        if metadata.get(key) is not False:
            raise ValueError('Expected an explicitly unpublished development build')
    if metadata.get('core_commit') != manifest['core_commit'] or metadata.get('capability') != 'native-instance-preview-1':
        raise ValueError('Preview capability/Core pin mismatch')
    if metadata.get('input_sha256') != builder.input_hashes():
        raise ValueError('Preview source snapshot differs from this checkout')
    if any(metadata.get(key) is not True for key in ('classic_dns_lifetime_applied', 'h3_lifetime_applied')) \
            or metadata.get('lifetime_patch_scope') != ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'] \
            or metadata.get('h3_lifetime_patch_sha256') != metadata['input_sha256'].get('third_party/xray-native-dns/h3_lifetime_patch.py'):
        raise ValueError('Preview lifetime patch evidence differs')
    arch = metadata.get('arch')
    if arch not in builder.TARGETS:
        raise ValueError('Preview ABI is unsupported')
    jni = directory / 'jniLibs'
    entries = list(jni.rglob('*'))
    expected_entries = {arch, arch + '/libxray_dns_preview.so'}
    if jni.is_symlink() or {path.relative_to(jni).as_posix() for path in entries} != expected_entries or any(path.is_symlink() for path in entries):
        raise ValueError('Preview JNI tree contains unverified inputs')
    artifact = jni / arch / 'libxray_dns_preview.so'
    if artifact.is_symlink() or not artifact.is_file() or Path(metadata.get('artifact', '')).resolve() != artifact.resolve():
        raise ValueError('Preview artifact location mismatch')
    with artifact.open('rb') as source:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024*1024), b''):
            hasher.update(chunk)
        digest = hasher.hexdigest()
    if digest != metadata.get('artifact_sha256'):
        raise ValueError('Preview artifact checksum mismatch')
    return {'capability': metadata['capability'], 'core_commit': metadata['core_commit'], 'arch': arch,
            'artifact_sha256': digest, 'artifact': str(artifact), 'load_alignments': elf_alignment(artifact, arch),
            'production_enabled': False, 'host_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        print(json.dumps(verify(arguments.directory)))
    except (OSError, ValueError, KeyError, struct.error) as error:
        parser.exit(1, f'Android preview verification failed: {error}\n')
