#!/usr/bin/env python3
"""Match packaged preview libraries to fresh, separately verified build reports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile


SUPPORTED_ABIS = frozenset(('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'))
CORE_NAME = 'libxray_dns_preview.so'
TUN_NAME = 'libtun2socks_preview.so'
PREVIEW_NAMES = {name.casefold(): name for name in (CORE_NAME, TUN_NAME)}


def _report(report: dict, capability: str) -> tuple[str, str]:
    if not isinstance(report, dict) or report.get('capability') != capability:
        raise ValueError('Preview verification capability mismatch')
    arch = report.get('arch')
    if not isinstance(arch, str) or arch not in SUPPORTED_ABIS:
        raise ValueError('Preview verification ABI is unsupported')
    digest = report.get('artifact_sha256')
    if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
        raise ValueError('Preview verification checksum is invalid')
    if report.get('production_enabled') is not False or report.get('host_qualified') is not False:
        raise ValueError('Expected an explicitly unqualified development preview')
    return arch, digest


def _preview_name(info: zipfile.ZipInfo) -> str | None:
    # Inspect the original ZIP name too: ZipInfo truncates NUL-bearing names.
    # Backslash, case aliases, and directory-shaped occurrences are never valid
    # library paths, but must not hide an additional preview payload.
    matches = {PREVIEW_NAMES[part.casefold()]
               for name in (info.orig_filename, info.filename)
               for part in name.replace('\\', '/').split('/')
               if part.casefold() in PREVIEW_NAMES}
    if len(matches) > 1:
        raise ValueError('APK preview library has an invalid path')
    return next(iter(matches), None)


def verify(apkPath, coreVerification: dict, tunVerification: dict | None = None):
    """Verify ZIP bytes only; this does not qualify or execute the Android host."""
    arch, core_digest = _report(coreVerification, 'native-instance-preview-1')
    expected = {f'lib/{arch}/{CORE_NAME}': core_digest}
    if tunVerification is not None:
        tun_arch, tun_digest = _report(tunVerification, 'native-tun-forwarder-preview-1')
        if tun_arch != arch:
            raise ValueError('Core and forwarder verification ABIs differ')
        expected[f'lib/{arch}/{TUN_NAME}'] = tun_digest
    apk = Path(apkPath).absolute()
    if apk.is_symlink() or not apk.is_file():
        raise ValueError('APK must be a regular file without a symlink')
    selected = {}
    try:
        with zipfile.ZipFile(apk) as archive:
            for info in archive.infolist():
                preview = _preview_name(info)
                if preview is None:
                    continue
                required_path = f'lib/{arch}/{preview}'
                if (info.orig_filename != required_path or info.filename != required_path
                        or required_path not in expected):
                    raise ValueError('APK contains an unexpected preview library path or ABI')
                if required_path in selected:
                    raise ValueError('APK contains duplicate preview library entries')
                mode = info.external_attr >> 16
                if info.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise ValueError('APK preview entry must be a regular file without a symlink')
                if info.flag_bits & 1:
                    raise ValueError('APK preview entry must not be encrypted')
                selected[required_path] = info
            if set(selected) != set(expected):
                raise ValueError('APK is missing a verified preview library')
            digests = {}
            for name, info in selected.items():
                hasher = hashlib.sha256()
                count = 0
                with archive.open(info) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        hasher.update(chunk)
                        count += len(chunk)
                if count != info.file_size or hasher.hexdigest() != expected[name]:
                    raise ValueError('APK preview library checksum mismatch')
                digests[name] = hasher.hexdigest()
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as error:
        raise ValueError('APK preview ZIP data is invalid') from error
    return {'verified': True, 'apk': str(apk), 'arch': arch, 'entries': digests,
            'production_enabled': False, 'host_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--core-verification', type=Path, required=True)
    parser.add_argument('--tun-verification', type=Path)
    arguments = parser.parse_args()
    try:
        core = json.loads(arguments.core_verification.read_text(encoding='utf-8'))
        tun = (json.loads(arguments.tun_verification.read_text(encoding='utf-8'))
               if arguments.tun_verification is not None else None)
        print(json.dumps(verify(arguments.apk, core, tun)))
    except (OSError, ValueError) as error:
        parser.exit(1, f'Android preview APK verification failed: {error}\n')
