#!/usr/bin/env python3
"""Verify an unpublished routing CLI and its packaged APK bytes; execute nothing."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile

import build_android_routing_preview as builder
from verify_android_dns_preview import elf_alignment


def verify(directory):
    directory = Path(directory).absolute()
    if directory.is_symlink() or not directory.is_dir() or (directory/'result.json').is_symlink():
        raise ValueError('Routing preview must be a real directory without symlinks')
    metadata = json.loads((directory/'result.json').read_text())
    if metadata.get('success') is not True or any(metadata.get(k) is not False for k in ('published','production_enabled','host_qualified','runtime_executed')):
        raise ValueError('Routing preview is incomplete or published')
    if metadata.get('capability') != builder.CAPABILITY_ID or metadata.get('routing_capability_expected') != 1 or isinstance(metadata.get('routing_capability_expected'),bool):
        raise ValueError('Routing preview capability differs')
    arch = metadata.get('arch')
    if arch not in builder.FLAGS: raise ValueError('Routing preview ABI is unsupported')
    expected = builder.validate_receipt(metadata.get('build_receipt',{}), arch, directory/'raw')
    jni = directory/'jniLibs'; entries = list(jni.rglob('*'))
    if jni.is_symlink() or any(p.is_symlink() for p in entries) or {p.relative_to(jni).as_posix() for p in entries} != {arch,arch+'/'+builder.NAME}:
        raise ValueError('Routing JNI tree contains unverified inputs')
    artifact = jni/arch/builder.NAME
    if not artifact.is_file() or Path(metadata.get('artifact','')).absolute() != artifact.absolute(): raise ValueError('Routing artifact location differs')
    checksum = builder.digest(artifact)
    if not re.fullmatch('[0-9a-f]{64}',checksum) or checksum != metadata.get('artifact_sha256') or checksum != expected:
        raise ValueError('Routing artifact checksum differs')
    return {'capability':builder.CAPABILITY_ID,'core_commit':metadata['build_receipt']['core_commit'],'arch':arch,
            'artifact':str(artifact),'artifact_sha256':checksum,'load_alignments':elf_alignment(artifact,arch),
            'production_enabled':False,'host_qualified':False}


def verify_apk(apk, report):
    expected = 'lib/'+report['arch']+'/'+builder.NAME
    selected = None
    apk = Path(apk)
    if apk.is_symlink() or not apk.is_file(): raise ValueError('APK must be a real file')
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if not any(part.casefold() == builder.NAME for name in (info.orig_filename,info.filename) for part in name.replace('\\','/').split('/')): continue
            if info.orig_filename != expected or info.filename != expected or selected is not None:
                raise ValueError('Unexpected or duplicate routing APK entry')
            if info.is_dir() or stat.S_IFMT(info.external_attr>>16) not in (0,stat.S_IFREG) or info.flag_bits & 1:
                raise ValueError('Routing APK entry is not a regular unencrypted file')
            selected = info
        if selected is None: raise ValueError('Routing preview is missing from APK')
        value = hashlib.sha256(); count = 0
        with archive.open(selected) as source:
            for chunk in iter(lambda:source.read(1024*1024),b''): value.update(chunk); count += len(chunk)
        if value.hexdigest() != report['artifact_sha256'] or count != selected.file_size: raise ValueError('Routing APK bytes differ')
    return {'verified':True,'arch':report['arch'],'entries':{expected:report['artifact_sha256']}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--apk',type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.directory)
        if args.apk is not None: result['apk_verification'] = verify_apk(args.apk,result)
        print(json.dumps(result))
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile,RuntimeError) as error:
        parser.exit(1,f'Routing preview verification failed: {error}\n')
