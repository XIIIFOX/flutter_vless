#!/usr/bin/env python3
"""Package a source-bound unpublished AAR; never install or execute binaries."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import re
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import build_android_runtime_preview as builder
from build_android_runtime_preview import digest, tree, safe_relative, git_head
from verify_android_dns_preview import elf_alignment

ROOT = Path(__file__).resolve().parents[1]
PACKAGING_INPUTS = ('.github/workflows/android-runtime-preview.yml', 'tool/package_android_runtime_preview.py',
                    'tool/test_android_runtime_preview.py', 'tool/verify_android_dns_preview.py',
                    'tool/build_android_dns_preview.py')


def git_blob(repository, head, name):
    return builder.subprocess.check_output(['git', 'show', head + ':' + name], cwd=repository, timeout=20)


def git_bindings(repository, head, bindings):
    if not isinstance(bindings, dict) or not bindings:
        raise ValueError('Source provenance is missing')
    for name, value in bindings.items():
        path = repository / safe_relative(name)
        if not re.fullmatch('[0-9a-f]{64}', value) or path.is_symlink() \
                or digest(path) != value or hashlib.sha256(git_blob(repository, head, name)).hexdigest() != value:
            raise ValueError('Exact Git source provenance differs: ' + name)


def validate(preview, head, repository=ROOT):
    version = builder.preview_version(head)
    if git_head(repository) != head:
        raise ValueError('Checkout head differs')
    if preview.is_symlink() or (repository / 'build').resolve() not in preview.resolve().parents:
        raise ValueError('Preview must be an owned real build directory')
    tree(preview)  # Refuse any symlink before following receipt paths.
    result = json.loads((preview / 'preview.json').read_text())
    if result.get('schema') != 1 or result.get('head') != head or result.get('version') != version \
            or any(result.get(k) is not True for k in ('success', 'source_unchanged', 'copied_source_unchanged',
                'module_cache_source_unchanged', 'staged_runtime_unchanged', 'fresh_outputs_unchanged')) \
            or any(result.get(k) is not False for k in ('runtime_executed', 'installed', 'published')):
        raise ValueError('Preview producer evidence is incomplete')
    sources = result['source_sha256']
    ordinary_names = set(builder.ordinary_inputs(repository))
    if set(sources) != set(builder.WRAPPER_INPUTS) | ordinary_names:
        raise ValueError('Required producer sources are missing')
    git_bindings(repository, head, sources)
    packaging = {name: digest(repository / name) for name in PACKAGING_INPUTS}
    git_bindings(repository, head, packaging)
    receipt_name = safe_relative(result['core_build_receipt'])
    if receipt_name.parent.as_posix() != 'fresh-jni':
        raise ValueError('Ordinary Core receipt path differs')
    receipt_path = preview / receipt_name
    if digest(receipt_path) != result['core_build_receipt_sha256']:
        raise ValueError('Ordinary Core receipt changed')
    receipt = json.loads(receipt_path.read_text())
    if any(receipt.get(k) is not True for k in ('success', 'source_unchanged', 'module_cache_source_unchanged',
                                               'copies_unchanged', 'classic_dns_lifetime_applied', 'h3_lifetime_applied', 'darwin_interface_binding_source_applied')) \
            or type(receipt.get('routing_capability_expected')) is not int or receipt['routing_capability_expected'] != 0 \
            or receipt.get('lifetime_patch_scope') != ['classic_dns', 'xhttp_h3_dial'] \
            or receipt.get('selected_abis') != list(builder.ABIS) \
            or any(receipt.get(k) is not False for k in ('runtime_executed', 'published')):
        raise ValueError('Ordinary lifetime proof differs')
    if set(receipt['source_sha256']) != ordinary_names \
            or any(sources.get(name) != value for name, value in receipt['source_sha256'].items()) \
            or receipt['h3_lifetime_patch_sha256'] != sources[builder.H3] \
            or receipt.get('darwin_interface_binding_patch_sha256') != sources['third_party/xray-native-dns/darwin_interface_bind_patch.py']:
        raise ValueError('Ordinary lifetime source provenance differs')
    pin = json.loads((repository / 'third_party/xray-vpn-routing/pin-manifest.json').read_text())
    if any(receipt.get(key) != pin[field] for key, field in [('core_module', 'module'), ('core', 'module_version'),
                                                           ('core_sum', 'module_sum'), ('core_commit', 'core_commit')]):
        raise ValueError('Core pin differs')
    copied = builder.core_copy(receipt_name.name, repository)
    if tree(copied) != receipt['core_copy_sha256']:
        raise ValueError('Ordinary copied source changed')
    cache = Path(receipt['core_source'])
    if not cache.is_absolute() or preview.resolve() == cache.resolve() or preview.resolve() in cache.resolve().parents \
            or tree(cache) != receipt['module_cache_before_sha256']:
        raise ValueError('Original source cache changed')
    copied_h3 = receipt['core_copy_sha256'][builder.DIALER]
    if result['copied_h3_sha256'] != copied_h3:
        raise ValueError('Copied H3 provenance differs')
    pins = json.loads((repository / builder.RUNTIME / 'runtime-inputs.sha256.json').read_text())
    pinned = {name: value for name, value in pins.items() if not name.endswith('/libxray.so')}
    if result['pinned_HEV_geodata_sha256'] != pinned or len(pinned) != 6:
        raise ValueError('Pinned HEV/geodata evidence differs')
    staged = preview / 'project/src/main'
    if tree(staged) != result['staged_runtime_sha256']:
        raise ValueError('Staged runtime source changed')
    for name in builder.PROJECT_FILES:
        if digest(preview / 'project' / name) != sources[builder.RUNTIME + '/' + name]:
            raise ValueError('Isolated Gradle project source changed')
    for name, value in pinned.items():
        if digest(staged / safe_relative(name)) != value or digest(repository / builder.RUNTIME / 'src/main' / name) != value:
            raise ValueError('Pinned HEV/geodata changed')
    fresh = preview / 'fresh-jni'
    artifacts = receipt['artifacts_sha256']
    if set(artifacts) != {abi + '/libxray.so' for abi in builder.ABIS} \
            or set(tree(fresh)) != set(artifacts) | {receipt_name.name}:
        raise ValueError('All four fresh ABI outputs and one receipt required')
    for name, value in artifacts.items():
        if value == pins['jniLibs/' + name]:
            raise ValueError('Old Xray runtime cannot be relabelled')
        if digest(fresh / safe_relative(name)) != value or digest(staged / 'jniLibs' / name) != value:
            raise ValueError('Fresh Xray bytes differ')
    repo = preview / 'project/build/repo'
    maven = tree(repo)
    if maven != result['maven_files_sha256']:
        raise ValueError('Maven output changed')
    coordinates = f'dev/tfox/fluttervless/xray-android/{version}/xray-android-{version}'
    aar_name = coordinates + '.aar'
    if result['aar'] != 'project/build/repo/' + aar_name:
        raise ValueError('Candidate Maven version or AAR path differs')
    for name in maven:
        parts = safe_relative(name).parts
        if parts[:4] != ('dev', 'tfox', 'fluttervless', 'xray-android') or len(parts) < 5 \
                or (parts[4] != version and not (len(parts) == 5 and parts[4].startswith('maven-metadata.xml'))):
            raise ValueError('Unexpected Maven artifact coordinates')
    pom = ET.fromstring((repo / (coordinates + '.pom')).read_bytes())
    fields = {node.tag.rsplit('}', 1)[-1]: node.text for node in pom}
    if any(fields.get(k) != v for k, v in [('groupId', 'dev.tfox.fluttervless'), ('artifactId', 'xray-android'), ('version', version)]):
        raise ValueError('Candidate Maven POM differs')
    aar = repo / aar_name
    if digest(aar) != result['aar_sha256']:
        raise ValueError('Candidate AAR hash differs')
    expected = {'jni/' + name: value for name, value in artifacts.items()}
    expected.update({name.replace('jniLibs/', 'jni/', 1): value for name, value in pinned.items()})
    alignments, members = {}, {}
    with tempfile.TemporaryDirectory(prefix='aar-static-', dir=preview.parent) as temporary, zipfile.ZipFile(aar) as archive:
        infos = archive.infolist()
        if len({item.filename for item in infos}) != len(infos) or sum(item.file_size for item in infos) > 512 * 1024 * 1024:
            raise ValueError('Duplicate or excessive AAR members')
        names = {item.filename for item in infos if not item.is_dir()}
        if {name for name in names if name.startswith(('jni/', 'assets/'))} != set(expected):
            raise ValueError('AAR runtime members differ')
        if 'AndroidManifest.xml' not in names:
            raise ValueError('AAR manifest missing')
        for item in infos:
            safe_relative(item.filename.rstrip('/'))
            if item.flag_bits & 1 or (item.external_attr >> 16) & 0o170000 not in (0, 0o040000, 0o100000):
                raise ValueError('AAR member is not a regular file/directory')
            if item.is_dir():
                continue
            if item.file_size > 256 * 1024 * 1024:
                raise ValueError('AAR member too large')
            value = hashlib.sha256()
            xray = item.filename.startswith('jni/') and item.filename.endswith('/libxray.so')
            output = Path(temporary) / item.filename.split('/')[1] if xray else None
            with archive.open(item) as source:
                if output is not None:
                    with output.open('xb') as destination:
                        for block in iter(lambda: source.read(1024 * 1024), b''):
                            value.update(block)
                            destination.write(block)
                else:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        value.update(block)
            members[item.filename] = value.hexdigest()
            if item.filename in expected and value.hexdigest() != expected[item.filename]:
                raise ValueError('AAR runtime bytes differ')
            if xray:
                abi = item.filename.split('/')[1]
                alignments[abi] = elf_alignment(output, abi)
    return {'selected_abis': list(builder.ABIS), 'version': version, 'aar_relative': aar_name,
            'aar_sha256': digest(aar), 'AAR_members_sha256': members, 'ELF_LOAD_alignments': alignments,
            'runtime_members_sha256': expected, 'maven_files_sha256': maven,
            'source_sha256': sources, 'packaging_source_sha256': packaging,
            'core_commit': pin['core_commit'], 'core_module': pin['module'],
            'core_version': pin['module_version'], 'core_sum': pin['module_sum'],
            'h3_lifetime_patch_sha256': sources[builder.H3], 'copied_h3_sha256': copied_h3,
            'producer_receipts_sha256': {'preview.json': digest(preview / 'preview.json'),
                                        'core-build-receipt.json': digest(receipt_path)}}


def package(preview, output, head, repository=ROOT):
    if output.exists() or output.is_symlink() or preview.resolve() == output.resolve() \
            or preview.resolve() in output.resolve().parents or (repository / 'build').resolve() not in output.resolve().parents \
            or any(p.is_symlink() for p in output.parents if p.exists()):
        raise ValueError('Artifact output must be new and outside preview inputs')
    checked = validate(preview, head, repository)
    result = json.loads((preview / 'preview.json').read_text())
    members = {'maven/' + name: value for name, value in checked['maven_files_sha256'].items()}
    members.update(checked['producer_receipts_sha256'])
    files = {name: preview / 'project/build/repo' / name.removeprefix('maven/') for name in members if name.startswith('maven/')}
    files.update({'preview.json': preview / 'preview.json', 'core-build-receipt.json': preview / result['core_build_receipt']})
    output.mkdir(parents=True)
    archive = output / 'android-runtime-preview.tar.gz'
    with archive.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode='w') as packed:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size, info.mode = files[name].stat().st_size, 0o644
            with files[name].open('rb') as content:
                packed.addfile(info, content)
    found = {}
    with tarfile.open(archive, 'r:gz') as packed:
        for item in packed:
            safe_relative(item.name)
            if not item.isfile() or item.name in found or item.name not in members:
                raise ValueError('Unexpected preview archive member')
            value = hashlib.sha256()
            with packed.extractfile(item) as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    value.update(block)
            found[item.name] = value.hexdigest()
    if found != members or validate(preview, head, repository) != checked:
        raise ValueError('Artifact/source changed during packaging')
    manifest = dict(checked, schema=1, success=True, head=head, platform='android',
                    archive=archive.name, archive_sha256=digest(archive), members_sha256=members,
                    lifetime_patch_scope=['classic_dns', 'xhttp_h3_dial'], routing_capability_expected=0,
                    runtime_executed=False, installed=False, published=False)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preview', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--head', required=True)
    args = parser.parse_args()
    try:
        result = package(args.preview, args.output, args.head)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, 'Unpublished Android runtime packaging failed: ' + str(error) + '\n')
    print('ANDROID_RUNTIME_PREVIEW_PACKAGED=' + result['archive_sha256'])


if __name__ == '__main__':
    main()
