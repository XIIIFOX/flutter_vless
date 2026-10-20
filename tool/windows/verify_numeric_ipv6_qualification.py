"""Strict, file-only qualifier for the dedicated numeric IPv6 TCP proof."""
import argparse
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import sys

class EvidenceError(ValueError):
    """Only closed error codes escape; no native text or packet bodies."""

def require(value, code):
    if not value:
        raise EvidenceError(code)

def fields(value, names, code):
    require(type(value) is dict and set(value) == set(names.split()), code)

def integer(value, minimum=0, maximum=None):
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)

def yes(value):
    return value is True

def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None

CASES = (
    ('wrong_address', 'fd00:85:2::3', 18443, 6),
    ('wrong_port', 'fd00:85:2::2', 18444, 6),
    ('udp', 'fd00:85:2::2', 18443, 17),
    ('wrong_image', 'fd00:85:2::2', 18443, 6),
)

def private_core_image(image, system_root):
    if type(image) is not str or type(system_root) is not str:
        return False
    drive, _ = ntpath.splitdrive(system_root)
    if len(drive) != 2 or drive[1] != ':' or not ntpath.isabs(system_root) or not ntpath.isabs(image):
        return False
    if any(part in ('.', '..') for part in image.replace('\\', '/').split('/')):
        return False
    directory, binary = ntpath.split(ntpath.normpath(image))
    parent, protected = ntpath.split(directory)
    return (ntpath.normcase(parent) == ntpath.normcase(ntpath.join(ntpath.normpath(system_root), 'Temp'))
            and re.fullmatch(r'flutter-vless-protected-[0-9a-f]{64}', protected) is not None
            and ntpath.normcase(binary) == 'xray.exe')


def verify_runtime(document, expected, log):
    require(type(log) is str and log.endswith('\n') and '\0' not in log, 'markers')
    require(not re.search(r'\b(?:SKIP|FAIL|NOT_REACHED)\b', log), 'incomplete')
    for name, count in (('WINDOWS_NUMERIC_IPV6_OUTER_TCP_PASS', 1), ('WINDOWS_NUMERIC_IPV6_SCOPE_DENY_PASS', 4)):
        require(re.findall(r'(?m)^' + re.escape(name) + r'=([^\r\n]*)\r?$', log) == [str(count)], 'markers')
    fields(document, 'version binary_variant run_id head source_sha256 build_receipt_sha256 nonce peer_nonce scope positive denied cleanup passed skipped', 'document')
    require(type(document['version']) is int and document['version'] == 1, 'document')
    require(document['passed'] is True and document['skipped'] is False, 'incomplete')
    require(expected['binary_variant'] in ('official', 'routing') and document['binary_variant'] == expected['binary_variant'], 'binary')
    require(document['run_id'] == expected['run_id'] and type(document['run_id']) is str and re.fullmatch(r'[0-9]+', document['run_id']), 'identity')
    require(document['head'] == expected['head'] and type(document['head']) is str and re.fullmatch(r'[0-9a-f]{40}', document['head']), 'identity')
    sources = document['source_sha256']
    require(type(sources) is dict and sources == expected['source_sha256'] and bool(sources), 'sources')
    for name, value in sources.items():
        require(type(name) is str and name and not name.startswith('/') and '\\' not in name and not any(p in ('', '.', '..') for p in name.split('/')) and digest(value), 'sources')
    require(digest(document['build_receipt_sha256']) and document['build_receipt_sha256'] == expected['build_receipt_sha256'], 'build')
    nonce = document['nonce']
    require(type(nonce) is str and re.fullmatch(r'[0-9a-f]{32}', nonce) and document['peer_nonce'] == nonce, 'nonce')
    scope = document['scope']
    fields(scope, 'remote port protocol LUID CorePID controllerPID ServicePID CoreParentPID Core_image Core_image_sha256 owned_filter_ids', 'scope')
    require(scope['remote'] == 'fd00:85:2::2' and type(scope['port']) is int and scope['port'] == 18443 and type(scope['protocol']) is int and scope['protocol'] == 6, 'scope')
    require(integer(scope['LUID'], 1) and integer(scope['CorePID'], 1) and integer(scope['controllerPID'], 1) and scope['CorePID'] != scope['controllerPID'], 'scope')
    require(integer(scope['ServicePID'], 1) and type(scope['CoreParentPID']) is int and scope['CoreParentPID'] == scope['ServicePID'] and len({scope['CorePID'], scope['ServicePID'], scope['controllerPID']}) == 3, 'scope')
    require(private_core_image(scope['Core_image'], expected['SystemRoot']), 'scope')
    require(digest(scope['Core_image_sha256']) and scope['Core_image_sha256'] == expected['Core_image_sha256'], 'scope')
    owned = scope['owned_filter_ids']
    require(type(owned) is list and 0 < len(owned) <= 512 and all(integer(v, 1) for v in owned) and len(owned) == len(set(owned)), 'scope')
    positive = document['positive']
    fields(positive, 'source response_exact peer controlled_packets tcp_owner', 'peer')
    require(positive['source'] == '10.0.85.2' and yes(positive['response_exact']), 'peer')
    peer = positive['peer']
    fields(peer, 'syn_count authentication_count connect_count challenge_count complete error client_port', 'peer')
    require(all(type(peer[k]) is int and peer[k] == 1 for k in ('syn_count', 'authentication_count', 'connect_count', 'challenge_count')), 'peer')
    require(yes(peer['complete']) and type(peer['error']) is int and peer['error'] == 0 and integer(peer['client_port'], 1, 65535), 'peer')
    tcp = positive['tcp_owner']
    fields(tcp, 'PID local_address local_port remote_address remote_port', 'tcp_owner')
    require(type(tcp['PID']) is int and tcp['PID'] == scope['CorePID'] and tcp['local_address'] == 'fd00:85:2::1' and type(tcp['local_port']) is int and tcp['local_port'] == peer['client_port'] and tcp['remote_address'] == scope['remote'] and type(tcp['remote_port']) is int and tcp['remote_port'] == scope['port'], 'tcp_owner')
    packets = positive['controlled_packets']
    fields(packets, 'baseline protected', 'packets')
    require(all(type(packets[k]) is list and len(packets[k]) == 4 for k in ('baseline', 'protected')), 'packets')
    denied = document['denied']
    require(type(denied) is list and len(denied) == 4, 'denials')
    for index, (case, remote, port, protocol) in enumerate(CASES):
        denial = denied[index]
        fields(denial, 'case sender_attempted CorePID SenderPID protocol remote port observer_baseline_positive matching_packets_after kernel', 'denials')
        require(denial['case'] == case and denial['remote'] == remote and type(denial['port']) is int and denial['port'] == port and type(denial['protocol']) is int and denial['protocol'] == protocol, 'denials')
        require(yes(denial['sender_attempted']) and yes(denial['observer_baseline_positive']) and type(denial['matching_packets_after']) is int and denial['matching_packets_after'] == 0, 'denials')
        sender = scope['controllerPID'] if case == 'wrong_image' else scope['CorePID']
        require(type(denial['SenderPID']) is int and denial['SenderPID'] == sender, 'denials')
        require(denial['CorePID'] is None if case == 'wrong_image' else type(denial['CorePID']) is int and denial['CorePID'] == scope['CorePID'], 'denials')
        kernel = denial['kernel']
        fields(kernel, 'kind ProcessID SourcePort FilterRTID RecordId AfterRecordId', 'denials')
        require(type(kernel['ProcessID']) is int and kernel['ProcessID'] == sender and integer(kernel['SourcePort'], 1, 65535), 'denials')
        if case == 'wrong_image':
            require(kernel['kind'] == 'WSAEACCES' and kernel['FilterRTID'] is None and kernel['RecordId'] is None and kernel['AfterRecordId'] is None, 'denials')
        else:
            require(kernel['kind'] == 'owned_filter_event_5157' and integer(kernel['FilterRTID'], 1) and kernel['FilterRTID'] in owned and integer(kernel['AfterRecordId']) and integer(kernel['RecordId'], 1) and kernel['RecordId'] > kernel['AfterRecordId'], 'denials')
        for kind in ('baseline', 'protected'):
            row = packets[kind][index]
            fields(row, 'case remote port protocol sourcePort senderPID syn_packets udp_packets', 'packets')
            require(row['case'] == case and row['remote'] == remote and type(row['port']) is int and row['port'] == port and type(row['protocol']) is int and row['protocol'] == protocol, 'packets')
            require(integer(row['sourcePort'], 1, 65535) and integer(row['senderPID'], 1) and integer(row['syn_packets']) and integer(row['udp_packets']), 'packets')
            if kind == 'baseline':
                require(row['senderPID'] == scope['controllerPID'] and row['udp_packets' if protocol == 17 else 'syn_packets'] >= 1 and row['syn_packets' if protocol == 17 else 'udp_packets'] == 0, 'packets')
            else:
                require(row['senderPID'] == sender and row['sourcePort'] == kernel['SourcePort'] and row['syn_packets'] == 0 and row['udp_packets'] == 0 and row['sourcePort'] != peer['client_port'], 'packets')
    cleanup = document['cleanup']
    fields(cleanup, 'service_exit0 policy_filters capture_routes owned_adapter_absent owned_helpers_remaining', 'cleanup')
    require(yes(cleanup['service_exit0']) and yes(cleanup['owned_adapter_absent']), 'cleanup')
    require(all(type(cleanup[k]) is int and cleanup[k] == 0 for k in ('policy_filters', 'capture_routes', 'owned_helpers_remaining')), 'cleanup')
    return True

# Relevant candidate/probe inputs only; this is not a full transitive ABI claim.
# Runtime producer and verifier share this exact set, never a receipt-chosen subset.
MANDATORY_SOURCES = (
    'tool/windows/runtime_probe.cpp',
    'tool/windows/runtime_smoke.py',
    'tool/windows/ipv6_tcp_challenge_peer.h',
    'tool/windows/verify_numeric_ipv6_qualification.py',
    'tool/test_windows_numeric_ipv6_callers.py',
    'tool/windows/build_native_tests.cmd',
) + tuple('packages/flutter_vless_windows/windows/' + name for name in (
    'vpn_service.cpp', 'vpn_service.h',
    'traffic_protection.cpp', 'traffic_protection.h',
    'ipv6_tcp_scope.h', 'windows_underlay.h', 'xray_config.h',
    'vpn_worker_candidate.h', 'wfp_compat.h',
    'native_runtime.cpp', 'native_runtime.h',
    'packet_path_probe.cpp', 'packet_path_probe.h',
    'protected_runtime.cpp', 'protected_runtime.h',
    'native_routing_spec.cpp', 'native_routing_spec.h',
))
JSON_LIMIT = 1024 * 1024
LOG_LIMIT = 8 * 1024 * 1024
SOURCE_LIMIT = 4 * 1024 * 1024
BINARY_LIMIT = 128 * 1024 * 1024


def identity(run_id, head):
    require(type(run_id) is str and re.fullmatch(r'[1-9][0-9]{0,23}', run_id), 'identity')
    require(type(head) is str and re.fullmatch(r'[0-9a-f]{40}', head), 'identity')


def regular(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        require(not component.is_symlink() and not getattr(component, 'is_junction', lambda: False)(), 'file')
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode), 'file')
    return path


def read_bounded(path, limit):
    path = regular(path)
    require(path.stat().st_size <= limit, 'size')
    with path.open('rb') as handle:
        content = handle.read(limit + 1)
    require(len(content) <= limit, 'size')
    return content


def file_sha256(path, limit):
    path = regular(path)
    require(path.stat().st_size <= limit, 'size')
    value = hashlib.sha256()
    length = 0
    with path.open('rb') as handle:
        while block := handle.read(1024 * 1024):
            length += len(block)
            require(length <= limit, 'size')
            value.update(block)
    require(length > 0, 'file')
    return value.hexdigest()


def source_vector(root):
    root = Path(root).absolute()
    return {name: file_sha256(root / name, SOURCE_LIMIT) for name in MANDATORY_SOURCES}


def unique_object(pairs):
    output = {}
    for key, value in pairs:
        require(key not in output, 'json')
        output[key] = value
    return output


def load_json(path):
    try:
        return json.loads(read_bounded(path, JSON_LIMIT).decode('utf-8'), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError('json')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise EvidenceError('json') from error


def record_build(root, directory, run_id, head):
    # Invoke only after the existing strict CMD build succeeds. This records
    # observed bytes; it does not itself execute or assert a compiler result.
    identity(run_id, head)
    directory = Path(directory).absolute()
    require(directory.is_dir() and directory.resolve() == directory, 'file')
    sources = source_vector(root)
    probe = file_sha256(directory / 'runtime_probe.exe', BINARY_LIMIT)
    document = {'version': 1, 'run_id': run_id, 'head': head,
                'source_sha256': sources, 'runtime_probe_sha256': probe,
                'core_binaries_sha256': {
                    'official': file_sha256(directory / 'xray-official.exe', BINARY_LIMIT),
                    'routing': file_sha256(directory / 'xray.exe', BINARY_LIMIT)}}
    require(document['core_binaries_sha256']['official'] != document['core_binaries_sha256']['routing'], 'binary')
    path = directory / 'numeric-ipv6-build-results.json'
    content = (json.dumps(document, sort_keys=True, indent=2) + '\n').encode('utf-8')
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise EvidenceError('exists') from error
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(content)
    return path


def verify_files(root, directory, run_id, head, *, variant='routing', log_name='native-routing-runtime.log', system_root=None):
    identity(run_id, head)
    require(variant in ('official', 'routing'), 'binary')
    directory = Path(directory).absolute()
    require(directory.is_dir() and directory.resolve() == directory, 'file')
    require(log_name in ('native-routing-runtime.log', 'numeric-ipv6-runtime.log'), 'file')
    sources = source_vector(root)
    receipt = directory / 'numeric-ipv6-build-results.json'
    build = load_json(receipt)
    fields(build, 'version run_id head source_sha256 runtime_probe_sha256 core_binaries_sha256', 'build')
    require(type(build['version']) is int and build['version'] == 1, 'build')
    require(build['run_id'] == run_id and build['head'] == head, 'build')
    require(type(build['source_sha256']) is dict and build['source_sha256'] == sources, 'sources')
    require(build['runtime_probe_sha256'] == file_sha256(directory / 'runtime_probe.exe', BINARY_LIMIT), 'build')
    core_path = regular(directory / 'xray.exe')
    core_hash = file_sha256(core_path, BINARY_LIMIT)
    binaries = build['core_binaries_sha256']
    fields(binaries, 'official routing', 'binary')
    require(all(digest(v) for v in binaries.values()) and binaries['official'] != binaries['routing'] and core_hash == binaries[variant], 'binary')
    expected = {'run_id': run_id, 'head': head, 'source_sha256': sources,
                'build_receipt_sha256': file_sha256(receipt, JSON_LIMIT),
                'SystemRoot': system_root if system_root is not None else os.environ.get('SystemRoot'),
                'Core_image_sha256': core_hash, 'binary_variant': variant}
    try:
        log = read_bounded(directory / log_name, LOG_LIMIT).decode('utf-8')
    except UnicodeError as error:
        raise EvidenceError('log') from error
    return verify_runtime(load_json(directory / 'numeric-ipv6-results.json'), expected, log)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--record-build', action='store_true')
    parser.add_argument('--log', choices=('native-routing-runtime.log', 'numeric-ipv6-runtime.log'), default='native-routing-runtime.log')
    parser.add_argument('--variant', choices=('official', 'routing'))
    args = parser.parse_args(argv)
    try:
        run_id, head = os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_SHA')
        identity(run_id, head)
        if args.record_build:
            require(args.variant is None, 'arguments')
            record_build(args.root, args.directory, run_id, head)
            print('WINDOWS_NUMERIC_IPV6_BUILD_RECORDED=1')
        else:
            require(args.variant in ('official', 'routing'), 'arguments')
            verify_files(args.root, args.directory, run_id, head, log_name=args.log, variant=args.variant)
            print('WINDOWS_NUMERIC_IPV6_QUALIFIED=' + args.variant)
        return 0
    except (EvidenceError, OSError) as error:
        # Native errors, paths, packet bodies and arbitrary JSON never escape.
        print('WINDOWS_NUMERIC_IPV6_QUALIFICATION_FAILED=' + (str(error) if isinstance(error, EvidenceError) else 'file'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
