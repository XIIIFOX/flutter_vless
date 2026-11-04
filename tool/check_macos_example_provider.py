#!/usr/bin/env python3
"""Read-only macOS example/provider identity check; never starts or repairs VPN.

The build receipt must contain ``success: true``, ``app_path`` and the signed
``provider_sha256``. Optional launch observations are a JSON list of records
with ``bundle_id``, ``provider_path`` and ``provider_sha256``. The caller must
obtain these observations from the actual launch, not from registration alone.
This JSON is trusted caller input, not image evidence collected by this tool;
copying the expected path/hash into it does not prove that the image ran.
Without launch evidence the result is unqualified, even for a correct build.

Alternatively, --log-start/--log-end inspect at most five minutes of unified
logs for the specific launchd path-conflict failure. A requested launch path
does not prove which image ran; path-only logs cannot produce a green result.
Only bundle/identity metadata is reported, never unified log message bodies.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys

MAX_INPUT = 4 * 1024 * 1024
DEFAULT_BUNDLE_ID = 'dev.tfox.flutterXrayExample'


class InspectionError(ValueError):
    """A fixed diagnostic code, safe to include in a public report."""


def canonical(path):
    if not isinstance(path, (str, Path)) or not str(path) or '\x00' in str(path):
        raise InspectionError('invalid_path')
    value = Path(path).expanduser()
    if not value.is_absolute():
        raise InspectionError('absolute_path_required')
    try:
        return value.resolve()
    except (OSError, RuntimeError):
        raise InspectionError('path_resolution_failed') from None


def provider_path(path):
    """Accept a provider bundle or its executable, normalizing path aliases."""
    value = canonical(path)
    for part in (value, *value.parents):
        if part.suffix == '.appex':
            return part
    raise InspectionError('provider_bundle_path_required')


def read_document(path):
    path = Path(path)
    if path.stat().st_size > MAX_INPUT:
        raise InspectionError('input_too_large')
    return json.loads(path.read_bytes())


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def bundle_metadata(bundle):
    plist = bundle/'Contents/Info.plist'
    if plist.stat().st_size > MAX_INPUT:
        raise InspectionError('bundle_metadata_too_large')
    info = plistlib.loads(plist.read_bytes())
    if not isinstance(info, dict):
        raise InspectionError('invalid_bundle_metadata')
    executable = info.get('CFBundleExecutable')
    if not isinstance(executable, str) or executable in ('', '.', '..') \
            or '/' in executable or '\\' in executable:
        raise InspectionError('invalid_bundle_executable')
    binary = canonical(bundle/'Contents/MacOS'/executable)
    try:
        binary.relative_to(bundle)
    except ValueError:
        raise InspectionError('bundle_executable_escaped') from None
    if not binary.is_file():
        raise InspectionError('bundle_executable_missing')
    return {'bundle_id': info.get('CFBundleIdentifier'),
            'version': info.get('CFBundleShortVersionString'),
            'build': str(info.get('CFBundleVersion', '')),
            'binary': binary}


def parse_registrations(text, bundle_id):
    """Parse only the requested provider; malformed own entries fail closed."""
    result = {}
    # Selection markers may be adjacent to the identifier. Recognize the own
    # entry before strict parsing so a marked stale duplicate cannot vanish.
    own = re.compile(r'^\s*(?:[+!\-=]\s*)*' + re.escape(bundle_id) + r'\(')
    pattern = re.compile(r'^\s*[+!\-]?\s*' + re.escape(bundle_id)
                         + r'\(([^)]+)\)\s+([0-9A-Fa-f-]{36})\s+.*?\s(/.+\.appex)\s*$')
    for line in text.splitlines():
        if not own.search(line):
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise InspectionError('own_registration_unreadable')
        version, identity, path = match.groups()
        path = str(provider_path(path))
        previous = result.get(path)
        if previous and previous['version'] != version:
            raise InspectionError('conflicting_registration_versions')
        result[path] = {'bundle_id': bundle_id, 'version': version,
                        'uuid': identity, 'provider_path': path}
    return sorted(result.values(), key=lambda item: item['provider_path'])


def observations_from_logs(records, bundle_id):
    """Extract actual reused-service paths; requested overlays are insufficient."""
    if not isinstance(records, list):
        raise InspectionError('log_records_must_be_list')
    pattern = re.compile(r'Attempt to re-bootstrap service from different path, will use existing: '
                         r'service = ' + re.escape(bundle_id)
                         + r', existing = (.+?\.appex), conflicting = (.+?\.appex)(?:$|\s)')
    result = []
    for record in records:
        if not isinstance(record, dict):
            raise InspectionError('invalid_log_record')
        message = record.get('eventMessage', '')
        if not isinstance(message, str):
            continue
        match = pattern.search(message)
        if match:
            result.append({'bundle_id': bundle_id, 'provider_path': match[1],
                           'source': 'launchd_existing_service_path'})
    return result


def log_window(start, end):
    try:
        first, last = (datetime.fromisoformat(value) for value in (start, end))
        duration = (last - first).total_seconds()
    except (ValueError, TypeError):
        raise InspectionError('invalid_log_window') from None
    if first.tzinfo is not None or last.tzinfo is not None:
        raise InspectionError('local_log_time_required')
    if not 0 < duration <= 300:
        raise InspectionError('log_window_must_be_one_to_300_seconds')
    return [first.strftime('%Y-%m-%d %H:%M:%S'), last.strftime('%Y-%m-%d %H:%M:%S')]


def run_readonly(arguments):
    """All callers supply fixed read-only commands; no shell or raw error output."""
    result = subprocess.run(arguments, capture_output=True, timeout=20)
    if result.returncode != 0:
        raise InspectionError('inspection_command_failed')
    if len(result.stdout) > MAX_INPUT:
        raise InspectionError('inspection_output_too_large')
    return result.stdout.decode('utf-8', errors='strict')


def inspect(receipt, registration_text, observations, *, bundle_id=DEFAULT_BUNDLE_ID,
            version='1.1.7', verify_signature=None):
    """Check build, registrations and supplied launch identity independently."""
    report = {'success': False, 'status': 'unqualified', 'scope': 'provider_identity_only',
              'failures': [], 'unqualified': [], 'registrations': [], 'observations': [],
              'launch_evidence_policy': 'Caller-supplied image claims are trusted input, not collected image attestation.',
              'VPN_started': False, 'registry_mutated': False}
    fail, missing = report['failures'], report['unqualified']
    try:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]+', bundle_id):
            raise InspectionError('invalid_bundle_identifier')
        if not isinstance(receipt, dict) or receipt.get('success') is not True:
            raise InspectionError('successful_build_receipt_required')
        expected_hash = receipt.get('provider_sha256')
        if not isinstance(expected_hash, str) or not re.fullmatch('[0-9a-f]{64}', expected_hash):
            missing.append('signed_provider_hash_missing_from_build_receipt')
            expected_hash = None
        app = canonical(receipt.get('app_path'))
        provider = canonical(app/'Contents/PlugIns/XrayTunnel.appex')
        try:
            provider.relative_to(app)
        except ValueError:
            raise InspectionError('provider_escaped_app_bundle') from None
        app_info, provider_info = bundle_metadata(app), bundle_metadata(provider)
        provider_id = bundle_id + '.XrayTunnel'
        if app_info['bundle_id'] != bundle_id or provider_info['bundle_id'] != provider_id:
            fail.append('bundle_identifier_mismatch')
        if app_info['version'] != version or provider_info['version'] != version:
            fail.append('bundle_version_mismatch')
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', app_info['build']) \
                or app_info['build'] != provider_info['build']:
            fail.append('app_provider_build_number_mismatch')
        if receipt.get('build_number') is not None and str(receipt['build_number']) != app_info['build']:
            fail.append('build_receipt_number_mismatch')
        actual_hash = digest(provider_info['binary'])
        if expected_hash and expected_hash != actual_hash:
            fail.append('signed_provider_hash_mismatch')
        if verify_signature is None:
            missing.append('code_signature_not_verified')
        elif not all(verify_signature(path) for path in (app, provider)):
            fail.append('code_signature_invalid')
        report['expected'] = {'app_path': str(app), 'provider_path': str(provider),
                              'bundle_id': provider_id, 'version': version,
                              'build': app_info['build'], 'provider_sha256': expected_hash}
        registrations = parse_registrations(registration_text, provider_id)
        report['registrations'] = registrations
        report['duplicate_version_tie'] = len(registrations) > 1 and len({r['version'] for r in registrations}) < len(registrations)
        if not registrations:
            missing.append('own_provider_not_registered')
        elif len(registrations) > 1:
            fail.append('multiple_registered_provider_paths')
        elif registrations[0]['provider_path'] != str(provider):
            fail.append('registered_provider_path_mismatch')
        elif registrations[0]['version'] != version:
            fail.append('registered_provider_version_mismatch')
        if observations is None:
            observations = []
        if not isinstance(observations, list):
            raise InspectionError('launch_observations_must_be_list')
        for item in observations:
            if not isinstance(item, dict):
                raise InspectionError('invalid_launch_observation')
            if item.get('bundle_id') != provider_id:
                continue
            actual_path = str(provider_path(item.get('provider_path')))
            actual_digest = item.get('provider_sha256')
            report['observations'].append({'provider_path': actual_path,
                                            'provider_sha256': actual_digest if isinstance(actual_digest, str) and re.fullmatch('[0-9a-f]{64}', actual_digest) else None})
            if actual_path != str(provider):
                fail.append('launched_provider_path_mismatch')
            if not isinstance(actual_digest, str) or re.fullmatch('[0-9a-f]{64}', actual_digest) is None:
                missing.append('launched_provider_hash_unobserved')
            elif expected_hash is not None and actual_digest != expected_hash:
                fail.append('launched_provider_hash_mismatch')
        if not report['observations']:
            missing.append('actual_provider_launch_unobserved')
    except InspectionError as error:
        fail.append(str(error))
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        fail.append('inspection_input_unreadable')
    report['failures'] = sorted(set(fail))
    report['unqualified'] = sorted(set(missing))
    report['status'] = 'failed' if fail else 'unqualified' if missing else 'qualified'
    report['success'] = report['status'] == 'qualified'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--bundle-id', default=DEFAULT_BUNDLE_ID)
    parser.add_argument('--version', default='1.1.7')
    parser.add_argument('--observations', type=Path)
    parser.add_argument('--log-start', help='Local macOS time: YYYY-MM-DD HH:MM:SS')
    parser.add_argument('--log-end', help='Local macOS time, at most 300 seconds after start')
    args = parser.parse_args(argv)
    try:
        if sys.platform != 'darwin':
            raise InspectionError('macOS_required')
        if (args.log_start is None) != (args.log_end is None):
            raise InspectionError('both_log_window_bounds_required')
        if args.observations and args.log_start:
            raise InspectionError('choose_one_observation_source')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]+', args.bundle_id):
            raise InspectionError('invalid_bundle_identifier')
        observations = read_document(args.observations) if args.observations else []
        if args.log_start:
            first, last = log_window(args.log_start, args.log_end)
            logs = json.loads(run_readonly(['log', 'show', '--style', 'json', '--start', first, '--end', last,
                             '--predicate', 'eventMessage CONTAINS "' + args.bundle_id + '.XrayTunnel"']))
            observations = observations_from_logs(logs, args.bundle_id + '.XrayTunnel')
        registrations = run_readonly(['pluginkit', '-m', '-A', '-D', '-v', '-i', args.bundle_id + '.XrayTunnel'])
        def signature(path):
            run_readonly(['codesign', '--verify', '--deep', '--strict', str(path)])
            return True
        result = inspect(read_document(args.receipt), registrations, observations,
                         bundle_id=args.bundle_id, version=args.version, verify_signature=signature)
    except InspectionError as error:
        result = {'success': False, 'status': 'unqualified', 'scope': 'provider_identity_only',
                  'failures': [], 'unqualified': [str(error)], 'VPN_started': False, 'registry_mutated': False}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        result = {'success': False, 'status': 'unqualified', 'scope': 'provider_identity_only',
                  'failures': [], 'unqualified': ['inspection_command_or_input_unavailable'],
                  'VPN_started': False, 'registry_mutated': False}
    print(json.dumps(result, indent=2))
    return 0 if result['success'] else 1 if result['status'] == 'failed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
