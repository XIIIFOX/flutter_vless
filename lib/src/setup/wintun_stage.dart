import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:path/path.dart' as p;

import 'common.dart';

enum WindowsWintunResult { absent, present, staged }

typedef WindowsWintunCommand = Future<WindowsWintunResult> Function(
  String action,
  File dll,
);

class WindowsWintunStaging {
  const WindowsWintunStaging(this.present, this._dll, this._run);

  final bool present;
  final File _dll;
  final WindowsWintunCommand _run;

  /// Apply after the project has committed its verified runtime files.
  /// Returns whether this call staged the driver.
  Future<bool> stage() async =>
      !present && await _run('stage', _dll) == WindowsWintunResult.staged;
}

Future<WindowsWintunResult> runWindowsWintunCommand(
  String action,
  File dll, {
  void Function(Map<String, int>)? recordTiming,
}) async {
  if (!Platform.isWindows) {
    throw const SetupException('--stage-wintun must run on Windows.');
  }
  final systemRoot = Platform.environment['SystemRoot'];
  final script = await Isolate.resolvePackageUri(
    Uri.parse('package:flutter_vless/src/setup/wintun_stage.ps1'),
  );
  if (systemRoot == null || !p.isAbsolute(systemRoot) || script == null) {
    throw const SetupException('Windows Wintun setup helper is unavailable.');
  }
  final source = await File.fromUri(script).readAsString();
  final encoded = ByteData(source.length * 2);
  for (var i = 0; i < source.length; i++) {
    encoded.setUint16(i * 2, source.codeUnitAt(i), Endian.little);
  }
  final ProcessResult result;
  try {
    result = await Process.run(
      p.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0',
          'powershell.exe'),
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        base64Encode(encoded.buffer.asUint8List()),
      ],
      environment: {
        'FLUTTER_VLESS_WINTUN_STAGE_ACTION': action,
        'FLUTTER_VLESS_WINTUN_STAGE_DLL': dll.path,
        'FLUTTER_VLESS_WINTUN_STAGE_TIMING': recordTiming == null ? '0' : '1',
      },
    );
  } on ProcessException {
    throw const SetupException(
        'Could not run the Windows Wintun setup helper.');
  }
  final lines = const LineSplitter().convert((result.stdout as String).trim());
  final status = lines.isEmpty ? '' : lines.first;
  if (recordTiming != null && result.exitCode == 0 && lines.length == 2) {
    final phases = jsonDecode(lines[1]) as Map<String, dynamic>;
    recordTiming(
        {for (final entry in phases.entries) entry.key: entry.value as int});
  }
  if (result.exitCode == 0) {
    if (status == 'present') return WindowsWintunResult.present;
    if (action == 'inspect' && status == 'absent') {
      return WindowsWintunResult.absent;
    }
    if (action == 'stage' && status == 'staged') {
      return WindowsWintunResult.staged;
    }
  }
  final phase = RegExp(r'^failed_([a-z_]{1,24})$').firstMatch(status)?.group(1);
  throw SetupException(switch (status) {
    'elevation_required' =>
      'Open an administrator terminal to use --stage-wintun.',
    'blocked' =>
      'Windows already has another Wintun driver or device. Run setup without --stage-wintun.',
    _ =>
      'Windows could not verify Wintun driver staging ($action${phase == null ? '' : ', $phase'}, exit ${result.exitCode}).',
  });
}
