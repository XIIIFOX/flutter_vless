import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/src/setup/common.dart';
import 'package:flutter_vless/src/setup/windows.dart';
import 'package:path/path.dart' as p;

const _cmake = r'''
cmake_minimum_required(VERSION 3.14)
project(runner LANGUAGES CXX)
install(TARGETS runner RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}" COMPONENT Runtime)
''';
const _fragment = 'windows/flutter_vless_runtime.cmake';
const _stage = 'windows/.flutter_vless/runtime/x64';

void main() {
  late Directory root;
  late int calls;

  File projectFile(String path) => File.fromUri(root.uri.resolve(path));

  void write(String path, List<int> bytes) => projectFile(path)
    ..parent.createSync(recursive: true)
    ..writeAsBytesSync(bytes);

  SetupPlan inspect(
    SetupMode mode, {
    String? source,
    String? arch,
  }) {
    final request = SetupRequest(
      root: root,
      platform: SetupPlatform.windows,
      mode: mode,
      runtimeDirectory: source,
      architecture: arch ?? 'x64',
    );
    final plan = SetupPlan(request);
    planWindows(
      request,
      plan,
      download: (uri, limit) async {
        calls++;
        return Uint8List.fromList([42]);
      },
    );
    return plan;
  }

  setUp(() {
    root = Directory.systemTemp.createTempSync('vless-windows-setup-');
    calls = 0;
    write('windows/CMakeLists.txt', _cmake.codeUnits);
    write('windows/.gitignore', 'flutter/ephemeral/\n'.codeUnits);
  });

  tearDown(() => root.deleteSync(recursive: true));

  test('read-only planning selects downloads by requested mode', () {
    final proxy = inspect(SetupMode.proxy);
    expect(proxy.pendingActions, hasLength(1));
    final vpn = inspect(SetupMode.vpn);
    expect(vpn.pendingActions, hasLength(4));
    expect(vpn.changedPaths, contains(p.normalize(_fragment)));
    expect(calls, 0);
    expect(projectFile('windows/CMakeLists.txt').readAsStringSync(), _cmake);
    expect(projectFile(_fragment).existsSync(), isFalse);
  });

  test('a digest mismatch leaves the application unchanged', () async {
    final plan = inspect(SetupMode.vpn);
    await expectLater(
      plan.apply(),
      throwsA(isA<SetupException>().having(
        (exception) => exception.message,
        'message',
        contains('SHA-256'),
      )),
    );
    expect(calls, 1);
    expect(projectFile('windows/CMakeLists.txt').readAsStringSync(), _cmake);
    expect(projectFile('windows/.gitignore').readAsStringSync(),
        'flutter/ephemeral/\n');
    expect(projectFile(_fragment).existsSync(), isFalse);
  });

  test('a supplied VPN runtime is staged and repeatable without downloads',
      () async {
    write('vendor/xray.exe', _pe());
    write('vendor/tun2socks.exe', _pe());
    write('vendor/wintun.dll', _pe(dll: true));
    write('vendor/geosite.dat', [1, 2, 3]);
    await inspect(SetupMode.vpn, source: 'vendor').apply();

    expect(projectFile('$_stage/geosite.dat').readAsBytesSync(), [1, 2, 3]);
    expect(projectFile('vendor/xray.exe').readAsBytesSync(), _pe());
    final fragment = projectFile(_fragment).readAsStringSync();
    expect(
        fragment,
        contains(
            r'DESTINATION "${CMAKE_INSTALL_PREFIX}/xray" COMPONENT Runtime'));
    expect(fragment, contains(r'${CMAKE_CURRENT_LIST_DIR}'));
    expect(fragment, contains('tun2socks.exe'));
    expect(fragment, contains('FLUTTER_TARGET_PLATFORM'));
    final repeat = inspect(SetupMode.vpn);
    expect(repeat.pendingActions, isEmpty);
    expect(repeat.changedPaths, isEmpty);
    expect(calls, 0);
  });

  test('proxy setup can reuse a local Core without VPN files', () async {
    write('windows/xray/xray.exe', _pe());
    await inspect(SetupMode.proxy).apply();
    expect(projectFile('$_stage/xray.exe').existsSync(), isTrue);
    expect(projectFile('$_stage/wintun.dll').existsSync(), isFalse);
    expect(
        projectFile(_fragment).readAsStringSync(), isNot(contains('wintun')));
    expect(inspect(SetupMode.proxy).changedPaths, isEmpty);
    expect(
      () => inspect(SetupMode.vpn),
      throwsA(isA<SetupException>().having(
        (exception) => exception.message,
        'message',
        contains('tun2socks.exe'),
      )),
    );
    expect(calls, 0);
  });

  test('does not replace a different staged custom Core', () async {
    write('vendor/xray.exe', _pe());
    await inspect(SetupMode.proxy, source: 'vendor').apply();
    final replacement = _pe()..[13] = 9;
    write('other/xray.exe', replacement);
    expect(
      () => inspect(SetupMode.proxy, source: 'other'),
      throwsA(isA<SetupException>()),
    );
    expect(projectFile('$_stage/xray.exe').readAsBytesSync(), _pe());
    expect(projectFile('other/xray.exe').readAsBytesSync(), replacement);
  });

  test('reports invalid architecture before staging files', () {
    write('vendor/xray.exe', _pe());
    expect(
      () => inspect(SetupMode.proxy, source: 'vendor', arch: 'arm64'),
      throwsA(isA<SetupException>().having(
        (exception) => exception.message,
        'message',
        contains('arm64 PE'),
      )),
    );
    expect(projectFile(_fragment).existsSync(), isFalse);
  });

  test('preserves existing user runtime integration', () {
    const custom = _cmake +
        r'install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/xray" DESTINATION ".")' +
        '\n';
    write('windows/CMakeLists.txt', custom.codeUnits);
    expect(() => inspect(SetupMode.proxy), throwsA(isA<SetupException>()));
    expect(projectFile('windows/CMakeLists.txt').readAsStringSync(), custom);
    expect(projectFile(_fragment).existsSync(), isFalse);
  });

  test('reports a modified managed file without overwriting it', () {
    write('$_stage/xray.exe', _pe());
    expect(
      () => inspect(SetupMode.proxy),
      throwsA(isA<SetupException>().having(
        (exception) => exception.message,
        'message',
        contains('differs from the pinned runtime'),
      )),
    );
    expect(projectFile('$_stage/xray.exe').readAsBytesSync(), _pe());
    expect(calls, 0);
  });
}

Uint8List _pe({bool dll = false}) {
  final bytes = Uint8List(96);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  final data = ByteData.sublistView(bytes);
  data.setUint32(0x3c, 64, Endian.little);
  data.setUint32(64, 0x4550, Endian.little);
  data.setUint16(68, 0x8664, Endian.little);
  if (dll) data.setUint16(86, 0x2000, Endian.little);
  return bytes;
}
