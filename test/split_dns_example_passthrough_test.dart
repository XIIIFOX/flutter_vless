import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const directory = 'example/configs/split-dns';
  const channel = MethodChannel('flutter_vless');
  late VlessPlatform previous;
  final calls = <MethodCall>[];

  setUp(() {
    previous = VlessPlatform.instance;
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 23 : null;
    });
  });

  tearDown(() {
    VlessPlatform.instance = previous;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('documented split DNS recipe has explicit DNS and data egress', () {
    final source = File('$directory/profile.json').readAsStringSync();
    final config = jsonDecode(source) as Map<String, dynamic>;
    final parsed = FlutterVless.parse(source);
    expect(parsed.fullConfiguration, config);
    expect(jsonDecode(parsed.getFullConfiguration()), config);

    final outbounds = (config['outbounds'] as List).cast<Map>();
    expect(outbounds.map((outbound) => outbound['tag']),
        ['proxy', 'direct', 'block']);
    expect(outbounds.first['protocol'], 'socks');
    expect(outbounds.first['settings'], {
      'servers': [
        {'address': 'proxy.example.invalid', 'port': 1080}
      ]
    });
    expect(outbounds[1]['protocol'], 'freedom');
    expect(outbounds[2]['protocol'], 'blackhole');
    expect(config['dns'], {
      'servers': [
        {
          'address': 'https://1.1.1.1/dns-query',
          'domains': ['full:api.ipify.org'],
          'tag': 'case-api-direct-dns',
          'skipFallback': true,
          'finalQuery': true,
        },
        'localhost',
      ]
    });
    expect((config['routing'] as Map)['domainStrategy'], 'AsIs');
    expect((config['routing'] as Map)['rules'], [
      {
        'type': 'field',
        'network': 'udp',
        'port': '443',
        'outboundTag': 'block',
      },
      {
        'type': 'field',
        'inboundTag': ['case-api-direct-dns'],
        'outboundTag': 'direct',
      },
      {
        'type': 'field',
        'domain': ['full:api.ipify.org'],
        'outboundTag': 'direct',
      },
    ]);
  });

  test('README links the portable JSON that the contract tests exercise', () {
    final text = File('$directory/README.md').readAsStringSync();
    final link = RegExp(r'\[profile\.json\]\(([^)]+)\)').firstMatch(text);
    expect(link, isNotNull);
    expect(link!.group(1), 'profile.json');
    final linked =
        jsonDecode(File('$directory/${link.group(1)}').readAsStringSync())
            as Map;
    expect((linked['outbounds'] as List).first['tag'], 'proxy');
    expect(text, contains('proxy.example.invalid'));
  });

  for (final adapter in <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  }.entries) {
    test('document JSON reaches ${adapter.key} start/delay without rewriting',
        () async {
      final source = File('$directory/profile.json').readAsStringSync();
      final expected = jsonDecode(source);
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      await api.startVless(remark: 'Split DNS example', config: source);
      expect(await api.getServerDelay(config: source), 23);
      expect(
          calls.map((call) => call.method), ['startVless', 'getServerDelay']);
      for (final call in calls) {
        expect(
            jsonDecode((call.arguments as Map)['config'] as String), expected);
      }
      expect(File('$directory/profile.json').readAsStringSync(), source);
    });
  }
}
