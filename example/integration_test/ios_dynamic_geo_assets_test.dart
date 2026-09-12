import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:integration_test/integration_test.dart';

const _geoCode = 'FLUTTER_VLESS_DYNAMIC_TEST';
const _responseMarker = 'flutter-vless-dynamic-geo-ok';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'iOS uses geoip.dat and geosite.dat from geoAssetsDirectory',
    (tester) async {
      if (!Platform.isIOS) {
        return;
      }

      final assetsDirectory = await Directory.systemTemp.createTemp(
        'flutter-vless-dynamic-geo-',
      );
      final geoIp = _buildGeoIpFixture();
      final geoSite = _buildGeoSiteFixture();
      await File('${assetsDirectory.path}/geoip.dat').writeAsBytes(
        geoIp,
        flush: true,
      );
      await File('${assetsDirectory.path}/geosite.dat').writeAsBytes(
        geoSite,
        flush: true,
      );

      // These values are intentionally printed by the integration test. They
      // let a simulator run prove which absolute sandbox path and which exact
      // bytes were handed to the native plugin.
      // ignore: avoid_print
      print('IOS_DYNAMIC_GEO_ASSETS_DIRECTORY=${assetsDirectory.path}');
      // ignore: avoid_print
      print('IOS_DYNAMIC_GEOIP_BASE64=${base64Encode(geoIp)}');
      // ignore: avoid_print
      print('IOS_DYNAMIC_GEOSITE_BASE64=${base64Encode(geoSite)}');

      var requestCount = 0;
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        requestCount += 1;
        request.response.write(_responseMarker);
        await request.response.close();
      });

      final vless = FlutterVless(onStatusChanged: (_) {});
      await vless.initializeVless();

      try {
        // Control: the local SOCKS proxy and direct outbound must work before
        // a blocked result can count as routing evidence.
        await vless.startVless(
          remark: 'iOS dynamic geo baseline',
          config: _buildConfig(),
          proxyOnly: true,
        );
        final baselineResponse = await _httpGetThroughSocks(
          targetPort: server.port,
          address: '127.0.0.1',
          sendAsDomain: false,
        );
        expect(baselineResponse, contains(_responseMarker));
        expect(requestCount, 1);
        await vless.stopVless();

        // Negative controls: neither unique code exists in Xray's default
        // assets. Both configurations must fail unless the custom directory is
        // actually applied before Xray parses its routing rules.
        await _expectStartFailureWithoutCustomAssets(
          vless,
          config: _buildConfig(useGeoSite: true),
          expectedAssetName: 'geosite.dat',
        );
        await _expectStartFailureWithoutCustomAssets(
          vless,
          config: _buildConfig(useGeoIp: true),
          expectedAssetName: 'geoip.dat',
        );

        // GeoSite proof: the fixture contains FULL localhost. A SOCKS request
        // encoded with a domain name must be routed to blackhole, so the local
        // HTTP server must not receive it.
        await vless.startVless(
          remark: 'iOS dynamic geosite',
          config: _buildConfig(useGeoSite: true),
          proxyOnly: true,
          geoAssetsDirectory: assetsDirectory.path,
        );
        final beforeGeoSite = requestCount;
        final geoSiteResponse = await _httpGetThroughSocks(
          targetPort: server.port,
          address: 'localhost',
          sendAsDomain: true,
        );
        await Future<void>.delayed(const Duration(milliseconds: 250));
        expect(geoSiteResponse, isNot(contains(_responseMarker)));
        expect(requestCount, beforeGeoSite);
        await vless.stopVless();

        // GeoIP proof: the fixture contains exactly 127.0.0.1/32. An IPv4
        // SOCKS request must likewise be routed to blackhole.
        await vless.startVless(
          remark: 'iOS dynamic geoip',
          config: _buildConfig(useGeoIp: true),
          proxyOnly: true,
          geoAssetsDirectory: assetsDirectory.path,
        );
        final beforeGeoIp = requestCount;
        final geoIpResponse = await _httpGetThroughSocks(
          targetPort: server.port,
          address: '127.0.0.1',
          sendAsDomain: false,
        );
        await Future<void>.delayed(const Duration(milliseconds: 250));
        expect(geoIpResponse, isNot(contains(_responseMarker)));
        expect(requestCount, beforeGeoIp);
        await vless.stopVless();

        // ignore: avoid_print
        print(
          'IOS_DYNAMIC_GEO_RESULT=PASS '
          'baselineRequests=1 finalRequests=$requestCount',
        );
      } finally {
        await vless.stopVless();
        await server.close(force: true);
      }
    },
  );
}

Future<void> _expectStartFailureWithoutCustomAssets(
  FlutterVless vless, {
  required String config,
  required String expectedAssetName,
}) async {
  Object? caught;
  try {
    await vless.startVless(
      remark: 'iOS dynamic geo negative control',
      config: config,
      proxyOnly: true,
    );
  } catch (error) {
    caught = error;
  } finally {
    await vless.stopVless();
  }

  expect(caught, isA<PlatformException>());
  expect(
    caught.toString(),
    anyOf(contains(expectedAssetName), contains(_geoCode)),
  );
  // ignore: avoid_print
  print('IOS_DYNAMIC_GEO_NEGATIVE_CONTROL=$expectedAssetName error=$caught');
}

String _buildConfig({bool useGeoIp = false, bool useGeoSite = false}) {
  final rules = <Map<String, Object>>[];
  if (useGeoSite) {
    rules.add({
      'type': 'field',
      'domain': ['geosite:$_geoCode'],
      'outboundTag': 'blocked',
    });
  }
  if (useGeoIp) {
    rules.add({
      'type': 'field',
      'ip': ['geoip:$_geoCode'],
      'outboundTag': 'blocked',
    });
  }

  return jsonEncode({
    'log': {'loglevel': 'warning'},
    'routing': {
      'domainStrategy': 'AsIs',
      'rules': rules,
    },
    'outbounds': [
      {
        'protocol': 'freedom',
        'tag': 'direct',
        'settings': <String, Object>{},
      },
      {
        'protocol': 'blackhole',
        'tag': 'blocked',
        'settings': <String, Object>{},
      },
    ],
  });
}

Future<String> _httpGetThroughSocks({
  required int targetPort,
  required String address,
  required bool sendAsDomain,
}) async {
  Socket? socket;
  _SocketReader? reader;
  try {
    socket = await Socket.connect(
      InternetAddress.loopbackIPv4,
      10807,
      timeout: const Duration(seconds: 3),
    );
    reader = _SocketReader(socket);

    socket.add(const [0x05, 0x01, 0x00]);
    await socket.flush();
    final greeting =
        await reader.readExactly(2).timeout(const Duration(seconds: 3));
    if (greeting[0] != 0x05 || greeting[1] != 0x00) {
      return '';
    }

    final portBytes = [targetPort >> 8, targetPort & 0xff];
    if (sendAsDomain) {
      final domainBytes = utf8.encode(address);
      socket.add([
        0x05,
        0x01,
        0x00,
        0x03,
        domainBytes.length,
        ...domainBytes,
        ...portBytes,
      ]);
    } else {
      socket.add([
        0x05,
        0x01,
        0x00,
        0x01,
        ...InternetAddress(address).rawAddress,
        ...portBytes,
      ]);
    }
    await socket.flush();

    final reply =
        await reader.readExactly(4).timeout(const Duration(seconds: 3));
    if (reply[0] != 0x05 || reply[1] != 0x00) {
      return '';
    }
    switch (reply[3]) {
      case 0x01:
        await reader.readExactly(6);
      case 0x03:
        final length = (await reader.readExactly(1)).single;
        await reader.readExactly(length + 2);
      case 0x04:
        await reader.readExactly(18);
      default:
        return '';
    }

    socket.write(
      'GET /geo-assets HTTP/1.1\r\n'
      'Host: $address\r\n'
      'Connection: close\r\n\r\n',
    );
    await socket.flush();

    final responseBytes = await reader
        .readToEnd()
        .timeout(const Duration(seconds: 3), onTimeout: () => const []);
    return utf8.decode(responseBytes, allowMalformed: true);
  } on Object {
    return '';
  } finally {
    socket?.destroy();
    await reader?.cancel();
  }
}

/// Produces the same protobuf wire format consumed by Xray's geodat loader.
/// The list contains one GeoIP entry: `_geoCode` => 127.0.0.1/32.
Uint8List _buildGeoIpFixture() {
  final cidr = <int>[
    ..._bytesField(1, const [127, 0, 0, 1]),
    ..._varintField(2, 32),
  ];
  final entry = <int>[
    ..._stringField(1, _geoCode),
    ..._bytesField(2, cidr),
  ];
  return Uint8List.fromList(_bytesField(1, entry));
}

/// Produces one GeoSite entry: `_geoCode` => FULL `localhost`.
Uint8List _buildGeoSiteFixture() {
  final domain = <int>[
    ..._varintField(1, 3), // xray.common.geodata.Domain.Type.Full
    ..._stringField(2, 'localhost'),
  ];
  final entry = <int>[
    ..._stringField(1, _geoCode),
    ..._bytesField(2, domain),
  ];
  return Uint8List.fromList(_bytesField(1, entry));
}

List<int> _stringField(int fieldNumber, String value) =>
    _bytesField(fieldNumber, utf8.encode(value));

List<int> _bytesField(int fieldNumber, List<int> value) => [
      ..._encodeVarint((fieldNumber << 3) | 2),
      ..._encodeVarint(value.length),
      ...value,
    ];

List<int> _varintField(int fieldNumber, int value) => [
      ..._encodeVarint(fieldNumber << 3),
      ..._encodeVarint(value),
    ];

List<int> _encodeVarint(int value) {
  final result = <int>[];
  do {
    var byte = value & 0x7f;
    value >>= 7;
    if (value != 0) {
      byte |= 0x80;
    }
    result.add(byte);
  } while (value != 0);
  return result;
}

final class _SocketReader {
  _SocketReader(Socket socket) : _iterator = StreamIterator(socket);

  final StreamIterator<Uint8List> _iterator;
  final List<int> _buffer = [];

  Future<List<int>> readExactly(int count) async {
    while (_buffer.length < count) {
      if (!await _iterator.moveNext()) {
        throw const SocketException('SOCKS connection closed early');
      }
      _buffer.addAll(_iterator.current);
    }
    final result = _buffer.sublist(0, count);
    _buffer.removeRange(0, count);
    return result;
  }

  Future<List<int>> readToEnd() async {
    final result = <int>[..._buffer];
    _buffer.clear();
    while (await _iterator.moveNext()) {
      result.addAll(_iterator.current);
    }
    return result;
  }

  Future<void> cancel() => _iterator.cancel();
}
