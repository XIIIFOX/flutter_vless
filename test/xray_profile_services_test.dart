import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() {
  test('Freedom rules keep their order and guard new delay and severity', () {
    final profile = XrayProfile.build((draft) {
      draft.requireCoreAtLeast('26.10.31');
      final direct = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
      draft.setFreedomFinalRules(direct, [
        XrayFreedomFinalRule.allow(
          destinationCidrs: [XrayCidr.parse('192.0.2.0/24')],
          destinationPorts: [XrayPortRange.single(443)],
          networks: {XrayRouteNetwork.tcp},
        ),
        XrayFreedomFinalRule.block(
          destinationCidrs: [XrayCidr.parse('2001:db8::/32')],
          destinationPorts: [XrayPortRange.range(2000, 3000)],
          networks: {XrayRouteNetwork.udp},
          delay: XrayFreedomBlockDelay.range(
            const Duration(seconds: 2),
            const Duration(seconds: 7),
          ),
          logLevel: XrayFreedomLogLevel.none,
        ),
        XrayFreedomFinalRule.block(
          delay: XrayFreedomBlockDelay.fixed(Duration.zero),
        ),
      ]);
    }).toCoreMap();
    expect(profile['version'], {'min': '26.11.9'});
    expect(profile['outbounds'][0]['settings']['finalRules'], [
      {
        'action': 'allow',
        'ip': ['192.0.2.0/24'],
        'port': '443',
        'network': 'tcp'
      },
      {
        'action': 'block',
        'ip': ['2001:db8::/32'],
        'port': '2000-3000',
        'network': 'udp',
        'delay': '2-7',
        'logLevel': 'none',
      },
      {'action': 'block', 'delay': 0},
    ]);
  });

  test('a raw override still conflicts with a stronger typed Core minimum', () {
    expect(
      () => XrayProfile.build((draft) {
        draft.requireCoreAtLeast('26.10.31');
        draft.setRaw(CorePath.root.key('version').key('min'), '26.10.31',
            replace: true);
        draft.requireCoreAtLeast('26.11.9');
      }),
      throwsStateError,
    );
  });

  test('basic Freedom rules preserve existing versions and neighboring fields',
      () {
    final original = XrayProfile.fromJson('''
      {"version":{"max":"26.10.31"},"outbounds":[{
        "protocol":"direct","tag":"direct","Settings":{"finalRules":[
          {"action":"block","blockDelay":5}],"domainStrategy":"UseIP","future":null}
      }]}
    ''');
    final updated = original.edit((draft) => draft.setFreedomFinalRules(
          draft.nodeAt(0),
          [XrayFreedomFinalRule.allow(), XrayFreedomFinalRule.block()],
        ));
    expect(updated.toCoreMap()['version'], {'max': '26.10.31'});
    expect(updated.toCoreMap()['outbounds'][0]['Settings'], {
      'domainStrategy': 'UseIP',
      'future': null,
      'finalRules': [
        {'action': 'allow'},
        {'action': 'block'},
      ],
    });
    expect(
      original.toCoreMap()['outbounds'][0]['Settings']['finalRules'][0],
      containsPair('blockDelay', 5),
    );
    expect(
      () => original.edit((draft) => draft.setFreedomFinalRules(draft.nodeAt(0),
          [XrayFreedomFinalRule.block(logLevel: XrayFreedomLogLevel.none)])),
      throwsArgumentError,
    );
  });

  test('Freedom rejects invalid delays, outbounds and conflicting raw edits',
      () {
    for (final (minimum, maximum) in [
      (const Duration(seconds: -1), Duration.zero),
      (const Duration(milliseconds: 500), const Duration(seconds: 1)),
      (const Duration(seconds: 2), const Duration(seconds: 1)),
      (Duration.zero, const Duration(seconds: 2147483648)),
    ]) {
      expect(() => XrayFreedomBlockDelay.range(minimum, maximum),
          throwsArgumentError);
    }
    expect(
      () => XrayProfile.build((draft) {
        final node =
            draft.addNode(ProxyNode.fromMap({'protocol': 'blackhole'}));
        draft.setFreedomFinalRules(node, []);
      }),
      throwsArgumentError,
    );
    expect(
      () => XrayProfile.build((draft) {
        final node = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
        draft.setRaw(CorePath.root.key('outbounds').index(0).key('settings'),
            {'finalRules': []},
            replace: true);
        draft.setFreedomFinalRules(node, [XrayFreedomFinalRule.block()]);
      }),
      throwsStateError,
    );
  });

  test('GeoDAT assets, typed outbound and schedule preserve raw profile data',
      () {
    final asset = XrayGeoDataAsset(
      url: Uri.parse('https://assets.example.org/geosite.dat.gz'),
      file: 'geosite.dat',
    );
    final list = [asset];
    final schedule = XrayGeoDataSchedule.every(
      const Duration(hours: 6),
      assets: list,
    );
    list.clear();
    final original = XrayProfile.fromJson('''
      {"GeoData":{"future":null},"outbounds":[{"protocol":"freedom","tag":"dns"}]}
    ''');
    final updated = original.edit((draft) =>
        draft.setGeoDataSchedule(schedule, outbound: draft.nodeAt(0)));
    expect(updated.toCoreMap()['GeoData'], {
      'future': null,
      'cron': '@every 21600s',
      'outbound': 'dns',
      'assets': [
        {
          'url': 'https://assets.example.org/geosite.dat.gz',
          'file': 'geosite.dat'
        }
      ],
    });
    final rescheduled = updated.edit((draft) =>
        draft.setGeoDataSchedule(XrayGeoDataSchedule.cron('0 3 * * *')));
    expect(rescheduled.toCoreMap()['GeoData']['assets'], hasLength(1));
    expect(rescheduled.toCoreMap()['GeoData']['outbound'], 'dns');
    final reloadOnly = rescheduled.edit((draft) => draft
        .setGeoDataSchedule(XrayGeoDataSchedule.cron('0 3 * * *', assets: [])));
    expect(reloadOnly.toCoreMap()['GeoData']['assets'], isEmpty);
    expect(original.toCoreMap()['GeoData'], {'future': null});
  });

  test('GeoDAT schedule observes duration, HTTPS, extension and count limits',
      () {
    for (final value in [
      const Duration(seconds: 59),
      const Duration(milliseconds: 60500),
      const Duration(seconds: 9223372037),
    ]) {
      expect(() => XrayGeoDataSchedule.every(value), throwsArgumentError);
    }
    expect(() => XrayGeoDataSchedule.cron(' '), throwsArgumentError);
    expect(
      () => XrayProfile.build((draft) =>
          draft.setGeoDataSchedule(XrayGeoDataSchedule.cron('@every 59s'))),
      throwsArgumentError,
    );
    final valid = XrayGeoDataAsset(
      url: Uri.parse('https://assets.example.org/geo.dat.gz'),
      file: 'geo.dat',
    );
    for (final assets in [
      [
        XrayGeoDataAsset(
            url: Uri.parse('http://assets.example.org'), file: 'geo.dat')
      ],
      [XrayGeoDataAsset(url: valid.url, file: 'geo.gz')],
      List.filled(101, valid),
    ]) {
      expect(
        () => XrayProfile.build((draft) => draft.setGeoDataSchedule(
            XrayGeoDataSchedule.every(const Duration(minutes: 1),
                assets: assets))),
        throwsArgumentError,
      );
    }
  });

  test('a typed GeoDAT outbound must still be present in the final profile',
      () {
    final original = XrayProfile.fromJson('''
      {"outbounds":[{"protocol":"freedom","tag":"direct"}]}
    ''');
    final schedule = XrayGeoDataSchedule.every(const Duration(hours: 24));
    final outbounds = CorePath.root.key('outbounds');
    expect(
        () => original.edit((draft) {
              draft.setGeoDataSchedule(schedule, outbound: draft.nodeAt(0));
              draft.removeRaw(outbounds.index(0));
            }),
        throwsArgumentError);
    final overridden = original.edit((draft) {
      draft.setGeoDataSchedule(schedule, outbound: draft.nodeAt(0));
      draft.setRaw(CorePath.root.key('geodata').key('outbound'), 'replacement',
          replace: true);
      draft.setRaw(
          outbounds.index(0), {'protocol': 'freedom', 'tag': 'replacement'});
    });
    expect(overridden.toCoreMap()['geodata']['outbound'], 'replacement');
  });
}
