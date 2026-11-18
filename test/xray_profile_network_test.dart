import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/xray_profile.dart';

void main() {
  const direct = RouteTarget.direct();
  const block = RouteTarget.block();
  const root = CorePath.root;

  test('combines CIDRs, ports, networks and inbound tags in one ordered rule',
      () {
    final domains = ['domain:service.invalid'];
    final cidrs = [
      XrayCidr.parse('192.0.2.0/24'),
      XrayCidr.parse('2001:db8::/32')
    ];
    final ports = [XrayPortRange.single(53), XrayPortRange.range(8000, 8002)];
    final networks = {XrayRouteNetwork.udp, XrayRouteNetwork.tcp};
    final tags = ['internal'];
    final rule = RouteRule.match(
      to: direct,
      domains: domains,
      destinationCidrs: cidrs,
      destinationPorts: ports,
      networks: networks,
      inboundTags: tags,
    );
    domains.clear();
    cidrs.clear();
    ports.clear();
    networks.clear();
    tags.clear();

    final initial = XrayProfile.build((draft) {
      draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.ipOnDemand);
      draft.addRule(RouteRule.domains(['full:blocked.invalid'], to: block));
      draft.setDefaultRoute(block);
    });
    final edited = initial.edit((draft) => draft.addRule(rule));
    final routing = edited.toCoreMap()['routing'] as Map;
    final rules = routing['rules'] as List;
    final initialRules = initial.toCoreMap()['routing']['rules'] as List;
    expect(routing['domainStrategy'], 'IPOnDemand');
    expect(initialRules, hasLength(2));
    expect(rules, [
      initialRules.first,
      {
        'type': 'field',
        'domain': ['domain:service.invalid'],
        'ip': ['192.0.2.0/24', '2001:db8::/32'],
        'port': '53,8000-8002',
        'network': 'tcp,udp',
        'inboundTag': ['internal'],
        'outboundTag': isA<String>(),
      },
      initialRules.last,
    ]);
    expect(rules[1]['outboundTag'], isNot(rules.first['outboundTag']));
  });

  test('CIDR and port values enforce numeric families and bounds', () {
    for (final (text, prefix) in [
      ('0.0.0.0/0', 0),
      ('255.255.255.255/32', 32),
      ('::/0', 0),
      ('2001:db8::1234/128', 128),
      ('64:ff9b::192.0.2.1/96', 96),
    ]) {
      final cidr = XrayCidr.parse(text);
      expect(cidr.address, text.split('/').first);
      expect(cidr.prefixLength, prefix);
    }
    for (final invalid in [
      '192.0.2.1',
      '192.0.2.1/33',
      '192.0.2.1/-1',
      '192.0.2.1/24/24',
      '192.0.2.1/24\n',
      '192.0.002.1/24',
      '192.0.256.1/24',
      'example.invalid/24',
      '2001:db8::1/129',
      '2001:db8::1/0x20',
      '::ffff:192.0.2.1/128',
      '[2001:db8::1]/32',
      'fe80::1%en0/32',
    ]) {
      expect(() => XrayCidr.parse(invalid), throwsFormatException,
          reason: invalid);
    }
    expect(XrayPortRange.single(65535).last, 65535);
    final range = XrayPortRange.range(1, 65535);
    expect((range.first, range.last), (1, 65535));
    for (final (first, last) in [(65536, 65536), (0, 1), (53, 52)]) {
      expect(() => XrayPortRange.range(first, last), throwsArgumentError);
    }
  });

  test('typed rules require effective conditions', () {
    expect(() => RouteRule.match(to: direct), throwsArgumentError);
    expect(
      () => RouteRule.match(to: direct, inboundTags: [' ']),
      throwsArgumentError,
    );
    expect(
      () => RouteRule.match(to: direct, domains: [' ']),
      throwsArgumentError,
    );
    expect(
      () => RouteRule.match(
        to: direct,
        networks: {XrayRouteNetwork.tcp, XrayRouteNetwork.udp},
      ),
      throwsArgumentError,
    );
    final profile = XrayProfile.build((draft) {
      draft.addRule(
          RouteRule.match(to: direct, networks: {XrayRouteNetwork.udp}));
      draft.setDefaultRoute(block);
    });
    expect(profile.toCoreMap()['routing']['rules'][0]['network'], 'udp');
  });

  test('adds split DNS alongside raw aliases, shorthand and future fields', () {
    final raw = XrayProfile.fromMap({
      'DNS': {
        'Servers': ['tcp://192.0.2.53'],
        'QueryStrategy': 'UseIPv6',
        'DisableFallbackIfMatch': false,
        'hosts': {'resolver.invalid': '192.0.2.54'},
        'futureResolverPolicy': {'value': true},
      },
      'Routing': {
        'DomainStrategy': 'AsIs',
        'Rules': [
          {
            'type': 'field',
            'domain': ['full:old.invalid'],
            'outboundTag': 'old'
          }
        ],
        'futureRouterPolicy': [true],
      },
    });
    final domains = ['domain:corp.invalid'];
    final doh = XrayDnsServer.doh(
      Uri.parse('https://resolver.invalid/dns-query?mode=wire'),
      domains: domains,
      tag: 'corp-dns',
      queryStrategy: XrayDnsQueryStrategy.useIpv6,
      skipFallback: true,
      finalQuery: true,
    );
    domains.clear();
    final edited = raw.edit((draft) {
      draft.setDnsOptions(const XrayDnsOptions(
        queryStrategy: XrayDnsQueryStrategy.useIp,
        disableFallbackIfMatch: true,
      ));
      draft.addDnsServer(XrayDnsServer.udp('2001:db8::53', port: 5353));
      draft.addDnsServer(doh);
      draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.ipIfNonMatch);
      draft.addRule(RouteRule.match(to: direct, inboundTags: ['corp-dns']));
    });
    final original = raw.toCoreMap();
    final json = edited.toCoreMap();
    expect(json, isNot(contains('dns')));
    expect(json, isNot(contains('routing')));
    expect(json['DNS'], {
      ...original['DNS'] as Map,
      'Servers': [
        'tcp://192.0.2.53',
        {'address': '2001:db8::53', 'port': 5353},
        {
          'address': 'https://resolver.invalid/dns-query?mode=wire',
          'domains': ['domain:corp.invalid'],
          'tag': 'corp-dns',
          'queryStrategy': 'UseIPv6',
          'skipFallback': true,
          'finalQuery': true,
        },
      ],
      'QueryStrategy': 'UseIP',
      'DisableFallbackIfMatch': true,
    });
    final routing = json['Routing'] as Map;
    expect(routing['DomainStrategy'], 'IPIfNonMatch');
    expect(routing['futureRouterPolicy'], [true]);
    expect(routing['Rules'][0], original['Routing']['Rules'][0]);
    expect(routing['Rules'][1]['inboundTag'], ['corp-dns']);
    expect(original['DNS']['Servers'], ['tcp://192.0.2.53']);
  });

  test('omitted DNS options add neither fallback, routes nor outbounds', () {
    final empty = XrayProfile.fromMap({});
    expect(
        empty
            .edit((draft) => draft.setDnsOptions(const XrayDnsOptions()))
            .toCoreMap(),
        isEmpty);
    final edited = empty.edit((draft) {
      draft.addDnsServer(XrayDnsServer.udp('192.0.2.53'));
    });
    expect(edited.toCoreMap(), {
      'dns': {
        'servers': [
          {'address': '192.0.2.53'}
        ]
      }
    });
  });

  test('typed DNS rejects invalid syntax and structural script conflicts', () {
    expect(() => XrayDnsServer.udp('resolver.invalid'), throwsFormatException);
    expect(() => XrayDnsServer.udp('192.0.2.53', port: 0), throwsArgumentError);
    expect(() => XrayDnsServer.udp('192.0.2.53', domains: [' ']),
        throwsArgumentError);
    expect(() => XrayDnsServer.udp('192.0.2.53', tag: ''), throwsArgumentError);
    for (final endpoint in [
      '/dns-query',
      'http://resolver.invalid/dns-query',
      'https+local://resolver.invalid/dns-query',
      'https://secret@resolver.invalid/dns-query',
      'https://resolver.invalid/dns-query#fragment',
      'https://resolver.invalid:65536/dns-query',
    ]) {
      expect(() => XrayDnsServer.doh(Uri.parse(endpoint)), throwsArgumentError,
          reason: endpoint);
    }
    final source = XrayProfile.fromMap({
      'dns': {'Script': 'future_dns_selection()'},
      'routing': {'Script': 'future_route_selection()'},
    });
    expect(
      () => source.edit((draft) => draft.addDnsServer(XrayDnsServer.udp(
            '192.0.2.53',
            domains: ['domain:corp.invalid'],
          ))),
      throwsArgumentError,
    );
    expect(
      () => source.edit((draft) => draft.setDnsOptions(
            const XrayDnsOptions(disableFallbackIfMatch: true),
          )),
      throwsArgumentError,
    );
    expect(
      () => source.edit((draft) =>
          draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.asIs)),
      throwsArgumentError,
    );
    final valid = source.edit((draft) => draft
        .addDnsServer(XrayDnsServer.udp('192.0.2.53', skipFallback: false)));
    expect(valid.toCoreMap()['dns']['Script'], 'future_dns_selection()');
  });

  test('raw overlaps are explicit and failed option writes remain atomic', () {
    final dns = root.key('dns');
    final resolver = dns.key('servers').index(0);
    final routing = root.key('routing');
    final domain = routing.key('domainStrategy');
    final raw = XrayProfile.fromMap({
      'dns': {'future': true},
      'routing': {'future': false},
    });
    final collided = raw.edit((draft) {
      draft.setRaw(dns, {'future': true});
      expect(() => draft.addDnsServer(XrayDnsServer.udp('192.0.2.53')),
          throwsStateError);
      draft.setRaw(domain, 'FutureDomainStrategy');
      expect(
          () => draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.asIs),
          throwsStateError);
    });
    expect(collided.toCoreMap()['dns'], {'future': true});
    expect(collided.toCoreMap()['routing']['domainStrategy'],
        'FutureDomainStrategy');
    final options = raw.edit((draft) {
      draft.setRaw(dns.key('disableFallbackIfMatch'), false);
      expect(
          () => draft.setDnsOptions(const XrayDnsOptions(
                queryStrategy: XrayDnsQueryStrategy.useSystem,
                disableFallbackIfMatch: true,
              )),
          throwsStateError);
      draft.setDnsOptions(const XrayDnsOptions(
        queryStrategy: XrayDnsQueryStrategy.useIpv4,
      ));
    });
    expect(options.toCoreMap()['dns'], {
      'future': true,
      'queryStrategy': 'UseIPv4',
      'disableFallbackIfMatch': false,
    });
    final overwritten = raw.edit((draft) {
      draft.addDnsServer(XrayDnsServer.udp('192.0.2.53'));
      expect(() => draft.setRaw(resolver, 'future://resolver.invalid'),
          throwsStateError);
      draft.setRaw(resolver.key('futureField'), true, replace: true);
      draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.ipOnDemand);
      draft.setRaw(domain, 'FutureDomainStrategy', replace: true);
      draft.addRule(RouteRule.match(to: direct, inboundTags: ['dns']));
      final tag = routing.key('rules').index(0).key('inboundTag').index(0);
      expect(() => draft.setRaw(tag, 'new-dns'), throwsStateError);
      draft.setRaw(tag, 'new-dns', replace: true);
    });
    expect(overwritten.toCoreMap()['dns']['servers'], [
      {'address': '192.0.2.53', 'futureField': true},
    ]);
    expect(overwritten.toCoreMap()['routing']['domainStrategy'],
        'FutureDomainStrategy');
    expect(overwritten.toCoreMap()['routing']['rules'][0]['inboundTag'],
        ['new-dns']);
  });
}
