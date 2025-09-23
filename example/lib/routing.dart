import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

class Routing extends StatefulWidget {
  final String config;
  final List<String> blockedApps;
  final List<String> blockedDomains;
  final Function(List<String>)? onApplyApps;
  final Function(List<String>)? onApplyDomains;
  final Function(String)? onApplyConfig;
  const Routing({
    super.key,
    required this.config,
    required this.blockedApps,
    required this.blockedDomains,
    this.onApplyApps,
    this.onApplyDomains,
    this.onApplyConfig,
  });

  @override
  State<Routing> createState() => _RoutingState();
}

class _RoutingState extends State<Routing> {
  final TextEditingController _domainsController =
      TextEditingController(text: '''
example.com
tfox.dev
''');
  final TextEditingController _appsController = TextEditingController(text: '''
com.example.sensitiveapp
''');

  List<String> blockedDomains = [];
  List<String> blockedApps = [];

  @override
  void initState() {
    super.initState();
    blockedDomains = _domainsController.text
        .trim()
        .split('\n')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    blockedApps = _appsController.text
        .trim()
        .split('\n')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
  }

  @override
  void dispose() {
    _domainsController.dispose();
    _appsController.dispose();
    super.dispose();
  }

  Future<void> _applyRouting() async {
    try {
      final newConfig = await routingConfig(
          config: widget.config, selectedSites: blockedDomains);

      widget.onApplyConfig?.call(newConfig);
      widget.onApplyApps?.call(blockedApps);
      widget.onApplyDomains?.call(blockedDomains);

      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Routing rules applied')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Failed to apply rules: \$e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Routing — Blocked sites & apps')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Expanded(
              child: SingleChildScrollView(
                child: Column(
                  children: [
                    _section(
                        'Blocked domains (one per line)', _domainsController),
                    const SizedBox(height: 12),
                    _section('Blocked apps (package names, one per line)',
                        _appsController),
                  ],
                ),
              ),
            ),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: () {
                      setState(() {
                        blockedDomains = _domainsController.text
                            .split('\n')
                            .map((s) => s.trim())
                            .where((s) => s.isNotEmpty)
                            .toList();
                        blockedApps = _appsController.text
                            .split('\n')
                            .map((s) => s.trim())
                            .where((s) => s.isNotEmpty)
                            .toList();
                      });
                      _applyRouting();
                    },
                    child: const Text('Apply rules'),
                  ),
                ),
                const SizedBox(width: 12),
                OutlinedButton(
                  onPressed: () {
                    _domainsController.clear();
                    _appsController.clear();
                    setState(() {
                      blockedDomains = [];
                      blockedApps = [];
                    });
                  },
                  child: const Text('Clear'),
                ),
              ],
            )
          ],
        ),
      ),
    );
  }

  Widget _section(String title, TextEditingController controller) {
    return Card(
      color: Colors.grey[900],
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            SizedBox(
              height: 140,
              child: TextField(
                controller: controller,
                maxLines: null,
                expands: true,
                decoration: const InputDecoration(
                  isDense: true,
                  contentPadding: EdgeInsets.all(10),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<String> routingConfig({
    required String config,
    List<String> selectedSites = const [],
  }) async {
    if (selectedSites.isEmpty) {
      return config;
    }
    final configMap = jsonDecode(config) as Map<String, dynamic>;

    configMap['dns'] ??= <String, dynamic>{};
    configMap['dns']['servers'] =
        configMap['dns']['servers'] ?? ['8.8.8.8', '8.8.4.4'];
    // Optional: disable fallback (strict behavior)
    configMap['dns']['disableFallback'] = true;

    configMap['routing'] ??= <String, dynamic>{};
    final routing = configMap['routing'] as Map<String, dynamic>;

    // Use AsIs for domain strategy (to rely on domain/regexp)
    routing['domainStrategy'] = 'AsIs';

    routing['rules'] ??= <dynamic>[];
    final rules = (routing['rules'] as List).cast<Map<String, dynamic>>();

    // Collect site list for bypass rules
    final List<String> vlessDomainList = [];

    for (final site in selectedSites) {
      final n = normalizeDomainEntry(site);
      if (n.isNotEmpty) vlessDomainList.add(n);
    }

    // Remove duplicates
    final uniqueDomains = vlessDomainList.toSet().toList();

    // Separate explicit vs regexp
    final explicitDomains = <String>[];
    final regexpDomains = <String>[];
    for (final d in uniqueDomains) {
      if (d.startsWith('domain:') ||
          d.startsWith('geosite:') ||
          d.startsWith('keyword:')) {
        explicitDomains.add(d);
      } else {
        regexpDomains.add(d);
      }
    }

    // Allow them locally and add IP rules
    final explicitIps = <String>[];
    for (final rawSite in selectedSites) {
      final host = rawSite.trim();
      if (host.isEmpty) continue;
      // Add domain:host explicitly (in case normalize returned regexp or something else)
      final nd = normalizeDomainEntry(host);
      if (!nd.startsWith('domain:')) {
        // if normalize returned regexp, still add domain:host additionally
        explicitDomains.add('domain:$host');
      } else {
        // if already domain:... — leave as is
        explicitDomains.add(nd);
      }

      // Attempt local DNS resolve to get IPs and insert IP rules
      try {
        final List<InternetAddress> list = await InternetAddress.lookup(
          host,
        );
        for (final ia in list) {
          final ip = ia.address;
          if (!explicitIps.contains(ip)) explicitIps.add(ip);
        }
        debugPrint('Resolved $host -> ${list.map((e) => e.address).toList()}');
      } catch (e) {
        debugPrint('DNS lookup failed for $host: $e');
      }
    }

    // Insert rules at the top: 1) specific IPs for sites, 2) explicit domains, 3) regexp domains
    if (explicitIps.isNotEmpty) {
      rules.insert(0, <String, dynamic>{
        'type': 'field',
        'ip': explicitIps,
        'outboundTag': 'direct',
      });
    }

    if (explicitDomains.isNotEmpty) {
      rules.insert(0, <String, dynamic>{
        'type': 'field',
        'domain': explicitDomains,
        'outboundTag': 'direct',
      });
    }

    if (regexpDomains.isNotEmpty) {
      rules.insert(0, <String, dynamic>{
        'type': 'field',
        'domain': regexpDomains,
        'outboundTag': 'direct',
      });
    }

    routing['rules'] = rules;
    configMap['routing'] = routing;

    // Enable sniffing for inbounds (to extract HTTP Host / TLS SNI)
    if (configMap['inbounds'] is List) {
      final inbounds =
          (configMap['inbounds'] as List).cast<Map<String, dynamic>>();
      for (final inbound in inbounds) {
        inbound['sniffing'] = {
          'enabled': true,
          'destOverride': ['http', 'tls'],
        };
      }
      configMap['inbounds'] = inbounds;
    }

    // Update outbound direct (freedom) — to set domainStrategy = AsIs for it as well, if specified
    if (configMap['outbounds'] is List) {
      final outbounds =
          (configMap['outbounds'] as List).cast<Map<String, dynamic>>();
      for (final o in outbounds) {
        final tag = (o['tag'] ?? '') as String;
        final protocol = (o['protocol'] ?? '') as String;
        if (protocol == 'freedom' || tag == 'direct') {
          o['settings'] ??= <String, dynamic>{};
          o['settings']['domainStrategy'] = 'AsIs';
        }
      }
      configMap['outbounds'] = outbounds;
    }

    final updatedConfig = jsonEncode(configMap);
    debugPrint(
      'Final config (short): routing.rules count = ${(routing['rules'] as List).length}',
    );
    return updatedConfig;
  }

  // Helper function: normalize site entry into Vless format
  String normalizeDomainEntry(String raw) {
    raw = raw.trim();
    if (raw.isEmpty) return '';

    final lower = raw.toLowerCase();
    if (lower.startsWith('geosite:') ||
        lower.startsWith('domain:') ||
        lower.startsWith('regexp:') ||
        lower.startsWith('keyword:')) {
      return raw;
    }

    if (raw.startsWith('*.')) {
      final rest = raw.substring(2);
      return 'regexp:\\.' + RegExp.escape(rest) + r'$';
    }

    if (raw.startsWith('.')) {
      final escaped = RegExp.escape(raw);
      return 'regexp:' + escaped + r'$';
    }

    if (raw.contains('*')) {
      final escaped = RegExp.escape(raw).replaceAll('\\*', '.*');
      return 'regexp:^' + escaped + r'$';
    }

    return 'domain:$raw';
  }
}
