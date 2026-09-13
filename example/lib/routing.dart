import 'dart:io';

import 'package:flutter/material.dart';

import 'routing_config.dart';

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
  late final TextEditingController _domainsController;
  late final TextEditingController _appsController;
  List<String> blockedDomains = [];
  List<String> blockedApps = [];

  @override
  void initState() {
    super.initState();
    blockedDomains = List.of(
        routingDomainsFromConfig(widget.config) ?? widget.blockedDomains);
    blockedApps = List.of(widget.blockedApps);
    _domainsController = TextEditingController(text: blockedDomains.join('\n'));
    _appsController = TextEditingController(text: blockedApps.join('\n'));
  }

  @override
  void dispose() {
    _domainsController.dispose();
    _appsController.dispose();
    super.dispose();
  }

  void _applyRouting() {
    try {
      final newConfig =
          routingConfig(config: widget.config, selectedSites: blockedDomains);

      widget.onApplyConfig?.call(newConfig);
      widget.onApplyApps?.call(blockedApps);
      widget.onApplyDomains?.call(blockedDomains);

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Routing rules saved. Reconnect VPN to apply.')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Failed to apply rules: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Routing — Bypass VPN')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Expanded(
              child: SingleChildScrollView(
                child: Column(
                  children: [
                    _section(
                        'Bypass domains (one per line)', _domainsController),
                    const SizedBox(height: 12),
                    if (Platform.isAndroid)
                      _section('Bypass apps (package names, one per line)',
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
}
