import 'package:flutter/material.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_json.dart';

/// Per-profile choices; the imported JSON and global plugin options stay intact.
class VpnRoutingPanel extends StatelessWidget {
  const VpnRoutingPanel({
    super.key,
    required this.config,
    required this.proxyOnly,
    required this.value,
    required this.onChanged,
  });

  final String config;
  final bool proxyOnly;
  final VpnRoutingOptions? value;
  final ValueChanged<VpnRoutingOptions?> onChanged;

  @override
  Widget build(BuildContext context) {
    Map<dynamic, dynamic> profile = const {};
    try {
      final decoded = decodeXrayJson(config);
      if (decoded is Map) profile = decoded;
    } on FormatException {
      // The editor can contain an incomplete draft. Connect validates it.
    }
    final inputs = profile['inbounds'] is List
        ? profile['inbounds'] as List
        : [];
    final outputs = profile['outbounds'] is List
        ? profile['outbounds'] as List
        : [];
    final inputChoices = <int, String>{-1: 'VPN input'};
    for (var index = 0; index < inputs.length; index++) {
      final input = inputs[index];
      final tag = input is Map ? input['tag'] : null;
      final protocol = input is Map ? input['protocol'] : null;
      inputChoices[index] =
          '${tag is String && tag.isNotEmpty ? tag : 'Input ${index + 1}'}'
          '${protocol is String ? ' ($protocol)' : ''}';
    }
    final outputChoices = <String, String>{'': 'Configuration default'};
    for (final output in outputs) {
      final tag = output is Map ? output['tag'] : null;
      if (tag is String && tag.isNotEmpty) outputChoices[tag] = tag;
    }
    final input = value?.sourceInboundIndex ?? -1;
    final output = value?.defaultOutboundTag ?? '';
    // Keep stale selections visible; editing JSON must not silently select a
    // different route. Native admission will reject a missing input or tag.
    inputChoices.putIfAbsent(input, () => 'Input ${input + 1} (missing)');
    outputChoices.putIfAbsent(output, () => '$output (missing)');

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('VPN routing'),
          subtitle: Text(
            proxyOnly
                ? 'Available in VPN mode.'
                : 'Use an input’s rules or choose the default outbound.',
          ),
          value: !proxyOnly && value != null,
          onChanged: proxyOnly
              ? null
              : (enabled) => onChanged(
                  enabled ? value ?? const VpnRoutingOptions() : null,
                ),
        ),
        if (!proxyOnly && value != null) ...[
          DropdownButtonFormField<int>(
            key: ValueKey(('vpn-routing-input', config, input)),
            initialValue: input,
            isExpanded: true,
            decoration: const InputDecoration(
              labelText: 'Use routing from input',
            ),
            items: [
              for (final entry in inputChoices.entries)
                DropdownMenuItem(value: entry.key, child: Text(entry.value)),
            ],
            onChanged: (selected) => onChanged(
              VpnRoutingOptions(
                sourceInboundIndex: selected == -1 ? null : selected,
                defaultOutboundTag: value?.defaultOutboundTag,
              ),
            ),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            key: ValueKey(('vpn-routing-output', config, output)),
            initialValue: output,
            isExpanded: true,
            decoration: const InputDecoration(labelText: 'Default outbound'),
            items: [
              for (final entry in outputChoices.entries)
                DropdownMenuItem(value: entry.key, child: Text(entry.value)),
            ],
            onChanged: (selected) => onChanged(
              VpnRoutingOptions(
                sourceInboundIndex: value?.sourceInboundIndex,
                defaultOutboundTag: selected == '' ? null : selected,
              ),
            ),
          ),
        ],
      ],
    );
  }
}
