import 'package:flutter/material.dart';
import 'package:flutter_vless/flutter_vless.dart';

/// Presentation belongs to the app; system actions are fixed native actions.
class PluginOptionsPage extends StatefulWidget {
  const PluginOptionsPage(
      {super.key,
      required this.initial,
      required this.capabilities,
      required this.onApply,
      required this.onAddTile,
      required this.onClearProfile});
  final VlessOptions initial;
  final VlessCapabilities capabilities;
  final Future<void> Function(VlessOptions) onApply;
  final Future<QuickTileAddResult> Function() onAddTile;
  final Future<void> Function() onClearProfile;
  @override
  State<PluginOptionsPage> createState() => _PluginOptionsPageState();
}

class _PluginOptionsPageState extends State<PluginOptionsPage> {
  late bool quick = widget.initial.quickAccess.enabled;
  late bool unlock = widget.initial.quickAccess.requireUnlock;
  late bool reconnect = widget.initial.reconnect.enabled;
  late bool diagnostics = widget.initial.diagnostics.enabled;
  late QuickAccessSurface surface = widget.initial.quickAccess.surface;
  late VlessSystemAction action = widget.initial.quickAccess.action;
  late VlessNotificationAction notificationAction =
      widget.initial.notification.action;
  late OnDemandMode onDemand = widget.initial.protection.onDemand;
  late AlwaysOnMode alwaysOn = widget.initial.protection.alwaysOn;
  late final label =
      TextEditingController(text: widget.initial.quickAccess.label);
  late final button =
      TextEditingController(text: widget.initial.notification.buttonLabel);
  late final icon =
      TextEditingController(text: widget.initial.notification.iconResourceName);
  late final symbol =
      TextEditingController(text: widget.initial.quickAccess.appleSymbol);
  late final tileIcon = TextEditingController(
      text: widget.initial.quickAccess.androidIconResourceName);
  late final windowsIcon = TextEditingController(
      text: widget.initial.quickAccess.windowsIconPath ?? '');
  late final initialDelay = TextEditingController(
      text: widget.initial.reconnect.initialDelay.inMilliseconds.toString());
  late final maximumDelay = TextEditingController(
      text: widget.initial.reconnect.maxDelay.inMilliseconds.toString());
  late final attempts = TextEditingController(
      text: widget.initial.reconnect.maxAttempts.toString());
  late final bytes = TextEditingController(
      text: widget.initial.diagnostics.maxBytes.toString());
  late final lines = TextEditingController(
      text: widget.initial.diagnostics.maxLines.toString());
  late String iconType = widget.initial.notification.iconResourceType;
  bool saving = false;
  @override
  void dispose() {
    for (final controller in [
      label,
      button,
      icon,
      symbol,
      tileIcon,
      windowsIcon,
      initialDelay,
      maximumDelay,
      attempts,
      bytes,
      lines
    ]) {
      controller.dispose();
    }
    super.dispose();
  }

  Widget field(String title, TextEditingController controller,
          {bool number = false}) =>
      Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: TextField(
              controller: controller,
              keyboardType: number ? TextInputType.number : TextInputType.text,
              decoration: InputDecoration(labelText: title)));
  Widget choice<T>(
          String title, T value, List<T> values, ValueChanged<T> change) =>
      Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: DropdownButtonFormField<T>(
              initialValue: value,
              decoration: InputDecoration(labelText: title),
              items: values
                  .map((v) => DropdownMenuItem(
                      value: v, child: Text(v.toString().split('.').last)))
                  .toList(),
              onChanged: (v) {
                if (v != null) {
                  setState(() => change(v));
                }
              }));
  Future<void> operation(Future<Object?> Function() body) async {
    try {
      final result = await body();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(result?.toString() ?? 'Done')));
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$error')));
      }
    }
  }

  Future<void> apply() async {
    setState(() => saving = true);
    try {
      final options = VlessOptions(
          notification: NotificationOptions(
              iconResourceType: iconType,
              iconResourceName: icon.text,
              buttonLabel: button.text,
              action: notificationAction),
          quickAccess: QuickAccessOptions(
              enabled: quick,
              surface: surface,
              label: label.text,
              action: action,
              requireUnlock: unlock,
              androidIconResourceName: tileIcon.text,
              appleSymbol: symbol.text,
              windowsIconPath:
                  windowsIcon.text.trim().isEmpty ? null : windowsIcon.text),
          reconnect: ReconnectOptions(
              enabled: reconnect,
              initialDelay:
                  Duration(milliseconds: int.parse(initialDelay.text)),
              maxDelay: Duration(milliseconds: int.parse(maximumDelay.text)),
              maxAttempts: int.parse(attempts.text)),
          protection: ProtectionOptions(onDemand: onDemand, alwaysOn: alwaysOn),
          diagnostics: DiagnosticsOptions(
              enabled: diagnostics,
              maxBytes: int.parse(bytes.text),
              maxLines: int.parse(lines.text)));
      options.validate();
      await widget.onApply(options);
      if (mounted) Navigator.pop(context);
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$error')));
      }
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final caps = widget.capabilities;
    return Scaffold(
        appBar: AppBar(title: const Text('Plugin options')),
        bottomNavigationBar: SafeArea(
            child: Padding(
                padding: const EdgeInsets.all(16),
                child: FilledButton(
                    onPressed: saving ? null : apply,
                    child: Text(saving ? 'Saving…' : 'Apply options')))),
        body: ListView(padding: const EdgeInsets.all(16), children: [
          const Text('Notification Options', style: TextStyle(fontSize: 20)),
          const Text(
              'Android foreground notification. Icons must be bundled native resources.'),
          choice('Icon resource type', iconType, ['mipmap', 'drawable'],
              (v) => iconType = v),
          field('Notification icon', icon),
          field('Notification button label', button),
          choice('Notification action', notificationAction,
              VlessNotificationAction.values, (v) => notificationAction = v),
          const Divider(),
          const Text('Quick Access Options', style: TextStyle(fontSize: 20)),
          SwitchListTile(
              title: const Text('Enable system control'),
              value: quick,
              onChanged: caps.quickAccessSurfaces.isEmpty
                  ? null
                  : (v) => setState(() => quick = v)),
          choice(
              'System control',
              surface,
              [QuickAccessSurface.platformDefault, ...caps.quickAccessSurfaces],
              (v) => surface = v),
          field('Control label', label),
          choice('Control action', action, VlessSystemAction.values,
              (v) => action = v),
          SwitchListTile(
              title: const Text('Unlock before action'),
              value: unlock,
              onChanged: (v) => setState(() => unlock = v)),
          field('Android tile drawable', tileIcon),
          field('Apple SF Symbol', symbol),
          field('Windows .ico absolute path (optional)', windowsIcon),
          if (caps.quickAccessSurfaces
              .contains(QuickAccessSurface.controlCenter))
            Text(
                'Control Center extension: ${caps.controlCenterExtensionConfigured ? "configured" : "setup required"}. The control opens the app.'),
          if (caps.requestAddQuickTile)
            OutlinedButton(
                onPressed: () => operation(widget.onAddTile),
                child: const Text('Add Android Quick Tile')),
          OutlinedButton(
              onPressed: () => operation(() async {
                    await widget.onClearProfile();
                    return 'Saved quick-access permission cleared';
                  }),
              child: const Text('Forget quick-access profile')),
          const Divider(),
          const Text('Reconnect Options', style: TextStyle(fontSize: 20)),
          SwitchListTile(
              title: const Text('Auto Reconnect'),
              value: reconnect,
              onChanged: (v) => setState(() {
                    reconnect = v;
                    if (!v && onDemand == OnDemandMode.enabled) {
                      onDemand = OnDemandMode.disabled;
                    }
                  })),
          field('Initial retry delay (ms)', initialDelay, number: true),
          field('Maximum retry delay (ms)', maximumDelay, number: true),
          field('Retry attempts (0 = unlimited)', attempts, number: true),
          const Divider(),
          const Text('Protection Options', style: TextStyle(fontSize: 20)),
          const ListTile(
              title: Text('Kill Switch'),
              subtitle: Text(
                  'Required for VPN mode. Failed forwarding keeps traffic protected until explicit Stop.')),
          if (caps.onDemand)
            choice('Apple On Demand', onDemand, OnDemandMode.values,
                (v) => onDemand = v),
          if (caps.alwaysOn) ...[
            choice('Android Always On', alwaysOn, AlwaysOnMode.values,
                (v) => alwaysOn = v),
            Text(
                'Enabled: ${caps.alwaysOnEnabled}; lockdown: ${caps.lockdownEnabled}. Configure these in Android VPN settings. Stop is managed by the OS while enabled.'),
          ],
          const Text(
              'Apple Always On requires a managed IKEv2 deployment. This custom Xray tunnel supports On Demand.'),
          const Divider(),
          const Text('Diagnostics Options', style: TextStyle(fontSize: 20)),
          SwitchListTile(
              title: const Text('Collect private diagnostics'),
              subtitle: const Text(
                  'Raw configuration and credentials are never enabled.'),
              value: diagnostics,
              onChanged: (v) => setState(() => diagnostics = v)),
          field('Diagnostics bytes (4096–131072)', bytes, number: true),
          field('Diagnostics lines (1–300)', lines, number: true),
          const Text(
              'Recovery/protection settings apply on the next explicit connection. Desktop controls require the app process. Save options before adding a tile.'),
        ]));
  }
}
