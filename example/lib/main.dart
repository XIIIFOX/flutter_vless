import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/routing.dart';
import 'options.dart';
import 'options_storage.dart';
import 'profile_import.dart';
import 'preparation_report.dart';
import 'vpn_routing.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final options = await ExampleOptionsStorage.load();
  runApp(MyApp(options: options));
}

class MyApp extends StatelessWidget {
  const MyApp({super.key, this.options = const VlessOptions()});
  final VlessOptions options;

  @override
  Widget build(BuildContext context) {
    final base = ThemeData.dark();
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Flutter VLESS',
      theme: base.copyWith(
        colorScheme: base.colorScheme.copyWith(
          primary: Colors.orangeAccent,
          secondary: Colors.orangeAccent.shade200,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      ),
      home: HomePage(options: options),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key, this.options = const VlessOptions()});
  final VlessOptions options;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final ValueNotifier<VlessStatus> vlessStatus =
      ValueNotifier<VlessStatus>(VlessStatus());

  late VlessOptions pluginOptions = widget.options;
  VlessPreparationReport? preparationReport;
  int preparationRequest = 0;
  late String reportEditorText;
  late FlutterVless flutterVless = FlutterVless(
    options: pluginOptions,
    onStatusChanged: (status) {
      vlessStatus.value = status;
    },
  );

  final TextEditingController config = TextEditingController(text: '{}');
  final TextEditingController certificateDirectory = TextEditingController();
  bool proxyOnly = false;
  VpnRoutingOptions? vpnRouting;
  List<String> bypassSubnets = [];
  List<String> blockedApps = [];

  /// Domains routed directly, bypassing the VPN.
  /// Use https://tfox.dev/ip/ to check the IP address of the direct connection.
  List<String> blockedDomains = ['tfox.dev'];
  String? coreVersion;
  String remark = 'Example Remark';

  @override
  void initState() {
    super.initState();
    reportEditorText = config.text;
    config.addListener(_configurationEdited);
    certificateDirectory.addListener(_invalidatePreparation);

    _initializePlugin(flutterVless);
  }

  void _invalidatePreparation() {
    preparationRequest++;
    if (preparationReport != null) setState(() => preparationReport = null);
  }

  void _configurationEdited() {
    if (reportEditorText == config.text) return;
    reportEditorText = config.text;
    _invalidatePreparation();
  }

  Future<void> _initializePlugin(FlutterVless plugin) async {
    try {
      await plugin.initializeVless(
          providerBundleIdentifier: 'dev.tfox.flutterXrayExample',
          groupIdentifier: 'group.dev.tfox.flutterXray');
      final version = await plugin.getCoreVersion();
      if (mounted) setState(() => coreVersion = version);
    } catch (error) {
      if (mounted) setState(() => coreVersion = 'Unavailable: $error');
    }
  }

  Future<void> _showOptions() async {
    try {
      final capabilities = await flutterVless.getCapabilities();
      if (!mounted) return;
      await Navigator.of(context).push(MaterialPageRoute<void>(
          builder: (_) => PluginOptionsPage(
                initial: pluginOptions,
                capabilities: capabilities,
                onAddTile: () => flutterVless.requestAddQuickTile(),
                onClearProfile: () => flutterVless.clearQuickAccessProfile(),
                onApply: (options) async {
                  _invalidatePreparation();
                  final replacement = FlutterVless(
                      options: options,
                      onStatusChanged: (status) {
                        if (mounted) vlessStatus.value = status;
                      });
                  await replacement.initializeVless(
                      providerBundleIdentifier: 'dev.tfox.flutterXrayExample',
                      groupIdentifier: 'group.dev.tfox.flutterXray');
                  flutterVless = replacement;
                  pluginOptions = options;
                  await ExampleOptionsStorage.save(options);
                },
              )));
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Options unavailable: $error')));
      }
    }
  }

  @override
  void dispose() {
    config.removeListener(_configurationEdited);
    config.dispose();
    certificateDirectory.removeListener(_invalidatePreparation);
    certificateDirectory.dispose();
    vlessStatus.dispose();
    super.dispose();
  }

  Future<void> _requestPermission() async {
    final ok = await flutterVless.requestPermission();
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(ok ? 'Permission granted' : 'Permission denied'),
    ));
  }

  Future<void> _connect() async {
    _invalidatePreparation();
    final request = preparationRequest;
    if (!proxyOnly && !await flutterVless.requestPermission()) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('Permission Denied'),
      ));
      return;
    }

    if (!mounted || request != preparationRequest) return;
    final report = await flutterVless.startVlessWithReport(
      remark: remark,
      config: config.text,
      proxyOnly: proxyOnly,
      vpnRouting: proxyOnly ? null : vpnRouting,
      bypassSubnets: bypassSubnets,
      blockedApps: blockedApps,
      certificateAssetsDirectory: certificateDirectory.text.isEmpty
          ? null
          : certificateDirectory.text,
    );
    if (mounted && request == preparationRequest) {
      setState(() => preparationReport = report);
    }
  }

  Future<void> _disconnect() async {
    _invalidatePreparation();
    await flutterVless.stopVless();
  }

  Future<void> _measureDelay({bool isolatedProfile = false}) async {
    try {
      final connected = vlessStatus.value.state.toUpperCase() == 'CONNECTED';
      final delay = connected && !isolatedProfile
          ? await flutterVless.getConnectedServerDelay()
          : await flutterVless.getServerDelay(
              config: config.text,
              certificateAssetsDirectory: certificateDirectory.text.isEmpty
                  ? null
                  : certificateDirectory.text);
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('$delay ms')));
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Unable to measure delay. Check the profile and connection.',
          ),
        ),
      );
    }
  }

  Future<void> _showProviderDiagnostics() async {
    try {
      final snapshot = await flutterVless.getProviderDebugSnapshot();
      if (!mounted) return;

      final content = snapshot.trim().isEmpty
          ? !pluginOptions.diagnostics.enabled
              ? 'Diagnostics are disabled in Plugin options.'
              : 'No provider diagnostics have been recorded yet.'
          : snapshot;
      await showDialog<void>(
        context: context,
        builder: (dialogContext) => AlertDialog(
          title: const Text('VPN diagnostics'),
          content: SizedBox(
            width: double.maxFinite,
            height: 420,
            child: Scrollbar(
              thumbVisibility: true,
              child: SingleChildScrollView(
                padding: const EdgeInsets.only(right: 12),
                child: SelectableText(
                  content,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: const Text('Close'),
            ),
            ElevatedButton.icon(
              onPressed: snapshot.trim().isEmpty
                  ? null
                  : () async {
                      await Clipboard.setData(ClipboardData(text: snapshot));
                      if (!dialogContext.mounted || !mounted) return;
                      Navigator.of(dialogContext).pop();
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('VPN diagnostics copied')),
                      );
                    },
              icon: const Icon(Icons.copy),
              label: const Text('Copy'),
            ),
          ],
        ),
      );
    } on PlatformException catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Diagnostics unavailable: ${error.message}')),
      );
    }
  }

  Future<void> _importFromClipboard() async {
    if (await Clipboard.hasStrings()) {
      try {
        final text =
            (await Clipboard.getData('text/plain'))?.text?.trim() ?? '';
        final imported = importProfile(text);
        remark = imported.remark ?? 'Imported profile';
        config.text = imported.config;
        if (!mounted) return;
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('Imported')));
      } catch (e) {
        if (!mounted) return;
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Import error: $e')));
      }
    }
  }

  bool _canStop(VlessStatus status) {
    return switch (status.connectionState) {
      VlessConnectionState.connected ||
      VlessConnectionState.connecting ||
      VlessConnectionState.disconnecting =>
        true,
      VlessConnectionState.disconnected ||
      VlessConnectionState.unknown =>
        false,
    };
  }

  Future<void> _showBypassEditor() async {
    final controller = TextEditingController(text: bypassSubnets.join('\n'));
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Colors.grey[900],
        title: const Text('Bypass subnets'),
        content: TextField(
          controller: controller,
          maxLines: 6,
          decoration: const InputDecoration(
            hintText: 'one subnet per line, e.g. 192.168.0.0/13',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              final list = controller.text
                  .split('\n')
                  .map((s) => s.trim())
                  .where((s) => s.isNotEmpty)
                  .toList();
              _invalidatePreparation();
              setState(() {
                bypassSubnets = list;
              });
              Navigator.of(context).pop();
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  String _formatBytes(int? bytes) {
    if (bytes == null) return '-';
    const units = ['B', 'KB', 'MB', 'GB'];
    double b = bytes.toDouble();
    int i = 0;
    while (b >= 1024 && i < units.length - 1) {
      b /= 1024;
      i++;
    }
    return '${b.toStringAsFixed(b >= 10 ? 0 : 1)} ${units[i]}';
  }

  String _formatDuration(int? seconds) {
    if (seconds == null) return '- s';
    return '$seconds s';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Flutter Vless — Example'),
        actions: [
          IconButton(
              icon: const Icon(Icons.tune),
              onPressed: _showOptions,
              tooltip: 'Plugin options'),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                  builder: (_) => Routing(
                      config: config.text,
                      blockedApps: blockedApps,
                      blockedDomains: blockedDomains,
                      onApplyConfig: (String c) => config.text = c,
                      onApplyApps: (List<String> apps) {
                        _invalidatePreparation();
                        blockedApps = apps;
                      },
                      onApplyDomains: (List<String> domains) {
                        _invalidatePreparation();
                        blockedDomains = domains;
                      })),
            ),
            tooltip: 'Routing / Rules',
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            children: [
              Expanded(
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildConfigCard(),
                      const SizedBox(height: 12),
                      _buildStatusCard(),
                      if (preparationReport case final report?) ...[
                        const SizedBox(height: 12),
                        PreparationReportCard(report: report),
                      ],
                      const SizedBox(height: 12),
                      _buildControls(),
                      const SizedBox(height: 52),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async {
          try {
            if (_canStop(vlessStatus.value)) {
              await _disconnect();
            } else {
              await _connect();
            }
          } on PlatformException catch (error) {
            if (!context.mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(
              content: Text(configurationFailureMessage(error)),
            ));
          } on ArgumentError {
            if (!context.mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
              content: Text('Check the configuration and VPN routing choices.'),
            ));
          } on UnsupportedError {
            if (!context.mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
              content: Text(
                'The installed backend does not support these VPN options.',
              ),
            ));
          }
        },
        backgroundColor: Theme.of(context).colorScheme.primary,
        icon: const Icon(
          Icons.power_settings_new,
          color: Colors.black87,
        ),
        label: ValueListenableBuilder<VlessStatus>(
          valueListenable: vlessStatus,
          builder: (context, status, child) {
            return Text(
              _canStop(status) ? 'Disconnect' : 'Connect',
              style: const TextStyle(color: Colors.black87),
            );
          },
        ),
      ),
    );
  }

  Widget _buildConfigCard() {
    return Card(
      color: Colors.grey[900],
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Configuration (JSON)',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            SizedBox(
              height: 140,
              child: TextField(
                controller: config,
                maxLines: null,
                expands: true,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                decoration: const InputDecoration(
                  isDense: true,
                  contentPadding: EdgeInsets.all(12),
                ),
              ),
            ),
            const SizedBox(height: 8),
            ValueListenableBuilder<TextEditingValue>(
              valueListenable: config,
              builder: (context, draft, child) => VpnRoutingPanel(
                config: draft.text,
                proxyOnly: proxyOnly,
                value: vpnRouting,
                onChanged: (value) {
                  _invalidatePreparation();
                  setState(() => vpnRouting = value);
                },
              ),
            ),
            ExpansionTile(
              title: const Text('Certificate files'),
              children: [
                TextField(
                  controller: certificateDirectory,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(
                    labelText: 'Certificate directory (optional)',
                    helperText: 'Absolute path; Apple VPN needs App Group access.',
                  ),
                ),
              ],
            ),
            Wrap(
              spacing: 8,
              children: [
                ElevatedButton.icon(
                  onPressed: _requestPermission,
                  icon: const Icon(Icons.shield),
                  label: const Text('Request Permission'),
                ),
                ElevatedButton.icon(
                  onPressed: _importFromClipboard,
                  icon: const Icon(Icons.paste),
                  label: const Text('Import (clipboard)'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusCard() {
    return Card(
      color: Colors.grey[900],
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: ValueListenableBuilder<VlessStatus>(
          valueListenable: vlessStatus,
          builder: (context, st, child) {
            final state = st.state;
            final durationSeconds = st.duration;
            final upSpeed = st.uploadSpeed;
            final downSpeed = st.downloadSpeed;
            final upTraffic = st.upload;
            final downTraffic = st.download;

            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(state,
                        style: const TextStyle(
                            fontSize: 18, fontWeight: FontWeight.bold)),
                    Chip(
                      backgroundColor:
                          Colors.orangeAccent.shade100.withValues(alpha: 0.15),
                      label: Text(_formatDuration(durationSeconds)),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                        child: _smallInfo(
                            'Up', _formatBytes(upTraffic), '$upSpeed B/s')),
                    const SizedBox(width: 12),
                    Expanded(
                        child: _smallInfo('Down', _formatBytes(downTraffic),
                            '$downSpeed B/s')),
                  ],
                ),
                const SizedBox(height: 12),
                if ((vlessStatus.value.state).toUpperCase() == 'CONNECTED')
                  LinearProgressIndicator(value: null),
                const SizedBox(height: 8),
                Text('Core: ${coreVersion ?? '-'}',
                    style: const TextStyle(fontSize: 12)),
              ],
            );
          },
        ),
      ),
    );
  }

  Widget _buildControls() {
    return Card(
      color: Colors.grey[900],
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Wrap(
          spacing: 8,
          children: [
            ElevatedButton.icon(
              onPressed: _showBypassEditor,
              icon: const Icon(Icons.wifi_off),
              label: const Text('Bypass Subnets'),
            ),
            ElevatedButton.icon(
              onPressed: () {
                _invalidatePreparation();
                setState(() => proxyOnly = !proxyOnly);
              },
              icon: const Icon(Icons.swap_horiz),
              label: Text(proxyOnly ? 'Proxy Only' : 'VPN Mode'),
            ),
            ElevatedButton.icon(
              onPressed: _measureDelay,
              icon: const Icon(Icons.timer),
              label: const Text('Delay'),
            ),
            ElevatedButton.icon(
              onPressed: () => _measureDelay(isolatedProfile: true),
              icon: const Icon(Icons.timer_outlined),
              label: const Text('Profile delay'),
            ),
            ElevatedButton.icon(
              onPressed: _showProviderDiagnostics,
              icon: const Icon(Icons.bug_report_outlined),
              label: const Text('VPN Diagnostics'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _smallInfo(String title, String traffic, String speed) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title,
            style: const TextStyle(fontSize: 12, color: Colors.white70)),
        const SizedBox(height: 6),
        Text(traffic,
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
        const SizedBox(height: 4),
        Text(speed,
            style: const TextStyle(fontSize: 12, color: Colors.white60)),
      ],
    );
  }
}
