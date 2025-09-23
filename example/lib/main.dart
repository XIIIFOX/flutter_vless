import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/routing.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    final base = ThemeData.dark();
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Flutter Vless — Example',
      theme: base.copyWith(
        colorScheme: base.colorScheme.copyWith(
          primary: Colors.orangeAccent,
          secondary: Colors.orangeAccent.shade200,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final ValueNotifier<VlessStatus> vlessStatus =
      ValueNotifier<VlessStatus>(VlessStatus());

  late final FlutterVless flutterVless = FlutterVless(
    onStatusChanged: (status) {
      vlessStatus.value = status;
    },
  );

  final TextEditingController config = TextEditingController(text: '{}');
  bool proxyOnly = false;
  List<String> bypassSubnets = [];
  List<String> blockedApps = [];
  List<String> blockedDomains = [];
  String? coreVersion;
  String remark = 'Example Remark';

  @override
  void initState() {
    super.initState();

    // Plugin initialization
    flutterVless
        .initializeVless(
      notificationIconResourceType: 'mipmap',
      notificationIconResourceName: 'ic_launcher',
      providerBundleIdentifier: 'dev.tfox.example.flutterVless',
      groupIdentifier: 'group.dev.tfox.example.flutterVless',
    )
        .then((_) async {
      coreVersion = await flutterVless.getCoreVersion();
      setState(() {});
    });
  }

  @override
  void dispose() {
    config.dispose();
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
    if (!await flutterVless.requestPermission()) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('Permission Denied'),
      ));
      return;
    }

    await flutterVless.startVless(
      remark: remark,
      config: config.text,
      proxyOnly: proxyOnly,
      bypassSubnets: bypassSubnets,
      blockedApps: blockedApps,
      notificationDisconnectButtonName: 'DISCONNECT',
    );
  }

  Future<void> _disconnect() async {
    await flutterVless.stopVless();
  }

  Future<void> _importFromClipboard() async {
    if (await Clipboard.hasStrings()) {
      try {
        final text =
            (await Clipboard.getData('text/plain'))?.text?.trim() ?? '';
        final FlutterVlessURL parsed = FlutterVless.parseFromURL(text);
        remark = parsed.remark;
        config.text = parsed.getFullConfiguration();
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
            icon: const Icon(Icons.settings),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                  builder: (_) => Routing(
                      config: config.text,
                      blockedApps: blockedApps,
                      blockedDomains: blockedDomains,
                      onApplyConfig: (String c) => config.text = c,
                      onApplyApps: (List<String> apps) => blockedApps = apps,
                      onApplyDomains: (List<String> domains) =>
                          blockedDomains = domains)),
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
          final state = vlessStatus.value.state.toUpperCase();
          if (state == 'CONNECTED') {
            await _disconnect();
          } else {
            await _connect();
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
            final s = status.state.toUpperCase();
            return Text(
              s == 'CONNECTED' ? 'Disconnect' : 'Connect',
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
          children: [
            ElevatedButton.icon(
              onPressed: _showBypassEditor,
              icon: const Icon(Icons.wifi_off),
              label: const Text('Bypass Subnets'),
            ),
            ElevatedButton.icon(
              onPressed: () => setState(() => proxyOnly = !proxyOnly),
              icon: const Icon(Icons.swap_horiz),
              label: Text(proxyOnly ? 'Proxy Only' : 'VPN Mode'),
            ),
            ElevatedButton.icon(
              onPressed: () async {
                // Get server delay
                int delay;
                if ((vlessStatus.value.state).toUpperCase() == 'CONNECTED') {
                  delay = await flutterVless.getConnectedServerDelay();
                } else {
                  delay =
                      await flutterVless.getServerDelay(config: config.text);
                }
                if (!mounted) return;
                ScaffoldMessenger.of(context)
                    .showSnackBar(SnackBar(content: Text('$delay ms')));
              },
              icon: const Icon(Icons.timer),
              label: const Text('Delay'),
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
