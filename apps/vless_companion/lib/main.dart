import 'package:flutter/material.dart';

import 'src/companion_controller.dart';
import 'src/local_api_server.dart';

void main() {
  runApp(const CompanionApp());
}

class CompanionApp extends StatelessWidget {
  const CompanionApp({super.key});

  @override
  Widget build(BuildContext context) {
    final base = ThemeData.dark();
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Flutter Vless Companion',
      theme: base.copyWith(
        colorScheme: base.colorScheme.copyWith(
          primary: const Color(0xFF5DD39E),
          secondary: const Color(0xFFFFC857),
          surface: const Color(0xFF151A1E),
        ),
        cardTheme: const CardThemeData(
          color: Color(0xFF1D2429),
          margin: EdgeInsets.zero,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.all(Radius.circular(8)),
          ),
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
          isDense: true,
        ),
      ),
      home: const CompanionHome(),
    );
  }
}

class CompanionHome extends StatefulWidget {
  const CompanionHome({super.key});

  @override
  State<CompanionHome> createState() => _CompanionHomeState();
}

class _CompanionHomeState extends State<CompanionHome> {
  final CompanionController _controller = CompanionController();
  final TextEditingController _input = TextEditingController();
  LocalApiServer? _apiServer;
  String? _error;
  bool _busy = false;
  bool _setSystemProxy = false;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  @override
  void dispose() {
    _input.dispose();
    _apiServer?.dispose();
    _controller.dispose();
    super.dispose();
  }

  Future<void> _bootstrap() async {
    try {
      await _controller.initialize();
      final server = LocalApiServer(controller: _controller);
      await server.start();
      setState(() {
        _apiServer = server;
      });
    } catch (error) {
      setState(() {
        _error = error.toString();
      });
    }
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } catch (error) {
      setState(() {
        _error = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
        });
      }
    }
  }

  Future<void> _importInput() async {
    await _run(() async {
      await _controller.importProfile(_input.text);
    });
  }

  Future<void> _connect() async {
    await _run(() async {
      if (_controller.profiles.isEmpty && _input.text.trim().isNotEmpty) {
        await _controller.importProfile(_input.text);
      }
      await _controller.connect(setSystemProxy: _setSystemProxy);
    });
  }

  Future<void> _disconnect() async {
    await _run(_controller.disconnect);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Flutter Vless Companion'),
        actions: [
          IconButton(
            onPressed: _busy ? null : _disconnect,
            icon: const Icon(Icons.power_settings_new),
            tooltip: 'Disconnect',
          ),
        ],
      ),
      body: SafeArea(
        child: AnimatedBuilder(
          animation: _controller,
          builder: (context, _) {
            return SelectionArea(
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _StatusPanel(
                    controller: _controller,
                    apiServer: _apiServer,
                    error: _error,
                  ),
                  const SizedBox(height: 12),
                  _ImportPanel(
                    controller: _input,
                    busy: _busy,
                    setSystemProxy: _setSystemProxy,
                    onSetSystemProxyChanged: (value) {
                      setState(() {
                        _setSystemProxy = value;
                      });
                    },
                    onImport: _importInput,
                    onConnect: _connect,
                    onDisconnect: _disconnect,
                  ),
                  const SizedBox(height: 12),
                  _ProfilesPanel(controller: _controller),
                ],
              ),
            );
          },
        ),
      ),
    );
  }
}

class _StatusPanel extends StatelessWidget {
  const _StatusPanel({
    required this.controller,
    required this.apiServer,
    required this.error,
  });

  final CompanionController controller;
  final LocalApiServer? apiServer;
  final String? error;

  @override
  Widget build(BuildContext context) {
    final endpoint = controller.proxyEndpoint;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    controller.status.state,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ),
                Chip(label: Text(endpoint.label)),
              ],
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 16,
              runSpacing: 8,
              children: [
                _Metric(
                  label: 'Upload',
                  value: '${controller.status.uploadSpeed} B/s',
                ),
                _Metric(
                  label: 'Download',
                  value: '${controller.status.downloadSpeed} B/s',
                ),
                _Metric(
                  label: 'Elapsed',
                  value: '${controller.status.duration}s',
                ),
                _Metric(label: 'API', value: apiServer?.origin ?? 'starting'),
              ],
            ),
            if (apiServer != null) ...[
              const SizedBox(height: 8),
              Text(
                'State file: ${CompanionStateFile.path}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
            if (error != null) ...[
              const SizedBox(height: 12),
              Text(error!, style: const TextStyle(color: Color(0xFFFF6B6B))),
            ],
          ],
        ),
      ),
    );
  }
}

class _ImportPanel extends StatelessWidget {
  const _ImportPanel({
    required this.controller,
    required this.busy,
    required this.setSystemProxy,
    required this.onSetSystemProxyChanged,
    required this.onImport,
    required this.onConnect,
    required this.onDisconnect,
  });

  final TextEditingController controller;
  final bool busy;
  final bool setSystemProxy;
  final ValueChanged<bool> onSetSystemProxyChanged;
  final VoidCallback onImport;
  final VoidCallback onConnect;
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Profile input',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 10),
            SizedBox(
              height: 150,
              child: TextField(
                controller: controller,
                maxLines: null,
                expands: true,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                decoration: const InputDecoration(
                  hintText:
                      'vless://, vmess://, trojan://, ss://, socks://, subscription, or Xray JSON',
                ),
              ),
            ),
            const SizedBox(height: 10),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: setSystemProxy,
              onChanged: busy ? null : onSetSystemProxyChanged,
              title: const Text('Set system proxy'),
              subtitle: const Text(
                'Off keeps Xray local for browser-extension controlled proxying.',
              ),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                ElevatedButton.icon(
                  onPressed: busy ? null : onImport,
                  icon: const Icon(Icons.playlist_add),
                  label: const Text('Import'),
                ),
                ElevatedButton.icon(
                  onPressed: busy ? null : onConnect,
                  icon: const Icon(Icons.link),
                  label: const Text('Connect'),
                ),
                OutlinedButton.icon(
                  onPressed: busy ? null : onDisconnect,
                  icon: const Icon(Icons.link_off),
                  label: const Text('Disconnect'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _ProfilesPanel extends StatelessWidget {
  const _ProfilesPanel({required this.controller});

  final CompanionController controller;

  @override
  Widget build(BuildContext context) {
    final profiles = controller.profiles;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Profiles', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            if (profiles.isEmpty)
              const Text('No imported profiles yet.')
            else
              for (final profile in profiles)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(profile.remark),
                  subtitle: Text(profile.id),
                  trailing: controller.activeProfile?.id == profile.id
                      ? const Icon(Icons.check_circle)
                      : null,
                ),
          ],
        ),
      ),
    );
  }
}

class _Metric extends StatelessWidget {
  const _Metric({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 180,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 2),
          Text(value, overflow: TextOverflow.ellipsis),
        ],
      ),
    );
  }
}
