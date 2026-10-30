// Opted-in physical-device QA only. The native view is unavailable in normal apps.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

const acceptanceWebChannel = MethodChannel(
  'dev.tfox.flutterXrayExample/acceptanceWeb',
);

Future<String> captureAcceptanceOwnView() async {
  try {
    final result = await acceptanceWebChannel
        .invokeMethod<Object?>('snapshot')
        .timeout(const Duration(seconds: 8));
    return jsonEncode(result);
  } catch (_) {
    return 'acceptance-error';
  }
}

class AcceptanceWebOverlay extends StatefulWidget {
  const AcceptanceWebOverlay({super.key, required this.child});
  final Widget child;

  @override
  State<AcceptanceWebOverlay> createState() => _AcceptanceWebOverlayState();
}

class _AcceptanceWebOverlayState extends State<AcceptanceWebOverlay>
    with WidgetsBindingObserver {
  bool available = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _check();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _check();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  Future<void> _check() async {
    try {
      final value = await acceptanceWebChannel
          .invokeMethod<bool>('available')
          .timeout(const Duration(seconds: 3));
      if (mounted) setState(() => available = value == true);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) => Stack(
    children: [
      widget.child,
      if (available)
        Positioned(
          top: MediaQuery.paddingOf(context).top + 58,
          right: 10,
          child: Material(
            color: Colors.black87,
            child: TextButton(
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => const AcceptanceWebProbePage(),
                ),
              ),
              child: const Text('Website QA'),
            ),
          ),
        ),
    ],
  );
}

class AcceptanceWebProbePage extends StatefulWidget {
  const AcceptanceWebProbePage({super.key});

  @override
  State<AcceptanceWebProbePage> createState() => _AcceptanceWebProbePageState();
}

class _AcceptanceWebProbePageState extends State<AcceptanceWebProbePage> {
  String status = 'Choose a public test site';

  Future<void> _open(String target, {bool inSafari = false}) async {
    try {
      final ok = await acceptanceWebChannel
          .invokeMethod<bool>(inSafari ? 'openSafari' : 'navigate', target)
          .timeout(const Duration(seconds: 3));
      if (mounted) {
        setState(
          () => status = ok == true
              ? (inSafari ? 'Requested browser for $target' : 'Opened $target')
              : 'Unavailable',
        );
      }
    } catch (_) {
      if (mounted) setState(() => status = 'Unavailable');
    }
  }

  @override
  void dispose() {
    acceptanceWebChannel.invokeMethod<void>('stop').catchError((_) {});
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Website QA')),
    body: Column(
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            TextButton(
              onPressed: () => _open('2ip'),
              child: const Text('Open 2ip'),
            ),
            TextButton(
              onPressed: () => _open('tfox'),
              child: const Text('Open tfox'),
            ),
          ],
        ),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            TextButton(
              onPressed: () => _open('2ip', inSafari: true),
              child: const Text('Open 2ip in browser'),
            ),
            TextButton(
              onPressed: () => _open('tfox', inSafari: true),
              child: const Text('Open tfox in browser'),
            ),
          ],
        ),
        Text(status),
        const Expanded(
          child: UiKitView(
            viewType: 'dev.tfox.flutterXrayExample/acceptanceWeb',
          ),
        ),
      ],
    ),
  );
}
