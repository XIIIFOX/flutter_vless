// Debug-only entrypoint for live UI acceptance tests against real native VPNs.
// No mocked channels, profile injection or production entrypoint changes.
import 'package:flutter_driver/driver_extension.dart';

import 'package:flutter_vless_example/main.dart' as example;

Future<void> main() async {
  enableFlutterDriverExtension();
  await example.main();
}
