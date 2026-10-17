import 'dart:io';

/// Creates an optional WidgetKit target. Requires macOS and CocoaPods' xcodeproj gem.
Future<void> main(List<String> args) async {
  if (args.contains('--help')) {
    stdout.writeln(
        'dart run flutter_vless:setup_apple_controls --platform ios|macos '
        '--project-dir . --bundle-id com.example.app --group-id group.com.example.app [--team-id TEAM]');
    return;
  }
  final script =
      File.fromUri(Platform.script.resolve('setup_apple_controls.rb'));
  final process = await Process.start('ruby', [script.path, ...args],
      mode: ProcessStartMode.inheritStdio);
  exitCode = await process.exitCode;
}
