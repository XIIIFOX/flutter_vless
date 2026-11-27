import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

import 'android.dart';
import 'apple.dart';
import 'common.dart';
import 'windows.dart';
import 'wintun_stage.dart';

Future<void> runSetupCli(List<String> arguments, {bool doctor = false}) async {
  final command = doctor ? 'doctor' : 'setup';
  if (arguments.contains('--help') || arguments.contains('-h')) {
    stdout.writeln('''
Usage: dart run flutter_vless:$command --platform macos|android|windows|ios [--proxy|--vpn]

  --project-dir PATH   Existing Flutter app; defaults to the current directory.
  --proxy              Prepare local/system proxy mode (default).
  --vpn                Prepare VPN mode.
  --dry-run            Print files and actions without applying them.
  --non-interactive    Suppress interactive prompts.
  --bundle-id ID       Apple VPN app bundle ID; detected when possible.
  --group-id ID        Apple VPN App Group; defaults to group.<bundle-id>.
  --team-id ID         Apple VPN signing team; reuse Runner's team when set.
  --arch x64|arm64     Windows target architecture; uses host arch on Windows.
  --runtime-dir PATH   Windows directory containing a user-supplied runtime.
  --stage-wintun       Prepare the pinned Wintun driver on elevated Windows x64 VPN setup.
''');
    return;
  }
  try {
    final flags = _parse(arguments);
    if (flags.containsKey('proxy') && flags.containsKey('vpn')) {
      throw const SetupException('Choose either --proxy or --vpn.');
    }
    final platformName = flags['platform'];
    final platform = SetupPlatform.values
        .where((item) => item.name == platformName)
        .firstOrNull;
    if (platform == null) {
      throw const SetupException(
          'Choose --platform macos, android, windows or ios.');
    }
    final mode = flags.containsKey('vpn') ? SetupMode.vpn : SetupMode.proxy;
    final isApple =
        platform == SetupPlatform.macos || platform == SetupPlatform.ios;
    if ((!isApple || mode != SetupMode.vpn) &&
        ['bundle-id', 'group-id', 'team-id'].any(flags.containsKey)) {
      throw const SetupException(
          'Apple signing identifiers apply to macOS or iOS with --vpn.');
    }
    if (platform != SetupPlatform.windows &&
        ['arch', 'runtime-dir'].any(flags.containsKey)) {
      throw const SetupException('--arch and --runtime-dir apply to Windows.');
    }
    final stageWintun = flags.containsKey('stage-wintun');
    if (stageWintun &&
        (platform != SetupPlatform.windows || mode != SetupMode.vpn)) {
      throw const SetupException(
          '--stage-wintun requires --platform windows --vpn.');
    }
    final directory = Directory(flags['project-dir'] ?? '.');
    if (!directory.existsSync()) {
      throw SetupException(
          'Project directory does not exist: ${directory.path}.');
    }
    final request = SetupRequest(
      root: Directory(directory.resolveSymbolicLinksSync()),
      platform: platform,
      mode: mode,
      bundleId: flags['bundle-id'],
      groupId: flags['group-id'],
      teamId: flags['team-id'],
      architecture: flags['arch'],
      runtimeDirectory: flags['runtime-dir'],
    );
    final dryRun = flags.containsKey('dry-run');
    final clock = !doctor &&
            !dryRun &&
            Platform.environment['FLUTTER_VLESS_SETUP_TIMING'] == '1'
        ? (Stopwatch()..start())
        : null;
    final timings = <String, int>{'runtime_prepare': 0, 'project_apply': 0};
    final wintunPhases = <String, int>{};
    _checkProject(request, isApple: isApple);
    final plan = SetupPlan(request);
    final interactive = !doctor &&
        !dryRun &&
        !flags.containsKey('non-interactive') &&
        stdin.hasTerminal;
    switch (platform) {
      case SetupPlatform.macos:
      case SetupPlatform.ios:
        planApple(request, plan, prompt: interactive ? _prompt : null);
      case SetupPlatform.android:
        planAndroid(request, plan);
      case SetupPlatform.windows:
        planWindows(request, plan);
    }
    final title = '${platform.name} ${mode.name}';
    if (clock != null) timings['project_plan'] = clock.elapsedMilliseconds;
    WindowsWintunStaging? wintun;
    Future<void> inspectWintun() async {
      wintun = await inspectWindowsWintun(request, run: (action, dll) async {
        final start = clock?.elapsedMilliseconds;
        final result = await runWindowsWintunCommand(action, dll,
            recordTiming: clock == null
                ? null
                : (phases) {
                    for (final entry in phases.entries) {
                      wintunPhases['${action}_${entry.key}'] = entry.value;
                    }
                  });
        if (clock != null) {
          timings['wintun_$action'] = clock.elapsedMilliseconds - start!;
        }
        return result;
      });
    }

    final projectReady =
        plan.changedPaths.isEmpty && plan.pendingActions.isEmpty;
    final inspectDuringPreparation =
        stageWintun && !doctor && !dryRun && !projectReady;
    if (stageWintun && !inspectDuringPreparation) await inspectWintun();
    final ready = projectReady && (wintun?.present ?? true);
    if (ready) {
      stdout.writeln('$title: project configuration is up to date.');
    } else if (doctor || dryRun) {
      stdout.writeln('$title: setup changes pending.');
      for (final path in plan.changedPaths) {
        stdout.writeln('  Edit $path');
      }
      for (final action in plan.pendingActions) {
        stdout.writeln('  $action');
      }
      if (wintun?.present == false) {
        stdout.writeln('  Stage the pinned Wintun driver.');
      }
      if (doctor) exitCode = 1;
    } else {
      for (final action in plan.pendingActions) {
        stdout.writeln('  $action');
      }
      await plan.apply(
          inspect: inspectDuringPreparation ? inspectWintun : null,
          recordTiming: clock == null
              ? null
              : (stage, elapsed) {
                  timings[stage] = elapsed;
                });
      stdout.writeln('$title: project configured.');
      for (final path in plan.changedPaths) {
        stdout.writeln('  Updated $path');
      }
      final pendingWintun = wintun;
      if (pendingWintun != null && !pendingWintun.present) {
        final staged = await pendingWintun.stage();
        stdout.writeln(
            staged ? 'Wintun driver staged.' : 'Wintun driver already staged.');
      }
    }
    if (wintun?.present ?? false) {
      stdout.writeln('Wintun driver already staged.');
    }
    for (final note in plan.notes) {
      stdout.writeln(note);
    }
    if (clock != null) {
      stdout.writeln('WINDOWS_SETUP_TIMING ${jsonEncode({
            ...timings,
            'total': clock.elapsedMilliseconds,
            if (stageWintun) 'wintun_phases': wintunPhases,
          })}');
    }
  } on SetupException catch (error) {
    stderr.writeln('flutter_vless $command: ${error.message}');
    exitCode = 64;
  } on YamlException {
    stderr.writeln('flutter_vless $command: invalid pubspec.yaml.');
    exitCode = 65;
  } on FormatException {
    stderr.writeln('flutter_vless $command: invalid project configuration. '
        'Check pubspec.yaml and .dart_tool/package_config.json.');
    exitCode = 65;
  } on FileSystemException catch (error) {
    stderr.writeln('flutter_vless $command: ${error.message} (${error.path}).');
    exitCode = 74;
  }
}

Map<String, String?> _parse(List<String> args) {
  const switches = {
    'proxy',
    'vpn',
    'dry-run',
    'non-interactive',
    'stage-wintun'
  };
  const options = {
    'platform',
    'project-dir',
    'bundle-id',
    'group-id',
    'team-id',
    'arch',
    'runtime-dir',
  };
  final result = <String, String?>{};
  for (var index = 0; index < args.length; index++) {
    final argument = args[index];
    if (!argument.startsWith('--')) {
      throw SetupException('Unknown argument $argument. Use --help.');
    }
    final equals = argument.indexOf('=');
    final key = argument.substring(2, equals == -1 ? null : equals);
    if (result.containsKey(key)) {
      throw SetupException('Duplicate option --$key.');
    }
    if (switches.contains(key) && equals == -1) {
      result[key] = null;
      continue;
    }
    if (!options.contains(key)) {
      throw SetupException('Unknown option $argument. Use --help.');
    }
    final value = equals == -1
        ? (index + 1 < args.length ? args[++index] : '')
        : argument.substring(equals + 1);
    if (value.trim().isEmpty || (equals == -1 && value.startsWith('--'))) {
      throw SetupException('Missing value for --$key.');
    }
    result[key] = value;
  }
  return result;
}

void _checkProject(SetupRequest request, {required bool isApple}) {
  final pubspec = File(request.resolve('pubspec.yaml'));
  if (!pubspec.existsSync()) {
    throw const SetupException(
        'Run this from a Flutter app or pass --project-dir.');
  }
  final yaml = loadYaml(pubspec.readAsStringSync());
  final dependencies = yaml is Map ? yaml['dependencies'] : null;
  if (dependencies is! Map || !dependencies.containsKey('flutter_vless')) {
    throw const SetupException(
        'First add flutter_vless with flutter pub add flutter_vless.');
  }
  final platform = request.platform.name;
  if (!Directory(request.resolve(platform)).existsSync()) {
    throw SetupException(
        'Missing $platform folder. Run flutter create --platforms=$platform .');
  }
  if (!isApple) return;
  final flutter = yaml['flutter'];
  final settings = flutter is Map ? flutter['config'] : null;
  if (settings is Map && settings['enable-swift-package-manager'] == false) {
    throw const SetupException(
        'SwiftPM is disabled in this app. Enable SwiftPM in '
        'pubspec.yaml or follow the manual CocoaPods setup guide.');
  }
  final config =
      File(request.resolve(p.join('.dart_tool', 'package_config.json')));
  if (config.existsSync()) {
    final decoded = jsonDecode(config.readAsStringSync());
    final version = decoded is Map ? decoded['flutterVersion'] : null;
    if (version is String) {
      final parts = version.split('.').take(2).map(int.tryParse).toList();
      if (parts.length == 2 &&
          parts[0] != null &&
          parts[1] != null &&
          (parts[0]! < 3 || (parts[0] == 3 && parts[1]! < 44))) {
        throw const SetupException(
            'Apple setup requires Flutter 3.44+ with SwiftPM. '
            'Update Flutter or use the platform setup guide.');
      }
    }
  }
}

String? _prompt(String question, String? suggested) {
  stdout.write('$question${suggested == null ? '' : ' [$suggested]'}: ');
  final answer = stdin.readLineSync()?.trim();
  return answer == null || answer.isEmpty ? suggested : answer;
}
