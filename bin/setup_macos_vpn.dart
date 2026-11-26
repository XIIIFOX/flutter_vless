import 'dart:convert';
import 'dart:io';

import 'package:flutter_vless/src/setup/apple_project.dart';

// macOS Packet Tunnel setup generator.
//
// This command edits the host Flutter app's macOS Xcode project so the app can
// embed the `XrayTunnel` Network Extension target. The generated extension is
// intentionally thin:
//
//   import flutter_vless_macos_tunnel_support
//   final class PacketTunnelProvider: FlutterVlessPacketTunnelProvider {}
//
// All real tunnel behavior lives in the SwiftPM product
// `flutter-vless-macos-tunnel-support`. Keeping generated app files tiny avoids
// copying provider code into every app and makes future fixes land through the
// plugin package rather than through manual Xcode edits.
//
// Idempotency is a hard requirement. Users rerun this after changing bundle ids,
// regenerating Flutter macOS files, or upgrading the plugin. Every project edit
// below must tolerate preexisting targets, build phases, package references,
// entitlements, and framework references.

const tunnelModuleName = 'flutter_vless_macos_tunnel_support';
const pluginPackageName = 'flutter_vless_macos';
const pluginPackagesRelativeDir = 'Flutter/ephemeral/Packages/.packages';
const generatedPluginSwiftPackageRelativeDir =
    'Flutter/ephemeral/Packages/FlutterGeneratedPluginSwiftPackage';

void main(List<String> args) async {
  final options = _Options.parse(args);
  if (options.help) {
    _printUsage();
    return;
  }

  final appRoot = Directory(options.projectDir).absolute;
  final macosDir = Directory('${appRoot.path}/macos');
  final pbxprojFile = File('${macosDir.path}/Runner.xcodeproj/project.pbxproj');

  if (!pbxprojFile.existsSync()) {
    _fail(
        'Could not find ${pbxprojFile.path}. Run this from a Flutter app root '
        'or pass --project-dir.');
  }
  if (!options.prepareOnly &&
      (options.bundleId == null || options.groupId == null)) {
    _fail('Both --bundle-id and --group-id are required.');
  }

  final pluginPackagePaths = await _prepareMacOSSwiftPMMetadata(
    appRoot: appRoot,
    macosDir: macosDir,
    deploymentTarget: options.deploymentTarget,
  );
  if (options.prepareOnly) {
    final project = AppleProject(pbxprojFile.readAsStringSync());
    project.prepareSwiftPM(deploymentTarget: options.deploymentTarget);
    pbxprojFile.writeAsStringSync(project.text);

    stdout.writeln('macOS SwiftPM metadata prepared.');
    stdout.writeln('Deployment target: ${options.deploymentTarget}');
    stdout.writeln(
        'Plugin package path: ${pluginPackagePaths.xcodeProjectRelativePath}');
    return;
  }

  _writeTunnelFiles(macosDir, options.groupId!);

  final project = AppleProject(pbxprojFile.readAsStringSync());
  project.configure(
    bundleId: options.bundleId!,
    teamId: options.teamId,
    deploymentTarget: options.deploymentTarget,
    pluginPackageRelativePath: pluginPackagePaths.xcodeProjectRelativePath,
  );
  pbxprojFile.writeAsStringSync(project.text);

  stdout.writeln('macOS VPN setup complete.');
  stdout.writeln('Runner bundle id: ${options.bundleId}');
  stdout.writeln('Tunnel bundle id: ${options.bundleId}.$tunnelTargetName');
  stdout.writeln('App Group: ${options.groupId}');
  stdout.writeln('Next: open macos/Runner.xcworkspace and let Xcode resolve '
      'Swift packages/signing if it asks.');
}

void _printUsage() {
  stdout.writeln('''
Usage:
  dart run flutter_vless:setup_macos_vpn \\
    --bundle-id com.example.myapp \\
    --group-id group.com.example.myapp \\
    --team-id ABCDE12345

Options:
  --project-dir <path>          Flutter app root. Defaults to current directory.
  --deployment-target <value>   Defaults to 13.0.
  --team-id <id>                Optional, but recommended for automatic signing.
  --prepare-only                Only repair generated macOS SwiftPM metadata.
''');
}

class _FlutterSwiftPackagePaths {
  const _FlutterSwiftPackagePaths({
    required this.xcodeProjectRelativePath,
    required this.generatedPackageRelativePath,
  });

  final String xcodeProjectRelativePath;
  final String generatedPackageRelativePath;
}

Future<_FlutterSwiftPackagePaths> _resolveFlutterSwiftPackagePaths({
  required Directory appRoot,
  required Directory macosDir,
}) async {
  final swiftPackageDir = await _resolveFlutterSwiftPackageDir(appRoot);
  _ensureGeneratedPackageLink(appRoot, swiftPackageDir);

  final generatedPackageDir =
      Directory('${macosDir.path}/$generatedPluginSwiftPackageRelativeDir');
  return _FlutterSwiftPackagePaths(
    xcodeProjectRelativePath: _relativePosixPath(
      fromDirectory: macosDir,
      toDirectory: swiftPackageDir,
    ),
    generatedPackageRelativePath: _relativePosixPath(
      fromDirectory: generatedPackageDir,
      toDirectory: swiftPackageDir,
    ),
  );
}

Future<_FlutterSwiftPackagePaths> _prepareMacOSSwiftPMMetadata({
  required Directory appRoot,
  required Directory macosDir,
  required String deploymentTarget,
}) async {
  _clearSwiftPMResolvedFiles(macosDir);
  var pluginPackagePaths = await _resolveFlutterSwiftPackagePaths(
    appRoot: appRoot,
    macosDir: macosDir,
  );

  await _runFlutterMacOSConfigOnly(appRoot);

  pluginPackagePaths = await _resolveFlutterSwiftPackagePaths(
    appRoot: appRoot,
    macosDir: macosDir,
  );
  _patchGeneratedPluginSwiftPackage(
    macosDir,
    pluginPackagePaths.generatedPackageRelativePath,
    deploymentTarget,
  );
  _clearSwiftPMResolvedFiles(macosDir);
  return pluginPackagePaths;
}

Future<void> _runFlutterMacOSConfigOnly(Directory appRoot) async {
  stdout.writeln('Generating Flutter macOS SwiftPM metadata...');
  final result = await Process.run(
    'flutter',
    ['build', 'macos', '--config-only'],
    workingDirectory: appRoot.path,
  );
  stdout.write(result.stdout);
  stderr.write(result.stderr);
  if (result.exitCode != 0) {
    _fail('flutter build macos --config-only failed.');
  }
}

void _clearSwiftPMResolvedFiles(Directory macosDir) {
  if (!macosDir.existsSync()) return;

  for (final entity in macosDir.listSync(recursive: true, followLinks: false)) {
    if (entity is! File || _basename(entity.path) != 'Package.resolved') {
      continue;
    }
    final normalized = entity.path.replaceAll('\\', '/');
    if (normalized.contains('/xcshareddata/swiftpm/')) {
      entity.deleteSync();
    }
  }
}

Future<Directory> _resolveFlutterSwiftPackageDir(Directory appRoot) async {
  final existingPackageConfig = _swiftPackageDirFromPackageConfig(appRoot);
  if (existingPackageConfig != null) return existingPackageConfig;

  stdout.writeln(
      'Flutter generated packages are missing; running flutter pub get...');
  final result = await Process.run(
    'flutter',
    ['pub', 'get'],
    workingDirectory: appRoot.path,
  );
  stdout.write(result.stdout);
  stderr.write(result.stderr);
  if (result.exitCode != 0) {
    _fail('flutter pub get failed.');
  }

  final packageConfig = _swiftPackageDirFromPackageConfig(appRoot);
  if (packageConfig != null) return packageConfig;

  final generated = _findFlutterSwiftPackageDir(appRoot);
  if (generated != null) return generated;

  _fail(
    'Could not find Swift package directory for $pluginPackageName. '
    'Expected Package.swift in Flutter generated packages or package_config.json. '
    'Run flutter clean, flutter pub get, and retry.',
  );
}

Directory? _findFlutterSwiftPackageDir(Directory appRoot) {
  final packagesDir =
      Directory('${appRoot.path}/macos/$pluginPackagesRelativeDir');
  if (!packagesDir.existsSync()) return null;

  final entries = packagesDir
      .listSync(followLinks: false)
      .where((entry) {
        final name = _basename(entry.path);
        return _isFlutterVlessMacOSPackageName(name) &&
            File('${entry.path}/Package.swift').existsSync();
      })
      .map((entry) => Directory(entry.path))
      .toList()
    ..sort((a, b) => _basename(a.path).compareTo(_basename(b.path)));

  for (final entry in entries) {
    if (_basename(entry.path) == pluginPackageName) {
      return entry;
    }
  }
  if (entries.isNotEmpty) {
    return entries.last;
  }

  return null;
}

Directory? _swiftPackageDirFromPackageConfig(Directory appRoot) {
  final packageConfigFile =
      File('${appRoot.path}/.dart_tool/package_config.json');
  if (!packageConfigFile.existsSync()) return null;

  Object? decoded;
  try {
    decoded = jsonDecode(packageConfigFile.readAsStringSync());
  } on FormatException {
    return null;
  }
  if (decoded is! Map<String, Object?>) return null;
  final packages = decoded['packages'];
  if (packages is! List<Object?>) return null;

  for (final package in packages) {
    if (package is! Map<String, Object?> ||
        package['name'] != pluginPackageName) {
      continue;
    }
    final rootUriValue = package['rootUri'];
    if (rootUriValue is! String) return null;
    final packageRoot = _packageRootFromConfigUri(
      packageConfigFile,
      rootUriValue,
    );
    if (packageRoot == null) return null;

    final swiftPackageDir =
        Directory('${packageRoot.path}/macos/$pluginPackageName');
    if (!File('${swiftPackageDir.path}/Package.swift').existsSync()) {
      return null;
    }

    return swiftPackageDir;
  }

  return null;
}

void _ensureGeneratedPackageLink(
  Directory appRoot,
  Directory swiftPackageDir,
) {
  final packagesDir =
      Directory('${appRoot.path}/macos/$pluginPackagesRelativeDir')
        ..createSync(recursive: true);
  final link = Link('${packagesDir.path}/$pluginPackageName');

  switch (FileSystemEntity.typeSync(link.path, followLinks: false)) {
    case FileSystemEntityType.notFound:
      break;
    case FileSystemEntityType.link:
      link.deleteSync();
      break;
    case FileSystemEntityType.directory:
      Directory(link.path).deleteSync(recursive: true);
      break;
    case FileSystemEntityType.file:
      File(link.path).deleteSync();
      break;
    case FileSystemEntityType.pipe:
    case FileSystemEntityType.unixDomainSock:
      _fail('Cannot replace unsupported file system entry: ${link.path}');
  }

  link.createSync(swiftPackageDir.path, recursive: true);
}

Directory? _packageRootFromConfigUri(File packageConfigFile, String rootUri) {
  final uri = Uri.tryParse(rootUri);
  if (uri == null) return null;
  final resolved =
      uri.hasScheme ? uri : packageConfigFile.parent.uri.resolveUri(uri);
  if (resolved.scheme != 'file') return null;
  return Directory.fromUri(resolved);
}

void _patchGeneratedPluginSwiftPackage(
  Directory macosDir,
  String pluginPackageRelativePath,
  String deploymentTarget,
) {
  final packageFile = File(
    '${macosDir.path}/Flutter/ephemeral/Packages/'
    'FlutterGeneratedPluginSwiftPackage/Package.swift',
  );
  if (!packageFile.existsSync()) return;

  final generatedRelativePath = _swiftStringLiteral(pluginPackageRelativePath);
  final source = packageFile.readAsStringSync();
  final updated = source
      .replaceAll(
        RegExp(
          r'\.package\((?=[^)]*(?:name:\s*"flutter_vless_macos"|path:\s*"[^"]*flutter_vless_macos[^"]*"))[^)]*\)',
        ),
        '.package(name: "flutter_vless_macos", path: "$generatedRelativePath")',
      )
      .replaceAll(
        RegExp(r'\.macOS\("[^"]+"\)'),
        '.macOS("$deploymentTarget")',
      );
  if (updated != source) {
    packageFile.writeAsStringSync(updated);
  }
}

String _relativePosixPath({
  required Directory fromDirectory,
  required Directory toDirectory,
}) {
  final from = _splitAbsolutePath(fromDirectory.absolute.path);
  final to = _splitAbsolutePath(toDirectory.absolute.path);

  var common = 0;
  while (common < from.length &&
      common < to.length &&
      from[common] == to[common]) {
    common += 1;
  }

  final parts = [
    for (var i = common; i < from.length; i++) '..',
    ...to.skip(common),
  ];
  return parts.isEmpty ? '.' : parts.join('/');
}

List<String> _splitAbsolutePath(String path) {
  return path
      .replaceAll('\\', '/')
      .split('/')
      .where((part) => part.isNotEmpty && part != '.')
      .toList();
}

String _swiftStringLiteral(String value) {
  return value.replaceAll(r'\', r'\\').replaceAll('"', r'\"');
}

bool _isFlutterVlessMacOSPackageName(String name) {
  return name == pluginPackageName || name.startsWith('$pluginPackageName-');
}

String _basename(String path) {
  final normalized = path.replaceAll('\\', '/');
  final slash = normalized.lastIndexOf('/');
  return slash == -1 ? normalized : normalized.substring(slash + 1);
}

void _writeTunnelFiles(Directory macosDir, String groupId) {
  final tunnelDir = Directory('${macosDir.path}/$tunnelTargetName');
  tunnelDir.createSync(recursive: true);

  // The generated provider is intentionally only a subclass. Do not paste the
  // full provider implementation here: the implementation is shared through the
  // SwiftPM support product so the app receives Packet Tunnel DNS/route fixes
  // when the plugin package updates.
  File('${tunnelDir.path}/PacketTunnelProvider.swift').writeAsStringSync('''
import $tunnelModuleName

final class PacketTunnelProvider: FlutterVlessPacketTunnelProvider {}
''');

  // `NSExtensionPrincipalClass` must point at the generated app-extension
  // module, not at the SwiftPM module. The subclass above is the bridge from the
  // extension bundle into the shared provider implementation.
  File('${tunnelDir.path}/Info.plist').writeAsStringSync('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>NSExtension</key>
\t<dict>
\t\t<key>NSExtensionPointIdentifier</key>
\t\t<string>com.apple.networkextension.packet-tunnel</string>
\t\t<key>NSExtensionPrincipalClass</key>
\t\t<string>\$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
\t</dict>
\t<key>LSMinimumSystemVersion</key>
\t<string>\$(MACOSX_DEPLOYMENT_TARGET)</string>
</dict>
</plist>
''');

  // The extension needs both Network Extension and App Group entitlements:
  //
  // - Network Extension lets macOS run the Packet Tunnel provider.
  // - App Groups let the app and extension share debug logs and future shared
  //   artifacts. Without a matching App Group on both targets, provider debug
  //   fallback files cannot be read from the app process.
  File('${tunnelDir.path}/XrayTunnel.entitlements').writeAsStringSync('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>com.apple.developer.networking.networkextension</key>
\t<array>
\t\t<string>packet-tunnel-provider</string>
\t</array>
\t<key>com.apple.security.application-groups</key>
\t<array>
\t\t<string>$groupId</string>
\t</array>
\t<key>com.apple.security.network.client</key>
\t<true/>
\t<key>com.apple.security.network.server</key>
\t<true/>
</dict>
</plist>
''');

  for (final name in ['DebugProfile.entitlements', 'Release.entitlements']) {
    // Runner also needs the App Group. The packet tunnel itself runs in the
    // appex, but the app process saves NETunnelProviderManager preferences and
    // reads shared debug files.
    _ensureRunnerEntitlement(File('${macosDir.path}/Runner/$name'), groupId);
  }
}

/// Ensures a Runner entitlement plist contains the values needed to manage and
/// observe the tunnel.
///
/// This edits existing files instead of replacing them wholesale because Flutter
/// apps often carry additional sandbox, signing, or app-specific entitlements.
void _ensureRunnerEntitlement(File file, String groupId) {
  if (!file.existsSync()) {
    file.createSync(recursive: true);
    file.writeAsStringSync('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>com.apple.security.app-sandbox</key>
\t<false/>
\t<key>com.apple.developer.networking.networkextension</key>
\t<array>
\t\t<string>packet-tunnel-provider</string>
\t</array>
\t<key>com.apple.security.application-groups</key>
\t<array>
\t\t<string>$groupId</string>
\t</array>
</dict>
</plist>
''');
    return;
  }

  var content = file.readAsStringSync();

  content = _ensureEntitlementArrayValue(
    content: content,
    key: 'com.apple.developer.networking.networkextension',
    value: 'packet-tunnel-provider',
  );
  content = _ensureEntitlementArrayValue(
    content: content,
    key: 'com.apple.security.application-groups',
    value: groupId,
  );
  file.writeAsStringSync(content);
}

String _ensureEntitlementArrayValue({
  required String content,
  required String key,
  required String value,
}) {
  if (content.contains('<key>$key</key>') &&
      content.contains('<string>$value</string>')) {
    return content;
  }

  final arrayPattern = RegExp(
    '\\s*<key>${RegExp.escape(key)}</key>\\s*<array>',
  );
  final arrayMatch = arrayPattern.firstMatch(content);
  if (arrayMatch != null) {
    return content.replaceRange(
      arrayMatch.start,
      arrayMatch.end,
      '${arrayMatch.group(0)!}\n\t\t<string>$value</string>',
    );
  }

  return content.replaceFirst(
    '</dict>',
    '\t<key>$key</key>\n'
        '\t<array>\n'
        '\t\t<string>$value</string>\n'
        '\t</array>\n'
        '</dict>',
  );
}

class _Options {
  const _Options({
    required this.projectDir,
    required this.deploymentTarget,
    required this.bundleId,
    required this.groupId,
    required this.teamId,
    required this.prepareOnly,
    required this.help,
  });

  final String projectDir;
  final String deploymentTarget;
  final String? bundleId;
  final String? groupId;
  final String? teamId;
  final bool prepareOnly;
  final bool help;

  static _Options parse(List<String> args) {
    final values = <String, String>{};
    final flags = <String>{};
    var help = false;
    for (var i = 0; i < args.length; i++) {
      final arg = args[i];
      if (arg == '--help' || arg == '-h') {
        help = true;
        continue;
      }
      if (arg == '--prepare-only') {
        flags.add('prepare-only');
        continue;
      }
      if (!arg.startsWith('--')) {
        _fail('Unknown argument: $arg');
      }
      final equals = arg.indexOf('=');
      if (equals > 0) {
        values[arg.substring(2, equals)] = arg.substring(equals + 1);
        continue;
      }
      if (i + 1 >= args.length) {
        _fail('Missing value for $arg');
      }
      values[arg.substring(2)] = args[++i];
    }

    return _Options(
      projectDir: values['project-dir'] ?? '.',
      deploymentTarget: values['deployment-target'] ?? '13.0',
      bundleId: values['bundle-id'],
      groupId: values['group-id'],
      teamId: values['team-id'],
      prepareOnly: flags.contains('prepare-only'),
      help: help,
    );
  }
}

Never _fail(String message) {
  stderr.writeln('setup_macos_vpn: $message');
  exit(64);
}
