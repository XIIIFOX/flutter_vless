import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';

import 'apple_project.dart';
import 'common.dart';

typedef SetupPrompt = String? Function(String question, String? suggested);

const _appGroups = 'com.apple.security.application-groups';
const _networkExtension = 'com.apple.developer.networking.networkextension';
const _keychainSetting = 'FlutterVlessKeychainAccessGroup';

void planApple(SetupRequest request, SetupPlan plan, {SetupPrompt? prompt}) {
  final platform = request.platform.name;
  final ios = request.platform == SetupPlatform.ios;
  final minimum = ios ? '15.0' : '13.0';
  final projectPath = '$platform/Runner.xcodeproj/project.pbxproj';
  final original = _requiredText(request, projectPath);
  final crlf = original.contains('\r\n');
  final project = AppleProject(
    original.replaceAll('\r\n', '\n'),
    ios: ios,
    preserveProject: true,
  )..raiseDeploymentFloor(minimum);
  void writeProject() => plan.writeText(
      projectPath, crlf ? project.text.replaceAll('\n', '\r\n') : project.text);

  if (request.mode == SetupMode.proxy) {
    if (!ios) {
      for (final path in project.runnerSettings('CODE_SIGN_ENTITLEMENTS')) {
        final relative = _projectRelative(platform, path);
        final entitlements = _Plist.read(request, relative);
        _allowSandboxNetworking(entitlements);
        plan.writeText(relative, entitlements.text);
      }
    }
    writeProject();
    plan.notes.add(
      'Use proxyOnly: true at runtime. Building the $platform app requires Xcode '
      'on macOS. Flutter generates the SwiftPM integration during the build.',
    );
    return;
  }

  final configurations = project.runnerConfigurationNames;
  if (configurations.length != 3 ||
      !configurations.containsAll(['Debug', 'Profile', 'Release'])) {
    throw SetupException(
      '$projectPath uses custom Runner configurations. Configure the Packet '
      'Tunnel for each scheme using the $platform setup guide.',
    );
  }
  final module = ios
      ? 'flutter_vless_tunnel_support'
      : 'flutter_vless_macos_tunnel_support';
  final tunnel = '$platform/$tunnelTargetName';
  final providerPath = '$tunnel/PacketTunnelProvider.swift';
  final provider = 'import $module\n\n'
      'final class PacketTunnelProvider: FlutterVlessPacketTunnelProvider {}\n';
  final providerFile = File(request.resolve(providerPath));
  final providerExists = providerFile.existsSync();
  if (project.hasTunnel || Directory(request.resolve(tunnel)).existsSync()) {
    if (!project.hasTunnel ||
        !providerExists ||
        providerFile.readAsStringSync().trim() != provider.trim()) {
      throw SetupException(
        '$tunnel already contains a custom or incomplete tunnel. '
        'Review its configuration before adopting the setup generator.',
      );
    }
  }
  final existingBundleIds = project.runnerSettings('PRODUCT_BUNDLE_IDENTIFIER');
  if (!ios && existingBundleIds.isEmpty) {
    final appInfo =
        File(request.resolve('macos/Runner/Configs/AppInfo.xcconfig'));
    if (appInfo.existsSync()) {
      final value = RegExp(
              r'^\s*PRODUCT_BUNDLE_IDENTIFIER\s*=\s*([A-Za-z0-9.-]+)',
              multiLine: true)
          .firstMatch(appInfo.readAsStringSync())
          ?.group(1);
      if (value != null) existingBundleIds.add(value);
    }
  }
  if (existingBundleIds.length > 1) {
    throw SetupException(
        'Runner uses multiple bundle identifiers in $projectPath. '
        'Set up each VPN scheme separately.');
  }
  final bundleId = request.bundleId ??
      existingBundleIds.firstOrNull ??
      prompt?.call('Bundle ID', null);
  if (bundleId == null || !_validIdentifier(bundleId)) {
    throw const SetupException(
        'Provide a literal Apple bundle ID with --bundle-id.');
  }
  final entitlementPath = '$tunnel/$tunnelTargetName.entitlements';
  final tunnelEntitlements = _Plist.read(request, entitlementPath);
  final existingGroups = tunnelEntitlements.strings(_appGroups);
  if (existingGroups.length > 1 && request.groupId == null) {
    throw const SetupException(
        'The tunnel has multiple App Groups. Select one with --group-id.');
  }
  final suggestedGroup = existingGroups.firstOrNull ?? 'group.$bundleId';
  final groupId = request.groupId ??
      existingGroups.firstOrNull ??
      prompt?.call('App Group', suggestedGroup) ??
      suggestedGroup;
  if (!groupId.startsWith('group.') || !_validIdentifier(groupId)) {
    throw const SetupException(
        'Provide an Apple App Group starting with group. using --group-id.');
  }
  final teams = project.runnerSettings('DEVELOPMENT_TEAM')
    ..removeWhere((team) => team.isEmpty);
  if (teams.length > 1) {
    throw SetupException(
        'Runner uses more than one signing team in $projectPath.');
  }
  final teamId = request.teamId ??
      teams.firstOrNull ??
      prompt?.call('Apple Team ID (Enter to defer signing)', null);
  if (teamId != null && !RegExp(r'^[A-Z0-9]{10}$').hasMatch(teamId)) {
    throw const SetupException(
        'Provide a 10-character Apple Team ID with --team-id.');
  }
  if (request.teamId != null &&
      teams.isNotEmpty &&
      teams.single != request.teamId) {
    throw const SetupException(
        'The requested Team ID differs from Runner’s signing team. '
        'Choose the correct team in the project before configuring the tunnel.');
  }
  final packagePath = _flutterPluginPath(request, ios: ios);
  project.configure(
    bundleId: bundleId,
    deploymentTarget: minimum,
    pluginPackageRelativePath: packagePath,
    teamId: teamId,
  );
  project.setMissingRunnerEntitlements(
      ios ? 'Runner/Runner.entitlements' : 'Runner/DebugProfile.entitlements');
  final runnerEntitlements = <_Plist>[];
  for (final path in project.runnerSettings('CODE_SIGN_ENTITLEMENTS')) {
    runnerEntitlements
        .add(_Plist.read(request, _projectRelative(platform, path)));
  }
  for (final entitlements in [tunnelEntitlements, ...runnerEntitlements]) {
    entitlements.addString(_appGroups, groupId);
    entitlements.addString(_networkExtension, 'packet-tunnel-provider');
    if (!ios) _allowSandboxNetworking(entitlements);
  }

  if (ios) {
    final infoPaths = project.runnerSettings('INFOPLIST_FILE');
    if (infoPaths.isEmpty) {
      throw SetupException(
          'Runner has no explicit Info.plist in $projectPath.');
    }
    for (final path in infoPaths) {
      final relative = _projectRelative(platform, path);
      final info = _Plist.read(request, relative, required: true);
      final existing = info.string(_keychainSetting);
      if (existing != null && existing != groupId) {
        final entitlements = [tunnelEntitlements, ...runnerEntitlements];
        if (!entitlements.every((item) =>
            item.strings('keychain-access-groups').contains(existing) ||
            item.strings(_appGroups).contains(existing))) {
          throw SetupException(
            '$relative sets a different $_keychainSetting. Confirm that '
            'Runner and $tunnelTargetName both have access to that group.',
          );
        }
      } else {
        info.setString(_keychainSetting, groupId);
      }
      plan.writeText(relative, info.text);
    }
  }
  for (final entitlements in [tunnelEntitlements, ...runnerEntitlements]) {
    plan.writeText(entitlements.path, entitlements.text);
  }
  final infoPath = '$tunnel/Info.plist';
  if (!File(request.resolve(infoPath)).existsSync()) {
    plan.writeText(infoPath, _extensionInfo(ios: ios));
  } else {
    _Plist.read(request, infoPath, required: true).checkTunnelInfo();
  }
  plan.writeText(providerPath, provider);
  writeProject();
  plan.notes
      .add('Initialize FlutterVless with providerBundleIdentifier: $bundleId '
          'and groupIdentifier: $groupId.');
  if (teamId == null) {
    plan.notes.add('Signing needs an Apple Team ID before deploying the VPN.');
  }
  plan.notes.add(
    'Register the App Group and ensure signing profiles include the VPN capabilities '
    'for Runner and $tunnelTargetName. Build validation and on-device VPN consent are separate.',
  );
}

String _requiredText(SetupRequest request, String path) {
  final file = File(request.resolve(path));
  if (!file.existsSync()) {
    throw SetupException(
        'Missing $path. Add the ${request.platform.name} Flutter platform first.');
  }
  return file.readAsStringSync();
}

String _flutterPluginPath(SetupRequest request, {required bool ios}) {
  const configPath = '.dart_tool/package_config.json';
  final configFile = File(request.resolve(configPath));
  if (!configFile.existsSync()) {
    throw const SetupException(
        'Run flutter pub get to resolve the Apple Swift package.');
  }
  final config = jsonDecode(configFile.readAsStringSync());
  final packages = config is Map ? config['packages'] : null;
  if (packages is! List) {
    throw const SetupException(
        'Invalid .dart_tool/package_config.json. Run flutter pub get.');
  }
  final packageName = ios ? 'flutter_vless' : 'flutter_vless_macos';
  final package = packages
      .whereType<Map>()
      .where((item) => item['name'] == packageName)
      .firstOrNull;
  final rootUri = package?['rootUri'];
  if (rootUri is! String) {
    throw SetupException(
        '$packageName is missing from package_config.json. Run flutter pub get.');
  }
  final uri = configFile.parent.uri.resolve(rootUri);
  if (uri.scheme != 'file') {
    throw SetupException(
        '$packageName has an invalid package path. Run flutter pub get.');
  }
  final root = Directory.fromUri(uri).path;
  if (!File(p.join(root, request.platform.name, packageName, 'Package.swift'))
      .existsSync()) {
    throw SetupException(
        'The resolved $packageName does not contain its Apple Swift package.');
  }
  final basename = p.basename(p.normalize(root));
  final name = basename == packageName || basename.startsWith('$packageName-')
      ? basename
      : packageName;
  return 'Flutter/ephemeral/Packages/.packages/$name';
}

bool _validIdentifier(String id) =>
    RegExp(r'^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$').hasMatch(id);

String _projectRelative(String platform, String path) {
  final relative =
      path.replaceFirst(RegExp(r'^\$\((?:SRCROOT|PROJECT_DIR)\)/'), '');
  if (p.isAbsolute(relative) ||
      p.split(relative).contains('..') ||
      relative.contains(r'$')) {
    throw SetupException('Cannot resolve $platform project file "$path".');
  }
  return p.join(platform, relative);
}

void _allowSandboxNetworking(_Plist plist) {
  plist.enable('com.apple.security.network.client');
  plist.enable('com.apple.security.network.server');
}

const _plistOpen = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
''';
const _plistClose = '</dict>\n</plist>\n';

String _extensionInfo({required bool ios}) => '''$_plistOpen
	<key>NSExtension</key>
	<dict>
		<key>NSExtensionPointIdentifier</key>
		<string>com.apple.networkextension.packet-tunnel</string>
		<key>NSExtensionPrincipalClass</key>
		<string>\$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
	</dict>
${ios ? '' : '\t<key>LSMinimumSystemVersion</key>\n\t<string>\$(MACOSX_DEPLOYMENT_TARGET)</string>\n'}$_plistClose''';

class _Plist {
  _Plist(this.path, this._document, this._contents, this._dictionary);

  factory _Plist.read(SetupRequest request, String path,
      {bool required = false}) {
    final file = File(request.resolve(path));
    final content = required || file.existsSync()
        ? _requiredText(request, path)
        : '$_plistOpen$_plistClose';
    try {
      final document = XmlDocument.parse(content);
      final dictionary = document.rootElement.getElement('dict');
      if (document.rootElement.name.local == 'plist' && dictionary != null) {
        return _Plist(path, document, content, dictionary);
      }
    } on XmlParserException {
      // Report the path without dumping signing or app configuration.
    }
    throw SetupException('Expected an XML dictionary property list at $path.');
  }

  final String path;
  final XmlDocument _document;
  final String _contents;
  final XmlElement _dictionary;
  bool _changed = false;

  String get text => _changed ? _document.toXmlString() : _contents;

  void checkTunnelInfo() {
    final extension = _value('NSExtension');
    if (extension == null ||
        extension.name.local != 'dict' ||
        _value('NSExtensionPointIdentifier', extension)?.innerText !=
            'com.apple.networkextension.packet-tunnel' ||
        _value('NSExtensionPrincipalClass', extension)?.innerText !=
            r'$(PRODUCT_MODULE_NAME).PacketTunnelProvider') {
      throw SetupException(
          '$path does not declare the expected Packet Tunnel provider.');
    }
  }

  XmlElement? _value(String key, [XmlElement? dictionary]) {
    final entries = (dictionary ?? _dictionary).childElements.toList();
    XmlElement? value;
    for (var index = 0; index < entries.length; index += 2) {
      if (index + 1 >= entries.length || entries[index].name.local != 'key') {
        throw SetupException('Invalid property list entry in $path.');
      }
      if (entries[index].innerText == key) {
        if (value != null) _invalid(key);
        value = entries[index + 1];
      }
    }
    return value;
  }

  void _add(String key, XmlElement value) {
    _dictionary.children.addAll([
      XmlText('\t'),
      XmlElement(XmlName('key'), [], [XmlText(key)]),
      XmlText('\n\t'),
      value,
      XmlText('\n'),
    ]);
    _changed = true;
  }

  String? string(String key) {
    final entry = _value(key);
    if (entry == null) return null;
    if (entry.name.local != 'string') _invalid(key);
    return entry.innerText;
  }

  void setString(String key, String content) {
    if (string(key) == content) return;
    final entry = _value(key);
    if (entry != null) {
      _invalid(key);
    }
    _add(key, XmlElement(XmlName('string'), [], [XmlText(content)]));
  }

  List<String> strings(String key) {
    final entry = _value(key);
    if (entry == null) return const [];
    if (entry.name.local != 'array' ||
        entry.childElements.any((item) => item.name.local != 'string')) {
      _invalid(key);
    }
    return entry.childElements.map((item) => item.innerText).toList();
  }

  void addString(String key, String content) {
    if (strings(key).contains(content)) return;
    final entry = XmlElement(XmlName('string'), [], [XmlText(content)]);
    final old = _value(key);
    if (old == null) {
      _add(
          key,
          XmlElement(XmlName('array'), [],
              [XmlText('\n\t\t'), entry, XmlText('\n\t')]));
    } else {
      old.children.addAll([XmlText('\t'), entry, XmlText('\n\t')]);
      _changed = true;
    }
  }

  void enable(String key) {
    final old = _value(key);
    if (old == null) {
      _add(key, XmlElement(XmlName('true'), [], [], true));
    } else if (old.name.local != 'true') {
      if (old.name.local != 'false') _invalid(key);
      old.replace(XmlElement(XmlName('true'), [], [], true));
      _changed = true;
    }
  }

  Never _invalid(String key) =>
      throw SetupException('Unexpected value for $key in $path.');
}
