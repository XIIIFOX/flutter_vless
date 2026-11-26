import 'dart:math';

import 'common.dart';

const tunnelTargetName = 'XrayTunnel';

String _pbxStringLiteral(String value) {
  final escaped = value.replaceAll(r'\', r'\\').replaceAll('"', r'\"');
  if (RegExp(r'^[A-Za-z0-9_./$-]+$').hasMatch(value)) {
    return escaped;
  }
  return '"$escaped"';
}

class AppleProject {
  AppleProject(this.text, {this.ios = false, this.preserveProject = false});

  String text;
  final bool ios;
  final bool preserveProject;
  final _random = Random.secure();

  String get tunnelProductName => ios
      ? 'flutter-vless-tunnel-support'
      : 'flutter-vless-macos-tunnel-support';
  String get _deploymentKey =>
      ios ? 'IPHONEOS_DEPLOYMENT_TARGET' : 'MACOSX_DEPLOYMENT_TARGET';

  String get _projectId => _requiredMatch(
        RegExp(r'rootObject = ([A-Z0-9]{24})(?: /\*[^*]*\*/)?;'),
        'project root',
      );

  String get _runnerId =>
      _targetId('Runner') ?? _projectError('Runner target is missing.');

  List<String> _targetConfigs(String id) => _configurationIds(
        _requiredMatchIn(
          _objectBlock(id).text,
          RegExp(r'buildConfigurationList = ([A-Z0-9]{24})(?: /\*)?'),
          'build configuration list',
        ),
      );

  bool get hasTunnel => _targetId(tunnelTargetName) != null;

  Set<String> runnerSettings(String key) => _targetConfigs(_runnerId)
      .map((id) => _setting(id, key))
      .whereType<String>()
      .toSet();

  Set<String> get runnerConfigurationNames => _targetConfigs(_runnerId)
      .map((id) => _requiredMatchIn(_objectBlock(id).text,
          RegExp(r'\bname = "?(.*?)"?;'), 'build configuration name'))
      .toSet();

  void setMissingRunnerEntitlements(String path) {
    for (final id in _targetConfigs(_runnerId)) {
      if (_setting(id, 'CODE_SIGN_ENTITLEMENTS') == null) {
        _setBuildSetting(id, 'CODE_SIGN_ENTITLEMENTS', _pbxStringLiteral(path));
      }
    }
  }

  void raiseDeploymentFloor(String minimum) {
    for (final id in _targetConfigs(_projectId)) {
      _raiseDeployment(id, minimum);
    }
    for (final id in _targetConfigs(_runnerId)) {
      if (_setting(id, _deploymentKey) != null) _raiseDeployment(id, minimum);
    }
  }

  String? _setting(String id, String key) {
    final value =
        RegExp('^\\s*${RegExp.escape(key)} = ([^;]+);', multiLine: true)
            .firstMatch(_objectBlock(id).text)
            ?.group(1)
            ?.trim();
    if (value != null && value.startsWith('"') && value.endsWith('"')) {
      return value.substring(1, value.length - 1);
    }
    return value;
  }

  void _raiseDeployment(String id, String minimum) {
    final current = _setting(id, _deploymentKey);
    if (current == null || _versionLessThan(current, minimum)) {
      _setBuildSetting(id, _deploymentKey, minimum);
    }
  }

  /// Applies project-level settings needed by the macOS SwiftPM plugin package.
  void prepareSwiftPM({required String deploymentTarget}) {
    _patchAllMacOSDeploymentTargets(deploymentTarget);
  }

  /// Applies all Xcode project changes required for macOS Packet Tunnel mode.
  ///
  /// The method intentionally avoids Xcodeproj dependencies and edits the
  /// project text directly because this command must run from a plain Dart
  /// environment in user apps. Helpers below are narrow and idempotent: each
  /// `_ensure...` method first searches for an existing object before inserting
  /// a new one.
  void configure({
    required String bundleId,
    required String deploymentTarget,
    required String pluginPackageRelativePath,
    String? teamId,
  }) {
    final projectId = _projectId;
    final projectBlock = _objectBlock(projectId);
    final mainGroupId = _requiredMatchIn(
      projectBlock.text,
      RegExp(r'mainGroup = ([A-Z0-9]{24})(?: /\*)?'),
      'main group',
    );
    final productGroupId = _requiredMatchIn(
      projectBlock.text,
      RegExp(r'productRefGroup = ([A-Z0-9]{24}) /\*'),
      'products group',
    );
    final runnerTargetId = _targetId('Runner') ??
        (throw StateError('Could not find Runner target in project.pbxproj.'));
    final tunnelTargetId = _targetId(tunnelTargetName) ?? _id();

    final supportPackageId =
        _ensureLocalPackageReference(pluginPackageRelativePath);
    final supportProductId = _ensurePackageProductDependency(
      productName: tunnelProductName,
      packageId: supportPackageId,
      pluginPackageRelativePath: pluginPackageRelativePath,
    );
    final supportBuildFileId = _ensureProductBuildFile(
      productName: tunnelProductName,
      productId: supportProductId,
    );

    final networkFileId =
        _ensureFrameworkFileReference('NetworkExtension.framework');
    final networkBuildFileId = _ensureFrameworkBuildFile(
      name: 'NetworkExtension.framework',
      fileId: networkFileId,
    );

    final tunnelProductFileId = _ensureProductFileReference();
    final tunnelEmbedBuildFileId =
        _ensureExtensionEmbedBuildFile(tunnelProductFileId);
    final proxyId = _ensureContainerProxy(projectId, tunnelTargetId);
    final dependencyId = _ensureTargetDependency(proxyId, tunnelTargetId);

    String? tunnelFrameworksId;
    String? tunnelSourcesId;
    String? tunnelResourcesId;
    String? tunnelConfigListId;
    String? tunnelGroupId;

    if (_targetId(tunnelTargetName) == null) {
      tunnelFrameworksId = _id();
      tunnelSourcesId = _id();
      tunnelResourcesId = _id();
      tunnelConfigListId = _id();
      tunnelGroupId = _id();
      final providerFileId = _id();
      final infoFileId = _id();
      final entitlementsFileId = _id();
      final providerBuildFileId = _id();

      _addBuildFile(
        providerBuildFileId,
        'PacketTunnelProvider.swift in Sources',
        'fileRef = $providerFileId /* PacketTunnelProvider.swift */;',
      );
      _addFileReference(
        providerFileId,
        'PacketTunnelProvider.swift',
        'lastKnownFileType = sourcecode.swift; path = PacketTunnelProvider.swift; sourceTree = "<group>";',
      );
      _addFileReference(
        infoFileId,
        'Info.plist',
        'lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>";',
      );
      _addFileReference(
        entitlementsFileId,
        'XrayTunnel.entitlements',
        'lastKnownFileType = text.plist.entitlements; path = XrayTunnel.entitlements; sourceTree = "<group>";',
      );
      _addGroup(
        tunnelGroupId,
        tunnelTargetName,
        [
          '$providerFileId /* PacketTunnelProvider.swift */',
          '$infoFileId /* Info.plist */',
          '$entitlementsFileId /* XrayTunnel.entitlements */',
        ],
        path: tunnelTargetName,
      );
      _appendListEntry(
          mainGroupId, 'children', '$tunnelGroupId /* $tunnelTargetName */');

      _addFrameworksPhase(tunnelFrameworksId, [
        '$supportBuildFileId /* $tunnelProductName in Frameworks */',
        '$networkBuildFileId /* NetworkExtension.framework in Frameworks */',
      ]);
      _addSourcesPhase(tunnelSourcesId, [
        '$providerBuildFileId /* PacketTunnelProvider.swift in Sources */',
      ]);
      _addResourcesPhase(tunnelResourcesId);
      _addNativeTarget(
        tunnelTargetId,
        tunnelConfigListId,
        tunnelSourcesId,
        tunnelFrameworksId,
        tunnelResourcesId,
        tunnelProductFileId,
        supportProductId,
      );
      _addBuildConfigurationList(
        tunnelConfigListId,
        'PBXNativeTarget "$tunnelTargetName"',
        bundleId,
        deploymentTarget,
        teamId,
      );
      _appendListEntry(
          projectId, 'targets', '$tunnelTargetId /* $tunnelTargetName */');
      _appendListEntry(productGroupId, 'children',
          '$tunnelProductFileId /* $tunnelTargetName.appex */');
      _ensureTargetAttributes(projectId, tunnelTargetId);
    }

    final actualTunnelTargetId = _targetId(tunnelTargetName)!;
    final tunnelBlock = _objectBlock(actualTunnelTargetId).text;
    tunnelFrameworksId ??= _requiredMatchIn(
      tunnelBlock,
      RegExp(r'([A-Z0-9]{24}) /\* Frameworks \*/'),
      'XrayTunnel Frameworks phase',
    );
    _appendListEntry(
      actualTunnelTargetId,
      'packageProductDependencies',
      '$supportProductId /* $tunnelProductName */',
    );
    _appendListEntry(
      tunnelFrameworksId,
      'files',
      '$supportBuildFileId /* $tunnelProductName in Frameworks */',
    );
    _appendListEntry(
      tunnelFrameworksId,
      'files',
      '$networkBuildFileId /* NetworkExtension.framework in Frameworks */',
    );

    // Older local setups embedded XRay/Tun2Socks frameworks manually. The
    // supported path now links the SwiftPM support product, which brings the
    // correct Xray and HEV bindings together with the shared provider code.
    // Leaving stale manual frameworks in the extension target can cause duplicate
    // symbols, wrong architectures, or a provider that compiles against old
    // tunnel-support assumptions.
    if (!preserveProject) {
      _removeFrameworkFromTarget(actualTunnelTargetId, 'XRay.xcframework');
      _removeFrameworkFromTarget(actualTunnelTargetId, 'Tun2SocksKit');
      _removeProjectFileReferences('XRay.xcframework');
    }

    final embedPhaseId = _ensureEmbedExtensionsPhase(runnerTargetId);
    if (ios) _orderIosEmbedPhase(runnerTargetId, embedPhaseId);
    _appendListEntry(
      embedPhaseId,
      'files',
      '$tunnelEmbedBuildFileId /* $tunnelTargetName.appex in Embed Foundation Extensions */',
    );
    _appendListEntry(
      runnerTargetId,
      'dependencies',
      '$dependencyId /* PBXTargetDependency */',
    );

    _appendListEntry(
      projectId,
      'packageReferences',
      '$supportPackageId /* XCLocalSwiftPackageReference "$pluginPackageRelativePath" */',
    );
    // Normalize deployment targets everywhere. Mixed generated 10.15 settings
    // can leak into SwiftPM/CocoaPods builds and produce warnings or extension
    // build failures even when Runner itself is configured for macOS 13+.
    if (preserveProject) {
      raiseDeploymentFloor(deploymentTarget);
    } else {
      prepareSwiftPM(deploymentTarget: deploymentTarget);
    }
    _patchRunnerBuildSettings(bundleId, deploymentTarget, teamId);
    _patchTunnelBuildSettings(bundleId, deploymentTarget, teamId);
  }

  String _ensureLocalPackageReference(String pluginPackageRelativePath) {
    final packageName = ios ? 'flutter_vless' : 'flutter_vless_macos';
    final existing = RegExp(
      r'([A-Z0-9]{24}) /\* XCLocalSwiftPackageReference "[^"]*" \*/ = \{\s*isa = XCLocalSwiftPackageReference;\s*relativePath = ([^;]+);',
      multiLine: true,
    ).allMatches(text).where((reference) {
      final path = reference.group(2)!.replaceAll('"', '');
      final name = path.split('/').last;
      return name == packageName || name.startsWith('$packageName-');
    }).firstOrNull;
    if (existing != null) {
      final id = existing.group(1)!;
      _patchLocalPackageReference(id, pluginPackageRelativePath);
      return id;
    }

    final id = _id();
    _insertObject(
      'XCLocalSwiftPackageReference',
      '''
\t\t$id /* XCLocalSwiftPackageReference "$pluginPackageRelativePath" */ = {
\t\t\tisa = XCLocalSwiftPackageReference;
\t\t\trelativePath = ${_pbxStringLiteral(pluginPackageRelativePath)};
\t\t};
''',
    );
    return id;
  }

  void _patchLocalPackageReference(
    String id,
    String pluginPackageRelativePath,
  ) {
    final block = _objectBlock(id);
    final updatedBlock = block.text.replaceFirst(
      RegExp(r'relativePath = [^;]+;'),
      'relativePath = ${_pbxStringLiteral(pluginPackageRelativePath)};',
    );
    text = text.replaceRange(block.start, block.end, updatedBlock);
    _patchLocalPackageReferenceComments(id, pluginPackageRelativePath);
  }

  void _patchLocalPackageReferenceComments(
    String id,
    String pluginPackageRelativePath,
  ) {
    text = text.replaceAll(
      RegExp(
        '$id /\\* XCLocalSwiftPackageReference "[^"]*" \\*/',
      ),
      '$id /* XCLocalSwiftPackageReference "$pluginPackageRelativePath" */',
    );
  }

  String _ensurePackageProductDependency({
    required String productName,
    required String packageId,
    required String pluginPackageRelativePath,
  }) {
    final existing = RegExp(
      '([A-Z0-9]{24}) /\\* $productName \\*/ = \\{[\\s\\S]*?productName = $productName;',
    ).firstMatch(text);
    if (existing != null) {
      final id = existing.group(1)!;
      _patchPackageProductDependency(
        id: id,
        packageId: packageId,
        pluginPackageRelativePath: pluginPackageRelativePath,
      );
      return id;
    }

    final id = _id();
    _insertObject(
      'XCSwiftPackageProductDependency',
      '''
\t\t$id /* $productName */ = {
\t\t\tisa = XCSwiftPackageProductDependency;
\t\t\tpackage = $packageId /* XCLocalSwiftPackageReference "$pluginPackageRelativePath" */;
\t\t\tproductName = $productName;
\t\t};
''',
    );
    return id;
  }

  void _patchPackageProductDependency({
    required String id,
    required String packageId,
    required String pluginPackageRelativePath,
  }) {
    final block = _objectBlock(id);
    final updatedBlock = block.text.replaceFirst(
      RegExp(
        r'package = [A-Z0-9]{24}(?: /\*[^*]*\*/)?;',
      ),
      'package = $packageId /* XCLocalSwiftPackageReference "$pluginPackageRelativePath" */;',
    );
    text = text.replaceRange(block.start, block.end, updatedBlock);
  }

  String _ensureProductBuildFile({
    required String productName,
    required String productId,
  }) {
    final existing = RegExp(
      '([A-Z0-9]{24}) /\\* $productName in Frameworks \\*/ = \\{isa = PBXBuildFile; productRef = $productId',
    ).firstMatch(text);
    if (existing != null) return existing.group(1)!;

    final id = _id();
    _addBuildFile(
      id,
      '$productName in Frameworks',
      'productRef = $productId /* $productName */;',
    );
    return id;
  }

  String _ensureFrameworkFileReference(String name) {
    final existing = RegExp(
      '([A-Z0-9]{24}) /\\* $name \\*/ = \\{isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = $name;',
    ).firstMatch(text);
    if (existing != null) return existing.group(1)!;

    final id = _id();
    _addFileReference(
      id,
      name,
      'lastKnownFileType = wrapper.framework; name = $name; path = System/Library/Frameworks/$name; sourceTree = SDKROOT;',
    );
    return id;
  }

  String _ensureFrameworkBuildFile({
    required String name,
    required String fileId,
  }) {
    final existing = RegExp(
      '([A-Z0-9]{24}) /\\* $name in Frameworks \\*/ = \\{isa = PBXBuildFile; fileRef = $fileId',
    ).firstMatch(text);
    if (existing != null) return existing.group(1)!;

    final id = _id();
    _addBuildFile(id, '$name in Frameworks', 'fileRef = $fileId /* $name */;');
    return id;
  }

  String _ensureProductFileReference() {
    final existing = RegExp(
      r'([A-Z0-9]{24}) /\* XrayTunnel.appex \*/ = \{isa = PBXFileReference;',
    ).firstMatch(text);
    if (existing != null) return existing.group(1)!;

    final id = _id();
    _addFileReference(
      id,
      '$tunnelTargetName.appex',
      'explicitFileType = "wrapper.app-extension"; includeInIndex = 0; path = $tunnelTargetName.appex; sourceTree = BUILT_PRODUCTS_DIR;',
    );
    return id;
  }

  String _ensureExtensionEmbedBuildFile(String fileId) {
    final existing = RegExp(
      '([A-Z0-9]{24}) /\\* $tunnelTargetName.appex in Embed Foundation Extensions \\*/ = \\{isa = PBXBuildFile; fileRef = $fileId',
    ).firstMatch(text);
    if (existing != null) return existing.group(1)!;

    final id = _id();
    _addBuildFile(
      id,
      '$tunnelTargetName.appex in Embed Foundation Extensions',
      'fileRef = $fileId /* $tunnelTargetName.appex */; settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); };',
    );
    return id;
  }

  String _ensureContainerProxy(String projectId, String tunnelTargetId) {
    for (final match in RegExp(
      r'\t\t([A-Z0-9]{24}) /\* PBXContainerItemProxy \*/ = \{([\s\S]*?)\n\t\t\};',
    ).allMatches(text)) {
      final body = match.group(2)!;
      if (body.contains('remoteGlobalIDString = $tunnelTargetId;') &&
          body.contains('remoteInfo = $tunnelTargetName;')) {
        return match.group(1)!;
      }
    }

    final id = _id();
    _insertObject(
      'PBXContainerItemProxy',
      '''
\t\t$id /* PBXContainerItemProxy */ = {
\t\t\tisa = PBXContainerItemProxy;
\t\t\tcontainerPortal = $projectId /* Project object */;
\t\t\tproxyType = 1;
\t\t\tremoteGlobalIDString = $tunnelTargetId;
\t\t\tremoteInfo = $tunnelTargetName;
\t\t};
''',
    );
    return id;
  }

  String _ensureTargetDependency(String proxyId, String tunnelTargetId) {
    for (final match in RegExp(
      r'\t\t([A-Z0-9]{24}) /\* PBXTargetDependency \*/ = \{([\s\S]*?)\n\t\t\};',
    ).allMatches(text)) {
      final body = match.group(2)!;
      if (body.contains('target = $tunnelTargetId /* $tunnelTargetName */;') &&
          body.contains(
              'targetProxy = $proxyId /* PBXContainerItemProxy */;')) {
        return match.group(1)!;
      }
    }

    final id = _id();
    _insertObject(
      'PBXTargetDependency',
      '''
\t\t$id /* PBXTargetDependency */ = {
\t\t\tisa = PBXTargetDependency;
\t\t\ttarget = $tunnelTargetId /* $tunnelTargetName */;
\t\t\ttargetProxy = $proxyId /* PBXContainerItemProxy */;
\t\t};
''',
    );
    return id;
  }

  String _ensureEmbedExtensionsPhase(String runnerTargetId) {
    final runner = _objectBlock(runnerTargetId).text;
    final existing = RegExp(
      r'([A-Z0-9]{24}) /\* Embed Foundation Extensions \*/ = \{\s*isa = PBXCopyFilesBuildPhase;',
      multiLine: true,
    ).allMatches(text).where((candidate) {
      return runner
          .contains('${candidate.group(1)!} /* Embed Foundation Extensions */');
    }).firstOrNull;
    if (existing != null) {
      return existing.group(1)!;
    }

    final id = _id();
    _insertObject(
      'PBXCopyFilesBuildPhase',
      '''
\t\t$id /* Embed Foundation Extensions */ = {
\t\t\tisa = PBXCopyFilesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tdstPath = "";
\t\t\tdstSubfolderSpec = 13;
\t\t\tfiles = (
\t\t\t);
\t\t\tname = "Embed Foundation Extensions";
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
''',
    );
    _appendListEntry(
        runnerTargetId, 'buildPhases', '$id /* Embed Foundation Extensions */');
    return id;
  }

  void _orderIosEmbedPhase(String runnerTargetId, String embedPhaseId) {
    final runner = _objectBlock(runnerTargetId);
    final phases =
        RegExp(r'buildPhases = \(([\s\S]*?)\);').firstMatch(runner.text);
    final entries = phases?.group(1);
    if (entries == null) _projectError('Could not read Runner build phases.');
    final embed = RegExp(
            '^\\t+$embedPhaseId /\\* Embed Foundation Extensions \\*/,\\n',
            multiLine: true)
        .firstMatch(entries);
    final thinBinary =
        RegExp(r'^\t+[A-Z0-9]{24} /\* Thin Binary \*/,', multiLine: true)
            .firstMatch(entries);
    if (embed == null || thinBinary == null || embed.start < thinBinary.start) {
      return;
    }
    // Flutter's Thin Binary phase consumes Runner.app/Info.plist, which also
    // depends on the embedded extension. Embedding after it creates a cycle.
    final updated = entries
        .replaceRange(embed.start, embed.end, '')
        .replaceRange(thinBinary.start, thinBinary.start, embed.group(0)!);
    final start = runner.start + phases!.start + 'buildPhases = ('.length;
    text = text.replaceRange(start, start + entries.length, updated);
  }

  void _addBuildFile(String id, String comment, String fields) {
    _insertObject(
      'PBXBuildFile',
      '\t\t$id /* $comment */ = {isa = PBXBuildFile; $fields };\n',
    );
  }

  void _addFileReference(String id, String comment, String fields) {
    _insertObject(
      'PBXFileReference',
      '\t\t$id /* $comment */ = {isa = PBXFileReference; $fields };\n',
    );
  }

  void _addGroup(String id, String comment, List<String> children,
      {String? path}) {
    _insertObject(
      'PBXGroup',
      '''
\t\t$id /* $comment */ = {
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
${children.map((child) => '\t\t\t\t$child,').join('\n')}
\t\t\t);
${path == null ? '' : '\t\t\tpath = $path;\n'}\t\t\tsourceTree = "<group>";
\t\t};
''',
    );
  }

  void _addFrameworksPhase(String id, List<String> files) {
    _insertObject(
      'PBXFrameworksBuildPhase',
      '''
\t\t$id /* Frameworks */ = {
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
${files.map((file) => '\t\t\t\t$file,').join('\n')}
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
''',
    );
  }

  void _addSourcesPhase(String id, List<String> files) {
    _insertObject(
      'PBXSourcesBuildPhase',
      '''
\t\t$id /* Sources */ = {
\t\t\tisa = PBXSourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
${files.map((file) => '\t\t\t\t$file,').join('\n')}
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
''',
    );
  }

  void _addResourcesPhase(String id) {
    _insertObject(
      'PBXResourcesBuildPhase',
      '''
\t\t$id /* Resources */ = {
\t\t\tisa = PBXResourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
''',
    );
  }

  void _addNativeTarget(
    String id,
    String configListId,
    String sourcesId,
    String frameworksId,
    String resourcesId,
    String productFileId,
    String supportProductId,
  ) {
    _insertObject(
      'PBXNativeTarget',
      '''
\t\t$id /* $tunnelTargetName */ = {
\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = $configListId /* Build configuration list for PBXNativeTarget "$tunnelTargetName" */;
\t\t\tbuildPhases = (
\t\t\t\t$sourcesId /* Sources */,
\t\t\t\t$frameworksId /* Frameworks */,
\t\t\t\t$resourcesId /* Resources */,
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = $tunnelTargetName;
\t\t\tpackageProductDependencies = (
\t\t\t\t$supportProductId /* $tunnelProductName */,
\t\t\t);
\t\t\tproductName = $tunnelTargetName;
\t\t\tproductReference = $productFileId /* $tunnelTargetName.appex */;
\t\t\tproductType = "com.apple.product-type.app-extension";
\t\t};
''',
    );
  }

  void _addBuildConfigurationList(
    String listId,
    String owner,
    String bundleId,
    String deploymentTarget,
    String? teamId,
  ) {
    final baseConfig = preserveProject ? _flutterGeneratedConfig() : null;
    final debugId = _id();
    final releaseId = _id();
    final profileId = _id();
    for (final entry in [
      ('Debug', debugId),
      ('Release', releaseId),
      ('Profile', profileId),
    ]) {
      _insertObject(
        'XCBuildConfiguration',
        _tunnelBuildConfiguration(
          id: entry.$2,
          name: entry.$1,
          bundleId: bundleId,
          deploymentTarget: deploymentTarget,
          teamId: teamId,
          baseConfig: baseConfig,
        ),
      );
    }
    _insertObject(
      'XCConfigurationList',
      '''
\t\t$listId /* Build configuration list for $owner */ = {
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t$debugId /* Debug */,
\t\t\t\t$releaseId /* Release */,
\t\t\t\t$profileId /* Profile */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
\t\t};
''',
    );
  }

  String _flutterGeneratedConfig() {
    final path = ios
        ? 'Flutter/Generated.xcconfig'
        : 'Flutter/ephemeral/Flutter-Generated.xcconfig';
    final id = _id();
    _addFileReference(id, 'Flutter generated settings',
        'lastKnownFileType = text.xcconfig; path = "$path"; sourceTree = SOURCE_ROOT;');
    return id;
  }

  String _tunnelBuildConfiguration({
    required String id,
    required String name,
    required String bundleId,
    required String deploymentTarget,
    required String? teamId,
    required String? baseConfig,
  }) {
    final isDebug = name == 'Debug';
    final platformSettings = ios
        ? '\t\t\t\tAPPLICATION_EXTENSION_API_ONLY = YES;\n'
            '\t\t\t\tTARGETED_DEVICE_FAMILY = "1,2";\n'
        : '\t\t\t\t"CODE_SIGN_IDENTITY[sdk=macosx*]" = "Apple Development";\n'
            '\t\t\t\tENABLE_APP_SANDBOX = YES;\n'
            '\t\t\t\tREGISTER_APP_GROUPS = YES;\n';
    final executableFrameworkPath =
        ios ? '@executable_path/Frameworks' : '@executable_path/../Frameworks';
    final hostFrameworkPath = ios
        ? '@executable_path/../../Frameworks'
        : '@executable_path/../../../../Frameworks';
    return '''
\t\t$id /* $name */ = {
\t\t\tisa = XCBuildConfiguration;
${baseConfig == null ? '' : '\t\t\tbaseConfigurationReference = $baseConfig /* Flutter generated settings */;\n'}\t\t\tbuildSettings = {
\t\t\t\tCLANG_ENABLE_MODULES = YES;
\t\t\t\tCODE_SIGN_ENTITLEMENTS = $tunnelTargetName/$tunnelTargetName.entitlements;
$platformSettings\t\t\t\tCODE_SIGN_STYLE = Automatic;
\t\t\t\tCURRENT_PROJECT_VERSION = "\$(FLUTTER_BUILD_NUMBER)";
${teamId == null ? '' : '\t\t\t\tDEVELOPMENT_TEAM = $teamId;\n'}\t\t\t\tGENERATE_INFOPLIST_FILE = YES;
\t\t\t\tINFOPLIST_FILE = $tunnelTargetName/Info.plist;
\t\t\t\tINFOPLIST_KEY_CFBundleDisplayName = $tunnelTargetName;
\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (
\t\t\t\t\t"\$(inherited)",
\t\t\t\t\t"$executableFrameworkPath",
\t\t\t\t\t"$hostFrameworkPath",
\t\t\t\t);
\t\t\t\t$_deploymentKey = $deploymentTarget;
\t\t\t\tMARKETING_VERSION = "\$(FLUTTER_BUILD_NAME)";
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = $bundleId.$tunnelTargetName;
\t\t\t\tPRODUCT_NAME = "\$(TARGET_NAME)";
\t\t\t\tSKIP_INSTALL = YES;
\t\t\t\tSWIFT_VERSION = 5.0;
${isDebug ? '\t\t\t\tSWIFT_OPTIMIZATION_LEVEL = "-Onone";\n' : ''}\t\t\t};
\t\t\tname = $name;
\t\t};
''';
  }

  void _ensureTargetAttributes(String projectId, String targetId) {
    final block = _objectBlock(projectId);
    if (block.text.contains('$targetId = {')) return;
    final index = text.indexOf('TargetAttributes = {', block.start);
    if (index < 0 || index > block.end) return;
    final insert = text.indexOf('\n', index) + 1;
    text = text.replaceRange(insert, insert, '''
\t\t\t\t\t$targetId = {
\t\t\t\t\t\tCreatedOnToolsVersion = 15.0;
\t\t\t\t\t\tProvisioningStyle = Automatic;
\t\t\t\t\t};
''');
  }

  void _patchRunnerBuildSettings(
    String bundleId,
    String deploymentTarget,
    String? teamId,
  ) {
    for (final configId in _targetConfigs(_runnerId)) {
      if (!preserveProject ||
          _setting(configId, 'PRODUCT_BUNDLE_IDENTIFIER') != bundleId) {
        _setBuildSetting(configId, 'PRODUCT_BUNDLE_IDENTIFIER', bundleId);
      }
      _raiseDeployment(configId, deploymentTarget);
      if (!ios) _setBuildSetting(configId, 'REGISTER_APP_GROUPS', 'YES');
      if (teamId != null) {
        _setBuildSetting(configId, 'DEVELOPMENT_TEAM', teamId);
      }
    }
  }

  void _patchAllMacOSDeploymentTargets(String deploymentTarget) {
    text = text.replaceAllMapped(
      RegExp(r'MACOSX_DEPLOYMENT_TARGET = [^;]+;'),
      (_) => 'MACOSX_DEPLOYMENT_TARGET = $deploymentTarget;',
    );
  }

  void _patchTunnelBuildSettings(
    String bundleId,
    String deploymentTarget,
    String? teamId,
  ) {
    final targetId = _targetId(tunnelTargetName)!;
    final configListId = _requiredMatchIn(
      _objectBlock(targetId).text,
      RegExp(r'buildConfigurationList = ([A-Z0-9]{24}) /\*'),
      'XrayTunnel build configuration list',
    );
    for (final configId in _configurationIds(configListId)) {
      _setBuildSetting(
        configId,
        'CODE_SIGN_ENTITLEMENTS',
        '$tunnelTargetName/$tunnelTargetName.entitlements',
      );
      _setBuildSetting(
          configId, 'PRODUCT_BUNDLE_IDENTIFIER', '$bundleId.$tunnelTargetName');
      _raiseDeployment(configId, deploymentTarget);
      _setBuildSetting(
          configId, 'CURRENT_PROJECT_VERSION', r'"$(FLUTTER_BUILD_NUMBER)"');
      _setBuildSetting(
          configId, 'MARKETING_VERSION', r'"$(FLUTTER_BUILD_NAME)"');
      if (!ios) _setBuildSetting(configId, 'REGISTER_APP_GROUPS', 'YES');
      _setBuildSetting(configId, 'SKIP_INSTALL', 'YES');
      if (teamId != null) {
        _setBuildSetting(configId, 'DEVELOPMENT_TEAM', teamId);
      }
    }
  }

  List<String> _configurationIds(String configListId) {
    final block = _objectBlock(configListId).text;
    final configurations = _requiredMatchIn(
        block,
        RegExp(r'buildConfigurations = \(([\s\S]*?)\);'),
        'build configurations');
    return RegExp(r'([A-Z0-9]{24})(?: /\*[^*]*\*/)?\s*,')
        .allMatches(configurations)
        .map((match) => match.group(1)!)
        .toList();
  }

  void _setBuildSetting(String configId, String key, String value) {
    final block = _objectBlock(configId);
    final keyPattern =
        RegExp('(^\\s*)"?${RegExp.escape(key)}"? = [^;]+;', multiLine: true);
    final match = keyPattern.firstMatch(block.text);
    if (match != null) {
      final replacement = '${match.group(1)}$key = $value;';
      text = text.replaceRange(
          block.start + match.start, block.start + match.end, replacement);
      return;
    }

    final settingsIndex = text.indexOf('buildSettings = {', block.start);
    final insert = text.indexOf('\n', settingsIndex) + 1;
    text = text.replaceRange(insert, insert, '\t\t\t\t$key = $value;\n');
  }

  void _removeFrameworkFromTarget(String targetId, String frameworkName) {
    final targetBlock = _objectBlock(targetId).text;
    final frameworksIdMatch =
        RegExp(r'([A-Z0-9]{24}) /\* Frameworks \*/').firstMatch(targetBlock);
    if (frameworksIdMatch == null) return;
    final frameworksId = frameworksIdMatch.group(1)!;
    final frameworksBlock = _objectBlock(frameworksId);
    final line = RegExp(
      '^\\s*[A-Z0-9]{24} /\\* ${RegExp.escape(frameworkName)}(?: in Frameworks)? \\*/,\\n',
      multiLine: true,
    ).firstMatch(frameworksBlock.text);
    if (line == null) return;
    text = text.replaceRange(
      frameworksBlock.start + line.start,
      frameworksBlock.start + line.end,
      '',
    );
  }

  void _removeProjectFileReferences(String fileName) {
    final ids = <String>{};
    for (final match in RegExp(
      '([A-Z0-9]{24}) /\\* ${RegExp.escape(fileName)}(?: in Frameworks)? \\*/ = \\{[^\\n]*?;',
    ).allMatches(text)) {
      ids.add(match.group(1)!);
    }
    for (final id in ids) {
      text = text.replaceAll(
        RegExp('^\\s*$id /\\* [^\\n]*? \\*/ = \\{[^\\n]*?;\\n',
            multiLine: true),
        '',
      );
      text = text.replaceAll(
        RegExp('^\\s*$id /\\* [^\\n]*? \\*/,\\n', multiLine: true),
        '',
      );
    }
  }

  void _appendListEntry(String objectId, String listName, String entry) {
    final block = _objectBlock(objectId);
    final list =
        RegExp('$listName = \\(([\\s\\S]*?)\\);').firstMatch(block.text);
    if (list == null) {
      final insert = block.end - '\t\t};\n'.length;
      text = text.replaceRange(
          insert, insert, '\t\t\t$listName = (\n\t\t\t\t$entry,\n\t\t\t);\n');
      return;
    }
    if (list.group(1)!.contains(entry.split(' /* ').first)) return;
    final close = block.start + list.end - 2;
    final whitespace = RegExp(r'\s*$').firstMatch(list.group(1)!)!.group(0)!;
    text = text.replaceRange(
        close - whitespace.length, close, '\n\t\t\t\t$entry,\n\t\t\t');
  }

  void _insertObject(String sectionName, String objectText) {
    final end = text.indexOf('/* End $sectionName section */');
    if (end < 0) {
      final objectsStart = text.indexOf('objects = {');
      final insert = text.indexOf('\n', objectsStart) + 1;
      text = text.replaceRange(insert, insert,
          '\n/* Begin $sectionName section */\n$objectText/* End $sectionName section */\n');
      return;
    }
    text = text.replaceRange(end, end, objectText);
  }

  String? _targetId(String name) {
    final pattern = RegExp(
      '([A-Z0-9]{24}) /\\* ${RegExp.escape(name)} \\*/ = \\{\\s*isa = PBXNativeTarget;',
      multiLine: true,
    );
    return pattern.firstMatch(text)?.group(1);
  }

  _Block _objectBlock(String id) {
    final objectLine = RegExp(
      '^\\t\\t${RegExp.escape(id)}(?: /\\*[^\\n]*\\*/)? = \\{',
      multiLine: true,
    ).firstMatch(text);
    if (objectLine == null) _projectError('Could not find Xcode object $id.');
    final start = objectLine.start;
    final brace = text.indexOf('{', start);
    var depth = 0;
    for (var i = brace; i < text.length; i++) {
      final char = text.codeUnitAt(i);
      if (char == 123) depth++;
      if (char == 125) {
        depth--;
        if (depth == 0) {
          final end = text.indexOf(';\n', i) + 2;
          return _Block(start, end, text.substring(start, end));
        }
      }
    }
    _projectError('Could not parse Xcode object $id.');
  }

  String _requiredMatch(RegExp pattern, String description) {
    final match = pattern.firstMatch(text);
    if (match == null) {
      _projectError('Could not find $description in project.pbxproj.');
    }
    return match.group(1)!;
  }

  String _requiredMatchIn(String source, RegExp pattern, String description) {
    final match = pattern.firstMatch(source);
    if (match == null) {
      _projectError('Could not find $description in project.pbxproj.');
    }
    return match.group(1)!;
  }

  String _id() {
    const chars = '0123456789ABCDEF';
    while (true) {
      final id = List.generate(24, (_) => chars[_random.nextInt(16)]).join();
      if (!text.contains(id)) return id;
    }
  }
}

class _Block {
  const _Block(this.start, this.end, this.text);

  final int start;
  final int end;
  final String text;
}

Never _projectError(String message) => throw SetupException(message);

bool _versionLessThan(String actual, String minimum) {
  final parts = actual.split('.').map(int.tryParse).toList();
  final floor = minimum.split('.').map(int.parse).toList();
  if (parts.contains(null)) {
    _projectError(
        'Cannot resolve deployment target "$actual". Set it to at least $minimum.');
  }
  for (var index = 0; index < max(parts.length, floor.length); index++) {
    final value = index < parts.length ? parts[index]! : 0;
    final required = index < floor.length ? floor[index] : 0;
    if (value != required) return value < required;
  }
  return false;
}
