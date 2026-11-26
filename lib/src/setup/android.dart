import 'dart:io';

import 'common.dart';

const _minSdk = 23;

void planAndroid(SetupRequest request, SetupPlan plan) {
  final build = _gradleFile(request, 'android/app/build.gradle');
  if (build == null) {
    throw SetupException(
      'Missing android/app/build.gradle or build.gradle.kts. '
      'Add the Android target with flutter create --platforms=android .',
    );
  }
  _checkRepositories(request, plan);
  final project = _GradleProject(build.$1, build.$2);
  final android = project.root.child('android', project);
  if (android == null) {
    throw SetupException(
        '${project.path}: expected one top-level android block.');
  }
  final defaults = android.child('defaultConfig', project);
  final packaging = android.child('packaging|packagingOptions', project);
  final jniLibs = packaging?.child('jniLibs', project);

  project.checkOtherSettings(
    project.root,
    defaults: defaults,
    jniLibs: jniLibs,
    flavors: android.child('productFlavors', project),
  );
  _planMinimumSdk(project, android, defaults);
  _planPackaging(project, android, packaging, jniLibs);
  plan.writeText(project.path, project.updatedText());

  plan.notes.add(
    'The Android plugin supplies the manifest and pinned Maven runtime. '
    'Both modes need minSdk >= $_minSdk and useLegacyPackaging = true. '
    'Build an APK or app bundle to check dependency resolution and packaged ABIs.',
  );
  if (request.mode == SetupMode.vpn) {
    plan.notes.add('Accept the Android system VPN prompt on first connection.');
  }
}

void _planMinimumSdk(
  _GradleProject project,
  _GradleBlock android,
  _GradleBlock? defaults,
) {
  if (defaults == null) {
    project.append(android, ['defaultConfig {', '    minSdk = $_minSdk', '}']);
    return;
  }
  final setting = project.setting(defaults, _GradleProject.minimumSdk);
  if (setting == null) {
    project.append(defaults, ['minSdk = $_minSdk']);
    return;
  }
  final minimum = int.tryParse(setting.value);
  if (minimum != null) {
    if (minimum < _minSdk) project.replace(setting, '$_minSdk');
    return;
  }
  final minimumFunction = project.kotlin ? 'maxOf' : 'Math.max';
  final requiredMinimum = '$minimumFunction($_minSdk, flutter.minSdkVersion)';
  if (setting.value == 'flutter.minSdkVersion') {
    project.replace(setting, requiredMinimum);
    return;
  }
  if (setting.value.replaceAll(RegExp(r'\s+'), '') !=
      requiredMinimum.replaceAll(' ', '')) {
    throw SetupException(
      '${project.path}: ${setting.name} uses a custom expression. '
      'Use a literal of at least $_minSdk or $requiredMinimum.',
    );
  }
}

void _planPackaging(
  _GradleProject project,
  _GradleBlock android,
  _GradleBlock? packaging,
  _GradleBlock? jniLibs,
) {
  const useLegacy = 'useLegacyPackaging = true';
  if (packaging == null) {
    project.append(android, [
      'packaging {',
      '    jniLibs {',
      '        $useLegacy',
      '    }',
      '}',
    ]);
  } else if (jniLibs == null) {
    project.append(packaging, ['jniLibs {', '    $useLegacy', '}']);
  } else {
    final setting = project.setting(jniLibs, _GradleProject.legacyPackaging);
    if (setting == null) {
      project.append(jniLibs, [useLegacy]);
    } else if (setting.value == 'false') {
      project.replace(setting, 'true');
    } else if (setting.value != 'true') {
      throw SetupException(
        '${project.path}: useLegacyPackaging uses a custom expression. '
        'Set it to true so Xray can run from the native library directory.',
      );
    }
  }
}

void _checkRepositories(SetupRequest request, SetupPlan plan) {
  final settings = _gradleFile(request, 'android/settings.gradle');
  if (settings == null) return;
  final project = _GradleProject(settings.$1, settings.$2);
  final dependencies =
      project.root.child('dependencyResolutionManagement', project);
  if (dependencies == null) return;
  final configuration = project.directText(dependencies);
  const mode = r'\brepositoriesMode\s*(?:=|\.set\s*\()\s*'
      r'(?:RepositoriesMode\.)?';
  if (RegExp('${mode}FAIL_ON_PROJECT_REPOS\\b').hasMatch(configuration)) {
    throw SetupException(
      '${project.path}: FAIL_ON_PROJECT_REPOS conflicts with repositories '
      'declared by the Android plugin. Review your Gradle repository policy.',
    );
  }
  if (RegExp('${mode}PREFER_SETTINGS\\b').hasMatch(configuration)) {
    final repos = dependencies.child('repositories', project);
    if (repos == null ||
        !RegExp(r'\bmavenCentral[ \t]*\(')
            .hasMatch(project.directText(repos))) {
      plan.notes.add(
        '${project.path}: PREFER_SETTINGS requires a Maven Central repository '
        'or an approved mirror that serves dev.tfox.fluttervless:xray-android.',
      );
    }
  }
}

(String, String)? _gradleFile(SetupRequest request, String base) {
  final paths = [base, '$base.kts']
      .where((path) => File(request.resolve(path)).existsSync())
      .toList();
  if (paths.length > 1) {
    throw SetupException(
        'Both $base and $base.kts exist. Select one Gradle file.');
  }
  if (paths.isEmpty) return null;
  final path = paths.single;
  return (path, File(request.resolve(path)).readAsStringSync());
}

class _GradleBlock {
  _GradleBlock(this.name, this.open, this.close);

  final String? name;
  final int open;
  int close;
  final children = <_GradleBlock>[];

  _GradleBlock? child(String names, _GradleProject project) {
    final pattern = RegExp('^(?:$names)\$');
    final matches = children
        .where((block) => block.name != null && pattern.hasMatch(block.name!))
        .toList();
    if (matches.length > 1) {
      throw SetupException('${project.path}: multiple $names blocks.');
    }
    return matches.isEmpty ? null : matches.single;
  }
}

class _GradleSetting {
  const _GradleSetting(this.name, this.value, this.start, this.end);

  final String name;
  final String value;
  final int start;
  final int end;
}

class _GradleProject {
  _GradleProject(this.path, this.source) {
    masked = _maskGradle(source);
    root = _GradleBlock(null, -1, source.length);
    final stack = [root];
    var previousEnd = 0;
    for (final marker in RegExp(r'[{}]').allMatches(masked)) {
      if (marker.group(0) == '{') {
        final before = masked.substring(previousEnd, marker.start);
        final name = RegExp(r'(?:^|[;\r\n])[ \t]*([a-zA-Z_]\w*)[ \t\r\n]*$')
            .firstMatch(before)
            ?.group(1);
        final block = _GradleBlock(name, marker.start, source.length);
        stack.last.children.add(block);
        stack.add(block);
      } else if (stack.length == 1) {
        throw SetupException('$path: unmatched Gradle braces.');
      } else {
        stack.removeLast().close = marker.start;
      }
      previousEnd = marker.end;
    }
    if (stack.length != 1) {
      throw SetupException('$path: unmatched Gradle braces.');
    }
  }

  static const minimumSdk = r'minSdk(?:Version)?';
  static const legacyPackaging = 'useLegacyPackaging';
  final String path;
  final String source;
  late final String masked;
  late final _GradleBlock root;
  final _edits = <(int, int, String)>[];
  final _insertions = <_GradleBlock, List<String>>{};

  bool get kotlin => path.endsWith('.kts');
  String get newline => source.contains('\r\n') ? '\r\n' : '\n';

  String directText(_GradleBlock block) {
    // Clear child bodies while retaining source offsets and line endings.
    final text = masked.substring(block.open + 1, block.close);
    final chars = text.codeUnits.toList();
    for (final child in block.children) {
      for (var offset = child.open + 1; offset < child.close; offset++) {
        final index = offset - block.open - 1;
        if (chars[index] != 10 && chars[index] != 13) chars[index] = 32;
      }
    }
    return String.fromCharCodes(chars);
  }

  _GradleSetting? setting(_GradleBlock block, String key) {
    final pattern = RegExp('(?:^|[;\\r\\n])[ \\t]*($key)\\b([^;\\r\\n]*)');
    final matches = pattern.allMatches(directText(block)).toList();
    if (matches.isEmpty) return null;
    if (matches.length > 1) {
      throw SetupException(
          '$path: multiple ${matches.first.group(1)} settings.');
    }
    final entry = matches.single;
    final raw = entry.group(2)!;
    final absolute = block.open + 1 + entry.end - raw.length;
    var expression = raw.trimLeft();
    var start = absolute + raw.length - expression.length;
    if (expression.startsWith('=') || expression.startsWith('(')) {
      final expressionWithoutPrefix = expression.substring(1).trimLeft();
      start += expression.length - expressionWithoutPrefix.length;
      expression = expressionWithoutPrefix;
      if (raw.trimLeft().startsWith('(') &&
          expression.trimRight().endsWith(')')) {
        expression = expression.trimRight();
        expression = expression.substring(0, expression.length - 1);
      }
    }
    final value = expression.trimRight();
    return _GradleSetting(entry.group(1)!, value, start, start + value.length);
  }

  void checkOtherSettings(
    _GradleBlock block, {
    required _GradleBlock? defaults,
    required _GradleBlock? flavors,
    required _GradleBlock? jniLibs,
    bool inFlavor = false,
  }) {
    final insideFlavors = inFlavor || identical(flavors, block);
    if (!identical(defaults, block)) {
      final other = setting(block, minimumSdk);
      if (other != null &&
          (!insideFlavors || (int.tryParse(other.value) ?? -1) < _minSdk)) {
        throw SetupException(
          '$path: ${other.name} outside defaultConfig may override the minimum. '
          'Set every flavor explicitly to at least $_minSdk or let it inherit.',
        );
      }
    }
    if ((!identical(jniLibs, block) &&
            setting(block, legacyPackaging) != null) ||
        setting(block, 'useLegacyPackagingFromBundle') != null ||
        RegExp(r'\.\s*(?:minSdk(?:Version)?|useLegacyPackaging(?:FromBundle)?)'
                r'[ \t]*(?:=(?!=)|\.set\s*\()')
            .hasMatch(directText(block))) {
      throw SetupException(
        '$path: a custom Gradle override controls minSdk or JNI packaging. '
        'Verify every build variant has minSdk >= $_minSdk and '
        'useLegacyPackaging = true.',
      );
    }
    for (final child in block.children) {
      checkOtherSettings(
        child,
        defaults: defaults,
        flavors: flavors,
        jniLibs: jniLibs,
        inFlavor: insideFlavors,
      );
    }
  }

  void append(_GradleBlock block, List<String> lines) {
    _insertions.putIfAbsent(block, () => []).addAll(lines);
  }

  void replace(_GradleSetting setting, String value) {
    if (source.substring(setting.start, setting.end) != setting.value) {
      throw SetupException('$path: set ${setting.name} to $value manually.');
    }
    _edits.add((setting.start, setting.end, value));
  }

  String updatedText() {
    for (final entry in _insertions.entries) {
      final block = entry.key;
      final closeLine = source.lastIndexOf('\n', block.close - 1) + 1;
      final openingLine = source.lastIndexOf('\n', block.open - 1) + 1;
      final openIndent = RegExp(r'^[ \t]*')
          .stringMatch(source.substring(openingLine, block.open))!;
      final beforeClose = source.substring(closeLine, block.close);
      final ownLine = beforeClose.trim().isEmpty;
      final indent = ownLine ? beforeClose : openIndent;
      final contents =
          entry.value.map((line) => '$indent    $line').join(newline);
      final offset = ownLine ? closeLine : block.close;
      final replacement = ownLine
          ? '$contents$newline'
          : '$newline$contents$newline$openIndent';
      _edits.add((offset, offset, replacement));
    }
    _edits.sort((left, right) => right.$1.compareTo(left.$1));
    var result = source;
    for (final (start, end, replacement) in _edits) {
      result = result.replaceRange(start, end, replacement);
    }
    return result;
  }
}

// Preserve offsets and newlines while ignoring braces in comments and strings.
String _maskGradle(String source) => source.replaceAllMapped(
      RegExp(
        r'/\*[\s\S]*?\*/|//[^\r\n]*|"""[\s\S]*?"""|'
        r"'''[\s\S]*?'''|"
        r'"(?:\\[\s\S]|[^"\\])*"|'
        r"'(?:\\[\s\S]|[^'\\])*'",
      ),
      (match) => match.group(0)!.replaceAll(RegExp(r'[^\r\n]'), ' '),
    );
