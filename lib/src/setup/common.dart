import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'package:path/path.dart' as p;

enum SetupPlatform { macos, android, windows, ios }

enum SetupMode { proxy, vpn }

class SetupRequest {
  SetupRequest({
    required this.root,
    required this.platform,
    required this.mode,
    this.bundleId,
    this.groupId,
    this.teamId,
    this.runtimeDirectory,
    this.architecture,
  });

  final Directory root;
  final SetupPlatform platform;
  final SetupMode mode;
  final String? bundleId;
  final String? groupId;
  final String? teamId;
  final String? runtimeDirectory;
  final String? architecture;

  String resolve(String path) => p.normalize(p.join(root.absolute.path, path));
}

class SetupException implements Exception {
  const SetupException(this.message);

  final String message;

  @override
  String toString() => message;
}

class SetupPlan {
  SetupPlan(this.request);

  final SetupRequest request;
  final notes = <String>[];
  final _edits = <String, ({Uint8List? before, Uint8List after})>{};
  final _preparations = <String, Future<void> Function()>{};

  List<String> get changedPaths => _edits.keys.toList(growable: false);
  List<String> get pendingActions => _preparations.keys.toList(growable: false);

  void writeText(String relativePath, String contents) {
    writeBytes(relativePath, utf8.encode(contents));
  }

  void writeBytes(String relativePath, List<int> contents) {
    final path = p.normalize(relativePath);
    final file = _projectFile(path);
    final before = _read(file);
    if (_sameBytes(before, contents)) return;
    final after = Uint8List.fromList(contents);
    final existing = _edits[path];
    if (existing != null && !_sameBytes(existing.after, after)) {
      throw SetupException('Conflicting edits planned for $path.');
    }
    _edits[path] = (before: before, after: after);
  }

  /// Prepare verified inputs only on apply. Preparations may add file writes.
  void defer(String description, Future<void> Function() prepare) {
    _preparations[description] = prepare;
  }

  Future<void> apply({void Function(String, int)? recordTiming}) async {
    final clock = recordTiming == null ? null : (Stopwatch()..start());
    for (final prepare in _preparations.values.toList()) {
      await prepare();
    }
    if (clock != null) {
      recordTiming!('runtime_prepare', clock.elapsedMilliseconds);
      clock.reset();
    }
    final staged = <({File file, File next, File? backup})>[];
    final committed = <({File file, File next, File? backup})>[];
    final scratch = <Directory>[];
    final created = <Directory>[];
    try {
      for (final entry in _edits.entries) {
        final file = _projectFile(entry.key);
        if (!_sameBytes(_read(file), entry.value.before)) {
          throw SetupException(
              '${entry.key} changed during setup. Rerun setup.');
        }
        Directory parent = file.parent;
        while (!parent.existsSync()) {
          created.add(parent);
          parent = parent.parent;
        }
        file.parent.createSync(recursive: true);
        final staging = file.parent.createTempSync('.flutter-vless-setup-');
        scratch.add(staging);
        final next = File(p.join(staging.path, 'next'))
          ..writeAsBytesSync(entry.value.after, flush: true);
        final backup = entry.value.before == null
            ? null
            : file.copySync(p.join(staging.path, 'backup'));
        staged.add((file: file, next: next, backup: backup));
      }
      for (final entry in staged) {
        entry.next.renameSync(entry.file.path);
        committed.add(entry);
      }
    } catch (_) {
      for (final entry in committed.reversed) {
        if (entry.backup == null) {
          entry.file.deleteSync();
        } else {
          entry.backup!.renameSync(entry.file.path);
        }
      }
      rethrow;
    } finally {
      for (final dir in scratch) {
        dir.deleteSync(recursive: true);
      }
      for (final dir in created) {
        if (dir.existsSync() && dir.listSync().isEmpty) {
          dir.deleteSync();
        }
      }
    }
    if (clock != null) {
      recordTiming!('project_apply', clock.elapsedMilliseconds);
    }
  }

  File _projectFile(String path) {
    final root = request.root.absolute.path;
    final full = request.resolve(path);
    if (p.isAbsolute(path) || !p.isWithin(root, full)) {
      throw SetupException(
          'Expected a path inside the Flutter project: $path.');
    }
    var component = root;
    for (final part in p.split(path)) {
      component = p.join(component, part);
      if (FileSystemEntity.isLinkSync(component)) {
        throw SetupException('Setup cannot replace a symbolic link: $path.');
      }
    }
    return File(full);
  }
}

Uint8List? _read(File file) {
  final type = FileSystemEntity.typeSync(file.path, followLinks: false);
  if (type == FileSystemEntityType.notFound) return null;
  if (type != FileSystemEntityType.file) {
    throw SetupException('Expected a regular file at ${file.path}.');
  }
  return file.readAsBytesSync();
}

bool _sameBytes(List<int>? a, List<int>? b) {
  if (a == null || b == null) return a == b;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
