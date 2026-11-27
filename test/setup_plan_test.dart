import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/src/setup/common.dart';

void main() {
  late Directory root;
  late SetupPlan plan;

  setUp(() {
    root = Directory.systemTemp.createTempSync('flutter-vless-plan-');
    plan = SetupPlan(SetupRequest(
        root: root, platform: SetupPlatform.macos, mode: SetupMode.proxy));
  });
  tearDown(() => root.deleteSync(recursive: true));

  test('failed preparation leaves every proposed file untouched', () async {
    final original = File.fromUri(root.uri.resolve('existing.txt'))
      ..writeAsStringSync('original');
    plan.writeText('existing.txt', 'proposed');
    plan.defer<void>('prepare verified input', () async {
      throw const SetupException('preparation failed');
    }, (_) => plan.writeText('staged.txt', 'pending'));

    expect(plan.pendingActions, ['prepare verified input']);
    await expectLater(plan.apply(), throwsA(isA<SetupException>()));
    expect(original.readAsStringSync(), 'original');
    expect(root.listSync(), hasLength(1));
  });

  test('inspection overlaps preparation and finishes before files change',
      () async {
    final started = Completer<void>();
    final canPrepare = Completer<void>();
    final prepared = Completer<void>();
    final canApply = Completer<void>();
    final destination = File.fromUri(root.uri.resolve('runtime.txt'));
    plan.defer('prepare verified input', () async {
      started.complete();
      await canPrepare.future;
      prepared.complete();
      return 'verified';
    }, (contents) => plan.writeText('runtime.txt', contents));
    final applied = plan.apply(inspect: () async {
      await started.future;
      canPrepare.complete();
      await canApply.future;
    });

    await prepared.future;
    expect(destination.existsSync(), isFalse);
    canApply.complete();
    await applied;
    expect(destination.readAsStringSync(), 'verified');
  });

  test('failed inspection prevents writes even if preparation succeeds',
      () async {
    plan.defer('prepare verified input', () async => 'verified',
        (contents) => plan.writeText('runtime.txt', contents));
    await expectLater(
      plan.apply(inspect: () => throw const SetupException('blocked driver')),
      throwsA(isA<SetupException>()),
    );
    expect(root.listSync(), isEmpty);
  });

  test('parallel preparation stages files in planning order', () async {
    final first = Completer<String>();
    final second = Completer<String>();
    plan.defer('prepare first input', () => first.future,
        (contents) => plan.writeText('first.txt', contents));
    plan.defer('prepare second input', () => second.future,
        (contents) => plan.writeText('second.txt', contents));

    final applied = plan.apply();
    second.complete('second');
    await Future<void>.delayed(Duration.zero);
    expect(plan.changedPaths, isEmpty);
    expect(root.listSync(), isEmpty);
    first.complete('first');
    await applied;

    expect(plan.changedPaths, ['first.txt', 'second.txt']);
    expect(File.fromUri(root.uri.resolve('first.txt')).readAsStringSync(),
        'first');
    expect(File.fromUri(root.uri.resolve('second.txt')).readAsStringSync(),
        'second');
  });

  test('failed preparation waits for other inputs and stages nothing',
      () async {
    final second = Completer<String>();
    plan.defer<String>('prepare first input',
        () => throw const SetupException('preparation failed'), (_) {});
    plan.defer('prepare second input', () => second.future,
        (contents) => plan.writeText('second.txt', contents));

    var completed = false;
    final failure = expectLater(
      plan.apply().whenComplete(() => completed = true),
      throwsA(isA<SetupException>()),
    );
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);
    second.complete('second');
    await failure;
    expect(plan.changedPaths, isEmpty);
    expect(root.listSync(), isEmpty);
  });

  test('changes made after planning are never replaced', () async {
    final original = File.fromUri(root.uri.resolve('existing.txt'))
      ..writeAsStringSync('original');
    plan.writeText('nested/new.txt', 'proposed');
    plan.writeText('existing.txt', 'proposed');
    original.writeAsStringSync('user edit');

    await expectLater(plan.apply(), throwsA(isA<SetupException>()));
    expect(original.readAsStringSync(), 'user edit');
    expect(root.listSync(), hasLength(1));
  });

  test('setup refuses writes outside the app', () {
    expect(() => plan.writeText('../outside.txt', 'proposed'),
        throwsA(isA<SetupException>()));
  });
}
