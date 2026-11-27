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
    plan.defer('prepare verified input', () async {
      plan.writeText('staged.txt', 'pending');
      throw const SetupException('preparation failed');
    });

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
      plan.writeText('runtime.txt', 'verified');
      prepared.complete();
    });
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
    plan.defer('prepare verified input', () async {
      plan.writeText('runtime.txt', 'verified');
    });
    await expectLater(
      plan.apply(inspect: () => throw const SetupException('blocked driver')),
      throwsA(isA<SetupException>()),
    );
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
