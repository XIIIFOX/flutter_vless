import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/src/setup/android.dart';
import 'package:flutter_vless/src/setup/common.dart';
import 'package:path/path.dart' as p;

void main() {
  late Directory root;

  setUp(
      () => root = Directory.systemTemp.createTempSync('vless-android-setup-'));
  tearDown(() => root.deleteSync(recursive: true));

  File write(String path, String text) {
    final file = File('${root.path}/$path');
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(text);
    return file;
  }

  SetupPlan plan([SetupMode mode = SetupMode.vpn]) {
    final request = SetupRequest(
      root: root,
      platform: SetupPlatform.android,
      mode: mode,
    );
    final result = SetupPlan(request);
    planAndroid(request, result);
    return result;
  }

  test('plans Kotlin template edits without mutating and applies just once',
      () async {
    const path = 'android/app/build.gradle.kts';
    const source = '''plugins {
    id("com.android.application")
}
android {
    namespace = "com.example.myapp"
    defaultConfig {
        minSdk = flutter.minSdkVersion // Preserve Flutter's floor
        targetSdk = flutter.targetSdkVersion
    }
    signingConfigs { create("myRelease") {} }
}
''';
    final file = write(path, source);
    final planBefore = plan(SetupMode.proxy);
    expect(planBefore.changedPaths, [p.normalize(path)]);
    expect(file.readAsStringSync(), source);
    expect(planBefore.notes.join(' '), isNot(contains('VPN prompt')));

    await planBefore.apply();
    final updated = file.readAsStringSync();
    expect(updated,
        contains('minSdk = maxOf(23, flutter.minSdkVersion) // Preserve'));
    expect(updated, contains('useLegacyPackaging = true'));
    expect(updated, contains('signingConfigs { create("myRelease") {} }'));
    expect(updated, contains('targetSdk = flutter.targetSdkVersion'));
    expect(plan().notes.join(' '), contains('VPN prompt'));
    expect(plan().changedPaths, isEmpty);
    await plan().apply();
    expect(file.readAsStringSync(), updated);
  });

  test('preserves Groovy layout, higher flavor SDK and packaging policy',
      () async {
    const path = 'android/app/build.gradle';
    const source = '''android {
    defaultConfig { minSdkVersion(21); versionCode 5 }
    // Ignore malformed braces in comments: } { .
    productFlavors {
        enterprise { minSdkVersion 27 }
    }
    packagingOptions {
        jniLibs {
            keepDebugSymbols += ['**/lib{a}.so']
            useLegacyPackaging false // Required by an older build
        }
    }
}
''';
    final file = write(path, source.replaceAll('\n', '\r\n'));
    await plan().apply();
    final updated = file.readAsStringSync();
    expect(updated, contains('minSdkVersion(23); versionCode 5'));
    expect(updated, contains('enterprise { minSdkVersion 27 }'));
    expect(updated, contains("keepDebugSymbols += ['**/lib{a}.so']"));
    expect(updated, contains('useLegacyPackaging true // Required'));
    expect(updated.replaceAll('\r\n', ''), isNot(contains('\n')));
    expect(plan().changedPaths, isEmpty);
  });

  test('inserts into compact blocks while leaving a higher minSdk alone',
      () async {
    final file = write(
      'android/app/build.gradle.kts',
      'android { defaultConfig { minSdk = 31 }; packaging { jniLibs {} } }\n',
    );
    await plan().apply();
    expect(file.readAsStringSync(), contains('minSdk = 31'));
    expect(file.readAsStringSync(), contains('useLegacyPackaging = true'));
    expect(plan().changedPaths, isEmpty);
  });

  test('creates default blocks when absent', () async {
    final file = write('android/app/build.gradle', 'android {}\n');
    await plan().apply();
    expect(file.readAsStringSync(),
        contains('defaultConfig {\n        minSdk = 23'));
    expect(file.readAsStringSync(), contains('packaging {\n        jniLibs {'));
    expect(plan().changedPaths, isEmpty);
  });

  test('reports custom values and variant conflicts without rewriting', () {
    final settings = {
      'defaultConfig { minSdk = computeProjectMinimum() }': 'custom expression',
      'defaultConfig { minSdk = 23 }; productFlavors { custom { minSdk = 21 } }':
          'outside defaultConfig',
      'defaultConfig { minSdk = 23; minSdk = 24 }': 'multiple minSdk',
      'packaging { jniLibs { useLegacyPackaging = config.extract } }':
          'custom expression',
      'packaging { jniLibs.useLegacyPackaging = flag }':
          'custom Gradle override',
    };
    for (final entry in settings.entries) {
      final source = 'android { ${entry.key} }\n';
      final file = write('android/app/build.gradle.kts', source);
      expect(
          plan,
          throwsA(isA<SetupException>().having(
            (error) => error.toString(),
            'diagnostic',
            contains(entry.value),
          )));
      expect(file.readAsStringSync(), source);
    }
  });

  test('reports Maven repository policy and leaves its settings intact', () {
    write('android/app/build.gradle.kts', 'android {}\n');
    const path = 'android/settings.gradle.kts';
    const strict = '''dependencyResolutionManagement {
    repositoriesMode.set(
        RepositoriesMode.FAIL_ON_PROJECT_REPOS
    )
    repositories { mavenCentral() }
}
''';
    final settings = write(path, strict);
    expect(
        plan,
        throwsA(isA<SetupException>().having(
          (error) => error.toString(),
          'diagnostic',
          contains('FAIL_ON_PROJECT_REPOS'),
        )));
    expect(settings.readAsStringSync(), strict);

    final missingRepository = strict
        .replaceFirst('FAIL_ON_PROJECT_REPOS', 'PREFER_SETTINGS')
        .replaceFirst('mavenCentral()', 'google()');
    settings.writeAsStringSync(missingRepository);
    expect(plan().notes.join(' '), contains('approved mirror'));
    expect(settings.readAsStringSync(), missingRepository);
    settings.writeAsStringSync(
        strict.replaceFirst('FAIL_ON_PROJECT_REPOS', 'PREFER_SETTINGS'));
    expect(plan().notes.join(' '), isNot(contains('approved mirror')));
  });
}
