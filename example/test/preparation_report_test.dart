import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/preparation_report.dart';

void main() {
  const canary = 'CANARY-private-config-path-host';
  test('error display uses only closed stages and bounded locations', () {
    final message = configurationFailureMessage(
      PlatformException(
        code: 'CORE_CONFIG_ERROR',
        message: canary,
        details: {
          'stage': 'build',
          'section': 'outbounds',
          'index': 2,
          'raw': canary,
        },
      ),
    );
    expect(message, 'Xray could not build the configuration. Outbound 3.');
    expect(message, isNot(contains(canary)));
    expect(
      configurationFailureMessage(
        PlatformException(
          code: canary,
          message: canary,
          details: {'stage': canary, 'section': canary},
        ),
      ),
      'The system could not change the VPN connection.',
    );
    for (final stage in VlessConfigurationFailure.stages) {
      expect(
        configurationFailureMessage(
          PlatformException(
            code: canary,
            message: canary,
            details: {'stage': stage, 'raw': canary},
          ),
        ),
        isNot(contains(canary)),
      );
    }
  });

  testWidgets(
    'host report cannot be mistaken for extension or internet success',
    (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PreparationReportCard(
              report: VlessPreparationReport(
                scope: VlessPreparationScope.host,
                coreCheck: VlessCoreCheck.passed,
                changes: [VlessPreparationChange.tlsOverrideRemoved],
              ),
            ),
          ),
        ),
      );
      expect(
        find.text('App configuration · Xray check passed'),
        findsOneWidget,
      );
      expect(
        find.textContaining('Only the app-side configuration'),
        findsOneWidget,
      );
      expect(
        find.textContaining('does not confirm internet access'),
        findsOneWidget,
      );
      expect(
        find.text('Legacy TLS verification override removed'),
        findsOneWidget,
      );
      expect(find.textContaining('Final runtime configuration'), findsNothing);
    },
  );

  testWidgets('old runtime displays unavailability with known Dart edits', (
    tester,
  ) async {
    final report = const VlessPreparationReport.unavailable().withChanges([
      VlessPreparationChange.tlsOverrideRemoved,
    ]);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: PreparationReportCard(report: report)),
      ),
    );
    expect(
      find.textContaining('Native preparation report unavailable'),
      findsOneWidget,
    );
    expect(find.textContaining('Xray check passed'), findsNothing);
    expect(
      find.text('Legacy TLS verification override removed'),
      findsOneWidget,
    );
  });
}
