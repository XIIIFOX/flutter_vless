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

  for (final entry in {
    'prepare': 'The configuration could not be prepared.',
    'core-check':
        'The Xray configuration check could not complete successfully.',
    'start': 'The prepared configuration could not be started.',
  }.entries) {
    test('${entry.key} failures remain distinct without a report panel', () {
      expect(
        configurationFailureMessage(
          PlatformException(
            code: 'CORE_CONFIG_ERROR',
            message: canary,
            details: {'stage': entry.key, 'raw': canary},
          ),
        ),
        entry.value,
      );
    });
  }
}
