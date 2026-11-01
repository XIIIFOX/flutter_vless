import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../test_driver/import_contract_probe.dart';

/// Device-compiled import and sandbox-file checks only. This test deliberately
/// never initializes a VPN, requests VPN permission or starts a connection.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Device import preserves TLS identity and encoded credentials', (
    tester,
  ) async {
    final result = await runAcceptanceImportContract();
    // Independent expected values: the probe returns observations, not a PASS.
    expect(result['version'], 1);
    expect(result['probe'], 'synthetic_import_contract');
    expect(result['vmessRemark'], '');
    expect(result['vmessSni'], 'certificate.example.invalid');
    expect(result['vmessHttpHost'], 'http-front.example.invalid');
    expect(result['trojanPassword'], 'пароль+@:%2F');
    expect(result['vlessId'], 'тест+%2F');
    expect(result['sandboxConfiguration'], const {
      'outbounds': [
        {'protocol': 'freedom', 'tag': 'direct'},
      ],
      'extension': {
        'keep': [null, {}, [], '日本語 // # /* */'],
      },
    });
  });
}
