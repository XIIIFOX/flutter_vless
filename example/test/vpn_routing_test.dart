import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/vpn_routing.dart';

void main() {
  const config =
      '\ufeff{/* imported profile */"inbounds":'
      '[{"tag":"caller","protocol":"socks"}],"outbounds":'
      '[{"tag":"blocked","protocol":"blackhole"},'
      '{"tag":"chosen","protocol":"freedom"}]}';

  testWidgets(
    'choose the original input and a non-first default independently',
    (tester) async {
      VpnRoutingOptions? selection;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: StatefulBuilder(
              builder: (context, setState) => VpnRoutingPanel(
                config: config,
                value: selection,
                proxyOnly: false,
                onChanged: (value) => setState(() => selection = value),
              ),
            ),
          ),
        ),
      );
      await tester.tap(find.byType(Switch));
      await tester.pumpAndSettle();
      expect(selection?.toMap(), isEmpty);
      await tester.tap(find.text('VPN input'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('caller (socks)').last);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Configuration default'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('chosen').last);
      await tester.pumpAndSettle();
      expect(selection?.toMap(), {
        'sourceInboundIndex': 0,
        'defaultOutboundTag': 'chosen',
      });
      await tester.tap(find.byType(Switch));
      await tester.pumpAndSettle();
      expect(selection, isNull);
    },
  );

  testWidgets('proxy-only mode does not offer VPN routing controls', (
    tester,
  ) async {
    var changed = false;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: VpnRoutingPanel(
            config: config,
            proxyOnly: true,
            value: const VpnRoutingOptions(sourceInboundIndex: 0),
            onChanged: (_) => changed = true,
          ),
        ),
      ),
    );
    expect(tester.widget<Switch>(find.byType(Switch)).onChanged, isNull);
    expect(find.byType(DropdownButtonFormField<int>), findsNothing);
    expect(changed, isFalse);
  });

  testWidgets(
    'editing a profile never silently replaces a previous selection',
    (tester) async {
      var changed = false;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: VpnRoutingPanel(
              config: '{"inbounds":[],"outbounds":[]}',
              proxyOnly: false,
              value: const VpnRoutingOptions(
                sourceInboundIndex: 5,
                defaultOutboundTag: 'previous',
              ),
              onChanged: (_) => changed = true,
            ),
          ),
        ),
      );
      expect(find.text('Input 6 (missing)'), findsOneWidget);
      expect(find.text('previous (missing)'), findsOneWidget);
      expect(changed, isFalse);
    },
  );

  testWidgets('invalid draft JSON and duplicate tags do not crash the editor', (
    tester,
  ) async {
    for (final source in ['{', '{"outbounds":[{"tag":"x"},{"tag":"x"}]}']) {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: VpnRoutingPanel(
              config: source,
              proxyOnly: false,
              value: const VpnRoutingOptions(),
              onChanged: (_) {},
            ),
          ),
        ),
      );
      expect(tester.takeException(), isNull);
    }
  });
}
