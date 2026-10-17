import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/options.dart';

void main() {
  const caps = VlessCapabilities(
      optionsVersion: 1,
      quickAccessSurfaces: [QuickAccessSurface.quickTile],
      requestAddQuickTile: true,
      alwaysOn: true);
  testWidgets(
      'example exposes all five blocks, native actions and validated apply',
      (tester) async {
    VlessOptions? applied;
    int additions = 0, clears = 0;
    await tester.pumpWidget(MaterialApp(
        home: PluginOptionsPage(
            initial: const VlessOptions(),
            capabilities: caps,
            onApply: (v) async {
              applied = v;
            },
            onAddTile: () async {
              additions++;
              return QuickTileAddResult.added;
            },
            onClearProfile: () async {
              clears++;
            })));
    expect(find.text('Notification Options'), findsOneWidget);
    Future<void> reach(String text) async {
      await tester.scrollUntilVisible(find.text(text), 300,
          scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
    }

    await reach('Quick Access Options');
    await reach('Enable system control');
    await tester.tap(find.text('Enable system control'));
    await tester.pump();
    await reach('Add Android Quick Tile');
    await tester.tap(find.text('Add Android Quick Tile'));
    await tester.pumpAndSettle();
    expect(additions, 1);
    await reach('Forget quick-access profile');
    await tester.tap(find.text('Forget quick-access profile'));
    await tester.pumpAndSettle();
    expect(clears, 1);
    await reach('Reconnect Options');
    expect(find.text('Auto Reconnect'), findsOneWidget);
    await reach('Protection Options');
    expect(find.text('Kill Switch'), findsOneWidget);
    await reach('Diagnostics Options');
    await reach('Apply options');
    await tester.tap(find.text('Apply options'));
    await tester.pumpAndSettle();
    expect(applied?.quickAccess.enabled, isTrue);
    expect(applied?.protection.killSwitch, KillSwitchPolicy.required);
    expect(applied?.reconnect.enabled, isTrue);
    expect(applied?.diagnostics.enabled, isTrue);
  });
  testWidgets('example refuses invalid bounds without applying or dismissing',
      (tester) async {
    int applications = 0;
    await tester.pumpWidget(MaterialApp(
        home: PluginOptionsPage(
            initial: const VlessOptions(),
            capabilities: caps,
            onApply: (_) async {
              applications++;
            },
            onAddTile: () async => QuickTileAddResult.unsupported,
            onClearProfile: () async {})));
    final input = find.widgetWithText(TextField, 'Diagnostics lines (1–300)');
    await tester.scrollUntilVisible(input, 400,
        scrollable: find.byType(Scrollable).first);
    await tester.enterText(input, '0');
    tester.testTextInput.hide();
    await tester.scrollUntilVisible(find.text('Apply options'), 300,
        scrollable: find.byType(Scrollable).first);
    await tester.tap(find.text('Apply options'));
    await tester.pumpAndSettle();
    expect(applications, 0);
    expect(find.text('Plugin options'), findsOneWidget);
    expect(find.textContaining('Diagnostics limits'), findsOneWidget);
  });
  testWidgets(
      'a restored unavailable control can be disabled without a dropdown failure',
      (tester) async {
    VlessOptions? applied;
    await tester.pumpWidget(MaterialApp(
        home: PluginOptionsPage(
            initial: const VlessOptions(
                quickAccess: QuickAccessOptions(
                    enabled: true, surface: QuickAccessSurface.controlCenter)),
            capabilities: const VlessCapabilities(optionsVersion: 1),
            onApply: (value) async {
              applied = value;
            },
            onAddTile: () async => QuickTileAddResult.unsupported,
            onClearProfile: () async {})));
    await tester.scrollUntilVisible(find.text('Enable system control'), 300,
        scrollable: find.byType(Scrollable).first);
    await tester.tap(find.text('Enable system control'));
    await tester.pump();
    await tester.tap(find.text('Apply options'));
    await tester.pumpAndSettle();
    expect(applied?.quickAccess.enabled, isFalse);
    expect(tester.takeException(), isNull);
  });
}
