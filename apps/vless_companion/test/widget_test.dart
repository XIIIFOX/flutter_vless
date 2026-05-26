import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_companion/main.dart';

void main() {
  testWidgets('companion renders shell', (tester) async {
    await tester.pumpWidget(const CompanionApp());
    expect(find.text('Flutter Vless Companion'), findsWidgets);
    expect(find.text('Profile input'), findsOneWidget);
  });
}
