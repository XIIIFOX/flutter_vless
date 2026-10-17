import 'dart:convert';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Application preferences contain only Options; VPN URLs/configuration are
/// deliberately excluded. Restore before initializeVless on a cold app launch.
class ExampleOptionsStorage {
  static const key = 'flutter_vless_example.options.v1';
  static Future<VlessOptions> load() async {
    try {
      final preferences = await SharedPreferences.getInstance();
      final text = preferences.getString(key);
      if (text == null) return const VlessOptions();
      return VlessOptions.fromMap(
          Map<String, Object?>.from(jsonDecode(text) as Map));
    } catch (_) {
      return const VlessOptions();
    }
  }

  static Future<void> save(VlessOptions options) async {
    final text = jsonEncode(options.toMap());
    final preferences = await SharedPreferences.getInstance();
    if (!await preferences.setString(key, text)) {
      throw StateError(
          'Options applied, but the application could not save them for its next launch.');
    }
  }
}
