import 'dart:convert';

import 'package:flutter_vless/url/url.dart';
import 'package:flutter_vless/url/xray_config_model.dart';
import 'package:flutter_vless/url/xray_config_validator.dart';
import 'package:flutter_vless/url/xray_json.dart';

/// Raw Xray JSON import wrapper.
///
/// Happ-style subscriptions can provide full Xray JSON or JSON arrays instead
/// of a compact share URL. Keep those configs as a 1:1 passthrough because some
/// server-provisioned values do not exist in the URL surface at all. The most
/// important current example is VLESS `users[].encryption` with
/// `mlkem768x25519plus...`: without that exact client value, XHTTP/none can
/// start Xray and pass SOCKS CONNECT while still failing to fetch real HTTP
/// bytes on device.
class XrayJsonConfig extends FlutterVlessURL {
  XrayJsonConfig({required super.url}) {
    final decoded = _decodeJsonConfig(url);
    late final Map<String, dynamic> decodedConfig;
    if (decoded is Map<String, dynamic>) {
      decodedConfig = decoded;
    } else if (decoded is List<dynamic> &&
        decoded.isNotEmpty &&
        decoded.first is Map<String, dynamic>) {
      decodedConfig = decoded.first as Map<String, dynamic>;
    } else {
      throw ArgumentError('JSON config is invalid');
    }

    const XrayConfigValidator().validate(decodedConfig);
    rawConfig = sanitizeXrayJson(decodedConfig, preserveStructure: true)
        as Map<String, dynamic>;
  }

  late final Map<String, dynamic> rawConfig;

  dynamic _decodeJsonConfig(String rawJson) {
    try {
      return decodeXrayJson(rawJson);
    } catch (_) {
      throw ArgumentError('JSON config is invalid');
    }
  }

  @override
  String get remark {
    final remarks = rawConfig['remarks'];
    if (remarks is String && remarks.isNotEmpty) {
      return remarks;
    }
    final remark = rawConfig['remark'];
    if (remark is String && remark.isNotEmpty) {
      return remark;
    }
    final ps = rawConfig['ps'];
    if (ps is String && ps.isNotEmpty) {
      return ps;
    }
    return 'Xray JSON';
  }

  @override
  Map<String, dynamic> get fullConfiguration => rawConfig;

  @override
  Map<String, dynamic> get outbound1 {
    final outbounds = readXraySchemaField(rawConfig, 'outbounds');
    if (outbounds is List<dynamic> &&
        outbounds.isNotEmpty &&
        outbounds.first is Map<String, dynamic>) {
      return outbounds.first as Map<String, dynamic>;
    }
    return {};
  }

  @override
  String getFullConfiguration({int indent = 2}) {
    return JsonEncoder.withIndent(' ' * indent).convert(rawConfig);
  }
}
