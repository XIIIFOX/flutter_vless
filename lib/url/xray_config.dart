import 'dart:convert';

import 'package:flutter_vless/url/url.dart';
import 'package:flutter_vless/url/xray_config_model.dart';
import 'package:flutter_vless/url/xray_config_validator.dart';
import 'package:flutter_vless/url/xray_json.dart';

/// Full-profile Xray JSON import with limited compatibility normalization.
///
/// Unlike share-link generators, this preserves unknown fields, explicit nulls,
/// empty containers and server-provided encryption values. Known transport
/// aliases are normalized and unsupported TLS `allowInsecure` overrides removed
/// at their schema owners; it is not a byte-for-byte passthrough. Native Core
/// and each platform adapter still validate the final prepared configuration.
class XrayJsonConfig extends FlutterVlessURL {
  /// Imports an Xray object, or the first object of a nonempty JSON array.
  ///
  /// Accepts the supported Core-style comments and leading BOM. Throws
  /// [ArgumentError] for invalid input or failed structural checks. A raw array
  /// contains only one selected profile here; use `FlutterVless.parseMany` to
  /// import every supported profile.
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

  /// Structurally checked configuration used by [fullConfiguration].
  ///
  /// Unknown fields, explicit nulls and empty containers are retained, with
  /// limited schema-owned compatibility normalization. This map is mutable and
  /// can contain credentials. Editing it bypasses the constructor validation.
  late final Map<String, dynamic> rawConfig;

  dynamic _decodeJsonConfig(String rawJson) {
    try {
      return decodeXrayJson(rawJson);
    } catch (_) {
      throw ArgumentError('JSON config is invalid');
    }
  }

  /// Display name from `remarks`, `remark` or `ps`, falling back to `Xray JSON`.
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

  /// Returns [rawConfig] by reference, including all retained full-profile fields.
  ///
  /// This getter does not rebuild the document from typed share-link models.
  @override
  Map<String, dynamic> get fullConfiguration => rawConfig;

  /// First imported outbound object, or an empty map after caller removal.
  ///
  /// It may be a direct/block output rather than a remote proxy. The returned
  /// object belongs to [rawConfig]; edits are not revalidated by this getter.
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

  /// Serializes the retained full profile using [indent] spaces per level.
  ///
  /// This does not revalidate later edits to [rawConfig] or run native preflight.
  @override
  String getFullConfiguration({int indent = 2}) {
    return JsonEncoder.withIndent(' ' * indent).convert(rawConfig);
  }
}
