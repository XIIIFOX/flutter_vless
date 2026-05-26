import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_vless/flutter_vless.dart';

class CompanionProfile {
  CompanionProfile({
    required this.id,
    required this.remark,
    required this.config,
  });

  final String id;
  final String remark;
  final String config;

  Map<String, Object?> toJson() {
    return {'id': id, 'remark': remark, 'config': config};
  }
}

class ProxyEndpoint {
  const ProxyEndpoint({
    required this.scheme,
    required this.host,
    required this.port,
  });

  static const fallback = ProxyEndpoint(
    scheme: 'socks5',
    host: '127.0.0.1',
    port: 10807,
  );

  final String scheme;
  final String host;
  final int port;

  String get label => '$scheme://$host:$port';

  Map<String, Object?> toJson() {
    return {'scheme': scheme, 'host': host, 'port': port};
  }
}

class CompanionController extends ChangeNotifier {
  CompanionController() {
    _runtime = FlutterVless(
      onStatusChanged: (status) {
        _status = status;
        notifyListeners();
      },
    );
  }

  late final FlutterVless _runtime;
  final List<CompanionProfile> _profiles = [];
  VlessStatus _status = VlessStatus();
  CompanionProfile? _activeProfile;
  String _coreVersion = '';

  List<CompanionProfile> get profiles => List.unmodifiable(_profiles);
  VlessStatus get status => _status;
  CompanionProfile? get activeProfile => _activeProfile;
  String get coreVersion => _coreVersion;

  ProxyEndpoint get proxyEndpoint {
    final profile =
        _activeProfile ?? (_profiles.isEmpty ? null : _profiles.last);
    if (profile == null) {
      return ProxyEndpoint.fallback;
    }
    return _readProxyEndpoint(profile.config);
  }

  Future<void> initialize() async {
    await _runtime.initializeVless(
      providerBundleIdentifier: 'dev.tfox.flutterVlessCompanion',
      groupIdentifier: 'group.dev.tfox.flutterVlessCompanion',
    );
    _coreVersion = await _runtime.getCoreVersion();
    notifyListeners();
  }

  Future<CompanionProfile> importProfile(String input) async {
    final trimmed = input.trim();
    if (trimmed.isEmpty) {
      throw ArgumentError('Profile input is empty.');
    }

    final parsed = FlutterVless.parse(trimmed);
    final profile = CompanionProfile(
      id: DateTime.now().microsecondsSinceEpoch.toString(),
      remark: parsed.remark.isEmpty ? 'Imported profile' : parsed.remark,
      config: parsed.getFullConfiguration(),
    );
    _profiles.add(profile);
    _activeProfile = profile;
    notifyListeners();
    return profile;
  }

  Future<void> connect({
    String? profileId,
    String? input,
    String? config,
    String? remark,
    bool setSystemProxy = false,
  }) async {
    CompanionProfile profile;
    if (config != null && config.trim().isNotEmpty) {
      profile = CompanionProfile(
        id: DateTime.now().microsecondsSinceEpoch.toString(),
        remark: remark?.trim().isNotEmpty == true
            ? remark!.trim()
            : 'Raw Xray JSON',
        config: config,
      );
      _profiles.add(profile);
    } else if (input != null && input.trim().isNotEmpty) {
      profile = await importProfile(input);
    } else if (profileId != null) {
      profile = _profiles.firstWhere(
        (candidate) => candidate.id == profileId,
        orElse: () => throw ArgumentError('Profile not found: $profileId'),
      );
    } else if (_activeProfile != null) {
      profile = _activeProfile!;
    } else if (_profiles.isNotEmpty) {
      profile = _profiles.last;
    } else {
      throw StateError('No profile is available to connect.');
    }

    _activeProfile = profile;
    await _runtime.startVless(
      remark: profile.remark,
      config: profile.config,
      proxyOnly: true,
      setSystemProxy: setSystemProxy,
    );
    notifyListeners();
  }

  Future<void> disconnect() async {
    await _runtime.stopVless();
    _status = VlessStatus();
    notifyListeners();
  }

  Future<int> delay({String url = 'https://google.com/generate_204'}) async {
    final profile =
        _activeProfile ?? (_profiles.isEmpty ? null : _profiles.last);
    if (profile == null) {
      throw StateError('No profile is available for delay measurement.');
    }
    return _runtime.getServerDelay(config: profile.config, url: url);
  }

  Map<String, Object?> toStatusJson() {
    return {
      'state': _status.state,
      'connectionState': _status.connectionState.name,
      'duration': _status.duration,
      'uploadSpeed': _status.uploadSpeed,
      'downloadSpeed': _status.downloadSpeed,
      'upload': _status.upload,
      'download': _status.download,
      'coreVersion': _coreVersion,
      'activeProfile': _activeProfile?.toJson(),
      'proxyEndpoint': proxyEndpoint.toJson(),
      'profiles': _profiles.map((profile) => profile.toJson()).toList(),
    };
  }

  ProxyEndpoint _readProxyEndpoint(String config) {
    try {
      final decoded = jsonDecode(config);
      if (decoded is! Map<String, dynamic>) {
        return ProxyEndpoint.fallback;
      }
      final inbounds = decoded['inbounds'];
      if (inbounds is! List) {
        return ProxyEndpoint.fallback;
      }

      Map<String, dynamic>? firstHttp;
      Map<String, dynamic>? firstSocks;
      for (final inbound in inbounds.whereType<Map>()) {
        final typed = inbound.cast<String, dynamic>();
        final protocol = typed['protocol'];
        if (protocol == 'socks' && firstSocks == null) {
          firstSocks = typed;
        } else if (protocol == 'http' && firstHttp == null) {
          firstHttp = typed;
        }
      }

      final selected = firstSocks ?? firstHttp;
      if (selected == null) {
        return ProxyEndpoint.fallback;
      }
      final protocol = selected['protocol'] == 'http' ? 'http' : 'socks5';
      final port = selected['port'];
      return ProxyEndpoint(
        scheme: protocol,
        host: selected['listen'] as String? ?? '127.0.0.1',
        port: port is int ? port : ProxyEndpoint.fallback.port,
      );
    } catch (_) {
      return ProxyEndpoint.fallback;
    }
  }
}
