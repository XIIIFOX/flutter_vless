import 'package:flutter/services.dart';
import 'package:flutter_vless/flutter_vless.dart';

/// Do not render native exception text: it may come from a legacy runtime.
String configurationFailureMessage(PlatformException error) {
  final failure = VlessConfigurationFailure.fromDetails(error.details);
  final message = switch (failure?.stage) {
    'prepare' => 'The configuration could not be prepared.',
    'core-check' =>
      'The Xray configuration check could not complete successfully.',
    'persist' => 'The configuration could not be saved.',
    'start' => 'The prepared configuration could not be started.',
    'privacy' => 'The configuration could not be checked with private logging.',
    'decode' => 'Xray could not read the configuration.',
    'build' => 'Xray could not build the configuration.',
    'environment-policy' =>
      'This runtime cannot safely check environment settings.',
    'active-session' =>
      'Stop the active proxy session before replacing its configuration.',
    'port-environment' => 'A configured listener port could not be resolved.',
    'certificate-assets' => 'A certificate file could not be prepared.',
    'routing' =>
      'The VPN routing selection is incompatible with this configuration.',
    'capability' => 'The runtime does not support this configuration feature.',
    'internal' => 'The configuration check could not finish.',
    _ => switch (error.code) {
      'ALWAYS_ON_MANAGED' =>
        'Disable system Always-on VPN before stopping this session.',
      'VPN_KEYCHAIN_ERROR' =>
        'VPN credentials are unavailable. Check the app Keychain setup.',
      _ => 'The system could not change the VPN connection.',
    },
  };
  if (failure?.section == null || failure?.index == null) return message;
  final kind = failure!.section == 'inbounds' ? 'Inbound' : 'Outbound';
  return '$message $kind ${failure.index! + 1}.';
}
