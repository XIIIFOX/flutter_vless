import 'package:flutter/material.dart';
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

class PreparationReportCard extends StatelessWidget {
  const PreparationReportCard({required this.report, super.key});
  final VlessPreparationReport report;

  @override
  Widget build(BuildContext context) {
    final boundary = switch (report.scope) {
      VlessPreparationScope.host => 'App configuration',
      VlessPreparationScope.runtimeFinal => 'Final runtime configuration',
      VlessPreparationScope.unavailable =>
        'Native preparation report unavailable',
    };
    final check = switch (report.coreCheck) {
      VlessCoreCheck.passed => 'Xray check passed',
      VlessCoreCheck.failed => 'Xray check failed',
      VlessCoreCheck.unavailable => 'Xray check unavailable',
      VlessCoreCheck.notRun => 'Xray check not run',
    };
    return Card(
      key: const Key('preparation-report'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Configuration check',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text('$boundary · $check'),
            const SizedBox(height: 4),
            Text(
              report.scope == VlessPreparationScope.host
                  ? 'Only the app-side configuration is covered. This check does not confirm internet access.'
                  : 'This report does not confirm internet access.',
            ),
            for (final change in VlessPreparationChange.values)
              if (report.changes.contains(change)) ...[
                const SizedBox(height: 6),
                Text(switch (change) {
                  VlessPreparationChange.certificateRefsBound =>
                    'Certificate file references resolved',
                  VlessPreparationChange.privateListenerAdded =>
                    'Private local listener added',
                  VlessPreparationChange.systemDnsGuardAdded =>
                    'System DNS protection added',
                  VlessPreparationChange.privateLoggingApplied =>
                    'Private logging applied',
                  VlessPreparationChange.portEnvironmentBound =>
                    'Listener port references resolved',
                  VlessPreparationChange.addressEnvironmentBound =>
                    'Endpoint address references resolved',
                  VlessPreparationChange.tlsOverrideRemoved =>
                    'Legacy TLS verification override removed',
                  VlessPreparationChange.streamAliasNormalized =>
                    'Legacy transport spelling normalized',
                }),
              ],
          ],
        ),
      ),
    );
  }
}
