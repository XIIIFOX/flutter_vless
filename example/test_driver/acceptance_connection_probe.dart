// Development entrypoint only. These observations never configure a resolver,
// open a direct HTTP fallback, or change the device's network settings.
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';

import 'acceptance_web_probe.dart';

final class AcceptanceInterfaceAddresses {
  AcceptanceInterfaceAddresses(this.index, List<InternetAddress> addresses)
    : addresses = List.unmodifiable(addresses);
  final int index;
  final List<InternetAddress> addresses;
}

typedef AcceptanceInterfaceReader =
    Future<List<AcceptanceInterfaceAddresses>> Function();

Future<List<AcceptanceInterfaceAddresses>> _readInterfaceAddresses() async {
  final interfaces = await NetworkInterface.list(
    type: InternetAddressType.any,
    includeLoopback: false,
    includeLinkLocal: true,
  );
  return interfaces
      .map(
        (value) => AcceptanceInterfaceAddresses(value.index, value.addresses),
      )
      .toList();
}

const _targets = {'2ip': 'https://2ip.io/ru/', 'tfox': 'https://tfox.dev/ip/'};

Future<bool> acceptanceConnectionProbeAdmitted({
  bool Function()? isAndroidDebugRuntime,
}) async {
  // This file is reachable only from the development driver entrypoint.
  // Android has no Apple web diagnostics channel; its own debug runner can
  // observe these fixed probes. Apple keeps its native opt-in/visibility gate.
  if ((isAndroidDebugRuntime ?? () => kDebugMode && Platform.isAndroid)()) {
    return true;
  }
  try {
    return await acceptanceWebChannel
            .invokeMethod<bool>('available')
            .timeout(const Duration(seconds: 1)) ==
        true;
  } catch (_) {
    return false;
  }
}

Future<Map<String, Object>> runAcceptanceConnectedProbe(String target) async {
  final output = <String, Object>{
    'version': 1,
    'probe': 'connected_domain_socks',
    'target': target,
    'status': 'unavailable',
  };
  final url = _targets[target];
  if (url == null) throw ArgumentError('unsupported fixed target');
  if (!await acceptanceConnectionProbeAdmitted()) return output;
  try {
    // The provider uses the active managed SOCKS endpoint and domain ATYP.
    // A negative answer is ambiguous (HTTP challenge, timeout, or transport).
    // The method performs no direct/origin fallback and is never retried here.
    const channel = MethodChannel('flutter_vless');
    final delay = await channel
        .invokeMethod<int>('getConnectedServerDelay', {'url': url})
        .timeout(const Duration(seconds: 10));
    if (delay != null && delay >= 0 && delay <= 60000) {
      output['status'] = 'response';
      output['delayMs'] = delay;
    }
  } catch (_) {
    // Native exception details can contain configuration or host information.
  }
  return output;
}

Future<Map<String, Object>> runAcceptanceNetworkInventory({
  AcceptanceInterfaceReader? readInterfaces,
}) async {
  final interfaces = await (readInterfaces ?? _readInterfaceAddresses)()
      .timeout(const Duration(seconds: 2));
  final rows = <Map<String, Object>>[];
  var remaining = 256;
  for (final interface in interfaces.take(32)) {
    final counts = <String, int>{
      'ipv4': 0,
      'ipv6Global': 0,
      'ipv6UniqueLocal': 0,
      'ipv6LinkLocal': 0,
      'ipv6Other': 0,
    };
    for (final address in interface.addresses) {
      if (remaining-- <= 0) break;
      if (address.isLoopback) continue;
      final bytes = address.rawAddress;
      if (address.type == InternetAddressType.IPv4) {
        counts['ipv4'] = counts['ipv4']! + 1;
      } else if (bytes.length == 16) {
        final key = bytes[0] & 0xe0 == 0x20
            ? 'ipv6Global'
            : bytes[0] & 0xfe == 0xfc
            ? 'ipv6UniqueLocal'
            : bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
            ? 'ipv6LinkLocal'
            : 'ipv6Other';
        counts[key] = counts[key]! + 1;
      }
    }
    rows.add({'index': interface.index, ...counts});
  }
  return {
    'version': 1,
    'probe': 'interface_families',
    'status': interfaces.length > 32 || remaining < 0 ? 'bounded' : 'observed',
    'scope': 'assigned_addresses_only',
    // No interface names, SSIDs, literal addresses, DNS settings or credentials.
    // Assigned IPv6 never claims Internet reachability, DNS64 or handover.
    'interfaces': rows,
  };
}
