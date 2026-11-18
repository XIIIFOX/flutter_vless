part of '../xray_profile.dart';

/// A downloaded GeoDAT dataset and its relative `.dat` destination.
final class XrayGeoDataAsset {
  /// References an HTTPS [url] and existing asset [file] in Core's asset root.
  /// The URL may serve a gzip-compressed dataset.
  const XrayGeoDataAsset({required this.url, required this.file});

  /// HTTPS source of the dataset.
  final Uri url;

  /// Relative path of the existing `.dat` target.
  final String file;

  JsonMap _toCore() => {'url': url.toString(), 'file': file};
}

/// A schedule for reloading or updating GeoDAT inside an active Core.
///
/// Pass a list of [XrayGeoDataAsset]s to update files before reloading them.
/// An omitted list retains the existing asset declarations. An empty list
/// explicitly schedules a reload of the existing datasets without downloads.
final class XrayGeoDataSchedule {
  XrayGeoDataSchedule._(this._expression, List<XrayGeoDataAsset>? assets)
      : _assets = assets == null ? null : List.unmodifiable(assets);

  /// Reloads on a fixed [interval] of at least one minute.
  /// The interval must be representable in whole seconds as a Go duration.
  factory XrayGeoDataSchedule.every(
    Duration interval, {
    List<XrayGeoDataAsset>? assets,
  }) {
    if (interval < const Duration(minutes: 1) ||
        interval.inSeconds > 9223372036 ||
        interval.inMicroseconds % Duration.microsecondsPerSecond != 0) {
      throw ArgumentError(
          'GeoDAT interval requires whole seconds of at least one minute');
    }
    return XrayGeoDataSchedule._('@every ${interval.inSeconds}s', assets);
  }

  /// Schedules a reload using Core's cron grammar, for example `0 3 * * *`.
  /// Core validates expressions when the profile is checked or started.
  factory XrayGeoDataSchedule.cron(
    String expression, {
    List<XrayGeoDataAsset>? assets,
  }) {
    final value = expression.trim();
    if (value.isEmpty) throw ArgumentError('GeoDAT cron must be nonempty');
    return XrayGeoDataSchedule._(value, assets);
  }

  final String _expression;
  final List<XrayGeoDataAsset>? _assets;
}
