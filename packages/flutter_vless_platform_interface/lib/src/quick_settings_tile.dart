/// Android Quick Settings tile appearance configured during [VlessPlatform.initializeVless].
///
/// Icons must reference Android `drawable` or `mipmap` resources in the host app.
class QuickSettingsTile {
  QuickSettingsTile(
      {required this.tileLabel,
      required this.tileIconResourceType,
      required this.tileIconResourceName});

  final String tileLabel;
  final String tileIconResourceType;
  final String tileIconResourceName;
}
