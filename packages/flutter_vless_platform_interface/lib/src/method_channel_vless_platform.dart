import 'vless_method_channel_adapter.dart';

/// Default MethodChannel implementation using [VlessMethodChannelAdapter].
/// This is used when no platform-specific implementation is registered.
class MethodChannelVlessPlatform extends VlessMethodChannelAdapter {
  /// Creates the adapter using the standard method and status channels.
  MethodChannelVlessPlatform();
}
