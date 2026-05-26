# Flutter Vless Native Host

This package is the Chrome Native Messaging bridge between the browser
extension and the desktop companion app.

Build and register the dev host from the repository root:

```bash
dart run tool/setup_chrome_extension_dev.dart
```

Manual build:

```bash
dart pub get
mkdir -p build
dart compile exe bin/flutter_vless_native_host.dart -o build/flutter_vless_native_host
```

The installer should copy the executable, write the browser-specific native
messaging manifest, replace the `path`, and restrict `allowed_origins` to the
published extension id.
