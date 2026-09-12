Pod::Spec.new do |s|
  s.name             = 'flutter_vless_macos'
  s.version          = '1.1.6'
  s.summary          = 'macOS implementation of the flutter_vless plugin.'
  s.description      = <<-DESC
macOS implementation of the flutter_vless plugin.
                       DESC
  s.homepage         = 'https://tfox.dev'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { '13FOX Studio' => '13fox.comp@gmail.com' }

  s.source = { :path => '..' }
  cxray_pod_include_dir = '${PODS_TARGET_SRCROOT}/flutter_vless_macos/Sources/CXRay/include'
  cxray_user_include_dir = '${PODS_ROOT}/../Flutter/ephemeral/.symlinks/plugins/flutter_vless_macos/macos/flutter_vless_macos/Sources/CXRay/include'

  s.source_files = 'flutter_vless_macos/Sources/flutter_vless_macos/**/*.swift'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '13.0'
  s.osx.deployment_target = '13.0'

  s.prepare_command = <<-CMD
    set -e
    FRAMEWORK_DIR="XRay.xcframework"
    FRAMEWORK_ZIP="XRay.xcframework.zip"

    if [ -d "$FRAMEWORK_DIR" ]; then
      exit 0
    fi

    DEFAULT_FRAMEWORK_URL="https://github.com/XIIIFOX/flutter_vless/releases/download/xray-macos-v26.7.28/XRay.xcframework.zip"
    FRAMEWORK_URL="${FLUTTER_VLESS_MACOS_FRAMEWORK_URL:-$DEFAULT_FRAMEWORK_URL}"
    FRAMEWORK_SHA256="${FLUTTER_VLESS_MACOS_FRAMEWORK_SHA256:-be0102278d72659086d6b7235adff20a07bdd4966a003f5cf3eeae5850ceb8ab}"

    rm -rf "$FRAMEWORK_DIR" "$FRAMEWORK_ZIP"

    curl -fL -A "Mozilla/5.0" -o "$FRAMEWORK_ZIP" "$FRAMEWORK_URL"

    if [ -n "$FRAMEWORK_SHA256" ]; then
      echo "$FRAMEWORK_SHA256  $FRAMEWORK_ZIP" | shasum -a 256 -c -
    else
      echo "flutter_vless_macos: FLUTTER_VLESS_MACOS_FRAMEWORK_SHA256 not set; checksum verification skipped." >&2
    fi

    unzip -q "$FRAMEWORK_ZIP"
    rm "$FRAMEWORK_ZIP"

    if [ ! -d "$FRAMEWORK_DIR" ]; then
      echo "flutter_vless_macos: extracted XRay.xcframework is invalid or incomplete." >&2
      exit 1
    fi
  CMD

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'HEADER_SEARCH_PATHS' => '$(inherited) "' + cxray_pod_include_dir + '"',
    'OTHER_SWIFT_FLAGS' => '$(inherited) -Xcc -fmodule-map-file="' + cxray_pod_include_dir + '/module.modulemap"',
  }
  s.user_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '$(inherited) "' + cxray_user_include_dir + '"',
    'OTHER_SWIFT_FLAGS' => '$(inherited) -Xcc -fmodule-map-file="' + cxray_user_include_dir + '/module.modulemap"',
  }
  s.swift_version = '5.0'
  s.libraries = 'resolv'
  s.vendored_frameworks = 'XRay.xcframework'
end
