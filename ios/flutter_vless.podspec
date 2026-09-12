#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint flutter_vless.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'flutter_vless'
  s.version          = '1.1.6'
  s.summary          = 'Flutter VLESS/VMESS proxy and VPN plugin with XRay core.'
  s.description      = <<-DESC
Flutter plugin to run VLESS/VMESS as a local proxy and VPN on iOS with XRay core.
                       DESC
  s.homepage         = 'https://tfox.dev'
  s.license          = { :file => '../LICENSE' }
  s.author           = { '13FOX Studio' => '13fox.comp@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'flutter_vless/Sources/flutter_vless/**/*.swift', 'flutter_vless/Sources/flutter_vless_privacy/**/*.swift'
  s.dependency 'Flutter'
  s.platform = :ios, '15.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.static_framework = true
  xray_version = ENV['FLUTTER_VLESS_XRAY_VERSION'] || 'v26.7.28'
  xray_release_tag = ENV['FLUTTER_VLESS_XRAY_RELEASE_TAG'] || 'xray-ios-v26.7.28-r3'
  xray_url = ENV['FLUTTER_VLESS_XRAY_URL'] || "https://github.com/XIIIFOX/flutter_vless/releases/download/#{xray_release_tag}/XRay.xcframework.zip"
  xray_checksum = ENV['FLUTTER_VLESS_XRAY_CHECKSUM'] || '3792dc3ae6ffa42922c4604827812e48e29307d381d5db40a2c3932e0b779a60'

  s.prepare_command = <<-CMD
    set -e
    if [ ! -d XRay.xcframework ]; then
      echo "Downloading flutter_vless XRay #{xray_version} binary..."
      curl -L "#{xray_url}" -o XRay.xcframework.zip
      actual_checksum="$(swift package compute-checksum XRay.xcframework.zip)"
      if [ "$actual_checksum" != "#{xray_checksum}" ]; then
        echo "XRay.xcframework.zip checksum mismatch"
        echo "Expected: #{xray_checksum}"
        echo "Actual:   $actual_checksum"
        exit 1
      fi
      unzip -q XRay.xcframework.zip
      rm XRay.xcframework.zip
    fi
  CMD

  s.preserve_paths = 'XRay.xcframework/**/*'
  s.libraries = 'resolv'
  s.vendored_frameworks = 'XRay.xcframework'
  s.swift_version = '5.0'
end
