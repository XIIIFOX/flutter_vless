# frozen_string_literal: true
require 'optparse'
require 'pathname'
require 'fileutils'
begin
  require 'xcodeproj'
rescue LoadError
  abort 'The xcodeproj Ruby gem is required (included with CocoaPods). Install it with: gem install xcodeproj'
end
options = { root: '.', platform: 'ios' }
OptionParser.new do |parser|
  parser.on('--project-dir PATH') { |v| options[:root] = v }
  parser.on('--platform NAME') { |v| options[:platform] = v }
  parser.on('--bundle-id ID') { |v| options[:bundle] = v }
  parser.on('--group-id ID') { |v| options[:group] = v }
  parser.on('--team-id ID') { |v| options[:team] = v }
end.parse!
abort 'Platform must be ios or macos' unless %w[ios macos].include?(options[:platform])
abort 'A valid --bundle-id and --group-id are required' unless [options[:bundle], options[:group]].all? { |v| v&.match?(/\A[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\z/) } && options[:group].start_with?('group.')
app_version = File.read(Pathname.new(options[:root]).expand_path.join('pubspec.yaml')).match(/^version:\s*['\"]?([0-9.]+)(?:\+([0-9]+))?/i)
marketing_version = app_version ? app_version[1] : '1.1.7'
build_number = app_version && app_version[2] ? app_version[2] : '1'
platform = options[:platform]
root = Pathname.new(options[:root]).expand_path.join(platform)
path = root.join('Runner.xcodeproj')
abort "Project missing: #{path}" unless path.directory?
project = Xcodeproj::Project.open(path)
host = project.targets.find { |target| target.name == 'Runner' }
abort 'Runner app target missing' unless host
name = 'VlessControls'
existing = project.targets.find { |target| target.name == name }
info_path = root.join(name, 'Info.plist')
if existing && (!info_path.file? || Xcodeproj::Plist.read_from_path(info_path)['FlutterVlessGeneratedControls'] != true)
  abort 'An unrelated VlessControls target already exists. Choose another target name before running this generator.'
end
package = project.root_object.package_references.find { |ref| ref.isa == 'XCLocalSwiftPackageReference' && ref.relative_path.match?(/(?:flutter_vless(?:_macos)?|\.packages\/flutter_vless(?:_macos)?)\/?\z/) }
abort 'Prepare the flutter_vless SwiftPM package in Xcode first (for macOS run setup_macos_vpn).' unless package
# Resolve app Info and signing files before making any changes.
host_infos = host.build_configurations.map { |c| c.build_settings['INFOPLIST_FILE'] }.compact.uniq.map { |p| root.join(p) }
abort 'Runner must have a concrete Info.plist path' if host_infos.empty? || host_infos.any? { |p| !p.file? }
entitlements = host.build_configurations.map { |c| c.build_settings['CODE_SIGN_ENTITLEMENTS'] }.compact.uniq.map { |p| root.join(p) }
abort 'Configure Runner VPN/App Group entitlements before adding controls' if entitlements.empty? || entitlements.any? { |p| !p.file? }
minimum = platform == 'ios' ? '18.0' : '26.0'
target = existing || project.new_target(:app_extension, name, platform == 'ios' ? :ios : :osx, minimum)
group = project.main_group.find_subpath(name, true)
group.set_source_tree('<group>'); group.path = name
source_root = Pathname.new(__dir__).parent.join('templates', 'apple_controls')
FileUtils.mkdir_p(root.join(name))
%w[VlessControlIntent.swift VlessControls.swift].each do |file|
  FileUtils.cp(source_root.join(file), root.join(name, file))
  reference = group.files.find { |f| f.path == file } || group.new_file(file)
  target.add_file_references([reference]) unless target.source_build_phase.files_references.include?(reference)
  if file == 'VlessControlIntent.swift'
    host.add_file_references([reference]) unless host.source_build_phase.files_references.include?(reference)
  end
end
[host, target].each do |owner|
  dependency = owner.package_product_dependencies.find { |d| d.product_name == 'flutter-vless-controls' }
  unless dependency
    dependency = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
    dependency.package = package; dependency.product_name = 'flutter-vless-controls'
    owner.package_product_dependencies << dependency
  end
  unless owner.frameworks_build_phase.files.any? { |f| f.product_ref == dependency }
    build = project.new(Xcodeproj::Project::Object::PBXBuildFile); build.product_ref = dependency
    owner.frameworks_build_phase.files << build
  end
end
provider = "#{options[:bundle]}.XrayTunnel"
metadata = { 'FlutterVlessControlGroupIdentifier' => options[:group], 'FlutterVlessControlProviderIdentifier' => provider }
host_infos.each do |file|
  info = Xcodeproj::Plist.read_from_path(file)
  info['NSFaceIDUsageDescription'] ||= 'Authenticate to change your VPN connection.' if platform == 'ios'
  Xcodeproj::Plist.write_to_path(info.merge(metadata).merge('FlutterVlessControlsConfigured' => true), file)
end
entitlements.each do |file|
  data = Xcodeproj::Plist.read_from_path(file)
  data['com.apple.security.application-groups'] = (Array(data['com.apple.security.application-groups']) + [options[:group]]).uniq
  Xcodeproj::Plist.write_to_path(data, file)
end
info = metadata.merge('FlutterVlessGeneratedControls' => true,
  'CFBundleDisplayName' => 'VPN Controls', 'CFBundleExecutable' => '$(EXECUTABLE_NAME)',
  'CFBundleIdentifier' => '$(PRODUCT_BUNDLE_IDENTIFIER)', 'CFBundleName' => '$(PRODUCT_NAME)',
  'CFBundlePackageType' => 'XPC!', 'CFBundleShortVersionString' => '$(MARKETING_VERSION)',
  'CFBundleVersion' => '$(CURRENT_PROJECT_VERSION)',
  'NSExtension' => { 'NSExtensionPointIdentifier' => 'com.apple.widgetkit-extension' })
Xcodeproj::Plist.write_to_path(info, info_path)
widget_entitlements = { 'com.apple.security.application-groups' => [options[:group]],
  'com.apple.developer.networking.networkextension' => ['packet-tunnel-provider'] }
widget_entitlements['com.apple.security.app-sandbox'] = true if platform == 'macos'
Xcodeproj::Plist.write_to_path(widget_entitlements, root.join(name, "#{name}.entitlements"))
# The widget can inspect only this app's profile; the intent executes in Runner.
target.build_configurations.each do |configuration|
  settings = configuration.build_settings
  settings.merge!('PRODUCT_NAME' => '$(TARGET_NAME)', 'PRODUCT_BUNDLE_IDENTIFIER' => "#{options[:bundle]}.#{name}", 'INFOPLIST_FILE' => "#{name}/Info.plist",
    'CODE_SIGN_ENTITLEMENTS' => "#{name}/#{name}.entitlements", 'SWIFT_VERSION' => '5.0',
    'APPLICATION_EXTENSION_API_ONLY' => 'YES', 'SKIP_INSTALL' => 'YES',
    'SWIFT_ACTIVE_COMPILATION_CONDITIONS' => '$(inherited) FLUTTER_VLESS_WIDGET_EXTENSION',
    'MARKETING_VERSION' => marketing_version, 'CURRENT_PROJECT_VERSION' => build_number, 'CODE_SIGN_STYLE' => 'Automatic')
  settings['DEVELOPMENT_TEAM'] = options[:team] || host.build_configurations.first.build_settings['DEVELOPMENT_TEAM']
  settings[platform == 'ios' ? 'IPHONEOS_DEPLOYMENT_TARGET' : 'MACOSX_DEPLOYMENT_TARGET'] = minimum
  settings['TARGETED_DEVICE_FAMILY'] = '1,2' if platform == 'ios'
end
host.add_dependency(target) unless host.dependencies.any? { |d| d.target == target }
embed = host.copy_files_build_phases.find { |phase| phase.dst_subfolder_spec == '13' } || host.new_copy_files_build_phase('Embed App Extensions')
embed.dst_subfolder_spec = '13'
unless embed.files_references.include?(target.product_reference)
  build = embed.add_file_reference(target.product_reference)
  build.settings = { 'ATTRIBUTES' => ['RemoveHeadersOnCopy'] }
end
project.save
puts "#{platform} controls configured (#{minimum}+). Enable App Groups and Network Extensions for the controls App ID in signing, then build Runner."
