#!/usr/bin/env python3
"""Exercise the real generator against disposable copies, never host signing/VPN."""
import pathlib
import plistlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="vless-controls-") as folder:
    target = pathlib.Path(folder)
    shutil.copy(ROOT / "example/pubspec.yaml", target / "pubspec.yaml")
    for platform in ("ios", "macos"):
        source = ROOT / "example" / platform
        project = target / platform
        (project / "Runner.xcodeproj").mkdir(parents=True)
        shutil.copy(source / "Runner.xcodeproj/project.pbxproj", project / "Runner.xcodeproj/project.pbxproj")
        shutil.copytree(source / "Runner", project / "Runner", ignore=shutil.ignore_patterns("Assets.xcassets", "*.xcassets"))
        # Remove the existing generated extension to exercise file regeneration.
        command = ["ruby", str(ROOT / "bin/setup_apple_controls.rb"), "--project-dir", str(target), "--platform", platform,
                   "--bundle-id", "dev.tfox.fixture", "--group-id", "group.dev.tfox.fixture"]
        # Start without a target, then exercise the existing-target path on rerun.
        subprocess.run(["ruby", "-rxcodeproj", "-e", """
project=Xcodeproj::Project.open(ARGV[0]); target=project.targets.find { |t| t.name=='VlessControls' }
if target
  project.targets.each { |t| t.dependencies.select { |d| d.target==target }.each(&:remove_from_project) }
  product=target.product_reference
  project.targets.each { |t| t.copy_files_build_phases.each { |phase| phase.files.select { |f| f.file_ref==product }.each(&:remove_from_project) } }
  target.remove_from_project; product.remove_from_project
end
project.save
""", str(project / "Runner.xcodeproj")],check=True,capture_output=True)
        (project / "VlessControls").mkdir()
        shutil.copy(source / "VlessControls/Info.plist", project / "VlessControls/Info.plist")
        subprocess.run(command, check=True, capture_output=True)
        files = [project / "Runner.xcodeproj/project.pbxproj", *sorted((project / "VlessControls").iterdir())]
        original = {path: path.read_bytes() for path in files}
        subprocess.run(command, check=True, capture_output=True)
        assert all(path.read_bytes() == data for path, data in original.items()), f"{platform}: generator not idempotent"
        with (project / "Runner/Info.plist").open("rb") as file:
            info = plistlib.load(file)
        assert info["FlutterVlessControlsConfigured"]
        assert info["FlutterVlessControlGroupIdentifier"] == "group.dev.tfox.fixture"
        if platform == "ios":
            assert info["NSFaceIDUsageDescription"]
        with (project / "VlessControls/VlessControls.entitlements").open("rb") as file:
            assert plistlib.load(file)["com.apple.security.application-groups"] == ["group.dev.tfox.fixture"]
        print(f"PASS {platform}: target generation, host intent membership, signing metadata and idempotency")
