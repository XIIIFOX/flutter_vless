#!/usr/bin/env python3
"""Explicit development build with locally built AAR verification, then restore official pins."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

root = Path(__file__).resolve().parents[1]
version = "26.9.9-protect1"
repo = root / "android_runtime/xray_android/build/repo"
artifacts = repo / f"dev/tfox/fluttervless/xray-android/{version}"
aar = artifacts / f"xray-android-{version}.aar"
subprocess.run([sys.executable, str(root / "tool/verify_android_runtime_inputs.py")], check=True)
expected = json.loads((root / "android_runtime/xray_android/runtime-inputs.sha256.json").read_text())
with zipfile.ZipFile(aar) as archive:
    for name, digest in expected.items():
        if hashlib.sha256(archive.read(name.replace("jniLibs/", "jni/", 1))).hexdigest() != digest:
            raise SystemExit(f"Local AAR does not contain the reviewed input: {name}")

metadata = root / "example/android/gradle/verification-metadata.xml"
namespace = "https://schema.gradle.org/dependency-verification"
ET.register_namespace("", namespace)
lock_path = root / "build/android-local-verification.lock"
lock_path.parent.mkdir(exist_ok=True)
with lock_path.open("w") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    original = metadata.read_bytes()
    tree = ET.fromstring(original)
    component = tree.find(f"{{{namespace}}}components/{{{namespace}}}component")
    component.clear()
    component.attrib.update(group="dev.tfox.fluttervless", name="xray-android", version=version)
    for suffix in ("aar", "pom", "module"):
        artifact = artifacts / f"xray-android-{version}.{suffix}"
        if not artifact.exists():
            if suffix == "module":
                continue
            raise SystemExit(f"Missing local artifact: {artifact.name}")
        node = ET.SubElement(component, f"{{{namespace}}}artifact", name=artifact.name)
        ET.SubElement(node, f"{{{namespace}}}sha256", value=hashlib.sha256(artifact.read_bytes()).hexdigest(),
                      origin="Explicit development build from independently verified repository inputs; not an official release pin")
    try:
        metadata.write_bytes(ET.tostring(tree, encoding="UTF-8", xml_declaration=True))
        env = dict(os.environ)
        java = Path("/Applications/Android Studio.app/Contents/jbr/Contents/Home")
        if java.exists() and not env.get("JAVA_HOME"):
            env["JAVA_HOME"] = str(java)
        command = ["./gradlew", *(sys.argv[1:] or [":flutter_vless_android:testDebugUnitTest"]),
                   "--dependency-verification=strict", f"-PflutterVlessAndroidRuntimeRepo={repo}"]
        print("DEVELOPMENT runtime verification: local AAR; official release verification is separate", flush=True)
        result = subprocess.run(command, cwd=root / "example/android", env=env)
    finally:
        metadata.write_bytes(original)
    raise SystemExit(result.returncode)
