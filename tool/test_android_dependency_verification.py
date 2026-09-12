#!/usr/bin/env python3
"""Real Gradle positive/negative tests using official reviewed AAR and POM bytes."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
aar, pom = map(Path, sys.argv[1:])
metadata = root / "example/android/gradle/verification-metadata.xml"
ns = {"v": "https://schema.gradle.org/dependency-verification"}
tree = ET.parse(metadata)
component = tree.find("v:components/v:component", ns)
version = component.attrib["version"]
for path, suffix in [(aar, "aar"), (pom, "pom")]:
    wanted = component.find(f"v:artifact[@name='xray-android-{version}.{suffix}']/v:sha256", ns).attrib["value"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != wanted:
        raise SystemExit(f"Official {suffix.upper()} does not match the committed release checksum")
env = dict(os.environ)
java = Path("/Applications/Android Studio.app/Contents/jbr/Contents/Home")
if java.exists() and not env.get("JAVA_HOME"):
    env["JAVA_HOME"] = str(java)
with tempfile.TemporaryDirectory(prefix="flutter-vless-verification-") as work:
    base = Path(work)
    for case in ("official", "changed-aar", "changed-pom"):
        project = base / case
        repo = project / "repo/dev/tfox/fluttervless/xray-android" / version
        repo.mkdir(parents=True)
        (project / "gradle").mkdir()
        shutil.copyfile(metadata, project / "gradle/verification-metadata.xml")
        for source, suffix in [(aar, "aar"), (pom, "pom")]:
            data = source.read_bytes()
            if case == f"changed-{suffix}":
                data += b"\n<!-- tampered -->\n" if suffix == "pom" else b"tampered"
            (repo / f"xray-android-{version}.{suffix}").write_bytes(data)
        (project / "settings.gradle").write_text("rootProject.name = 'runtime-verification'\n")
        (project / "build.gradle").write_text("""
repositories { maven { url = uri('repo') } }
configurations { reviewedRuntime }
dependencies { reviewedRuntime 'dev.tfox.fluttervless:xray-android:%s' }
tasks.register('resolveReviewedRuntime') {
    doLast { assert configurations.reviewedRuntime.singleFile.name.endsWith('.aar') }
}
""" % version)
        result = subprocess.run([str(root / "example/android/gradlew"), "-p", str(project),
            "resolveReviewedRuntime", "--dependency-verification=strict", "--refresh-dependencies", "--console=plain"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        good = result.returncode == 0 if case == "official" else (
            result.returncode != 0 and "verification failed" in result.stdout.lower())
        if not good:
            print(result.stdout)
            raise SystemExit(f"Unexpected Gradle verification result: {case}")
        print(f"PASS Gradle dependency verification: {case}", flush=True)
