#!/usr/bin/env python3
"""Verify reviewed native inputs; does not generate or accept new checksums."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "android_runtime/xray_android"
expected = json.loads((root / "runtime-inputs.sha256.json").read_text())
for name, digest in expected.items():
    path = root / "src/main" / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"Untrusted Android runtime input: {name}")
print(f"Verified {len(expected)} pinned native runtime inputs")
