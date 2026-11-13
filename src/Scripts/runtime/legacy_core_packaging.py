#!/usr/bin/env python3
"""Validate the optional, staged device-only Core; never qualify or enable it."""
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess

ROOT = Path(__file__).resolve().parents[2]
NAME = "RRLive2DLegacyCore"
DOCUMENTS = ("LICENSE.md", "RedistributableFiles.txt", "Live2DFramework-LICENSE.md", "Live2DFramework.patch")


def regular(path, limit):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Missing, linked or oversized legacy Core file: " + str(path))
    return path.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def optional_framework(root=ROOT):
    framework = root / "RuntimeKit/Optional" / (NAME + ".framework")
    if not framework.exists() and not framework.is_symlink():
        return None
    if framework.is_symlink() or not framework.is_dir() or framework.parent.is_symlink():
        raise ValueError("Legacy Core staging directory is linked or invalid")
    info = plistlib.loads(regular(framework / "Info.plist", 65536))
    record = json.loads(regular(framework / "live2d-core.json", 65536))
    binary = regular(framework / NAME, 100 * 1024 * 1024)
    if (info.get("CFBundleExecutable") != NAME or info.get("MinimumOSVersion") != "17.0"
            or info.get("CFBundleSupportedPlatforms") != ["iPhoneOS"]
            or record.get("sdkRelease") != "5-r.1" or record.get("minimumOS") != "17.0"
            or record.get("platform") != "iphoneos" or record.get("qualified") is not False
            or record.get("mocMaximum") != 5 or record.get("featureMask") != 0
            or record.get("archiveSHA256") != "073f623fc3fb06c192e68bb5287fdb9dab1952164c2a956dec6d4b45fd342ffb"
            or record.get("binarySHA256") != sha(binary)):
        raise ValueError("Legacy Core staging identity is inconsistent")
    names = ("RRLive2DLegacyCore.c", "RRLive2DEffects.mm", "RRLive2DPhysicsState.cpp")
    sources = {"RuntimeKit/Native/" + name: sha(regular(root / "RuntimeKit/Native" / name, 2 * 1024 * 1024)) for name in names}
    if record.get("sourceSHA256") != sources:
        raise ValueError("Legacy Core source has changed since staging")
    for name in DOCUMENTS:
        regular(framework / name, 512 * 1024).decode("utf-8")
    regular(framework / "PrivacyInfo.xcprivacy", 65536)
    arch = subprocess.check_output(["xcrun", "lipo", "-archs", str(framework / NAME)], text=True).split()
    if arch != ["arm64"]:
        raise ValueError("Legacy Core must contain only the arm64 device architecture")
    build = subprocess.check_output(["xcrun", "vtool", "-show-build", str(framework / NAME)], text=True)
    if "platform IOS\n" not in build or "minos 17.0\n" not in build:
        raise ValueError("Legacy Core is not an iOS 17.0 device binary")
    return framework


if __name__ == "__main__":
    if optional_framework() is None:
        raise SystemExit("No legacy Core staged")
    print("Legacy Core staging identity checked; qualification remains disabled")
