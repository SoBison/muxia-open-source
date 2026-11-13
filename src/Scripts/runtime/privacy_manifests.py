#!/usr/bin/env python3
"""Place required-reason declarations in each actual framework bundle."""
from pathlib import Path
import json
import plistlib
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "RuntimeKit/Artifacts"
REASONS = {
    "FileTimestamp": "C617.1",  # Module/cache/save metadata inside this app.
    "SystemBootTime": "35F9.1",  # Frame/event intervals and application timers.
    "DiskSpace": "E174.1",  # Fail saving before insufficient-space writes.
}


def write_framework_manifest(framework, name):
    manifest = framework / "PrivacyInfo.xcprivacy"
    if name == "MetalANGLE" and manifest.exists():
        return
    if name.startswith("RRRuntime"):
        categories = ("FileTimestamp", "SystemBootTime", "DiskSpace")
    elif name == "RRPlatform":
        categories = ("SystemBootTime",)
    elif name == "RRGalleryAudio":
        categories = ("FileTimestamp", "SystemBootTime")
    elif name == "MetalANGLE":
        categories = ("FileTimestamp", "SystemBootTime")
    elif name in ("RRLive2DCore", "RRLive2DLegacyCore"):
        imports = subprocess.check_output(["nm", "-u", framework / name], text=True).split()
        categories = tuple(category for category, symbols in {
            "FileTimestamp": {"_stat", "_fstat", "_fstatat", "_lstat"},
            "SystemBootTime": {"_mach_absolute_time"},
            "DiskSpace": {"_statvfs", "_fstatvfs", "_statfs", "_fstatfs"},
        }.items() if set(imports) & symbols)
    else:
        raise ValueError("Unreviewed native bundle: " + name)
    contents = {"NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategory" + category, "NSPrivacyAccessedAPITypeReasons": [REASONS[category]]} for category in categories]}
    manifest.write_bytes(plistlib.dumps(contents))


def patch_existing():
    audit = []
    for framework in sorted(ARTIFACTS.glob("*.xcframework/*/*.framework")):
        name = framework.stem
        write_framework_manifest(framework, name)
        binary = framework / name
        imports = subprocess.check_output(["nm", "-u", binary], text=True)
        selected = sorted({line.strip() for line in imports.splitlines() if line.strip() in {"_stat", "_fstat", "_fstatat", "_lstat", "_statvfs", "_fstatvfs", "_statfs", "_fstatfs", "_mach_absolute_time", "_OBJC_CLASS_$_NSUserDefaults"}})
        audit.append({"framework": str(framework.relative_to(ROOT)), "observedImports": selected, "manifest": plistlib.loads((framework / "PrivacyInfo.xcprivacy").read_bytes())})
    notice = ROOT / "RuntimeKit/Notices/required-reason-audit.json"
    notice.write_text(json.dumps({"reference": "https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api", "reasonReference": "https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype", "reviewedBundles": audit}, indent=2) + "\n")
    print("Privacy manifests present in", len(audit), "framework slices")


if __name__ == "__main__":
    patch_existing()
