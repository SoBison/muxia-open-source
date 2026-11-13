#!/usr/bin/env python3
"""Clone a built Main App and replace only its isolated clean input framework.

Does not build, install, launch, or mutate DerivedData/production Artifacts.
Preserves the source App's actual signing identifier, entitlements and flags.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "RuntimeKit"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(path):
    return {str(item.relative_to(path)): "symlink:" + str(item.readlink()) if item.is_symlink() else sha(item)
            for item in sorted(path.rglob("*")) if item.is_symlink() or item.is_file()}


def fingerprint(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True)


def signature(path):
    text = run(["codesign", "-d", "--verbose=4", path]).stderr.decode()
    entitlements = plistlib.loads(run(["codesign", "-d", "--entitlements", "-", "--xml", path]).stdout)
    return {"identifier": re.search(r"^Identifier=(.*)$", text, re.M).group(1),
            "flags": re.search(r"flags=(0x[0-9a-fA-F]+)", text).group(1), "entitlements": entitlements,
            "teamIdentifier": re.search(r"^TeamIdentifier=(.*)$", text, re.M).group(1), "display": text}


def unsigned_macho_hash(path):
    # Thin arm64 debug launcher: codesign changes its resource-seal special slot
    # inside LC_CODE_SIGNATURE. Compare every byte preceding that blob, masking
    # only the signature command's offset/size, instead of calling a signature
    # change a Swift/native code change.
    data = bytearray(path.read_bytes())
    if struct.unpack_from("<I", data)[0] != 0xFEEDFACF:
        raise ValueError("Expected a thin arm64 Main executable")
    count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x1D:
            start, _ = struct.unpack_from("<II", data, offset + 8)
            data[offset + 8:offset + 16] = bytes(8)
            return hashlib.sha256(data[:start]).hexdigest()
        offset += size
    raise ValueError("The source Main executable has no embedded code signature")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / ".derivedData/Build/Products/Debug-iphonesimulator/RenReader.app")
    parser.add_argument("--output", type=Path, default=KIT / "Validation/AuxiliaryInputCandidate/MainApp")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if not source.is_dir() or not output.is_relative_to((KIT / "Validation").resolve()):
        raise ValueError("A built Main App and an isolated Validation output are required")
    output.mkdir(parents=True, exist_ok=True)
    target = output / "RenReader.app"
    if target.exists():
        raise FileExistsError("Preserve the existing candidate evidence; select a fresh --output")
    run(["codesign", "--verify", "--deep", "--strict", source])
    before, original_signature = tree(source), signature(source)
    executable = plistlib.loads((source / "Info.plist").read_bytes())["CFBundleExecutable"]
    code_before = unsigned_macho_hash(source / executable)
    clean = KIT / "Validation/AuxiliaryInputCandidate/Clean/RRPlatform.xcframework/ios-arm64-simulator/RRPlatform.framework"
    clean_result = json.loads((KIT / "Validation/AuxiliaryInputCandidate/result.json").read_text())
    clean_entry = next(item for item in clean_result["frameworks"] if item["variant"] == "Clean" and item["platform"] == "iphonesimulator")
    if sha(clean / "RRPlatform") != clean_entry["sha256"] or clean_entry["testProbeIncluded"]:
        raise ValueError("The clean candidate differs from the completed native validation")
    symbols = set(run(["nm", "-gU", clean / "RRPlatform"]).stdout.decode().split())
    if any("RunAuxiliaryInputProbe" in symbol or "RunInputProbe" in symbol for symbol in symbols):
        raise ValueError("A test entry point must never enter the Main candidate")
    if not set(clean_entry["exportsVerified"]) <= symbols:
        raise ValueError("The clean candidate is missing an auxiliary-input API")
    run(["cp", "-cR", source, target])
    framework = target / "Frameworks/RRPlatform.framework"
    shutil.rmtree(framework)
    run(["cp", "-cR", clean, framework])
    run(["codesign", "--force", "--sign", "-", framework])
    run(["codesign", "--force", "--sign", "-", "--preserve-metadata=identifier,entitlements,flags", target])
    verification = run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", target])
    (output / "strict-signature.log").write_bytes(verification.stdout + verification.stderr)
    after, final_signature = tree(target), signature(target)
    if any(original_signature[key] != final_signature[key] for key in ("identifier", "flags", "entitlements", "teamIdentifier")):
        raise ValueError("Candidate signing metadata differs from its source Main App")
    ignored = lambda name: name == executable or name.startswith("_CodeSignature/") or name.startswith("Frameworks/RRPlatform.framework/")
    preserved_before = {name: value for name, value in before.items() if not ignored(name)}
    preserved_after = {name: value for name, value in after.items() if not ignored(name)}
    if preserved_before != preserved_after or code_before != unsigned_macho_hash(target / executable):
        raise ValueError("The candidate modified code/resources outside the permitted Platform/signature scope")
    if before != tree(source):
        raise ValueError("Source DerivedData changed during preparation; do not attribute a moving build")
    groups = {}
    for child in sorted(source.iterdir()):
        if child.suffix == ".bundle":
            files = tree(child)
            groups[child.name] = {"files": len(files), "treeSHA256": fingerprint(files), "unchanged": tree(target / child.name) == files}
    native = {}
    for child in sorted((source / "Frameworks").iterdir()):
        if child.name == "RRPlatform.framework":
            continue
        files = tree(child)
        native[child.name] = {"files": len(files), "treeSHA256": fingerprint(files), "unchanged": tree(target / "Frameworks" / child.name) == files}
    bridge_sources = {str(path.relative_to(ROOT)): sha(path) for path in sorted((KIT / "Bridge").glob("*.[hm]"))}
    write = lambda name, value: (output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    write("payload-sha256.json", after)
    write("verification.json", {"passed": True, "timeUTC": datetime.now(timezone.utc).isoformat(), "sourceApp": str(source), "candidateApp": str(target),
        "operation": "APFS cp -cR; replace only clean RRPlatform; ad-hoc re-sign framework and preserve App identifier/entitlements/flags; strict deep verify",
        "sourceSigning": original_signature, "candidateSigning": final_signature,
        "mainExecutableSHA256Before": before[executable], "mainExecutableSHA256After": after[executable], "mainExecutableUnsignedSHA256": code_before,
        "debugDylibSHA256": after.get(executable + ".debug.dylib"), "bridgeSourceSHA256": bridge_sources,
        "otherNativeFrameworks": native, "runtimeBundles": groups, "unchangedOtherPayloadFileCount": len(preserved_after),
        "unchangedOtherPayloadSHA256": fingerprint(preserved_after), "candidatePayloadSHA256": fingerprint(after),
        "cleanCandidateIdentity": clean_entry, "stagedPlatformSHA256": sha(framework / "RRPlatform"),
        "stagedPlatformUUID": run(["xcrun", "dwarfdump", "--uuid", framework / "RRPlatform"]).stdout.decode().strip(),
        "hasTestProbe": False, "sourceAppUnmodified": True, "productionArtifactsModified": False, "installedOrLaunched": False,
        "preparationSourceSHA256": {str(Path(__file__).relative_to(ROOT)): sha(Path(__file__))}})
    print(json.dumps({"passed": True, "app": str(target), "verification": str(output / "verification.json"), "otherNativeFrameworksUnchanged": len(native), "runtimeBundlesUnchanged": len(groups), "installedOrLaunched": False}, indent=2))


if __name__ == "__main__":
    main()
