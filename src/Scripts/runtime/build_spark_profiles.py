#!/usr/bin/env python3
"""Build available Spark patch versions into an isolated, unadvertised stage."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile
import build_runtime as builder

ROOT = builder.ROOT
NIGHTLY = ("7.8.8", "8.5.4")
AVAILABLE = ("7.8.4", "8.3.4", "8.5.0", "8.5.2", *NIGHTLY)
DESTINATION = ROOT / "RuntimeKit/Validation/SparkParity20261104/NewRuntimes/Artifacts"
NIGHTLY_DESTINATION = ROOT / "RuntimeKit/Validation/NightlyProfiles20261104/Artifacts"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def official_loader(sdk, version):
    directory = builder.CACHE / "official" / version
    record = json.loads((directory / "paths.json").read_text())
    archive = directory / ("renpy-" + record.get("buildID", version) + "-sdk.zip")
    if builder.hashlib.sha256(archive.read_bytes()).hexdigest() != record["sha256"][archive.name]:
        raise ValueError("Official SDK archive changed")
    with zipfile.ZipFile(archive) as source:
        content = source.read(sdk.name + "/renpy/loader.py")
    if (sdk / "renpy/loader.py").read_bytes() != content:
        raise ValueError("Loader differs from checksum-verified official SDK")
    return content


def validate_loader(sdk, version, pyver):
    record = json.loads((builder.CACHE / "official" / version / "paths.json").read_text())
    if version not in AVAILABLE or sdk.name != "renpy-" + record.get("buildID", version) + "-sdk" or pyver not in ("2.7", "3.9", "3.12"):
        raise ValueError("Unexpected new runtime identity")
    official_loader(sdk, version)
    bundle = builder.ARTIFACTS / ("RenPy" + version.replace(".", "") + ".bundle")
    if bundle.exists():
        raise ValueError("Existing staged resources require review before replacement")


def patch_loader(base, sdk, version):
    source = official_loader(sdk, version)
    old = b"                rv = io.BufferedReader(rv)\n\n        # Compatibility path."
    new = b"                rv = io.BufferedReader(rv)\n                return rv\n\n        # Compatibility path."
    if source.count(old) == 1:
        output = source.replace(old, new, 1)
    elif source.count(new) == 1:
        output = source
    else:
        raise ValueError("Review the exact upstream archive-prefix boundary for " + version)
    target = base / "renpy/loader.py"
    if target.read_bytes() != source:
        raise ValueError("Resource loader changed before patching")
    removed = []
    for path in [target.with_suffix(".pyc"), target.with_suffix(".pyo"), *target.parent.glob("__pycache__/loader.*.py[co]")]:
        if path.is_symlink():
            raise ValueError("Linked loader cache")
        if path.exists():
            removed.append({"path": path.relative_to(base).as_posix(), "sha256": sha(path.read_bytes())})
            path.unlink()
    target.write_bytes(output)
    return {"id": "spark-patch-version-prefix-return", "runtimeID": version, "sourceRelativePath": "renpy/loader.py",
        "originalSourceSHA256": sha(source), "outputSourceSHA256": sha(output), "removedBytecode": removed,
        "sourceOrigin": "pinned official nightly SDK ZIP" if version in NIGHTLY else "checksum-verified official SDK ZIP", "bytecodePolicy": "sourceOnly"}


def nightly_host():
    # Preserve the already qualified basic host instead of advertising the
    # eleven original profiles' advanced capabilities on two untested ABIs.
    original = ROOT / "RuntimeKit/Artifacts/RenPy852.bundle/base/rr_host.py"
    source = original.read_bytes()
    if sha(source) != "02bc6b9240e50a1cab04e6c0f41e7c60bf487065073ae7b916e4ad2f8076aaa2":
        raise ValueError("The qualified basic-profile host changed")
    before = b'"titlePatches": False, "languageSelection": language_selection,'
    if source.count(before) != 1:
        raise ValueError("Review the basic-profile capability boundary")
    source = source.replace(before, b'"titlePatches": False, "advancedTranslation": False, "languageSelection": language_selection,', 1)
    target = ROOT / "RuntimeKit/Candidates/NightlyProfiles20261104/rr_host.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() != source:
        raise ValueError("A different nightly host is already retained")
    target.write_bytes(source)
    return target


def constrain_unqualified_features(bundle):
    """Keep staged profiles on the SDK-free resource path."""
    host = bundle / "base/rr_host.py"
    builder.validate_no_sdk_entry(host)
    output = host.read_bytes()
    source_host = DESTINATION.parent / "QualifiedHost/rr_host.py"
    source_host.parent.mkdir(parents=True, exist_ok=True)
    if source_host.exists() and source_host.read_bytes() != output:
        raise ValueError("Existing new-profile host snapshot differs; preserve and review it before replacement")
    source_host.write_bytes(output)
    host.write_bytes(output)
    for path in [host.with_suffix(".pyc"), host.with_suffix(".pyo"), *host.parent.glob("__pycache__/rr_host.*.py[co]")]:
        if path.is_symlink():
            raise ValueError("Linked host bytecode")
        path.unlink(missing_ok=True)
    profile_file = bundle / "runtime-profile.json"
    profile = json.loads(profile_file.read_text())
    profile["live2D"] = {"available": False, "reason": "notIncluded"}
    profile_file.write_text(json.dumps(profile, indent=2) + "\n")
    provenance_file = bundle / "provenance.json"
    provenance = json.loads(provenance_file.read_text())
    if provenance.get("newProfileSourceHost") is None:
        provenance["newProfileSourceHost"] = provenance["resourceHost"]
    provenance["resourceHost"] = {"path": str(source_host.relative_to(ROOT)), "sha256": sha(output)}
    provenance["newProfileCapabilityPolicy"] = {"live2D": False, "customEngineOverlay": False,
        "hostGeneratorPath": "Scripts/runtime/build_spark_profiles.py", "hostGeneratorSHA256": sha(Path(__file__).read_bytes())}
    provenance_file.write_text(json.dumps(provenance, indent=2) + "\n")
    notices = DESTINATION.parent / "Notices"
    (notices / ("renpy-" + profile["runtimeID"] + "-provenance.json")).write_bytes(provenance_file.read_bytes())


def main():
    global DESTINATION
    parser = argparse.ArgumentParser(); parser.add_argument("--version", choices=AVAILABLE, required=True)
    parser.add_argument("--constrain-existing-stage", action="store_true")
    options = parser.parse_args(); version = options.version
    if version in NIGHTLY:
        DESTINATION = NIGHTLY_DESTINATION
    if options.constrain_existing_stage:
        constrain_unqualified_features(DESTINATION / ("RenPy" + version.replace(".", "") + ".bundle"))
        return
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for name in ("RRPlatform.xcframework", "MetalANGLE.xcframework"):
        target = DESTINATION / name
        if not target.exists():
            subprocess.run(["cp", "-cR", str(builder.ARTIFACTS / name), str(target)], check=True)
    builder.ARTIFACTS = DESTINATION
    sdk = builder.fetch(version, native=True); pyver = builder.python_version(sdk)
    host = nightly_host() if version in NIGHTLY else builder.select_resource_host("8.5.3")
    notices = DESTINATION.parent / "Notices"; notices.mkdir(exist_ok=True)
    bundle = builder.resources(sdk, version, pyver, notices, loader_validator=validate_loader,
        archive_patcher=patch_loader, host_source=host)
    builder.build_core(sdk, version, pyver, destination=DESTINATION)
    constrain_unqualified_features(bundle)
    provenance = json.loads((bundle / "provenance.json").read_text())
    provenance["nativeArtifacts"] = builder.native_packaging_records(version)
    provenance["newRuntimeStatus"] = "unadvertised; simulator execution and overlay qualification pending"
    if version in NIGHTLY:
        record = json.loads((builder.CACHE / "official" / version / "paths.json").read_text())
        build_id = record["buildID"]
        if not build_id.startswith(version + ".") or not build_id.endswith("+nightly"):
            raise ValueError("Nightly build identity does not match its runtime")
        provenance.update(upstreamBuildID=build_id, releaseChannel="nightly", sourceCommits=record["sourceCommits"])
        provenance["officialArchives"] = [{"url": record["archiveURLs"][name], "sha256": digest}
                                           for name, digest in record["sha256"].items()]
        provenance["nightlyInputManifestSHA256"] = sha((ROOT / "RuntimeKit/Inputs/official-nightlies.json").read_bytes())
        provenance["upstreamLicense"] = {key: value for key, value in record["canonicalLicense"].items() if key != "path"}
        profile_path = bundle / "runtime-profile.json"
        profile = json.loads(profile_path.read_text())
        profile.update(upstreamBuildID=build_id, releaseChannel="nightly")
        profile_path.write_text(json.dumps(profile, indent=2) + "\n")
    (bundle / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (notices / ("renpy-" + version + "-provenance.json")).write_bytes((bundle / "provenance.json").read_bytes())
    print("Built isolated official runtime " + version + "; production catalog unchanged.")


if __name__ == "__main__":
    main()
