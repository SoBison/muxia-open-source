#!/usr/bin/env python3
"""Fail closed when an advertised 853 overlay no longer has its tested inputs.

This is an isolated candidate. A qualification is valid only with a separately
reviewed UI result; hashing alone does not create one.
"""
import argparse
import datetime
import hashlib
import json
import os
import pickletools
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

VERSIONS = ("7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.3.7", "8.4.1", "8.5.3")
FRAMEWORKS = ("RRRuntime853", "RRPlatform", "RRLive2DCore", "MetalANGLE")
LAUNCH_MODES = {"enhanced", "minimal", "nativeCompatibility"}
HOST_STATUS_KEY = "RenReaderQualificationStatus"
HOST_STATUS = "COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED"
SOURCE_SUFFIXES = {".swift", ".h", ".m", ".mm", ".c", ".cpp", ".modulemap"}
# Only the already published v1 contract is grandfathered. New inputs require v2.
LEGACY_CONTRACT_SHA256 = "1e22c8f71fee015bc15e8c1617b6ca35652e90400d018e6f144c435851a51e51"
FROZEN_V2_CONTRACT_SHA256 = "fa07080fdc724a8ca4f0cd7ba9d5339f30cb5a12e36e02152774cd45565cc023"
# V3 represents one independently reviewed build; a new build needs a new review.
V3_SIMULATOR_BINDING_SHA256 = "08da35c2b6e23d7be5e1c1a86f861df36d87bb2f32f82838d4ee1a29a8937014"
V3_SEMANTIC_BASELINE_SHA256 = "cf91f21a3e477dff28e7ce4327ae43c9c9624d2eb79ee68317026544ccccda00"
V3_BASELINE_RESOURCES_SHA256 = "631f11e7706bc952ff14ea67c5c68b3344157d14a81612ed409775cea7a00dd6"
V3_DEVICE_EVIDENCE_SHA256 = {
    "preSignAudit": "b0a4eb9806e0497fe6783e93756e25394f12d182acca25e1e24e020cc6fa7888",
    "signedAudit": "c924e83daf5f4bee283f957105268972194ed4d0e28f47fdb543dd669ef4701d",
    "staticAudit": "39e8892f36cf74e03c3b9d0b8a7f2c250460182771608cc3ef18b7d58d270c96",
    "failedInventory": "a01d4d0fbf4468d6f2353f633b4212d13b96499f0110eebd448ce08352af3389",
    "signedInventory": "6ff9a8f926bc3fb224d6725dc66fb7b62ce63dc8e81048a8eba797198e044d39",
    "deviceXcent": "7ac2d21517a48272211589de6ee45e294e20115fc6d1fb21c62695c9338cc260",
    "sourceEvidence": "cb5552379fcde287cc0621fd7b98db781c441e3baa8a98c8a7e9c93458afff73",
    "deviceSignature": "f0fae12da722ac24817c95ee8f465c6a9e0c9b5494bb7c04428c15e5fa48332a",
}


def legacy_contract_qualified(contract):
    canonical = json.dumps(contract, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest() == LEGACY_CONTRACT_SHA256


def frozen_v2_contract_qualified(contract):
    canonical = json.dumps(contract, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest() == FROZEN_V2_CONTRACT_SHA256


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or linked capability input: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root, include=None, substitutions=None):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Missing or linked capability tree: " + str(root))
    entries = [(".", "directory", stat.S_IMODE(root.stat().st_mode))]
    files = directories = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Linked capability tree entry: " + str(path))
        if path.is_file() and (include is None or include(path)):
            relative = path.relative_to(root).as_posix()
            actual = digest(path)
            entries.append((relative, "file", stat.S_IMODE(path.stat().st_mode), (substitutions or {}).get(relative, actual)))
            files += 1
        elif path.is_dir():
            entries.append((path.relative_to(root).as_posix(), "directory", stat.S_IMODE(path.stat().st_mode)))
            directories += 1
        elif not path.is_file() and not path.is_dir():
            raise ValueError("Special capability tree entry: " + str(path))
    payload = json.dumps(sorted(entries), ensure_ascii=False, separators=(",", ":")).encode()
    return {"fileCount": files, "directoryCount": directories, "sha256": hashlib.sha256(payload).hexdigest()}


def profile_content(profile):
    # The feature flag itself is the only intentional difference from QA.
    value = dict(profile)
    value.pop("engineOverlaySchemaVersion", None)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def current_inputs(root):
    artifacts = root / "RuntimeKit/Artifacts"
    bundle = artifacts / "RenPy853.bundle"
    profile_path = bundle / "runtime-profile.json"
    digest(profile_path)
    profile = json.loads(profile_path.read_bytes())
    if profile.get("runtimeID") != "8.5.3" or profile.get("pythonVersion") != "3.12":
        raise ValueError("Unqualified 853 runtime or Python ABI")
    return {
        "profileContentSHA256": profile_content(profile),
        "provenanceSHA256": digest(bundle / "provenance.json"),
        "base": tree_digest(bundle / "base"),
        "appSources": tree_digest(root / "App", lambda p: p.suffix in SOURCE_SUFFIXES or p.name == "module.modulemap"),
        "bridgeSources": tree_digest(root / "RuntimeKit/Bridge"),
        "pythonSources": tree_digest(root / "RuntimeKit/Python", lambda p: p.suffix == ".py"),
        "nativeSources": {name: digest(root / "RuntimeKit/Native" / name) for name in ("RRRuntime.m", "RRPlatform.m")},
        "frameworks": {name: tree_digest(artifacts / (name + ".xcframework")) for name in FRAMEWORKS},
        "projectSHA256": digest(root / "RenReader.xcodeproj/project.pbxproj"),
    }


def verify_inputs(root, contract, *, components_only=False):
    if contract.get("schemaVersion") != 1 or contract.get("runtimeID") != "8.5.3":
        raise ValueError("Unrecognized capability contract")
    actual = current_inputs(root)
    if set(contract.get("inputs", {})) != set(actual):
        raise ValueError("Incomplete capability input contract")
    for key, expected in contract["inputs"].items():
        if components_only and key in ("appSources", "projectSHA256"):
            continue
        if actual.get(key) != expected:
            raise ValueError("853 engine overlay requires requalification: " + key)


def evidence_path(root, name):
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("Invalid capability qualification path")
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Linked capability qualification path")
    return path


def checked_reference(root, ref):
    if not isinstance(ref, dict) or digest(evidence_path(root, ref["path"])) != ref.get("sha256"):
        raise ValueError("Qualification binding evidence changed")
    return evidence_path(root, ref["path"])


CONFIG_PLISTS = ("App/Info.plist", "Config/App.entitlements", "Config/Simulator.entitlements",
                 ".runtime-cache/Signing/App.entitlements", ".runtime-cache/Signing/Simulator.entitlements",
                 "Widgets/Info.plist", "Widgets/Widget.entitlements")


def plist_value(path):
    digest(path)
    value = plistlib.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Capability configuration is not a plist dictionary: " + str(path))
    return value


def plist_identity(path):
    return hashlib.sha256(plistlib.dumps(plist_value(path), fmt=plistlib.FMT_BINARY, sort_keys=True)).hexdigest()


def same_plist_value(a, b):
    # Python considers True == 1 and False == 0, but plist types matter.
    return plistlib.dumps(a, fmt=plistlib.FMT_BINARY, sort_keys=True) == plistlib.dumps(b, fmt=plistlib.FMT_BINARY, sort_keys=True)


def v2_configuration(root, binding, candidate_inventory, *, historical_only=False):
    config = binding["buildConfiguration"]
    sources = config["sourcePlists"]
    if set(sources) != set(CONFIG_PLISTS):
        raise ValueError("Capability configuration source inventory mismatch")
    for name in CONFIG_PLISTS:
        if not historical_only and plist_identity(evidence_path(root, name)) != sources[name]:
            raise ValueError("Capability configuration source changed: " + name)
    platforms = {"iphonesimulator", "iphoneos"}
    if set(config["builtInfo"]) != platforms or set(config["effectiveEntitlements"]) != platforms or set(config["buildSettings"]) != platforms:
        raise ValueError("Capability configuration platform inventory mismatch")
    for platform in ("iphonesimulator", "iphoneos"):
        info = plist_value(checked_reference(root, config["builtInfo"][platform]))
        expected_settings = {"INFOPLIST_FILE": "App/Info.plist", "GENERATE_INFOPLIST_FILE": "NO",
            "IPHONEOS_DEPLOYMENT_TARGET": info.get("MinimumOSVersion"),
            "TARGETED_DEVICE_FAMILY": ",".join(str(x) for x in info.get("UIDeviceFamily", [])),
            "PRODUCT_BUNDLE_IDENTIFIER": info.get("CFBundleIdentifier"),
            "CODE_SIGN_ENTITLEMENTS": ".runtime-cache/Signing/Simulator.entitlements" if platform == "iphonesimulator" else ".runtime-cache/Signing/App.entitlements"}
        if config["buildSettings"][platform] != expected_settings:
            raise ValueError("Capability build setting inventory mismatch: " + platform)
        entries = config["effectiveEntitlements"][platform]
        expected = {"signed", "simulated"} if platform == "iphonesimulator" else {"signed"}
        if set(entries) != expected:
            raise ValueError("Capability entitlement inventory mismatch: " + platform)
        for ref in entries.values():
            plist_value(checked_reference(root, ref))
    if config["builtInfo"]["iphonesimulator"]["sha256"] != candidate_inventory["Info.plist"]["sha256"]:
        raise ValueError("Capability simulator Info does not match tested package")
    return config


def qualified_v2_configuration(root, contract):
    q = contract.get("qualification", {})
    if q.get("bindingVersion", 1) not in (2, 3):
        return None
    receipt = json.loads(checked_reference(root, {"path": q["reportPath"], "sha256": q["reportSHA256"]}).read_bytes())
    binding = json.loads(checked_reference(root, receipt["binding"]).read_bytes())
    return binding["buildConfiguration"]


def framework_slice(root, name, platform):
    package = root / "RuntimeKit/Artifacts" / (name + ".xcframework")
    info = plist_value(package / "Info.plist")
    expected_variant = "simulator" if platform == "iphonesimulator" else None
    matches = [item for item in info.get("AvailableLibraries", []) if item.get("SupportedPlatform") == "ios"
               and item.get("SupportedPlatformVariant") == expected_variant
               and "arm64" in item.get("SupportedArchitectures", [])]
    if len(matches) != 1 or matches[0].get("LibraryPath") != name + ".framework":
        raise ValueError("Capability framework slice mismatch: " + name)
    return evidence_path(package, matches[0]["LibraryIdentifier"] + "/" + matches[0]["LibraryPath"])


def verify_v2_built_configuration(root, contract, app, platform):
    config = qualified_v2_configuration(root, contract)
    if config is None:
        return
    expected_info = plist_value(checked_reference(root, config["builtInfo"][platform]))
    if not same_plist_value(plist_value(app / "Info.plist"), expected_info):
        raise ValueError("Built App Info differs from qualification")
    if digest(app / "RenPy853.bundle/Info.plist") != digest(root / "RuntimeKit/Artifacts/RenPy853.bundle/Info.plist"):
        raise ValueError("Built runtime bundle Info differs from qualification")
    for name in FRAMEWORKS:
        source = framework_slice(root, name, platform)
        actual = app / "Frameworks" / (name + ".framework")
        names = ("Info.plist", "live2d-core.json") if name == "RRLive2DCore" else ("Info.plist",)
        for filename in names:
            if digest(source / filename) != digest(actual / filename):
                raise ValueError("Built framework metadata differs from qualification: " + name + "/" + filename)
    # During Xcode script phases, check resolved settings and generated xcent.
    # This precedes final CodeSign; signed entitlements need a separate post-build audit.
    if "XCODE_VERSION_ACTUAL" in os.environ:
        expected_settings = config["buildSettings"][platform]
        for key, expected in expected_settings.items():
            if os.environ.get(key) != expected:
                raise ValueError("Effective build setting differs from qualification: " + key)
        temporary = os.environ.get("TARGET_TEMP_DIR")
        if not temporary or os.environ.get("FULL_PRODUCT_NAME") != "RenReader.app":
            raise ValueError("Missing expected Xcode entitlement output path")
        expected = config["effectiveEntitlements"][platform]
        outputs = {"signed": Path(temporary) / "RenReader.app.xcent"}
        if platform == "iphonesimulator":
            outputs["simulated"] = Path(temporary) / "RenReader.app-Simulated.xcent"
        for kind, output in outputs.items():
            if not same_plist_value(plist_value(output), plist_value(checked_reference(root, expected[kind]))):
                raise ValueError("Effective entitlement differs from qualification: " + kind)


def verify_v2_signed_configuration(root, contract, platform, permissions):
    """Called by the post-sign package audit; Xcode's script phase runs before CodeSign."""
    config = qualified_v2_configuration(root, contract)
    if config is None:
        return
    kind = "simulated" if platform == "iphonesimulator" else "signed"
    if not same_plist_value(permissions, plist_value(checked_reference(root, config["effectiveEntitlements"][platform][kind]))):
        raise ValueError("Signed App entitlement differs from qualification: " + platform)


def check_save_73(path):
    # Static opcode inspection only; never load or execute the pickle.
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Oversized save")
    with zipfile.ZipFile(path) as archive:
        if sum(info.filename == "log" for info in archive.infolist()) != 1:
            raise ValueError("Ambiguous save log")
        info = archive.getinfo("log")
        if info.file_size > 16 * 1024 * 1024:
            raise ValueError("Oversized save log")
        operations = list(pickletools.genops(archive.read(info)))
    values = []
    for index, (_, argument, _) in enumerate(operations):
        if argument == "store.engine_main_value":
            for operation, value, _ in operations[index + 1:index + 6]:
                if operation.name in ("BINPUT", "LONG_BINPUT", "MEMOIZE"):
                    continue
                if operation.name in ("BININT", "BININT1", "BININT2", "INT", "LONG", "LONG1", "LONG4"):
                    values.append(value)
                break
    if not values or any(type(value) is not int or value != 73 for value in values):
        raise ValueError("Save has no exact 73 opcode evidence")


def verify_v2_binding(root, contract, report, *, historical_only=False):
    binding = json.loads(checked_reference(root, report["binding"]).read_bytes())
    if binding.get("schemaVersion") != 2 or binding.get("inputs") != contract["inputs"]:
        raise ValueError("Qualification source and project binding mismatch")
    acceptance = json.loads(checked_reference(root, binding["acceptance"]).read_bytes())
    review = json.loads(checked_reference(root, binding["review"]).read_bytes())
    package = json.loads(checked_reference(root, binding["package"]).read_bytes())
    if (acceptance.get("status") != "SCOPED_EXACT_NEXTQA_RECOVERY_AND_853_SIX_SESSION_UI_PASSED_WITH_LIMITS"
            or acceptance.get("qualifiedModeSessionCount") != 6 or review.get("status") != "PASS"
            or review.get("sessionCount") != 6 or review.get("immutableSaveCount") != 18
            or review.get("failedCheckCount") != 0 or not review.get("checks")
            or not all(value is True for value in review["checks"].values())
            or acceptance["packageIdentity"]["sha256"] != binding["package"]["sha256"]
            or acceptance["independentSixSessionReview"]["sha256"] != binding["review"]["sha256"]
            or acceptance["candidate"] != package["candidate"] or acceptance["installedApp"] != package["installed"]
            or package.get("status") != "PASS_BYTES_IMAGES_SIGNATURES_WITH_KNOWN_INSTALLER_MODES"
            or package.get("allPathContentsEqualCandidate") is not True
            or package.get("candidateUnchangedSinceInitialSeal") is not True
            or package.get("installedFullTreeUnchangedSincePreTest") is not True
            or len(package.get("strictSignatures", [])) != 2
            or {x.get("label") for x in package["strictSignatures"]} != {"candidate", "installed"}
            or any(x.get("exitCode") != 0 for x in package["strictSignatures"])):
        raise ValueError("Qualification acceptance/package binding mismatch")
    names = {*FRAMEWORKS, "RenReader", "RenReader.debug.dylib"}
    images = contract["builtImages"]["iphonesimulator"]
    if set(images) != names or set(package["images"]) != names:
        raise ValueError("Qualification simulator image set mismatch")
    for name in names:
        image = package["images"][name]
        if image["candidate"] != images[name] or image["installed"] != images[name]:
            raise ValueError("Qualification simulator image identity mismatch: " + name)
    inventories = []
    for name in ("candidateManifest", "installedManifest"):
        ref = binding[name]
        if ref["sha256"] != package[name]["sha256"]:
            raise ValueError("Qualification package inventory binding mismatch")
        inventories.append(json.loads(checked_reference(root, ref).read_bytes()))
    if (set(inventories[0]) != set(inventories[1]) or
            any({k: v for k, v in inventories[0][key].items() if k != "mode"} !=
                {k: v for k, v in inventories[1][key].items() if k != "mode"} for key in inventories[0])):
        raise ValueError("Qualification package inventory content mismatch")
    if inventories[0]["RenReader.debug.dylib"]["sha256"] != binding["debugDylibSHA256"]:
        raise ValueError("Qualification debug dylib bytes mismatch")
    v2_configuration(root, binding, inventories[0], historical_only=historical_only)
    target = acceptance["target"]
    if target != review["exactTarget"] or target["engineOverlay"]["runtimeProvenanceSHA256"] != contract["inputs"]["provenanceSHA256"]:
        raise ValueError("Qualification target mismatch")
    phases = {mode + "-" + temperature for mode in ("enhanced", "minimal", "native") for temperature in ("warm", "cold")}
    sessions = binding["sessions"]
    reviewed = {entry["phase"]: entry for entry in review["sessions"]}
    if set(sessions) != phases or set(acceptance["modes"]) != phases or set(reviewed) != phases or len(review["sessions"]) != 6:
        raise ValueError("Qualification requires six distinct phases")
    for prefix, mode in (("enhanced", "enhanced"), ("minimal", "minimal"), ("native", "nativeCompatibility")):
        mode_path = evidence_path(root, report["launchModes"][mode]["resultPath"])
        detail = json.loads(mode_path.read_bytes())["evidence"]
        warm, cold = sessions[prefix + "-warm"], sessions[prefix + "-cold"]
        expected = {"result": binding["acceptance"], "finalData": binding["review"], "active": warm["active"],
                    "completed": warm["completion"], "screenshots": [warm["screen"], cold["screen"]]}
        if detail != expected:
            raise ValueError("Qualification mode detail binding mismatch: " + mode)
    session_ids, save_paths = set(), set()
    for phase in sorted(phases):
        local, accepted, independent = sessions[phase], acceptance["modes"][phase], reviewed[phase]
        mode = "nativeCompatibility" if phase.startswith("native-") else phase.split("-")[0]
        sid, pid = accepted["sessionID"], independent["pid"]
        if (sid in session_ids or type(pid) is not int or pid <= 0 or accepted["pid"] != [pid]
                or accepted["mode"] != mode or independent["launchMode"] != mode
                or independent["sessionID"] != sid):
            raise ValueError("Qualification session/mode/PID mismatch: " + phase)
        session_ids.add(sid)
        for name, review_name in (("active", "active"), ("completion", "completion"), ("screen", "screenshot")):
            checked_reference(root, local[name])
            if local[name]["sha256"] != accepted[name]["sha256"] or local[name]["sha256"] != independent[review_name]["sha256"]:
                raise ValueError("Qualification cross-session evidence mismatch: " + phase)
        visual = independent["visualReview"]
        if (visual["phase"] != phase or visual["sessionID"] != sid
                or visual["activeScreenshotSHA256"] != local["screen"]["sha256"]
                or visual.get("engineMarkerVisible") is not True or visual.get("value73Visible") is not True):
            raise ValueError("Qualification screenshot review mismatch: " + phase)
        runs = {}
        for key in ("authorRun", "exitRun"):
            path = checked_reference(root, local[key])
            if local[key]["sha256"] != accepted[key]["sha256"]:
                raise ValueError("Qualification run evidence mismatch: " + phase)
            run = json.loads(path.read_bytes())
            if (run["exitCode"] != 0 or run["device"] != acceptance["device"]
                    or run["appPath"] != acceptance["installedApp"] or run["dataPath"] != acceptance["data"]
                    or run["mainPIDs"] != [pid]):
                raise ValueError("Qualification process/package mismatch: " + phase)
            runs[key] = run
        authored = runs["authorRun"]["journal"]
        if (authored["sessionID"] != sid or authored["launchTarget"] != target or authored["launchMode"] != mode
                or runs["exitRun"]["step"] != "readerSaveExit" or runs["exitRun"]["journal"] is not None):
            raise ValueError("Qualification run session mismatch: " + phase)
        if phase.endswith("-cold"):
            cold_path = checked_reference(root, local["coldReceipt"])
            if local["coldReceipt"]["sha256"] != accepted["coldReceipt"]["sha256"]:
                raise ValueError("Qualification cold evidence mismatch: " + phase)
            cold = json.loads(cold_path.read_bytes())
            warm = phase.replace("-cold", "-warm")
            if (cold["device"] != acceptance["device"] or cold["app"] != acceptance["installedApp"]
                    or cold["data"] != acceptance["data"] or cold["newPID"] != pid
                    or cold["oldPID"] != acceptance["modes"][warm]["pid"][0] or cold["oldPID"] == pid
                    or cold["wasIdleJournalAbsent"] is not True or cold["wasNoActiveOrFinalizing"] is not True
                    or cold["debugDylibSHA256"] != binding["debugDylibSHA256"]):
                raise ValueError("Qualification cold process mismatch: " + phase)
        active = json.loads(checked_reference(root, local["active"]).read_bytes())
        completed = json.loads(checked_reference(root, local["completion"]).read_bytes())
        journal, initial, finished, snapshot = active["journal"], active["session"], completed["session"], completed["snapshot"]
        if (journal["launchTarget"] != target or initial["target"] != target or finished["target"] != target
                or journal["sessionID"] != sid or initial["id"] != sid or initial["state"] != "active"
                or journal["launchMode"] != mode or completed["mode"] != mode or completed["pid"] != [pid]
                or completed["sessionID"] != sid or completed.get("journalCleared") is not True
                or finished["id"] != sid or finished["state"] != "completed"
                or finished["finalization"]["snapshotID"] != sid or snapshot["id"] != sid
                or snapshot["manifestHash"] != finished["snapshotManifestHash"]
                or any(snapshot[key] != target[key] for key in ("gameID", "variantID", "saveProfileID", "runtimeID", "contentFingerprint"))):
            raise ValueError("Qualification raw state mismatch: " + phase)
        manifest_path = checked_reference(root, local["manifest"])
        if (local["manifest"]["sha256"] != snapshot["manifestHash"]
                or not any(ref["sha256"] == local["manifest"]["sha256"] and ref["path"].endswith("/Snapshots/" + sid + "/manifest.json") for ref in review["references"])):
            raise ValueError("Qualification snapshot manifest mismatch: " + phase)
        manifest = json.loads(manifest_path.read_bytes())
        if (manifest["id"] != sid or manifest["parentIDs"] != snapshot["parentIDs"]
                or manifest["content"]["fingerprint"] != snapshot["saveFingerprint"]
                or any(manifest[key] != target[key] for key in ("runtimeID", "saveProfileID", "contentFingerprint"))):
            raise ValueError("Qualification snapshot manifest content mismatch: " + phase)
        slots = independent["immutableSlots"]
        if len(slots) != 3 or len(local["saves"]) != 3:
            raise ValueError("Qualification snapshot count mismatch: " + phase)
        slot_roles = set()
        for slot, ref in zip(slots, local["saves"]):
            path = checked_reference(root, ref)
            if ref["path"] in save_paths or ref["sha256"] != slot["sha256"] or path.stat().st_size != slot["byteCount"]:
                raise ValueError("Qualification snapshot identity mismatch: " + phase)
            save_paths.add(ref["path"])
            suffix = "Snapshots/" + sid + "/Files/" + slot["path"].split("/Snapshots/" + sid + "/Files/", 1)[-1]
            matching = [entry for entry in completed["files"] if entry["path"] == suffix]
            if len(matching) != 1 or matching[0]["sha256"] != slot["sha256"] or matching[0]["byteCount"] != slot["byteCount"]:
                raise ValueError("Qualification snapshot/session mismatch: " + phase)
            relative = suffix.split("/Files/", 1)[1]
            slot_roles.add(relative)
            manifest_items = [item for item in manifest["content"]["files"] if item["relativePath"] == relative]
            if len(manifest_items) != 1 or manifest_items[0]["sha256"] != slot["sha256"] or manifest_items[0]["byteCount"] != slot["byteCount"]:
                raise ValueError("Qualification snapshot/manifest mismatch: " + phase)
            check_save_73(path)
        if slot_roles != {"rr_suspend-LT1.save", "sync/rr_suspend-LT1.save", "engine-main-manual-LT1.save"}:
            raise ValueError("Qualification snapshot roles mismatch: " + phase)
    if len(session_ids) != 6 or len(save_paths) != 18:
        raise ValueError("Qualification session or snapshot reuse")


def _inventory_tree(inventory, prefix):
    root_entry = inventory[prefix]
    if root_entry[0] != "dir":
        raise ValueError("Device inventory bundle root is not a directory")
    rows = [(".", "directory", root_entry[1])]
    files = directories = 0
    for path, entry in inventory.items():
        if not path.startswith(prefix + "/"):
            continue
        rel = path[len(prefix) + 1:]
        if entry[0] == "dir":
            rows.append((rel, "directory", entry[1])); directories += 1
        elif entry[0] == "file":
            rows.append((rel, "file", entry[1], entry[3])); files += 1
        else:
            raise ValueError("Linked or special device bundle evidence")
    payload = json.dumps(sorted(rows), ensure_ascii=False, separators=(",", ":")).encode()
    return {"fileCount": files, "directoryCount": directories, "sha256": hashlib.sha256(payload).hexdigest()}


def _device_profile(root, binary, info, profile_path, reviewed, group, expected_team, expected_cert):
    subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True, capture_output=True)
    entitlements = plistlib.loads(subprocess.check_output(["codesign", "-d", "--entitlements", "-", "--xml", str(binary)], stderr=subprocess.DEVNULL))
    profile = plistlib.loads(subprocess.check_output(["security", "cms", "-D", "-i", str(profile_path)], stderr=subprocess.DEVNULL))
    signature = subprocess.check_output(["codesign", "-d", "--verbose=4", str(binary)], stderr=subprocess.STDOUT, text=True)
    team_match = re.search(r"^TeamIdentifier=(\S+)$", signature, re.MULTILINE)
    if not team_match or team_match.group(1) != expected_team:
        raise ValueError("Device signature team mismatch")
    if (expected_team not in profile["TeamIdentifier"] or entitlements.get("com.apple.developer.team-identifier") != expected_team
            or profile["Entitlements"].get("com.apple.developer.team-identifier") != expected_team):
        raise ValueError("Device profile team mismatch")
    signed_id = entitlements.get("application-identifier")
    prefix = reviewed["authorization"]["applicationIdentifierPrefix"]
    if (signed_id != prefix + "." + info["CFBundleIdentifier"] or prefix not in profile["ApplicationIdentifierPrefix"]
            or reviewed["authorization"]["signedApplicationIdentifier"] != signed_id):
        raise ValueError("Device signed bundle identity mismatch")
    def match(value, allowed):
        return isinstance(value, str) and isinstance(allowed, str) and (value == allowed or
                (allowed.endswith("*") and allowed.count("*") == 1 and value.startswith(allowed[:-1])))
    for key, value in entitlements.items():
        if key not in profile["Entitlements"]:
            raise ValueError("Device profile entitlement missing: " + key)
        allowed = profile["Entitlements"][key]
        candidates = allowed if isinstance(allowed, list) else [allowed]
        if isinstance(value, list):
            valid = all(any(match(item, choice) for choice in candidates) for item in value)
        elif isinstance(value, str):
            valid = any(match(value, choice) for choice in candidates)
        else:
            valid = type(value) is type(allowed) and value == allowed
        if not valid:
            raise ValueError("Device profile entitlement mismatch: " + key)
    signed_groups = entitlements.get("com.apple.security.application-groups")
    if not isinstance(signed_groups, list) or group not in signed_groups or group not in profile["Entitlements"].get("com.apple.security.application-groups", []):
        raise ValueError("Device application group mismatch")
    expiration = profile["ExpirationDate"]
    if not isinstance(expiration, datetime.datetime):
        raise ValueError("Device profile expiration invalid")
    expiration = expiration.replace(tzinfo=datetime.timezone.utc) if expiration.tzinfo is None else expiration.astimezone(datetime.timezone.utc)
    if expiration <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("Device profile expired")
    creation = profile.get("CreationDate")
    if not isinstance(creation, datetime.datetime):
        raise ValueError("Device profile creation date invalid")
    creation = creation.replace(tzinfo=datetime.timezone.utc) if creation.tzinfo is None else creation.astimezone(datetime.timezone.utc)
    if creation > datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("Device profile is not yet valid")
    if (reviewed.get("signedAllEntitlementsAuthorized") is not True or reviewed.get("leafCertificateListedInProfile") is not True
            or reviewed["authorization"].get("identityAndGroupAuthorizationPassed") is not True
            or reviewed["authorization"]["bundleID"] != info["CFBundleIdentifier"]
            or reviewed["authorization"]["signatureTeamIdentifier"] != expected_team
            or reviewed["authorization"]["profileUUID"] != profile["UUID"]
            or reviewed["profileSHA256"] != digest(profile_path)
            or reviewed["authorization"]["configuredGroup"] != group
            or reviewed["authorization"]["expirationUTC"] != expiration.isoformat()
            or sorted(entitlements) != reviewed["signedEntitlementKeys"]):
        raise ValueError("Device independent profile review mismatch")
    with tempfile.TemporaryDirectory() as temp:
        prefix_path = str(Path(temp) / "certificate")
        subprocess.run(["codesign", "-d", "--extract-certificates=" + prefix_path, str(binary)], check=True, capture_output=True)
        leaf = Path(prefix_path + "0").read_bytes()
    if (leaf not in profile["DeveloperCertificates"] or hashlib.sha256(leaf).hexdigest() != reviewed["leafCertificateSHA256"]
            or hashlib.sha1(leaf).hexdigest().upper() != expected_cert):
        raise ValueError("Device signature certificate/profile mismatch")
    return entitlements


def frozen_v3_evidence(report, binding):
    return (report["binding"]["sha256"] == V3_SIMULATOR_BINDING_SHA256 and
            all(binding[key]["sha256"] == expected for key, expected in V3_DEVICE_EVIDENCE_SHA256.items()))


def verify_device_binding(root, contract, report, *, historical_only=False):
    binding = json.loads(checked_reference(root, report["deviceBinding"]).read_bytes())
    if not frozen_v3_evidence(report, binding):
        raise ValueError("Device or simulator evidence is not the independently reviewed record")
    if (binding.get("schemaVersion") != 3 or binding.get("scope") != "device-static-build-signing-only"
            or binding.get("physicalDeviceExecution") is not False or binding.get("inputs") != contract["inputs"]
            or contract["qualification"].get("deviceScope") != "device-static-build-signing-only"
            or contract["qualification"].get("physicalDeviceExecution") is not False):
        raise ValueError("Device qualification scope or source binding mismatch")
    refs = {key: checked_reference(root, binding[key]) for key in
            ("preSignAudit", "signedAudit", "staticAudit", "failedInventory", "signedInventory", "deviceXcent", "sourceEvidence", "deviceSignature")}
    semantic = binding["semanticSeal"]
    if (semantic["baseline"]["sha256"] != V3_SEMANTIC_BASELINE_SHA256 or
            semantic["codeResources"]["sha256"] != V3_BASELINE_RESOURCES_SHA256):
        raise ValueError("Device semantic seal is not the independently reviewed baseline")
    checked_reference(root, semantic["baseline"])
    checked_reference(root, semantic["codeResources"])
    pre = json.loads(refs["preSignAudit"].read_bytes()); signed = json.loads(refs["signedAudit"].read_bytes())
    static = json.loads(refs["staticAudit"].read_bytes()); source = json.loads(refs["sourceEvidence"].read_bytes())
    failed = json.loads(refs["failedInventory"].read_bytes()); final = json.loads(refs["signedInventory"].read_bytes())
    signature = json.loads(refs["deviceSignature"].read_bytes())
    if (pre.get("beforeCloneExact") is not True or signed.get("status") != "SIGNED_CLONE_LOADABLE_IDENTITIES_EQUAL_NOT_YET_QUALIFIED"
            or signed.get("preSignAuditSHA256") != binding["preSignAudit"]["sha256"]
            or signed.get("originalInventorySHA256") != binding["failedInventory"]["sha256"]
            or signed.get("signedInventorySHA256") != binding["signedInventory"]["sha256"]
            or signed.get("originalUnchanged") is not True or signed.get("allImageIdentitiesEqual") is not True
            or signed.get("imageCount") != 16 or signed.get("codeSignatureVerified") is not True
            or signed.get("signedEntitlementsEqualXcent") is not True
            or static.get("status") != "STATIC_DEVICE_SIGNING_AUDIT_PASS_NOT_QUALIFIED"
            or any(static.get(key) != "PASS" for key in ("sourceAndEvidenceGuard", "builtConfigurationAndSignedEntitlements", "codeSignatureDeepStrict"))
            or source.get("appSourcesMatch") is not True or source.get("appSources") != contract["inputs"]["appSources"]
            or source.get("pbxMatch") is not True or source.get("pbxSHA256") != contract["inputs"]["projectSHA256"]
            or any(source.get(key) is not True for key in ("bridgeMatch", "pythonMatch", "nativeMatch", "provenanceMatch"))
            or set(source.get("sourcePlistsMatch", {})) != set(CONFIG_PLISTS)
            or not all(value is True for value in source["sourcePlistsMatch"].values())
            or signature.get("schemaVersion") != 1 or signature.get("physicalDeviceExecution") is not False
            or signature.get("staticAuditSHA256") != binding["staticAudit"]["sha256"]):
        raise ValueError("Device source, signing, or independent audit mismatch")
    missing = sorted(set(failed) - set(final)); extra = sorted(set(final) - set(failed))
    changed = sorted(key for key in set(failed) & set(final) if failed[key] != final[key])
    if (missing != signed["missing"] or extra != signed["extra"] or changed != signed["changed"]
            or missing or extra != ["_CodeSignature", "_CodeSignature/CodeResources"] or changed != ["RenReader"]):
        raise ValueError("Device package signing delta mismatch")
    if (failed["RenReader"][3] != pre["originalMainSHA256"] or failed["RenReader"][3] != signed["unsignedMainSHA256"]
            or final["RenReader"][3] != signed["signedMainSHA256"]):
        raise ValueError("Device main inventory mismatch")
    names = {*FRAMEWORKS, "RenReader"}
    if set(contract["builtImages"]["iphoneos"]) != names or set(static["protectedDeviceImages"]) != names:
        raise ValueError("Device image inventory mismatch")
    for name in names:
        rel = "RenReader" if name == "RenReader" else "Frameworks/" + name + ".framework/" + name
        if (contract["builtImages"]["iphoneos"][name] != pre["imageIdentities"][rel]
                or contract["builtImages"]["iphoneos"][name] != static["protectedDeviceImages"][name]):
            raise ValueError("Device signed image identity mismatch: " + name)
    if pre["imageIdentities"]["PlugIns/RenReaderWidgets.appex/RenReaderWidgets"] != static["widgetImageIdentity"]:
        raise ValueError("Device Widget image identity mismatch")
    versions = ("7411", "753", "763", "773", "787", "803", "813", "823", "837", "841", "853")
    names = {"RenPy" + version + ".bundle" for version in versions}
    if set(pre["runtimeBundles"]) != names or set(static["runtimeBundleTrees"]) != names:
        raise ValueError("Device runtime bundle inventory mismatch")
    for name in sorted(names):
        expected = pre["runtimeBundles"][name]
        if (expected.get("matches") is not True or expected["tree"] != static["runtimeBundleTrees"][name]
                or _inventory_tree(final, name) != expected["tree"]
                or (not historical_only and tree_digest(root / "RuntimeKit/Artifacts" / name) != expected["tree"])):
            raise ValueError("Device runtime bundle tree mismatch: " + name)
    config = qualified_v2_configuration(root, contract)
    if (digest(refs["deviceXcent"]) != pre["deviceXcentSHA256"]
            or digest(refs["deviceXcent"]) != config["effectiveEntitlements"]["iphoneos"]["signed"]["sha256"]):
        raise ValueError("Device xcent evidence mismatch")
    profiles = static["profiles"]
    if len(profiles) != 2 or set(signature.get("bundles", {})) != {"app", "widget"}:
        raise ValueError("Device App/Widget signature evidence mismatch")
    for index, (label, prefix) in enumerate((("app", ""), ("widget", "PlugIns/RenReaderWidgets.appex/"))):
        summary = signature["bundles"][label]; reviewed = profiles[index]; auth = reviewed["authorization"]
        binary = "RenReader" if label == "app" else "RenReaderWidgets"
        if (summary["bundleID"] != auth["bundleID"] or summary["team"] != auth["signatureTeamIdentifier"]
                or summary["profileSHA256"] != reviewed["profileSHA256"] or summary["profileSHA256"] != final[prefix + "embedded.mobileprovision"][3]
                or summary["infoSHA256"] != final[prefix + "Info.plist"][3] or summary["binarySHA256"] != final[prefix + binary][3]
                or summary["certificateSHA256"] != reviewed["leafCertificateSHA256"]
                or summary["certificateFingerprint"] != pre["certificateFingerprint"]
                or sorted(summary["entitlements"]) != reviewed["signedEntitlementKeys"]
                or reviewed.get("signedAllEntitlementsAuthorized") is not True or reviewed.get("leafCertificateListedInProfile") is not True
                or auth.get("identityAndGroupAuthorizationPassed") is not True
                or not re.fullmatch(r"[0-9a-f]{40}", summary["cdHash"])):
            raise ValueError("Device signature summary mismatch: " + label)
    if (signature["bundles"]["app"]["team"] != signature["bundles"]["widget"]["team"]
            or signature["bundles"]["widget"]["bundleID"] != signature["bundles"]["app"]["bundleID"] + ".widgets"
            or not same_plist_value(signature["bundles"]["app"]["entitlements"], plist_value(refs["deviceXcent"]))):
        raise ValueError("Device signature team/bundle/entitlement mismatch")


def verify_v3_signed_device(root, contract, app):
    """Re-audit the newly signed actual product; no historical app is needed."""
    if contract.get("qualification", {}).get("bindingVersion", 1) != 3:
        return
    q = contract["qualification"]
    receipt = json.loads(checked_reference(root, {"path": q["reportPath"], "sha256": q["reportSHA256"]}).read_bytes())
    binding = json.loads(checked_reference(root, receipt["deviceBinding"]).read_bytes())
    pre = json.loads(checked_reference(root, binding["preSignAudit"]).read_bytes())
    static = json.loads(checked_reference(root, binding["staticAudit"]).read_bytes())
    signature = json.loads(checked_reference(root, binding["deviceSignature"]).read_bytes())
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True, capture_output=True)
    config = qualified_v2_configuration(root, contract)
    verify_v2_built_configuration(root, contract, app, "iphoneos")
    for name in (*FRAMEWORKS, "RenReader"):
        binary = app / "RenReader" if name == "RenReader" else app / "Frameworks" / (name + ".framework") / name
        if image_identity(root, binary) != contract["builtImages"]["iphoneos"][name]:
            raise ValueError("Signed device product image differs: " + name)
    for name, expected in pre["runtimeBundles"].items():
        if tree_digest(app / name) != expected["tree"]:
            raise ValueError("Signed device product runtime bundle differs: " + name)
    info = plist_value(app / "Info.plist"); widget = app / "PlugIns/RenReaderWidgets.appex"
    widget_info = plist_value(widget / "Info.plist"); group = info["RenReaderAppGroup"]
    if widget_info["CFBundleIdentifier"] != info["CFBundleIdentifier"] + ".widgets" or widget_info["RenReaderAppGroup"] != group:
        raise ValueError("Signed device Widget Info mismatch")
    team = signature["bundles"]["app"]["team"]; cert = pre["certificateFingerprint"]
    for index, (label, bundle, binary, parsed) in enumerate((("app", app, app / "RenReader", info), ("widget", widget, widget / "RenReaderWidgets", widget_info))):
        reviewed = static["profiles"][index]; summary = signature["bundles"][label]
        if digest(bundle / "Info.plist") != summary["infoSHA256"] or digest(bundle / "embedded.mobileprovision") != summary["profileSHA256"]:
            raise ValueError("Signed device Info/profile differs: " + label)
        permissions = _device_profile(root, binary, parsed, bundle / "embedded.mobileprovision", reviewed, group, team, cert)
        if not same_plist_value(permissions, summary["entitlements"]):
            raise ValueError("Signed device entitlements differ: " + label)
        details = subprocess.check_output(["codesign", "-d", "--verbose=4", str(bundle)], stderr=subprocess.STDOUT, text=True)
        match = re.search(r"^CDHash=([0-9a-f]{40})$", details, re.MULTILINE)
        if not match or (label == "widget" and match.group(1) != summary["cdHash"]):
            raise ValueError("Signed device code-directory identity differs: " + label)
    if image_identity(root, widget / "RenReaderWidgets") != static["widgetImageIdentity"]:
        raise ValueError("Signed device Widget image differs")
    if not same_plist_value(signature["bundles"]["app"]["entitlements"], plist_value(checked_reference(root, binding["deviceXcent"]))):
        raise ValueError("Signed device xcent differs")
    sys.path.insert(0, str(root / "Scripts/runtime"))
    from semantic_seal import verify_semantic_seal
    verify_semantic_seal(root, app, binding, pre, static, image_identity=image_identity, checked_reference=checked_reference)

def accepted(root, contract, *, components_only=False, historical_only=False):
    qualification = contract.get("qualification", {})
    if qualification.get("accepted") is not True:
        raise ValueError("853 engine overlay UI qualification is not approved")
    # Evidence is a build input, not a claim derived from this checker.
    evidence = evidence_path(root, qualification["reportPath"])
    if digest(evidence) != qualification["reportSHA256"]:
        raise ValueError("853 engine overlay qualification evidence changed")
    report = json.loads(evidence.read_bytes())
    modes = report.get("launchModes")
    version = qualification.get("bindingVersion", 1)
    if type(version) is not int or version not in (1, 2, 3) or report.get("schemaVersion") != version:
        raise ValueError("Unsupported qualification binding version")
    if version == 1 and "binding" in report:
        raise ValueError("Unexpected version 2 binding in legacy qualification")
    if version == 1 and not legacy_contract_qualified(contract):
        raise ValueError("Legacy qualification contract is not the published contract")
    if version == 2 and ("deviceBinding" in report or not frozen_v2_contract_qualified(contract)):
        raise ValueError("Version 2 qualification contract is not the frozen contract")
    if (report.get("kind") != "853-custom-engine-all-modes-simulator-evidence"
            or report.get("versionWideCapabilityQualified") is not True
            or report.get("runtimeProvenanceSHA256") != contract["inputs"]["provenanceSHA256"]
            or not isinstance(modes, dict) or set(modes) != LAUNCH_MODES):
        raise ValueError("853 qualification does not cover all launch modes on the exact runtime")
    for mode in LAUNCH_MODES:
        result = modes[mode]
        if not isinstance(result, dict) or result.get("passed") is not True:
            raise ValueError("853 launch mode not qualified: " + mode)
        path = evidence_path(root, result["resultPath"])
        if digest(path) != result.get("resultSHA256"):
            raise ValueError("853 launch mode evidence changed: " + mode)
        detail = json.loads(path.read_bytes())
        if (detail.get("launchMode") != mode or detail.get("passed") is not True or
                detail.get("runtimeProvenanceSHA256") != contract["inputs"]["provenanceSHA256"]):
            raise ValueError("853 launch mode evidence does not match its runtime: " + mode)
        detail_evidence = detail.get("evidence")
        expected_keys = {"result", "finalData", "screenshots"} if mode == "enhanced" else {"result", "active", "completed", "screenshots"}
        if not isinstance(detail_evidence, dict) or not expected_keys <= set(detail_evidence):
            raise ValueError("853 launch mode has incomplete source evidence: " + mode)
        refs = [detail_evidence[key] for key in expected_keys if key != "screenshots"]
        screenshots = detail_evidence["screenshots"]
        if not isinstance(screenshots, list) or not screenshots:
            raise ValueError("853 launch mode has no screenshots: " + mode)
        refs.extend(screenshots)
        for ref in refs:
            if not isinstance(ref, dict) or digest(evidence_path(root, ref["path"])) != ref.get("sha256"):
                raise ValueError("853 source evidence changed: " + mode)
    if version in (2, 3):
        verify_v2_binding(root, contract, report, historical_only=(historical_only or components_only))
    if version == 3:
        verify_device_binding(root, contract, report, historical_only=historical_only)
    if not historical_only:
        verify_inputs(root, contract, components_only=components_only)


def load_commands_identity(path):
    """Hash all loading semantics while normalizing the replaceable signature.

    Code signing changes LC_CODE_SIGNATURE and can change only the signature
    tail of __LINKEDIT. Preserve its pre-signature file extent and any extra
    mapped pages, along with every other header and load-command byte.
    """
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("Truncated Mach-O header")
    header = bytearray(data[:32])
    magic, _, _, _, count, commands_size, _, _ = struct.unpack_from("<8I", header)
    if magic != 0xfeedfacf or 32 + commands_size > len(data):
        raise ValueError("Unsupported or truncated arm64 Mach-O")
    offset = 32
    commands = []
    signature = None
    for _ in range(count):
        if offset + 8 > 32 + commands_size:
            raise ValueError("Truncated Mach-O load command")
        cmd, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 8 or offset + size > 32 + commands_size:
            raise ValueError("Invalid Mach-O load command")
        command = bytearray(data[offset:offset + size])
        if cmd == 0x1d:
            if signature is not None or size != 16:
                raise ValueError("Invalid Mach-O signature command")
            signature = struct.unpack_from("<II", command, 8)
        else:
            commands.append(command)
        offset += size
    if offset != 32 + commands_size:
        raise ValueError("Inconsistent Mach-O load command size")
    linkedit = [command for command in commands if struct.unpack_from("<I", command)[0] == 0x19
                and len(command) >= 72 and bytes(command[8:24]).rstrip(b"\0") == b"__LINKEDIT"]
    if len(linkedit) != 1:
        raise ValueError("Expected exactly one Mach-O __LINKEDIT")
    segment = linkedit[0]
    _, vm_size, file_offset, file_size = struct.unpack_from("<QQQQ", segment, 24)
    page = 16384  # All qualified images are arm64 iOS/device simulator slices.
    align = lambda value: (value + page - 1) // page * page
    if vm_size < align(file_size):
        raise ValueError("Invalid Mach-O __LINKEDIT extent")
    unsigned_size = file_size
    if signature is not None:
        sig_offset, sig_size = signature
        if sig_offset < file_offset or sig_offset + sig_size != file_offset + file_size:
            raise ValueError("Mach-O signature is not the final __LINKEDIT tail")
        unsigned_size = sig_offset - file_offset
    if file_offset > len(data) or unsigned_size > len(data) - file_offset:
        raise ValueError("Mach-O __LINKEDIT content is truncated")
    normalized_vm_size = align(unsigned_size) + vm_size - align(file_size)
    struct.pack_into("<Q", segment, 32, normalized_vm_size)
    struct.pack_into("<Q", segment, 48, unsigned_size)
    struct.pack_into("<II", header, 16, len(commands), sum(map(len, commands)))
    return (hashlib.sha256(header + b"".join(commands)).hexdigest(),
            hashlib.sha256(data[file_offset:file_offset + unsigned_size]).hexdigest())


def has_code_signature(path):
    """Recognize an unsigned thin arm64 image without treating invalid signed images as unsigned."""
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("Truncated Mach-O header")
    magic, _, _, _, count, size, _, _ = struct.unpack_from("<8I", data)
    if magic != 0xfeedfacf or 32 + size > len(data):
        raise ValueError("Unsupported or truncated arm64 Mach-O")
    offset = 32
    seen = False
    for _ in range(count):
        if offset + 8 > 32 + size:
            raise ValueError("Truncated Mach-O load command")
        command, length = struct.unpack_from("<II", data, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise ValueError("Invalid Mach-O load command")
        if command == 0x1d:
            if seen or length != 16:
                raise ValueError("Invalid Mach-O signature command")
            seen = True
        offset += length
    if offset != 32 + size:
        raise ValueError("Inconsistent Mach-O load command size")
    return seen


def image_identity(root, path):
    """Compare loadable arm64 contents independently of the signing envelope."""
    digest(path)  # Reject a missing, linked or special image before invoking lipo.
    sys.path.insert(0, str(root / "Scripts/runtime"))
    from audit_renderer_candidate import native_identity
    archs = subprocess.check_output(["xcrun", "lipo", "-archs", str(path)], text=True).split()
    if "arm64" not in archs:
        raise ValueError("Missing arm64 in capability image: " + str(path))
    with tempfile.TemporaryDirectory() as temp:
        selected = path
        if len(archs) != 1:
            selected = Path(temp) / "arm64"
            subprocess.run(["xcrun", "lipo", "-thin", "arm64", str(path), "-output", str(selected)], check=True)
        # Xcode's final build phase runs before the host executable is signed.
        # Sign only a temporary copy of a truly unsigned image; never overwrite
        # or silently repair an existing (possibly invalid) signature.
        if not has_code_signature(selected):
            signed = Path(temp) / "adhoc-signed"
            shutil.copy2(selected, signed)
            subprocess.run(["codesign", "--force", "--sign", "-", str(signed)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            selected = signed
        image = native_identity(selected)
        commands, linkedit = load_commands_identity(selected)
    return {"machOUUID": image["machOUUID"], "sectionSHA256": image["sectionSHA256"],
            "loadCommandsSHA256": commands, "linkeditSHA256": linkedit}


def packaged_source_identity(root, source, platform):
    # Xcode's iPhoneOS framework-copy phase strips bitcode before signing.
    # Reproduce that transformation in a temporary file for an honest comparison.
    if platform != "iphoneos":
        return image_identity(root, source)
    with tempfile.TemporaryDirectory() as directory:
        stripped = Path(directory) / source.name
        subprocess.run(["xcrun", "bitcode_strip", str(source), "-r", "-o", str(stripped)], check=True, capture_output=True)
        return image_identity(root, stripped)


def verify_built_app(root, contract, app, platform, configuration):
    """Post-copy check catches resources changing after the pre-build gate."""
    if (configuration, platform) not in (("Debug", "iphonesimulator"), ("Release", "iphoneos")):
        raise ValueError("This build configuration requires capability requalification")
    bundle = app / "RenPy853.bundle"
    profile_path = bundle / "runtime-profile.json"
    digest(profile_path)
    profile = json.loads(profile_path.read_bytes())
    flag = profile.get("engineOverlaySchemaVersion")
    if "engineOverlaySchemaVersion" in profile and (type(flag) is not int or flag != 1):
        raise ValueError("Invalid built 853 capability flag")
    expected = current_inputs(root)
    if profile_content(profile) != expected["profileContentSHA256"] or \
            digest(bundle / "provenance.json") != expected["provenanceSHA256"] or \
            tree_digest(bundle / "base") != expected["base"]:
        raise ValueError("Built 853 resources differ from the qualified base")
    source_info = plist_value(root / "App/Info.plist")
    built_info = plist_value(app / "Info.plist")
    if source_info.get(HOST_STATUS_KEY) != HOST_STATUS or built_info.get(HOST_STATUS_KEY) != HOST_STATUS:
        raise ValueError("Current App must declare unqualified host status")
    if built_info.get("MinimumOSVersion") != "17.0":
        raise ValueError("Current App deployment target differs")
    if digest(app / "RenPy853.bundle/Info.plist") != digest(root / "RuntimeKit/Artifacts/RenPy853.bundle/Info.plist"):
        raise ValueError("Built runtime bundle Info differs from component")
    for name in FRAMEWORKS:
        source = framework_slice(root, name, platform)
        actual = app / "Frameworks" / (name + ".framework")
        names = ("Info.plist", "live2d-core.json") if name == "RRLive2DCore" else ("Info.plist",)
        for filename in names:
            if digest(source / filename) != digest(actual / filename):
                raise ValueError("Built framework metadata differs from component: " + name)
    images = {name: app / "Frameworks" / (name + ".framework") / name for name in FRAMEWORKS}
    for name, path in images.items():
        source = framework_slice(root, name, platform) / name
        if image_identity(root, path) != packaged_source_identity(root, source, platform):
            raise ValueError("Built capability image differs from qualification: " + name)


def require_v3_enabled_profile(root, contract, profile):
    version = contract.get("qualification", {}).get("bindingVersion", 1)
    value = profile.get("engineOverlaySchemaVersion")
    if type(version) is not int:
        raise ValueError("Invalid qualification version")
    if type(value) is int and value == 1:
        return
    if version == 3:
        raise ValueError("V3 qualification requires the enabled 853 profile")
    if ((version == 1 and legacy_contract_qualified(contract)) or
            (version == 2 and frozen_v2_contract_qualified(contract))):
        verify_inputs(root, contract)
        return
    raise ValueError("Disabled 853 requires an explicitly frozen legacy contract")


EXPANDED_CERTIFICATE_SHA256 = "30cbed3c70ee6b76857504700f289b960f30e97b93c7b465caa0115fd9b0ebd5"
REMAINING_CERTIFICATE_SHA256 = "95e1c64007ceb848b2c9e5af51ef1e8b1e090e238477eea433c218b0b11d6eaa"
LEGACY_MENU_CERTIFICATE_SHA256 = "3ae457a11656f31c67e39508295047d8834ef3ec723a9e0492ab9a428f86ecac"
PROGRESS_763_CERTIFICATE_SHA256 = "f7f4e2f055f9db07810961a9c17f2b1309a953041d0d655515f7e0a29155fe17"
PROGRESS_837_CERTIFICATE_SHA256 = "e7797bc60a71e65374e97f8a9f5c257c1073a994d2b719c4683909529df1360e"
PROGRESS_REMAINING = {
    '7.4.11': ('429abf310d9f5752d237672a5d1911be6e9210da8e0a697e5545ea15ca8029ed', '44f3a1c2f9360323dfadcb398b52d92fce3444796cb0cfb5c299e5d8c50728aa'),
    '7.5.3': ('fbcfa885edd2030384c0416145e72598ac913f12ec0db4934f53b885f0d83859', '5446f9ff81337a43267b24ae52092a757c55cde956f733b9fd76bcd976b5d303'),
    '7.7.3': ('36ca96d073fb5ed0496edeab6a199f624d5d269ac8c9f8eb12c4acdc59869408', 'b8fcbb39197353f6becc65a47a358596b141d5ee684eed410653d3b2806b69e1'),
    '7.8.7': ('b8eb71c20adfa8e919dd63ac78a98592b889baad3dead1ea76f398228260e1fd', 'e500110445ae93ce425cd7da3220933e22716ec6c4c60ec2fec6c88a50330f8b'),
    '8.0.3': ('044bfcc7e6724f95dae59f1a5ac6d1ff702e3a9d4f12a8537950a23bbb617052', '91fc224c4bef1c5133057b4467bc7680d216f2be47459e703f5c37ec7266c374'),
    '8.1.3': ('43fc7051e687cae259a7b4cd16ab5fc9c3b92ea41b3efbbd40444ddfd93bd304', 'a856be2b31c771106f130586963635839f47c955bdcfff96e1c9f732f6e01e30'),
    '8.2.3': ('c61be616e469fa67291f8cef752001092188e43c1623178c6bf88f07f4883f8c', 'd3fc2d4ad3cdf50960e53092dcd811748a9388e92f1caff85aacf673b60adade'),
    '8.4.1': ('eee9ffb30fb0aec57c6979915d155565f7403c3459ca88fee7bf45a52a099314', 'ebcadb050ff1ede2311c5d57e5568f55aa77d0d05f09dbd8130fbb70b8bc12a4'),
}
MENU_7411_837_CERTIFICATE_SHA256 = "9be35d807cdd866cf50d7261ceffafc94f9131677b9cc1284215306de8433618"
SEVEN_MENU_CERTIFICATE_SHA256 = "8a8e9ba5b7edd0463e90ac244c4e4cc7663552c5f0dd43c98a6f686cd4e09ee8"
INITIAL_EXPANDED_VERSIONS = frozenset(("7.5.3", "8.0.3"))
EXPANDED_VERSIONS = frozenset(VERSIONS) - {"8.5.3"}
SEVEN_MENU_VERSIONS = frozenset(("7.5.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.4.1"))


def seven_menu_update(root, source, previous, version):
    certificate = root / "RuntimeKit/Patches/overlay-capability-seven-deferred-menu.json"
    if digest(certificate) != SEVEN_MENU_CERTIFICATE_SHA256:
        raise ValueError("Seven-menu certificate changed")
    document = json.loads(certificate.read_bytes())
    if document.get("schemaVersion") != 1 or set(document.get("runtimes", {})) != SEVEN_MENU_VERSIONS:
        raise ValueError("Seven-menu certificate identity changed")
    update = document["runtimes"][version]
    prior = EXPANDED_CERTIFICATE_SHA256 if version in INITIAL_EXPANDED_VERSIONS else REMAINING_CERTIFICATE_SHA256
    evidence = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031" / version.replace(".", "")
    backup = evidence / "previous"
    if (update.get("runtimeID") != version or update.get("priorCertificateSHA256") != prior or
            update["previousProvenanceSHA256"] != previous["provenanceSHA256"] or
            digest(backup / "provenance.json") != previous["provenanceSHA256"] or
            digest(backup / "rr_host.py") != update["previousHostSHA256"] or
            digest(source / "provenance.json") != update["newProvenanceSHA256"] or
            digest(source / "base/rr_host.py") != update["newHostSHA256"] or
            tree_digest(source / "base") != update["newBase"] or
            tree_digest(source / "base", substitutions={"rr_host.py": update["previousHostSHA256"]}) != previous["base"]):
        raise ValueError("Seven-menu resource identity changed")
    if set(update.get("events", {})) != {"warm", "cold", "menu"}:
        raise ValueError("Seven-menu evidence list changed")
    processes = []
    for phase, expected_hash in update["events"].items():
        path = evidence / (phase + ".events.ndjson")
        if digest(path) != expected_hash:
            raise ValueError("Seven-menu evidence changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != update["overlayManifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") or
                                        row.get("marker") != "ENGINE-QA-" + version for row in probes) or
                len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
                any(row.get("type") in ("qaFailed", "qaFailure", "commandRejected") for row in rows)):
            raise ValueError("Seven-menu sessions did not pass")
        if phase == "menu":
            visible = {(row.get("sessionID"), row.get("screen")) for row in rows if row.get("type") == "menuProbeVisible"}
            if visible != {("overlay-0", "save"), ("overlay-1", "history")}:
                raise ValueError("Seven-menu screen evidence incomplete")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 3:
        raise ValueError("Seven-menu runs did not use separate processes")
    return {**previous, "provenanceSHA256": update["newProvenanceSHA256"], "base": update["newBase"]}


def remaining_menu_update(root, source, previous, version):
    certificate = root / "RuntimeKit/Patches/overlay-capability-7411-837-deferred-menu.json"
    if digest(certificate) != MENU_7411_837_CERTIFICATE_SHA256:
        raise ValueError("Menu update certificate changed")
    document = json.loads(certificate.read_bytes())
    if (document.get("schemaVersion") != 1 or document.get("priorCertificateSHA256") != REMAINING_CERTIFICATE_SHA256 or
            set(document.get("runtimes", {})) != {"7.4.11", "8.3.7"}):
        raise ValueError("Menu update certificate identity changed")
    update = document["runtimes"][version]
    evidence = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031" / version.replace(".", "")
    backup = evidence / "previous"
    if (update.get("runtimeID") != version or update["previousProvenanceSHA256"] != previous["provenanceSHA256"] or
            digest(backup / "provenance.json") != previous["provenanceSHA256"] or
            digest(backup / "rr_host.py") != update["previousHostSHA256"] or
            digest(source / "provenance.json") != update["newProvenanceSHA256"] or
            digest(source / "base/rr_host.py") != update["newHostSHA256"] or
            tree_digest(source / "base") != update["newBase"] or
            tree_digest(source / "base", substitutions={"rr_host.py": update["previousHostSHA256"]}) != previous["base"]):
        raise ValueError("Menu update resource identity changed")
    processes = []
    if set(update.get("events", {})) != {"warm", "cold"}:
        raise ValueError("Menu update evidence list changed")
    for phase, expected_hash in update["events"].items():
        path = evidence / (phase + ".events.ndjson")
        if digest(path) != expected_hash:
            raise ValueError("Menu update evidence changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != update["overlayManifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") or
                                        row.get("marker") != "ENGINE-QA-" + version for row in probes) or
                len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
                any(row.get("type") in ("qaFailed", "qaFailure") for row in rows)):
            raise ValueError("Menu update sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Menu update cold run did not use a new process")
    return {**previous, "provenanceSHA256": update["newProvenanceSHA256"], "base": update["newBase"]}


def legacy_menu_update(root, source, previous):
    certificate = root / "RuntimeKit/Patches/overlay-capability-763-deferred-menu.json"
    if digest(certificate) != LEGACY_MENU_CERTIFICATE_SHA256:
        raise ValueError("Legacy menu update certificate changed")
    update = json.loads(certificate.read_bytes())
    backup = root / "RuntimeKit/Validation/DeferredLegacyOverlay20261031/previous"
    if (update.get("schemaVersion") != 1 or update.get("runtimeID") != "7.6.3" or
            update.get("priorCertificateSHA256") != REMAINING_CERTIFICATE_SHA256 or
            update.get("previousProvenanceSHA256") != previous["provenanceSHA256"] or
            digest(backup / "provenance.json") != previous["provenanceSHA256"] or
            digest(backup / "rr_host.py") != update["previousHostSHA256"] or
            digest(source / "provenance.json") != update["newProvenanceSHA256"] or
            digest(source / "base/rr_host.py") != update["newHostSHA256"] or
            tree_digest(source / "base") != update["newBase"] or
            tree_digest(source / "base", substitutions={"rr_host.py": update["previousHostSHA256"]}) != previous["base"]):
        raise ValueError("Legacy menu update resource identity changed")
    evidence = evidence_path(root, update["evidencePath"])
    if digest(evidence) != update["evidenceSHA256"]:
        raise ValueError("Legacy menu update evidence changed")
    report = json.loads(evidence.read_bytes())
    if (report.get("runtime") != "7.6.3" or report.get("candidateHostSHA256") != update["newHostSHA256"] or
            report.get("stageProvenanceSHA256") != update["newProvenanceSHA256"] or
            set(report.get("events", {})) != {"warm", "cold"}):
        raise ValueError("Legacy menu update evidence identity changed")
    processes = []
    for phase, expected_hash in report["events"].items():
        path = evidence.parent / ("service-" + phase + ".events.ndjson")
        if digest(path) != expected_hash:
            raise ValueError("Legacy menu update events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                {row.get("launchMode") for row in ready} != LAUNCH_MODES or len(ready) != 3 or len(probes) != 3 or
                any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailed", "qaFailure") for row in rows)):
            raise ValueError("Legacy menu update sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Legacy menu cold run did not use a new process")
    return {**previous, "provenanceSHA256": update["newProvenanceSHA256"], "base": update["newBase"]}


def progress_763_update(root, source, previous):
    return progress_update(root, source, previous, "7.6.3", PROGRESS_763_CERTIFICATE_SHA256, LEGACY_MENU_CERTIFICATE_SHA256)


def progress_837_update(root, source, previous):
    return progress_update(root, source, previous, "8.3.7", PROGRESS_837_CERTIFICATE_SHA256, MENU_7411_837_CERTIFICATE_SHA256)


def inline_update(root, source, previous, version):
    suffix = version.replace(".", "")
    certificate = root / ("RuntimeKit/Patches/overlay-capability-" + suffix + "-inline-translation.json")
    expected_certificate = {"7.6.3": "397affd84101c9e1166b87549af5100b4a6a1d9ca267a39aa01200fb6385d0e8", "8.3.7": "08fe4b16e94b12863612fde516f5432dfcc491655595f62989d292d2346299fe", "8.4.1": "f9c3b6e05d0e3563ef80b4c8b4cf2b08d212567ad2c3c9b78e28e66ee1264b4f", "8.2.3": "817cdf9567db33cbface9b4755bd49b0c56b2b1ba2bb9cea2ab8de873e65621c", "7.8.7": "04ac3cf59ee7730481d96a455d71b55500bc0d6b56bb4026a5684b44843a775b", "7.7.3": "e2ad7485bdc198b6b4d73e5c0bba757825c7b913b973d32f0e367e1d666d30b2", "8.1.3": "ce8e92ba0c9b98b9f96331f0a5cc593e34678d2fa1aa809966c2288574c6106b", "8.0.3": "47747a98730c1203f612e17237b5babc784d729354e776631a24a05baba62e9e", "7.5.3": "4d35b2b1197d11f32f63fe37f6c068cb3910ccdbf0bd687f6489b7599a1e2816", "7.4.11": "0e27273df35bc8ebd9ccd3f3655a5916ad4c8004dc7076820ac281e43c7b52ba"}[version]
    if digest(certificate) != expected_certificate:
        raise ValueError("Inline translation certificate changed")
    update = json.loads(certificate.read_bytes())
    prior = root / ("RuntimeKit/Validation/InlineTranslation" + suffix + "Overlay20261101/previous/RenPy" + suffix + ".bundle")
    prior_certificate = (PROGRESS_763_CERTIFICATE_SHA256 if version == "7.6.3" else
                         PROGRESS_837_CERTIFICATE_SHA256 if version == "8.3.7" else PROGRESS_REMAINING[version][0])
    if (update.get("schemaVersion") != 1 or update.get("runtimeID") != version or
            update.get("priorCertificateSHA256") != prior_certificate or
            update.get("previousProvenanceSHA256") != previous["provenanceSHA256"] or
            digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(prior / "base/rr_host.py") != update["previousHostSHA256"] or
            digest(source / "provenance.json") != update["newProvenanceSHA256"] or
            digest(source / "base/rr_host.py") != update["newHostSHA256"] or
            tree_digest(source / "base") != update["newBase"] or
            tree_digest(source / "base", substitutions={"rr_host.py": update["previousHostSHA256"]}) != previous["base"]):
        raise ValueError("Inline translation resource identity changed")
    evidence = evidence_path(root, update["evidencePath"])
    if digest(evidence) != update["evidenceSHA256"]:
        raise ValueError("Inline translation evidence changed")
    report = json.loads(evidence.read_bytes())
    if (report.get("runtime") != version or report.get("candidateHostSHA256") != update["newHostSHA256"] or
            report.get("stageProvenanceSHA256") != update["newProvenanceSHA256"] or
            set(report.get("events", {})) != {"warm", "cold"}):
        raise ValueError("Inline translation evidence identity changed")
    ui = evidence_path(root, report["uiEvidencePath"])
    if digest(ui) != report["uiEvidenceSHA256"]:
        raise ValueError("Inline translation UI evidence changed")
    ui_report = json.loads(ui.read_bytes())
    if ui_report.get("runtime") != version or ui_report.get("hostSHA256") != update["newHostSHA256"]:
        raise ValueError("Inline translation UI host identity changed")
    screenshots = ui_report.get("screenshots", {})
    if set(screenshots) != {"first.png", "second.png", "rollback.png"} or any(
            digest(ui.parent / name) != expected for name, expected in screenshots.items()):
        raise ValueError("Inline translation UI screenshots changed")
    processes = []
    for phase, expected_hash in report["events"].items():
        path = evidence.parent / (phase + ".events.ndjson")
        if digest(path) != expected_hash:
            raise ValueError("Inline translation overlay events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("capabilities", {}).get("inlineTranslation") is not (row.get("launchMode") != "nativeCompatibility") for row in ready) or
                any(row.get("engineOverlaySHA256") != report.get("overlayManifestSHA256") for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") or row.get("marker") != "ENGINE-QA-" + version for row in probes) or
                len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
                any(row.get("type") in ("qaFailed", "qaFailure", "commandRejected") for row in rows)):
            raise ValueError("Inline translation overlay sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Inline translation cold run did not use a new process")
    return {**previous, "provenanceSHA256": update["newProvenanceSHA256"], "base": update["newBase"]}


def progress_update(root, source, previous, version, certificate_hash, prior_certificate_hash):
    suffix = version.replace(".", "")
    certificate = root / ("RuntimeKit/Patches/overlay-capability-" + suffix + "-dialogue-progress.json")
    if digest(certificate) != certificate_hash:
        raise ValueError("Dialogue progress certificate changed")
    update = json.loads(certificate.read_bytes())
    if version in PROGRESS_REMAINING:
        backup = root / ("RuntimeKit/Candidates/DialogueProgressRemaining/" + suffix + "/previous")
    else:
        backup = root / ("RuntimeKit/Candidates/DialogueProgress" + suffix + "/previous")
    if (update.get("schemaVersion") != 1 or update.get("runtimeID") != version or
            update.get("priorCertificateSHA256") != prior_certificate_hash or
            update.get("previousProvenanceSHA256") != previous["provenanceSHA256"] or
            digest(backup / "provenance.json") != previous["provenanceSHA256"] or
            digest(backup / "rr_host.py") != update["previousHostSHA256"] or
            digest(source / "provenance.json") != update["newProvenanceSHA256"] or
            digest(source / "base/rr_host.py") != update["newHostSHA256"] or
            tree_digest(source / "base") != update["newBase"] or
            tree_digest(source / "base", substitutions={"rr_host.py": update["previousHostSHA256"]}) != previous["base"]):
        raise ValueError("Dialogue progress resource identity changed")
    evidence = evidence_path(root, update["evidencePath"])
    if digest(evidence) != update["evidenceSHA256"]:
        raise ValueError("Dialogue progress evidence changed")
    report = json.loads(evidence.read_bytes())
    if (report.get("runtime") != version or report.get("candidateHostSHA256") != update["newHostSHA256"] or
            report.get("stageProvenanceSHA256") != update["newProvenanceSHA256"] or
            set(report.get("events", {})) != {"warm", "cold"}):
        raise ValueError("Dialogue progress evidence identity changed")
    processes = []
    for phase, expected_hash in report["events"].items():
        path = evidence.parent / (phase + ".events.ndjson")
        if digest(path) != expected_hash:
            raise ValueError("Dialogue progress events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        progress = [row for row in rows if row.get("type") == "dialogueProgress"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("capabilities", {}).get("dialogueProgress") is not (row.get("launchMode") != "nativeCompatibility") for row in ready) or
                any(row.get("engineOverlaySHA256") != report.get("overlayManifestSHA256") for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") or row.get("marker") != "ENGINE-QA-" + version for row in probes) or
                len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
                len(progress) != 2 or any(row.get("seenDialogueBlocks") not in (0, 1) or row.get("totalDialogueBlocks") != 1 for row in progress) or
                any(row.get("type") in ("qaFailed", "qaFailure", "commandRejected") for row in rows)):
            raise ValueError("Dialogue progress sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Dialogue progress cold run did not use a new process")
    return {**previous, "provenanceSHA256": update["newProvenanceSHA256"], "base": update["newBase"]}


def traceback_837_update(root, bundle, prior, expected):
    """Validate the narrow 8.3.7 log patch without weakening historical checks."""
    new_hash = "64bec4acabe6f913e311355f3bf419757cbfc725bb1f3f617cedc10aaa5c379d"
    if (digest(prior / "provenance.json") != expected["provenanceSHA256"] or
            tree_digest(prior / "base") != expected["base"] or
            digest(prior / "base/renpy/error.py") != "dfa364e74c6bebce6612e7028b311d4f122f5b27a8c5d8542eb697192c7c8e38" or
            digest(prior / "base/renpy/error.pyc") != "9b595ea4c4021bc0bfb50cd1e9a748e596fa9a8777eb6459a65e1453622bc9ff" or
            digest(bundle / "base/renpy/error.py") != "8a6cc45b0c71f1525b1a0ba664ed32df2fd9b43807bc0383fcb614459f8785c7" or
            (bundle / "base/renpy/error.pyc").exists()):
        raise ValueError("8.3.7 traceback resource identity changed")
    excluded = {"renpy/error.py", "renpy/error.pyc"}
    before, after = prior / "base", bundle / "base"
    if tree_digest(before, lambda p: p.relative_to(before).as_posix() not in excluded) != tree_digest(after, lambda p: p.relative_to(after).as_posix() not in excluded):
        raise ValueError("8.3.7 traceback resource tree changed")
    evidence = root / "RuntimeKit/Validation/TracebackUTF8837Candidate20261101/verification.json"
    overlay = root / "RuntimeKit/Validation/TracebackUTF8837Overlay20261101/verification.json"
    if (digest(evidence) != "3c5d9aef96ef237d97e461040a94407cbfa73e3260c17e7e870bc38fd44f9d02" or
            digest(overlay) != "898a8672363d1f2dfb6ef25c54d235ffa3bd7dce33276fe451f1edf68d515a3e"):
        raise ValueError("8.3.7 traceback evidence changed")
    ui = json.loads(evidence.read_bytes())
    for name, key in (("baseline-summary.txt", "baselineSummarySHA256"), ("patched-traceback.txt", "fullTracebackSHA256")):
        if digest(evidence.parent / name) != ui[key]: raise ValueError("8.3.7 traceback output changed")
    report = json.loads(overlay.read_bytes())
    if report.get("stageProvenanceSHA256") != new_hash or set(report.get("events", {})) != {"warm", "cold"}:
        raise ValueError("8.3.7 traceback overlay identity changed")
    processes = []
    for phase, expected_hash in report["events"].items():
        path = overlay.parent / (phase + ".events.ndjson")
        if digest(path) != expected_hash: raise ValueError("8.3.7 traceback overlay events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [r for r in rows if r.get("type") == "qaPassed"]
        ready = [r for r in rows if r.get("type") == "ready"]
        probes = [r for r in rows if r.get("type") == "engineOverlayProbe"]
        pins = [r for r in rows if r.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {r.get("launchMode") for r in ready} != LAUNCH_MODES or
                any(r.get("engineOverlaySHA256") != report.get("overlayManifestSHA256") for r in ready) or
                len(probes) != 3 or any(r.get("value") != 73 or r.get("marker") != "ENGINE-QA-8.3.7" or r.get("loaded") is not (phase == "cold") for r in probes) or
                len(pins) != 3 or any(not (r.get("sameAccepted") and r.get("stockRejected") and r.get("otherDigestRejected")) for r in pins) or
                any(r.get("type") in ("qaFailed", "qaFailure", "commandRejected") for r in rows)):
            raise ValueError("8.3.7 traceback overlay sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("8.3.7 cold run used the same process")
    return {**expected, "provenanceSHA256": new_hash, "base": tree_digest(after)}


def gallery_837_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GalleryUnlock837Stage20261101/previous"
    new_hash = "9b61cc39b0fa18a25948efcc98a6c457d8e718fa25c7e34c60684ad433a1361f"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != new_hash or
            digest(source / "base/rr_host.py") != "9bc522b57781ed48596b4154dc6810a941d1f622e60d89eaf4c7ba5f630614ca"):
        raise ValueError("Gallery 837 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery 837 runtime tree changed")
    path = root / "RuntimeKit/Validation/GalleryUnlock837Candidate20261101/verification.json"
    if digest(path) != "460713c44a2ca76c00ce881c3c4a9de1223a9ccac345261a298f3c601bdba8f8":
        raise ValueError("Gallery 837 evidence changed")
    report = json.loads(path.read_bytes())
    for name, expected in report["screenshots"].items():
        if digest(path.parent / name) != expected: raise ValueError("Gallery 837 screenshot changed")
    if set(report["events"]) != {"warm", "cold"}: raise ValueError("Gallery 837 event phases changed")
    processes = []
    for phase, expected in report["events"].items():
        events = path.parent / (phase + ".events.ndjson")
        if digest(events) != expected: raise ValueError("Gallery 837 events changed")
        rows = [row for line in events.read_text().splitlines() if line for row in [json.loads(line)] if row.get("runID") == "gallery837-" + phase]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["overlayManifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.3.7" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery 837 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery 837 cold process was not separate")
    return {**previous, "provenanceSHA256": new_hash, "base": tree_digest(after)}


def gallery_763_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GalleryUnlock763Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "b3d8a71a27f1436f1784e2a3b390aa5f05927c2eb668bd29d898b2a954d952ba" or
            digest(source / "base/rr_host.py") != "a9246587757c870eeb569c1ae015f228d227cd5250aca1cb313833be8b9d2142"):
        raise ValueError("Gallery 763 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery 763 runtime tree changed")
    report_path = root / "RuntimeKit/Validation/GalleryUnlock763Candidate20261101/verification.json"
    if digest(report_path) != "49a3388f4a73514a22c22c37d899f869c03ad2f394581d8280248eae7dec11a2":
        raise ValueError("Gallery 763 evidence changed")
    report = json.loads(report_path.read_bytes())
    for name, expected in {**report["screenshots"], **report["evidence"]}.items():
        if digest(report_path.parent / name) != expected: raise ValueError("Gallery 763 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == "gallery763-" + phase]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != "79ca192a5125503693081c8e7397d0e81115a2ee5d1858edca8c06da8f773572" for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery 763 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery 763 cold process was not separate")
    rows = [json.loads(line) for line in (report_path.parent / "command.events.ndjson").read_text().splitlines() if line]
    probes = [row for row in rows if row.get("type") == "galleryCommandProbe"]
    if (len([row for row in rows if row.get("type") == "qaPassed" and row.get("failures") == 0 and row.get("sessions") == 3]) != 1 or
            any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows) or
            len(probes) != 3 or {row.get("launchMode") for row in probes} != LAUNCH_MODES or
            any(not row.get("lockedBefore") or not (row.get("nativeRejected") if row.get("launchMode") == "nativeCompatibility" else row.get("unlocked") and row.get("lockedAfter")) for row in probes)):
        raise ValueError("Gallery 763 command checks did not pass")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}



def gallery_seen_763_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen763Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "35296c02545ff1f9c8a90b8f983dc14880fddbb71029ae698b750854ee1ed6fb" or
            digest(source / "base/rr_host.py") != "37d4812691918653801221c31ef7bbc7a1199bc8854508419fa84e38b4f89d29"):
        raise ValueError("Gallery seen 763 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 763 runtime tree changed")
    for directory, expected in (("GallerySeen763Candidate20261101", "25ffe33d15bcc2bfafe8da16ff2a668b3b1a7bc7be2c8e136dc0449e926e5332"), ("GallerySeen763Overlay20261101", "be4496ce5c8da0d2cdfe644957a32f88f747e93584c0488ceadac826c3be4718")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 763 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 763 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (("cold-retry" if phase == "cold" else phase) + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen763-cold-retry" if phase == "cold" else "galleryseen763-warm")]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-7.6.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 763 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 763 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def dialogue_segments_763_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/DialogueSegments763Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
        digest(source / "provenance.json") != "244491288fcdfd774951e43fd3ecb7918059c24ca3a32b0ffafb08dcc96197d1" or
        digest(source / "base/rr_host.py") != "d2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74"):
        raise ValueError("Dialogue segment 763 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Dialogue segment 763 runtime tree changed")
    mac = root / "RuntimeKit/Validation/DialogueSegmentsGroups76320261101/verification.json"
    overlay = root / "RuntimeKit/Validation/DialogueSegments763Overlay20261101"
    if (digest(mac) != "0ff90db79c4df7959779029df558c03c0ac2f82ff4b4bb4dd8be7006d7c09145" or
        digest(overlay / "verification.json") != "997e88ff9d557853fe92c0ebc5e604c95b01e5247818454dbb888a5dafcf6486" or
        digest(overlay / "fixture.rpy") != "1ba04aaf146138b3f0eb5f4cadf0640bbb753640216198e816394cac833ed7f9" or
        json.loads(mac.read_bytes()).get("hostSHA256") != digest(source / "base/rr_host.py")):
        raise ValueError("Dialogue segment 763 evidence changed")
    report = json.loads((overlay / "verification.json").read_bytes())
    if report.get("stageProvenanceSHA256") != digest(source / "provenance.json") or set(report.get("events", {})) != {"warm", "cold"}:
        raise ValueError("Dialogue segment 763 overlay identity changed")
    expected_texts = ["LEGACY FIRST", "LEGACY FIRST{w} LEGACY SECOND", "LEGACY CUSTOM", "LEGACY CUSTOM{w} LEGACY CUSTOM NEXT"]
    processes = []
    for phase, expected in report["events"].items():
        path = overlay / (phase + ".events.ndjson")
        if digest(path) != expected: raise ValueError("Dialogue segment 763 events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
            len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
            any(row.get("engineOverlaySHA256") != report["overlayManifestSHA256"] for row in ready) or
            len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-7.6.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
            len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
            any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Dialogue segment 763 custom-engine sessions did not pass")
        for session in ("overlay-0", "overlay-1"):
            dialogue = [row for row in rows if row.get("type") == "dialogue" and row.get("sessionID") == session]
            sequences = [dialogue[i:i+4] for i in range(len(dialogue)-3) if [row.get("text") for row in dialogue[i:i+4]] == expected_texts]
            if not sequences: raise ValueError("Dialogue segment 763 sequence missing")
            group = sequences[0]
            if (group[0].get("dialogueGroupID") != group[1].get("dialogueGroupID") or group[2].get("dialogueGroupID") != group[3].get("dialogueGroupID") or
                group[0].get("dialogueGroupID") == group[2].get("dialogueGroupID") or len({row.get("interactionID") for row in group}) != 4):
                raise ValueError("Dialogue segment 763 grouping changed")
        native = next(row for row in ready if row.get("launchMode") == "nativeCompatibility")
        if native.get("capabilities", {}).get("dialogue") is not False or any(row.get("type") == "dialogue" and row.get("sessionID") == native.get("sessionID") for row in rows):
            raise ValueError("Native compatibility unexpectedly enabled dialogue")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Dialogue segment 763 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def dialogue_segments_837_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/DialogueSegments837Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
        digest(source / "provenance.json") != "8284441217557a9cfe25417806f322f1858b253dfbf9b19b2feb055be44e1694" or
        digest(source / "base/rr_host.py") != "e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e"):
        raise ValueError("Dialogue segment 837 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Dialogue segment 837 runtime tree changed")
    mac = root / "RuntimeKit/Validation/DialogueSegmentsGroups83720261101/verification.json"
    overlay = root / "RuntimeKit/Validation/DialogueSegments837Overlay20261101"
    if (digest(mac) != "173507ef6c1fdc7fbebb10396aabdec81c1e963c8d4c907dd2e46555fc809cd0" or
        digest(overlay / "verification.json") != "5ddb925c4a5fb3e75326e8e67ab297e05d061542e831695478466b9b9348518b" or
        digest(overlay / "fixture.rpy") != "1ba04aaf146138b3f0eb5f4cadf0640bbb753640216198e816394cac833ed7f9" or
        json.loads(mac.read_bytes()).get("hostSHA256") != digest(source / "base/rr_host.py")):
        raise ValueError("Dialogue segment 837 evidence changed")
    report = json.loads((overlay / "verification.json").read_bytes())
    if report.get("stageProvenanceSHA256") != digest(source / "provenance.json") or set(report.get("events", {})) != {"warm", "cold"}:
        raise ValueError("Dialogue segment 837 overlay identity changed")
    expected_texts = ["LEGACY FIRST", "LEGACY FIRST{w} LEGACY SECOND", "LEGACY CUSTOM", "LEGACY CUSTOM{w} LEGACY CUSTOM NEXT"]
    processes = []
    for phase, expected in report["events"].items():
        path = overlay / (phase + ".events.ndjson")
        if digest(path) != expected: raise ValueError("Dialogue segment 837 events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
            len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
            any(row.get("engineOverlaySHA256") != report["overlayManifestSHA256"] for row in ready) or
            len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.3.7" or row.get("loaded") is not (phase == "cold") for row in probes) or
            len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
            any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Dialogue segment 837 custom-engine sessions did not pass")
        for session in ("overlay-0", "overlay-1"):
            dialogue = [row for row in rows if row.get("type") == "dialogue" and row.get("sessionID") == session]
            sequences = [dialogue[i:i+4] for i in range(len(dialogue)-3) if [row.get("text") for row in dialogue[i:i+4]] == expected_texts]
            if not sequences: raise ValueError("Dialogue segment 837 sequence missing")
            group = sequences[0]
            if (group[0].get("dialogueGroupID") != group[1].get("dialogueGroupID") or group[2].get("dialogueGroupID") != group[3].get("dialogueGroupID") or
                group[0].get("dialogueGroupID") == group[2].get("dialogueGroupID") or len({row.get("interactionID") for row in group}) != 4):
                raise ValueError("Dialogue segment 837 grouping changed")
        native = next(row for row in ready if row.get("launchMode") == "nativeCompatibility")
        if native.get("capabilities", {}).get("dialogue") is not False or any(row.get("type") == "dialogue" and row.get("sessionID") == native.get("sessionID") for row in rows):
            raise ValueError("Native compatibility unexpectedly enabled dialogue")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Dialogue segment 837 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_837_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen837Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "ec6396c9b55f9d7f9c06ad14744845cc9f37c5ba45f2008d51ccc1fb38f5412e" or
            digest(source / "base/rr_host.py") != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5"):
        raise ValueError("Gallery seen 837 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 837 runtime tree changed")
    for directory, expected in (("GallerySeen837Candidate20261101", "62b4e9f885c113be898532426f75d942eb3e3fb11ca6ef501dff43d644ce83cc"), ("GallerySeen837Overlay20261101", "175170e80ba6508616c03407dd4caea9ffce64a07420347fa77f4e2728a32fe4")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 837 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 837 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen837-warm-retry" if phase == "warm" else "galleryseen837-cold")]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.3.7" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 837 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 837 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_841_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen841Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "85eda498a8e2c4f50e1044b32cd55185ee8b383baa977c1e44d8833f0ad2b0f7" or
            digest(source / "base/rr_host.py") != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5"):
        raise ValueError("Gallery seen 841 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 841 runtime tree changed")
    for directory, expected in (("GallerySeen841Candidate20261101", "b9cfafae338e49739c5062c9ff0daa91b0251bb3e3203a93bcb36767f75b2075"), ("GallerySeen841Overlay20261101", "96780090e1998ee7c047d2677e34dbe09f59e3bd923a1e2c30e3232ea0f202b8")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 841 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 841 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen841-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.4.1" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 841 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 841 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_823_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen823Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "412611dcf0a02731c062975a1aa77499e2d94b143e14ae36a7562fcbfa94334d" or
            digest(source / "base/rr_host.py") != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5"):
        raise ValueError("Gallery seen 823 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 823 runtime tree changed")
    for directory, expected in (("GallerySeen823Candidate20261101", "ce5d4fe9a1691c786e810d69cfe1c23a413f8e35a73bb6343342a46f4b6e7fa8"), ("GallerySeen823Overlay20261101", "a0ff11167918c50a2e4ffa71b23bfad3a29700b3bad8cd77c7cd91249d26a267")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 823 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 823 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen823-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.2.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 823 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 823 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_787_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen787Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "df92a34ac44478ce547f28bbe18fc1224a0a49b69a88619b8fb5d244bd77d68f" or
            digest(source / "base/rr_host.py") != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5"):
        raise ValueError("Gallery seen 787 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 787 runtime tree changed")
    for directory, expected in (("GallerySeen787Candidate20261101", "9cfdf8caee9475c913842f0a9221489dcb4112cd81cb8a4afcc250d7e1bf3a38"), ("GallerySeen787Overlay20261101", "037dd09aa91a2388c4d39224b86489c070874f6276c4235bae47174b8290980a")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 787 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 787 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen787-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-7.8.7" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 787 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 787 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_773_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen773Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "94353c9105f1f94b8d75f67c32e57305bc379c14db740ec22726222f134f3856" or
            digest(source / "base/rr_host.py") != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5"):
        raise ValueError("Gallery seen 773 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 773 runtime tree changed")
    for directory, expected in (("GallerySeen773Candidate20261101", "4efa5bc4c36d0d80ae94ed085339e859f1cdc1d44a1152edb4e5c749c7dbffec"), ("GallerySeen773Overlay20261101", "173fb5fe74572299ef7c2bb38926e55d684fecfd0ab93b556353cf80a6e8c40b")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 773 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 773 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen773-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-7.7.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 773 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 773 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_813_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen813Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "3ebaf3056eb6cf0f5d8b08ca322ab5c59efad0cd03e0c4163d495921247e5ce4" or
            digest(source / "base/rr_host.py") != "37d4812691918653801221c31ef7bbc7a1199bc8854508419fa84e38b4f89d29"):
        raise ValueError("Gallery seen 813 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 813 runtime tree changed")
    for directory, expected in (("GallerySeen813Candidate20261101", "2d68bda2411f53f233e1a20beb9034e82fb55a7cdb97feccecac165c14e8972a"), ("GallerySeen813Overlay20261101", "a5e089f8796abb53b55cd2cf5e0030e8fc5790000e548e2fcd0ce46d9515726d")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 813 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 813 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen813-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.1.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 813 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 813 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_803_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen803Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "ed4cbc24e795e74ed682cd315cfc49f5b4a80c937b6fad444bfbc817021ef6c7" or
            digest(source / "base/rr_host.py") != "37d4812691918653801221c31ef7bbc7a1199bc8854508419fa84e38b4f89d29"):
        raise ValueError("Gallery seen 803 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 803 runtime tree changed")
    for directory, expected in (("GallerySeen803Candidate20261101", "f0242de94f9b7a28da8173d107cf085ea18b07f1ccebcba1db1d0028fa1c7f0d"), ("GallerySeen803Overlay20261101", "4612c4cdaec176815147f7a16d6b8fa4f7e0f52b3c0eedc3d05ca1c7074d754e")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 803 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 803 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen803-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.0.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 803 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 803 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_753_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen753Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "80b6ec8546427957a49122ac4443ed11aabd76702fb8a4f11b0f9379ce8383b2" or
            digest(source / "base/rr_host.py") != "37d4812691918653801221c31ef7bbc7a1199bc8854508419fa84e38b4f89d29"):
        raise ValueError("Gallery seen 753 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 753 runtime tree changed")
    for directory, expected in (("GallerySeen753Candidate20261101", "74f5b72ac744cb2234cbf3f7cfcda38473fbd76886185fe2399537d115a28e36"), ("GallerySeen753Overlay20261101", "5a3a0422d85dde88bf6f3f45d01664e99297d657ff0e67c65381962e21022179")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 753 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 753 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen753-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-7.5.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 753 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 753 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def gallery_seen_7411_update(root, source, previous):
    prior = root / "RuntimeKit/Validation/GallerySeen7411Stage20261101/previous"
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
            digest(source / "provenance.json") != "bc84b977304e235bd803cc119eaab0250a97661a3f1e8c8b6fc6f47203cfc63d" or
            digest(source / "base/rr_host.py") != "37d4812691918653801221c31ef7bbc7a1199bc8854508419fa84e38b4f89d29"):
        raise ValueError("Gallery seen 7411 resource identity changed")
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 7411 runtime tree changed")
    for directory, expected in (("GallerySeen7411Candidate20261101", "663a4492c0a5b73cd96125ba3cb1bd7df254d9b799c0b5d8b5801c36637fbde4"), ("GallerySeen7411Overlay20261101", "939dd546dc2e6a73286a94eb4fa943575f86869af97b26dead1983af2cc050a0")):
        report_path = root / "RuntimeKit/Validation" / directory / "verification.json"
        if digest(report_path) != expected: raise ValueError("Gallery seen 7411 evidence changed")
        report = json.loads(report_path.read_bytes())
        for name, expected_hash in report["evidence"].items():
            if digest(report_path.parent / name) != expected_hash: raise ValueError("Gallery seen 7411 evidence file changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (report_path.parent / (phase + ".events.ndjson")).read_text().splitlines() if line]
        rows = [row for row in rows if row.get("runID") == ("galleryseen7411-" + phase)]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["manifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-7.4.11" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 7411 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 7411 cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


DIALOGUE_SEGMENTS_REMAINING = {'7.4.11': {'provenanceSHA256': 'eae470c06319a755f041668eb9666b28558afb8a8dccda73d2c727412d40f8f8', 'hostSHA256': 'd2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74'}, '7.5.3': {'provenanceSHA256': '1cb7611263f0becfac7f33eacb8800d3fd42ddec6c06a22b9a270b15af8d6f14', 'hostSHA256': 'd2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74'}, '7.7.3': {'provenanceSHA256': '2c5ff6a5c1daa6cee3530e8c43756516d52ed892554e854d314a34b4b2372940', 'hostSHA256': 'e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e'}, '7.8.7': {'provenanceSHA256': '6c47cec3d5e75d9cc243efad2191d203199fe463d15b62f894e2a337dedbaf9b', 'hostSHA256': 'e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e'}, '8.0.3': {'provenanceSHA256': '5ea142430aa090c98150e92bb4af7410981c3f4421cc9bf199447eec4428513c', 'hostSHA256': 'd2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74'}, '8.1.3': {'provenanceSHA256': '3107d70b2437b47d4036928ed33f8721f60a5979c3c3c5aee3214b7cce360574', 'hostSHA256': 'd2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74'}, '8.2.3': {'provenanceSHA256': 'e7ee48447e3051fcaeb54ea3535c5ec2184048b37796f6cabc9e18c74bdd6a89', 'hostSHA256': 'e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e'}, '8.4.1': {'provenanceSHA256': 'f87ffe2bce079c1c9ddbfc9bfad47e669d6d9a0052681f8b874d635843f3dc83', 'hostSHA256': 'e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e'}}
DIALOGUE_SEGMENTS_REMAINING_EVIDENCE = "55d80cd1536284a642945d31ca14fcedf0b1ae74ccf1101ae581df74c8329146"


def dialogue_segments_remaining_update(root, source, previous, version):
    identity = DIALOGUE_SEGMENTS_REMAINING[version]
    prior = root / ("RuntimeKit/Validation/DialogueSegments" + version.replace(".", "") + "Stage20261101/previous")
    if (digest(prior / "provenance.json") != previous["provenanceSHA256"] or
        digest(source / "provenance.json") != identity["provenanceSHA256"] or
        digest(source / "base/rr_host.py") != identity["hostSHA256"]):
        raise ValueError("Dialogue segment remaining resource identity changed: " + version)
    before, after = prior / "base", source / "base"
    if tree_digest(before) != previous["base"] or tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Dialogue segment remaining runtime tree changed: " + version)
    evidence = root / "RuntimeKit/Validation/DialogueSegmentsRemainingOverlay20261101"
    if digest(evidence / "verification.json") != DIALOGUE_SEGMENTS_REMAINING_EVIDENCE:
        raise ValueError("Dialogue segment remaining evidence changed")
    report = json.loads((evidence / "verification.json").read_bytes())
    if (report.get("status") != "passed" or set(report.get("versions", {})) != set(DIALOGUE_SEGMENTS_REMAINING) or
        report["versions"][version].get("runtimeProvenanceSHA256") != identity["provenanceSHA256"] or
        digest(evidence / "fixture.rpy") != report.get("fixtureSHA256") or digest(evidence / "CustomHost.m") != report.get("smokeHostSHA256") or
        set(report.get("events", {})) != {"warm", "cold"}):
        raise ValueError("Dialogue segment remaining evidence identity changed")
    expected_texts = ["LEGACY FIRST", "LEGACY FIRST{w} LEGACY SECOND", "LEGACY CUSTOM", "LEGACY CUSTOM{w} LEGACY CUSTOM NEXT"]
    ordered = ["7.4.11", "7.5.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.4.1"]
    processes = []
    for phase, wanted in report["events"].items():
        path = evidence / (phase + ".events.ndjson")
        if digest(path) != wanted: raise ValueError("Dialogue segment remaining events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 24 or len(pins) != 24 or
            any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
            any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Dialogue segment remaining batch failed")
        for index, mode in enumerate(("enhanced", "minimal", "nativeCompatibility")):
            session = "overlay-" + str(ordered.index(version) * 3 + index)
            selected = [row for row in rows if row.get("sessionID") == session]
            ready = [row for row in selected if row.get("type") == "ready"]
            probes = [row for row in selected if row.get("type") == "engineOverlayProbe"]
            if (len(ready) != 1 or ready[0].get("launchMode") != mode or ready[0].get("engineOverlaySHA256") != report["versions"][version]["manifestSHA256"] or
                len(probes) != 1 or probes[0].get("marker") != "ENGINE-QA-" + version or probes[0].get("value") != 73 or probes[0].get("loaded") is not (phase == "cold")):
                raise ValueError("Dialogue segment remaining session failed: " + version)
            dialogue = [row for row in selected if row.get("type") == "dialogue"]
            if mode == "nativeCompatibility":
                if ready[0].get("capabilities", {}).get("dialogue") is not False or dialogue: raise ValueError("Native compatibility unexpectedly enabled dialogue")
                continue
            matches = [dialogue[i:i+4] for i in range(len(dialogue)-3) if [row.get("text") for row in dialogue[i:i+4]] == expected_texts]
            if not matches: raise ValueError("Dialogue segment remaining sequence missing: " + version)
            group = matches[0]
            if (group[0].get("dialogueGroupID") != group[1].get("dialogueGroupID") or group[2].get("dialogueGroupID") != group[3].get("dialogueGroupID") or
                group[0].get("dialogueGroupID") == group[2].get("dialogueGroupID") or len({row.get("interactionID") for row in group}) != 4):
                raise ValueError("Dialogue segment remaining grouping changed: " + version)
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Dialogue segment remaining cold process was not separate")
    return {**previous, "provenanceSHA256": digest(source / "provenance.json"), "base": tree_digest(after)}


def verify_expanded_version(root, version, profile, built_app=None, platform=None):
    initial = version in INITIAL_EXPANDED_VERSIONS
    certificate = root / ("RuntimeKit/Patches/overlay-capability-753-803.json" if initial else
                          "RuntimeKit/Patches/overlay-capability-remaining.json")
    certificate_hash = EXPANDED_CERTIFICATE_SHA256 if initial else REMAINING_CERTIFICATE_SHA256
    if digest(certificate) != certificate_hash:
        raise ValueError("Expanded engine overlay certificate changed")
    document = json.loads(certificate.read_bytes())
    if document.get("schemaVersion") != 1 or version not in EXPANDED_VERSIONS:
        raise ValueError("Unqualified expanded runtime")
    evidence_root = root / ("RuntimeKit/Validation/Overlay753803ExpansionQA" if initial else
                            "RuntimeKit/Validation/OverlayRemainingExpansionQA")
    expected_names = ({"fixed-warm.events.ndjson", "fixed-cold.events.ndjson", "verification.json"} if initial else
                      {"warm.events.ndjson", "cold.events.ndjson", "verification.json"})
    if set(document["evidence"]) != expected_names:
        raise ValueError("Expanded engine overlay evidence list changed")
    for name, expected in document["evidence"].items():
        if digest(evidence_root / name) != expected:
            raise ValueError("Expanded engine overlay evidence changed")
    expected = document["runtimes"][version]
    suffix = version.replace(".", "")
    source = root / "RuntimeKit/Artifacts" / ("RenPy" + suffix + ".bundle")
    actual_profile = json.loads((source / "runtime-profile.json").read_bytes())
    if json.dumps(profile, sort_keys=True) != json.dumps(actual_profile, sort_keys=True):
        raise ValueError("Expanded runtime profile identity changed")
    translation_update = profile.get("advancedTranslationSchemaVersion") == 1
    if translation_update:
        if __package__:
            from .advanced_translation_update import verify as verify_translation_update
        else:
            from advanced_translation_update import verify as verify_translation_update
        source, profile = verify_translation_update(root, version, source)
    dialogue_source = None
    if version in DIALOGUE_SEGMENTS_REMAINING and digest(source / "provenance.json") == DIALOGUE_SEGMENTS_REMAINING[version]["provenanceSHA256"]:
        dialogue_source = source
        source = root / ("RuntimeKit/Validation/DialogueSegments" + suffix + "Stage20261101/previous")
    if version == "7.6.3" and digest(source / "provenance.json") != expected["provenanceSHA256"]:
        if digest(source / "provenance.json") == "244491288fcdfd774951e43fd3ecb7918059c24ca3a32b0ffafb08dcc96197d1":
            prior_menu = root / "RuntimeKit/Validation/DeferredLegacyOverlay20261031/stage/RenPy763.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation763Overlay20261101/previous/RenPy763.bundle"
            prior_inline = root / "RuntimeKit/Validation/GalleryUnlock763Stage20261101/previous"
            prior_gallery = root / "RuntimeKit/Validation/GallerySeen763Stage20261101/previous"
            prior_seen = root / "RuntimeKit/Validation/DialogueSegments763Stage20261101/previous"
            expected = legacy_menu_update(root, prior_menu, expected)
            expected = progress_763_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, "7.6.3")
            expected = gallery_763_update(root, prior_gallery, expected)
            expected = gallery_seen_763_update(root, prior_seen, expected)
            expected = dialogue_segments_763_update(root, source, expected)
        elif digest(source / "provenance.json") == "35296c02545ff1f9c8a90b8f983dc14880fddbb71029ae698b750854ee1ed6fb":
            prior_menu = root / "RuntimeKit/Validation/DeferredLegacyOverlay20261031/stage/RenPy763.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation763Overlay20261101/previous/RenPy763.bundle"
            prior_inline = root / "RuntimeKit/Validation/GalleryUnlock763Stage20261101/previous"
            prior_gallery = root / "RuntimeKit/Validation/GallerySeen763Stage20261101/previous"
            expected = legacy_menu_update(root, prior_menu, expected)
            expected = progress_763_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, "7.6.3")
            expected = gallery_763_update(root, prior_gallery, expected)
            expected = gallery_seen_763_update(root, source, expected)
        elif digest(source / "provenance.json") == "b3d8a71a27f1436f1784e2a3b390aa5f05927c2eb668bd29d898b2a954d952ba":
            prior_menu = root / "RuntimeKit/Validation/DeferredLegacyOverlay20261031/stage/RenPy763.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation763Overlay20261101/previous/RenPy763.bundle"
            prior_inline = root / "RuntimeKit/Validation/GalleryUnlock763Stage20261101/previous"
            expected = legacy_menu_update(root, prior_menu, expected)
            expected = progress_763_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, "7.6.3")
            expected = gallery_763_update(root, source, expected)
        elif digest(source / "provenance.json") == "e69455f0916d6cd2d59a57f97d4de676f9cbaba88dec44caf2fc3d0b41d6e771":
            prior_menu = root / "RuntimeKit/Validation/DeferredLegacyOverlay20261031/stage/RenPy763.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation763Overlay20261101/previous/RenPy763.bundle"
            expected = legacy_menu_update(root, prior_menu, expected)
            expected = progress_763_update(root, prior_progress, expected)
            expected = inline_update(root, source, expected, "7.6.3")
        elif digest(source / "provenance.json") == "d288578b61edf606ec0c1e79d9ac6de1f5bcf3781aa0c5e434f68e2d7dc8a6e8":
            prior = root / "RuntimeKit/Validation/DeferredLegacyOverlay20261031/stage/RenPy763.bundle"
            expected = legacy_menu_update(root, prior, expected)
            expected = progress_763_update(root, source, expected)
        else:
            expected = legacy_menu_update(root, source, expected)
    if version in ("7.4.11", "8.3.7") and digest(source / "provenance.json") != expected["provenanceSHA256"]:
        if version == "8.3.7" and digest(source / "provenance.json") == "8284441217557a9cfe25417806f322f1858b253dfbf9b19b2feb055be44e1694":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/837/stage/RenPy837.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation837Overlay20261101/previous/RenPy837.bundle"
            prior_inline = root / "RuntimeKit/Validation/TracebackUTF8837Overlay20261101/previous/RenPy837.bundle"
            prior_gallery = root / "RuntimeKit/Validation/GalleryUnlock837Stage20261101/previous"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen837Stage20261101/previous"
            prior_dialogue = root / "RuntimeKit/Validation/DialogueSegments837Stage20261101/previous"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_837_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, version)
            expected = traceback_837_update(root, prior_gallery, prior_inline, expected)
            expected = gallery_837_update(root, prior_seen, expected)
            expected = gallery_seen_837_update(root, prior_dialogue, expected)
            expected = dialogue_segments_837_update(root, source, expected)
        elif version == "8.3.7" and digest(source / "provenance.json") == "ec6396c9b55f9d7f9c06ad14744845cc9f37c5ba45f2008d51ccc1fb38f5412e":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/837/stage/RenPy837.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation837Overlay20261101/previous/RenPy837.bundle"
            prior_inline = root / "RuntimeKit/Validation/TracebackUTF8837Overlay20261101/previous/RenPy837.bundle"
            prior_gallery = root / "RuntimeKit/Validation/GalleryUnlock837Stage20261101/previous"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen837Stage20261101/previous"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_837_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, version)
            expected = traceback_837_update(root, prior_gallery, prior_inline, expected)
            expected = gallery_837_update(root, prior_seen, expected)
            expected = gallery_seen_837_update(root, source, expected)
        elif version == "8.3.7" and digest(source / "provenance.json") == "9b61cc39b0fa18a25948efcc98a6c457d8e718fa25c7e34c60684ad433a1361f":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/837/stage/RenPy837.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation837Overlay20261101/previous/RenPy837.bundle"
            prior_inline = root / "RuntimeKit/Validation/TracebackUTF8837Overlay20261101/previous/RenPy837.bundle"
            prior_gallery = root / "RuntimeKit/Validation/GalleryUnlock837Stage20261101/previous"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_837_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, version)
            expected = traceback_837_update(root, prior_gallery, prior_inline, expected)
            expected = gallery_837_update(root, source, expected)
        elif version == "8.3.7" and digest(source / "provenance.json") == "64bec4acabe6f913e311355f3bf419757cbfc725bb1f3f617cedc10aaa5c379d":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/837/stage/RenPy837.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation837Overlay20261101/previous/RenPy837.bundle"
            prior_inline = root / "RuntimeKit/Validation/TracebackUTF8837Overlay20261101/previous/RenPy837.bundle"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_837_update(root, prior_progress, expected)
            expected = inline_update(root, prior_inline, expected, version)
            expected = traceback_837_update(root, source, prior_inline, expected)
        elif version == "8.3.7" and digest(source / "provenance.json") == "ab22ea655a82a70afbbe7a2aeb50f1461875e61f67ca705ad48f2a606b44ec70":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/837/stage/RenPy837.bundle"
            prior_progress = root / "RuntimeKit/Validation/InlineTranslation837Overlay20261101/previous/RenPy837.bundle"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_837_update(root, prior_progress, expected)
            expected = inline_update(root, source, expected, version)
        elif version == "8.3.7" and digest(source / "provenance.json") == "414ab4d55151662d43ac20cc443633e84e06524e68ae3286b5beb014d7de2947":
            prior = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/837/stage/RenPy837.bundle"
            expected = remaining_menu_update(root, prior, expected, version)
            expected = progress_837_update(root, source, expected)
        elif version == "7.4.11" and digest(source / "provenance.json") == "bc84b977304e235bd803cc119eaab0250a97661a3f1e8c8b6fc6f47203cfc63d":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/7411/stage/RenPy7411.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation7411Overlay20261101/previous/RenPy7411.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen7411Stage20261101/previous"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], MENU_7411_837_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_7411_update(root, source, expected)
        elif version == "7.4.11" and digest(source / "provenance.json") == "8990d27f9ff0e7afc904035cfa076891a16a2625bf7e0d707e5ec73d3e6fc9ca":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/7411/stage/RenPy7411.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation7411Overlay20261101/previous/RenPy7411.bundle"
            expected = remaining_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], MENU_7411_837_CERTIFICATE_SHA256)
            expected = inline_update(root, source, expected, version)
        elif version == "7.4.11" and digest(source / "provenance.json") == PROGRESS_REMAINING[version][1]:
            prior = root / "RuntimeKit/Validation/DeferredMenuRemainingOverlay20261031/7411/stage/RenPy7411.bundle"
            expected = remaining_menu_update(root, prior, expected, version)
            expected = progress_update(root, source, expected, version, PROGRESS_REMAINING[version][0], MENU_7411_837_CERTIFICATE_SHA256)
        else:
            expected = remaining_menu_update(root, source, expected, version)
    if version in SEVEN_MENU_VERSIONS and digest(source / "provenance.json") != expected["provenanceSHA256"]:
        inline_provenance = {"8.4.1": "5e221b3908c4bd84add15f2598ea2258f41b2948a6127ebb416ffa1f758fd380",
                             "8.2.3": "ba896677341b5df6732de9ac65d71476ce2fae5d9cb8f3828901d59ce6a4e6fe",
                             "7.8.7": "d45716961b27eef651865bc57bd4ea065301a5a536261357af7c44d8edace8ba",
                             "7.7.3": "3a76fbbf9b7a5a0a59f63e3e98399443d278df7f059f8f7d1a588e4515067d94",
                             "8.1.3": "e5a176eac15e6c6539132e2e7b4415b8783a10d793ff0716550f6ec27e655a45",
                             "8.0.3": "14c104f8ff053316ae0fc461e36b9dc8661d66ff5f571fd829da66d1b28b41e8",
                             "7.5.3": "755271f5497057aed70259a42a99c609859056b6c93d04df64a8a3e12cdeeaa7"}
        if version == "7.5.3" and digest(source / "provenance.json") == "80b6ec8546427957a49122ac4443ed11aabd76702fb8a4f11b0f9379ce8383b2":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/753/stage/RenPy753.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation753Overlay20261101/previous/RenPy753.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen753Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_753_update(root, source, expected)
        elif version == "8.0.3" and digest(source / "provenance.json") == "ed4cbc24e795e74ed682cd315cfc49f5b4a80c937b6fad444bfbc817021ef6c7":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/803/stage/RenPy803.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation803Overlay20261101/previous/RenPy803.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen803Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_803_update(root, source, expected)
        elif version == "8.1.3" and digest(source / "provenance.json") == "3ebaf3056eb6cf0f5d8b08ca322ab5c59efad0cd03e0c4163d495921247e5ce4":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/813/stage/RenPy813.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation813Overlay20261101/previous/RenPy813.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen813Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_813_update(root, source, expected)
        elif version == "7.7.3" and digest(source / "provenance.json") == "94353c9105f1f94b8d75f67c32e57305bc379c14db740ec22726222f134f3856":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/773/stage/RenPy773.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation773Overlay20261101/previous/RenPy773.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen773Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_773_update(root, source, expected)
        elif version == "7.8.7" and digest(source / "provenance.json") == "df92a34ac44478ce547f28bbe18fc1224a0a49b69a88619b8fb5d244bd77d68f":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/787/stage/RenPy787.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation787Overlay20261101/previous/RenPy787.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen787Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_787_update(root, source, expected)
        elif version == "8.2.3" and digest(source / "provenance.json") == "412611dcf0a02731c062975a1aa77499e2d94b143e14ae36a7562fcbfa94334d":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/823/stage/RenPy823.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation823Overlay20261101/previous/RenPy823.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen823Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_823_update(root, source, expected)
        elif version == "8.4.1" and digest(source / "provenance.json") == "85eda498a8e2c4f50e1044b32cd55185ee8b383baa977c1e44d8833f0ad2b0f7":
            prior_menu = root / "RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/841/stage/RenPy841.bundle"
            prior_inline = root / "RuntimeKit/Validation/InlineTranslation841Overlay20261101/previous/RenPy841.bundle"
            prior_seen = root / "RuntimeKit/Validation/GallerySeen841Stage20261101/previous"
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, prior_seen, expected, version)
            expected = gallery_seen_841_update(root, source, expected)
        elif version in inline_provenance and digest(source / "provenance.json") == inline_provenance[version]:
            prior_menu = root / ("RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/" + suffix + "/stage/RenPy" + suffix + ".bundle")
            prior_inline = root / ("RuntimeKit/Validation/InlineTranslation" + suffix + "Overlay20261101/previous/RenPy" + suffix + ".bundle")
            expected = seven_menu_update(root, prior_menu, expected, version)
            expected = progress_update(root, prior_inline, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
            expected = inline_update(root, source, expected, version)
        elif digest(source / "provenance.json") == PROGRESS_REMAINING[version][1]:
            prior = root / ("RuntimeKit/Validation/DeferredMenuSevenOverlay20261031/" + suffix + "/stage/RenPy" + suffix + ".bundle")
            expected = seven_menu_update(root, prior, expected, version)
            expected = progress_update(root, source, expected, version, PROGRESS_REMAINING[version][0], SEVEN_MENU_CERTIFICATE_SHA256)
        else:
            expected = seven_menu_update(root, source, expected, version)
    if dialogue_source is not None:
        expected = dialogue_segments_remaining_update(root, dialogue_source, expected, version)
        source = dialogue_source
    if profile_content(profile) != expected["profileContentSHA256"] or \
            digest(source / "provenance.json") != expected["provenanceSHA256"] or \
            tree_digest(source / "base") != expected["base"]:
        raise ValueError("Expanded runtime resource identity changed")
    for target in ("iphonesimulator", "iphoneos"):
        name = "RRRuntime" + suffix
        binary = framework_slice(root, name, target) / name
        if packaged_source_identity(root, binary, target) != expected["native"][target]:
            raise ValueError("Expanded runtime native identity changed")
    if built_app is not None:
        bundle = built_app / ("RenPy" + suffix + ".bundle")
        built_profile = json.loads((bundle / "runtime-profile.json").read_bytes())
        if translation_update:
            verify_translation_update(root, version, bundle)
        elif built_profile != profile or digest(bundle / "provenance.json") != expected["provenanceSHA256"] or \
                tree_digest(bundle / "base") != expected["base"]:
            raise ValueError("Built expanded runtime resources differ")
        name = "RRRuntime" + suffix
        if image_identity(root, built_app / "Frameworks" / (name + ".framework") / name) != expected["native"][platform]:
            raise ValueError("Built expanded runtime image differs")


def check_built_app(root, contract, app, platform, configuration):
    """Never trust the current source flag as proof of what Xcode already copied."""
    source_path = root / "RuntimeKit/Artifacts/RenPy853.bundle/runtime-profile.json"
    built_path = app / "RenPy853.bundle/runtime-profile.json"
    digest(source_path)
    digest(built_path)
    source = json.loads(source_path.read_bytes())
    built = json.loads(built_path.read_bytes())
    if ("engineOverlaySchemaVersion" in source) != ("engineOverlaySchemaVersion" in built) or \
            source.get("engineOverlaySchemaVersion") != built.get("engineOverlaySchemaVersion"):
        raise ValueError("Built and source capability flags disagree")
    verify_built_app(root, contract, app, platform, configuration)
    if __package__:
        from .spark_profile_guard import VERSIONS as additional_versions, verify as verify_additional_versions
        from .nightly_profile_guard import VERSIONS as nightly_versions, verify as verify_nightly_versions
    else:
        from spark_profile_guard import VERSIONS as additional_versions, verify as verify_additional_versions
        from nightly_profile_guard import VERSIONS as nightly_versions, verify as verify_nightly_versions
    catalog = json.loads((root / "RuntimeKit/Artifacts/runtime-catalog.json").read_bytes())
    entries = {p["runtimeID"]: p for p in catalog["profiles"]}
    if additional_versions.intersection(entries):
        verify_additional_versions(root, entries, built_app=app, platform=platform)
    if nightly_versions.intersection(entries):
        verify_nightly_versions(root, entries, built_app=app, platform=platform)
    for version in EXPANDED_VERSIONS:
        path = root / "RuntimeKit/Artifacts" / ("RenPy" + version.replace(".", "") + ".bundle/runtime-profile.json")
        profile = json.loads(path.read_bytes())
        if profile.get("engineOverlaySchemaVersion") == 1:
            verify_expanded_version(root, version, profile, built_app=app, platform=platform)


def check_traceback_853_update(root, bundle):
    """Pin the narrow 8.5.3 source update to its prior tree and simulator evidence."""
    provenance_hash = digest(bundle / "provenance.json")
    if provenance_hash != "efd7f9dc9858b9e972caeeef5042f4feb730995357855a8bd36ed112c7285b99":
        return
    prior = root / "RuntimeKit/Validation/TracebackUTF8Overlay20261101/previous/RenPy853.bundle"
    if (digest(prior / "provenance.json") != "8818afc70ac18ddc72ca4df5338eba17ab124c76b91b05323ee13c36e6696a58" or
            digest(prior / "base/renpy/error.py") != "7d1c0c77c40ad8fae8a7d4833891a237b541a71a32716a676a071cbf6a5fbf6b" or
            digest(prior / "base/renpy/error.pyc") != "3a090dca6d3ee7ce14328686d6e6fd99d00e001902e0df5d497245eaccec45a1" or
            digest(bundle / "base/renpy/error.py") != "daa5e4c16e5f659386d8a3a118cb741b02024ed8423d4e3c63c0f00bad7efb82" or
            (bundle / "base/renpy/error.pyc").exists()):
        raise ValueError("Traceback UTF-8 resource identity changed")
    excluded = {"renpy/error.py", "renpy/error.pyc"}
    before, after = prior / "base", bundle / "base"
    if tree_digest(before, lambda p: p.relative_to(before).as_posix() not in excluded) != tree_digest(after, lambda p: p.relative_to(after).as_posix() not in excluded):
        raise ValueError("Traceback UTF-8 resource tree changed")
    candidate = root / "RuntimeKit/Validation/TracebackUTF8Candidate20261101/verification.json"
    overlay = root / "RuntimeKit/Validation/TracebackUTF8Overlay20261101/verification.json"
    if (digest(candidate) != "2ac6998f3bb5eb422ad8773d3f58c4dd3ec41beadb52e7d70821bb3bf816c6b0" or
            digest(overlay) != "66351d6385d296bc181010c47ffab5538682ff72087239d0b47d017c64905f70"):
        raise ValueError("Traceback UTF-8 evidence changed")
    ui = json.loads(candidate.read_bytes())
    if digest(candidate.parent / "traceback.txt") != ui["tracebackSHA256"] or digest(candidate.parent / "history.png") != ui["screenshotSHA256"] or digest(candidate.parent / "encoding-probe.json") != ui["encodingProbeSHA256"]:
        raise ValueError("Traceback UTF-8 UI evidence changed")
    report = json.loads(overlay.read_bytes())
    if report.get("stageProvenanceSHA256") != provenance_hash or set(report.get("events", {})) != {"warm", "cold"}:
        raise ValueError("Traceback UTF-8 overlay evidence identity changed")
    processes = []
    for phase, expected in report["events"].items():
        path = overlay.parent / (phase + ".events.ndjson")
        if digest(path) != expected: raise ValueError("Traceback UTF-8 overlay events changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report.get("overlayManifestSHA256") for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.5.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
                any(row.get("type") in ("qaFailed", "qaFailure", "commandRejected") for row in rows)):
            raise ValueError("Traceback UTF-8 overlay sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Traceback UTF-8 cold run did not use a new process")


def check_gallery_853_update(root, bundle):
    if digest(bundle / "provenance.json") != "0a4006e8f89d8a01f0926d4f2364ce84655dddc6d363376bde9b2717fc89087b":
        raise ValueError("Gallery unlock runtime provenance changed")
    prior = root / "RuntimeKit/Validation/GalleryUnlock853Stage20261101/previous"
    if digest(prior / "provenance.json") != "efd7f9dc9858b9e972caeeef5042f4feb730995357855a8bd36ed112c7285b99":
        raise ValueError("Gallery unlock previous runtime identity changed")
    check_traceback_853_update(root, prior)
    if digest(bundle / "base/rr_host.py") != "9bc522b57781ed48596b4154dc6810a941d1f622e60d89eaf4c7ba5f630614ca":
        raise ValueError("Gallery unlock host changed")
    before, after = prior / "base", bundle / "base"
    if tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery unlock runtime tree changed")
    ui = root / "RuntimeKit/Validation/GalleryUnlockExact85320261101/verification.json"
    overlay = root / "RuntimeKit/Validation/GalleryUnlock853Overlay20261101/verification.json"
    if digest(ui) != "3fa3ba6e5331ae97a7e4f5cebe3de9049de3681085d648fa959df1283e8d4b42" or digest(overlay) != "817187282f7d21df74b3219de1f55658266bc1a59d9a31c36486c82b694772ee":
        raise ValueError("Gallery unlock evidence changed")
    for name, expected in json.loads(ui.read_bytes())["screenshots"].items():
        if digest(ui.parent / name) != expected: raise ValueError("Gallery unlock screenshot changed")
    report = json.loads(overlay.read_bytes())
    processes = []
    for phase, expected in report["events"].items():
        path = overlay.parent / (phase + ".events.ndjson")
        if digest(path) != expected: raise ValueError("Gallery unlock overlay evidence changed")
        rows = [row for line in path.read_text().splitlines() if line
                for row in [json.loads(line)] if row.get("runID") == "gallery853-" + phase]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["overlayManifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailed", "qaFailure", "commandRejected") for row in rows)):
            raise ValueError("Gallery unlock overlay sessions did not pass")
        processes.append(passed[0].get("processID"))
    if set(report["events"]) != {"warm", "cold"} or None in processes or len(set(processes)) != 2:
        raise ValueError("Gallery unlock cold run did not use a new process")


def check_gallery_seen_853_update(root, bundle):
    prior = root / "RuntimeKit/Validation/GallerySeen853Stage20261101/previous"
    check_gallery_853_update(root, prior)
    if (digest(bundle / "provenance.json") != "26b187d844b79ef9c2c5f91c5cce702188735b1fbc41239be41770133150f3bf" or
            digest(bundle / "base/rr_host.py") != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5"):
        raise ValueError("Gallery seen 853 resource identity changed")
    before, after = prior / "base", bundle / "base"
    if tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Gallery seen 853 runtime tree changed")
    evidence = root / "RuntimeKit/Validation/GallerySeenCandidate20261101/verification.json"
    overlay = root / "RuntimeKit/Validation/GallerySeen853Overlay20261101/verification.json"
    if digest(evidence) != "940a77792c93e9557b5af618d4884d8ba21c4640f15365006f373910b44b6ad3" or digest(overlay) != "841b3a5407c96ceada2d65b9dee7e0d050701bd89d2e47802d195b574f48ef00":
        raise ValueError("Gallery seen 853 evidence changed")
    for name, expected in json.loads(evidence.read_bytes())["evidence"].items():
        if digest(evidence.parent / name) != expected: raise ValueError("Gallery seen 853 evidence file changed")
    report = json.loads(overlay.read_bytes())
    if report.get("stageProvenanceSHA256") != digest(bundle / "provenance.json") or set(report.get("events", {})) != {"warm", "cold"}:
        raise ValueError("Gallery seen 853 event identity changed")
    processes = []
    for phase, expected in report["events"].items():
        path = overlay.parent / (phase + ".events.ndjson")
        if digest(path) != expected: raise ValueError("Gallery seen 853 events changed")
        rows = [row for line in path.read_text().splitlines() if line for row in [json.loads(line)] if row.get("runID") == "galleryseen853-" + phase]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
                len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
                any(row.get("engineOverlaySHA256") != report["overlayManifestSHA256"] for row in ready) or
                len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.5.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
                any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Gallery seen 853 engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2: raise ValueError("Gallery seen 853 cold process was not separate")


def check_dialogue_segments_853_update(root, bundle):
    previous = root / "RuntimeKit/Validation/DialogueSegments853Stage20261101/previous"
    check_gallery_seen_853_update(root, previous)
    if (digest(bundle / "provenance.json") != "ec94bce6c9d46ae48c9c662c9a38890fef91c7eff04b917ccdca3189a24fb7d0" or
            digest(bundle / "base/rr_host.py") != "e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e"):
        raise ValueError("Dialogue segment 853 resource identity changed")
    before, after = previous / "base", bundle / "base"
    if tree_digest(before, lambda p: p.relative_to(before).as_posix() != "rr_host.py") != tree_digest(after, lambda p: p.relative_to(after).as_posix() != "rr_host.py"):
        raise ValueError("Dialogue segment 853 runtime tree changed")
    ios = root / "RuntimeKit/Validation/DialogueGroupsIOS85320261101"
    mac = root / "RuntimeKit/Validation/DialogueSegmentsGroups85320261101/verification.json"
    overlay = root / "RuntimeKit/Validation/DialogueSegments853Overlay20261101"
    if (digest(ios / "verification.json") != "3c73e2f5cad782ae5d32e535902a0133326848074afbf8be865bce95c96fe891" or
        digest(ios / "events.json") != "70d92caeb118ec4f50d3af79022251cf3362ed29c0300f414bd3dfc12f4ae2d3" or
        digest(ios / "xcode.log") != "4610551c16db82c3dfb22638a3a3fbe30dca9fc17247f361b76bc1717e04f742" or
        digest(mac) != "3b26e85a00591c74eef3ab57c928e6ccdfc7e8a6ea4db47812cac59e3211c284" or
        digest(overlay / "verification.json") != "00867db3d84ab3960eb932c4802d17a9a29fdc5afe7d7e9decf6d63adb064810"):
        raise ValueError("Dialogue segment 853 qualification evidence changed")
    if (json.loads(ios.joinpath("verification.json").read_bytes()).get("candidateSHA256") != digest(bundle / "base/rr_host.py") or
        json.loads(mac.read_bytes()).get("hostSHA256") != digest(bundle / "base/rr_host.py")):
        raise ValueError("Dialogue segment evidence is for another host")
    report = json.loads((overlay / "verification.json").read_bytes())
    if report.get("stageProvenanceSHA256") != digest(bundle / "provenance.json") or set(report.get("events", {})) != {"warm", "cold"}:
        raise ValueError("Dialogue segment overlay identity changed")
    processes = []
    for phase, expected in report["events"].items():
        path = overlay / (phase + ".events.ndjson")
        if digest(path) != expected: raise ValueError("Dialogue segment overlay event evidence changed")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        passed = [row for row in rows if row.get("type") == "qaPassed"]
        ready = [row for row in rows if row.get("type") == "ready"]
        probes = [row for row in rows if row.get("type") == "engineOverlayProbe"]
        pins = [row for row in rows if row.get("type") == "nativeEnginePinProbe"]
        if (len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 3 or
            len(ready) != 3 or {row.get("launchMode") for row in ready} != LAUNCH_MODES or
            any(row.get("engineOverlaySHA256") != report["overlayManifestSHA256"] for row in ready) or
            len(probes) != 3 or any(row.get("value") != 73 or row.get("marker") != "ENGINE-QA-8.5.3" or row.get("loaded") is not (phase == "cold") for row in probes) or
            len(pins) != 3 or any(not (row.get("sameAccepted") and row.get("stockRejected") and row.get("otherDigestRejected")) for row in pins) or
            any(row.get("type") in ("qaFailure", "qaFailed", "commandRejected") for row in rows)):
            raise ValueError("Dialogue segment custom-engine sessions did not pass")
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Dialogue segment cold process was not separate")


def check(root, contract):
    catalog_path = root / "RuntimeKit/Artifacts/runtime-catalog.json"
    digest(catalog_path)
    catalog = json.loads(catalog_path.read_bytes())
    profiles = catalog.get("profiles")
    if __package__:
        from .spark_profile_guard import VERSIONS as additional_versions, verify as verify_additional_versions
        from .nightly_profile_guard import VERSIONS as nightly_versions, verify as verify_nightly_versions
    else:
        from spark_profile_guard import VERSIONS as additional_versions, verify as verify_additional_versions
        from nightly_profile_guard import VERSIONS as nightly_versions, verify as verify_nightly_versions
    allowed_sets = (set(VERSIONS), set(VERSIONS) | additional_versions, set(VERSIONS) | additional_versions | nightly_versions)
    if not isinstance(profiles, list) or len(profiles) not in tuple(len(allowed) for allowed in allowed_sets):
        raise ValueError("Unexpected runtime catalog")
    entries = {p.get("runtimeID"): p for p in profiles}
    if set(entries) not in allowed_sets:
        raise ValueError("Unexpected runtime catalog identities")
    if additional_versions.intersection(entries):
        verify_additional_versions(root, entries)
    if nightly_versions.intersection(entries):
        verify_nightly_versions(root, entries)
    for version in VERSIONS:
        profile_path = root / "RuntimeKit/Artifacts" / ("RenPy" + version.replace(".", "") + ".bundle/runtime-profile.json")
        digest(profile_path)
        profile = json.loads(profile_path.read_bytes())
        if profile.get("runtimeID") != version:
            raise ValueError("Runtime profile identity mismatch: " + version)
        if any(key not in entries[version] or entries[version][key] != value for key, value in profile.items()):
            raise ValueError("Runtime profile and catalog disagree: " + version)
        flag = profile.get("engineOverlaySchemaVersion")
        if "engineOverlaySchemaVersion" in profile and (version not in EXPANDED_VERSIONS | {"8.5.3"} or type(flag) is not int or flag != 1):
            raise ValueError("Unqualified engine overlay capability: " + version)
        if ("engineOverlaySchemaVersion" in profile) != ("engineOverlaySchemaVersion" in entries[version]) or entries[version].get("engineOverlaySchemaVersion") != flag:
            raise ValueError("Runtime profile and catalog disagree: " + version)
        if version in EXPANDED_VERSIONS and flag == 1:
            verify_expanded_version(root, version, profile)
    if plist_value(root / "App/Info.plist").get(HOST_STATUS_KEY) != HOST_STATUS:
        raise ValueError("Current App must declare unqualified host status")
    # A current source/package self-consistency check is not a qualification.
    actual = current_inputs(root)
    gallery_bundle = root / "RuntimeKit/Artifacts/RenPy853.bundle"
    if json.loads((gallery_bundle / "runtime-profile.json").read_bytes()).get("advancedTranslationSchemaVersion") == 1:
        if __package__:
            from .advanced_translation_update import verify as verify_translation_update
        else:
            from advanced_translation_update import verify as verify_translation_update
        gallery_bundle, _ = verify_translation_update(root, "8.5.3", gallery_bundle)
    check_traceback_853_update(root, gallery_bundle)
    if digest(gallery_bundle / "provenance.json") == "ec94bce6c9d46ae48c9c662c9a38890fef91c7eff04b917ccdca3189a24fb7d0":
        check_dialogue_segments_853_update(root, gallery_bundle)
    elif digest(gallery_bundle / "provenance.json") == "26b187d844b79ef9c2c5f91c5cce702188735b1fbc41239be41770133150f3bf":
        check_gallery_seen_853_update(root, gallery_bundle)
    else:
        check_gallery_853_update(root, gallery_bundle)
    provenance = json.loads((root / "RuntimeKit/Artifacts/RenPy853.bundle/provenance.json").read_bytes())
    if provenance.get("runtimeID") != "8.5.3" or provenance.get("pythonVersion") != "3.12":
        raise ValueError("Current runtime provenance identity differs")
    if not actual["base"]["fileCount"] or not all(item.get("fileCount", 0) > 0 for item in actual["frameworks"].values()):
        raise ValueError("Missing runtime component inputs")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--inputs-only", action="store_true")
    parser.add_argument("--built-app", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--configuration")
    parser.add_argument("--historical-evidence", action="store_true", help="Verify historic V3 evidence only, without qualifying current App")
    args = parser.parse_args()
    digest(args.contract)
    contract = json.loads(args.contract.read_bytes())
    if args.historical_evidence:
        if args.inputs_only or args.built_app:
            parser.error("--historical-evidence cannot qualify a current build")
        accepted(args.root, contract, historical_only=True)
        print("PASS: HISTORICAL_EVIDENCE_ONLY; current App not qualified")
        return
    (verify_inputs if args.inputs_only else check)(args.root, contract)
    if args.built_app:
        check_built_app(args.root, contract, args.built_app, args.platform, args.configuration)
    print("PASS: exact historical input contract" if args.inputs_only else "PASS: COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED; historical UI evidence does not qualify this App")


if __name__ == "__main__":
    main()
