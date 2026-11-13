#!/usr/bin/env python3
"""Strict F1-F10 shared-platform successor over the frozen seventeen-runtime layer.

The old validators run against their real immutable predecessor root. They are
never patched or presented a synthetic current tree. This layer changes only
RRPlatform; it does not claim a new Live2D, hardware or lower-iOS qualification.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

if __package__:
    from . import overlay_capability_guard as old
    from .legacy_core_packaging import optional_framework
else:
    import overlay_capability_guard as old
    from legacy_core_packaging import optional_framework

FOLDER = Path("RuntimeKit/Validation/SparkFunctionKeys20261110")
CERTIFICATE = Path("RuntimeKit/Patches/function-keys-20261110.json")
CERTIFICATE_SHA256 = "88891bbf309bf519f8dd50bc625ea27310e0e4a867b7699e440d32d4c4648857"
PREDECESSOR_REPLAY_SHA256 = "bce5ce23105fec7ce23f41f4edd29bd4c7adf4dca9ab25730ab5eb6761ca2003"
PREDECESSOR_RETENTION_SHA256 = "f238353b356c26d9c20788d38f18ff3951fda7d1eb975999de0da31653af9780"
MARKER = "PASS: COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED; historical UI evidence does not qualify this App"
DELTA = ("        case SDL_SCANCODE_F1: case SDL_SCANCODE_F2: case SDL_SCANCODE_F3: case SDL_SCANCODE_F4: case SDL_SCANCODE_F5:\n"
         "        case SDL_SCANCODE_F6: case SDL_SCANCODE_F7: case SDL_SCANCODE_F8: case SDL_SCANCODE_F9: case SDL_SCANCODE_F10:\n")
SOURCE = "RuntimeKit/Native/RRAuxiliaryInput.c"
NOTICE_NAMES = ("function-keys-20261110.json", "function-keys-20261110.patch")
IMAGE_NAMES = {"RRPlatform", "RRLive2DCore", "RRGalleryAudio", "MetalANGLE"}
LOCKED_SOURCES = ("App/Core/AdvancedTranslationState.swift", "App/Services/Translation/AdvancedTranslationCapture.swift",
    "App/Services/Translation/TranslationProvider.swift", "App/Services/Translation/OnlineTranslationService.swift",
    "App/Services/Translation/TranslationTextLayout.swift", "App/Services/Import/BuiltinStoryRepairRuntime.swift",
    "App/Services/Import/EngineOverlayService.swift", "App/Services/Import/CompiledScriptIdentity.swift",
    "App/Services/Import/CompiledScriptValidation.swift", "App/RuntimeScriptIdentityCapture.swift",
    "RuntimeKit/Bridge/RRRuntimeBridge.m", "RuntimeKit/Bridge/RRRuntimeBridge.h", "RuntimeKit/Native/RRRuntime.m")
image_identity = old.image_identity


def digest(path):
    path = Path(path).absolute()
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Linked qualification input ancestor: " + str(path))
    return old.digest(path)


def read(path):
    digest(path)
    return json.loads(path.read_bytes())


def safe_root(path):
    path = Path(path).absolute()
    # Check lexical components before resolve; a linked ancestor is also unsafe.
    if path.resolve() != path or any(parent.is_symlink() for parent in (path, *path.parents)) or not path.is_dir():
        raise ValueError("Qualification roots must be existing regular, unlinked directories: " + str(path))
    return path


def built_app_root(path):
    path = Path(path).absolute()
    # macOS has one standard /tmp -> /private/tmp alias. Canonicalize only
    # that prefix, then retain the same linked-ancestor / leaf rejection.
    if path.parts[:2] == ("/", "tmp") and Path("/tmp").resolve() == Path("/private/tmp"):
        path = Path("/private/tmp").joinpath(*path.parts[2:])
    return safe_root(path)


def preserved_sources(retention):
    # The current App may acquire unrelated presentation/settings features.
    # Only these thirteen locked integration inputs and the unchanged native
    # build/qualification chain belong to this narrow platform successor.
    names = set(LOCKED_SOURCES)
    names.update(name for name in retention["sources"] if name.startswith(("RuntimeKit/Native/", "Scripts/runtime/")))
    names.update(("App/Services/Import/SparkParityEngineUpdates.swift", "RuntimeKit/Live2DRendererPolicy.json", "RuntimeKit/NOTICE.md"))
    names.discard(SOURCE)
    return {name: retention["sources"][name] for name in sorted(names)}


def exact_plans(plans, versions):
    expected = Counter((version, mode) for version in versions for mode in ("enhanced", "minimal", "nativeCompatibility"))
    if (not isinstance(plans, list) or any(not isinstance(plan, dict) or set(plan) != {"runtimeID", "launchMode"} for plan in plans) or
            Counter((plan["runtimeID"], plan["launchMode"]) for plan in plans) != expected):
        raise ValueError("F-key matrix must cover the exact catalog times three distinct modes")


def ref(root, value):
    return old.checked_reference(root, value)


def binding(root, path):
    return {"path": path.relative_to(root).as_posix(), "sha256": digest(path)}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def expected_source(before):
    if DELTA in before:
        raise ValueError("The predecessor already contains the F-key delta")
    anchor = "        case SDL_SCANCODE_LCTRL: case SDL_SCANCODE_LSHIFT: case SDL_SCANCODE_LALT: return 1;\n"
    if before.count(anchor) != 1:
        raise ValueError("Unexpected predecessor key allowlist")
    return before.replace(anchor, DELTA + anchor)


def verify_source_delta(previous_root, source_root):
    if (source_root / SOURCE).read_text() != expected_source((previous_root / SOURCE).read_text()):
        raise ValueError("F-key source delta exceeds the exact ten whitelist cases")


def source_patch(previous_root):
    before = (previous_root / SOURCE).read_text()
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), expected_source(before).splitlines(keepends=True),
        fromfile="a/" + SOURCE, tofile="b/" + SOURCE)).encode()


def verify_notices(source_root, value):
    notices = source_root / "RuntimeKit/Notices"
    actual = old.tree_digest(notices, lambda path: path.name not in NOTICE_NAMES)
    if actual != value["predecessorNotices"]:
        raise ValueError("A preserved platform/renderer notice changed")
    if digest(notices / NOTICE_NAMES[0]) != CERTIFICATE_SHA256 or digest(notices / NOTICE_NAMES[1]) != value["sourcePatchSHA256"]:
        raise ValueError("F-key successor notice/patch does not describe this exact platform")


def platform_supplement_predecessor(root):
    """Legal attribution only: validate the exact old-platform -> F-platform pair.

    The virtual-joystick notice still describes the old platform. Do not rewrite
    its native SHA or pretend its embedded build record belongs to the F image.
    """
    root = safe_root(root)
    value = certificate(root)
    previous = safe_root(root / FOLDER / "Baseline")
    if (digest(previous / "replay.json") != PREDECESSOR_REPLAY_SHA256 or
            old.tree_digest(previous / "RuntimeKit/Artifacts/RRPlatform.xcframework") != value["predecessorArtifacts"]["RRPlatform.xcframework"] or
            old.tree_digest(root / "RuntimeKit/Artifacts/RRPlatform.xcframework") != value["platformTree"]):
        raise ValueError("SDL supplement successor chain changed")
    verify_source_delta(previous, root)
    verify_notices(root, value)
    return previous / "RuntimeKit/Artifacts"


def replay_predecessor(root, previous_root=None):
    previous = safe_root(previous_root or root / FOLDER / "Baseline")
    replay_path, retention_path = previous / "replay.json", previous / "retention.json"
    if digest(replay_path) != PREDECESSOR_REPLAY_SHA256 or digest(retention_path) != PREDECESSOR_RETENTION_SHA256:
        raise ValueError("Frozen predecessor attestation changed")
    replay, retention = read(replay_path), read(retention_path)
    if (replay.get("passed") is not True or replay.get("exitCode") != 0 or replay.get("successMarker") != MARKER or
            replay.get("successMarkerPresent") is not True or digest(previous / "replay.log") != replay.get("logSHA256")):
        raise ValueError("Predecessor replay did not finish successfully")
    for name, expected in retention["sources"].items():
        if digest(previous / name) != expected:
            raise ValueError("Frozen predecessor source changed: " + name)
    for name, expected in retention["certificates"].items():
        if digest(previous / name) != expected:
            raise ValueError("Frozen predecessor certificate changed: " + name)
    command = [sys.executable, "-B", previous / "Scripts/runtime/overlay_capability_guard.py", "--root", previous,
               "--contract", previous / "RuntimeKit/Patches/overlay-capability-853.json"]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(list(map(str, command)), cwd=previous, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode or not result.stdout.rstrip().endswith(MARKER):
        raise ValueError("The complete unchanged predecessor chain rejected its frozen root:\n" + result.stdout[-8000:])
    return previous, retention


def artifact_trees(artifacts):
    safe_root(artifacts)
    return {path.name: old.tree_digest(path) if path.is_dir() else {"sha256": digest(path)}
            for path in sorted(artifacts.iterdir())}


def verify_artifact_delta(previous, actual, platform, certificate):
    expected = certificate["predecessorArtifacts"]
    original = artifact_trees(previous / "RuntimeKit/Artifacts")
    if original != expected:
        raise ValueError("Predecessor artifact package changed")
    current = artifact_trees(actual)
    if set(current) != set(expected):
        raise ValueError("Current artifact package set changed")
    for name, identity in expected.items():
        if name != "RRPlatform.xcframework" and current[name] != identity:
            raise ValueError("F-key successor changed a preserved resource/native package: " + name)
    if current["RRPlatform.xcframework"] not in (expected["RRPlatform.xcframework"], certificate["platformTree"]):
        raise ValueError("Artifact root contains an unrelated shared platform")
    if old.tree_digest(platform) != certificate["platformTree"]:
        raise ValueError("Shared F-key platform differs from its actual tested package")
    if platform == actual / "RRPlatform.xcframework" and current["RRPlatform.xcframework"] != certificate["platformTree"]:
        raise ValueError("The selected platform does not describe current Artifacts")


def native_report(value, expected_count):
    if (type(value.get("passed")) is not int or value.get("passed") != 1 or
            type(value.get("failures")) is not int or value.get("failures") != 0 or
            len(value.get("checks", [])) != expected_count or
            any(row.get("passed") is not True for row in value.get("checks", []))):
        raise ValueError("Native SDL assertions did not all pass")


def verify_probe_packages(root, build, manifest, tag):
    label = "Instrumented" if tag == "UIKitNativeFinal" else "Clean"
    rows = {(row["variant"], row["platform"]): row for row in build["frameworks"]}
    if set(rows) != {(variant, platform) for variant in ("Instrumented", "Clean") for platform in ("iphoneos", "iphonesimulator")}:
        raise ValueError("Native candidate slice receipt is incomplete")
    for platform, identifier in (("iphoneos", "ios-arm64"), ("iphonesimulator", "ios-arm64-simulator")):
        clean, instrumented = rows[("Clean", platform)], rows[("Instrumented", platform)]
        if clean["inputObjects"] != instrumented["inputObjects"] or clean.get("testProbeIncluded") is not False or instrumented.get("testProbeIncluded") is not True:
            raise ValueError("Test and clean platforms did not use identical input objects")
        for variant in ("Clean", "Instrumented"):
            path = root / FOLDER / "CandidateBuild" / variant / "RRPlatform.xcframework" / identifier / "RRPlatform.framework/RRPlatform"
            if digest(path) != rows[(variant, platform)]["sha256"]:
                raise ValueError("Native candidate differs from its actual build receipt")
        for name, expected in clean["inputObjects"].items():
            if digest(root / FOLDER / "CandidateBuild/InputBuild" / platform / (name + ".o")) != expected:
                raise ValueError("A retained actual native input object changed")
    platform = manifest["frameworks"]["RRPlatform"]
    expected_source = (FOLDER / "CandidateBuild" / label / "RRPlatform.xcframework").as_posix()
    if platform.get("source") != expected_source or platform.get("simulatorBinarySHA256") != rows[(label, "iphonesimulator")]["sha256"]:
        raise ValueError("The actual probe did not use the tested platform package")
    for name, entry in manifest["frameworks"].items():
        if name != "RRPlatform":
            expected = "RuntimeKit/Artifacts/" + name + ".xcframework"
            original = old.framework_slice(root / FOLDER / "Baseline", name, "iphonesimulator") / name
            if entry.get("source") != expected or digest(original) != entry.get("simulatorBinarySHA256"):
                raise ValueError("An actual probe used a changed original native package")
        binary = root / FOLDER / tag / "FunctionKeyProbe.app/Frameworks" / (name + ".framework") / name
        if digest(binary) != entry.get("signedProbeBinarySHA256"):
            raise ValueError("The signed native probe product changed")


def verify_source_receipt(folder, sources):
    inputs = safe_root(folder / "SourceInputs")
    for name, expected in sources.items():
        ref(inputs, {"path": name, "sha256": expected})


def verify_phase(rows, plans, *, native=False, versions=None):
    if not native:
        exact_plans(plans, versions if versions is not None else {plan["runtimeID"] for plan in plans})
    if not rows or any(row.get("type") in {"auxiliaryProbeFailed", "error", "gameError", "quarantined", "seriesStateFailed", "commandRejected", "saveFailed"} for row in rows):
        raise ValueError("Actual F-key session failed")
    pids = {row.get("processID") for row in rows}
    if len(pids) != 1 or any(type(pid) is not int or pid <= 0 for pid in pids):
        raise ValueError("F-key phase did not retain one actual process")
    checks = [row for row in rows if row.get("type") == "auxiliaryCheck"]
    if not checks or any(row.get("passed") is not True for row in checks):
        raise ValueError("Actual Bridge/native assertions failed")
    if native:
        reports = [row for row in rows if row.get("type") == "auxiliaryNativeProbe"]
        if len(reports) != 1 or reports[0].get("executionPlatform") != "iOSSimulatorUIKit" or reports[0].get("keyboardBackendMocked") is not True:
            raise ValueError("Actual UIKit native probe missing")
        native_report(reports[0]["report"], 162)
        if sum(row.get("type") == "auxiliaryPrimitivePassed" for row in rows) != 1:
            raise ValueError("UIKit native probe did not complete")
        return next(iter(pids))
    complete = [row for row in rows if row.get("type") == "auxiliaryProbePassed"]
    if len(complete) != 1 or complete[0].get("sessions") != len(plans) or complete[0].get("checks") != len(checks):
        raise ValueError("Actual F-key phase is incomplete")
    expected_edges = [(number, edge) for number in range(1, 11) for edge in ("down", "up")]
    for index, plan in enumerate(plans):
        selected = [row for row in rows if row.get("sessionIndex") == index]
        for kind in ("auxiliarySessionStarted", "ready", "firstFrameDrawn", "surfaceAttached", "threadAudit", "didReset", "auxiliarySessionPassed"):
            matches = [row for row in selected if row.get("type") == kind]
            if len(matches) != 1 or (kind == "threadAudit" and matches[0].get("remaining") != []):
                raise ValueError("Session start/reset/thread evidence missing: " + kind)
        start = next(row for row in selected if row.get("type") == "auxiliarySessionStarted")
        if any(start.get(key) != plan[key] for key in ("runtimeID", "launchMode")):
            raise ValueError("The actual session did not match the planned runtime/mode")
        sent = [row for row in selected if row.get("type") == "functionKeySent"]
        observed = [row for row in selected if row.get("type") == "functionKeyObserved"]
        if plan["launchMode"] == "nativeCompatibility":
            disabled = [row for row in selected if row.get("type") == "functionKeysDisabled"]
            if sent or observed or len(disabled) != 1 or disabled[0].get("keys") != 10:
                raise ValueError("Native mode accepted function keys")
        else:
            if [(row.get("function"), row.get("edge")) for row in sent] != expected_edges or [(row.get("function"), row.get("edge")) for row in observed] != expected_edges:
                raise ValueError("Actual engine did not observe all ordered F1-F10 down/up events")
            for row in observed:
                if row.get("key") != ((1 << 30) | (57 + row["function"])) or row.get("scancode") not in (-1, 57 + row["function"]):
                    raise ValueError("Engine event key or scancode changed")
    for kind in ("auxiliaryBackgroundRequested", "auxiliaryBackgroundObserved"):
        if sum(row.get("type") == kind for row in rows) != 1:
            raise ValueError("Actual background ownership check missing")
    return next(iter(pids))


def verify_evidence(root, certificate):
    evidence = certificate["evidence"]
    for value in evidence.values():
        ref(root, value)
    build = read(ref(root, evidence["candidateBuild"]))
    if build.get("passed") is not True or build.get("nativeChecks") != 162 or build.get("baselineChecks") != 23 or build.get("productionUnchanged") is not True:
        raise ValueError("Candidate native build did not pass")
    native_report(read(ref(root, evidence["offlineNative"])), 162)
    native_report(read(ref(root, evidence["offlineKeyboard"])), 23)
    for tag in ("UIKitNativeFinal", "RuntimeMatrix"):
        folder = root / FOLDER / tag
        manifest = read(folder / "build-manifest.json")
        verify_probe_packages(root, build, manifest, tag)
        if digest(folder / "inputs.json") != manifest.get("inputsSHA256"):
            raise ValueError("Precompile source receipt changed")
        verify_source_receipt(folder, manifest["sources"])
        if tag == "RuntimeMatrix":
            if manifest["sessions"] != certificate["sessions"] or manifest.get("nativeOnly") is not False:
                raise ValueError("The actual matrix did not cover seventeen runtimes in three modes")
        pids = []
        for phase in (("native",) if tag == "UIKitNativeFinal" else ("warm", "cold")):
            report = read(folder / phase / "verification.json")
            inputs = read(folder / phase / "inputs.json")
            events_path = folder / phase / "events.ndjson"
            if (report.get("passed") is not True or report.get("debuggerIntervention") is not False or inputs.get("debuggerIntervention") is not False or
                    digest(events_path) != report.get("eventsSHA256") or digest(folder / phase / "inputs.json") != report.get("inputsSHA256") or
                    inputs.get("buildManifestSHA256") != digest(folder / "build-manifest.json")):
                raise ValueError("The actual phase receipt changed")
            rows = [json.loads(line) for line in events_path.read_text().splitlines() if line]
            if any(row.get("runID") != inputs["runID"] for row in rows):
                raise ValueError("Mixed actual run IDs")
            pid = verify_phase(rows, manifest["sessions"], native=tag == "UIKitNativeFinal")
            if pid != report.get("processID"):
                raise ValueError("The actual process does not match its report")
            pids.append(pid)
        if len(set(pids)) != len(pids):
            raise ValueError("Warm and cold phases used the same process")


def certificate(root):
    path = root / CERTIFICATE
    if CERTIFICATE_SHA256 is None or digest(path) != CERTIFICATE_SHA256:
        raise ValueError("F-key certificate is not frozen or has changed")
    value = read(path)
    if (value.get("schemaVersion") != 1 or value.get("kind") != "sharedPlatformFunctionKeys" or value.get("passed") is not True or
            value.get("functionKeys") != list(range(1, 11)) or value.get("runtimeNativeRebuilt") is not False or value.get("live2DRequalified") is not False):
        raise ValueError("Unsupported F-key certificate scope")
    catalog = read(root / FOLDER / "Baseline/RuntimeKit/Artifacts/runtime-catalog.json")
    versions = [row["runtimeID"] for row in catalog["profiles"]]
    if len(versions) != 17 or len(set(versions)) != 17:
        raise ValueError("F-key catalog runtime coverage changed")
    exact_plans(value.get("sessions"), versions)
    return value


def verify(root, *, artifacts_root=None, previous_root=None, platform_package=None, source_root=None, replay=True):
    """Composable exact layer. Explicit roots never authorize a different package.

    A successor can verify this retained F layer using its frozen SourceInputs
    and Clean platform while replaying the same predecessor root in place.
    """
    root = safe_root(root)
    previous = safe_root(previous_root or root / FOLDER / "Baseline")
    actual = safe_root(artifacts_root or root / "RuntimeKit/Artifacts")
    source = safe_root(source_root or root)
    platform = safe_root(platform_package or actual / "RRPlatform.xcframework")
    value = certificate(root)
    if replay:
        previous, _ = replay_predecessor(root, previous)
    elif digest(previous / "replay.json") != PREDECESSOR_REPLAY_SHA256:
        raise ValueError("Unrecognized predecessor root")
    verify_source_delta(previous, source)
    for name, expected in value["preservedSources"].items():
        if digest(source / name) != expected:
            raise ValueError("Preserved runtime qualification source changed: " + name)
    for name, expected in value["successorSources"].items():
        if digest(source / name) != expected:
            raise ValueError("F-key successor source changed: " + name)
    verify_artifact_delta(previous, actual, platform, value)
    verify_notices(source, value)
    verify_evidence(root, value)
    return value


def check(root, contract):
    previous = root / FOLDER / "Baseline"
    if contract != read(previous / "RuntimeKit/Patches/overlay-capability-853.json"):
        raise ValueError("The predecessor overlay contract changed")
    return verify(root)


def check_built_app(root, contract, app, platform, configuration):
    # check() runs first in the preflight / product audit. Recheck source and
    # actual copied bytes here; never rerun an old built-app guard on new bytes.
    value = verify(root, replay=False)
    app = built_app_root(app)
    if (configuration, platform) not in (("Debug", "iphonesimulator"), ("Release", "iphoneos")):
        raise ValueError("Unqualified build configuration")
    info = plistlib.loads((app / "Info.plist").read_bytes())
    source_info = plistlib.loads((root / "App/Info.plist").read_bytes())
    if info.get(old.HOST_STATUS_KEY) != old.HOST_STATUS or source_info.get(old.HOST_STATUS_KEY) != old.HOST_STATUS or info.get("MinimumOSVersion") != "17.0":
        raise ValueError("Current App host/deployment status changed")
    artifacts = root / "RuntimeKit/Artifacts"
    bundles = {name for name in value["predecessorArtifacts"] if name.endswith(".bundle")}
    if {path.name for path in app.glob("RenPy*.bundle")} != bundles:
        raise ValueError("Built runtime bundle set changed")
    for name in bundles:
        if old.tree_digest(app / name) != old.tree_digest(artifacts / name):
            raise ValueError("Built runtime resource differs: " + name)
    names = IMAGE_NAMES | {"RRRuntime" + p["runtimeID"].replace(".", "") for p in read(artifacts / "runtime-catalog.json")["profiles"]}
    legacy = optional_framework(root)
    if legacy is not None and platform == "iphoneos":
        names.add("RRLive2DLegacyCore")
    frameworks = safe_root(app / "Frameworks")
    if {path.stem for path in frameworks.glob("*.framework")} != names:
        raise ValueError("Built native framework set differs from its explicit artifacts")
    for name in names:
        source = legacy if name == "RRLive2DLegacyCore" else old.framework_slice(root, name, platform)
        built = app / "Frameworks" / (name + ".framework")
        safe_root(built)
        if digest(source / "Info.plist") != digest(built / "Info.plist"):
            raise ValueError("Built native framework metadata differs: " + name)
        if old.packaged_source_identity(root, source / name, platform) != image_identity(root, built / name):
            raise ValueError("Built native image differs from its exact artifact: " + name)


def prepare(root):
    previous = safe_root(root / FOLDER / "Baseline")
    replay = read(previous / "replay.json")
    if digest(previous / "replay.json") != PREDECESSOR_REPLAY_SHA256 or replay.get("passed") is not True:
        raise ValueError("Replay the exact predecessor first")
    verify_source_delta(previous, root)
    folder = root / FOLDER
    retention = read(previous / "retention.json")
    preserved = preserved_sources(retention)
    successor = {SOURCE: digest(root / SOURCE), "App/Views/ReaderInputControls.swift": digest(root / "App/Views/ReaderInputControls.swift")}
    build = read(folder / "CandidateBuild/result.json")
    successor.update(build["sourceSHA256"])
    evidence_paths = {"candidateBuild": folder / "CandidateBuild/result.json", "candidateInputs": folder / "CandidateBuild/inputs.json",
                      "offlineNative": folder / "CandidateBuild/native-probe.json", "offlineKeyboard": folder / "CandidateBuild/keyboard-baseline.json"}
    for tag in ("UIKitNativeFinal", "RuntimeMatrix"):
        for name in ("inputs.json", "build-manifest.json", "verification.json"):
            evidence_paths[tag + ":" + name] = folder / tag / name
        for phase in (("native",) if tag == "UIKitNativeFinal" else ("warm", "cold")):
            for name in ("inputs.json", "verification.json", "events.ndjson"):
                evidence_paths[tag + ":" + phase + ":" + name] = folder / tag / phase / name
    value = {"schemaVersion": 1, "kind": "sharedPlatformFunctionKeys", "passed": True,
             "timeUTC": datetime.now(timezone.utc).isoformat(), "functionKeys": list(range(1, 11)), "runtimeNativeRebuilt": False,
             "live2DRequalified": False, "scope": "F1-F10 source-owned input only. Seventeen RRRuntime and resource trees unchanged; predecessor render evidence remains attributed to its original platform. No hardware or iOS <17 claim.",
             "predecessorReplaySHA256": digest(previous / "replay.json"), "predecessorRetentionSHA256": digest(previous / "retention.json"),
             "predecessorArtifacts": artifact_trees(previous / "RuntimeKit/Artifacts"),
             "predecessorNotices": old.tree_digest(previous / "RuntimeKit/Notices"),
             "sourcePatchSHA256": hashlib.sha256(source_patch(previous)).hexdigest(),
             "platformTree": old.tree_digest(folder / "CandidateBuild/Clean/RRPlatform.xcframework"),
             "preservedSources": preserved, "successorSources": successor,
             "sessions": read(folder / "RuntimeMatrix/build-manifest.json")["sessions"],
             "evidence": {name: binding(root, path) for name, path in evidence_paths.items()}}
    exact_plans(value["sessions"], [row["runtimeID"] for row in read(previous / "RuntimeKit/Artifacts/runtime-catalog.json")["profiles"]])
    verify_evidence(root, value)
    verify_artifact_delta(previous, root / "RuntimeKit/Artifacts", folder / "CandidateBuild/Clean/RRPlatform.xcframework", value)
    if len({plan["runtimeID"] for plan in value["sessions"]}) != 17 or len(value["sessions"]) != 51:
        raise ValueError("Incomplete seventeen-runtime matrix")
    target = folder / "certificate-candidate.json"
    if target.exists():
        raise ValueError("Never overwrite an existing certificate candidate")
    frozen = folder / "FrozenSources"
    if frozen.exists():
        raise ValueError("Never overwrite frozen predecessor sources")
    for name, expected in {**preserved, **successor}.items():
        path = root / name
        if digest(path) != expected:
            raise ValueError("A source changed before retention: " + name)
        copied = frozen / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, copied)
    shutil.copytree(previous / "RuntimeKit/Notices", frozen / "RuntimeKit/Notices")
    (folder / "function-keys-20261110.patch").write_bytes(source_patch(previous))
    write(target, value)
    print(json.dumps({"certificate": str(target), "sha256": digest(target)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--built-app", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--configuration")
    parser.add_argument("--prepare-certificate", action="store_true")
    args = parser.parse_args()
    root = safe_root(args.root)
    if args.prepare_certificate:
        prepare(root)
        return
    contract = read(args.contract or root / "RuntimeKit/Patches/overlay-capability-853.json")
    check(root, contract)
    if args.built_app:
        check_built_app(root, contract, args.built_app, args.platform, args.configuration)
    print(MARKER + "; exact F1-F10 shared-platform successor")


if __name__ == "__main__":
    main()
