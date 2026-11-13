"""Exact-build nightly profiles; existing runtime certificates remain mandatory."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import plistlib

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path("RuntimeKit/Candidates/NightlyProfiles20261104")
CERTIFICATE = Path("RuntimeKit/Patches/nightly-profiles-20261104.json")
CERTIFICATE_SHA256 = "c5c2fecd253d78a6aeb49140f88ca2d477e16932deb6a6fc76b902aa1b16f0e8"
BUILDS = {"7.8.8": "7.8.8.25051901+nightly", "8.5.4": "8.5.4.26101301+nightly"}
VERSIONS = set(BUILDS)
MATRIX = ("7.8.8", "8.5.4", "8.5.3", "7.8.8")
ORIGINAL_VERSIONS = {"7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.4", "7.8.7",
                     "8.0.3", "8.1.3", "8.2.3", "8.3.4", "8.3.7", "8.4.1", "8.5.0", "8.5.2", "8.5.3"}
PREVIOUS_BRIDGE_SHA256 = "a9dd363ea0598a544c21fcb4303f92504cc92feeb32272600bb14171e59a7910"
PREVIOUS_VALIDATION_SHA256 = "f544db39b7a9e1c016a3d74d8ad16b93017a9d723da8e26543c4b9819f54bb74"
OFFICIAL_INPUTS_SHA256 = "c9793427763efc30920954d229b4966b1fc0c33506e7123f689368adfed190f7"
SOURCE_PATHS = [CANDIDATE / name for name in ("RRRuntimeBridge.m", "previous-RRRuntimeBridge.m",
    "CompiledScriptValidation.swift", "previous-CompiledScriptValidation.swift", "rr_host.py")]
SOURCE_PATHS += [Path(name) for name in ("RuntimeKit/Inputs/official-nightlies.json", "RuntimeKit/Bridge/RRRuntimeBridge.h",
    "RuntimeKit/Tests/SmokeHost.m", "RuntimeKit/Tests/Fixtures/Smoke/game/script.rpy", "RuntimeKit/Native/RRRuntime.m", "Scripts/runtime/smoke_runtime.py",
    "Scripts/runtime/build_spark_profiles.py", "Scripts/runtime/fetch_official.py")]
SUPPORTED_LINE = b'    NSSet *supported = [NSSet setWithArray:@[@"7.4.11", @"7.5.3", @"7.6.3", @"7.7.3", @"7.8.4", @"7.8.7", @"8.0.3", @"8.1.3", @"8.2.3", @"8.3.4", @"8.3.7", @"8.4.1", @"8.5.0", @"8.5.2", @"8.5.3"]];\n'


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or linked nightly input: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    sha(path)
    return json.loads(path.read_bytes())


def relative(root, path):
    return path.resolve().relative_to(root.resolve()).as_posix()


def evidence_path(root, name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Nightly evidence must remain inside its repository")
    result = root / path
    if result.resolve() != result.absolute():
        raise ValueError("Linked nightly evidence path")
    return result


def previous_bridge(root):
    path = root / CANDIDATE / "previous-RRRuntimeBridge.m"
    if sha(path) != PREVIOUS_BRIDGE_SHA256:
        raise ValueError("The certified pre-nightly bridge changed")
    return path


def successor_bridge_bytes(previous):
    if hashlib.sha256(previous).hexdigest() != PREVIOUS_BRIDGE_SHA256 or previous.count(SUPPORTED_LINE) != 1:
        raise ValueError("Unknown nightly bridge predecessor")
    updated = SUPPORTED_LINE.replace(b'@"7.8.7",', b'@"7.8.7", @"7.8.8",').replace(b'@"8.5.3"]', b'@"8.5.3", @"8.5.4"]')
    return previous.replace(SUPPORTED_LINE, updated, 1)


def candidate_bridge(root):
    path = root / CANDIDATE / "RRRuntimeBridge.m"
    if path.read_bytes() != successor_bridge_bytes(previous_bridge(root).read_bytes()):
        raise ValueError("Nightly bridge changed outside its exact version whitelist")
    sha(path)
    return path


def verify_bridge_delta(root, bridge):
    expected = candidate_bridge(root)
    record = certificate(root)
    if sha(bridge) != record["bridgeSHA256"] or bridge.read_bytes() != expected.read_bytes():
        raise ValueError("The nightly bridge successor changed")


def successor_validation_bytes(previous):
    if hashlib.sha256(previous).hexdigest() != PREVIOUS_VALIDATION_SHA256:
        raise ValueError("Unknown pre-nightly compiler validation")
    salt = b'if ["8.4.1", "8.5.0", "8.5.2", "8.5.3"].contains(version)'
    versions = b'"7.8.4", "7.8.7", "8.0.3"'
    tail = b'"8.5.0", "8.5.2", "8.5.3"].contains(version) else'
    if any(previous.count(part) != 1 for part in (salt, versions, tail)):
        raise ValueError("Unknown exact compiler validation boundaries")
    return previous.replace(salt, salt.replace(b'"8.5.3"]', b'"8.5.3", "8.5.4"]'), 1).replace(
        versions, b'"7.8.4", "7.8.7", "7.8.8", "8.0.3"', 1).replace(
        tail, tail.replace(b'"8.5.3"]', b'"8.5.3", "8.5.4"]'), 1)


def candidate_validation(root):
    previous = root / CANDIDATE / "previous-CompiledScriptValidation.swift"
    if sha(previous) != PREVIOUS_VALIDATION_SHA256:
        raise ValueError("The certified compiler-validation predecessor changed")
    candidate = root / CANDIDATE / "CompiledScriptValidation.swift"
    if candidate.read_bytes() != successor_validation_bytes(previous.read_bytes()):
        raise ValueError("Compiler validation changed outside the two exact runtime rules")
    sha(candidate)
    return candidate


def verify_compiler_validation_delta(root, expected_previous):
    actual = root / "App/Services/Import/CompiledScriptValidation.swift"
    if expected_previous != PREVIOUS_VALIDATION_SHA256:
        raise ValueError("The older compiler-validation proof changed")
    record = certificate(root)
    if sha(actual) != record["compilerValidationSHA256"] or actual.read_bytes() != candidate_validation(root).read_bytes():
        raise ValueError("The nightly compiler validation successor changed")


def verify_events(rows, phase):
    """Require real edit/save/load/reset in every ordered ABI-switch session."""
    if phase not in {"warm", "cold"}:
        raise ValueError("Unknown nightly execution phase")
    failed = {"error", "gameError", "smokeFailed", "smokeFailure", "saveFailed", "commandRejected", "quarantined"}
    if any(row.get("type") in failed for row in rows):
        raise ValueError("Nightly matrix contains a failure")
    passed = [r for r in rows if r.get("type") == "smokePassed"]
    if len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 4:
        raise ValueError("Nightly matrix did not complete four sessions")
    process = passed[0].get("processID")
    if type(process) is not int or process <= 0 or any(r.get("processID") != process for r in rows):
        raise ValueError("Nightly process identity changed")
    ready = [r for r in rows if r.get("type") == "ready"]
    if [r.get("runtimeVersion") for r in ready] != list(MATRIX):
        raise ValueError("Nightly ABI-switch order changed")
    expected_keys = {("smoke-" + str(i + 1), i + 1) for i in range(4)}
    if {(r.get("sessionID"), r.get("epoch")) for r in ready} != expected_keys:
        raise ValueError("Nightly ready coverage changed")
    for index, version in enumerate(MATRIX, 1):
        key = ("smoke-" + str(index), index)
        group = [r for r in rows if (r.get("sessionID"), r.get("epoch")) == key]
        kinds = lambda name: [r for r in group if r.get("type") == name]
        current = kinds("ready")
        if len(current) != 1 or current[0].get("launchMode") != "enhanced":
            raise ValueError("Nightly session mode changed")
        capabilities = current[0].get("capabilities", {})
        if any(capabilities.get(k) is not True for k in ("hostControl", "readingTools", "variables", "dialogue", "preferences", "gestures")):
            raise ValueError("Nightly ordinary reading capability handshake changed")
        if version in VERSIONS and any(capabilities.get(k) is not False for k in ("live2D", "advancedTranslation", "titlePatches")):
            raise ValueError("Nightly session advertised an unqualified capability")
        if version in VERSIONS and (current[0].get("live2D", {}).get("available") is not False or current[0].get("engineOverlaySHA256") is not None):
            raise ValueError("Nightly session admitted an unqualified Core or engine overlay")
        for name in ("threadBaseline", "firstFrameDrawn", "threadAudit", "eventQueueCleanupSummary", "didReset"):
            if len(kinds(name)) != 1:
                raise ValueError("Nightly cleanup is missing or repeated: " + name)
        if kinds("threadAudit")[0].get("remaining") != []:
            raise ValueError("Nightly session retained a thread")
        cleanup = kinds("eventQueueCleanupSummary")[0]
        if cleanup.get("succeeded") is not True or cleanup.get("errors") != []:
            raise ValueError("Nightly session did not drain its event queue")
        saves = kinds("saveCommitted")
        if Counter(r.get("slot") for r in saves) != Counter({"smoke": 1, "rr_suspend": 1}):
            raise ValueError("Nightly manual and suspend saves are incomplete")
        manual = group.index(next(r for r in saves if r["slot"] == "smoke"))
        after_save = group[manual + 1:]
        accepted = next((i for i, r in enumerate(after_save) if r.get("type") == "ack" and r.get("status") == "accepted"), None)
        if accepted is None or not any(r.get("type") == "dialogue" for r in after_save[accepted + 1:]):
            raise ValueError("Nightly manual load did not return to real dialogue")
        dialogue = next(i for i in range(accepted + 1, len(after_save)) if after_save[i].get("type") == "dialogue")
        def edited(row):
            values = {v.get("name"): (v.get("type"), v.get("value")) for v in row.get("variables", [])}
            return values.get("affection") == ("integer", 42) and values.get("ratio") == ("float", 2.5)
        if not any(r.get("type") == "variables" and edited(r) for r in after_save[dialogue + 1:]):
            raise ValueError("Nightly saved scalar values were not read back after load")
        preferences = [r for r in rows if r.get("sessionID") == key[0] and r.get("type") == "preferencesReadbackPassed"]
        if len(preferences) != 1 or preferences[0].get("actualPreferences") is not True:
            raise ValueError("Nightly actual preference readback is missing")
        resumes = kinds("resumeState")
        if phase == "cold" and (len(resumes) != 1 or resumes[0].get("slot") != "rr_suspend" or resumes[0].get("available") is not True):
            raise ValueError("Nightly cold session did not request its explicit checkpoint")
    return {"processID": process, "sessions": 4}


def verify_script_identity(document):
    before, after = document.get("warmCompiledSHA256"), document.get("afterColdSHA256")
    if document.get("sameInstalledApplication") is not True or document.get("unchanged") is not True or not before or before != after:
        raise ValueError("Nightly cold run did not preserve warm compiled identities")
    for name, value in before.items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not name.endswith(".rpyc") or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("Invalid nightly compiled identity record")
    if any("Smoke" + v.replace(".", "") + "/game/script.rpyc" not in before for v in set(MATRIX)):
        raise ValueError("Nightly compiled identity coverage is incomplete")


def _validate_certificate(root, value):
    if value.get("schemaVersion") != 1 or value.get("status") != "simulatorWarmColdPassed" or set(value.get("runtimes", {})) != VERSIONS:
        raise ValueError("Nightly profiles have not passed independent acceptance")
    if value.get("bridgeSHA256") != sha(candidate_bridge(root)) or value.get("previousBridgeSHA256") != PREVIOUS_BRIDGE_SHA256:
        raise ValueError("Nightly certificate has another bridge delta")
    if value.get("compilerValidationSHA256") != sha(candidate_validation(root)):
        raise ValueError("Nightly certificate has another compiler-validation delta")
    evidence = value.get("evidence", {})
    if set(evidence) != {"inputs", "warm", "cold", "scriptIdentity"}:
        raise ValueError("Nightly execution evidence is incomplete")
    documents = {}
    for name, item in evidence.items():
        path = evidence_path(root, item["path"])
        if sha(path) != item["sha256"]:
            raise ValueError("Nightly evidence changed: " + name)
        documents[name] = path
    inputs = read(documents["inputs"])
    if (inputs.get("schemaVersion") != 1 or inputs.get("matrix") != list(MATRIX)
            or inputs.get("bridgeSHA256") != value["bridgeSHA256"]
            or inputs.get("compilerValidationSHA256") != value["compilerValidationSHA256"]
            or inputs.get("officialInputsSHA256") != OFFICIAL_INPUTS_SHA256):
        raise ValueError("Nightly precompilation identity changed")
    if set(inputs.get("sources", {})) != {p.as_posix() for p in SOURCE_PATHS}:
        raise ValueError("Nightly compilation source inventory changed")
    if inputs["sources"]["RuntimeKit/Inputs/official-nightlies.json"] != OFFICIAL_INPUTS_SHA256:
        raise ValueError("Nightly source manifest is not the frozen upstream archive set")
    for name, expected in inputs["sources"].items():
        if sha(evidence_path(root, name)) != expected:
            raise ValueError("Nightly compiled source changed: " + name)
    if (value.get("baselineCatalogProfiles") != inputs["baselineCatalogProfiles"]
            or len(inputs["baselineCatalogProfiles"]) != 15
            or {p.get("runtimeID") for p in inputs["baselineCatalogProfiles"]} != ORIGINAL_VERSIONS):
        raise ValueError("Nightly baseline must retain all fifteen catalog profiles")
    if value["runtimes"] != {v: inputs["resources"][v] for v in VERSIONS} or value.get("baseline853") != inputs["resources"]["8.5.3"]:
        raise ValueError("Nightly resource inputs changed")
    for version in VERSIONS:
        if value["runtimes"][version].get("upstreamBuildID") != BUILDS[version]:
            raise ValueError("Nightly complete upstream build identity changed")
    processes = []
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in documents[phase].read_text().splitlines() if line]
        processes.append(verify_events(rows, phase)["processID"])
    if len(set(processes)) != 2:
        raise ValueError("Nightly cold run reused its warm process")
    verify_script_identity(read(documents["scriptIdentity"]))
    return value


def certificate(root):
    path = root / CERTIFICATE
    if CERTIFICATE_SHA256 is None or sha(path) != CERTIFICATE_SHA256:
        raise ValueError("Nightly profiles have no pinned acceptance certificate")
    return _validate_certificate(root, read(path))


def native_identities(root, artifacts, version):
    from_module = __package__ + ".overlay_capability_guard" if __package__ else "overlay_capability_guard"
    from importlib import import_module
    packaged_source_identity = import_module(from_module).packaged_source_identity
    name = "RRRuntime" + version.replace(".", "")
    package = artifacts / (name + ".xcframework")
    metadata = plistlib.loads((package / "Info.plist").read_bytes())
    result = {}
    for platform in ("iphoneos", "iphonesimulator"):
        variant = "simulator" if platform == "iphonesimulator" else None
        library = next(item for item in metadata["AvailableLibraries"] if item.get("SupportedPlatform") == "ios" and item.get("SupportedPlatformVariant") == variant and "arm64" in item["SupportedArchitectures"])
        binary = package / library["LibraryIdentifier"] / library["LibraryPath"] / name
        result[platform] = packaged_source_identity(root, binary, platform)
    return result


def resource_identity(root, artifacts, version):
    if __package__:
        from .overlay_capability_guard import tree_digest
    else:
        from overlay_capability_guard import tree_digest
    bundle = artifacts / ("RenPy" + version.replace(".", "") + ".bundle")
    profile = read(bundle / "runtime-profile.json")
    if profile.get("runtimeID") != version:
        raise ValueError("Nightly resource/profile identity mismatch")
    if version in VERSIONS:
        expected_python = "2.7" if version == "7.8.8" else "3.12"
        manifest_path = root / "RuntimeKit/Inputs/official-nightlies.json"
        if sha(manifest_path) != OFFICIAL_INPUTS_SHA256:
            raise ValueError("Official nightly source manifest changed")
        upstream = read(manifest_path)["versions"][version]
        if ((bundle / "base/renpy/vc_version.py").read_bytes() != upstream["sdkVCVersion"].encode("utf-8")
                or sha(bundle / "base/renpy/script.py") != upstream["verifiedSourceFiles"]["renpy/script.py"]["sha256"]):
            raise ValueError("Nightly packaged compiler differs from its frozen official build")
        if (profile.get("upstreamBuildID") != BUILDS[version] or profile.get("pythonVersion") != expected_python
                or profile.get("live2D", {}).get("available") is not False
                or sha(bundle / "base/rr_host.py") != sha(root / CANDIDATE / "rr_host.py")
                or any(k in profile for k in ("engineOverlaySchemaVersion", "advancedTranslationSchemaVersion", "storySessionPatchSchemaVersion"))):
            raise ValueError("Nightly build identity or unqualified capability flag changed")
    return {"upstreamBuildID": profile.get("upstreamBuildID"), "profileSHA256": sha(bundle / "runtime-profile.json"),
            "hostSHA256": sha(bundle / "base/rr_host.py"), "bundle": tree_digest(bundle),
            "native": native_identities(root, artifacts, version)}


def verify(root, entries, *, built_app=None, platform=None):
    if any(entries.get(version, {}).get("scriptTranslationPagingSchemaVersion") == 1 for version in VERSIONS):
        if __package__:
            from .advanced_translation17_update import verify_added_profiles
        else:
            from advanced_translation17_update import verify_added_profiles
        return verify_added_profiles(root, entries, VERSIONS, built_app=built_app, platform=platform)
    if __package__:
        from .overlay_capability_guard import tree_digest, image_identity
    else:
        from overlay_capability_guard import tree_digest, image_identity
    record = certificate(root)
    if {v: entries[v] for v in ORIGINAL_VERSIONS} != {p["runtimeID"]: p for p in record["baselineCatalogProfiles"]}:
        raise ValueError("Nightly promotion changed an existing catalog profile")
    bridge = root / "RuntimeKit/Bridge/RRRuntimeBridge.m"
    if sha(bridge) != record["bridgeSHA256"] or bridge.read_bytes() != candidate_bridge(root).read_bytes():
        raise ValueError("Nightly catalog requires its exact bridge successor")
    validation = root / "App/Services/Import/CompiledScriptValidation.swift"
    if sha(validation) != record["compilerValidationSHA256"] or validation.read_bytes() != candidate_validation(root).read_bytes():
        raise ValueError("Nightly catalog requires its exact compiler-validation successor")
    for version in VERSIONS | {"8.5.3"}:
        expected = record["baseline853"] if version == "8.5.3" else record["runtimes"][version]
        if resource_identity(root, root / "RuntimeKit/Artifacts", version) != expected:
            raise ValueError("Qualified nightly or baseline 853 resources changed: " + version)
        name = "RenPy" + version.replace(".", "") + ".bundle"
        profile = read(root / "RuntimeKit/Artifacts" / name / "runtime-profile.json")
        if any(entries[version].get(k) != value for k, value in profile.items()):
            raise ValueError("Nightly catalog differs from its profile")
        if built_app is not None:
            framework = "RRRuntime" + version.replace(".", "")
            if tree_digest(built_app / name) != expected["bundle"] or image_identity(root, built_app / "Frameworks" / (framework + ".framework") / framework) != expected["native"][platform]:
                raise ValueError("Built nightly or baseline 853 image differs from acceptance")


def prepare_inputs(root, artifacts, output):
    catalog = read(root / "RuntimeKit/Artifacts/runtime-catalog.json")["profiles"]
    baseline = [p for p in catalog if p["runtimeID"] in ORIGINAL_VERSIONS]
    if len(baseline) != 15 or {p["runtimeID"] for p in baseline} != ORIGINAL_VERSIONS:
        raise ValueError("Nightly input capture requires all fifteen original profiles")
    sources = [root / path for path in SOURCE_PATHS]
    if sha(root / "RuntimeKit/Inputs/official-nightlies.json") != OFFICIAL_INPUTS_SHA256:
        raise ValueError("Official nightly archive manifest changed")
    result = {"schemaVersion": 1, "matrix": list(MATRIX), "bridgeSHA256": sha(candidate_bridge(root)),
        "compilerValidationSHA256": sha(candidate_validation(root)), "officialInputsSHA256": OFFICIAL_INPUTS_SHA256,
        "sources": {relative(root, p): sha(p) for p in sources}, "baselineCatalogProfiles": baseline,
        "resources": {v: resource_identity(root, artifacts if v in VERSIONS else root / "RuntimeKit/Artifacts", v) for v in set(MATRIX)}}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--artifacts", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    accept = commands.add_parser("accept")
    for name in ("inputs", "warm", "cold", "script-identity"):
        accept.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    if options.command == "prepare":
        prepare_inputs(ROOT, options.artifacts, options.output)
        print("Prepared nightly inputs SHA256=" + sha(options.output))
        return
    inputs = read(options.inputs)
    value = {"schemaVersion": 1, "status": "simulatorWarmColdPassed", "previousBridgeSHA256": PREVIOUS_BRIDGE_SHA256,
        "compilerValidationSHA256": inputs["compilerValidationSHA256"],
        "bridgeSHA256": inputs["bridgeSHA256"], "baselineCatalogProfiles": inputs["baselineCatalogProfiles"],
        "baseline853": inputs["resources"]["8.5.3"], "runtimes": {v: inputs["resources"][v] for v in VERSIONS},
        "evidence": {name: {"path": relative(ROOT, path), "sha256": sha(path)} for name, path in
            (("inputs", options.inputs), ("warm", options.warm), ("cold", options.cold), ("scriptIdentity", options.script_identity))}}
    _validate_certificate(ROOT, value)
    target = ROOT / CERTIFICATE
    if target.exists():
        raise ValueError("Preserve the existing nightly certificate before replacing it")
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print("Reviewed nightly acceptance certificate SHA256=" + sha(target))


if __name__ == "__main__":
    main()
