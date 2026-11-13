#!/usr/bin/env python3
"""Resource-only engine preferences successor. Static inspection grants no qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
CERTIFICATE = Path("RuntimeKit/Patches/engine-preferences-20261111.json")
CERTIFICATE_SHA256 = "11283b59a93d945720d059182489e946d5460abefba512dbb6f678f9329c1983"
PARENT_GUARD = "Scripts/runtime/legacy_packaging_guard.py"
PARENT_GUARD_SHA256 = "14367e06329946e2c109ee4d96e29d54e20031bd41b7187f1313958d67c592df"
PARENT_CERTIFICATE = "RuntimeKit/Patches/legacy-packaging-20261110.json"
PARENT_CERTIFICATE_SHA256 = "d09254dfccbeb6905a2f430dc9c0679895e190f1421709d205c388244152f998"
REGISTRY = "App/Services/Import/SparkParityEngineUpdates.swift"
REGISTRY_SHA256 = "9150bc2047d1b2d2cfd0e0a08c69e6822de20f79978a9eb081bacb057a458233"
INLINE_REGISTRY = "App/Services/Import/EngineOverlayService.swift"
INLINE_REGISTRY_SHA256 = "940bbb74c4d9bc7968ca111299e7ac3b62f514e0141c18b4e354ec86770d1539"
VERSIONS = ("7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.4", "7.8.7", "7.8.8", "8.0.3", "8.1.3", "8.2.3", "8.3.4", "8.3.7", "8.4.1", "8.5.0", "8.5.2", "8.5.3", "8.5.4")
PROVENANCE_SCOPE = "typed launch sidecar; standard Python network control is partial, not OS isolation"
PROBE_SOURCES = {"RuntimeKit/Bridge/RRRuntimeBridge.m", "RuntimeKit/Bridge/RRRuntimeBridge.h",
    "RuntimeKit/Bridge/RRLive2DSelection.h", "RuntimeKit/Native/RRAuxiliaryInput.h",
    "RuntimeKit/Candidates/EnginePreferences20261111/ActualSessionsProbe/run_probe.py",
    "RuntimeKit/Candidates/EnginePreferences20261111/ActualSessionsProbe/EnginePreferencesProbe.m",
    "RuntimeKit/Candidates/EnginePreferences20261111/ActualSessionsProbe/fixture.rpy"}
ENGINE_SOURCES = {"App/Core/ReaderEnginePreferences.swift", "App/Services/Import/ReaderEngineSidecarStore.swift",
    "App/ReaderStore+Runtime.swift", "App/ReaderStore.swift"}
MARKER = "PASS: COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED; historical UI evidence does not qualify this App"
ROW = re.compile(rb'\.init\(runtimeID:\s*"(renpy-[0-9.]+)",\s*previousProvenanceSHA256:\s*"([0-9a-f]{64})",\s*currentProvenanceSHA256:\s*"([0-9a-f]{64})",\s*currentBaseFingerprint:\s*"([0-9a-f]{64})"\)')


def safe(path, directory=False):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not (path.is_dir() if directory else path.is_file()):
        raise ValueError("Missing, linked or non-regular qualification input: " + str(path))
    return path


def ref(root, value):
    if type(value) is not dict or set(value) != {"path", "sha256"}:
        raise ValueError("Incomplete immutable evidence reference")
    name = value["path"]
    if type(name) is not str or not name or Path(name).is_absolute() or any(p in ("", ".", "..") for p in name.split("/")):
        raise ValueError("Unsafe qualification reference")
    path = safe(root / name)
    if sha(path) != value["sha256"]:
        raise ValueError("Qualification input hash changed: " + name)
    return path


def sha(path):
    return hashlib.sha256(safe(path).read_bytes()).hexdigest()


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate qualification JSON key")
            result[key] = value
        return result
    return json.loads(safe(path).read_bytes(), object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def filemap(directory):
    directory = safe(directory, directory=True)
    result = {}
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise ValueError("Special or linked qualification tree entry: " + str(path))
        result[path.relative_to(directory).as_posix()] = {"size": info.st_size, "mode": stat.S_IMODE(info.st_mode), "sha256": sha(path)}
    return result


def directories(directory):
    directory = safe(directory, directory=True)
    return {str(path.relative_to(directory)): stat.S_IMODE(path.stat().st_mode)
        for path in [directory, *sorted(directory.rglob("*"))] if path.is_dir() and not path.is_symlink()}


def relative_directory(root, name):
    if type(name) is not str or not name or Path(name).is_absolute() or any(p in ("", ".", "..") for p in name.split("/")):
        raise ValueError("Unsafe qualification directory")
    return safe(root / name, directory=True)


def fingerprint(base):
    digest = hashlib.sha256()
    for name, record in sorted(filemap(base).items()):
        digest.update(("%d:%s:%d:%s\n" % (len(name.encode()), name, record["size"], record["sha256"])).encode())
    return digest.hexdigest()


def bundle(artifacts, version):
    return safe(artifacts / ("RenPy" + version.replace(".", "") + ".bundle"), directory=True)


def expected_main(original):
    text = original.decode("utf-8")
    marker = 'session = rr_host.begin_session()\n'
    call = 'try:\n    entry.main()\n'
    cleanup = 'finally:\n    try:\n        rr_host.close_inline_style()'
    if text.count(marker) != 1 or text.count(call) != 1 or text.count(cleanup) != 1 or "rr_engine_preferences" in text:
        raise ValueError("Unknown predecessor trusted entry")
    text = text.replace(marker, marker + '_preferences_module = _stock_module("rr_engine_preferences", "rr_engine_preferences.py")\n_preferences = _preferences_module.Session(session, rr_host)\n')
    prefix, tail = text.split(call)
    result = prefix + 'try:\n    try:\n        entry.main()\n' + ''.join('    ' + line if line.strip() else line for line in tail.splitlines(True)) + 'finally:\n    _preferences.finish()\n'
    compile(result, "main.py", "exec")
    return result.encode("utf-8")


def registry_rows(data):
    rows = ROW.findall(data)
    if len({row[:3] for row in rows}) != len(rows):
        raise ValueError("Duplicate direct registry edge")
    return rows


def expected_registry(original, inline, runtimes):
    if hashlib.sha256(original).hexdigest() != REGISTRY_SHA256 or hashlib.sha256(inline).hexdigest() != INLINE_REGISTRY_SHA256:
        raise ValueError("The exact434 registry or original inline registry changed")
    rows, shipped = registry_rows(original), registry_rows(inline)
    if len(rows) != 434 or len(shipped) != 36 or set(runtimes) != set(VERSIONS):
        raise ValueError("The complete historical registry/17-runtime inventory is required")
    keys, additions, counts = {row[:3] for row in rows + shipped}, [], {}
    for version in VERSIONS:
        runtime = ("renpy-" + version).encode()
        record = runtimes[version]
        for field in ("previousProvenanceSHA256", "provenanceSHA256", "baseFingerprint"):
            if type(record.get(field)) is not str or re.fullmatch(r"[0-9a-f]{64}", record[field]) is None:
                raise ValueError("Unfrozen registry target")
        origins = {row[i] for row in rows + shipped if row[0] == runtime for i in (1, 2)}
        origins.add(record["previousProvenanceSHA256"].encode())
        target = record["provenanceSHA256"].encode()
        counts[version] = 0
        for origin in sorted(origins):
            key = (runtime, origin, target)
            if origin == target:
                continue
            if key not in keys:
                additions.append('        .init(runtimeID: "%s", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' % (*[p.decode() for p in key], record["baseFingerprint"]))
                keys.add(key); counts[version] += 1
    boundary = b"\n    ]\n}\n"
    if original.count(boundary) != 1:
        raise ValueError("Unexpected historical registry layout")
    result = original.replace(boundary, b",\n" + ",\n".join(additions).encode() + boundary, 1)
    if len(additions) != 151 or len(registry_rows(result)) != 585:
        raise ValueError("The exact minimal151-edge successor changed")
    return result, counts


def parent(root, sources):
    path = safe(sources / PARENT_GUARD)
    if sha(path) != PARENT_GUARD_SHA256 or sha(root / PARENT_CERTIFICATE) != PARENT_CERTIFICATE_SHA256:
        raise ValueError("The immutable legacy packaging guard/certificate changed")
    spec = importlib.util.spec_from_file_location("immutable_engine_preferences_packaging_parent", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.CERTIFICATE_SHA256 != PARENT_CERTIFICATE_SHA256:
        raise ValueError("The predecessor certificate declaration changed")
    return module


def normalized_guard(path):
    data = safe(path).read_bytes()
    pattern = rb'^CERTIFICATE_SHA256 = [^\n]+$'
    if len(re.findall(pattern, data, re.M)) != 1:
        raise ValueError("Unexpected successor certificate declaration")
    return re.sub(pattern, b"CERTIFICATE_SHA256 = None", data, flags=re.M)


def inspect_candidate(root, identity, *, artifacts_root=None, source_root=None):
    """Hash/delta inspection only. Never sets runtime/UI qualification."""
    root = safe(root, directory=True)
    if identity.get("schemaVersion") != 1 or type(identity["schemaVersion"]) is not int or identity.get("kind") != "enginePreferencesResourceSuccessor":
        raise ValueError("Unknown successor identity")
    if set(identity.get("buildInputs", {})) != {"manifest", "helper", "builder"}:
        raise ValueError("Incomplete frozen candidate build inputs")
    inputs = {name: ref(root, record) for name, record in identity["buildInputs"].items()}
    manifest = read(inputs["manifest"])
    if (sha(inputs["helper"]) != identity["helperSHA256"] or manifest.get("helperSHA256") != identity["helperSHA256"] or
            manifest.get("candidateBuilderSHA256") != sha(inputs["builder"]) or manifest.get("componentOnly") is not True):
        raise ValueError("The actual candidate helper/builder differs from its frozen generation")
    previous = relative_directory(root, identity["predecessorArtifactsPath"])
    sources = relative_directory(root, identity["predecessorSourcesPath"])
    artifacts = safe(artifacts_root, directory=True) if artifacts_root else relative_directory(root, identity["candidateArtifactsPath"])
    current_sources = safe(source_root, directory=True) if source_root else relative_directory(root, identity["candidateSourcesPath"])
    if filemap(previous) != identity["predecessorArtifacts"] or filemap(sources) != identity["predecessorSources"]:
        raise ValueError("The actual frozen predecessor snapshot changed")
    if filemap(artifacts) != identity["candidateArtifacts"]:
        raise ValueError("The exact candidate artifact bytes/modes changed")
    if (directories(previous) != identity["artifactDirectories"] or directories(artifacts) != identity["artifactDirectories"] or
            directories(sources) != identity["predecessorSourceDirectories"]):
        raise ValueError("The complete artifact/predecessor directory inventory or modes changed")
    parent(root, sources)
    if set(identity["runtimes"]) != set(VERSIONS):
        raise ValueError("The complete17 runtime identity is required")
    before, after = identity["predecessorArtifacts"], identity["candidateArtifacts"]
    allowed = {"runtime-catalog.json"}
    added = set()
    for version in VERSIONS:
        prefix = "RenPy" + version.replace(".", "") + ".bundle/"
        allowed.update(prefix + name for name in ("base/main.py", "runtime-profile.json", "provenance.json"))
        added.add(prefix + "base/rr_engine_preferences.py")
    if set(after) != set(before) | added or any(before[name] != after[name] for name in set(before) - allowed):
        raise ValueError("Unexpected resource/native/cache delta outside the exact69 leaves")
    changed = {name for name in after if before.get(name) != after[name]}
    if changed != allowed | added or len(changed) != 69:
        raise ValueError("Missing or additional engine-preference delta")
    for version in VERSIONS:
        original, actual = bundle(previous, version), bundle(artifacts, version)
        record = identity["runtimes"][version]
        if (actual / "base/main.py").read_bytes() != expected_main((original / "base/main.py").read_bytes()):
            raise ValueError("Trusted entry exceeds the deterministic hook: " + version)
        if sha(actual / "base/rr_engine_preferences.py") != identity["helperSHA256"]:
            raise ValueError("Engine-preference helper changed: " + version)
        profile = read(original / "runtime-profile.json")
        profile.update(enginePreferencesSchemaVersion=1, enginePreferencesQualification="candidate-component-only")
        if (actual / "runtime-profile.json").read_bytes() != encoded(profile):
            raise ValueError("Profile exceeds the exact two fields: " + version)
        provenance = read(original / "provenance.json")
        provenance["enginePreferencesCandidate"] = dict(schemaVersion=1,
            previousProvenanceSHA256=sha(original / "provenance.json"), mainSHA256=sha(actual / "base/main.py"),
            helperSHA256=identity["helperSHA256"], hostUnchangedSHA256=sha(original / "base/rr_host.py"),
            status="component-unqualified", scope=PROVENANCE_SCOPE)
        if (actual / "provenance.json").read_bytes() != encoded(provenance):
            raise ValueError("Provenance exceeds the exact successor fields: " + version)
        expected = {"previousProvenanceSHA256": sha(original / "provenance.json"),
            "provenanceSHA256": sha(actual / "provenance.json"), "baseFingerprint": fingerprint(actual / "base"),
            "mainSHA256": sha(actual / "base/main.py"), "hostSHA256": sha(actual / "base/rr_host.py"),
            "profileSHA256": sha(actual / "runtime-profile.json")}
        if record != expected:
            raise ValueError("Runtime identity differs from the actual package: " + version)
    catalog = read(previous / "runtime-catalog.json")
    versions = [row["runtimeID"] for row in catalog["profiles"]]
    if len(versions) != 17 or set(versions) != set(VERSIONS):
        raise ValueError("The exact17 catalog inventory changed")
    for row in catalog["profiles"]:
        row.update(enginePreferencesSchemaVersion=1, enginePreferencesQualification="candidate-component-only")
    if (artifacts / "runtime-catalog.json").read_bytes() != encoded(catalog):
        raise ValueError("Catalog exceeds the exact two fields")
    registry, counts = expected_registry((sources / REGISTRY).read_bytes(), (sources / INLINE_REGISTRY).read_bytes(), identity["runtimes"])
    if (current_sources / REGISTRY).read_bytes() != registry or sha(current_sources / REGISTRY) != identity["registrySHA256"]:
        raise ValueError("The exact585-row direct registry successor changed")
    for name, record in identity["predecessorSources"].items():
        path = current_sources / name
        if name == REGISTRY:
            continue
        if name.startswith("RuntimeKit/Notices/renpy-") and name.endswith("-provenance.json"):
            version = Path(name).name[len("renpy-"):-len("-provenance.json")]
            if version in VERSIONS:
                if path.read_bytes() != (bundle(artifacts, version) / "provenance.json").read_bytes():
                    raise ValueError("Current provenance notice differs: " + version)
                continue
        if sha(path) != record["sha256"] or stat.S_IMODE(path.stat().st_mode) != record["mode"]:
            raise ValueError("Preserved source/gate/certificate changed: " + name)
    for folder in ("RuntimeKit/Native", "RuntimeKit/Bridge"):
        if filemap(current_sources / folder) != filemap(sources / folder) or directories(current_sources / folder) != directories(sources / folder):
            raise ValueError("Native/Bridge source inventory changed")
    return {"passed": True, "staticInspectionOnly": True, "runtimeExecutionQualified": False, "uiQualified": False,
        "runtimes": 17, "changedLeaves": 69, "nativePackagesUnchanged": True,
        "registryRows": 585, "registryAddedDirectEdges": 151, "directEdgesByRuntime": counts}


def replay_predecessor(root, identity, *, replay=True):
    sources = safe(root / identity["predecessorSourcesPath"], directory=True)
    wrapper = parent(root, sources)
    # Execute the exact old full validator on its real old snapshots. No new
    # resource bytes are substituted into any historical qualification.
    return wrapper.verify(root, artifacts_root=root / identity["predecessorArtifactsPath"],
        source_root=sources, replay=replay)


def derived_built_check(root, identity, *, verifier=None, artifacts=None):
    wrapper = parent(root, root / identity["predecessorSourcesPath"])
    function, source = wrapper.derive(wrapper.parent(root))
    before = "value = verify(root, replay=False)"
    original_artifacts = 'artifacts = root / "RuntimeKit/Artifacts"'
    if source.count(before) != 1 or source.count(original_artifacts) != 1 or "successor_verify" in source:
        raise ValueError("Unexpected predecessor built-image verifier")
    updated = source.replace(before, "value = successor_verify(root, replay=False)")
    updated = updated.replace(original_artifacts, "artifacts = successor_artifacts(root)")
    namespace = dict(function.__globals__)
    namespace["successor_verify"] = verifier or verify
    namespace["successor_artifacts"] = lambda root: artifacts or root / "RuntimeKit/Artifacts"
    exec(compile(updated, str(__file__) + "::successor-built-check", "exec", dont_inherit=True, optimize=0), namespace)
    return namespace["check_built_app"], updated


def inspect_built_app(root, identity, app, platform, configuration):
    # Candidate-only Xcode phases must retain the real old sources in production.
    # The candidate registry/provenance are explicit project references instead.
    for name, record in identity["predecessorSources"].items():
        if sha(root / name) != record["sha256"]:
            raise ValueError("A formal predecessor/gate changed during candidate build: " + name)
    inspect_candidate(root, identity)
    replay_predecessor(root, identity, replay=False)
    def candidate_verify(_root, *, replay=False):
        return {"identity": identity}
    function, _ = derived_built_check(root, identity, verifier=candidate_verify,
        artifacts=relative_directory(root, identity["candidateArtifactsPath"]))
    function(root, read(root / "RuntimeKit/Patches/overlay-capability-853.json"), app, platform, configuration)
    return {"passed": True, "staticInspectionOnly": True, "builtResourceAndNativeComparisonPassed": True,
        "runtimeExecutionQualified": False, "uiQualified": False, "publicationQualified": False}


def program_inventory(app):
    return {name: {"kind": "regular", "byteCount": row["size"], "sha256": row["sha256"]}
        for name, row in filemap(app).items()}


def verify_program(root, execution, identity, identity_sha):
    references = execution["sessions"][0]["programEvidence"]
    if set(references) != {"inputs", "build", "beforeInstall", "verification"} or any(
            session["programEvidence"] != references for session in execution["sessions"]):
        raise ValueError("The real34-session program evidence closure changed")
    paths = {name: ref(root, value) for name, value in references.items()}
    inputs, build, before, native = [read(paths[name]) for name in ("inputs", "build", "beforeInstall", "verification")]
    installed = read(ref(root, execution["installedBeforeLaunch"]))
    if (inputs.get("kind") != "enginePreferencesProbeInputs" or inputs.get("usedStubs") is not False or
            inputs.get("identity", {}).get("sha256") != identity_sha or inputs.get("helperSHA256") != identity["helperSHA256"] or
            build.get("usedStubs") is not False or build.get("strictSignaturePassed") is not True or
            before.get("capturedBeforeFirstInstall") is not True or before.get("strictSignaturePassed") is not True or
            installed.get("matchesSignedBeforeFirstInstall") is not True):
        raise ValueError("The executed program is not bound before first installation")
    ref(root, inputs["identity"])
    if inputs["candidateArtifacts"] != {p: row["sha256"] for p, row in identity["candidateArtifacts"].items()}:
        raise ValueError("Actual execution borrowed another runtime package")
    manifest = read(ref(root, inputs["candidateManifest"]))
    actual_delta = {name: {"previous": identity["predecessorArtifacts"].get(name, {}).get("sha256"), "candidate": row["sha256"]}
        for name, row in identity["candidateArtifacts"].items() if identity["predecessorArtifacts"].get(name) != row}
    if manifest["allowedDelta"] != actual_delta or inputs["allowedDelta"] != actual_delta or len(actual_delta) != 69:
        raise ValueError("Actual execution did not use the exact69 resource delta")
    if type(inputs.get("sources")) is not dict or set(inputs["sources"]) != PROBE_SOURCES:
        raise ValueError("The complete exact7 compiled probe source inputs are required")
    for name, source in inputs["sources"].items():
        expected_path = str((paths["inputs"].parent / "SourceInputs" / name).relative_to(root))
        if type(source) is not dict or set(source) != {"frozenPath", "sha256"} or source["frozenPath"] != expected_path:
            raise ValueError("The actual compiled source snapshot path changed: " + name)
        ref(root, {"path": source["frozenPath"], "sha256": source["sha256"]})
        if name.startswith(("RuntimeKit/Bridge/", "RuntimeKit/Native/")) and source["sha256"] != identity["predecessorSources"][name]["sha256"]:
            raise ValueError("The actual probe compiled a changed native/Bridge source")
    app = relative_directory(root, build["appPath"])
    leaves = program_inventory(app)
    if (leaves != build["signedAppLeaves"] or leaves != before["actualAppLeaves"] or leaves != installed["actualAppLeaves"] or
            build["inputs"] != references["inputs"] or before["build"] != references["build"] or
            installed["sourceAppLeavesSHA256"] != references["beforeInstall"]["sha256"]):
        raise ValueError("The signed executed program changed from its before-install inventory")
    for name, delta in actual_delta.items():
        if name == "runtime-catalog.json":
            # The native probe uses the exact17 individual profile resources;
            # the shared catalog is recorded in inputs, not copied to its App.
            continue
        if leaves.get(name, {}).get("sha256") != delta["candidate"]:
            raise ValueError("An actual executed changed resource differs: " + name)
    if set(build["resources"]) != {"RenPy" + v.replace(".", "") + ".bundle" for v in VERSIONS}:
        raise ValueError("The real program omitted a runtime resource bundle")
    for version in VERSIONS:
        name = "RenPy" + version.replace(".", "") + ".bundle"
        expected = {p[len(name) + 1:]: row["sha256"] for p, row in identity["candidateArtifacts"].items() if p.startswith(name + "/")}
        actual = {p[len(name) + 1:]: row["sha256"] for p, row in leaves.items() if p.startswith(name + "/")}
        if build["resources"][name] != expected or actual != expected:
            raise ValueError("The actual complete runtime resource tree differs: " + version)
    wrapper = parent(root, root / identity["predecessorSourcesPath"])
    legacy = wrapper.parent(root)
    old = legacy.load_parent(root)
    artifacts = relative_directory(root, identity["candidateArtifactsPath"])
    names = old.previous.IMAGE_NAMES | {"RRRuntime" + v.replace(".", "") for v in VERSIONS}
    if set(build["frameworkInputs"]) != {name + ".framework" for name in names}:
        raise ValueError("The actual native framework inventory changed")
    for name in names:
        source = legacy.framework_slice(old, artifacts, name)
        record = build["frameworkInputs"][name + ".framework"]
        target = safe(app / "Frameworks" / (name + ".framework"), directory=True)
        if (record["candidatePath"] != str(source.relative_to(artifacts)) or record["beforeSigning"] != program_inventory(source) or
                legacy.image_identity(root, source / name) != legacy.image_identity(root, target / name)):
            raise ValueError("A real native image/source input differs beyond signing: " + name)
        original = program_inventory(source)
        actual = program_inventory(target)
        signature = "_CodeSignature/CodeResources"
        if (set(original) - set(actual) or set(actual) - set(original) - {signature} or
                any(original[p] != actual[p] for p in original if p not in {name, signature})):
            raise ValueError("A real native non-MachO resource changed: " + name)
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (native.get("passed") is not True or native.get("sessionsCount") != 34 or native.get("profileCount") != 17 or
            native.get("closedAndReset") is not True or native.get("allFinalBridgeStatesIdle") is not True or
            native.get("noNativeErrorRetainedOrQuarantine") is not True or native.get("readbackVerified") is not True):
        raise ValueError("The actual native verifier did not complete all34 sessions")
    all_events = [json.loads(line) for line in ref(root, native["nativeEvents"]).read_text().splitlines() if line.strip()]
    host_events = [json.loads(line) for line in ref(root, native["hostEvents"]).read_text().splitlines() if line.strip()]
    bad = {"error", "gameError", "quarantined", "enginePreferencesRetained", "commandRejected", "saveFailed"}
    if any(row.get("type") in bad for row in all_events) or any(row.get("type") in {"enginePreferencesProbeFailure", "enginePreferencesProbeFailed"} for row in host_events):
        raise ValueError("Actual native/host failure events cannot qualify a candidate")
    if sum(row.get("type") == "enginePreferencesProbePassed" for row in host_events) != 1:
        raise ValueError("Missing unique actual native matrix completion")
    normalized = copy_sessions_without_verification(execution["sessions"])
    if native.get("sessions") != normalized or len(inputs.get("plans", [])) != 34:
        raise ValueError("The frozen program plan/session verification changed")
    return inputs, all_events


def copy_sessions_without_verification(sessions):
    result = []
    for session in sessions:
        entry = dict(session)
        entry["programEvidence"] = {key: value for key, value in session["programEvidence"].items() if key != "verification"}
        result.append(entry)
    return result


def verify_evidence(root, value, identity):
    # These references remain empty in the draft. Actual events, signed program
    # bindings and independent UI review must be supplied by the qualification run.
    execution = read(ref(root, value["executionEvidence"]))
    identity_sha = value["identity"]["sha256"]
    if (execution.get("kind") != "enginePreferencesActual17Sessions" or execution.get("passed") is not True or
            execution.get("identitySHA256") != identity_sha or execution.get("helperSHA256") != identity["helperSHA256"] or
            execution.get("usedStubs") is not False or execution.get("beforeFirstInstallBound") is not True or
            type(execution.get("sessions")) is not list or len(execution["sessions"]) != 34 or
            execution.get("sessionsCount") != 34 or execution.get("profileCount") != 17):
        raise ValueError("Actual17-profile/34-session qualification is missing or belongs to another package")
    inputs, all_events = verify_program(root, execution, identity, identity_sha)
    seen = set()
    owners = set()
    for index, session in enumerate(execution["sessions"]):
        version = session["runtimeID"]
        phase = session["phase"]
        if (version, phase) in seen or version not in VERSIONS or phase not in ("overrides", "defaults") or session.get("provenanceSHA256") != identity["runtimes"][version]["provenanceSHA256"]:
            raise ValueError("Missing/duplicate/mismatched actual runtime session")
        seen.add((version, phase))
        events = [json.loads(line) for line in ref(root, session["events"]).read_text().splitlines() if line.strip()]
        owner, epoch, digest = session["sessionID"], session["epoch"], session["sidecarSHA256"]
        if owner in owners or type(epoch) is not int or epoch != index + 1 or re.fullmatch(r"[0-9a-f]{64}", digest) is None or session.get("finalBridgeState") != "idle":
            raise ValueError("Untyped actual session owner/sidecar")
        owners.add(owner)
        owned = [row for row in events if row.get("sessionID") == owner and row.get("epoch") == epoch]
        if owned != events or owned != [row for row in all_events if row.get("sessionID") == owner and row.get("epoch") == epoch]:
            raise ValueError("The session event file differs from actual native raw events")
        packet_path = ref(root, session["sidecar"])
        packet = read(packet_path)
        plan = inputs["plans"][index]
        if (sha(packet_path) != digest or plan["runtimeID"] != version or plan["phase"] != phase or
                packet != dict(schemaVersion=1, sessionID=owner, epoch=epoch, runtimeID=version, prefs=plan["prefs"])):
            raise ValueError("The actual sidecar does not match its frozen native session plan")
        if any(row.get("type") in ("quarantined", "error", "enginePreferencesRetained", "gameError") for row in owned):
            raise ValueError("The actual preference session did not reset cleanly")
        for kind in ("enginePreferencesLoaded", "enginePreferencesApplied", "enginePreferencesClosed", "enginePreferencesReadback", "ready", "didReset", "threadAudit"):
            matching = [row for row in owned if row.get("type") == kind]
            if len(matching) != 1:
                raise ValueError("Missing/duplicate actual session event: " + kind)
            if kind.startswith("enginePreferences") and matching[0].get("sidecarSHA256") != digest:
                raise ValueError("Actual event borrowed another launch sidecar")
        if next(row for row in owned if row.get("type") == "threadAudit").get("remaining") != [] or next(row for row in owned if row.get("type") == "enginePreferencesClosed").get("state") != "closed":
            raise ValueError("The actual engine owner did not finish a clean reset")
        readback = next(row for row in owned if row.get("type") == "enginePreferencesReadback")
        values, override = readback["values"], phase == "overrides"
        flags = ["developer", "console", "allowSkipping", "rollbackEnabled", "skipUnseen", "storeSkipping", "storeRollback", "networkGetaddrinfoPatched", "networkSocketConnectPatched"]
        environment = {key: "1" if override else None for key in ("RENPY_LESS_MEMORY", "RENPY_LESS_UPDATES")}
        environment["RENPY_VARIANT"] = "mobile touch phone small" if override else None
        if (readback.get("phase") != phase or any(values.get(key) is not override for key in flags) or
                values.get("rollbackLength") != (100 if override else 16) or values.get("hardRollbackLimit") != (100 if override else 16) or
                values.get("environment") != environment or (override and values.get("variants") != plan["prefs"]["variants"] + [None])):
            raise ValueError("Actual native preference readback differs from the plan")
        ready = next(row for row in owned if row.get("type") == "ready")
        if (ready.get("runtimeVersion") != version or ready.get("capabilities", {}).get("enginePreferencesV1") is not True or
                ready.get("capabilities", {}).get("unicodeSaveSlotsV1") is not False):
            raise ValueError("Wrong actual runtime version, unnegotiated capability or premature Unicode-slot claim")
    verify_ui(root, value, identity)


def verify_ui(root, value, identity):
    ui = read(ref(root, value["uiEvidence"]))
    identity_sha = value["identity"]["sha256"]
    if (ui.get("kind") != "enginePreferencesIndependentUIReview" or ui.get("passed") is not True or
            ui.get("identitySHA256") != identity_sha or ui.get("reviewedActualUI") is not True or
            ui.get("historicalUIReused") is not False or not ui.get("evidence")):
        raise ValueError("A new actual UI review is required")
    for reference in ui["evidence"].values():
        ref(root, reference)
    bindings = ui.get("engineSourceSHA256")
    if type(bindings) is not dict or set(bindings) != ENGINE_SOURCES:
        raise ValueError("The exact4 Engine App source bindings are required")
    build_inputs = read(ref(root, ui["evidence"]["candidateBuildInputs"]))
    build = read(ref(root, ui["evidence"]["candidateBuildVerification"]))
    ui_run = read(ref(root, ui["evidence"]["uiRunInputs"]))
    for name, digest in bindings.items():
        if build_inputs.get(name) != digest or sha(root / name) != digest:
            raise ValueError("An Engine App source differs from the actually reviewed package: " + name)
    wrapper = parent(root, root / identity["predecessorSourcesPath"])
    locked = wrapper.parent(root).load_parent(root).previous.LOCKED_SOURCES
    for name in locked:
        digest = identity["predecessorSources"][name]["sha256"]
        if sha(root / name) != digest or (name in build_inputs and build_inputs[name] != digest):
            raise ValueError("A protected source differs from the reviewed App/native predecessor: " + name)
    if (build.get("passed") is not True or type(build.get("exitCode")) is not int or build["exitCode"] != 0 or
            build.get("inputsChanged") != [] or build.get("minimumOS") != "15.5" or
            build.get("bundleID") != "dev.renreader.enginecandidate20261111" or ui_run.get("bundleID") != build["bundleID"] or
            type(build.get("binaries")) is not dict or set(build["binaries"]) != {"RenReader", "RenReader.debug.dylib"} or
            ui_run.get("productSHA256") != build.get("binaries") or
            type(ui_run.get("testExitCode")) is not int or ui_run["testExitCode"] != 0 or ui_run.get("testSourceUnchangedAfterRun") is not True):
        raise ValueError("The independent UI run is not bound to its actual successful candidate build")
    app = safe(build["product"], directory=True)
    if not app.is_relative_to(root) or str(app) != ui_run.get("sourceProduct"):
        raise ValueError("The reviewed UI source product is not the frozen candidate App")
    leaves = {name: row["sha256"] for name, row in filemap(app).items()}
    if leaves != build["signedLeaves"]:
        raise ValueError("The frozen reviewed App signature/resource inventory changed")
    for version in VERSIONS:
        prefix = "RenPy" + version.replace(".", "") + ".bundle/"
        expected = {p: row["sha256"] for p, row in identity["candidateArtifacts"].items() if p.startswith(prefix)}
        if {p: digest for p, digest in leaves.items() if p.startswith(prefix)} != expected:
            raise ValueError("The reviewed UI App used another exact runtime resource package: " + version)
    if {name: sha(app / name) for name in build["binaries"]} != ui_run["productSHA256"]:
        raise ValueError("The reviewed UI executed another App binary")
    for path_key, digest_key in (("testSourceSnapshot", "testSourceSHA256"), ("runnerSourceSnapshot", "runnerSHA256")):
        path = safe(ui_run[path_key])
        if not path.is_relative_to(root) or sha(path) != ui_run[digest_key]:
            raise ValueError("The actual UI test/runner SourceSnapshot changed")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def certificate(root):
    if CERTIFICATE_SHA256 is None or sha(root / CERTIFICATE) != CERTIFICATE_SHA256:
        raise ValueError("Engine preferences successor remains UNQUALIFIED")
    value = read(root / CERTIFICATE)
    flags = {"passed": True, "runtimeExecutionQualified": True, "uiQualified": True, "nativePackagesUnchanged": True,
        "oldOSExecutionQualified": False, "legacyCoreQualified": False, "physicalEffectsQualified": False,
        "networkSandboxQualified": False, "unicodeSaveSlotsQualified": False}
    if (type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1 or value.get("kind") != "enginePreferencesResourceQualification" or
            any(value.get(key) is not expected for key, expected in flags.items()) or
            value.get("parentGuardSHA256") != PARENT_GUARD_SHA256 or value.get("parentCertificateSHA256") != PARENT_CERTIFICATE_SHA256 or
            value.get("guardTemplateSHA256") != hashlib.sha256(normalized_guard(__file__)).hexdigest()):
        raise ValueError("The resource-only qualification scope changed")
    identity = read(ref(root, value["identity"]))
    _, source = derived_built_check(root, identity)
    if hashlib.sha256(source.encode()).hexdigest() != value.get("derivedBuiltCheckSHA256"):
        raise ValueError("Built-image verifier changed beyond the one qualification call")
    verify_evidence(root, value, identity)
    return value, identity


def verify(root, *, artifacts_root=None, source_root=None, replay=True):
    if sys.flags.optimize:
        raise ValueError("Qualification requires Python assertions")
    value, identity = certificate(root)
    inspect_candidate(root, identity, artifacts_root=artifacts_root or root / "RuntimeKit/Artifacts", source_root=source_root or root)
    replay_predecessor(root, identity, replay=replay)
    return dict(value, identity=identity)


def image_identity(root, path):
    # This general API keeps the raw historical comparator; only the derived
    # built-device check uses the already-qualified packaged-source transform.
    spec = importlib.util.spec_from_file_location("unchanged_packaging_parent_image_api", root / PARENT_GUARD)
    module = importlib.util.module_from_spec(spec)
    if sha(root / PARENT_GUARD) != PARENT_GUARD_SHA256:
        raise ValueError("The immutable packaging guard changed")
    spec.loader.exec_module(module)
    return module.image_identity(root, path)


def check(root, contract):
    _, identity = certificate(root)
    parent(root, root / identity["predecessorSourcesPath"]).parent(root).contract_is_original(root, contract)
    return verify(root)


def check_built_app(root, contract, app, platform, configuration):
    _, identity = certificate(root)
    function, _ = derived_built_check(root, identity)
    return function(root, contract, app, platform, configuration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--inspect-candidate", action="store_true")
    parser.add_argument("--inspect-built-app", action="store_true")
    parser.add_argument("--replay-predecessor", action="store_true")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--built-app", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--configuration")
    args = parser.parse_args()
    if args.inspect_candidate or args.replay_predecessor or args.inspect_built_app:
        if args.identity is None:
            parser.error("--identity is required for candidate inspection/replay")
        identity = read(args.identity)
        result = inspect_candidate(args.root, identity)
        if args.replay_predecessor:
            replay_predecessor(args.root, identity)
            result["fullPredecessorReplayPassed"] = True
        if args.inspect_built_app:
            if not args.built_app or not args.platform or not args.configuration:
                parser.error("Candidate built-app inspection requires --built-app/--platform/--configuration")
            result.update(inspect_built_app(args.root, identity, args.built_app, args.platform, args.configuration))
        print(json.dumps(result, sort_keys=True))
        print("PASS: static candidate shape only; engine preference execution/UI remains UNQUALIFIED")
    elif args.built_app:
        check_built_app(args.root, read(args.contract), args.built_app, args.platform, args.configuration)
        print(MARKER)
    elif args.contract:
        check(args.root, read(args.contract)); print(MARKER)
    else:
        verify(args.root); print(MARKER)
